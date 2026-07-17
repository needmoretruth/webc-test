//! Transaction mempool: admission, ordering, and block selection.
//!
//! Purpose: hold pending transactions between submission and block inclusion,
//! admitting only well-formed ones and selecting a fee-prioritized,
//! nonce-contiguous batch for the proposer. This is WEBC's own policy logic —
//! not a reusable library — so it lives in the node.
//!
//! Boundaries: it validates against a read-only [`ChainState`] snapshot but never
//! mutates chain state; execution and the final authoritative checks happen in
//! `build_block`. It reads no clock: the caller supplies `now_ms` so admission,
//! expiry, and selection stay deterministic and testable.
//!
//! Model / data flow:
//! - Transactions are keyed by `(sender, lane, nonce)`. A [`std::collections::BTreeMap`]
//!   over that key gives per-(sender, lane) nonce ordering for free.
//! - Admission ([`Mempool::insert`]) runs stateless checks (signature, protocol,
//!   chain id) then stateful checks (known sender/lane, nonce not stale and not
//!   too far ahead, fee at or above the current base fee, and a best-effort fee
//!   affordability check).
//! - Replacement-by-fee: a new transaction at an occupied `(sender, lane, nonce)`
//!   replaces the old one only if its max fee-per-unit beats it by a configured
//!   margin, so a spammer cannot cheaply churn a slot.
//! - Expiry ([`Mempool::prune_expired`]): entries older than the configured TTL
//!   are dropped.
//! - Selection ([`Mempool::select_block`]): a max-heap on effective fee-per-unit
//!   pulls the highest-paying runnable transaction across senders while each
//!   sender's own transactions stay in strict nonce order with no gaps, all under
//!   an execution-unit budget.
//!
//! Security notes: all inputs are hostile. Bounds cap total transactions and how
//! far ahead of the expected nonce a sender may queue, so a single account cannot
//! exhaust memory. The mempool is advisory: passing admission does not guarantee
//! execution success, and `build_block` remains the fail-closed authority.

use std::collections::{BTreeMap, BinaryHeap};

use webc_chain::{AuthorizationLaneId, ChainConfig, ChainError, ChainState, Transaction};
use webc_crypto::{Address, Hash256};

/// Tuning knobs for mempool admission and retention.
#[derive(Clone, Debug)]
pub struct MempoolConfig {
    /// Hard cap on retained transactions; further inserts (that are not
    /// replacements) are rejected with [`MempoolError::Full`].
    pub max_transactions: usize,
    /// How far above a sender's expected nonce a queued transaction may sit.
    /// Bounds per-sender memory and prevents unbounded future-nonce parking.
    pub max_future_nonce_gap: u64,
    /// Time-to-live in milliseconds; entries older than this are pruned.
    pub ttl_ms: u64,
    /// Minimum fee increase, in basis points, for a replacement to win its slot.
    /// For example 1000 = the new max fee-per-unit must be at least 10% higher.
    pub min_replacement_bump_bps: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_transactions: 8_192,
            max_future_nonce_gap: 64,
            ttl_ms: 120_000,
            min_replacement_bump_bps: 1_000,
        }
    }
}

/// Why a transaction was refused admission.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    /// Stateless validation failed (bad signature, wrong protocol version, ...).
    #[error("invalid transaction: {0}")]
    Invalid(ChainError),
    /// The transaction targets a different network than this node.
    #[error("transaction chain id does not match this node")]
    ChainIdMismatch,
    /// The sender account (default lane) or lane does not exist in state.
    #[error("unknown sender or authorization lane")]
    UnknownSenderOrLane,
    /// The nonce is below the sender's expected next nonce (already used).
    #[error("nonce {actual} is below the expected next nonce {expected}")]
    NonceTooLow { expected: u64, actual: u64 },
    /// The nonce is further ahead of expected than the configured gap allows.
    #[error("nonce {actual} is too far ahead of expected {expected}")]
    NonceTooFarAhead { expected: u64, actual: u64 },
    /// The bid's max fee-per-unit is below the current base fee.
    #[error("max fee-per-unit is below the current base fee")]
    Underpriced,
    /// The sender cannot afford even the maximum fee for this transaction.
    #[error("sender cannot afford the maximum fee")]
    InsufficientFeeFunds,
    /// A transaction already occupies this (sender, lane, nonce) and the new bid
    /// does not beat it by the required margin.
    #[error("replacement does not beat the existing transaction's fee enough")]
    ReplacementUnderpriced,
    /// The mempool is at capacity and this is not a replacement.
    #[error("mempool is full")]
    Full,
}

/// The result of a successful admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    /// A new slot was filled.
    Added,
    /// An existing (sender, lane, nonce) slot was replaced by a higher bid.
    Replaced,
}

/// A pending transaction plus the time it entered the pool.
#[derive(Clone, Debug)]
struct Entry {
    tx: Transaction,
    added_at_ms: u64,
}

/// Unique ordering key: sender, then lane, then nonce. BTreeMap iteration over
/// this yields each sender/lane's transactions in ascending nonce order.
type TxKey = (Address, AuthorizationLaneId, u64);

/// A pending-transaction pool with fee-priority, nonce-ordered block selection.
#[derive(Debug)]
pub struct Mempool {
    config: MempoolConfig,
    entries: BTreeMap<TxKey, Entry>,
}

impl Mempool {
    /// Creates an empty mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
        }
    }

    /// Number of pending transactions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pool holds no transactions.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The sender's expected next nonce for `lane`, or `None` if the account
    /// (default lane) or the lane does not exist. Mirrors the rule enforced in
    /// state execution so admission agrees with what a block will accept.
    fn expected_nonce(
        state: &ChainState,
        sender: Address,
        lane: AuthorizationLaneId,
    ) -> Option<u64> {
        if lane.is_default() {
            state.accounts.get(&sender).map(|account| account.nonce)
        } else {
            state
                .authorization_lanes
                .get(&(sender, lane))
                .map(|lane_state| lane_state.next_nonce.get())
        }
    }

    /// Validates and admits `tx`, or replaces a lower-bid transaction in the same
    /// slot.
    ///
    /// `state` is the current committed state used for stateful checks, `config`
    /// supplies the chain id and base fee, and `now_ms` timestamps the entry for
    /// expiry. Returns [`InsertOutcome`] on success or a [`MempoolError`] on
    /// rejection; the pool is unchanged on rejection.
    pub fn insert(
        &mut self,
        tx: Transaction,
        state: &ChainState,
        config: &ChainConfig,
        now_ms: u64,
    ) -> Result<InsertOutcome, MempoolError> {
        // Stateless: signature and protocol version.
        tx.verify().map_err(MempoolError::Invalid)?;
        // Replay-domain: the transaction must target this network.
        if tx.chain_id != config.chain_id {
            return Err(MempoolError::ChainIdMismatch);
        }

        // Stateful: sender/lane must exist so replay state and funds are defined.
        let expected = Self::expected_nonce(state, tx.sender, tx.authorization_lane)
            .ok_or(MempoolError::UnknownSenderOrLane)?;
        if tx.nonce < expected {
            return Err(MempoolError::NonceTooLow {
                expected,
                actual: tx.nonce,
            });
        }
        let gap = tx.nonce - expected;
        if gap > self.config.max_future_nonce_gap {
            return Err(MempoolError::NonceTooFarAhead {
                expected,
                actual: tx.nonce,
            });
        }

        // Fee floor: the bid must at least meet the current base fee.
        if tx.fee.max_fee_per_unit < state.current_base_fee_per_unit {
            return Err(MempoolError::Underpriced);
        }
        // Best-effort affordability: the sender must be able to cover the maximum
        // fee (gas_limit * max_fee_per_unit). Execution re-checks funds exactly;
        // this only filters obviously unpayable transactions early.
        Self::assert_can_afford_fee(state, &tx)?;

        let key: TxKey = (tx.sender, tx.authorization_lane, tx.nonce);
        match self.entries.get(&key) {
            Some(existing) => {
                // Replacement-by-fee: require a strict margin over the old bid.
                let floor = self.replacement_floor(existing.tx.fee.max_fee_per_unit);
                if tx.fee.max_fee_per_unit < floor {
                    return Err(MempoolError::ReplacementUnderpriced);
                }
                self.entries.insert(
                    key,
                    Entry {
                        tx,
                        added_at_ms: now_ms,
                    },
                );
                Ok(InsertOutcome::Replaced)
            }
            None => {
                if self.entries.len() >= self.config.max_transactions {
                    // H2: the pool is full. Rejecting outright lets a base-fee
                    // flood permanently block higher-fee honest transactions, so
                    // instead evict the LEAST valuable entry for a strictly more
                    // valuable newcomer. "Value" is `(runnable, effective_fee)`: a
                    // transaction sitting at exactly its sender/lane's expected
                    // next nonce is immediately includable and outranks any gapped
                    // (non-runnable) transaction regardless of the bid. This is
                    // what keeps eviction free of churn abuse: a gapped bid can
                    // never be sealed (`select_block` skips gaps) so it would never
                    // actually pay, and therefore must not be able to evict a
                    // runnable honest transaction by merely nominating a high fee.
                    // Within the same runnability class the higher effective fee
                    // wins; an entry that no longer meets the base fee ranks fee 0.
                    // Conversely a runnable newcomer *can* evict parked non-runnable
                    // junk even at a lower nominal fee, actively clearing the pool
                    // of never-includable transactions.
                    let base_fee = state.current_base_fee_per_unit;
                    let is_runnable = |sender, lane, nonce| {
                        matches!(
                            Self::expected_nonce(state, sender, lane),
                            Some(expected) if nonce == expected
                        )
                    };
                    let incoming_value = (
                        is_runnable(tx.sender, tx.authorization_lane, tx.nonce),
                        tx.fee.effective_fee_per_unit(base_fee).unwrap_or(0),
                    );
                    let victim = self
                        .entries
                        .iter()
                        .map(|(entry_key, entry)| {
                            let (sender, lane, nonce) = *entry_key;
                            (
                                *entry_key,
                                (
                                    is_runnable(sender, lane, nonce),
                                    entry.tx.fee.effective_fee_per_unit(base_fee).unwrap_or(0),
                                ),
                            )
                        })
                        .min_by(|left, right| {
                            left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0))
                        });
                    match victim {
                        Some((evict_key, victim_value)) if incoming_value > victim_value => {
                            self.entries.remove(&evict_key);
                        }
                        _ => return Err(MempoolError::Full),
                    }
                }
                self.entries.insert(
                    key,
                    Entry {
                        tx,
                        added_at_ms: now_ms,
                    },
                );
                Ok(InsertOutcome::Added)
            }
        }
    }

    /// The minimum max-fee-per-unit a replacement must offer, given the current
    /// occupant's bid and the configured bump. Saturating, so a huge existing bid
    /// cannot overflow the floor.
    fn replacement_floor(&self, existing_max_fee: u64) -> u64 {
        let bump = (u128::from(existing_max_fee) * u128::from(self.config.min_replacement_bump_bps)
            / 10_000) as u64;
        existing_max_fee.saturating_add(bump.max(1))
    }

    /// Rejects a transaction the sender plainly cannot pay the max fee for.
    fn assert_can_afford_fee(state: &ChainState, tx: &Transaction) -> Result<(), MempoolError> {
        let Some(account) = state.accounts.get(&tx.sender) else {
            // Non-default lanes still draw the sender account for value; a missing
            // account cannot pay.
            return Err(MempoolError::UnknownSenderOrLane);
        };
        let max_fee_units = u128::from(tx.fee.gas_limit)
            .checked_mul(u128::from(tx.fee.max_fee_per_unit))
            .ok_or(MempoolError::InsufficientFeeFunds)?;
        let cost = webc_chain::Amount::from_units(max_fee_units);
        if account.balance.checked_sub(cost).is_none() {
            return Err(MempoolError::InsufficientFeeFunds);
        }
        Ok(())
    }

    /// Removes entries older than the configured TTL and returns how many were
    /// dropped. `now_ms` is the caller's current time.
    pub fn prune_expired(&mut self, now_ms: u64) -> usize {
        let ttl = self.config.ttl_ms;
        let before = self.entries.len();
        self.entries
            .retain(|_, entry| now_ms.saturating_sub(entry.added_at_ms) < ttl);
        before - self.entries.len()
    }

    /// Drops every transaction whose nonce is now below the sender's expected
    /// nonce in `state` (i.e. included or otherwise obsoleted by a committed
    /// block). Returns how many were removed.
    pub fn remove_obsolete(&mut self, state: &ChainState) -> usize {
        let before = self.entries.len();
        self.entries.retain(|(sender, lane, nonce), _| {
            match Self::expected_nonce(state, *sender, *lane) {
                Some(expected) => *nonce >= expected,
                // Sender/lane vanished from state (should not happen in practice);
                // drop the entry rather than keep an unusable one.
                None => false,
            }
        });
        before - self.entries.len()
    }

    /// Selects a fee-prioritized, nonce-contiguous batch of transactions for the
    /// next block, within `max_units` total execution units.
    ///
    /// For each sender/lane, transactions are eligible only as a gap-free run
    /// starting at the expected next nonce. Across senders, the highest effective
    /// fee-per-unit (given `config`'s base fee) runs first. A transaction that
    /// would exceed the unit budget ends its sender's run (later nonces cannot be
    /// included without it). Expired transactions are treated as absent, so an
    /// expired head blocks nothing beyond breaking its own run. The returned
    /// transactions are cloned and ready to hand to `build_block`.
    pub fn select_block(
        &self,
        state: &ChainState,
        config: &ChainConfig,
        max_units: u64,
        now_ms: u64,
    ) -> Vec<Transaction> {

        // Build each sender/lane's gap-free runnable run, in nonce order.
        let mut runs: BTreeMap<(Address, AuthorizationLaneId), Vec<&Entry>> = BTreeMap::new();
        for ((sender, lane, nonce), entry) in &self.entries {
            // Skip expired entries: they are pending removal and must not be
            // proposed.
            if now_ms.saturating_sub(entry.added_at_ms) >= self.config.ttl_ms {
                continue;
            }
            let Some(expected) = Self::expected_nonce(state, *sender, *lane) else {
                continue;
            };
            let run = runs.entry((*sender, *lane)).or_default();
            let wanted = expected + run.len() as u64;
            // Only extend the run if this is exactly the next contiguous nonce.
            if *nonce == wanted {
                run.push(entry);
            }
            // A gap ends the run; because BTreeMap iterates nonces ascending, any
            // later nonce for this group is non-contiguous and correctly ignored.
        }

        /// A heap element pointing at one group's current head transaction.
        struct Candidate<'a> {
            effective_fee: u64,
            key: (Address, AuthorizationLaneId),
            index: usize,
            entry: &'a Entry,
        }
        impl PartialEq for Candidate<'_> {
            fn eq(&self, other: &Self) -> bool {
                self.effective_fee == other.effective_fee && self.key == other.key
            }
        }
        impl Eq for Candidate<'_> {}
        impl Ord for Candidate<'_> {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                // Highest effective fee first; deterministic tie-break by key.
                self.effective_fee
                    .cmp(&other.effective_fee)
                    .then_with(|| self.key.cmp(&other.key))
            }
        }
        impl PartialOrd for Candidate<'_> {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        // Effective fee ignoring an unaffordable base fee: an underpriced head
        // disqualifies its whole run. Object operations are priced by their
        // namespace's localized base fee, account-scoped ones by the global base
        // fee (Phase 6 §8), so affordability and priority use the same per-operation
        // base fee the state machine will charge.
        let effective = |entry: &Entry| {
            let base_fee = state.base_fee_per_unit_for(&entry.tx.operation, config);
            entry.tx.fee.effective_fee_per_unit(base_fee).ok()
        };

        let mut heap: BinaryHeap<Candidate> = BinaryHeap::new();
        for (key, run) in &runs {
            if let Some(first) = run.first() {
                if let Some(fee) = effective(first) {
                    heap.push(Candidate {
                        effective_fee: fee,
                        key: *key,
                        index: 0,
                        entry: first,
                    });
                }
            }
        }

        // Fair packing (Phase 6 acceptance): defer a namespace once it reaches its
        // per-block share cap, but keep admitting other namespaces' transactions, so
        // one hot application cannot monopolize the block. Best-effort here — an
        // invalid policy falls back to the whole-block limit — because `build_block`
        // is the hard validity gate; this only shapes the proposer's selection.
        let namespace_unit_cap = config
            .fee_policy
            .namespace_block_unit_cap()
            .unwrap_or(config.fee_policy.max_block_units);
        let mut namespace_units: BTreeMap<Hash256, u64> = BTreeMap::new();

        let mut selected = Vec::new();
        let mut units_used = 0u64;
        while let Some(candidate) = heap.pop() {
            let required = candidate.entry.tx.required_units();
            let projected = units_used.saturating_add(required);
            if projected > max_units || projected > config.fee_policy.max_block_units {
                // Head does not fit; its later nonces cannot be included either,
                // so drop this group and keep filling from other senders.
                continue;
            }
            // Fair-packing cap for namespace-scoped (object) operations: if this
            // namespace is at its share, defer this group but keep filling others.
            let namespace_projected =
                if let Some(namespace) = candidate.entry.tx.operation.fee_namespace() {
                    let projected_ns = namespace_units
                        .get(&namespace)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(required);
                    if projected_ns > namespace_unit_cap {
                        continue;
                    }
                    Some((namespace, projected_ns))
                } else {
                    None
                };
            selected.push(candidate.entry.tx.clone());
            units_used = projected;
            if let Some((namespace, projected_ns)) = namespace_projected {
                namespace_units.insert(namespace, projected_ns);
            }

            // Advance this group's run to the next contiguous transaction.
            let run = &runs[&candidate.key];
            let next_index = candidate.index + 1;
            if let Some(next_entry) = run.get(next_index) {
                if let Some(fee) = effective(next_entry) {
                    heap.push(Candidate {
                        effective_fee: fee,
                        key: candidate.key,
                        index: next_index,
                        entry: next_entry,
                    });
                }
            }
        }
        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_chain::{Amount, ChainConfig, FeeBid, GenesisAccount, GenesisConfig, Operation};
    use webc_crypto::Keypair;

    const NOW: u64 = 1_000;

    fn keypair(seed: u8) -> Keypair {
        Keypair::from_seed([seed; 32])
    }

    /// A committed state funding each `(keypair, whole WEBC)` pair.
    fn funded_state(accounts: &[(&Keypair, u64)]) -> (ChainState, ChainConfig) {
        let genesis = GenesisConfig {
            chain: ChainConfig::default(),
            accounts: accounts
                .iter()
                .map(|(kp, whole)| GenesisAccount {
                    address: kp.address(),
                    balance: Amount::from_webc(*whole),
                })
                .collect(),
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).unwrap();
        (state, genesis.chain)
    }

    #[allow(clippy::too_many_arguments)]
    fn transfer(
        from: &Keypair,
        to: &Keypair,
        whole: u64,
        nonce: u64,
        max_fee: u64,
        priority: u64,
        gas: u64,
    ) -> Transaction {
        Transaction::for_operation(
            from,
            nonce,
            Operation::Transfer {
                to: to.address(),
                amount: Amount::from_webc(whole),
            },
            FeeBid {
                gas_limit: gas,
                max_fee_per_unit: max_fee,
                priority_fee_per_unit: priority,
            },
        )
        .unwrap()
    }

    fn create_object(from: &Keypair, namespace: Hash256, obj_seed: &[u8], nonce: u64) -> Transaction {
        Transaction::for_operation(
            from,
            nonce,
            Operation::CreateObject {
                object_id: webc_chain::ObjectId::new(Hash256::digest(obj_seed)),
                namespace,
                data: Vec::new(),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn fair_packing_defers_a_hot_namespace_but_admits_other_namespaces() {
        // Phase 6 acceptance: when one application namespace floods the pool, the
        // fair packer includes only up to its per-block share cap and defers the
        // rest, while still admitting an unrelated namespace's transactions — one
        // hot app cannot monopolize block capacity.
        let hot = keypair(1);
        let other = keypair(2);
        // A small block so the cap is a couple of object operations: cap =
        // 100_000 * 5000 / 10_000 = 50_000 units = 2 object operations (20_000 each);
        // a third would exceed it.
        let config = ChainConfig {
            fee_policy: webc_chain::FeePolicy {
                target_block_units: 50_000,
                max_block_units: 100_000,
                namespace_block_share_bps: 5_000,
                ..webc_chain::FeePolicy::default()
            },
            ..ChainConfig::default()
        };
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![
                GenesisAccount {
                    address: hot.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: other.address(),
                    balance: Amount::from_webc(1_000),
                },
            ],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).unwrap();
        let ns_hot = Hash256::digest(b"hot-namespace");
        let ns_other = Hash256::digest(b"other-namespace");

        let mut pool = Mempool::new(MempoolConfig::default());
        // Three object creates in the hot namespace (only two fit under the cap).
        for nonce in 0..3u64 {
            pool.insert(
                create_object(&hot, ns_hot, format!("hot-{nonce}").as_bytes(), nonce),
                &state,
                &config,
                NOW,
            )
            .unwrap();
        }
        // One object create in an unrelated namespace.
        pool.insert(
            create_object(&other, ns_other, b"other-0", 0),
            &state,
            &config,
            NOW,
        )
        .unwrap();

        let block = pool.select_block(&state, &config, u64::MAX, NOW);

        let hot_selected = block
            .iter()
            .filter(|tx| tx.operation.fee_namespace() == Some(ns_hot))
            .count();
        let other_selected = block
            .iter()
            .filter(|tx| tx.operation.fee_namespace() == Some(ns_other))
            .count();
        assert_eq!(
            hot_selected, 2,
            "the hot namespace is capped at its fair per-block share (2 object ops)"
        );
        assert_eq!(
            other_selected, 1,
            "an unrelated namespace's transaction is still admitted alongside the hot one"
        );
    }

    #[test]
    fn full_pool_evicts_lowest_fee_for_a_strictly_higher_bidder() {
        // H2: a full pool admits a strictly higher bidder by evicting the
        // lowest-fee entry, instead of rejecting it (which would let a low-fee
        // flood permanently block honest higher-fee transactions). The base fee
        // is 0 at genesis, so effective fee is the priority tip.
        let a = keypair(1);
        let b = keypair(2);
        let c = keypair(3);
        let d = keypair(4);
        let (state, config) = funded_state(&[(&a, 1_000), (&b, 1_000), (&c, 1_000), (&d, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig {
            max_transactions: 2,
            ..MempoolConfig::default()
        });

        // Fill the pool with two low-priority (effective-fee 1) transactions.
        pool.insert(transfer(&a, &b, 1, 0, 100, 1, 1_000), &state, &config, NOW)
            .unwrap();
        pool.insert(transfer(&b, &a, 1, 0, 100, 1, 1_000), &state, &config, NOW)
            .unwrap();
        assert_eq!(pool.len(), 2);

        // A strictly higher bidder (effective fee 10) evicts a lowest-fee entry.
        let outcome = pool
            .insert(transfer(&c, &a, 1, 0, 100, 10, 1_000), &state, &config, NOW)
            .unwrap();
        assert!(matches!(outcome, InsertOutcome::Added));
        assert_eq!(pool.len(), 2);

        // An equal-fee newcomer is still rejected when full — eviction is not a
        // free churn.
        assert!(matches!(
            pool.insert(transfer(&d, &a, 1, 0, 100, 1, 1_000), &state, &config, NOW),
            Err(MempoolError::Full)
        ));
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn full_pool_gapped_bid_cannot_evict_a_runnable_transaction() {
        // H2 hardening: a gapped (non-runnable) transaction can never be sealed —
        // `select_block` skips it forever — so it must not be able to evict a
        // runnable honest transaction merely by nominating a high fee. Otherwise
        // an attacker parks high-bid, never-includable transactions to churn
        // honest traffic out of a full pool for free (the free-churn vector the
        // eviction path claimed to prevent).
        let a = keypair(1);
        let b = keypair(2);
        let z = keypair(9);
        let (state, config) = funded_state(&[(&a, 1_000), (&b, 1_000), (&z, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig {
            max_transactions: 2,
            ..MempoolConfig::default()
        });

        // Fill the pool with two runnable (nonce 0) honest transactions.
        pool.insert(transfer(&a, &b, 1, 0, 100, 1, 1_000), &state, &config, NOW)
            .unwrap();
        pool.insert(transfer(&b, &a, 1, 0, 100, 1, 1_000), &state, &config, NOW)
            .unwrap();
        assert_eq!(pool.len(), 2);

        // A gapped high-fee bid (nonce 5 while the sender's expected nonce is 0,
        // effective fee 10) is rejected, not admitted by evicting a runnable
        // honest entry.
        assert!(matches!(
            pool.insert(transfer(&z, &a, 1, 5, 100, 10, 1_000), &state, &config, NOW),
            Err(MempoolError::Full)
        ));
        assert_eq!(pool.len(), 2);
        // Both honest runnable transactions survive and still seal.
        let block = pool.select_block(&state, &config, u64::MAX, NOW);
        assert_eq!(block.len(), 2);
    }

    #[test]
    fn full_pool_runnable_bid_evicts_a_parked_gap_entry() {
        // The dual of the guard above: a runnable newcomer outranks a parked
        // non-runnable entry even at a lower nominal fee, so honest traffic
        // actively clears never-includable junk from a full pool.
        let a = keypair(1);
        let z = keypair(9);
        let c = keypair(3);
        let (state, config) = funded_state(&[(&a, 1_000), (&z, 1_000), (&c, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig {
            max_transactions: 2,
            ..MempoolConfig::default()
        });

        // Fill the pool with one runnable honest tx and one parked gapped
        // high-fee tx (admitted while the pool still had room).
        pool.insert(transfer(&a, &z, 1, 0, 100, 1, 1_000), &state, &config, NOW)
            .unwrap();
        pool.insert(transfer(&z, &a, 1, 5, 100, 50, 1_000), &state, &config, NOW)
            .unwrap();
        assert_eq!(pool.len(), 2);

        // A runnable newcomer at a *lower* fee than the parked bid still gets in,
        // evicting the non-runnable junk rather than the runnable honest entry.
        let outcome = pool
            .insert(transfer(&c, &a, 1, 0, 100, 1, 1_000), &state, &config, NOW)
            .unwrap();
        assert!(matches!(outcome, InsertOutcome::Added));
        assert_eq!(pool.len(), 2);

        // The two runnable transactions (a, c) remain and seal; the parked gap
        // entry (z) is gone.
        let block = pool.select_block(&state, &config, u64::MAX, NOW);
        assert_eq!(block.len(), 2);
        let senders: std::collections::BTreeSet<_> = block.iter().map(|tx| tx.sender).collect();
        assert!(senders.contains(&a.address()));
        assert!(senders.contains(&c.address()));
        assert!(!senders.contains(&z.address()));
    }

    #[test]
    fn selects_highest_fee_across_senders_first() {
        let alice = keypair(1);
        let bob = keypair(2);
        let (state, config) = funded_state(&[(&alice, 1_000), (&bob, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig::default());

        // Bob bids a higher priority tip than Alice.
        pool.insert(
            transfer(&alice, &bob, 1, 0, 10, 2, 1_000),
            &state,
            &config,
            NOW,
        )
        .unwrap();
        pool.insert(
            transfer(&bob, &alice, 1, 0, 10, 9, 1_000),
            &state,
            &config,
            NOW,
        )
        .unwrap();

        let block = pool.select_block(&state, &config, u64::MAX, NOW);
        assert_eq!(block.len(), 2);
        assert_eq!(block[0].sender, bob.address());
        assert_eq!(block[1].sender, alice.address());
    }

    #[test]
    fn respects_nonce_contiguity_and_gaps() {
        let alice = keypair(1);
        let bob = keypair(2);
        let (state, config) = funded_state(&[(&alice, 1_000), (&bob, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig::default());

        // Insert nonces 0 and 2 (a gap at 1).
        pool.insert(
            transfer(&alice, &bob, 1, 0, 10, 1, 1_000),
            &state,
            &config,
            NOW,
        )
        .unwrap();
        pool.insert(
            transfer(&alice, &bob, 1, 2, 10, 1, 1_000),
            &state,
            &config,
            NOW,
        )
        .unwrap();

        // Only nonce 0 is runnable; the gap stops the run before nonce 2.
        let block = pool.select_block(&state, &config, u64::MAX, NOW);
        assert_eq!(block.len(), 1);
        assert_eq!(block[0].nonce, 0);

        // Filling the gap makes all three runnable, in strict nonce order.
        pool.insert(
            transfer(&alice, &bob, 1, 1, 10, 1, 1_000),
            &state,
            &config,
            NOW,
        )
        .unwrap();
        let block = pool.select_block(&state, &config, u64::MAX, NOW);
        let nonces: Vec<u64> = block.iter().map(|tx| tx.nonce).collect();
        assert_eq!(nonces, vec![0, 1, 2]);
    }

    #[test]
    fn rejects_stale_and_too_far_ahead_nonces() {
        let alice = keypair(1);
        let bob = keypair(2);
        let (mut state, config) = funded_state(&[(&alice, 1_000), (&bob, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig::default());

        // Advance Alice's account nonce to 5, so nonce 3 is already used.
        state.accounts.get_mut(&alice.address()).unwrap().nonce = 5;
        let err = pool
            .insert(
                transfer(&alice, &bob, 1, 3, 10, 1, 1_000),
                &state,
                &config,
                NOW,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            MempoolError::NonceTooLow {
                expected: 5,
                actual: 3
            }
        ));

        // Nonce 5 + 65 exceeds the default gap of 64.
        let err = pool
            .insert(
                transfer(&alice, &bob, 1, 70, 10, 1, 1_000),
                &state,
                &config,
                NOW,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            MempoolError::NonceTooFarAhead {
                expected: 5,
                actual: 70
            }
        ));
    }

    #[test]
    fn rejects_underpriced_and_unaffordable() {
        let alice = keypair(1);
        let bob = keypair(2);
        let (mut state, config) = funded_state(&[(&alice, 1_000), (&bob, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig::default());

        // Raise the base fee above the bid.
        state.current_base_fee_per_unit = 5;
        let err = pool
            .insert(
                transfer(&alice, &bob, 1, 0, 3, 0, 1_000),
                &state,
                &config,
                NOW,
            )
            .unwrap_err();
        assert!(matches!(err, MempoolError::Underpriced));

        // A payable-looking bid whose max fee cost dwarfs the balance is refused.
        state.current_base_fee_per_unit = 0;
        let poor = keypair(3);
        let (poor_state, poor_config) = funded_state(&[(&poor, 1)]);
        let err = pool
            .insert(
                transfer(&poor, &bob, 0, 0, 1_000_000, 0, 1_000_000_000),
                &poor_state,
                &poor_config,
                NOW,
            )
            .unwrap_err();
        assert!(matches!(err, MempoolError::InsufficientFeeFunds));
    }

    #[test]
    fn replacement_requires_a_fee_bump() {
        let alice = keypair(1);
        let bob = keypair(2);
        let (state, config) = funded_state(&[(&alice, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig::default());

        pool.insert(
            transfer(&alice, &bob, 1, 0, 10, 1, 1_000),
            &state,
            &config,
            NOW,
        )
        .unwrap();
        // Equal fee does not clear the +10% (min +1) bump floor.
        let err = pool
            .insert(
                transfer(&alice, &bob, 2, 0, 10, 1, 1_000),
                &state,
                &config,
                NOW,
            )
            .unwrap_err();
        assert!(matches!(err, MempoolError::ReplacementUnderpriced));

        // A sufficiently higher bid replaces the slot.
        let outcome = pool
            .insert(
                transfer(&alice, &bob, 3, 0, 12, 4, 1_000),
                &state,
                &config,
                NOW,
            )
            .unwrap();
        assert_eq!(outcome, InsertOutcome::Replaced);
        assert_eq!(pool.len(), 1);

        // Selection uses the replacement (transfers 3 WEBC, priority 4).
        let block = pool.select_block(&state, &config, u64::MAX, NOW);
        assert_eq!(block.len(), 1);
        assert_eq!(block[0].fee.max_fee_per_unit, 12);
    }

    #[test]
    fn prunes_expired_entries() {
        let alice = keypair(1);
        let bob = keypair(2);
        let (state, config) = funded_state(&[(&alice, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig {
            ttl_ms: 10_000,
            ..MempoolConfig::default()
        });

        pool.insert(
            transfer(&alice, &bob, 1, 0, 10, 1, 1_000),
            &state,
            &config,
            NOW,
        )
        .unwrap();
        // Not yet expired.
        assert_eq!(pool.prune_expired(NOW + 9_999), 0);
        assert_eq!(pool.len(), 1);
        // At/after the TTL, it is dropped, and selection would not propose it.
        assert!(pool
            .select_block(&state, &config, u64::MAX, NOW + 10_000)
            .is_empty());
        assert_eq!(pool.prune_expired(NOW + 10_000), 1);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn unit_budget_limits_selection() {
        let alice = keypair(1);
        let bob = keypair(2);
        let (state, config) = funded_state(&[(&alice, 1_000), (&bob, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig::default());

        let alice_tx = transfer(&alice, &bob, 1, 0, 10, 2, 1_000);
        let bob_tx = transfer(&bob, &alice, 1, 0, 10, 9, 1_000);
        let one_unit = bob_tx.required_units();
        pool.insert(alice_tx, &state, &config, NOW).unwrap();
        pool.insert(bob_tx, &state, &config, NOW).unwrap();

        // A budget for exactly one transaction admits only the higher bid (bob).
        let block = pool.select_block(&state, &config, one_unit, NOW);
        assert_eq!(block.len(), 1);
        assert_eq!(block[0].sender, bob.address());
    }

    #[test]
    fn remove_obsolete_drops_included_nonces() {
        let alice = keypair(1);
        let bob = keypair(2);
        let (mut state, config) = funded_state(&[(&alice, 1_000)]);
        let mut pool = Mempool::new(MempoolConfig::default());

        pool.insert(
            transfer(&alice, &bob, 1, 0, 10, 1, 1_000),
            &state,
            &config,
            NOW,
        )
        .unwrap();
        pool.insert(
            transfer(&alice, &bob, 1, 1, 10, 1, 1_000),
            &state,
            &config,
            NOW,
        )
        .unwrap();

        // A committed block advanced Alice's nonce to 1: nonce 0 is now obsolete.
        state.accounts.get_mut(&alice.address()).unwrap().nonce = 1;
        assert_eq!(pool.remove_obsolete(&state), 1);
        assert_eq!(pool.len(), 1);
        let block = pool.select_block(&state, &config, u64::MAX, NOW);
        assert_eq!(block.len(), 1);
        assert_eq!(block[0].nonce, 1);
    }
}
