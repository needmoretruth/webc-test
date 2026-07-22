//! Transport-independent node service: the query and command core behind the API.
//!
//! Purpose: expose everything a developer API needs — health, account/object
//! queries, account proofs, block lookups, fee state, transaction submission,
//! block sealing, and a devnet faucet — as plain synchronous methods over the
//! node, mempool, and storage. Keeping this layer free of HTTP/WebSocket lets it
//! be unit-tested without a socket; the axum layer is a thin transport on top.
//!
//! Boundaries: it owns the single source of mutable node state behind one lock,
//! so concurrent API requests serialize cleanly. It reads no clock — callers pass
//! `now_ms` — so behavior stays deterministic and testable. It performs no
//! networking.
//!
//! Security: all inputs are hostile. Submitted transactions pass through the
//! mempool's full validation and, at seal time, the fail-closed `build_block`
//! authority. The faucet is devnet-only, rate-limited per recipient, refuses to
//! top up already-funded accounts, and labels its drips as valueless test units.

use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Mutex;

use webc_chain::{
    Account, AccountStateProof, Amount, Block, ChainError, FeeBid, GovProposalStatus,
    GovernanceInstance, GovernanceInstanceId, GovernanceProposal, Mandate, MandateId,
    NftCollection, NftCollectionId, NftId, NftItem, ObjectId, Operation, ProposalId, ServiceEntry,
    ServiceId, StateObject, SupplyInvariantReport, TokenId, TokenRecord, TokenSupplyReport,
    Transaction, Validator,
};
use webc_crypto::{Address, Hash256, Keypair};
use webc_storage::{KvStore, StorageError};

use crate::mempool::{Mempool, MempoolConfig, MempoolError};
use crate::node::{Node, NodeError};

/// Stable API contract version exposed in responses and route prefixes.
pub const API_VERSION: &str = "v1";

/// Errors surfaced to API callers, mapped to HTTP status codes by the transport.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// The requested resource (account, block, object) does not exist.
    #[error("not found")]
    NotFound,
    /// The request was structurally invalid (e.g. an unparseable identifier).
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// A submitted transaction was refused by the mempool.
    #[error("transaction rejected: {0}")]
    Rejected(#[from] MempoolError),
    /// Block production failed while sealing.
    #[error("block production failed: {0}")]
    Node(#[from] NodeError),
    /// A durable storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    /// The faucet is not enabled on this node (non-devnet).
    #[error("faucet is disabled")]
    FaucetDisabled,
    /// The recipient requested a drip again before its cooldown elapsed.
    #[error("faucet cooldown has not elapsed for this recipient")]
    FaucetCooldown,
    /// The recipient already holds at least the faucet's top-up ceiling.
    #[error("recipient already holds enough devnet funds")]
    FaucetRecipientFunded,
    /// An internal invariant failed (should not happen).
    #[error("internal error: {0}")]
    Internal(String),
}

/// Devnet faucet parameters. Present only when a node runs a valueless devnet.
///
/// The faucet drips native test units from a genesis-funded account it signs for.
/// It is **devnet only** and never represents real value.
pub struct FaucetConfig {
    /// Keypair of the genesis-funded faucet account.
    pub keypair: Keypair,
    /// Native base units sent per successful drip.
    pub drip_amount: Amount,
    /// Minimum milliseconds between drips to the same recipient.
    pub cooldown_ms: u64,
    /// Skip topping up any recipient already at or above this balance.
    pub max_recipient_balance: Amount,
}

/// Global faucet burst capacity, in drips (H1 token bucket).
///
/// Per-recipient cooldown/balance caps do not bound work from an attacker who
/// rotates through unlimited fresh addresses — each drip builds and durably
/// commits a full block. A global token bucket bounds the total drip rate
/// regardless of recipient: at most this many drips may burst before the
/// refill rate takes over.
const FAUCET_GLOBAL_BURST: u64 = 100;

/// Milliseconds to refill one global faucet token (H1) — a sustained ~1 drip/s.
const FAUCET_GLOBAL_REFILL_MS: u64 = 1_000;

/// Runtime faucet state: its config, recent per-recipient drip times, and the
/// global rate-limit token bucket.
struct Faucet {
    config: FaucetConfig,
    last_drip_ms: BTreeMap<Address, u64>,
    /// Available global drip tokens (H1). Bounded by `FAUCET_GLOBAL_BURST`.
    tokens: u64,
    /// Timestamp the bucket was last refilled from, in Unix ms.
    last_refill_ms: u64,
}

impl Faucet {
    /// Refills the global token bucket for elapsed time, capped at the burst.
    ///
    /// Deterministic and monotonic: it only ever advances `last_refill_ms` by
    /// whole-token intervals, so no fractional time is lost and a stalled or
    /// non-monotonic clock cannot mint extra tokens.
    fn refill_tokens(&mut self, now_ms: u64) {
        let elapsed = now_ms.saturating_sub(self.last_refill_ms);
        let refilled = elapsed / FAUCET_GLOBAL_REFILL_MS;
        if refilled > 0 {
            self.tokens = self
                .tokens
                .saturating_add(refilled)
                .min(FAUCET_GLOBAL_BURST);
            self.last_refill_ms = self
                .last_refill_ms
                .saturating_add(refilled.saturating_mul(FAUCET_GLOBAL_REFILL_MS));
        }
    }
}

/// Construction options for a [`NodeService`].
pub struct NodeServiceOptions {
    /// Mempool tuning.
    pub mempool: MempoolConfig,
    /// Optional devnet faucet.
    pub faucet: Option<FaucetConfig>,
    /// Operator address recorded as the proposer of sealed blocks.
    pub proposer: Address,
}

/// The mutable core guarded by one lock.
struct Inner<K: KvStore> {
    node: Node<K>,
    mempool: Mempool,
    faucet: Option<Faucet>,
    proposer: Address,
}

/// A thread-safe, transport-independent facade over the node.
pub struct NodeService<K: KvStore> {
    inner: Mutex<Inner<K>>,
}

/// Node health and identity summary.
#[derive(Debug, serde::Serialize)]
pub struct HealthSummary {
    pub api_version: &'static str,
    pub chain_id: String,
    pub height: u64,
    pub tip_hash: Option<Hash256>,
    pub state_root: Option<Hash256>,
    pub mempool_size: usize,
    pub faucet_enabled: bool,
}

/// Current fee state clients use to price transactions.
#[derive(Debug, serde::Serialize)]
pub struct FeeSummary {
    pub api_version: &'static str,
    pub base_fee_per_unit: u64,
    pub max_block_units: u64,
}

/// An account snapshot with its address.
#[derive(Debug, serde::Serialize)]
pub struct AccountSummary {
    pub address: Address,
    pub account: Account,
}

/// A validator snapshot with its derived total stake. Public, read-only.
#[derive(Debug, serde::Serialize)]
pub struct ValidatorSummary {
    #[serde(flatten)]
    pub validator: Validator,
    pub total_stake: Amount,
}

/// The public validator set with its API version.
#[derive(Debug, serde::Serialize)]
pub struct ValidatorsResponse {
    pub api_version: &'static str,
    pub validators: Vec<ValidatorSummary>,
}

/// The classified outcome of admitting a gossiped transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkAdmission {
    /// The transaction was new and entered (or replaced within) the mempool.
    Accepted,
    /// The transaction was refused (stale, duplicate, invalid, or full mempool).
    Rejected,
}

/// The result of admitting a transaction to the mempool.
#[derive(Debug, serde::Serialize)]
pub struct SubmitReceipt {
    pub tx_hash: Hash256,
    pub accepted: bool,
    pub mempool_size: usize,
}

/// A summary of a freshly sealed block.
#[derive(Debug, serde::Serialize)]
pub struct SealSummary {
    pub height: u64,
    pub block_hash: Hash256,
    pub transaction_count: usize,
    pub state_root: Hash256,
}

/// The result of a successful faucet drip. `disclaimer` is always present so no
/// client can mistake devnet units for value.
#[derive(Debug, serde::Serialize)]
pub struct FaucetReceipt {
    pub recipient: Address,
    pub amount: Amount,
    pub block_height: u64,
    pub new_balance: Amount,
    pub disclaimer: &'static str,
}

/// Fixed devnet disclaimer text attached to every faucet drip.
const FAUCET_DISCLAIMER: &str =
    "DEVNET faucet: these are valueless WEBC test units, not real funds.";

impl<K: KvStore> NodeService<K> {
    /// Wraps a node, mempool, and optional faucet into a service.
    pub fn new(node: Node<K>, options: NodeServiceOptions) -> Self {
        let faucet = options.faucet.map(|config| Faucet {
            config,
            last_drip_ms: BTreeMap::new(),
            tokens: FAUCET_GLOBAL_BURST,
            last_refill_ms: 0,
        });
        Self {
            inner: Mutex::new(Inner {
                node,
                mempool: Mempool::new(options.mempool),
                faucet,
                proposer: options.proposer,
            }),
        }
    }

    /// Locks the inner core, recovering from a poisoned lock by taking the guard
    /// anyway: a panic in one request must not wedge the whole node, and every
    /// mutation is a single atomic method, so no half-applied state can leak.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner<K>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Returns node health and identity.
    pub fn health(&self) -> HealthSummary {
        let inner = self.lock();
        let tip = inner.node.store().tip().ok().flatten();
        HealthSummary {
            api_version: API_VERSION,
            chain_id: inner.node.config().chain_id.to_string(),
            height: inner.node.height(),
            tip_hash: tip.as_ref().and_then(|t| t.block_hash),
            state_root: tip.as_ref().map(|t| t.state_root),
            mempool_size: inner.mempool.len(),
            faucet_enabled: inner.faucet.is_some(),
        }
    }

    /// Returns the current fee state.
    pub fn fees(&self) -> FeeSummary {
        let inner = self.lock();
        FeeSummary {
            api_version: API_VERSION,
            base_fee_per_unit: inner.node.state().current_base_fee_per_unit,
            max_block_units: inner.node.config().fee_policy.max_block_units,
        }
    }

    /// Returns an account snapshot, or `NotFound` if the account is absent.
    pub fn account(&self, address: Address) -> Result<AccountSummary, ApiError> {
        let inner = self.lock();
        let account = inner
            .node
            .state()
            .accounts
            .get(&address)
            .cloned()
            .ok_or(ApiError::NotFound)?;
        Ok(AccountSummary { address, account })
    }

    /// Returns every validator with its derived total stake, in deterministic
    /// address order. Public, read-only performance/stake data.
    pub fn validators(&self) -> Result<ValidatorsResponse, ApiError> {
        let inner = self.lock();
        let validators = inner
            .node
            .state()
            .validators
            .values()
            .map(|validator| {
                Ok(ValidatorSummary {
                    validator: validator.clone(),
                    total_stake: validator
                        .total_stake()
                        .map_err(|error| ApiError::Internal(error.to_string()))?,
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        Ok(ValidatorsResponse {
            api_version: API_VERSION,
            validators,
        })
    }

    /// Returns a single validator by operator address, or `NotFound`.
    pub fn validator(&self, address: Address) -> Result<ValidatorSummary, ApiError> {
        let inner = self.lock();
        let validator = inner
            .node
            .state()
            .validators
            .get(&address)
            .cloned()
            .ok_or(ApiError::NotFound)?;
        let total_stake = validator
            .total_stake()
            .map_err(|error| ApiError::Internal(error.to_string()))?;
        Ok(ValidatorSummary {
            validator,
            total_stake,
        })
    }

    /// Returns the deterministic supply-invariant reconciliation (gross issuance
    /// vs. every value bucket). Public, read-only monetary transparency.
    pub fn supply(&self) -> Result<SupplyInvariantReport, ApiError> {
        let inner = self.lock();
        inner
            .node
            .state()
            .supply_invariant_report()
            .map_err(|error| ApiError::Internal(error.to_string()))
    }

    /// Returns a Merkle proof of an account against the current account root.
    pub fn account_proof(&self, address: Address) -> Result<AccountStateProof, ApiError> {
        let inner = self.lock();
        // A membership proof exists only for an account that is present; an absent
        // account yields `None`, surfaced as NotFound.
        inner
            .node
            .state()
            .account_state_proof(address)
            .map_err(|error| ApiError::Internal(error.to_string()))?
            .ok_or(ApiError::NotFound)
    }

    /// Returns a persistent object by id, or `NotFound`.
    pub fn object(&self, id: ObjectId) -> Result<StateObject, ApiError> {
        let inner = self.lock();
        inner
            .node
            .state()
            .objects
            .get(&id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    /// Returns the finalized block at `height`, or `NotFound`.
    pub fn block_by_height(&self, height: u64) -> Result<Block, ApiError> {
        let inner = self.lock();
        inner
            .node
            .store()
            .block_by_height(height)?
            .ok_or(ApiError::NotFound)
    }

    /// Returns the finalized block with `hash`, or `NotFound`.
    pub fn block_by_hash(&self, hash: Hash256) -> Result<Block, ApiError> {
        let inner = self.lock();
        inner
            .node
            .store()
            .block_by_hash(&hash)?
            .ok_or(ApiError::NotFound)
    }

    /// Admits a transaction that arrived over gossip from a peer.
    ///
    /// Unlike [`Self::submit_transaction`], a peer legitimately re-sends
    /// transactions the node already knows, so this never surfaces an error: it
    /// classifies the outcome instead. A rejected transaction (stale nonce,
    /// duplicate, invalid signature, full mempool) is simply dropped. Peer
    /// scoring on repeated rejections is later work.
    pub fn admit_network_transaction(&self, tx: Transaction, now_ms: u64) -> NetworkAdmission {
        let mut inner = self.lock();
        let Inner { node, mempool, .. } = &mut *inner;
        match mempool.insert(tx, node.state(), node.config(), now_ms) {
            Ok(_) => NetworkAdmission::Accepted,
            Err(_) => NetworkAdmission::Rejected,
        }
    }

    /// Admits a transaction to the mempool after full validation.
    pub fn submit_transaction(
        &self,
        tx: Transaction,
        now_ms: u64,
    ) -> Result<SubmitReceipt, ApiError> {
        let tx_hash = tx
            .hash()
            .map_err(|error: ChainError| ApiError::InvalidRequest(error.to_string()))?;
        let mut inner = self.lock();
        let Inner { node, mempool, .. } = &mut *inner;
        mempool.insert(tx, node.state(), node.config(), now_ms)?;
        Ok(SubmitReceipt {
            tx_hash,
            accepted: true,
            mempool_size: mempool.len(),
        })
    }

    /// Seals the next block from the highest-priority runnable mempool
    /// transactions, or returns `None` when the mempool has nothing to include.
    ///
    /// `now_ms` becomes the block timestamp. On success the block is committed
    /// durably and included transactions are dropped from the mempool.
    pub fn seal_block(&self, now_ms: u64) -> Result<Option<SealSummary>, ApiError> {
        let mut inner = self.lock();
        let Inner {
            node,
            mempool,
            proposer,
            ..
        } = &mut *inner;
        // H2: prune expired transactions every seal tick, before selection, so a
        // pool filled with expired entries frees its slots instead of staying
        // permanently full (only `remove_obsolete` ran here before, which drops
        // nonce-obsolete txs but never TTL-expired ones).
        mempool.prune_expired(now_ms);
        let max_units = node.config().fee_policy.max_block_units;
        let selected = mempool.select_block(node.state(), node.config(), max_units, now_ms);
        if selected.is_empty() {
            return Ok(None);
        }
        let count = selected.len();
        let block = node.produce_block(selected, Vec::new(), *proposer, now_ms)?;
        mempool.remove_obsolete(node.state());
        Ok(Some(SealSummary {
            height: block.header.height,
            block_hash: block
                .hash()
                .map_err(|e| ApiError::Internal(e.to_string()))?,
            transaction_count: count,
            state_root: block.header.state_root,
        }))
    }

    /// Drips valueless devnet funds to `recipient` and seals a block so the funds
    /// are immediately final.
    ///
    /// Fails with [`ApiError::FaucetDisabled`] off devnet, [`ApiError::FaucetCooldown`]
    /// if the recipient drank too recently, or [`ApiError::FaucetRecipientFunded`]
    /// if the recipient already holds the ceiling balance.
    pub fn faucet_drip(&self, recipient: Address, now_ms: u64) -> Result<FaucetReceipt, ApiError> {
        let mut inner = self.lock();
        let Inner {
            node,
            mempool,
            faucet,
            proposer,
        } = &mut *inner;
        let faucet = faucet.as_mut().ok_or(ApiError::FaucetDisabled)?;

        // H1: global rate limit BEFORE any per-recipient check or block work, so
        // an attacker rotating fresh addresses cannot force unbounded block
        // builds. Refill for elapsed time, then require and consume one token.
        faucet.refill_tokens(now_ms);
        if faucet.tokens == 0 {
            return Err(ApiError::FaucetCooldown);
        }

        // Per-recipient cooldown.
        if let Some(last) = faucet.last_drip_ms.get(&recipient) {
            if now_ms.saturating_sub(*last) < faucet.config.cooldown_ms {
                return Err(ApiError::FaucetCooldown);
            }
        }
        // Do not top up an already-funded recipient.
        if let Some(account) = node.state().accounts.get(&recipient) {
            if account.balance >= faucet.config.max_recipient_balance {
                return Err(ApiError::FaucetRecipientFunded);
            }
        }

        // Commit to the work: consume one global token now that the cheap
        // rejections (cooldown, already-funded) have passed (H1).
        faucet.tokens -= 1;

        // Build a faucet-signed transfer at the faucet account's next nonce.
        let faucet_address = faucet.config.keypair.address();
        let nonce = node
            .state()
            .accounts
            .get(&faucet_address)
            .ok_or_else(|| ApiError::Internal("faucet account is not funded in genesis".into()))?
            .nonce;
        let base_fee = node.state().current_base_fee_per_unit;
        let tx = Transaction::for_operation(
            &faucet.config.keypair,
            nonce,
            Operation::Transfer {
                to: recipient,
                amount: faucet.config.drip_amount,
            },
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: base_fee.max(1),
                priority_fee_per_unit: 0,
            },
        )
        .map_err(|error| ApiError::Internal(error.to_string()))?;

        mempool.insert(tx, node.state(), node.config(), now_ms)?;

        // Seal immediately so the drip is final for the caller.
        let max_units = node.config().fee_policy.max_block_units;
        let selected = mempool.select_block(node.state(), node.config(), max_units, now_ms);
        let block = node.produce_block(selected, Vec::new(), *proposer, now_ms)?;
        mempool.remove_obsolete(node.state());

        faucet.last_drip_ms.insert(recipient, now_ms);
        // H1: bound `last_drip_ms` growth — once a recipient's cooldown has fully
        // elapsed its entry can no longer cause a rejection, so drop it. This
        // caps the map to recipients dripped within one cooldown window.
        let cooldown = faucet.config.cooldown_ms;
        faucet
            .last_drip_ms
            .retain(|_, last| now_ms.saturating_sub(*last) < cooldown);
        let new_balance = node
            .state()
            .accounts
            .get(&recipient)
            .map(|account| account.balance)
            .unwrap_or(Amount::ZERO);

        Ok(FaucetReceipt {
            recipient,
            amount: faucet.config.drip_amount,
            block_height: block.header.height,
            new_balance,
            disclaimer: FAUCET_DISCLAIMER,
        })
    }
}

impl<K: KvStore> NodeService<K> {
    /// Submits `tx` and immediately seals a block so the transaction is final.
    ///
    /// A convenience for local/devnet drivers — the CLI staking subcommands and
    /// tests — that want a submitted transaction to reach a committed block in a
    /// single call. `now_ms` is supplied by the caller (this reads no clock), so
    /// the flow stays deterministic. It errors if the mempool rejects the
    /// transaction or if, unexpectedly, nothing seals (e.g. the transaction was
    /// not runnable at selection time).
    pub fn submit_and_seal(&self, tx: Transaction, now_ms: u64) -> Result<SealSummary, ApiError> {
        self.submit_transaction(tx, now_ms)?;
        self.seal_block(now_ms)?.ok_or_else(|| {
            ApiError::Internal("submitted transaction did not seal into a block".to_owned())
        })
    }
}

/// Read accessors for the Phase 9/13 native state (tokens, NFTs, service
/// registry, governance, mandates).
///
/// Each is a pure point-read of the current committed [`webc_chain::ChainState`]
/// maps — the same shape as [`Self::account`] / [`Self::object`] — cloning the
/// requested record out under the single service lock and mapping an absent key
/// to [`ApiError::NotFound`]. They reuse the record types' own `Serialize`
/// derives (no wrapper types) and read no clock, so they are deterministic and
/// safe to expose to hostile callers.
impl<K: KvStore> NodeService<K> {
    /// Returns a native token's authority/supply record, or `NotFound`.
    pub fn token(&self, token_id: TokenId) -> Result<TokenRecord, ApiError> {
        let inner = self.lock();
        inner
            .node
            .state()
            .tokens
            .get(&token_id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    /// Returns `holder`'s balance of `token_id`.
    ///
    /// Zero-vs-404 choice: mirrors the chain's own balance semantics, where an
    /// absent `(token, holder)` entry is indistinguishable from a zero balance (a
    /// transfer prunes an entry that reaches zero — see `token_balances`). Once
    /// the token exists, every address holds a well-defined balance of it,
    /// [`Amount::ZERO`] when it holds none, so a holder with no entry is `200`
    /// with zero rather than `404`. An UNKNOWN token is `NotFound`: reporting zero
    /// for a nonexistent token would falsely imply the token exists, and this
    /// matches how [`Self::account`] 404s an absent account rather than inventing
    /// a zero.
    pub fn token_balance(&self, token_id: TokenId, holder: Address) -> Result<Amount, ApiError> {
        let inner = self.lock();
        let state = inner.node.state();
        if !state.tokens.contains_key(&token_id) {
            return Err(ApiError::NotFound);
        }
        Ok(state
            .token_balances
            .get(&(token_id, holder))
            .copied()
            .unwrap_or(Amount::ZERO))
    }

    /// Returns the per-token supply reconciliation (issued vs. held), or
    /// `NotFound` for an unknown token.
    ///
    /// Reuses [`webc_chain::ChainState::token_supply_report`]; an inconsistency in
    /// the committed state (never reachable through the state transitions) is an
    /// internal error, not a client error.
    pub fn token_supply(&self, token_id: TokenId) -> Result<TokenSupplyReport, ApiError> {
        let inner = self.lock();
        let state = inner.node.state();
        if !state.tokens.contains_key(&token_id) {
            return Err(ApiError::NotFound);
        }
        state
            .token_supply_report(token_id)
            .map_err(|error| ApiError::Internal(error.to_string()))
    }

    /// Returns a native NFT collection record, or `NotFound`.
    pub fn nft_collection(
        &self,
        collection_id: NftCollectionId,
    ) -> Result<NftCollection, ApiError> {
        let inner = self.lock();
        inner
            .node
            .state()
            .nft_collections
            .get(&collection_id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    /// Returns a single NFT item (owner, frozen flag, metadata commitment), or
    /// `NotFound`.
    pub fn nft_item(&self, nft_id: NftId) -> Result<NftItem, ApiError> {
        let inner = self.lock();
        inner
            .node
            .state()
            .nft_items
            .get(&nft_id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    /// Returns a registered service entry (the full current revision: owner,
    /// categories, pricing, payment flags, status), or `NotFound`. This is the
    /// read the SDK's HTTP-402 `validateChallenge` needs so a caller no longer has
    /// to supply the `ServiceEntry` itself.
    pub fn service_entry(&self, service_id: ServiceId) -> Result<ServiceEntry, ApiError> {
        let inner = self.lock();
        inner
            .node
            .state()
            .services
            .get(&service_id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    /// Returns a governance instance record, or `NotFound`.
    pub fn governance_instance(
        &self,
        instance_id: GovernanceInstanceId,
    ) -> Result<GovernanceInstance, ApiError> {
        let inner = self.lock();
        inner
            .node
            .state()
            .governance_instances
            .get(&instance_id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    /// Returns a governance proposal record (status, tallies, eta), or `NotFound`.
    pub fn governance_proposal(
        &self,
        proposal_id: ProposalId,
    ) -> Result<GovernanceProposal, ApiError> {
        let inner = self.lock();
        inner
            .node
            .state()
            .governance_proposals
            .get(&proposal_id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }

    /// Returns a mandate record (budget/spent/expiry/revoked/counterparty policy),
    /// or `NotFound`.
    pub fn mandate(&self, mandate_id: MandateId) -> Result<Mandate, ApiError> {
        let inner = self.lock();
        inner
            .node
            .state()
            .mandates
            .get(&mandate_id)
            .cloned()
            .ok_or(ApiError::NotFound)
    }
}

// ----- paginated discovery / list accessors (Phase 9/13 native state) -----

/// Default page size when a caller supplies no `limit`.
pub const DEFAULT_PAGE_LIMIT: usize = 50;

/// Hard upper bound on a page size. A larger requested `limit` is clamped to this,
/// so an unauthenticated caller can never force an unbounded response out of a map
/// that grows without limit.
pub const MAX_PAGE_LIMIT: usize = 200;

/// Per-request scan multiplier for FILTERED list pages (e.g. services-by-category).
/// Such a page examines at most `FILTER_SCAN_MULTIPLIER * limit` map entries even if
/// fewer (or none) match, then returns a `next_cursor` so the client continues —
/// this bounds the work one request can cost over a sparse filter regardless of map
/// size.
const FILTER_SCAN_MULTIPLIER: usize = 4;

/// Clamps a requested page limit into `1..=MAX_PAGE_LIMIT`, applying
/// `DEFAULT_PAGE_LIMIT` when unset. A `0` clamps up to `1` so a page always makes
/// forward progress (a zero-size page with a cursor could never advance).
fn clamp_limit(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAX_PAGE_LIMIT)
}

/// Decodes an opaque hash-shaped cursor (32-byte lowercase hex) into a `Hash256`,
/// mapping any malformed input to a fail-closed `InvalidRequest`.
fn decode_hash_cursor(raw: &str) -> Result<Hash256, ApiError> {
    let bytes = hex::decode(raw).map_err(|_| ApiError::InvalidRequest("invalid cursor".into()))?;
    let fixed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ApiError::InvalidRequest("invalid cursor".into()))?;
    Ok(Hash256(fixed))
}

/// Encodes a `(TokenId, Address)` balance key as the opaque cursor
/// `"{token_hex}:{address_hex}"` (both 32-byte lowercase hex). The FULL key is
/// carried so a resumed scan advances strictly past the last VISITED entry — never
/// only the last match — guaranteeing forward progress through non-matching runs.
fn encode_token_holder_cursor(token_id: TokenId, holder: Address) -> String {
    format!(
        "{}:{}",
        token_id.hash().to_hex(),
        hex::encode(holder.as_bytes())
    )
}

/// Decodes a `(TokenId, Address)` balance cursor, fail-closed on any malformation.
fn decode_token_holder_cursor(raw: &str) -> Result<(TokenId, Address), ApiError> {
    let (token_hex, addr_hex) = raw
        .split_once(':')
        .ok_or_else(|| ApiError::InvalidRequest("invalid cursor".into()))?;
    let token_id = TokenId::new(decode_hash_cursor(token_hex)?);
    let addr_bytes =
        hex::decode(addr_hex).map_err(|_| ApiError::InvalidRequest("invalid cursor".into()))?;
    let addr_fixed: [u8; 32] = addr_bytes
        .try_into()
        .map_err(|_| ApiError::InvalidRequest("invalid cursor".into()))?;
    Ok((token_id, Address::from_bytes(addr_fixed)))
}

/// One entry in a services listing: the service's id alongside its full current
/// `ServiceEntry` revision (the record's own serialization, flattened in).
#[derive(Debug, serde::Serialize)]
pub struct ServiceListItem {
    pub service_id: ServiceId,
    #[serde(flatten)]
    pub entry: ServiceEntry,
}

/// A paginated services page: `next_cursor` is non-null iff more may remain.
#[derive(Debug, serde::Serialize)]
pub struct ServicesPage {
    pub items: Vec<ServiceListItem>,
    pub next_cursor: Option<String>,
}

/// One entry in a collection's items listing: the item's serial alongside its
/// full `NftItem` record (the record's own serialization, flattened in).
#[derive(Debug, serde::Serialize)]
pub struct NftItemListItem {
    pub serial: u64,
    #[serde(flatten)]
    pub item: NftItem,
}

/// A paginated NFT-collection-items page.
#[derive(Debug, serde::Serialize)]
pub struct NftItemsPage {
    pub items: Vec<NftItemListItem>,
    pub next_cursor: Option<String>,
}

/// One entry in an instance's proposals listing: the proposal's id alongside its
/// full `GovernanceProposal` record (the record's own serialization, flattened in).
#[derive(Debug, serde::Serialize)]
pub struct ProposalListItem {
    pub proposal_id: ProposalId,
    #[serde(flatten)]
    pub proposal: GovernanceProposal,
}

/// A paginated governance-proposals page.
#[derive(Debug, serde::Serialize)]
pub struct ProposalsPage {
    pub items: Vec<ProposalListItem>,
    pub next_cursor: Option<String>,
}

/// One entry in an address's token-balances listing: the token id and the held
/// amount (the holder is fixed by the request path).
#[derive(Debug, serde::Serialize)]
pub struct TokenBalanceListItem {
    pub token_id: TokenId,
    pub balance: Amount,
}

/// A paginated token-balances page.
#[derive(Debug, serde::Serialize)]
pub struct TokenBalancesPage {
    pub items: Vec<TokenBalanceListItem>,
    pub next_cursor: Option<String>,
}

/// One entry in an address's mandates listing: the mandate's id alongside its full
/// `Mandate` record (the record's own serialization, flattened in).
#[derive(Debug, serde::Serialize)]
pub struct MandateListItem {
    pub mandate_id: MandateId,
    #[serde(flatten)]
    pub mandate: Mandate,
}

/// A paginated mandates page.
#[derive(Debug, serde::Serialize)]
pub struct MandatesPage {
    pub items: Vec<MandateListItem>,
    pub next_cursor: Option<String>,
}

/// Bounded, cursor-paginated DISCOVERY reads over the Phase 9/13 native-state maps.
///
/// Every accessor here is a pure, deterministic ASCENDING walk of a committed
/// `webc_chain::ChainState` `BTreeMap`, taken under the single service lock, that
/// clones out at most `limit` records and returns an opaque `next_cursor` (the last
/// key it visited) so the client can resume. A FILTERED walk additionally caps the
/// scan at `FILTER_SCAN_MULTIPLIER * limit` VISITED entries, matching or not, then
/// hands back a cursor — this bounds the per-request work over a sparse filter so a
/// hostile query can never force a whole-map scan.
///
/// A malformed cursor/limit/id maps to `ApiError::InvalidRequest`. Nothing here
/// reads a clock, network, or randomness, and nothing panics on hostile input.
impl<K: KvStore> NodeService<K> {
    /// Lists registered services in ascending `ServiceId` order. With `category`,
    /// returns only entries whose `categories` set contains that tag (a bounded
    /// filtered scan); without it, lists every service (a bounded range).
    pub fn services(
        &self,
        category: Option<Hash256>,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<ServicesPage, ApiError> {
        let limit = clamp_limit(limit);
        let max_scan = limit.saturating_mul(FILTER_SCAN_MULTIPLIER);
        let inner = self.lock();
        let services = &inner.node.state().services;

        let start = match cursor {
            Some(raw) => Bound::Excluded(ServiceId::new(decode_hash_cursor(raw)?)),
            None => Bound::Unbounded,
        };

        let mut items = Vec::new();
        let mut next_cursor = None;
        let mut scanned = 0usize;
        for (id, entry) in services.range((start, Bound::Unbounded)) {
            scanned += 1;
            let matched = match &category {
                Some(tag) => entry.categories.contains(tag),
                None => true,
            };
            if matched {
                items.push(ServiceListItem {
                    service_id: *id,
                    entry: entry.clone(),
                });
                if items.len() >= limit {
                    next_cursor = Some(id.hash().to_hex());
                    break;
                }
            }
            if scanned >= max_scan {
                next_cursor = Some(id.hash().to_hex());
                break;
            }
        }
        Ok(ServicesPage { items, next_cursor })
    }

    /// Lists a collection's live items ascending by serial. This is a contiguous
    /// range over `nft_items` (keyed by `(collection, serial)`, ordered by that
    /// pair), so it needs no filter scan bound — every visited key is an item of the
    /// collection, and the page is bounded by `limit` alone. The collection must
    /// exist, else `NotFound` (mirroring the item point-read). The cursor is the
    /// last serial returned; the next page starts strictly after it.
    pub fn nft_collection_items(
        &self,
        collection_id: NftCollectionId,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<NftItemsPage, ApiError> {
        let limit = clamp_limit(limit);
        let inner = self.lock();
        let state = inner.node.state();
        if !state.nft_collections.contains_key(&collection_id) {
            return Err(ApiError::NotFound);
        }

        let start = match cursor {
            Some(raw) => {
                let serial: u64 = raw
                    .parse()
                    .map_err(|_| ApiError::InvalidRequest("invalid cursor".into()))?;
                Bound::Excluded(NftId::new(collection_id, serial))
            }
            None => Bound::Included(NftId::new(collection_id, 0)),
        };
        // Bound the range to this collection's key space so the walk never crosses
        // into the next collection's items.
        let end = Bound::Included(NftId::new(collection_id, u64::MAX));

        let mut items = Vec::new();
        let mut next_cursor = None;
        for (nft_id, item) in state.nft_items.range((start, end)) {
            items.push(NftItemListItem {
                serial: nft_id.serial,
                item: item.clone(),
            });
            if items.len() >= limit {
                next_cursor = Some(nft_id.serial.to_string());
                break;
            }
        }
        Ok(NftItemsPage { items, next_cursor })
    }

    /// Lists an instance's proposals in ascending `ProposalId` order, optionally
    /// filtered by `status`. Proposals are keyed by their opaque `ProposalId`, not
    /// grouped by instance, so this is a bounded filtered scan (at most
    /// `FILTER_SCAN_MULTIPLIER * limit` entries per page); the cursor carries the
    /// last-visited id for forward progress. The instance must exist, else
    /// `NotFound`.
    pub fn instance_proposals(
        &self,
        instance_id: GovernanceInstanceId,
        status: Option<GovProposalStatus>,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<ProposalsPage, ApiError> {
        let limit = clamp_limit(limit);
        let max_scan = limit.saturating_mul(FILTER_SCAN_MULTIPLIER);
        let inner = self.lock();
        let state = inner.node.state();
        if !state.governance_instances.contains_key(&instance_id) {
            return Err(ApiError::NotFound);
        }

        let start = match cursor {
            Some(raw) => Bound::Excluded(ProposalId::new(decode_hash_cursor(raw)?)),
            None => Bound::Unbounded,
        };

        let mut items = Vec::new();
        let mut next_cursor = None;
        let mut scanned = 0usize;
        for (id, proposal) in state.governance_proposals.range((start, Bound::Unbounded)) {
            scanned += 1;
            let status_ok = match status {
                Some(want) => proposal.status == want,
                None => true,
            };
            if proposal.instance_id == instance_id && status_ok {
                items.push(ProposalListItem {
                    proposal_id: *id,
                    proposal: proposal.clone(),
                });
                if items.len() >= limit {
                    next_cursor = Some(id.hash().to_hex());
                    break;
                }
            }
            if scanned >= max_scan {
                next_cursor = Some(id.hash().to_hex());
                break;
            }
        }
        Ok(ProposalsPage { items, next_cursor })
    }

    /// Lists the token balances held BY `address`, ascending by the `(token, holder)`
    /// key. Balances are keyed by `(TokenId, Address)`, so one address's holdings are
    /// scattered across the map; this is a bounded filtered scan (at most
    /// `FILTER_SCAN_MULTIPLIER * limit` entries per page) whose cursor carries the
    /// full last-visited key for forward progress. An address that holds nothing is a
    /// 200 with an empty page (an absent holder is a zero balance, not an error).
    pub fn account_token_balances(
        &self,
        address: Address,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<TokenBalancesPage, ApiError> {
        let limit = clamp_limit(limit);
        let max_scan = limit.saturating_mul(FILTER_SCAN_MULTIPLIER);
        let inner = self.lock();
        let balances = &inner.node.state().token_balances;

        let start = match cursor {
            Some(raw) => Bound::Excluded(decode_token_holder_cursor(raw)?),
            None => Bound::Unbounded,
        };

        let mut items = Vec::new();
        let mut next_cursor = None;
        let mut scanned = 0usize;
        for (&(token_id, holder), amount) in balances.range((start, Bound::Unbounded)) {
            scanned += 1;
            if holder == address {
                items.push(TokenBalanceListItem {
                    token_id,
                    balance: *amount,
                });
                if items.len() >= limit {
                    next_cursor = Some(encode_token_holder_cursor(token_id, holder));
                    break;
                }
            }
            if scanned >= max_scan {
                next_cursor = Some(encode_token_holder_cursor(token_id, holder));
                break;
            }
        }
        Ok(TokenBalancesPage { items, next_cursor })
    }

    /// Lists the mandates whose `principal == address`, ascending by `MandateId`.
    /// Mandates are keyed by their opaque `MandateId`, so this is a bounded filtered
    /// scan (at most `FILTER_SCAN_MULTIPLIER * limit` entries per page); the cursor
    /// carries the last-visited id for forward progress. An address that is the
    /// principal of no mandate is a 200 with an empty page.
    pub fn account_mandates(
        &self,
        address: Address,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<MandatesPage, ApiError> {
        let limit = clamp_limit(limit);
        let max_scan = limit.saturating_mul(FILTER_SCAN_MULTIPLIER);
        let inner = self.lock();
        let mandates = &inner.node.state().mandates;

        let start = match cursor {
            Some(raw) => Bound::Excluded(MandateId::new(decode_hash_cursor(raw)?)),
            None => Bound::Unbounded,
        };

        let mut items = Vec::new();
        let mut next_cursor = None;
        let mut scanned = 0usize;
        for (id, mandate) in mandates.range((start, Bound::Unbounded)) {
            scanned += 1;
            if mandate.principal == address {
                items.push(MandateListItem {
                    mandate_id: *id,
                    mandate: mandate.clone(),
                });
                if items.len() >= limit {
                    next_cursor = Some(id.hash().to_hex());
                    break;
                }
            }
            if scanned >= max_scan {
                next_cursor = Some(id.hash().to_hex());
                break;
            }
        }
        Ok(MandatesPage { items, next_cursor })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_chain::{ChainConfig, GenesisAccount, GenesisConfig, GenesisValidator};
    use webc_storage::MemoryKvStore;

    const NOW: u64 = 1_000;

    fn keypair(seed: u8) -> Keypair {
        Keypair::from_seed([seed; 32])
    }

    /// A service over a fresh in-memory node with alice, bob, and a faucet
    /// account funded in genesis. `faucet_enabled` toggles the devnet faucet.
    fn build_service(
        faucet_enabled: bool,
    ) -> (NodeService<MemoryKvStore>, Keypair, Keypair, Keypair) {
        let alice = keypair(1);
        let bob = keypair(2);
        let faucet = keypair(9);
        let genesis = GenesisConfig {
            chain: ChainConfig::default(),
            accounts: vec![
                GenesisAccount {
                    address: alice.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: bob.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: faucet.address(),
                    balance: Amount::from_webc(1_000_000),
                },
            ],
            validators: Vec::new(),
        };
        let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let faucet_config = faucet_enabled.then(|| FaucetConfig {
            keypair: keypair(9),
            drip_amount: Amount::from_webc(10),
            cooldown_ms: 60_000,
            max_recipient_balance: Amount::from_webc(100),
        });
        let options = NodeServiceOptions {
            mempool: MempoolConfig::default(),
            faucet: faucet_config,
            proposer: faucet.address(),
        };
        (NodeService::new(node, options), alice, bob, faucet)
    }

    fn transfer(from: &Keypair, to: &Keypair, whole: u64, nonce: u64) -> Transaction {
        Transaction::for_operation(
            from,
            nonce,
            Operation::Transfer {
                to: to.address(),
                amount: Amount::from_webc(whole),
            },
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn faucet_token_bucket_refills_over_time_and_caps_at_burst() {
        // H1: the global bucket refills one token per interval, never above the
        // burst, and only advances by whole intervals (no fractional loss).
        let mut faucet = Faucet {
            config: FaucetConfig {
                keypair: keypair(9),
                drip_amount: Amount::from_webc(10),
                cooldown_ms: 60_000,
                max_recipient_balance: Amount::from_webc(100),
            },
            last_drip_ms: BTreeMap::new(),
            tokens: 0,
            last_refill_ms: 0,
        };
        faucet.refill_tokens(0);
        assert_eq!(faucet.tokens, 0);
        faucet.refill_tokens(5 * FAUCET_GLOBAL_REFILL_MS);
        assert_eq!(faucet.tokens, 5);
        // A large jump caps at the burst, not beyond.
        faucet.refill_tokens(1_000_000 * FAUCET_GLOBAL_REFILL_MS);
        assert_eq!(faucet.tokens, FAUCET_GLOBAL_BURST);
    }

    #[test]
    fn supply_endpoint_reconciles_gross_issuance() {
        let (service, _alice, _bob, _faucet) = build_service(false);
        let report = service.supply().expect("supply report");
        // Genesis funded 1_000 + 1_000 + 1_000_000 WEBC; nothing minted yet, so
        // gross issuance reconciles exactly against every value bucket.
        assert_eq!(report.issued, Amount::from_webc(1_002_000));
        assert!(report.balanced);
    }

    #[test]
    fn validator_endpoints_list_and_look_up() {
        // A service with no validators exposes an empty set and NotFound lookups.
        let (empty, _a, _b, _f) = build_service(false);
        assert!(empty
            .validators()
            .expect("validators")
            .validators
            .is_empty());
        assert!(matches!(
            empty.validator(keypair(3).address()),
            Err(ApiError::NotFound)
        ));

        // A genesis validator is exposed with its derived total stake.
        let operator = keypair(7);
        let genesis = GenesisConfig {
            chain: ChainConfig::default(),
            accounts: vec![GenesisAccount {
                address: operator.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: vec![GenesisValidator {
                operator: operator.address(),
                consensus_key: operator.public_key(),
                self_stake: Amount::from_webc(100),
                commission_bps: 500,
                bootstrap: false,
            }],
        };
        let node = Node::open(MemoryKvStore::new(), &genesis).unwrap();
        let service = NodeService::new(
            node,
            NodeServiceOptions {
                mempool: MempoolConfig::default(),
                faucet: None,
                proposer: operator.address(),
            },
        );

        let listed = service.validators().expect("validators");
        assert_eq!(listed.validators.len(), 1);
        assert_eq!(listed.validators[0].validator.operator, operator.address());
        assert_eq!(listed.validators[0].total_stake, Amount::from_webc(100));

        let one = service.validator(operator.address()).expect("validator");
        assert_eq!(one.total_stake, Amount::from_webc(100));
        assert!(matches!(
            service.validator(keypair(8).address()),
            Err(ApiError::NotFound)
        ));
    }

    #[test]
    fn faucet_global_rate_limit_bounds_total_drips() {
        // H1: with a fixed clock the global bucket never refills, so at most
        // FAUCET_GLOBAL_BURST drips succeed no matter how many fresh addresses an
        // attacker rotates through — each drip otherwise builds a full block.
        let (service, ..) = build_service(true);
        for i in 0..FAUCET_GLOBAL_BURST {
            let recipient = keypair(100u8.wrapping_add(i as u8)).address();
            service
                .faucet_drip(recipient, NOW)
                .expect("a burst drip succeeds");
        }
        // Bucket empty at the same instant: a fresh recipient is rate limited.
        let extra = keypair(250).address();
        assert!(matches!(
            service.faucet_drip(extra, NOW),
            Err(ApiError::FaucetCooldown)
        ));
        // Once a refill interval elapses, a drip succeeds again.
        assert!(service
            .faucet_drip(extra, NOW + FAUCET_GLOBAL_REFILL_MS)
            .is_ok());
    }

    #[test]
    fn seal_prunes_expired_transactions() {
        // H2: the seal tick prunes TTL-expired transactions, so a pool filled
        // with expired entries frees its slots instead of staying full forever.
        let (service, alice, bob, _faucet) = build_service(false);
        service
            .submit_transaction(transfer(&alice, &bob, 1, 0), NOW)
            .expect("submit");
        assert_eq!(service.health().mempool_size, 1);

        // Seal far past the mempool TTL: the expired tx is pruned, nothing seals.
        let ttl = MempoolConfig::default().ttl_ms;
        let sealed = service.seal_block(NOW + ttl + 1).expect("seal");
        assert!(sealed.is_none());
        assert_eq!(service.health().mempool_size, 0);
    }

    #[test]
    fn health_and_fees_report_fresh_state() {
        let (service, _alice, _bob, _faucet) = build_service(true);
        let health = service.health();
        assert_eq!(health.api_version, API_VERSION);
        assert_eq!(health.height, 0);
        assert!(health.faucet_enabled);
        assert_eq!(health.mempool_size, 0);

        let fees = service.fees();
        assert_eq!(
            fees.base_fee_per_unit,
            ChainConfig::default().fee_policy.min_base_fee_per_unit
        );
    }

    #[test]
    fn account_query_and_proof() {
        let (service, alice, _bob, _faucet) = build_service(true);
        let summary = service.account(alice.address()).unwrap();
        assert_eq!(summary.account.balance, Amount::from_webc(1_000));

        // A membership proof verifies against the account root.
        let proof = service.account_proof(alice.address()).unwrap();
        assert!(proof.verify().unwrap());

        // Unknown accounts are NotFound.
        let stranger = keypair(200);
        assert!(matches!(
            service.account(stranger.address()),
            Err(ApiError::NotFound)
        ));
    }

    #[test]
    fn submit_then_seal_produces_a_block() {
        let (service, alice, bob, _faucet) = build_service(false);
        let receipt = service
            .submit_transaction(transfer(&alice, &bob, 10, 0), NOW)
            .unwrap();
        assert!(receipt.accepted);
        assert_eq!(service.health().mempool_size, 1);

        let sealed = service.seal_block(NOW).unwrap().unwrap();
        assert_eq!(sealed.height, 1);
        assert_eq!(sealed.transaction_count, 1);

        // The block is retrievable by height and by hash, and bob was paid.
        let by_height = service.block_by_height(1).unwrap();
        assert_eq!(
            service
                .block_by_hash(sealed.block_hash)
                .unwrap()
                .hash()
                .unwrap(),
            by_height.hash().unwrap()
        );
        assert_eq!(
            service.account(bob.address()).unwrap().account.balance,
            Amount::from_webc(1_010)
        );
        // Mempool drained after inclusion.
        assert_eq!(service.health().mempool_size, 0);
    }

    #[test]
    fn seal_with_empty_mempool_is_noop() {
        let (service, _alice, _bob, _faucet) = build_service(false);
        assert!(service.seal_block(NOW).unwrap().is_none());
        assert_eq!(service.health().height, 0);
    }

    #[test]
    fn faucet_funds_a_fresh_wallet_and_enforces_limits() {
        let (service, _alice, _bob, _faucet) = build_service(true);
        // A brand-new wallet address not present in genesis.
        let newcomer = keypair(123);

        let receipt = service.faucet_drip(newcomer.address(), NOW).unwrap();
        assert_eq!(receipt.amount, Amount::from_webc(10));
        assert_eq!(receipt.new_balance, Amount::from_webc(10));
        assert_eq!(receipt.block_height, 1);
        assert!(!receipt.disclaimer.is_empty());
        // The funds are final: the account now exists with the dripped balance.
        assert_eq!(
            service.account(newcomer.address()).unwrap().account.balance,
            Amount::from_webc(10)
        );

        // A second drip within the cooldown is refused.
        assert!(matches!(
            service.faucet_drip(newcomer.address(), NOW + 1_000),
            Err(ApiError::FaucetCooldown)
        ));
    }

    #[test]
    fn faucet_refuses_already_funded_and_disabled() {
        let (service, alice, _bob, _faucet) = build_service(true);
        // Alice already holds 1000 WEBC, above the 100 ceiling.
        assert!(matches!(
            service.faucet_drip(alice.address(), NOW),
            Err(ApiError::FaucetRecipientFunded)
        ));

        // A node without a faucet refuses drips outright.
        let (no_faucet, _a, _b, _f) = build_service(false);
        let someone = keypair(55);
        assert!(matches!(
            no_faucet.faucet_drip(someone.address(), NOW),
            Err(ApiError::FaucetDisabled)
        ));
    }

    #[test]
    fn rejects_duplicate_nonce_submission() {
        let (service, alice, bob, _faucet) = build_service(false);
        service
            .submit_transaction(transfer(&alice, &bob, 10, 0), NOW)
            .unwrap();
        // Same nonce, same fee: replacement-underpriced rejection from the mempool.
        let err = service
            .submit_transaction(transfer(&alice, &bob, 10, 0), NOW)
            .unwrap_err();
        assert!(matches!(err, ApiError::Rejected(_)));
    }

    #[test]
    fn submit_and_seal_commits_in_one_call() {
        let (service, alice, bob, _faucet) = build_service(false);
        let summary = service
            .submit_and_seal(transfer(&alice, &bob, 5, 0), NOW)
            .expect("submit and seal");
        assert_eq!(summary.height, 1);
        assert_eq!(summary.transaction_count, 1);
        // The block is final: bob was paid and the mempool drained.
        assert_eq!(
            service.account(bob.address()).unwrap().account.balance,
            Amount::from_webc(1_005)
        );
        assert_eq!(service.health().mempool_size, 0);
    }
}
