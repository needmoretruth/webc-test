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
use std::sync::Mutex;

use webc_chain::{
    Account, AccountStateProof, Amount, Block, ChainError, FeeBid, ObjectId, Operation,
    StateObject, Transaction,
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

/// Runtime faucet state: its config plus recent per-recipient drip times.
struct Faucet {
    config: FaucetConfig,
    last_drip_ms: BTreeMap<Address, u64>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use webc_chain::{ChainConfig, GenesisAccount, GenesisConfig};
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
}
