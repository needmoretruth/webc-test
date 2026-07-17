//! Versioned logical keys for deterministic state access and scheduling.
//!
//! This module identifies consensus state but does not store or mutate it.
//! Transactions sign exact read-only and writable keys; execution records the
//! keys it actually touches and fails closed on missing, extra, overlapping, or
//! unsupported-version declarations. Fixed-size object and application keys
//! keep hostile access lists bounded independently of future storage backends.

use crate::{
    AssetId, AuthorizationLaneId, ChainError, ObjectId, ProtocolVersion, SessionKeyId,
    CURRENT_PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use webc_crypto::{Address, Hash256};

/// Maximum combined read-only and writable keys in one transaction.
///
/// The bound limits scheduler and validation work before execution. It is a
/// conservative Phase 1 safety limit, not a mainnet throughput parameter.
pub const MAX_TRANSACTION_STATE_KEYS: usize = 256;

/// Protocol-owned singleton state that native operations may access.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProtocolStateKey {
    /// Current base fee, in base units per execution unit; transactions only read it.
    BaseFee,
    /// Monotonic nonce used to identify outgoing prototype bridge messages.
    BridgeNonce,
}

/// Logical state identity interpreted under the enclosing key version.
///
/// Account keys currently cover the native balance, nonce, operator stake, and
/// delegated total stored in one account record. Asset balances remain owner
/// scoped, so ordinary transfers never lock one globally writable asset object.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StateKeyKind {
    /// Native account record for one address.
    Account { address: Address },
    /// Versioned signing/recovery policy for one stable account address.
    AuthorizationPolicy { owner: Address },
    /// Non-native fungible balance for one asset owner.
    AssetBalance { asset: AssetId, owner: Address },
    /// Validator-pool record keyed by operator address.
    Validator { operator: Address },
    /// One delegator's position in one validator pool.
    Delegation {
        delegator: Address,
        validator: Address,
    },
    /// Replay and prepaid-fee state for one non-default authorization lane.
    AuthorizationLane {
        owner: Address,
        lane: AuthorizationLaneId,
    },
    /// Lane-scoped fee delta merged into deterministic aggregate accounting.
    FeeAccumulator {
        payer: Address,
        lane: AuthorizationLaneId,
    },
    /// Constraint and cumulative-spend state for one constrained session key.
    SessionKey {
        owner: Address,
        session_key: SessionKeyId,
    },
    /// Replay marker for one incoming bridge message.
    BridgeMessage { message_hash: Hash256 },
    /// Native WEBC escrow isolated by the external bridge domain.
    BridgeEscrow { domain: crate::ExternalChain },
    /// Replay marker for one submitted slashing artifact.
    SlashingEvidence { evidence_hash: Hash256 },
    /// Validator-scoped exit queue and request records.
    UnbondingQueue { validator: Address },
    /// Persistent object-style state identified by a fixed 32-byte object ID.
    Object { object_id: ObjectId },
    /// Future native or contract module state identified by a fixed module ID.
    Module { module_id: Hash256 },
    /// Future application-owned state isolated by namespace and local key hash.
    Application {
        namespace: Hash256,
        key_hash: Hash256,
    },
    /// Native oracle feed-registry record for one feed id.
    OracleFeed { feed_id: crate::FeedId },
    /// Native oracle bonded-reporter record for one reporter on one feed.
    OracleReporter {
        feed_id: crate::FeedId,
        reporter: Address,
    },
    /// Protocol singleton state that cannot be attributed to one account/object.
    Protocol { field: ProtocolStateKey },
}

/// One versioned key in the unified consensus state space.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StateKey {
    /// Schema version used to interpret `kind`.
    pub version: ProtocolVersion,
    /// Logical identity inside the versioned state-key schema.
    pub kind: StateKeyKind,
}

impl StateKey {
    /// Constructs a key in the current protocol state-key schema.
    pub const fn current(kind: StateKeyKind) -> Self {
        Self {
            version: CURRENT_PROTOCOL_VERSION,
            kind,
        }
    }

    /// Returns the current native-account key for `address`.
    pub const fn account(address: Address) -> Self {
        Self::current(StateKeyKind::Account { address })
    }

    /// Returns the current account-authorization policy key for `owner`.
    pub const fn authorization_policy(owner: Address) -> Self {
        Self::current(StateKeyKind::AuthorizationPolicy { owner })
    }

    /// Returns the current non-native asset-balance key for one owner.
    pub fn asset_balance(asset: AssetId, owner: Address) -> Self {
        Self::current(StateKeyKind::AssetBalance { asset, owner })
    }

    /// Returns the current validator-pool key for `operator`.
    pub const fn validator(operator: Address) -> Self {
        Self::current(StateKeyKind::Validator { operator })
    }

    /// Returns the current key for one delegation position.
    pub const fn delegation(delegator: Address, validator: Address) -> Self {
        Self::current(StateKeyKind::Delegation {
            delegator,
            validator,
        })
    }

    /// Returns the payer-scoped fee-accounting key.
    pub const fn authorization_lane(owner: Address, lane: AuthorizationLaneId) -> Self {
        Self::current(StateKeyKind::AuthorizationLane { owner, lane })
    }

    /// Returns the default-lane fee-accounting key.
    pub const fn fee_accumulator(payer: Address) -> Self {
        Self::fee_accumulator_for_lane(payer, AuthorizationLaneId::DEFAULT)
    }

    /// Returns the state key for one constrained session key under `owner`.
    pub const fn session_key(owner: Address, session_key: SessionKeyId) -> Self {
        Self::current(StateKeyKind::SessionKey { owner, session_key })
    }

    /// Returns one lane-scoped fee-accounting key.
    pub const fn fee_accumulator_for_lane(payer: Address, lane: AuthorizationLaneId) -> Self {
        Self::current(StateKeyKind::FeeAccumulator { payer, lane })
    }

    /// Returns the replay-marker key for an incoming bridge message hash.
    pub const fn bridge_message(message_hash: Hash256) -> Self {
        Self::current(StateKeyKind::BridgeMessage { message_hash })
    }

    /// Returns the native-WEBC escrow key for one external bridge domain.
    pub const fn bridge_escrow(domain: crate::ExternalChain) -> Self {
        Self::current(StateKeyKind::BridgeEscrow { domain })
    }

    /// Returns the replay-marker key for an objective slashing artifact hash.
    pub const fn slashing_evidence(evidence_hash: Hash256) -> Self {
        Self::current(StateKeyKind::SlashingEvidence { evidence_hash })
    }

    /// Returns the validator-scoped unbonding queue key.
    pub const fn unbonding_queue(validator: Address) -> Self {
        Self::current(StateKeyKind::UnbondingQueue { validator })
    }

    /// Returns the current key for one persistent application object.
    pub const fn object(object_id: ObjectId) -> Self {
        Self::current(StateKeyKind::Object { object_id })
    }

    /// Returns the current module key that addresses a contract's code/manifest
    /// record (ADR-0014): a registered contract's [`crate::ContractManifest`] is
    /// addressed by `StateKey::module(code_id)`, so two registrations of the same
    /// code id deterministically share (and therefore serialize on) this key.
    pub const fn module(module_id: Hash256) -> Self {
        Self::current(StateKeyKind::Module { module_id })
    }

    /// Returns a future application state key with fixed-size namespace isolation.
    pub const fn application(namespace: Hash256, key_hash: Hash256) -> Self {
        Self::current(StateKeyKind::Application {
            namespace,
            key_hash,
        })
    }

    /// Returns a current protocol-singleton key.
    pub const fn protocol(field: ProtocolStateKey) -> Self {
        Self::current(StateKeyKind::Protocol { field })
    }

    /// Returns the current oracle feed-registry key for `feed_id`.
    pub const fn oracle_feed(feed_id: crate::FeedId) -> Self {
        Self::current(StateKeyKind::OracleFeed { feed_id })
    }

    /// Returns the current oracle reporter key for `reporter` on `feed_id`.
    pub const fn oracle_reporter(feed_id: crate::FeedId, reporter: Address) -> Self {
        Self::current(StateKeyKind::OracleReporter { feed_id, reporter })
    }

    /// Rejects keys whose schema is not supported by this executable.
    pub fn validate_version(&self) -> Result<(), ChainError> {
        if self.version != CURRENT_PROTOCOL_VERSION {
            return Err(ChainError::UnsupportedStateKeyVersion {
                actual: self.version,
            });
        }
        Ok(())
    }
}

/// Runtime recorder enforcing a signed access list against actual native access.
///
/// A writable declaration covers reads and writes to the same logical record.
/// On successful execution every declared key must have been used, preventing
/// attackers from creating artificial conflicts with unrelated extra keys.
pub(crate) struct StateAccessRecorder {
    declared_reads: BTreeSet<StateKey>,
    declared_writes: BTreeSet<StateKey>,
    observed_reads: BTreeSet<StateKey>,
    observed_writes: BTreeSet<StateKey>,
}

impl StateAccessRecorder {
    /// Validates and copies hostile declarations before state execution begins.
    pub(crate) fn new(read_only: &[StateKey], read_write: &[StateKey]) -> Result<Self, ChainError> {
        let total = read_only
            .len()
            .checked_add(read_write.len())
            .ok_or(ChainError::ArithmeticOverflow)?;
        if total > MAX_TRANSACTION_STATE_KEYS {
            return Err(ChainError::TooManyStateKeys {
                actual: total,
                maximum: MAX_TRANSACTION_STATE_KEYS,
            });
        }
        for key in read_only.iter().chain(read_write) {
            key.validate_version()?;
        }
        let declared_reads = read_only.iter().cloned().collect::<BTreeSet<_>>();
        let declared_writes = read_write.iter().cloned().collect::<BTreeSet<_>>();
        if declared_reads.len() != read_only.len()
            || declared_writes.len() != read_write.len()
            || !declared_reads.is_disjoint(&declared_writes)
        {
            return Err(ChainError::InvalidAccessList);
        }
        Ok(Self {
            declared_reads,
            declared_writes,
            observed_reads: BTreeSet::new(),
            observed_writes: BTreeSet::new(),
        })
    }

    /// Records one actual read, accepting either a read-only or writable declaration.
    pub(crate) fn read(&mut self, key: StateKey) -> Result<(), ChainError> {
        if self.declared_writes.contains(&key) {
            self.observed_writes.insert(key);
            return Ok(());
        }
        if self.declared_reads.contains(&key) {
            self.observed_reads.insert(key);
            return Ok(());
        }
        Err(ChainError::UndeclaredStateRead { key })
    }

    /// Records one actual write and rejects read-only or missing declarations.
    pub(crate) fn write(&mut self, key: StateKey) -> Result<(), ChainError> {
        if !self.declared_writes.contains(&key) {
            return Err(ChainError::UndeclaredStateWrite { key });
        }
        self.observed_writes.insert(key);
        Ok(())
    }

    /// Requires a successful transaction to use every key it declared.
    pub(crate) fn finish(self) -> Result<(), ChainError> {
        if self.observed_reads != self.declared_reads
            || self.observed_writes != self.declared_writes
        {
            return Err(ChainError::UnusedDeclaredStateAccess);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExternalChain;
    use webc_crypto::Keypair;

    #[test]
    fn recorder_rejects_overlap_and_unused_declarations() {
        let account = StateKey::account(Keypair::from_seed([1u8; 32]).address());
        assert!(matches!(
            StateAccessRecorder::new(
                std::slice::from_ref(&account),
                std::slice::from_ref(&account)
            ),
            Err(ChainError::InvalidAccessList)
        ));

        let recorder = StateAccessRecorder::new(&[], std::slice::from_ref(&account))
            .expect("one current key is valid");
        assert!(matches!(
            recorder.finish(),
            Err(ChainError::UnusedDeclaredStateAccess)
        ));
    }

    #[test]
    fn recorder_rejects_duplicate_unsupported_and_oversized_lists() {
        let account = StateKey::account(Keypair::from_seed([2u8; 32]).address());
        assert!(matches!(
            StateAccessRecorder::new(&[], &[account.clone(), account.clone()]),
            Err(ChainError::InvalidAccessList)
        ));

        let mut unsupported = account.clone();
        unsupported.version = ProtocolVersion::new(CURRENT_PROTOCOL_VERSION.get() + 1);
        assert!(matches!(
            StateAccessRecorder::new(&[], &[unsupported]),
            Err(ChainError::UnsupportedStateKeyVersion { .. })
        ));

        let oversized = vec![account; MAX_TRANSACTION_STATE_KEYS + 1];
        assert!(matches!(
            StateAccessRecorder::new(&[], &oversized),
            Err(ChainError::TooManyStateKeys { .. })
        ));
    }

    #[test]
    fn every_state_key_has_a_stable_cross_language_wire_vector() {
        let owner = Keypair::from_seed([1u8; 32]).address();
        let validator = Keypair::from_seed([2u8; 32]).address();
        let asset = AssetId::External {
            origin_chain: ExternalChain::Ethereum,
            symbol: "USDC".to_owned(),
            contract_or_mint: "0x1234".to_owned(),
        };
        let keys = vec![
            StateKey::account(owner),
            StateKey::authorization_policy(owner),
            StateKey::asset_balance(asset, owner),
            StateKey::validator(validator),
            StateKey::delegation(owner, validator),
            StateKey::authorization_lane(owner, AuthorizationLaneId::new(Hash256([0x99; 32]))),
            StateKey::session_key(owner, SessionKeyId::new(Hash256([0xab; 32]))),
            StateKey::fee_accumulator(owner),
            StateKey::bridge_message(Hash256([0x11; 32])),
            StateKey::bridge_escrow(ExternalChain::Ethereum),
            StateKey::slashing_evidence(Hash256([0x22; 32])),
            StateKey::unbonding_queue(validator),
            StateKey::current(StateKeyKind::Object {
                object_id: ObjectId::new(Hash256([0x33; 32])),
            }),
            StateKey::current(StateKeyKind::Module {
                module_id: Hash256([0x44; 32]),
            }),
            StateKey::application(Hash256([0x55; 32]), Hash256([0x66; 32])),
            StateKey::protocol(ProtocolStateKey::BaseFee),
            StateKey::protocol(ProtocolStateKey::BridgeNonce),
        ];
        let bytes =
            crate::canonical::canonical_json_bytes(&keys).expect("state-key vector serializes");
        assert_eq!(
            Hash256::digest(bytes).to_hex(),
            "86b42dee5ac735a7435d64b12b3f6f958e90c03ac03173ef6f98ec88169c9e20"
        );
    }

    #[test]
    fn oracle_state_keys_have_a_stable_cross_language_wire_vector() {
        // The oracle feed and reporter keys are new StateKeyKind variants (Phase 7,
        // §15.17). Adding variants leaves the frozen vector above untouched (serde
        // tags variants by name), so this separate vector pins the oracle keys'
        // canonical JSON shape for a browser SDK mirror without moving the old hash.
        let reporter = Keypair::from_seed([7u8; 32]).address();
        let feed_id = crate::FeedId::new(Hash256([0x88; 32]));
        let feed_key = StateKey::oracle_feed(feed_id);
        assert_eq!(
            crate::canonical::canonical_json_string(&feed_key).unwrap(),
            format!(
                r#"{{"kind":{{"OracleFeed":{{"feed_id":"{id}"}}}},"version":1}}"#,
                id = "88".repeat(32),
            )
        );
        let reporter_key = StateKey::oracle_reporter(feed_id, reporter);
        assert_eq!(
            crate::canonical::canonical_json_string(&reporter_key).unwrap(),
            format!(
                r#"{{"kind":{{"OracleReporter":{{"feed_id":"{id}","reporter":"{rep}"}}}},"version":1}}"#,
                id = "88".repeat(32),
                rep = reporter.to_base58(),
            )
        );
    }
}
