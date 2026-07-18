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
    /// Protocol singleton state that cannot be attributed to one account/object.
    Protocol { field: ProtocolStateKey },
    /// Durable replay, budget, and revocation state for one scoped sponsor grant.
    ///
    /// This variant is appended so every existing enum discriminant and stored
    /// schema-1 key remains byte-compatible. Protocol-2 V5 execution is the
    /// first consumer; protocol-1 transactions never construct this key.
    SponsorGrant {
        /// Account that signed and funds the immutable grant.
        sponsor: Address,
        /// Domain-separated digest of the immutable grant identifier.
        grant_id: Hash256,
    },
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

    /// Returns the durable state key for one scoped sponsor grant.
    pub const fn sponsor_grant(sponsor: Address, grant_id: Hash256) -> Self {
        Self::current(StateKeyKind::SponsorGrant { sponsor, grant_id })
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
    pub(crate) fn finish(&self) -> Result<(), ChainError> {
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
            StateKey::sponsor_grant(owner, Hash256([0x77; 32])),
        ];
        let bytes =
            crate::canonical::canonical_json_bytes(&keys).expect("state-key vector serializes");
        assert_eq!(
            Hash256::digest(bytes).to_hex(),
            "ce844cddc2979f04aacc81550845f574da2bbc1eeef9aa0f6bf2710a64dc68f4"
        );
    }
}
