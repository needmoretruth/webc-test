//! Signed transaction schema, native operations, fees, and declared state access.
//!
//! Wallets construct and sign this module's canonical payload; the module does
//! not execute or store state. Default access lists enumerate the exact logical
//! keys each native operation is expected to touch. Runtime enforcement lives in
//! `state` and fails atomically if execution diverges from that signed list.

use crate::{
    Amount, AssetId, AuthorizationLaneId, AuthorizationPolicyRevision, BridgeMessage, ChainError,
    ChainId, ExternalChain, ObjectId, ObjectVersion, PostQuantumRoot, PostQuantumRootReveal,
    ProtocolStateKey, ProtocolVersion, SessionKeyConstraints, SessionKeyId, SlashingEvidence,
    StateKey, UnbondingRequestId, CURRENT_PROTOCOL_VERSION, LEGACY_AUTHORIZATION_POLICY_REVISION,
    SIGNING_DOMAIN,
};
use serde::{Deserialize, Serialize};
use webc_crypto::{verify_signature, Address, Hash256, Keypair, PublicKeyBytes, SignatureBytes};

/// Signed transaction access list used for enforcement and parallel scheduling.
///
/// A transaction may run in parallel with another transaction only when their
/// access lists do not conflict. This borrows the useful part of Solana's model
/// while keeping WEBC's account/balance model easy for wallets.
///
/// Keys carry an explicit schema version and participate directly in the
/// canonical signing payload. Duplicate keys and read/write overlap are rejected
/// before execution rather than silently normalized on hostile wire input.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessList {
    /// Keys the transaction may inspect but must not change.
    pub read_only: Vec<StateKey>,
    /// Keys the transaction may both inspect and change.
    pub read_write: Vec<StateKey>,
}

impl AccessList {
    /// Constructs an access list without trusting or validating its contents.
    ///
    /// Runtime execution validates versions, count, duplicates, overlap, and
    /// actual use. Default builders use stable semantic insertion order shared
    /// with the TypeScript SDK.
    pub fn new(read_only: Vec<StateKey>, read_write: Vec<StateKey>) -> Self {
        Self {
            read_only,
            read_write,
        }
    }
}

/// User fee bid.
///
/// `max_fee_per_unit` caps what the user is willing to pay. `priority_fee_per_unit`
/// is an optional tip that helps validators prioritize the transaction during
/// congestion.
///
/// All fields are integers so canonical JSON encoding is identical in every
/// language — no float ambiguity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeBid {
    /// Maximum execution units the sender authorizes for this transaction.
    pub gas_limit: u64,
    /// Maximum native base units paid per execution unit.
    pub max_fee_per_unit: u64,
    /// Optional native base-unit tip per execution unit.
    pub priority_fee_per_unit: u64,
}

impl Default for FeeBid {
    fn default() -> Self {
        Self {
            gas_limit: 1_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        }
    }
}

impl FeeBid {
    /// Returns the actual base-unit price or fails when the base fee exceeds the cap.
    pub fn effective_fee_per_unit(self, base_fee_per_unit: u64) -> Result<u64, ChainError> {
        if self.max_fee_per_unit < base_fee_per_unit {
            return Err(ChainError::FeeTooLow);
        }
        let available_tip = self.max_fee_per_unit - base_fee_per_unit;
        Ok(base_fee_per_unit + self.priority_fee_per_unit.min(available_tip))
    }
}

/// Native protocol operations.
///
/// The first WEBC prototype intentionally exposes important coin/staking/bridge
/// actions directly instead of rushing into a full smart-contract VM. This keeps
/// security-sensitive logic explicit and easier to test.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    /// Migrates an address-derived account to versioned authorization.
    InstallAuthorizationPolicy {
        /// Commitment to the standard wallet's post-quantum recovery public key.
        post_quantum_root: PostQuantumRoot,
    },
    /// Opens a non-default lane with prepaid native fee units.
    OpenAuthorizationLane {
        /// New opaque lane identity; the all-zero default is reserved.
        lane: AuthorizationLaneId,
        /// Native base units moved from liquid balance into the lane.
        fee_deposit: Amount,
    },
    /// Adds prepaid fees to an existing non-default lane.
    FundAuthorizationLane {
        /// Existing opaque lane identity.
        lane: AuthorizationLaneId,
        /// Native base units moved from liquid balance into the lane.
        fee_deposit: Amount,
    },
    /// Installs a constrained session key under the sender's account policy.
    ///
    /// Critical action: requires the default lane, an installed policy, and a
    /// reveal of the committed post-quantum root. The session key can only
    /// authorize the operations, amounts, fees, lane, and lifetime it declares.
    InstallSessionKey {
        /// Ed25519 key the session may sign transactions with.
        session_public_key: PublicKeyBytes,
        /// Immutable constraint grant fixed at installation.
        constraints: SessionKeyConstraints,
        /// Reveal proving knowledge of the committed post-quantum root.
        post_quantum_root_reveal: PostQuantumRootReveal,
    },
    /// Revokes an installed session key immediately.
    ///
    /// Critical action: requires the default lane and a post-quantum root reveal.
    RevokeSessionKey {
        /// Opaque identity of the session key to remove.
        session_key: SessionKeyId,
        /// Reveal proving knowledge of the committed post-quantum root.
        post_quantum_root_reveal: PostQuantumRootReveal,
    },
    /// Rotates the account's active Ed25519 transaction key (recovery/rotation).
    ///
    /// Critical action: requires the default lane, an installed policy, and a
    /// post-quantum root signature over the exact new key. Recovery works even
    /// when the old key is lost or compromised, because the transaction envelope
    /// may be signed by the *new* key and the real authority is the root
    /// signature. A successful rotation advances the policy revision, which
    /// invalidates every outstanding session key; the post-quantum root itself is
    /// preserved.
    RotateActiveTransactionKey {
        /// Replacement Ed25519 key that will authorize ordinary transactions.
        new_active_transaction_key: PublicKeyBytes,
        /// Root signature over the exact rotation (chain, owner, revision, nonce,
        /// new key), proving control of the account's recovery root.
        post_quantum_root_reveal: PostQuantumRootReveal,
    },
    /// Rotates the account's post-quantum recovery root (root recovery).
    ///
    /// Critical action: requires the default lane, an installed policy, and a
    /// signature by the *current* post-quantum root over the exact new root
    /// commitment. The everyday active transaction key is preserved; the
    /// revision advances, invalidating outstanding session keys. Use it to
    /// replace a recovery root that may be weak or compromised. The transaction
    /// envelope is signed by the current active key, so replacing the root
    /// requires control of both the current root and the active key.
    RotatePostQuantumRoot {
        /// New committed post-quantum recovery root.
        new_post_quantum_root: PostQuantumRoot,
        /// Signature by the CURRENT root over the exact rotation, proving control
        /// of the recovery root being replaced.
        post_quantum_root_reveal: PostQuantumRootReveal,
    },
    /// Creates revision one of an address-owned application object.
    CreateObject {
        /// Caller-chosen collision-resistant object identity.
        object_id: ObjectId,
        /// Application namespace used for isolation and scheduling.
        namespace: Hash256,
        /// Bounded opaque on-chain bytes, encoded as lowercase hex.
        #[serde(with = "crate::object::bounded_hex")]
        data: Vec<u8>,
    },
    /// Replaces owned object data when its expected revision matches.
    MutateObject {
        /// Existing object identity.
        object_id: ObjectId,
        /// Signed namespace that must match stored object metadata.
        namespace: Hash256,
        /// Current revision expected by the sender.
        expected_version: ObjectVersion,
        /// Replacement bounded opaque bytes, encoded as lowercase hex.
        #[serde(with = "crate::object::bounded_hex")]
        data: Vec<u8>,
    },
    /// Transfers owned-object authority and advances its revision.
    TransferObject {
        /// Existing object identity.
        object_id: ObjectId,
        /// Signed namespace that must match stored object metadata.
        namespace: Hash256,
        /// Current revision expected by the sender.
        expected_version: ObjectVersion,
        /// New account owner.
        new_owner: Address,
    },
    /// Moves native base units between account records.
    Transfer {
        /// Recipient native account.
        to: Address,
        /// Native amount in base units.
        amount: Amount,
    },
    /// Creates a validator pool backed by operator self-stake.
    RegisterValidator {
        /// Ed25519 key currently authorized for consensus votes.
        consensus_key: PublicKeyBytes,
        /// Operator collateral in native base units.
        self_stake: Amount,
        /// Validator commission in basis points, from 0 through 10,000.
        commission_bps: u16,
        /// Legacy flag retained only so the new path can reject bootstrap power.
        bootstrap: bool,
    },
    /// Adds native stake to one validator pool.
    Delegate {
        /// Validator operator receiving the delegation.
        validator: Address,
        /// Delegated amount in native base units.
        amount: Amount,
    },
    /// Requests delayed exit from one delegation position.
    Undelegate {
        /// Validator whose queue receives the request.
        validator: Address,
        /// Requested principal in native base units.
        amount: Amount,
    },
    /// Requests delayed exit of the sender's operator self-stake.
    UnstakeValidator {
        /// Requested operator principal in native base units.
        amount: Amount,
    },
    /// Claims matured principal from one validator-scoped request.
    ClaimUnbonded {
        /// Validator queue holding the request.
        validator: Address,
        /// Monotonic request identity assigned at enqueue time.
        request_id: UnbondingRequestId,
    },
    /// Claims all accumulated operator rewards owned by the sender.
    ClaimValidatorRewards,
    /// Claims accumulated rewards from one delegation position.
    ClaimDelegatorRewards {
        /// Validator identifying the sender's position.
        validator: Address,
    },
    /// Submits objectively verifiable signed slashing evidence.
    SubmitSlashingEvidence {
        /// Signed artifact; subjective labels are not accepted.
        evidence: SlashingEvidence,
    },
    /// Locks an asset before minting its representation on another chain.
    BridgeLock {
        /// Canonical asset identity.
        asset: crate::AssetId,
        /// Destination domain that will receive the representation.
        destination_chain: ExternalChain,
        /// Destination-domain recipient bytes, serialized as lowercase hex.
        #[serde(with = "crate::hex_bytes")]
        recipient: Vec<u8>,
        /// Locked quantity in the asset's protocol base units.
        amount: Amount,
    },
    /// Burns a representation before release on its origin chain.
    BridgeBurn {
        /// Canonical asset identity.
        asset: crate::AssetId,
        /// Destination/origin domain that will release value.
        destination_chain: ExternalChain,
        /// Destination-domain recipient bytes, serialized as lowercase hex.
        #[serde(with = "crate::hex_bytes")]
        recipient: Vec<u8>,
        /// Burned quantity in the asset's protocol base units.
        amount: Amount,
    },
    /// Mints a representation from an authorized source-chain message.
    BridgeMint {
        /// Replay-protected source message; real-fund proofs remain disabled.
        message: BridgeMessage,
    },
    /// Releases escrowed value from an authorized burn message.
    BridgeRelease {
        /// Replay-protected source message; real-fund proofs remain disabled.
        message: BridgeMessage,
    },
}

impl Operation {
    /// Rough deterministic execution-unit cost for fee accounting.
    ///
    /// These numbers are placeholders for the prototype. They are centralized so
    /// future benchmarking can tune them without scattering magic constants.
    pub fn required_units(&self) -> u64 {
        match self {
            Self::Transfer { .. } => 500,
            Self::InstallAuthorizationPolicy { .. }
            | Self::RotateActiveTransactionKey { .. }
            | Self::RotatePostQuantumRoot { .. } => 25_000,
            Self::InstallSessionKey { .. } | Self::RevokeSessionKey { .. } => 15_000,
            Self::OpenAuthorizationLane { .. } | Self::FundAuthorizationLane { .. } => 10_000,
            Self::CreateObject { .. } | Self::MutateObject { .. } | Self::TransferObject { .. } => {
                20_000
            }
            Self::RegisterValidator { .. } => 25_000,
            Self::Delegate { .. }
            | Self::Undelegate { .. }
            | Self::UnstakeValidator { .. }
            | Self::ClaimUnbonded { .. } => 10_000,
            Self::ClaimValidatorRewards | Self::ClaimDelegatorRewards { .. } => 5_000,
            Self::SubmitSlashingEvidence { .. } => 20_000,
            Self::BridgeLock { .. } | Self::BridgeBurn { .. } => 50_000,
            Self::BridgeMint { .. } | Self::BridgeRelease { .. } => 75_000,
        }
    }

    /// Builds the exact current-version access list for this native operation.
    ///
    /// The sender account, sender-scoped fee delta, and read-only base fee are
    /// common to every signed transaction. Message/evidence hashes are computed
    /// before signing so replay markers cannot be substituted later.
    pub fn default_access_list(&self, sender: Address) -> Result<AccessList, ChainError> {
        self.default_access_list_for_lane(sender, AuthorizationLaneId::DEFAULT)
    }

    /// Builds exact access for a specific sender authorization lane.
    pub fn default_access_list_for_lane(
        &self,
        sender: Address,
        lane: AuthorizationLaneId,
    ) -> Result<AccessList, ChainError> {
        let mut read_only = vec![StateKey::protocol(ProtocolStateKey::BaseFee)];
        let mut read_write = if lane.is_default() {
            vec![StateKey::account(sender)]
        } else {
            vec![StateKey::authorization_lane(sender, lane)]
        };
        match self {
            Self::InstallAuthorizationPolicy { .. } => {
                push_unique_key(&mut read_write, StateKey::authorization_policy(sender));
            }
            Self::OpenAuthorizationLane { lane, .. } | Self::FundAuthorizationLane { lane, .. } => {
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::authorization_lane(sender, *lane));
            }
            Self::InstallSessionKey {
                session_public_key, ..
            } => {
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(
                    &mut read_write,
                    StateKey::session_key(sender, SessionKeyId::derive(session_public_key)),
                );
            }
            Self::RevokeSessionKey { session_key, .. } => {
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::session_key(sender, *session_key));
            }
            Self::RotateActiveTransactionKey { .. } | Self::RotatePostQuantumRoot { .. } => {
                // Both rotations write the account (nonce/fees) and the policy
                // record they replace. They intentionally touch no session-key
                // records: the revision bump alone invalidates them lazily at use
                // time.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::authorization_policy(sender));
            }
            Self::CreateObject {
                object_id,
                namespace,
                ..
            }
            | Self::MutateObject {
                object_id,
                namespace,
                ..
            }
            | Self::TransferObject {
                object_id,
                namespace,
                ..
            } => {
                push_unique_key(&mut read_write, StateKey::object(*object_id));
                push_unique_key(
                    &mut read_write,
                    StateKey::application(*namespace, object_id.hash()),
                );
            }
            Self::Transfer { to, .. } => {
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::account(*to));
            }
            Self::RegisterValidator { .. } | Self::ClaimValidatorRewards => {
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::validator(sender));
            }
            Self::Delegate { validator, .. } => {
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::validator(*validator));
                push_unique_key(&mut read_write, StateKey::delegation(sender, *validator));
                // Pending operator exits reduce the stake capacity that a new
                // delegation may rely on, so the signed access list must bind
                // the validator-scoped queue consulted by execution.
                push_unique_key(&mut read_write, StateKey::unbonding_queue(*validator));
            }
            Self::Undelegate { validator, .. } => {
                push_unique_key(&mut read_write, StateKey::delegation(sender, *validator));
                push_unique_key(&mut read_write, StateKey::unbonding_queue(*validator));
            }
            Self::UnstakeValidator { .. } => {
                push_unique_key(&mut read_write, StateKey::validator(sender));
                push_unique_key(&mut read_write, StateKey::unbonding_queue(sender));
            }
            Self::ClaimUnbonded { validator, .. } => {
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::unbonding_queue(*validator));
            }
            Self::ClaimDelegatorRewards { validator } => {
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::delegation(sender, *validator));
            }
            Self::SubmitSlashingEvidence { evidence } => {
                push_unique_key(&mut read_write, StateKey::validator(evidence.validator()));
                push_unique_key(&mut read_write, StateKey::account(evidence.validator()));
                push_unique_key(
                    &mut read_write,
                    StateKey::unbonding_queue(evidence.validator()),
                );
                push_unique_key(
                    &mut read_write,
                    StateKey::slashing_evidence(evidence.hash()?),
                );
            }
            Self::BridgeLock {
                asset,
                destination_chain,
                ..
            } => {
                if *asset == AssetId::NativeWebc {
                    push_unique_key(&mut read_write, StateKey::account(sender));
                }
                if *asset != AssetId::NativeWebc {
                    push_unique_key(
                        &mut read_write,
                        StateKey::asset_balance(asset.clone(), sender),
                    );
                } else {
                    push_unique_key(
                        &mut read_write,
                        StateKey::bridge_escrow(destination_chain.clone()),
                    );
                }
                push_unique_key(
                    &mut read_write,
                    StateKey::protocol(ProtocolStateKey::BridgeNonce),
                );
            }
            Self::BridgeBurn { asset, .. } => {
                if *asset != AssetId::NativeWebc {
                    push_unique_key(
                        &mut read_write,
                        StateKey::asset_balance(asset.clone(), sender),
                    );
                }
                push_unique_key(
                    &mut read_write,
                    StateKey::protocol(ProtocolStateKey::BridgeNonce),
                );
            }
            Self::BridgeMint { message } | Self::BridgeRelease { message } => {
                let recipient_bytes: [u8; 32] = message
                    .recipient
                    .as_slice()
                    .try_into()
                    .map_err(|_| ChainError::InvalidBridgeRecipient)?;
                let recipient = Address::from_bytes(recipient_bytes);
                if message.asset == AssetId::NativeWebc {
                    push_unique_key(&mut read_write, StateKey::account(recipient));
                } else {
                    push_unique_key(
                        &mut read_write,
                        StateKey::asset_balance(message.asset.clone(), recipient),
                    );
                }
                push_unique_key(&mut read_write, StateKey::bridge_message(message.hash()?));
                if matches!(self, Self::BridgeRelease { .. })
                    && message.asset == AssetId::NativeWebc
                {
                    push_unique_key(
                        &mut read_write,
                        StateKey::bridge_escrow(message.source_chain.clone()),
                    );
                }
            }
        }
        if !matches!(
            self,
            Self::InstallAuthorizationPolicy { .. }
                | Self::RotateActiveTransactionKey { .. }
                | Self::RotatePostQuantumRoot { .. }
        ) {
            push_unique_key(&mut read_only, StateKey::authorization_policy(sender));
        }
        push_unique_key(
            &mut read_write,
            StateKey::fee_accumulator_for_lane(sender, lane),
        );
        Ok(AccessList::new(read_only, read_write))
    }

    /// Builds the exact access for a transaction signed by a session key.
    ///
    /// This is the lane access list plus the session-key record, which execution
    /// reads to enforce constraints and writes to advance cumulative spend.
    pub fn default_access_list_for_session(
        &self,
        sender: Address,
        lane: AuthorizationLaneId,
        session_key: SessionKeyId,
    ) -> Result<AccessList, ChainError> {
        let mut list = self.default_access_list_for_lane(sender, lane)?;
        push_unique_key(
            &mut list.read_write,
            StateKey::session_key(sender, session_key),
        );
        Ok(list)
    }
}

fn push_unique_key(keys: &mut Vec<StateKey>, key: StateKey) {
    if !keys.contains(&key) {
        keys.push(key);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    /// Protocol schema version that interprets every signed field.
    pub protocol_version: ProtocolVersion,
    /// Network replay-protection identifier signed by the wallet.
    pub chain_id: ChainId,
    /// Native account authorizing fees and state changes.
    pub sender: Address,
    /// Ed25519 key that verifies `signature` and must be active in sender policy.
    pub public_key: PublicKeyBytes,
    /// Independent replay/fee lane selected by the wallet.
    pub authorization_lane: AuthorizationLaneId,
    /// Account-policy revision whose active key authorizes this signature.
    pub authorization_policy_revision: AuthorizationPolicyRevision,
    /// Sender sequence number inside `authorization_lane`.
    pub nonce: u64,
    /// One native protocol action.
    pub operation: Operation,
    /// Exact versioned state access signed by the sender.
    pub access_list: AccessList,
    /// Sender's execution-unit and price bounds.
    pub fee: FeeBid,
    /// Ed25519 signature over canonical signing bytes, or `None` before signing.
    pub signature: Option<SignatureBytes>,
}

impl Transaction {
    /// Constructs an unsigned devnet transaction without validating hostile fields.
    pub fn new_unsigned(
        sender: Address,
        public_key: PublicKeyBytes,
        nonce: u64,
        operation: Operation,
        access_list: AccessList,
        fee: FeeBid,
    ) -> Self {
        Self::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            sender,
            public_key,
            AuthorizationLaneId::DEFAULT,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            nonce,
            operation,
            access_list,
            fee,
        )
    }

    /// Constructs an unsigned transaction in an explicit authorization lane.
    pub fn new_unsigned_in_lane(
        sender: Address,
        public_key: PublicKeyBytes,
        authorization_lane: AuthorizationLaneId,
        nonce: u64,
        operation: Operation,
        access_list: AccessList,
        fee: FeeBid,
    ) -> Self {
        Self::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            sender,
            public_key,
            authorization_lane,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            nonce,
            operation,
            access_list,
            fee,
        )
    }

    /// Constructs an unsigned transaction on an explicit chain in the default lane.
    #[allow(
        clippy::too_many_arguments,
        reason = "wire construction keeps each consensus field explicit at the security boundary"
    )]
    pub fn new_unsigned_on_chain(
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        sender: Address,
        public_key: PublicKeyBytes,
        nonce: u64,
        operation: Operation,
        access_list: AccessList,
        fee: FeeBid,
    ) -> Self {
        Self::new_unsigned_in_lane_on_chain(
            protocol_version,
            chain_id,
            sender,
            public_key,
            AuthorizationLaneId::DEFAULT,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            nonce,
            operation,
            access_list,
            fee,
        )
    }

    /// Constructs an unsigned transaction for an explicit protocol and chain.
    #[allow(
        clippy::too_many_arguments,
        reason = "wire construction keeps each consensus field explicit at the security boundary"
    )]
    pub fn new_unsigned_in_lane_on_chain(
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        sender: Address,
        public_key: PublicKeyBytes,
        authorization_lane: AuthorizationLaneId,
        authorization_policy_revision: AuthorizationPolicyRevision,
        nonce: u64,
        operation: Operation,
        access_list: AccessList,
        fee: FeeBid,
    ) -> Self {
        Self {
            protocol_version,
            chain_id,
            sender,
            public_key,
            authorization_lane,
            authorization_policy_revision,
            nonce,
            operation,
            access_list,
            fee,
            signature: None,
        }
    }

    /// Builds default access and signs for the canonical development chain.
    pub fn for_operation(
        keypair: &Keypair,
        nonce: u64,
        operation: Operation,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        Self::for_operation_in_lane(keypair, AuthorizationLaneId::DEFAULT, nonce, operation, fee)
    }

    /// Builds and signs on devnet under an already installed policy revision.
    ///
    /// This helper applies while the policy's active key still derives the
    /// legacy address. Recovery and rotation use the explicit stable-address
    /// constructor added with those state transitions.
    pub fn for_operation_with_policy(
        keypair: &Keypair,
        authorization_policy_revision: AuthorizationPolicyRevision,
        nonce: u64,
        operation: Operation,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        Self::for_operation_in_lane_on_chain(
            keypair,
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            AuthorizationLaneId::DEFAULT,
            authorization_policy_revision,
            nonce,
            operation,
            fee,
        )
    }

    /// Builds exact access and signs an operation for an explicit chain.
    pub fn for_operation_on_chain(
        keypair: &Keypair,
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        nonce: u64,
        operation: Operation,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        Self::for_operation_in_lane_on_chain(
            keypair,
            protocol_version,
            chain_id,
            AuthorizationLaneId::DEFAULT,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            nonce,
            operation,
            fee,
        )
    }

    /// Builds exact access and signs in one lane on the development chain.
    pub fn for_operation_in_lane(
        keypair: &Keypair,
        authorization_lane: AuthorizationLaneId,
        nonce: u64,
        operation: Operation,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        Self::for_operation_in_lane_on_chain(
            keypair,
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            authorization_lane,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            nonce,
            operation,
            fee,
        )
    }

    /// Builds exact access and signs for an explicit protocol, chain, and lane.
    #[allow(
        clippy::too_many_arguments,
        reason = "signing keeps protocol, chain, lane, nonce, operation, and fee visibly explicit"
    )]
    pub fn for_operation_in_lane_on_chain(
        keypair: &Keypair,
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        authorization_lane: AuthorizationLaneId,
        authorization_policy_revision: AuthorizationPolicyRevision,
        nonce: u64,
        operation: Operation,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        let sender = keypair.address();
        let access_list = operation.default_access_list_for_lane(sender, authorization_lane)?;
        let mut tx = Self::new_unsigned_in_lane_on_chain(
            protocol_version,
            chain_id,
            sender,
            keypair.public_key(),
            authorization_lane,
            authorization_policy_revision,
            nonce,
            operation,
            access_list,
            fee,
        );
        tx.sign(keypair)?;
        Ok(tx)
    }

    /// Rebinds the public key, verifies sender derivation, and signs canonical bytes.
    pub fn sign(&mut self, keypair: &Keypair) -> Result<(), ChainError> {
        let public_key = keypair.public_key();
        let sender = Address::from_public_key(&public_key);
        if sender != self.sender {
            return Err(ChainError::SenderPublicKeyMismatch);
        }
        self.sign_with_policy_key(keypair)
    }

    /// Signs using a policy-selected key without deriving the stable address.
    ///
    /// This method performs only signature construction. The caller must submit
    /// through `ChainState::execute_transaction`, which checks that the signed
    /// policy revision exists and that this exact key is active. It is required
    /// after recovery rotates an account away from its address-derivation key.
    pub fn sign_with_policy_key(&mut self, keypair: &Keypair) -> Result<(), ChainError> {
        let public_key = keypair.public_key();
        self.public_key = public_key;
        let message = self.signing_bytes()?;
        self.signature = Some(keypair.sign(&message));
        Ok(())
    }

    /// Verifies the current-version signature without reading account policy.
    ///
    /// Active-chain equality requires `ChainConfig` and is enforced separately
    /// by `ChainState::execute_transaction` before fees or operation execution.
    /// Sender/key authorization is stateful after policy installation and is
    /// therefore deliberately not decided by this stateless method.
    pub fn verify(&self) -> Result<(), ChainError> {
        if self.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(ChainError::UnsupportedProtocolVersion {
                actual: self.protocol_version,
            });
        }
        let signature = self
            .signature
            .as_ref()
            .ok_or(ChainError::MissingSignature)?;
        verify_signature(&self.public_key, &self.signing_bytes()?, signature)?;
        Ok(())
    }

    /// Returns SHA-256 of the complete signed canonical transaction wire.
    pub fn hash(&self) -> Result<Hash256, ChainError> {
        // The transaction hash must be reproducible from any language. We sign
        // and identify transactions using canonical JSON, not Rust-only
        // bincode, so a browser can recompute the same hash after submitting.
        let bytes = crate::canonical::canonical_json_bytes(self)?;
        Ok(Hash256::digest(bytes))
    }

    /// Returns deterministic execution units charged for this native operation.
    pub fn required_units(&self) -> u64 {
        self.operation.required_units()
    }

    /// Canonical bytes that the sender's Ed25519 key must sign directly.
    ///
    /// The payload is `SigningPayload` serialized with stable canonical JSON
    /// (sorted keys, decimal-string amounts, hex byte arrays, no whitespace),
    /// and signed directly. Ed25519 already hashes its message internally; an
    /// extra undocumented pre-hash would create a different signature scheme.
    /// The TypeScript browser flow signs these same canonical bytes.
    ///
    /// The `signature` field itself is intentionally excluded from signing,
    /// so the same struct can carry its own signature without circularity.
    fn signing_bytes(&self) -> Result<Vec<u8>, ChainError> {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            domain: &'static str,
            protocol_version: ProtocolVersion,
            chain_id: &'a ChainId,
            sender: Address,
            public_key: PublicKeyBytes,
            authorization_lane: AuthorizationLaneId,
            authorization_policy_revision: AuthorizationPolicyRevision,
            nonce: u64,
            operation: &'a Operation,
            access_list: &'a AccessList,
            fee: FeeBid,
        }

        let payload = SigningPayload {
            domain: SIGNING_DOMAIN,
            protocol_version: self.protocol_version,
            chain_id: &self.chain_id,
            sender: self.sender,
            public_key: self.public_key,
            authorization_lane: self.authorization_lane,
            authorization_policy_revision: self.authorization_policy_revision,
            nonce: self.nonce,
            operation: &self.operation,
            access_list: &self.access_list,
            fee: self.fee,
        };
        crate::canonical::canonical_json_bytes(&payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DoubleVoteEvidence, SignedVote, Vote, VoteType, CURRENT_PROTOCOL_VERSION};
    use webc_crypto::SignatureBytes;

    #[test]
    fn signed_transaction_verifies() {
        let sender = Keypair::from_seed([1u8; 32]);
        let recipient = Keypair::from_seed([2u8; 32]);
        let tx = Transaction::for_operation(
            &sender,
            0,
            Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(10),
            },
            FeeBid::default(),
        )
        .unwrap();
        tx.verify().unwrap();
    }

    /// Exposes the canonical signing payload text for cross-language test vectors.
    /// Kept private to tests; the browser SDK has its own canonical encoder that
    /// must produce the same bytes.
    pub(crate) fn canonical_signing_text(tx: &Transaction) -> String {
        #[derive(Serialize)]
        struct SigningPayload<'a> {
            domain: &'static str,
            protocol_version: ProtocolVersion,
            chain_id: &'a ChainId,
            sender: Address,
            public_key: PublicKeyBytes,
            authorization_lane: AuthorizationLaneId,
            authorization_policy_revision: AuthorizationPolicyRevision,
            nonce: u64,
            operation: &'a Operation,
            access_list: &'a AccessList,
            fee: FeeBid,
        }
        let payload = SigningPayload {
            domain: SIGNING_DOMAIN,
            protocol_version: tx.protocol_version,
            chain_id: &tx.chain_id,
            sender: tx.sender,
            public_key: tx.public_key,
            authorization_lane: tx.authorization_lane,
            authorization_policy_revision: tx.authorization_policy_revision,
            nonce: tx.nonce,
            operation: &tx.operation,
            access_list: &tx.access_list,
            fee: tx.fee,
        };
        crate::canonical::canonical_json_string(&payload).unwrap()
    }

    /// Computes a diagnostic SHA-256 identity for canonical signing bytes.
    ///
    /// Ed25519 signs the canonical bytes themselves; this hash is only a compact
    /// regression-test identifier and is not a pre-hash signature input.
    pub(crate) fn signing_payload_hash(tx: &Transaction) -> Hash256 {
        let bytes = tx.signing_bytes().unwrap();
        Hash256::digest(bytes)
    }

    #[test]
    fn transfer_canonical_signing_payload_is_stable() {
        // Deterministic inputs make this test a cross-language vector: the
        // exact signing payload text is asserted so the browser SDK must
        // reproduce it byte-for-byte. If this string changes, the browser SDK
        // MUST be updated to match (and any pre-signed test fixtures regenerated).
        let sender = Keypair::from_seed([1u8; 32]);
        let recipient = Keypair::from_seed([2u8; 32]);

        let tx = Transaction::for_operation(
            &sender,
            7,
            Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(123_456),
            },
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
        )
        .unwrap();

        let sender_address = sender.address().to_base58();
        let recipient_address = recipient.address().to_base58();
        let sender_pubkey_hex = sender.public_key().to_hex();

        let expected = format!(
            r#"{{"access_list":{{"read_only":[{{"kind":{{"Protocol":{{"field":"BaseFee"}}}},"version":1}},{{"kind":{{"AuthorizationPolicy":{{"owner":"{sender_address}"}}}},"version":1}}],"read_write":[{{"kind":{{"Account":{{"address":"{sender_address}"}}}},"version":1}},{{"kind":{{"Account":{{"address":"{recipient_address}"}}}},"version":1}},{{"kind":{{"FeeAccumulator":{{"lane":"0000000000000000000000000000000000000000000000000000000000000000","payer":"{sender_address}"}}}},"version":1}}]}},"authorization_lane":"0000000000000000000000000000000000000000000000000000000000000000","authorization_policy_revision":0,"chain_id":"webc-devnet-1","domain":"WEBC_SIGNED_TRANSACTION_V4","fee":{{"gas_limit":1000,"max_fee_per_unit":5,"priority_fee_per_unit":1}},"nonce":7,"operation":{{"Transfer":{{"amount":"123456","to":"{recipient_address}"}}}},"protocol_version":1,"public_key":"{sender_pubkey_hex}","sender":"{sender_address}"}}"#
        );

        let actual = canonical_signing_text(&tx);
        assert_eq!(actual, expected);

        // A compact diagnostic hash must also be stable. The canonical text
        // above remains the actual Ed25519 message and authoritative contract.
        let h1 = signing_payload_hash(&tx).to_hex();
        let h2 = signing_payload_hash(&tx).to_hex();
        assert_eq!(h1, h2);
    }

    #[test]
    fn every_native_operation_has_a_stable_cross_language_wire_vector() {
        let sender = Keypair::from_seed([1u8; 32]);
        let validator = Keypair::from_seed([2u8; 32]);
        let vote = |block_hash, signature| SignedVote {
            payload: Vote {
                protocol_version: CURRENT_PROTOCOL_VERSION,
                chain_id: crate::ChainId::devnet(),
                height: 9,
                round: 1,
                vote_type: VoteType::Precommit,
                block_hash,
                validator: validator.address(),
            },
            signature,
        };
        let evidence = SlashingEvidence::DoubleVote(DoubleVoteEvidence {
            first: vote(Hash256([0x10; 32]), SignatureBytes([0x55; 64])),
            second: vote(Hash256([0x20; 32]), SignatureBytes([0x66; 64])),
        });
        let external_asset = AssetId::External {
            origin_chain: ExternalChain::Ethereum,
            symbol: "USDC".to_owned(),
            contract_or_mint: "0x1234".to_owned(),
        };
        let message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 9,
            asset: external_asset.clone(),
            sender: vec![0xab, 0xcd],
            recipient: validator.address().as_bytes().to_vec(),
            amount: Amount::from_units(77),
            source_tx: Hash256([0x77; 32]),
        };
        let operations = vec![
            Operation::InstallAuthorizationPolicy {
                post_quantum_root: PostQuantumRoot::new(
                    crate::PostQuantumScheme::MlDsa65,
                    Hash256([0x44; 32]),
                )
                .unwrap(),
            },
            Operation::Transfer {
                to: validator.address(),
                amount: Amount::from_units(1),
            },
            Operation::OpenAuthorizationLane {
                lane: AuthorizationLaneId::new(Hash256([0x99; 32])),
                fee_deposit: Amount::from_units(6),
            },
            Operation::FundAuthorizationLane {
                lane: AuthorizationLaneId::new(Hash256([0x99; 32])),
                fee_deposit: Amount::from_units(7),
            },
            Operation::CreateObject {
                object_id: ObjectId::new(Hash256([0x33; 32])),
                namespace: Hash256([0x55; 32]),
                data: vec![0xab],
            },
            Operation::MutateObject {
                object_id: ObjectId::new(Hash256([0x33; 32])),
                namespace: Hash256([0x55; 32]),
                expected_version: ObjectVersion::new(1),
                data: vec![0xcd],
            },
            Operation::TransferObject {
                object_id: ObjectId::new(Hash256([0x33; 32])),
                namespace: Hash256([0x55; 32]),
                expected_version: ObjectVersion::new(2),
                new_owner: sender.address(),
            },
            Operation::RegisterValidator {
                consensus_key: PublicKeyBytes([0xaa; 32]),
                self_stake: Amount::from_units(100),
                commission_bps: 500,
                bootstrap: false,
            },
            Operation::Delegate {
                validator: validator.address(),
                amount: Amount::from_units(2),
            },
            Operation::Undelegate {
                validator: validator.address(),
                amount: Amount::from_units(1),
            },
            Operation::UnstakeValidator {
                amount: Amount::from_units(3),
            },
            Operation::ClaimUnbonded {
                validator: validator.address(),
                request_id: UnbondingRequestId::new(7),
            },
            Operation::ClaimValidatorRewards,
            Operation::ClaimDelegatorRewards {
                validator: validator.address(),
            },
            Operation::SubmitSlashingEvidence { evidence },
            Operation::BridgeLock {
                asset: AssetId::NativeWebc,
                destination_chain: ExternalChain::Ethereum,
                recipient: vec![0xab, 0xcd],
                amount: Amount::from_units(4),
            },
            Operation::BridgeBurn {
                asset: external_asset,
                destination_chain: ExternalChain::Solana,
                recipient: vec![0xdc, 0xba],
                amount: Amount::from_units(5),
            },
            Operation::BridgeMint {
                message: message.clone(),
            },
            Operation::BridgeRelease { message },
        ];

        let bytes = crate::canonical::canonical_json_bytes(&operations)
            .expect("operation vector serializes");
        assert_eq!(
            Hash256::digest(bytes).to_hex(),
            "2d417a59882276e5908593eae97e323e4db4fceb324e5ff9d27ae895a0bbd1f5"
        );
        assert_eq!(
            serde_json::to_string(&Operation::ClaimValidatorRewards)
                .expect("unit operation serializes"),
            r#""ClaimValidatorRewards""#
        );
        assert_eq!(
            sender.address().to_string(),
            "webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3"
        );
    }

    #[test]
    fn session_and_rotation_operations_have_a_stable_cross_language_wire_vector() {
        // Deterministic placeholder bytes make this a cross-language vector: the
        // TypeScript SDK builds the same four operations and must hash to the same
        // value. Real signatures are unnecessary — only the canonical JSON shape
        // and field naming are under test. If this hash changes, the SDK vector in
        // `sdk/webc-js/src/transaction.test.ts` MUST be updated to match.
        let reveal = PostQuantumRootReveal {
            scheme: crate::PostQuantumScheme::MlDsa65,
            public_key: vec![0x33; 1952],
            signature: vec![0x44; 3309],
        };
        let constraints = SessionKeyConstraints {
            authorization_lane: AuthorizationLaneId::DEFAULT,
            allowed_operations: crate::SessionAllowedOperations::transfers_only(),
            max_amount_per_use: Amount::from_units(5),
            total_amount_budget: Amount::from_units(20),
            max_fee_per_use: Amount::from_units(1),
            total_fee_budget: Amount::from_units(5),
            lifetime_epochs: 60,
        };
        let operations = vec![
            Operation::InstallSessionKey {
                session_public_key: PublicKeyBytes([0x11; 32]),
                constraints: constraints.clone(),
                post_quantum_root_reveal: reveal.clone(),
            },
            Operation::RevokeSessionKey {
                session_key: SessionKeyId::new(Hash256([0x55; 32])),
                post_quantum_root_reveal: reveal.clone(),
            },
            Operation::RotateActiveTransactionKey {
                new_active_transaction_key: PublicKeyBytes([0x66; 32]),
                post_quantum_root_reveal: reveal.clone(),
            },
            Operation::RotatePostQuantumRoot {
                new_post_quantum_root: PostQuantumRoot::new(
                    crate::PostQuantumScheme::MlDsa65,
                    Hash256([0x22; 32]),
                )
                .unwrap(),
                post_quantum_root_reveal: reveal,
            },
        ];
        let bytes = crate::canonical::canonical_json_bytes(&operations)
            .expect("session/rotation operation vector serializes");
        assert_eq!(
            Hash256::digest(bytes).to_hex(),
            "272f10267381f778bb9dc0d2d81c3aba143081facb9f677216e0e7bb538dbf1d"
        );
    }

    #[test]
    fn signed_transaction_wire_vector_round_trips() {
        let sender = Keypair::from_seed([1u8; 32]);
        let recipient = Keypair::from_seed([2u8; 32]);
        let transaction = Transaction::for_operation(
            &sender,
            7,
            Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(123_456),
            },
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
        )
        .expect("wire fixture signs");
        let canonical = crate::canonical::canonical_json_string(&transaction)
            .expect("signed transaction serializes");
        let expected = format!(
            r#"{{"access_list":{{"read_only":[{{"kind":{{"Protocol":{{"field":"BaseFee"}}}},"version":1}},{{"kind":{{"AuthorizationPolicy":{{"owner":"{}"}}}},"version":1}}],"read_write":[{{"kind":{{"Account":{{"address":"{}"}}}},"version":1}},{{"kind":{{"Account":{{"address":"{}"}}}},"version":1}},{{"kind":{{"FeeAccumulator":{{"lane":"0000000000000000000000000000000000000000000000000000000000000000","payer":"{}"}}}},"version":1}}]}},"authorization_lane":"0000000000000000000000000000000000000000000000000000000000000000","authorization_policy_revision":0,"chain_id":"webc-devnet-1","fee":{{"gas_limit":1000,"max_fee_per_unit":5,"priority_fee_per_unit":1}},"nonce":7,"operation":{{"Transfer":{{"amount":"123456","to":"{}"}}}},"protocol_version":1,"public_key":"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c","sender":"{}","signature":"2c7c52e849d29b96605c8e936d1380d8a241b18ba8b1d2fef72bfbc06af4ce9a83ce3e58151ece30a91108a0dbba502788addfdf66a2c6ae48409d9557a1f305"}}"#,
            sender.address(),
            sender.address(),
            recipient.address(),
            sender.address(),
            recipient.address(),
            sender.address(),
        );
        assert_eq!(canonical, expected);
        assert_eq!(
            transaction.hash().expect("fixture hashes").to_hex(),
            "f96ee7384499aa9670ddb2829aca699d97a88c610cb6c0e56662e9ba8e5092a1"
        );
        let decoded: Transaction =
            serde_json::from_str(&canonical).expect("fixture decodes in Rust");
        assert_eq!(decoded, transaction);
        decoded
            .verify()
            .expect("decoded fixture signature verifies");

        let mut legacy = serde_json::to_value(&transaction).expect("fixture to value");
        let fields = legacy.as_object_mut().expect("transaction is an object");
        let public_key = fields.remove("public_key").expect("public key exists");
        fields.insert("publicKeyHex".to_owned(), public_key);
        assert!(serde_json::from_value::<Transaction>(legacy).is_err());
    }
}
