//! Protocol-version-2 transaction wire foundation.
//!
//! This module owns the immutable V5 sender/sponsor signing schemas, ordered
//! native-action envelope, cancellation form, consensus height validity, and
//! structural hostile-input limits. It deliberately does not execute actions,
//! read chain state, decide mempool policy, or activate protocol version 2.
//! Callers first decode with [`TransactionV5::decode_json`], then verify the
//! stateless structure/signatures, and later pass the value to the stateful
//! validation/execution pipeline. All newly introduced `u64` values serialize
//! as canonical decimal strings so browsers never round consensus data.
//!
//! Security boundary: V5 and every nested authorization are domain-separated;
//! action count, signed byte size, validity span, and fee multiplication are
//! bounded before state or cryptographic work. V4 types and fixtures remain
//! untouched and are never accepted by this module.

use crate::{
    AccessList, Amount, AuthorizationLaneId, AuthorizationPolicyRevision, BlockHeight, ChainId,
    FeeBid, Nonce, Operation, ProtocolVersion, SessionKeyId, StateKey, MAX_OBJECT_DATA_BYTES,
    MAX_TRANSACTION_STATE_KEYS,
};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use webc_crypto::{verify_signature, Address, Hash256, Keypair, PublicKeyBytes, SignatureBytes};

/// Protocol configuration that interprets the V5 transaction schema.
pub const TRANSACTION_V5_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(2);

/// Sender-signature domain for the immutable V5 payload.
pub const TRANSACTION_V5_SIGNING_DOMAIN: &str = "WEBC_SIGNED_TRANSACTION_V5";

/// Domain for a stable identifier of one complete signed V5 transaction.
pub const TRANSACTION_ID_V1_DOMAIN: &str = "WEBC_TRANSACTION_ID_V1";

/// Domain for an ordered native action program digest.
pub const ACTION_PROGRAM_V1_DOMAIN: &str = "WEBC_ACTION_PROGRAM_V1";

/// Domain for a canonical V5 fee-bid digest used by sponsorship.
pub const FEE_BID_V1_DOMAIN: &str = "WEBC_FEE_BID_V1";

/// Sponsor-signature and immutable grant-digest domain.
pub const SPONSOR_GRANT_V1_DOMAIN: &str = "WEBC_SPONSOR_GRANT_V1";

/// Domain for binding one grant-use nonce to one action program and fee bid.
pub const SPONSOR_USE_V1_DOMAIN: &str = "WEBC_SPONSOR_USE_V1";

/// Maximum number of ordered actions in one V5 program.
pub const MAX_ACTIONS_V1: usize = 32;

/// Maximum canonical JSON size of one complete signed V5 transaction, in bytes.
pub const MAX_TRANSACTION_V5_CANONICAL_BYTES: usize = 256 * 1024;

/// Maximum number of block heights covered by an inclusive V5 validity range.
pub const MAX_TRANSACTION_VALIDITY_BLOCKS: u64 = 4_096;

/// Fixed deterministic units reserved for an included cancellation transaction.
pub const CANCEL_V1_REQUIRED_UNITS: u64 = 50;

/// Fixed deterministic units for revoking one scoped sponsor grant.
pub const REVOKE_SPONSOR_GRANT_V1_REQUIRED_UNITS: u64 = 5_000;

/// Fixed units for verifying and potentially recording a signed-grant revocation.
///
/// The conservative prototype value prices one durable record even if that
/// record already exists. Keeping this cost stateless prevents block admission,
/// receipts, and fee charging from disagreeing about first-use state.
pub const REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS: u64 = 100_000;

/// Fixed units charged to every sponsored transaction for grant bookkeeping.
///
/// A first use creates one durable replay/budget record, including when the
/// sponsored transaction is a 50-unit cancellation or later action failure.
/// Charging every use is deliberately conservative until storage deposits and
/// benchmark-backed dynamic state costs are available.
pub const SPONSOR_GRANT_USE_V1_REQUIRED_UNITS: u64 = 100_000;

/// Stable typed failures from stateless V5 decoding and verification.
///
/// These codes are safe to map to node/API validation errors. Stateful failures
/// such as a stale nonce, base-fee mismatch, sponsor revocation, or insufficient
/// reserve belong to the later preparation layer and are intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransactionValidationErrorV1 {
    /// The submitted JSON body exceeds the consensus transaction byte ceiling.
    #[error("transaction exceeds the {MAX_TRANSACTION_V5_CANONICAL_BYTES}-byte V5 limit")]
    TransactionTooLarge,
    /// The JSON shape, exact decimal string, or strict nested schema is invalid.
    #[error("malformed V5 transaction")]
    MalformedTransaction,
    /// Canonical serialization failed or encountered an unsupported value.
    #[error("V5 transaction cannot be canonically encoded")]
    CanonicalEncoding,
    /// The payload does not explicitly select protocol version 2.
    #[error("unsupported V5 protocol version")]
    UnsupportedProtocolVersion,
    /// The signed network differs from the verifier's configured network.
    #[error("transaction chain ID does not match the configured chain")]
    WrongChain,
    /// The inclusive range is reversed or cannot be represented safely.
    #[error("transaction validity range is invalid")]
    InvalidValidityRange,
    /// The inclusive range covers more than 4,096 block heights.
    #[error("transaction validity range is too long")]
    ValidityRangeTooLong,
    /// An action program contains no action.
    #[error("V5 action program must not be empty")]
    EmptyActionProgram,
    /// An action program exceeds the 32-action bound.
    #[error("V5 action program contains too many actions")]
    TooManyActions,
    /// Summing statically measured action units overflowed `u64`.
    #[error("V5 action units overflow")]
    ActionUnitsOverflow,
    /// A native action contains an intrinsically invalid signed parameter or lane.
    #[error("V5 native action is structurally invalid")]
    InvalidNativeAction,
    /// This executable has not activated the selected native transition for V5.
    #[error("V5 native action is not supported by this executable")]
    UnsupportedNativeAction,
    /// The fee bid has a zero limit/rate or a priority rate above its maximum.
    #[error("V5 fee bid is structurally invalid")]
    InvalidFeeBid,
    /// Fee reserve multiplication overflowed the native `u128` amount range.
    #[error("V5 fee reserve overflows")]
    FeeReserveOverflow,
    /// The declared key list is oversized, duplicated, or internally overlaps.
    #[error("V5 declared state access is structurally invalid")]
    InvalidAccessList,
    /// The sender signature is absent.
    #[error("V5 transaction is missing its sender signature")]
    MissingSenderSignature,
    /// The sender signature does not verify over the exact V5 canonical payload.
    #[error("V5 sender signature is invalid")]
    InvalidSenderSignature,
    /// The sponsor grant has invalid bounds, identity, scope, or budget.
    #[error("V5 sponsor grant is structurally invalid")]
    InvalidSponsorGrant,
    /// The sponsor grant has no sponsor signature.
    #[error("V5 sponsor grant is missing its signature")]
    MissingSponsorSignature,
    /// The sponsor signature does not verify over the exact immutable grant.
    #[error("V5 sponsor grant signature is invalid")]
    InvalidSponsorSignature,
    /// A sponsor use does not bind the transaction's chain, sender, actions, or fee bid.
    #[error("V5 sponsor use does not match the transaction")]
    SponsorBindingMismatch,
}

/// Stable identity of a complete signed V5 transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransactionId(Hash256);

impl TransactionId {
    /// Constructs an identifier from an already domain-separated digest.
    pub const fn new(digest: Hash256) -> Self {
        Self(digest)
    }

    /// Returns the underlying 32-byte digest.
    pub const fn digest(self) -> Hash256 {
        self.0
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Opaque identity of one immutable sponsor grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SponsorGrantId(Hash256);

impl SponsorGrantId {
    /// Constructs a grant identity from a wallet-generated 32-byte value.
    pub const fn new(value: Hash256) -> Self {
        Self(value)
    }

    /// Returns the underlying grant identity.
    pub const fn digest(self) -> Hash256 {
        self.0
    }
}

/// Monotonic replay counter in one sponsor grant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SponsorUseNonce(u64);

impl SponsorUseNonce {
    /// Constructs a sponsor-use nonce from its unsigned consensus unit.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the unsigned consensus unit.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances the replay counter without wrapping.
    pub fn checked_next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl Serialize for SponsorUseNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SponsorUseNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_decimal_u64(deserializer).map(Self)
    }
}

/// Count of fee-paying inclusions consumed by one sponsor grant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SponsorUseCount(u64);

impl SponsorUseCount {
    /// Constructs a use count from its unsigned consensus unit.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the unsigned consensus unit.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Advances the count without wrapping.
    pub fn checked_next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl Serialize for SponsorUseCount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for SponsorUseCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_decimal_u64(deserializer).map(Self)
    }
}

/// Inclusive consensus-height validity window signed by a wallet or sponsor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidityWindowV1 {
    /// First block height at which the artifact may be included.
    #[serde(with = "block_height_decimal")]
    pub valid_from_height: BlockHeight,
    /// Last block height at which the artifact may be included.
    #[serde(with = "block_height_decimal")]
    pub valid_until_height: BlockHeight,
}

impl ValidityWindowV1 {
    /// Constructs a candidate inclusive height range without validating it.
    pub const fn new(valid_from_height: BlockHeight, valid_until_height: BlockHeight) -> Self {
        Self {
            valid_from_height,
            valid_until_height,
        }
    }

    /// Validates ordering and the 4,096-height inclusive consensus span.
    pub fn validate(self) -> Result<(), TransactionValidationErrorV1> {
        let difference = self
            .valid_until_height
            .get()
            .checked_sub(self.valid_from_height.get())
            .ok_or(TransactionValidationErrorV1::InvalidValidityRange)?;
        let inclusive_count = difference
            .checked_add(1)
            .ok_or(TransactionValidationErrorV1::InvalidValidityRange)?;
        if inclusive_count > MAX_TRANSACTION_VALIDITY_BLOCKS {
            return Err(TransactionValidationErrorV1::ValidityRangeTooLong);
        }
        Ok(())
    }

    /// Returns whether `height` lies inside the signed inclusive range.
    pub fn contains(self, height: BlockHeight) -> bool {
        self.valid_from_height <= height && height <= self.valid_until_height
    }

    /// Returns whether this outer window fully contains `inner`.
    pub fn covers(self, inner: Self) -> bool {
        self.valid_from_height <= inner.valid_from_height
            && inner.valid_until_height <= self.valid_until_height
    }
}

/// Versioned sender authorization coordinates for one V5 transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionAuthorizationV1 {
    /// Independent wallet authorization/fee lane.
    pub lane: AuthorizationLaneId,
    /// Account-policy revision under which the sender key is checked statefully.
    #[serde(with = "authorization_revision_decimal")]
    pub policy_revision: AuthorizationPolicyRevision,
    /// Replay-protection sequence inside `lane`.
    #[serde(with = "nonce_decimal")]
    pub nonce: Nonce,
}

/// One version-1 action, initially reusing a reviewed native operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ActionV1 {
    /// Existing deterministic native operation with unchanged execution semantics.
    Native {
        /// Native operation executed at this ordered action position.
        operation: Box<Operation>,
    },
    /// Permanently prevents later uses of one grant issued by the sender.
    RevokeSponsorGrant {
        /// Wallet-generated identity of the grant being revoked.
        grant_id: SponsorGrantId,
    },
    /// Revokes an unused grant while authenticating its identity and expiry.
    ///
    /// This form is larger than the ID-only path but can safely create a
    /// bounded pre-use record. The sender must be the grant sponsor.
    RevokeSignedSponsorGrant {
        /// Complete immutable grant carrying sponsor signature and lifetime.
        grant: Box<SponsorGrantV1>,
    },
}

impl ActionV1 {
    /// Wraps an existing native operation as a V1 action.
    pub fn native(operation: Operation) -> Self {
        Self::Native {
            operation: Box::new(operation),
        }
    }

    /// Constructs a protocol-2 sponsor-grant revocation action.
    pub const fn revoke_sponsor_grant(grant_id: SponsorGrantId) -> Self {
        Self::RevokeSponsorGrant { grant_id }
    }

    /// Constructs a pre-use revocation carrying authenticated grant lifetime.
    pub fn revoke_signed_sponsor_grant(grant: SponsorGrantV1) -> Self {
        Self::RevokeSignedSponsorGrant {
            grant: Box::new(grant),
        }
    }

    /// Returns the deterministic units statically assigned to this action.
    pub fn required_units(&self) -> u64 {
        match self {
            Self::Native { operation } => operation.required_units(),
            Self::RevokeSponsorGrant { .. } => REVOKE_SPONSOR_GRANT_V1_REQUIRED_UNITS,
            Self::RevokeSignedSponsorGrant { .. } => REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS,
        }
    }

    /// Returns whether this executable can run the action under V5 semantics.
    ///
    /// Admission and execution share this capability gate so an inactive
    /// operation cannot occupy a queue or invalidate a proposed block after it
    /// was described as prepared/includable.
    pub(crate) fn execution_supported(&self) -> bool {
        match self {
            Self::RevokeSponsorGrant { .. } | Self::RevokeSignedSponsorGrant { .. } => true,
            Self::Native { operation } => matches!(
                operation.as_ref(),
                Operation::Transfer { .. }
                    | Operation::InstallAuthorizationPolicy { .. }
                    | Operation::OpenAuthorizationLane { .. }
                    | Operation::FundAuthorizationLane { .. }
                    | Operation::ClaimValidatorRewards
                    | Operation::ClaimDelegatorRewards { .. }
                    | Operation::ClaimUnbonded { .. }
                    | Operation::CreateObject { .. }
                    | Operation::MutateObject { .. }
                    | Operation::TransferObject { .. }
            ),
        }
    }

    /// Validates signed native parameters that never require chain state.
    fn validate_structure(&self) -> Result<(), TransactionValidationErrorV1> {
        if !self.execution_supported() {
            return Err(TransactionValidationErrorV1::UnsupportedNativeAction);
        }
        let Self::Native { operation } = self else {
            return match self {
                Self::RevokeSponsorGrant { grant_id } if grant_id.digest() == Hash256::ZERO => {
                    Err(TransactionValidationErrorV1::InvalidNativeAction)
                }
                Self::RevokeSponsorGrant { .. } => Ok(()),
                Self::RevokeSignedSponsorGrant { grant } => {
                    grant.validate_structure()?;
                    if grant.sponsor_signature.is_none() {
                        return Err(TransactionValidationErrorV1::MissingSponsorSignature);
                    }
                    Ok(())
                }
                Self::Native { .. } => Err(TransactionValidationErrorV1::InvalidNativeAction),
            };
        };
        match operation.as_ref() {
            Operation::InstallAuthorizationPolicy { post_quantum_root }
                if post_quantum_root.validate().is_err() =>
            {
                Err(TransactionValidationErrorV1::InvalidNativeAction)
            }
            Operation::OpenAuthorizationLane { lane, fee_deposit }
                if lane.is_default() || fee_deposit.is_zero() =>
            {
                Err(TransactionValidationErrorV1::InvalidNativeAction)
            }
            Operation::FundAuthorizationLane { lane, fee_deposit }
                if lane.is_default() || fee_deposit.is_zero() =>
            {
                Err(TransactionValidationErrorV1::InvalidNativeAction)
            }
            Operation::CreateObject { data, .. } | Operation::MutateObject { data, .. }
                if data.len() > MAX_OBJECT_DATA_BYTES =>
            {
                Err(TransactionValidationErrorV1::InvalidNativeAction)
            }
            _ => Ok(()),
        }
    }

    /// Builds the exact sender/action access for this action.
    fn default_access_list_for_lane(
        &self,
        sender: Address,
        lane: AuthorizationLaneId,
    ) -> Result<AccessList, TransactionValidationErrorV1> {
        match self {
            Self::Native { operation } => operation
                .default_access_list_for_lane(sender, lane)
                .map_err(|_| TransactionValidationErrorV1::InvalidAccessList),
            Self::RevokeSponsorGrant { grant_id } => {
                let mut access = cancel_access_list(sender, lane);
                access
                    .read_write
                    .push(StateKey::sponsor_grant(sender, grant_id.digest()));
                Ok(access)
            }
            Self::RevokeSignedSponsorGrant { grant } => {
                let mut access = cancel_access_list(sender, lane);
                access
                    .read_write
                    .push(StateKey::sponsor_grant(sender, grant.grant_id.digest()));
                Ok(access)
            }
        }
    }
}

/// Bounded, ordered, atomic native-action program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionProgramV1 {
    /// Actions executed in ascending vector position; 1 through 32 entries.
    pub actions: Vec<ActionV1>,
}

impl ActionProgramV1 {
    /// Constructs a candidate action program without validating its count.
    pub fn new(actions: Vec<ActionV1>) -> Self {
        Self { actions }
    }

    /// Validates the action-count bound and checked aggregate unit total.
    pub fn validate(&self) -> Result<(), TransactionValidationErrorV1> {
        if self.actions.is_empty() {
            return Err(TransactionValidationErrorV1::EmptyActionProgram);
        }
        if self.actions.len() > MAX_ACTIONS_V1 {
            return Err(TransactionValidationErrorV1::TooManyActions);
        }
        for action in &self.actions {
            action.validate_structure()?;
        }
        self.required_units()?;
        Ok(())
    }

    /// Returns checked deterministic units for every ordered action.
    pub fn required_units(&self) -> Result<u64, TransactionValidationErrorV1> {
        self.actions.iter().try_fold(0_u64, |total, action| {
            total
                .checked_add(action.required_units())
                .ok_or(TransactionValidationErrorV1::ActionUnitsOverflow)
        })
    }

    /// Builds the sorted exact union of existing native-operation access lists.
    ///
    /// A key required writable by any action is writable for the whole atomic
    /// program. Sorting avoids action-order-dependent declaration bytes while
    /// action order itself remains signed separately in `actions`.
    pub fn default_access_list_for_lane(
        &self,
        sender: Address,
        lane: AuthorizationLaneId,
    ) -> Result<AccessList, TransactionValidationErrorV1> {
        self.validate()?;
        let mut read_only = BTreeSet::new();
        let mut read_write = BTreeSet::new();
        for action in &self.actions {
            let access = action.default_access_list_for_lane(sender, lane)?;
            for key in access.read_write {
                read_only.remove(&key);
                read_write.insert(key);
            }
            for key in access.read_only {
                if !read_write.contains(&key) {
                    read_only.insert(key);
                }
            }
        }
        Ok(AccessList::new(
            read_only.into_iter().collect(),
            read_write.into_iter().collect(),
        ))
    }
}

/// Signed no-effect replacement that consumes the selected sender nonce.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelV1 {}

/// Top-level V5 transaction form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum TransactionKindV1 {
    /// Ordered native actions that commit atomically in the later execution layer.
    Actions(ActionProgramV1),
    /// Signed cancellation competing for the same sender/lane/nonce slot.
    Cancel(CancelV1),
}

impl TransactionKindV1 {
    /// Validates the selected form and all structural action bounds.
    pub fn validate(&self) -> Result<(), TransactionValidationErrorV1> {
        match self {
            Self::Actions(program) => program.validate(),
            Self::Cancel(_) => Ok(()),
        }
    }

    /// Returns checked static units for this transaction form.
    pub fn required_units(&self) -> Result<u64, TransactionValidationErrorV1> {
        match self {
            Self::Actions(program) => program.required_units(),
            Self::Cancel(_) => Ok(CANCEL_V1_REQUIRED_UNITS),
        }
    }

    /// Computes a domain-separated digest of the exact ordered form.
    pub fn digest(&self) -> Result<Hash256, TransactionValidationErrorV1> {
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            kind: &'a TransactionKindV1,
        }
        canonical_hash(&Payload {
            domain: ACTION_PROGRAM_V1_DOMAIN,
            kind: self,
        })
    }

    /// Builds the exact sender-lane access baseline for this transaction form.
    ///
    /// Sponsorship later replaces only the fee-payer portion; sender nonce,
    /// authorization, and action access remain bound to this list.
    fn default_access_list_for_lane(
        &self,
        sender: Address,
        lane: AuthorizationLaneId,
    ) -> Result<AccessList, TransactionValidationErrorV1> {
        match self {
            Self::Actions(program) => program.default_access_list_for_lane(sender, lane),
            Self::Cancel(_) => Ok(cancel_access_list(sender, lane)),
        }
    }
}

/// Exact state touched by a sender-paid cancellation.
///
/// A cancellation has no action state, but inclusion still reads sender
/// authorization/base-fee state, advances the selected nonce, and accounts for
/// fees. Keeping those keys explicit prevents cancellation from becoming an
/// undeclared state mutation when V5 execution activates.
fn cancel_access_list(sender: Address, lane: AuthorizationLaneId) -> AccessList {
    let read_only = vec![
        StateKey::protocol(crate::ProtocolStateKey::BaseFee),
        StateKey::authorization_policy(sender),
    ];
    let nonce_key = if lane.is_default() {
        StateKey::account(sender)
    } else {
        StateKey::authorization_lane(sender, lane)
    };
    AccessList::new(
        read_only,
        vec![nonce_key, StateKey::fee_accumulator_for_lane(sender, lane)],
    )
}

/// Exact action scope authorized by a version-1 sponsor grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionScopeV1 {
    /// Digest from [`TransactionKindV1::digest`].
    pub exact_action_digest: Hash256,
}

impl ActionScopeV1 {
    /// Creates an exact-action scope from a precomputed domain-separated digest.
    pub const fn exact(exact_action_digest: Hash256) -> Self {
        Self {
            exact_action_digest,
        }
    }
}

/// Immutable sponsor authorization signed independently from the sender.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorGrantV1 {
    /// Protocol schema version; exactly 2 for this grant type.
    pub protocol_version: ProtocolVersion,
    /// Network on which the grant may pay fees.
    pub chain_id: ChainId,
    /// Wallet-generated non-zero replay identity for durable grant state.
    pub grant_id: SponsorGrantId,
    /// Account whose fee lane is debited.
    pub sponsor: Address,
    /// Ed25519 key whose stateful policy authority must later match `sponsor`.
    pub sponsor_public_key: PublicKeyBytes,
    /// Sponsor-owned fee lane used for reservation and charging.
    pub payer_lane: AuthorizationLaneId,
    /// Sole sender whose transaction may consume this grant.
    pub sender: Address,
    /// Optional hash of a wallet-validated website origin scope.
    pub site_namespace: Option<Hash256>,
    /// Optional on-chain application namespace scope.
    pub application_namespace: Option<Hash256>,
    /// Exact V1 action/cancellation digest permitted by this grant.
    pub action_scope: ActionScopeV1,
    /// Inclusive grant lifetime in consensus block heights.
    pub validity: ValidityWindowV1,
    /// Maximum native base units chargeable by any one use.
    pub max_fee_per_transaction: Amount,
    /// Maximum native base units chargeable across every use.
    pub max_cumulative_fee: Amount,
    /// Maximum successful fee reservations/charges across the grant lifetime.
    #[serde(with = "u64_decimal")]
    pub max_uses: u64,
    /// Sponsor signature over the canonical immutable grant, absent before signing.
    pub sponsor_signature: Option<SignatureBytes>,
}

impl SponsorGrantV1 {
    /// Validates immutable grant bounds without reading sponsor state.
    pub fn validate_structure(&self) -> Result<(), TransactionValidationErrorV1> {
        if self.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION
            || self.grant_id.digest() == Hash256::ZERO
            || self.action_scope.exact_action_digest == Hash256::ZERO
            || self.max_fee_per_transaction.is_zero()
            || self.max_cumulative_fee < self.max_fee_per_transaction
            || self.max_uses == 0
        {
            return Err(TransactionValidationErrorV1::InvalidSponsorGrant);
        }
        self.validity
            .validate()
            .map_err(|_| TransactionValidationErrorV1::InvalidSponsorGrant)?;
        Ok(())
    }

    /// Signs the immutable grant with an address-derived sponsor key.
    pub fn sign(&mut self, keypair: &Keypair) -> Result<(), TransactionValidationErrorV1> {
        if keypair.address() != self.sponsor {
            return Err(TransactionValidationErrorV1::InvalidSponsorGrant);
        }
        self.sign_with_policy_key(keypair)
    }

    /// Signs with a policy-selected sponsor key; state later checks its authority.
    pub fn sign_with_policy_key(
        &mut self,
        keypair: &Keypair,
    ) -> Result<(), TransactionValidationErrorV1> {
        self.validate_structure()?;
        self.sponsor_public_key = keypair.public_key();
        self.sponsor_signature = Some(keypair.sign(&self.signing_bytes()?));
        Ok(())
    }

    /// Verifies immutable structure and the sponsor signature.
    pub fn verify(&self) -> Result<(), TransactionValidationErrorV1> {
        self.validate_structure()?;
        let signature = self
            .sponsor_signature
            .as_ref()
            .ok_or(TransactionValidationErrorV1::MissingSponsorSignature)?;
        verify_signature(&self.sponsor_public_key, &self.signing_bytes()?, signature)
            .map_err(|_| TransactionValidationErrorV1::InvalidSponsorSignature)
    }

    /// Returns a domain-separated digest of the complete signed grant.
    pub fn digest(&self) -> Result<Hash256, TransactionValidationErrorV1> {
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            grant: &'a SponsorGrantV1,
        }
        canonical_hash(&Payload {
            domain: SPONSOR_GRANT_V1_DOMAIN,
            grant: self,
        })
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, TransactionValidationErrorV1> {
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            protocol_version: ProtocolVersion,
            chain_id: &'a ChainId,
            grant_id: SponsorGrantId,
            sponsor: Address,
            sponsor_public_key: PublicKeyBytes,
            payer_lane: AuthorizationLaneId,
            sender: Address,
            site_namespace: Option<Hash256>,
            application_namespace: Option<Hash256>,
            action_scope: ActionScopeV1,
            validity: ValidityWindowV1,
            max_fee_per_transaction: Amount,
            max_cumulative_fee: Amount,
            #[serde(with = "u64_decimal")]
            max_uses: u64,
        }
        canonical_bytes(&Payload {
            domain: SPONSOR_GRANT_V1_DOMAIN,
            protocol_version: self.protocol_version,
            chain_id: &self.chain_id,
            grant_id: self.grant_id,
            sponsor: self.sponsor,
            sponsor_public_key: self.sponsor_public_key,
            payer_lane: self.payer_lane,
            sender: self.sender,
            site_namespace: self.site_namespace,
            application_namespace: self.application_namespace,
            action_scope: self.action_scope,
            validity: self.validity,
            max_fee_per_transaction: self.max_fee_per_transaction,
            max_cumulative_fee: self.max_cumulative_fee,
            max_uses: self.max_uses,
        })
    }
}

/// One replay-bounded use of a signed sponsor grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorUseV1 {
    /// Complete immutable grant whose signature can be checked statelessly.
    pub grant: SponsorGrantV1,
    /// Digest of `grant`, preventing substitution during durable lookup.
    pub grant_digest: Hash256,
    /// Strictly increasing nonce checked against durable grant state.
    pub use_nonce: SponsorUseNonce,
    /// Exact V1 action/cancellation digest being paid for.
    pub action_digest: Hash256,
    /// Exact V1 fee-bid digest being paid for.
    pub fee_bid_digest: Hash256,
}

impl SponsorUseV1 {
    /// Constructs a grant use bound to one transaction form and fee bid.
    pub fn for_transaction(
        grant: SponsorGrantV1,
        use_nonce: SponsorUseNonce,
        kind: &TransactionKindV1,
        fee_bid: FeeBid,
    ) -> Result<Self, TransactionValidationErrorV1> {
        let grant_digest = grant.digest()?;
        Ok(Self {
            grant,
            grant_digest,
            use_nonce,
            action_digest: kind.digest()?,
            fee_bid_digest: fee_bid_digest(fee_bid)?,
        })
    }

    /// Returns a domain-separated identity for this exact replay-bounded use.
    pub fn digest(&self) -> Result<Hash256, TransactionValidationErrorV1> {
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            sponsor_use: &'a SponsorUseV1,
        }
        canonical_hash(&Payload {
            domain: SPONSOR_USE_V1_DOMAIN,
            sponsor_use: self,
        })
    }
}

/// Account/lane that reserves and pays the V5 transaction fee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FeePaymentV1 {
    /// Sender pays from the authorization lane named in the transaction.
    SenderLane,
    /// Separate sponsor pays under an immutable scoped grant.
    Sponsored(Box<SponsorUseV1>),
}

/// Complete signed protocol-version-2 transaction envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionV5 {
    /// Protocol schema version; exactly 2 for V5.
    pub protocol_version: ProtocolVersion,
    /// Network replay-protection identifier.
    pub chain_id: ChainId,
    /// Account authorizing every action and consuming the sender nonce.
    pub sender: Address,
    /// Ed25519 key checked against sender policy by stateful validation.
    pub sender_public_key: PublicKeyBytes,
    /// Authorization lane, policy revision, and nonce.
    pub authorization: TransactionAuthorizationV1,
    /// Inclusive signed block-height range.
    pub validity: ValidityWindowV1,
    /// Ordered atomic actions or cancellation.
    pub kind: TransactionKindV1,
    /// Exact logical state declaration signed by the sender.
    pub access_list: AccessList,
    /// Existing fee bid encoded with exact decimal-string `u64` fields.
    #[serde(with = "fee_bid_decimal")]
    pub fee_bid: FeeBid,
    /// Sender lane or scoped sponsor fee authorization.
    pub fee_payment: FeePaymentV1,
    /// Sender signature over every preceding field, absent before signing.
    pub sender_signature: Option<SignatureBytes>,
}

impl TransactionV5 {
    /// Constructs an unsigned candidate without performing structural checks.
    #[allow(
        clippy::too_many_arguments,
        reason = "wire construction keeps every authority and validity field explicit"
    )]
    pub fn new_unsigned(
        chain_id: ChainId,
        sender: Address,
        sender_public_key: PublicKeyBytes,
        authorization: TransactionAuthorizationV1,
        validity: ValidityWindowV1,
        kind: TransactionKindV1,
        access_list: AccessList,
        fee_bid: FeeBid,
        fee_payment: FeePaymentV1,
    ) -> Self {
        Self {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id,
            sender,
            sender_public_key,
            authorization,
            validity,
            kind,
            access_list,
            fee_bid,
            fee_payment,
            sender_signature: None,
        }
    }

    /// Builds an unsigned action transaction with its deterministic access union.
    #[allow(
        clippy::too_many_arguments,
        reason = "builder keeps chain, policy, lane, validity, actions, and fees explicit"
    )]
    pub fn for_actions_unsigned(
        chain_id: ChainId,
        sender: Address,
        sender_public_key: PublicKeyBytes,
        authorization: TransactionAuthorizationV1,
        validity: ValidityWindowV1,
        actions: Vec<ActionV1>,
        fee_bid: FeeBid,
        fee_payment: FeePaymentV1,
    ) -> Result<Self, TransactionValidationErrorV1> {
        let program = ActionProgramV1::new(actions);
        validate_native_action_lane(&program, authorization.lane)?;
        let access_list = program.default_access_list_for_lane(sender, authorization.lane)?;
        Ok(Self::new_unsigned(
            chain_id,
            sender,
            sender_public_key,
            authorization,
            validity,
            TransactionKindV1::Actions(program),
            access_list,
            fee_bid,
            fee_payment,
        ))
    }

    /// Builds an unsigned action transaction authorized by a constrained session key.
    ///
    /// This is a distinct constructor because session execution mutates the
    /// cumulative session budget and must therefore sign that derived state key.
    /// The wire schema is unchanged; only the exact access declaration differs
    /// from an active-account-key transaction.
    #[allow(
        clippy::too_many_arguments,
        reason = "builder keeps chain, session policy, lane, validity, actions, and fees explicit"
    )]
    pub fn for_session_actions_unsigned(
        chain_id: ChainId,
        sender: Address,
        session_public_key: PublicKeyBytes,
        authorization: TransactionAuthorizationV1,
        validity: ValidityWindowV1,
        actions: Vec<ActionV1>,
        fee_bid: FeeBid,
        fee_payment: FeePaymentV1,
    ) -> Result<Self, TransactionValidationErrorV1> {
        let mut transaction = Self::for_actions_unsigned(
            chain_id,
            sender,
            session_public_key,
            authorization,
            validity,
            actions,
            fee_bid,
            fee_payment,
        )?;
        transaction.access_list = transaction.expected_session_access_list()?;
        Ok(transaction)
    }

    /// Builds an unsigned no-effect cancellation for a sender slot.
    pub fn for_cancel_unsigned(
        chain_id: ChainId,
        sender: Address,
        sender_public_key: PublicKeyBytes,
        authorization: TransactionAuthorizationV1,
        validity: ValidityWindowV1,
        fee_bid: FeeBid,
        fee_payment: FeePaymentV1,
    ) -> Self {
        let access_list = cancel_access_list(sender, authorization.lane);
        Self::new_unsigned(
            chain_id,
            sender,
            sender_public_key,
            authorization,
            validity,
            TransactionKindV1::Cancel(CancelV1 {}),
            access_list,
            fee_bid,
            fee_payment,
        )
    }

    /// Decodes a bounded hostile JSON object with strict nested schemas.
    ///
    /// The byte ceiling is checked before JSON allocation. Structural and
    /// signature verification remain explicit follow-up calls because wallet
    /// construction also needs to represent an unsigned candidate.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, TransactionValidationErrorV1> {
        if bytes.len() > MAX_TRANSACTION_V5_CANONICAL_BYTES {
            return Err(TransactionValidationErrorV1::TransactionTooLarge);
        }
        serde_json::from_slice(bytes)
            .map_err(|_| TransactionValidationErrorV1::MalformedTransaction)
    }

    /// Validates stateless schema, bounds, sponsorship binding, and byte size.
    pub fn validate_structure(&self) -> Result<(), TransactionValidationErrorV1> {
        if self.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION {
            return Err(TransactionValidationErrorV1::UnsupportedProtocolVersion);
        }
        self.validity.validate()?;
        self.kind.validate()?;
        if let TransactionKindV1::Actions(program) = &self.kind {
            validate_native_action_lane(program, self.authorization.lane)?;
            for action in &program.actions {
                let ActionV1::RevokeSignedSponsorGrant { grant } = action else {
                    continue;
                };
                if grant.sponsor != self.sender
                    || grant.chain_id != self.chain_id
                    || grant.protocol_version != self.protocol_version
                {
                    return Err(TransactionValidationErrorV1::SponsorBindingMismatch);
                }
            }
        }
        validate_fee_bid(self.fee_bid)?;
        validate_access_list(&self.access_list)?;
        if matches!(self.fee_payment, FeePaymentV1::SenderLane) {
            let expected = self.expected_access_list()?;
            let expected_session = self.expected_session_access_list()?;
            if self.access_list != expected && self.access_list != expected_session {
                return Err(TransactionValidationErrorV1::InvalidAccessList);
            }
        }
        self.validate_fee_payment_binding()?;
        self.validate_sponsor_intent_consistency()?;
        if canonical_bytes(self)?.len() > MAX_TRANSACTION_V5_CANONICAL_BYTES {
            return Err(TransactionValidationErrorV1::TransactionTooLarge);
        }
        Ok(())
    }

    /// Verifies structure, configured chain, sponsor grant, and sender signature.
    pub fn verify_for_chain(
        &self,
        expected_chain: &ChainId,
    ) -> Result<(), TransactionValidationErrorV1> {
        if &self.chain_id != expected_chain {
            return Err(TransactionValidationErrorV1::WrongChain);
        }
        self.validate_structure()?;
        let signature = self
            .sender_signature
            .as_ref()
            .ok_or(TransactionValidationErrorV1::MissingSenderSignature)?;
        verify_signature(&self.sender_public_key, &self.signing_bytes()?, signature)
            .map_err(|_| TransactionValidationErrorV1::InvalidSenderSignature)?;
        self.verify_nested_sponsor_authorizations()
    }

    /// Signs using an address-derived sender key.
    pub fn sign(&mut self, keypair: &Keypair) -> Result<(), TransactionValidationErrorV1> {
        if keypair.address() != self.sender {
            return Err(TransactionValidationErrorV1::InvalidSenderSignature);
        }
        self.sign_with_policy_key(keypair)
    }

    /// Signs using a state-selected policy/session key without changing the sender.
    pub fn sign_with_policy_key(
        &mut self,
        keypair: &Keypair,
    ) -> Result<(), TransactionValidationErrorV1> {
        self.sender_public_key = keypair.public_key();
        self.validate_structure()?;
        self.verify_nested_sponsor_authorizations()?;
        self.sender_signature = Some(keypair.sign(&self.signing_bytes()?));
        self.validate_structure()
    }

    /// Returns checked static units, including conservative sponsor bookkeeping.
    pub fn required_units(&self) -> Result<u64, TransactionValidationErrorV1> {
        let units = self.kind.required_units()?;
        if matches!(&self.fee_payment, FeePaymentV1::Sponsored(_)) {
            units
                .checked_add(SPONSOR_GRANT_USE_V1_REQUIRED_UNITS)
                .ok_or(TransactionValidationErrorV1::ActionUnitsOverflow)
        } else {
            Ok(units)
        }
    }

    /// Recomputes the exact logical state declaration required for inclusion.
    ///
    /// Sender authority, nonce, and every action are always retained. Sponsored
    /// payment removes the sender fee accumulator and adds the sponsor policy,
    /// payer balance/lane, grant replay/budget state, and payer fee accumulator.
    /// The result is sorted so construction is independent of action order while
    /// the signed action program remains ordered separately.
    pub fn expected_access_list(&self) -> Result<AccessList, TransactionValidationErrorV1> {
        let baseline = self
            .kind
            .default_access_list_for_lane(self.sender, self.authorization.lane)?;
        let FeePaymentV1::Sponsored(sponsor_use) = &self.fee_payment else {
            return Ok(baseline);
        };

        let mut read_only = baseline.read_only.into_iter().collect::<BTreeSet<_>>();
        let mut read_write = baseline.read_write.into_iter().collect::<BTreeSet<_>>();
        read_write.remove(&StateKey::fee_accumulator_for_lane(
            self.sender,
            self.authorization.lane,
        ));

        let grant = &sponsor_use.grant;
        let sponsor_policy = StateKey::authorization_policy(grant.sponsor);
        if !read_write.contains(&sponsor_policy) {
            read_only.insert(sponsor_policy);
        }
        let payer_state = if grant.payer_lane.is_default() {
            StateKey::account(grant.sponsor)
        } else {
            StateKey::authorization_lane(grant.sponsor, grant.payer_lane)
        };
        read_only.remove(&payer_state);
        read_write.insert(payer_state);
        read_write.insert(StateKey::sponsor_grant(
            grant.sponsor,
            grant.grant_id.digest(),
        ));
        read_write.insert(StateKey::fee_accumulator_for_lane(
            grant.sponsor,
            grant.payer_lane,
        ));

        Ok(AccessList::new(
            read_only.into_iter().collect(),
            read_write.into_iter().collect(),
        ))
    }

    /// Recomputes exact access for the session key named by `sender_public_key`.
    ///
    /// Session execution has the same action, nonce, payer, and sponsor access
    /// as active-key execution, plus one writable cumulative-budget record. The
    /// stateful preparation layer later rejects this shape unless the signing
    /// key is actually the installed current-revision session key.
    pub fn expected_session_access_list(&self) -> Result<AccessList, TransactionValidationErrorV1> {
        let baseline = self.expected_access_list()?;
        let mut read_only = baseline.read_only.into_iter().collect::<BTreeSet<_>>();
        let mut read_write = baseline.read_write.into_iter().collect::<BTreeSet<_>>();
        let session_key =
            StateKey::session_key(self.sender, SessionKeyId::derive(&self.sender_public_key));
        read_only.remove(&session_key);
        read_write.insert(session_key);
        Ok(AccessList::new(
            read_only.into_iter().collect(),
            read_write.into_iter().collect(),
        ))
    }

    /// Returns the domain-separated stable identity of the complete signed wire.
    pub fn transaction_id(&self) -> Result<TransactionId, TransactionValidationErrorV1> {
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            transaction: &'a TransactionV5,
        }
        canonical_hash(&Payload {
            domain: TRANSACTION_ID_V1_DOMAIN,
            transaction: self,
        })
        .map(TransactionId::new)
    }

    /// Returns canonical sender-signing bytes shared with browser wallets.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, TransactionValidationErrorV1> {
        #[derive(Serialize)]
        struct Payload<'a> {
            domain: &'static str,
            protocol_version: ProtocolVersion,
            chain_id: &'a ChainId,
            sender: Address,
            sender_public_key: PublicKeyBytes,
            authorization: TransactionAuthorizationV1,
            validity: ValidityWindowV1,
            kind: &'a TransactionKindV1,
            access_list: &'a AccessList,
            #[serde(with = "fee_bid_decimal")]
            fee_bid: FeeBid,
            fee_payment: &'a FeePaymentV1,
        }
        canonical_bytes(&Payload {
            domain: TRANSACTION_V5_SIGNING_DOMAIN,
            protocol_version: self.protocol_version,
            chain_id: &self.chain_id,
            sender: self.sender,
            sender_public_key: self.sender_public_key,
            authorization: self.authorization,
            validity: self.validity,
            kind: &self.kind,
            access_list: &self.access_list,
            fee_bid: self.fee_bid,
            fee_payment: &self.fee_payment,
        })
    }

    fn validate_fee_payment_binding(&self) -> Result<(), TransactionValidationErrorV1> {
        let FeePaymentV1::Sponsored(sponsor_use) = &self.fee_payment else {
            return Ok(());
        };
        sponsor_use.grant.validate_structure()?;
        if sponsor_use.grant.sponsor_signature.is_none() {
            return Err(TransactionValidationErrorV1::MissingSponsorSignature);
        }
        if sponsor_use.grant.chain_id != self.chain_id
            || sponsor_use.grant.protocol_version != self.protocol_version
            || sponsor_use.grant.sender != self.sender
            || !sponsor_use.grant.validity.covers(self.validity)
            || sponsor_use.action_digest != self.kind.digest()?
            || sponsor_use.grant.action_scope.exact_action_digest != sponsor_use.action_digest
            || sponsor_use.fee_bid_digest != fee_bid_digest(self.fee_bid)?
            || sponsor_use
                .grant
                .application_namespace
                .is_some_and(|namespace| !kind_matches_application_namespace(&self.kind, namespace))
        {
            return Err(TransactionValidationErrorV1::SponsorBindingMismatch);
        }
        if sponsor_use.grant_digest != sponsor_use.grant.digest()? {
            return Err(TransactionValidationErrorV1::SponsorBindingMismatch);
        }
        let reserve = fee_reserve(self.fee_bid)?;
        if reserve > sponsor_use.grant.max_fee_per_transaction {
            return Err(TransactionValidationErrorV1::SponsorBindingMismatch);
        }
        Ok(())
    }

    /// Rejects one replay key naming different immutable grants in one envelope.
    fn validate_sponsor_intent_consistency(&self) -> Result<(), TransactionValidationErrorV1> {
        let mut identities = BTreeMap::<(Address, SponsorGrantId), (Hash256, BlockHeight)>::new();
        let mut observe = |key: (Address, SponsorGrantId), digest: Hash256, expiry: BlockHeight| {
            if let Some(previous) = identities.insert(key, (digest, expiry)) {
                if previous != (digest, expiry) {
                    return Err(TransactionValidationErrorV1::SponsorBindingMismatch);
                }
            }
            Ok(())
        };

        if let FeePaymentV1::Sponsored(sponsor_use) = &self.fee_payment {
            observe(
                (sponsor_use.grant.sponsor, sponsor_use.grant.grant_id),
                sponsor_use.grant_digest,
                sponsor_use.grant.validity.valid_until_height,
            )?;
        }
        if let TransactionKindV1::Actions(program) = &self.kind {
            for action in &program.actions {
                let ActionV1::RevokeSignedSponsorGrant { grant } = action else {
                    continue;
                };
                observe(
                    (grant.sponsor, grant.grant_id),
                    grant.digest()?,
                    grant.validity.valid_until_height,
                )?;
            }
        }
        Ok(())
    }

    /// Verifies each unique nested sponsor signature after sender authentication.
    fn verify_nested_sponsor_authorizations(&self) -> Result<(), TransactionValidationErrorV1> {
        let mut verified = BTreeSet::new();
        let mut verify = |grant: &SponsorGrantV1| {
            let digest = grant.digest()?;
            if verified.insert(digest) {
                grant.verify()?;
            }
            Ok(())
        };
        if let FeePaymentV1::Sponsored(sponsor_use) = &self.fee_payment {
            verify(&sponsor_use.grant)?;
        }
        if let TransactionKindV1::Actions(program) = &self.kind {
            for action in &program.actions {
                if let ActionV1::RevokeSignedSponsorGrant { grant } = action {
                    verify(grant)?;
                }
            }
        }
        Ok(())
    }
}

/// Requires at least one object action and rejects every mismatched object namespace.
fn kind_matches_application_namespace(kind: &TransactionKindV1, expected: Hash256) -> bool {
    let TransactionKindV1::Actions(program) = kind else {
        return false;
    };
    let mut observed = false;
    for action in &program.actions {
        let ActionV1::Native { operation } = action else {
            continue;
        };
        let namespace = match operation.as_ref() {
            Operation::CreateObject { namespace, .. }
            | Operation::MutateObject { namespace, .. }
            | Operation::TransferObject { namespace, .. } => namespace,
            _ => continue,
        };
        if *namespace != expected {
            return false;
        }
        observed = true;
    }
    observed
}

fn validate_native_action_lane(
    program: &ActionProgramV1,
    authorization_lane: AuthorizationLaneId,
) -> Result<(), TransactionValidationErrorV1> {
    if !authorization_lane.is_default()
        && program.actions.iter().any(|action| {
            matches!(
                action,
                ActionV1::Native { operation }
                    if matches!(
                        operation.as_ref(),
                        Operation::InstallAuthorizationPolicy { .. }
                            | Operation::OpenAuthorizationLane { .. }
                            | Operation::FundAuthorizationLane { .. }
                    )
            )
        })
    {
        return Err(TransactionValidationErrorV1::InvalidNativeAction);
    }
    Ok(())
}

fn validate_fee_bid(fee_bid: FeeBid) -> Result<(), TransactionValidationErrorV1> {
    if fee_bid.gas_limit == 0
        || fee_bid.max_fee_per_unit == 0
        || fee_bid.priority_fee_per_unit > fee_bid.max_fee_per_unit
    {
        return Err(TransactionValidationErrorV1::InvalidFeeBid);
    }
    fee_reserve(fee_bid)?;
    Ok(())
}

fn fee_reserve(fee_bid: FeeBid) -> Result<Amount, TransactionValidationErrorV1> {
    let units = u128::from(fee_bid.gas_limit)
        .checked_mul(u128::from(fee_bid.max_fee_per_unit))
        .ok_or(TransactionValidationErrorV1::FeeReserveOverflow)?;
    Ok(Amount::from_units(units))
}

fn fee_bid_digest(fee_bid: FeeBid) -> Result<Hash256, TransactionValidationErrorV1> {
    #[derive(Serialize)]
    struct Payload {
        domain: &'static str,
        #[serde(with = "fee_bid_decimal")]
        fee_bid: FeeBid,
    }
    canonical_hash(&Payload {
        domain: FEE_BID_V1_DOMAIN,
        fee_bid,
    })
}

fn validate_access_list(access: &AccessList) -> Result<(), TransactionValidationErrorV1> {
    let total = access
        .read_only
        .len()
        .checked_add(access.read_write.len())
        .ok_or(TransactionValidationErrorV1::InvalidAccessList)?;
    if total > MAX_TRANSACTION_STATE_KEYS {
        return Err(TransactionValidationErrorV1::InvalidAccessList);
    }
    let mut keys = BTreeSet::<&StateKey>::new();
    if access
        .read_only
        .iter()
        .chain(&access.read_write)
        .any(|key| !keys.insert(key))
    {
        return Err(TransactionValidationErrorV1::InvalidAccessList);
    }
    Ok(())
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, TransactionValidationErrorV1> {
    crate::canonical::canonical_json_bytes(value)
        .map_err(|_| TransactionValidationErrorV1::CanonicalEncoding)
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<Hash256, TransactionValidationErrorV1> {
    canonical_bytes(value).map(Hash256::digest)
}

fn parse_decimal_u64(value: &str) -> Result<u64, &'static str> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("expected a canonical unsigned decimal u64 string");
    }
    value
        .parse::<u64>()
        .map_err(|_| "decimal string exceeds the u64 range")
}

fn deserialize_decimal_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_decimal_u64(&value).map_err(D::Error::custom)
}

mod u64_decimal {
    use super::*;

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_decimal_u64(deserializer)
    }
}

mod block_height_decimal {
    use super::*;

    pub fn serialize<S>(value: &BlockHeight, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.get().to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BlockHeight, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_decimal_u64(deserializer).map(BlockHeight::new)
    }
}

mod nonce_decimal {
    use super::*;

    pub fn serialize<S>(value: &Nonce, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.get().to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Nonce, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_decimal_u64(deserializer).map(Nonce::new)
    }
}

mod authorization_revision_decimal {
    use super::*;

    pub fn serialize<S>(
        value: &AuthorizationPolicyRevision,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.get().to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<AuthorizationPolicyRevision, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_decimal_u64(deserializer).map(AuthorizationPolicyRevision::new)
    }
}

mod fee_bid_decimal {
    use super::*;

    #[derive(Serialize)]
    struct FeeBidRef {
        gas_limit: String,
        max_fee_per_unit: String,
        priority_fee_per_unit: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FeeBidWire {
        gas_limit: String,
        max_fee_per_unit: String,
        priority_fee_per_unit: String,
    }

    pub fn serialize<S>(value: &FeeBid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        FeeBidRef {
            gas_limit: value.gas_limit.to_string(),
            max_fee_per_unit: value.max_fee_per_unit.to_string(),
            priority_fee_per_unit: value.priority_fee_per_unit.to_string(),
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<FeeBid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FeeBidWire::deserialize(deserializer)?;
        Ok(FeeBid {
            gas_limit: parse_decimal_u64(&wire.gas_limit).map_err(D::Error::custom)?,
            max_fee_per_unit: parse_decimal_u64(&wire.max_fee_per_unit)
                .map_err(D::Error::custom)?,
            priority_fee_per_unit: parse_decimal_u64(&wire.priority_fee_per_unit)
                .map_err(D::Error::custom)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectId, Operation};

    fn transfer_kind(recipient: Address, amount: u128) -> TransactionKindV1 {
        TransactionKindV1::Actions(ActionProgramV1::new(vec![ActionV1::native(
            Operation::Transfer {
                to: recipient,
                amount: Amount::from_units(amount),
            },
        )]))
    }

    fn unsigned_sender_paid(
        sender: &Keypair,
        recipient: Address,
        validity: ValidityWindowV1,
    ) -> TransactionV5 {
        let authorization = TransactionAuthorizationV1 {
            lane: AuthorizationLaneId::DEFAULT,
            policy_revision: AuthorizationPolicyRevision::new(0),
            nonce: Nonce::new(7),
        };
        let kind = transfer_kind(recipient, 123_456);
        let access_list = kind
            .default_access_list_for_lane(sender.address(), authorization.lane)
            .expect("fixture access list");
        TransactionV5::new_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            authorization,
            validity,
            kind,
            access_list,
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        )
    }

    #[test]
    fn sender_paid_action_and_cancel_sign_verify_and_have_distinct_ids() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let validity = ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20));
        let mut action = unsigned_sender_paid(&sender, recipient.address(), validity);
        action.sign(&sender).expect("action signs");
        action
            .verify_for_chain(&ChainId::devnet())
            .expect("action verifies");

        let mut cancel = TransactionV5::for_cancel_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            action.authorization,
            validity,
            action.fee_bid,
            FeePaymentV1::SenderLane,
        );
        cancel.sign(&sender).expect("cancel signs");
        cancel
            .verify_for_chain(&ChainId::devnet())
            .expect("cancel verifies");
        assert_eq!(
            cancel.access_list,
            AccessList::new(
                vec![
                    StateKey::protocol(crate::ProtocolStateKey::BaseFee),
                    StateKey::authorization_policy(sender.address()),
                ],
                vec![
                    StateKey::account(sender.address()),
                    StateKey::fee_accumulator(sender.address()),
                ],
            )
        );
        assert_ne!(
            action.transaction_id().expect("action id"),
            cancel.transaction_id().expect("cancel id")
        );
        assert_eq!(cancel.required_units(), Ok(CANCEL_V1_REQUIRED_UNITS));

        let mut missing_action_key = action;
        missing_action_key.access_list.read_write.pop();
        assert_eq!(
            missing_action_key.validate_structure(),
            Err(TransactionValidationErrorV1::InvalidAccessList)
        );

        let mut extra_cancel_key = cancel;
        extra_cancel_key
            .access_list
            .read_only
            .push(StateKey::protocol(crate::ProtocolStateKey::BridgeNonce));
        assert_eq!(
            extra_cancel_key.validate_structure(),
            Err(TransactionValidationErrorV1::InvalidAccessList)
        );
    }

    #[test]
    fn intrinsically_invalid_native_actions_fail_before_signing() {
        let sender = Keypair::from_seed([1; 32]);
        let target_lane = AuthorizationLaneId::new(Hash256([0x81; 32]));
        let build = |lane, action| {
            TransactionV5::for_actions_unsigned(
                ChainId::devnet(),
                sender.address(),
                sender.public_key(),
                TransactionAuthorizationV1 {
                    lane,
                    policy_revision: AuthorizationPolicyRevision::new(0),
                    nonce: Nonce::new(0),
                },
                ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
                vec![action],
                FeeBid {
                    gas_limit: 100_000,
                    max_fee_per_unit: 5,
                    priority_fee_per_unit: 1,
                },
                FeePaymentV1::SenderLane,
            )
        };

        assert_eq!(
            build(
                AuthorizationLaneId::DEFAULT,
                ActionV1::native(Operation::OpenAuthorizationLane {
                    lane: AuthorizationLaneId::DEFAULT,
                    fee_deposit: Amount::from_units(1),
                }),
            ),
            Err(TransactionValidationErrorV1::InvalidNativeAction)
        );
        assert_eq!(
            build(
                AuthorizationLaneId::DEFAULT,
                ActionV1::native(Operation::FundAuthorizationLane {
                    lane: target_lane,
                    fee_deposit: Amount::ZERO,
                }),
            ),
            Err(TransactionValidationErrorV1::InvalidNativeAction)
        );
        assert_eq!(
            build(
                AuthorizationLaneId::DEFAULT,
                ActionV1::native(Operation::FundAuthorizationLane {
                    lane: AuthorizationLaneId::DEFAULT,
                    fee_deposit: Amount::from_units(1),
                }),
            ),
            Err(TransactionValidationErrorV1::InvalidNativeAction)
        );
        assert_eq!(
            build(
                AuthorizationLaneId::DEFAULT,
                ActionV1::revoke_sponsor_grant(SponsorGrantId::new(Hash256::ZERO)),
            ),
            Err(TransactionValidationErrorV1::InvalidNativeAction)
        );
        assert_eq!(
            build(
                AuthorizationLaneId::DEFAULT,
                ActionV1::native(Operation::Delegate {
                    validator: sender.address(),
                    amount: Amount::from_units(1),
                }),
            ),
            Err(TransactionValidationErrorV1::UnsupportedNativeAction)
        );
        assert_eq!(
            build(
                target_lane,
                ActionV1::native(Operation::OpenAuthorizationLane {
                    lane: AuthorizationLaneId::new(Hash256([0x82; 32])),
                    fee_deposit: Amount::from_units(1),
                }),
            ),
            Err(TransactionValidationErrorV1::InvalidNativeAction)
        );
        assert_eq!(
            build(
                AuthorizationLaneId::DEFAULT,
                ActionV1::native(Operation::CreateObject {
                    object_id: ObjectId::new(Hash256([0x83; 32])),
                    namespace: Hash256([0x84; 32]),
                    data: vec![0; MAX_OBJECT_DATA_BYTES + 1],
                }),
            ),
            Err(TransactionValidationErrorV1::InvalidNativeAction)
        );
    }

    #[test]
    fn session_builder_adds_exact_budget_access_in_consensus_order() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let session_public_key = PublicKeyBytes([0x11; 32]);
        let transaction = TransactionV5::for_session_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            session_public_key,
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(1),
                nonce: Nonce::new(7),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            vec![ActionV1::native(Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(123_456),
            })],
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("session transaction builds");

        assert_eq!(
            transaction.access_list.read_write,
            vec![
                StateKey::account(sender.address()),
                StateKey::account(recipient.address()),
                StateKey::fee_accumulator(sender.address()),
                StateKey::session_key(sender.address(), SessionKeyId::derive(&session_public_key),),
            ]
        );
        assert_eq!(
            SessionKeyId::derive(&session_public_key).hash().to_hex(),
            "0ccf7ce5d50b1e08cb4b7d2f7c5b7af9eb094dce0c9d1668a2e270de7fb40c74"
        );
    }

    #[test]
    fn validity_range_is_inclusive_and_bounded() {
        let one = ValidityWindowV1::new(BlockHeight::new(9), BlockHeight::new(9));
        assert_eq!(one.validate(), Ok(()));
        assert!(one.contains(BlockHeight::new(9)));

        let maximum = ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(4_105));
        assert_eq!(maximum.validate(), Ok(()));
        let too_long = ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(4_106));
        assert_eq!(
            too_long.validate(),
            Err(TransactionValidationErrorV1::ValidityRangeTooLong)
        );
        let reversed = ValidityWindowV1::new(BlockHeight::new(11), BlockHeight::new(10));
        assert_eq!(
            reversed.validate(),
            Err(TransactionValidationErrorV1::InvalidValidityRange)
        );
    }

    #[test]
    fn action_count_rejects_empty_and_more_than_thirty_two() {
        assert_eq!(
            ActionProgramV1::new(Vec::new()).validate(),
            Err(TransactionValidationErrorV1::EmptyActionProgram)
        );
        let actions = (0..=MAX_ACTIONS_V1)
            .map(|_| ActionV1::native(Operation::ClaimValidatorRewards))
            .collect();
        assert_eq!(
            ActionProgramV1::new(actions).validate(),
            Err(TransactionValidationErrorV1::TooManyActions)
        );
    }

    #[test]
    fn sponsor_revocation_action_has_frozen_digest_and_exact_access() {
        let sender = Keypair::from_seed([3; 32]);
        let grant_id = SponsorGrantId::new(Hash256([0x44; 32]));
        let kind =
            TransactionKindV1::Actions(ActionProgramV1::new(vec![ActionV1::revoke_sponsor_grant(
                grant_id,
            )]));

        assert_eq!(
            kind.required_units(),
            Ok(REVOKE_SPONSOR_GRANT_V1_REQUIRED_UNITS)
        );
        let access = kind
            .default_access_list_for_lane(sender.address(), AuthorizationLaneId::DEFAULT)
            .expect("revocation access");
        assert!(access.read_write.contains(&StateKey::sponsor_grant(
            sender.address(),
            grant_id.digest()
        )));
        assert_eq!(
            kind.digest().expect("revocation digest").to_string(),
            "9ee7f737d552bfc49ba6351b0c8954c70a83b989175a0892b106e95c36846de8"
        );
    }

    #[test]
    fn signed_sponsor_revocation_binds_grant_chain_owner_signature_and_access() {
        let sponsor = Keypair::from_seed([3; 32]);
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let scoped_kind = transfer_kind(recipient.address(), 123_456);
        let mut grant = SponsorGrantV1 {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            grant_id: SponsorGrantId::new(Hash256([0x44; 32])),
            sponsor: sponsor.address(),
            sponsor_public_key: sponsor.public_key(),
            payer_lane: AuthorizationLaneId::new(Hash256([0x55; 32])),
            sender: sender.address(),
            site_namespace: Some(Hash256([0x66; 32])),
            application_namespace: None,
            action_scope: ActionScopeV1::exact(scoped_kind.digest().expect("scoped action digest")),
            validity: ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            max_fee_per_transaction: Amount::from_units(10_000),
            max_cumulative_fee: Amount::from_units(100_000),
            max_uses: 10,
            sponsor_signature: None,
        };
        grant.sign(&sponsor).expect("grant signs");
        let signed_revoke_kind = TransactionKindV1::Actions(ActionProgramV1::new(vec![
            ActionV1::revoke_signed_sponsor_grant(grant.clone()),
        ]));
        const SIGNED_REVOKE_KIND_JSON: &str = r#"{"Actions":{"actions":[{"RevokeSignedSponsorGrant":{"grant":{"action_scope":{"exact_action_digest":"bb25a54623accd384abc84091335e289a9d3cfca5728b7f775f0329c6fa3e0a0"},"application_namespace":null,"chain_id":"webc-devnet-1","grant_id":"4444444444444444444444444444444444444444444444444444444444444444","max_cumulative_fee":"100000","max_fee_per_transaction":"10000","max_uses":"10","payer_lane":"5555555555555555555555555555555555555555555555555555555555555555","protocol_version":2,"sender":"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3","site_namespace":"6666666666666666666666666666666666666666666666666666666666666666","sponsor":"webc121uVaRnHeoTdcumRjrvYZuEaBBiHn4wito3PKSpNzjAf","sponsor_public_key":"ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1","sponsor_signature":"8114099820bc2d1cdfd7be9a9180fe848c98dad6b9a1b54cbfa3a5dbb61f73b82bbe9ba37f2f0370ed73d3d460bed9a3faebee629c7743fa4d53bd554650820d","validity":{"valid_from_height":"10","valid_until_height":"20"}}}}]}}"#;
        assert_eq!(
            String::from_utf8(
                crate::canonical::canonical_json_bytes(&signed_revoke_kind)
                    .expect("kind canonicalizes")
            )
            .expect("canonical JSON is UTF-8"),
            SIGNED_REVOKE_KIND_JSON
        );
        assert_eq!(
            signed_revoke_kind
                .digest()
                .expect("kind digest")
                .to_string(),
            "99a8fb14c579034d0ec37e1fb715ae624a91cbee227397db6e1d069f02e8560a"
        );
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sponsor.address(),
            sponsor.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            vec![ActionV1::revoke_signed_sponsor_grant(grant.clone())],
            FeeBid {
                gas_limit: REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("signed revocation builds");
        transaction.sign(&sponsor).expect("revocation signs");
        transaction
            .verify_for_chain(&ChainId::devnet())
            .expect("revocation verifies");
        assert_eq!(
            transaction.required_units(),
            Ok(REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS)
        );
        assert!(transaction
            .access_list
            .read_write
            .contains(&StateKey::sponsor_grant(
                sponsor.address(),
                grant.grant_id.digest()
            )));

        let mut conflicting_grant = grant.clone();
        conflicting_grant.validity =
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(21));
        conflicting_grant.sponsor_signature = None;
        conflicting_grant
            .sign(&sponsor)
            .expect("conflicting grant signs independently");
        let conflict = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sponsor.address(),
            sponsor.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            vec![
                ActionV1::revoke_signed_sponsor_grant(grant.clone()),
                ActionV1::revoke_signed_sponsor_grant(conflicting_grant),
            ],
            FeeBid {
                gas_limit: REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS * 2,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("unsigned candidates remain representable for validation");
        assert_eq!(
            conflict.validate_structure(),
            Err(TransactionValidationErrorV1::SponsorBindingMismatch)
        );

        let mut wrong_owner = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            vec![ActionV1::revoke_signed_sponsor_grant(grant)],
            FeeBid {
                gas_limit: REVOKE_SIGNED_SPONSOR_GRANT_V1_REQUIRED_UNITS,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("structurally signed grant builds");
        assert_eq!(
            wrong_owner.sign(&sender),
            Err(TransactionValidationErrorV1::SponsorBindingMismatch)
        );
    }

    #[test]
    fn introduced_u64_fields_are_exact_decimal_strings() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let tx = unsigned_sender_paid(
            &sender,
            recipient.address(),
            ValidityWindowV1::new(
                BlockHeight::new(9_007_199_254_740_992),
                BlockHeight::new(9_007_199_254_740_993),
            ),
        );
        let value = serde_json::to_value(&tx).expect("transaction serializes");
        assert_eq!(value["authorization"]["nonce"], "7");
        assert_eq!(value["validity"]["valid_from_height"], "9007199254740992");
        assert_eq!(value["fee_bid"]["gas_limit"], "1000");

        let mut numeric = value;
        numeric["authorization"]["nonce"] = serde_json::json!(7);
        assert!(serde_json::from_value::<TransactionV5>(numeric).is_err());
    }

    #[test]
    fn bounded_decoder_rejects_oversize_malformed_and_unknown_fields() {
        let oversize = vec![b' '; MAX_TRANSACTION_V5_CANONICAL_BYTES + 1];
        assert_eq!(
            TransactionV5::decode_json(&oversize),
            Err(TransactionValidationErrorV1::TransactionTooLarge)
        );
        assert_eq!(
            TransactionV5::decode_json(b"{"),
            Err(TransactionValidationErrorV1::MalformedTransaction)
        );

        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let tx = unsigned_sender_paid(
            &sender,
            recipient.address(),
            ValidityWindowV1::new(BlockHeight::new(1), BlockHeight::new(2)),
        );
        let mut value = serde_json::to_value(tx).expect("transaction value");
        value["unexpected"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&value).expect("hostile JSON encodes");
        assert_eq!(
            TransactionV5::decode_json(&bytes),
            Err(TransactionValidationErrorV1::MalformedTransaction)
        );
    }

    #[test]
    fn scoped_sponsor_binds_chain_sender_actions_fee_and_signature() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsor = Keypair::from_seed([3; 32]);
        let validity = ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20));
        let mut tx = unsigned_sender_paid(&sender, recipient.address(), validity);
        let action_digest = tx.kind.digest().expect("action digest");
        let mut grant = SponsorGrantV1 {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            grant_id: SponsorGrantId::new(Hash256([0x44; 32])),
            sponsor: sponsor.address(),
            sponsor_public_key: sponsor.public_key(),
            payer_lane: AuthorizationLaneId::new(Hash256([0x55; 32])),
            sender: sender.address(),
            site_namespace: Some(Hash256([0x66; 32])),
            application_namespace: None,
            action_scope: ActionScopeV1::exact(action_digest),
            validity,
            max_fee_per_transaction: Amount::from_units(10_000),
            max_cumulative_fee: Amount::from_units(100_000),
            max_uses: 10,
            sponsor_signature: None,
        };
        grant.sign(&sponsor).expect("grant signs");
        let sponsor_use =
            SponsorUseV1::for_transaction(grant, SponsorUseNonce::new(0), &tx.kind, tx.fee_bid)
                .expect("sponsor use builds");
        tx.fee_payment = FeePaymentV1::Sponsored(Box::new(sponsor_use));
        tx.sign(&sender).expect("sponsored transaction signs");
        tx.verify_for_chain(&ChainId::devnet())
            .expect("sponsored transaction verifies");

        let mut application_misbound = tx.clone();
        let FeePaymentV1::Sponsored(existing_use) = &application_misbound.fee_payment else {
            panic!("fixture is sponsored")
        };
        let mut application_grant = existing_use.grant.clone();
        application_grant.application_namespace = Some(Hash256([0x77; 32]));
        application_grant.sponsor_signature = None;
        application_grant
            .sign(&sponsor)
            .expect("application-scoped grant signs");
        application_misbound.fee_payment = FeePaymentV1::Sponsored(Box::new(
            SponsorUseV1::for_transaction(
                application_grant,
                SponsorUseNonce::new(0),
                &application_misbound.kind,
                application_misbound.fee_bid,
            )
            .expect("application-scoped use builds"),
        ));
        application_misbound.sender_signature = None;
        assert_eq!(
            application_misbound.sign(&sender),
            Err(TransactionValidationErrorV1::SponsorBindingMismatch)
        );

        let mut altered_fee = tx.clone();
        altered_fee.fee_bid.max_fee_per_unit = 6;
        assert_eq!(
            altered_fee.validate_structure(),
            Err(TransactionValidationErrorV1::SponsorBindingMismatch)
        );

        let mut altered_grant = tx;
        let FeePaymentV1::Sponsored(use_record) = &mut altered_grant.fee_payment else {
            panic!("fixture is sponsored")
        };
        use_record.grant.max_uses = 11;
        assert_eq!(
            altered_grant.validate_structure(),
            Err(TransactionValidationErrorV1::SponsorBindingMismatch)
        );
        let FeePaymentV1::Sponsored(use_record) = &mut altered_grant.fee_payment else {
            panic!("fixture is sponsored")
        };
        use_record.grant_digest = use_record.grant.digest().expect("altered grant digest");
        assert_eq!(
            altered_grant.verify_for_chain(&ChainId::devnet()),
            Err(TransactionValidationErrorV1::InvalidSenderSignature)
        );
        altered_grant.sender_signature = None;
        assert_eq!(
            altered_grant.sign(&sender),
            Err(TransactionValidationErrorV1::InvalidSponsorSignature)
        );
    }

    // ----------------------------------------------------------------------
    // Frozen protocol-version-2 cross-language wire vectors.
    //
    // The TypeScript test `sdk/webc-js/src/transaction-v5.test.ts` reproduces
    // every value below byte-for-byte and verifies these exact Rust signatures.
    // Ed25519 (RFC 8032) signatures are deterministic, so re-signing the same
    // canonical payload must reproduce the frozen signature; the transaction ID
    // is a domain-separated hash over the complete signed JSON, so freezing it
    // also freezes that JSON. Changing any value here is a wire-compatibility
    // break: it requires a coordinated protocol-version bump and a matching
    // TypeScript update. Never edit a frozen vector to make a test pass.
    // ----------------------------------------------------------------------

    /// Deterministic seed for the fixture sender (`Keypair::from_seed([1; 32])`).
    const SENDER_PUBLIC_KEY_HEX: &str =
        "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    /// Deterministic seed for the fixture sponsor (`Keypair::from_seed([3; 32])`).
    const SPONSOR_PUBLIC_KEY_HEX: &str =
        "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1";
    /// Sender-paid transfer: exact ordered-action/cancellation program digest.
    const SENDER_PAID_ACTION_DIGEST_HEX: &str =
        "bb25a54623accd384abc84091335e289a9d3cfca5728b7f775f0329c6fa3e0a0";
    /// Sender-paid transfer: sender Ed25519 signature over the signing bytes.
    const SENDER_PAID_SIGNATURE_HEX: &str =
        "fae71eef9827891d2bc4362ef49ccb9559a7e91fed98f041d0f56d690a120e05f6d3af6396bcd92cd66d63c0af144fdbf654fb2b4cd59162637dbe76592d050a";
    /// Sender-paid transfer: complete-signed-transaction identity.
    const SENDER_PAID_TRANSACTION_ID_HEX: &str =
        "c268d7d32a67ddbe985e18f881bcbd93bcfafcae5fbb6e7145276941b143f50f";
    /// Sponsor grant: exact fee-bid digest bound by the grant use.
    const SPONSORED_FEE_BID_DIGEST_HEX: &str =
        "3b304bcd83127294f126ab796e0614bed9472e888420b0bcbcbabc4ca6004c0c";
    /// Sponsor grant: sponsor Ed25519 signature over the immutable grant.
    const SPONSOR_GRANT_SIGNATURE_HEX: &str =
        "8114099820bc2d1cdfd7be9a9180fe848c98dad6b9a1b54cbfa3a5dbb61f73b82bbe9ba37f2f0370ed73d3d460bed9a3faebee629c7743fa4d53bd554650820d";
    /// Sponsor grant: domain-separated digest of the complete signed grant.
    const SPONSOR_GRANT_DIGEST_HEX: &str =
        "4bae024a7f9c82f7218cbdda309a7734d4e8c02b2c2a530376ac7531a499eb57";
    /// Sponsor use: domain-separated identity of the replay-bounded use.
    const SPONSOR_USE_DIGEST_HEX: &str =
        "4d929bbcb2e2e6bb8b827b3a584de213cca91aca95ce9e6e838c16b4da29fc83";
    /// Sponsored transfer: sender Ed25519 signature over the sponsored payload.
    const SPONSORED_SIGNATURE_HEX: &str =
        "eb06340360bf3147dff476900edbe65e1f9c90fb4ca2196056ef5a22ce46bcc665d432dbef9585ef42ef6aba5031574a42efae1ffed743f8ca3895ce258a1904";
    /// Sponsored transfer: complete-signed-transaction identity.
    const SPONSORED_TRANSACTION_ID_HEX: &str =
        "b44978261941c3bb0f6f42722d9671330ba9c7d307ee5e3e697906fcc16b89bd";

    /// Canonical sender-signing JSON (domain-wrapped) for the sender-paid vector.
    const SENDER_PAID_SIGNING_JSON: &str = "{\"access_list\":{\"read_only\":[{\"kind\":{\"AuthorizationPolicy\":{\"owner\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\"}},\"version\":1},{\"kind\":{\"Protocol\":{\"field\":\"BaseFee\"}},\"version\":1}],\"read_write\":[{\"kind\":{\"Account\":{\"address\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\"}},\"version\":1},{\"kind\":{\"Account\":{\"address\":\"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem\"}},\"version\":1},{\"kind\":{\"FeeAccumulator\":{\"lane\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"payer\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\"}},\"version\":1}]},\"authorization\":{\"lane\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"nonce\":\"7\",\"policy_revision\":\"0\"},\"chain_id\":\"webc-devnet-1\",\"domain\":\"WEBC_SIGNED_TRANSACTION_V5\",\"fee_bid\":{\"gas_limit\":\"1000\",\"max_fee_per_unit\":\"5\",\"priority_fee_per_unit\":\"1\"},\"fee_payment\":\"SenderLane\",\"kind\":{\"Actions\":{\"actions\":[{\"Native\":{\"operation\":{\"Transfer\":{\"amount\":\"123456\",\"to\":\"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem\"}}}}]}},\"protocol_version\":2,\"sender\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",\"sender_public_key\":\"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c\",\"validity\":{\"valid_from_height\":\"10\",\"valid_until_height\":\"20\"}}";

    /// Complete signed sender-paid transfer wire (no domain, signature present).
    const SENDER_PAID_FULL_JSON: &str = "{\"access_list\":{\"read_only\":[{\"kind\":{\"AuthorizationPolicy\":{\"owner\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\"}},\"version\":1},{\"kind\":{\"Protocol\":{\"field\":\"BaseFee\"}},\"version\":1}],\"read_write\":[{\"kind\":{\"Account\":{\"address\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\"}},\"version\":1},{\"kind\":{\"Account\":{\"address\":\"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem\"}},\"version\":1},{\"kind\":{\"FeeAccumulator\":{\"lane\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"payer\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\"}},\"version\":1}]},\"authorization\":{\"lane\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"nonce\":\"7\",\"policy_revision\":\"0\"},\"chain_id\":\"webc-devnet-1\",\"fee_bid\":{\"gas_limit\":\"1000\",\"max_fee_per_unit\":\"5\",\"priority_fee_per_unit\":\"1\"},\"fee_payment\":\"SenderLane\",\"kind\":{\"Actions\":{\"actions\":[{\"Native\":{\"operation\":{\"Transfer\":{\"amount\":\"123456\",\"to\":\"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem\"}}}}]}},\"protocol_version\":2,\"sender\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",\"sender_public_key\":\"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c\",\"sender_signature\":\"fae71eef9827891d2bc4362ef49ccb9559a7e91fed98f041d0f56d690a120e05f6d3af6396bcd92cd66d63c0af144fdbf654fb2b4cd59162637dbe76592d050a\",\"validity\":{\"valid_from_height\":\"10\",\"valid_until_height\":\"20\"}}";

    /// Canonical sponsor-grant signing JSON (domain-wrapped, no signature).
    const SPONSOR_GRANT_SIGNING_JSON: &str = "{\"action_scope\":{\"exact_action_digest\":\"bb25a54623accd384abc84091335e289a9d3cfca5728b7f775f0329c6fa3e0a0\"},\"application_namespace\":null,\"chain_id\":\"webc-devnet-1\",\"domain\":\"WEBC_SPONSOR_GRANT_V1\",\"grant_id\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"max_cumulative_fee\":\"100000\",\"max_fee_per_transaction\":\"10000\",\"max_uses\":\"10\",\"payer_lane\":\"5555555555555555555555555555555555555555555555555555555555555555\",\"protocol_version\":2,\"sender\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",\"site_namespace\":\"6666666666666666666666666666666666666666666666666666666666666666\",\"sponsor\":\"webc121uVaRnHeoTdcumRjrvYZuEaBBiHn4wito3PKSpNzjAf\",\"sponsor_public_key\":\"ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1\",\"validity\":{\"valid_from_height\":\"10\",\"valid_until_height\":\"20\"}}";

    /// Complete signed sponsored transfer wire (no domain, signature present).
    const SPONSORED_FULL_JSON: &str = "{\"access_list\":{\"read_only\":[{\"kind\":{\"AuthorizationPolicy\":{\"owner\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\"}},\"version\":1},{\"kind\":{\"Protocol\":{\"field\":\"BaseFee\"}},\"version\":1}],\"read_write\":[{\"kind\":{\"Account\":{\"address\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\"}},\"version\":1},{\"kind\":{\"Account\":{\"address\":\"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem\"}},\"version\":1},{\"kind\":{\"FeeAccumulator\":{\"lane\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"payer\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\"}},\"version\":1}]},\"authorization\":{\"lane\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"nonce\":\"7\",\"policy_revision\":\"0\"},\"chain_id\":\"webc-devnet-1\",\"fee_bid\":{\"gas_limit\":\"1000\",\"max_fee_per_unit\":\"5\",\"priority_fee_per_unit\":\"1\"},\"fee_payment\":{\"Sponsored\":{\"action_digest\":\"bb25a54623accd384abc84091335e289a9d3cfca5728b7f775f0329c6fa3e0a0\",\"fee_bid_digest\":\"3b304bcd83127294f126ab796e0614bed9472e888420b0bcbcbabc4ca6004c0c\",\"grant\":{\"action_scope\":{\"exact_action_digest\":\"bb25a54623accd384abc84091335e289a9d3cfca5728b7f775f0329c6fa3e0a0\"},\"application_namespace\":null,\"chain_id\":\"webc-devnet-1\",\"grant_id\":\"4444444444444444444444444444444444444444444444444444444444444444\",\"max_cumulative_fee\":\"100000\",\"max_fee_per_transaction\":\"10000\",\"max_uses\":\"10\",\"payer_lane\":\"5555555555555555555555555555555555555555555555555555555555555555\",\"protocol_version\":2,\"sender\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",\"site_namespace\":\"6666666666666666666666666666666666666666666666666666666666666666\",\"sponsor\":\"webc121uVaRnHeoTdcumRjrvYZuEaBBiHn4wito3PKSpNzjAf\",\"sponsor_public_key\":\"ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1\",\"sponsor_signature\":\"8114099820bc2d1cdfd7be9a9180fe848c98dad6b9a1b54cbfa3a5dbb61f73b82bbe9ba37f2f0370ed73d3d460bed9a3faebee629c7743fa4d53bd554650820d\",\"validity\":{\"valid_from_height\":\"10\",\"valid_until_height\":\"20\"}},\"grant_digest\":\"4bae024a7f9c82f7218cbdda309a7734d4e8c02b2c2a530376ac7531a499eb57\",\"use_nonce\":\"0\"}},\"kind\":{\"Actions\":{\"actions\":[{\"Native\":{\"operation\":{\"Transfer\":{\"amount\":\"123456\",\"to\":\"webc1Di3JaqnPgMD4EtG2EJkdEf1joUBx7uQgziZxZWevqvem\"}}}}]}},\"protocol_version\":2,\"sender\":\"webc16gBDxEHLXj6Tmntfm8227w6JHNoAhAtkoUvAaFw4N4J3\",\"sender_public_key\":\"8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c\",\"sender_signature\":\"eb06340360bf3147dff476900edbe65e1f9c90fb4ca2196056ef5a22ce46bcc665d432dbef9585ef42ef6aba5031574a42efae1ffed743f8ca3895ce258a1904\",\"validity\":{\"valid_from_height\":\"10\",\"valid_until_height\":\"20\"}}";

    #[test]
    fn sender_paid_transfer_has_frozen_cross_language_v5_vector() {
        use crate::canonical::canonical_json_string;
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let validity = ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20));

        let mut tx = unsigned_sender_paid(&sender, recipient.address(), validity);
        let action_digest = tx.kind.digest().expect("action digest");
        tx.sign(&sender).expect("transaction signs");
        tx.verify_for_chain(&ChainId::devnet())
            .expect("transaction verifies");

        assert_eq!(sender.public_key().to_hex(), SENDER_PUBLIC_KEY_HEX);
        assert_eq!(
            String::from_utf8(tx.signing_bytes().expect("signing bytes"))
                .expect("signing bytes are canonical UTF-8 JSON"),
            SENDER_PAID_SIGNING_JSON
        );
        assert_eq!(
            tx.sender_signature
                .as_ref()
                .expect("signature present")
                .to_hex(),
            SENDER_PAID_SIGNATURE_HEX
        );
        assert_eq!(action_digest.to_string(), SENDER_PAID_ACTION_DIGEST_HEX);
        assert_eq!(
            tx.transaction_id().expect("transaction id").to_string(),
            SENDER_PAID_TRANSACTION_ID_HEX
        );
        assert_eq!(
            canonical_json_string(&tx).expect("canonical json"),
            SENDER_PAID_FULL_JSON
        );
    }

    #[test]
    fn scoped_sponsor_has_frozen_cross_language_v5_vector() {
        use crate::canonical::canonical_json_string;
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsor = Keypair::from_seed([3; 32]);
        let validity = ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20));

        let mut tx = unsigned_sender_paid(&sender, recipient.address(), validity);
        let action_digest = tx.kind.digest().expect("action digest");
        let mut grant = SponsorGrantV1 {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            grant_id: SponsorGrantId::new(Hash256([0x44; 32])),
            sponsor: sponsor.address(),
            sponsor_public_key: sponsor.public_key(),
            payer_lane: AuthorizationLaneId::new(Hash256([0x55; 32])),
            sender: sender.address(),
            site_namespace: Some(Hash256([0x66; 32])),
            application_namespace: None,
            action_scope: ActionScopeV1::exact(action_digest),
            validity,
            max_fee_per_transaction: Amount::from_units(10_000),
            max_cumulative_fee: Amount::from_units(100_000),
            max_uses: 10,
            sponsor_signature: None,
        };
        grant.sign(&sponsor).expect("grant signs");

        assert_eq!(sponsor.public_key().to_hex(), SPONSOR_PUBLIC_KEY_HEX);
        assert_eq!(
            String::from_utf8(grant.signing_bytes().expect("grant signing bytes"))
                .expect("grant signing bytes are canonical UTF-8 JSON"),
            SPONSOR_GRANT_SIGNING_JSON
        );
        assert_eq!(
            grant
                .sponsor_signature
                .as_ref()
                .expect("grant signature present")
                .to_hex(),
            SPONSOR_GRANT_SIGNATURE_HEX
        );
        let grant_digest = grant.digest().expect("grant digest");
        assert_eq!(grant_digest.to_string(), SPONSOR_GRANT_DIGEST_HEX);
        assert_eq!(
            fee_bid_digest(tx.fee_bid)
                .expect("fee bid digest")
                .to_string(),
            SPONSORED_FEE_BID_DIGEST_HEX
        );

        let sponsor_use =
            SponsorUseV1::for_transaction(grant, SponsorUseNonce::new(0), &tx.kind, tx.fee_bid)
                .expect("sponsor use builds");
        assert_eq!(
            sponsor_use
                .digest()
                .expect("sponsor use digest")
                .to_string(),
            SPONSOR_USE_DIGEST_HEX
        );
        tx.fee_payment = FeePaymentV1::Sponsored(Box::new(sponsor_use));
        tx.sign(&sender).expect("sponsored transaction signs");
        tx.verify_for_chain(&ChainId::devnet())
            .expect("sponsored transaction verifies");

        assert_eq!(
            tx.sender_signature
                .as_ref()
                .expect("signature present")
                .to_hex(),
            SPONSORED_SIGNATURE_HEX
        );
        assert_eq!(
            tx.transaction_id().expect("transaction id").to_string(),
            SPONSORED_TRANSACTION_ID_HEX
        );
        assert_eq!(
            canonical_json_string(&tx).expect("canonical json"),
            SPONSORED_FULL_JSON
        );
    }

    #[test]
    fn signature_tamper_and_wrong_chain_fail_closed() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let mut tx = unsigned_sender_paid(
            &sender,
            recipient.address(),
            ValidityWindowV1::new(BlockHeight::new(1), BlockHeight::new(2)),
        );
        tx.sign(&sender).expect("transaction signs");
        assert_eq!(
            tx.verify_for_chain(&ChainId::new("webc-other-1").expect("valid chain")),
            Err(TransactionValidationErrorV1::WrongChain)
        );
        tx.validity.valid_until_height = BlockHeight::new(3);
        assert_eq!(
            tx.verify_for_chain(&ChainId::devnet()),
            Err(TransactionValidationErrorV1::InvalidSenderSignature)
        );
    }
}
