//! Signed transaction schema, native operations, fees, and declared state access.
//!
//! Wallets construct and sign this module's canonical payload; the module does
//! not execute or store state. Default access lists enumerate the exact logical
//! keys each native operation is expected to touch. Runtime enforcement lives in
//! `state` and fails atomically if execution diverges from that signed list.

use crate::contract::{
    ContractManifest, CONTRACT_DECLARED_KEY_UNITS, CONTRACT_INPUT_BYTE_UNITS,
    CONTRACT_INVOKE_BASE_UNITS,
};
use crate::namespace::namespace_state_key_hash;
use crate::sponsorship::sponsor_state_key_hash;
use crate::wasm_contract::{WASM_CODE_BYTE_UNITS, WASM_REGISTER_BASE_UNITS};
use crate::{
    Amount, AssetId, AuthorizationLaneId, AuthorizationPolicyRevision, BridgeMessage, ChainError,
    ChainId, Epoch, ExternalChain, GovernanceAction, GovernanceConfig, GovernanceInstanceId,
    MandateCounterpartyPolicy, MandateId, NftAuthorityKind, NftCollectionId, NftMetadata, ObjectId,
    ObjectVersion, PostQuantumRoot, PostQuantumRootReveal, ProposalId, ProtocolStateKey,
    ProtocolVersion, ServiceId, ServicePaymentFlags, ServicePrice, ServiceStatus,
    SessionKeyConstraints, SessionKeyId, SlashingEvidence, StateKey, TokenAuthorityKind, TokenId,
    TokenMetadata, UnbondingRequestId, VoteChoice, WasmBytecode, WasmContractManifest,
    CURRENT_PROTOCOL_VERSION, LEGACY_AUTHORIZATION_POLICY_REVISION, SIGNING_DOMAIN,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
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
// T1: strict decode of every struct variant, matching the sibling wire types
// (`AccessList`, `FeeBid`, `Transaction`). Without this, serde silently ignores
// unknown fields inside a variant, weakening the project's fail-closed decode
// discipline on hostile input.
#[serde(deny_unknown_fields)]
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
    /// Deletes an owned object and settles its storage deposit (§15.22).
    ///
    /// Refunds the configured `refund_bps` share of the object's recorded storage
    /// deposit to the owner's liquid balance and burns the remainder as the
    /// occupancy fee, then removes the object. Mirrors the other owned-object
    /// operations' owner, namespace, and expected-version authorization.
    DeleteObject {
        /// Existing object identity.
        object_id: ObjectId,
        /// Signed namespace that must match stored object metadata.
        namespace: Hash256,
        /// Current revision expected by the sender.
        expected_version: ObjectVersion,
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
    /// Compounds the sender's accumulated operator rewards directly into its own
    /// self-stake, without a claim-then-restake round trip.
    CompoundValidatorRewards,
    /// Compounds accumulated delegation rewards directly into that delegation
    /// position, subject to the operator/delegator ratio.
    CompoundDelegatorRewards {
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
        #[serde(with = "crate::bridge::bounded_recipient_hex")]
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
        #[serde(with = "crate::bridge::bounded_recipient_hex")]
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
    /// Registers the sender as the fee sponsor for an application namespace (§15.35).
    ///
    /// Creates the per-app sponsor record, sets the app-chosen per-day spend cap
    /// (rejected if above the protocol hard cap), and moves `initial_funding`
    /// native base units from the sender's liquid balance into the sponsor budget.
    RegisterAppSponsor {
        /// Application namespace this sponsor underwrites (the same namespace used
        /// by the app's objects — "application" is the sponsoring unit).
        namespace: Hash256,
        /// App-chosen maximum sponsored fee spend per day-window, in base units,
        /// bounded by `SponsorshipConfig::max_app_daily_budget`.
        daily_budget_cap: Amount,
        /// Initial native base units moved from liquid balance into the budget.
        initial_funding: Amount,
    },
    /// Adds native base units to an existing application sponsor budget.
    ///
    /// Only the sponsor owner may fund it. Moves `amount` from the sender's liquid
    /// balance into the app's sponsor budget.
    FundAppSponsor {
        /// Existing application namespace whose sponsor budget is topped up.
        namespace: Hash256,
        /// Native base units moved from liquid balance into the budget.
        amount: Amount,
    },
    /// Withdraws unspent native base units from an application sponsor budget.
    ///
    /// Only the sponsor owner may withdraw. Moves `amount` from the app's sponsor
    /// budget back to the owner's liquid balance; fails if it exceeds the budget.
    WithdrawAppSponsor {
        /// Existing application namespace whose sponsor budget is drawn down.
        namespace: Hash256,
        /// Native base units returned to the owner's liquid balance.
        amount: Amount,
    },
    /// Claims an unclaimed application namespace for the sender (§8 isolation).
    ///
    /// Records the sender as the owner of `namespace` in the namespace registry.
    /// Fails if the namespace is already registered. Locks no native units — it is
    /// purely an ownership record, so only the ordinary transaction fee moves.
    /// Ownership is **not** required to create objects under a namespace today;
    /// gating object creation on ownership is a later-phase policy decision.
    RegisterNamespace {
        /// Application namespace the sender claims.
        namespace: Hash256,
    },
    /// Transfers a registered application namespace to a new owner (§8 isolation).
    ///
    /// Only the current owner may transfer. Fails if the namespace is not
    /// registered or the sender is not its owner. Moves no native units.
    TransferNamespace {
        /// Registered application namespace being transferred.
        namespace: Hash256,
        /// Account that becomes the new owner.
        new_owner: Address,
    },
    /// Creates a native oracle feed for a flat fee (§15.6 permissionless-for-a-fee).
    ///
    /// Records a canonical [`crate::Feed`] owned by the sender and charges the
    /// configured feed-creation fee (burned). Fails if the feed id already exists.
    CreateFeed {
        /// Caller-chosen collision-resistant feed identity.
        feed_id: crate::FeedId,
    },
    /// Registers the sender as a bonded reporter on an existing feed (§15.17).
    ///
    /// Locks the feed's frozen bond from the sender's liquid balance into the
    /// `oracle_bonds` bucket. Fails if the feed is missing or the sender is
    /// already registered on it.
    RegisterReporter {
        /// Feed the sender bonds to report on.
        feed_id: crate::FeedId,
    },
    /// Deregisters the sender from a feed and returns its bond (§15.17).
    ///
    /// Removes the sender's reporter record and returns the feed's bond to the
    /// sender's liquid balance. Fails if the sender is not registered.
    DeregisterReporter {
        /// Feed the sender leaves.
        feed_id: crate::FeedId,
    },
    /// Submits the sender's latest value for a feed (§9 median aggregation).
    ///
    /// Records the value and the epoch it was submitted for (liveness). The feed's
    /// aggregate is the median of all registered reporters' latest values. Fails
    /// if the sender is not a registered reporter on the feed.
    SubmitReport {
        /// Feed being reported to.
        feed_id: crate::FeedId,
        /// The reporter's latest integer value in the feed's own units.
        value: crate::FeedValue,
    },
    /// Pays a read fee into a feed's revenue pool (§15.17 consumers pay).
    ///
    /// Moves `amount` from the payer's liquid balance into the feed's accrued
    /// revenue (`oracle_revenue` bucket); settlement later distributes it to the
    /// feed's reporters weighted by accuracy and liveness. Fails if the feed is
    /// missing or `amount` is zero.
    PayFeedRead {
        /// Feed whose value the payer is consuming on-chain.
        feed_id: crate::FeedId,
        /// Native base units paid into the feed's revenue pool.
        amount: Amount,
    },
    /// Submits a DEX order intent for per-block uniform-price batch settlement
    /// (§15.13/§15.18/§15.37).
    ///
    /// Locks the order's input into the `dex_escrow` bucket (a `Sell` locks
    /// `amount` base; a `Buy` locks `amount × limit_price` quote), records the
    /// order under `StateKey::dex_order(order_id)`, and lets the block's batch
    /// settle it against crossing counter-orders at one uniform clearing price. An
    /// unfilled remainder retries in later batches until filled, cancelled, or its
    /// `deadline_height` passes (unless `fill_or_cancel`, which cancels any
    /// remainder the same block). Default lane only. Fails if the order id already
    /// exists, the pair is degenerate, the amount/price is zero (or below the
    /// configured minimum), or the deadline is already in the past.
    SubmitOrder {
        /// Caller-chosen collision-resistant order identity (known at signing time
        /// so the access list can name the order's state key).
        order_id: crate::OrderId,
        /// Oriented trading pair; `amount` is in `base`, price in `quote`.
        pair: crate::TradingPair,
        /// Buy (acquire base, pay quote) or sell (dispose base, receive quote).
        side: crate::OrderSide,
        /// Order size in base-asset base units.
        amount: Amount,
        /// Limit price in quote base-units per base base-unit (a buy pays at most,
        /// a sell receives at least, this price).
        limit_price: crate::Price,
        /// Last block height at which the order may still settle; `0` means "use the
        /// configured default retry window from the submission height".
        deadline_height: u64,
        /// Immediate-or-cancel: cancel any amount unfilled in the batch it joins
        /// instead of retrying.
        fill_or_cancel: bool,
    },
    /// Cancels a live DEX order and refunds its remaining locked input (§15.37).
    ///
    /// Only the order's owner may cancel. Refunds the currently-locked remainder
    /// (a `Buy`'s `remaining × limit_price` quote, a `Sell`'s `remaining` base) to
    /// the owner and removes the record. Default lane only. Fails if the order does
    /// not exist or the sender is not its owner.
    CancelOrder {
        /// Identity of the order to cancel.
        order_id: crate::OrderId,
    },
    /// Registers an interim Rust-authored contract for a flat, burned fee
    /// (Phase 7a, ADR-0014 interim path (c)).
    ///
    /// Commits the signed [`ContractManifest`] under `StateKey::module(code_id)`
    /// and charges the configured registration fee (burned, supply-neutral, like
    /// feed creation). Fails if `code_id` is already registered or the manifest is
    /// malformed. Registers no untrusted bytecode — the manifest names an audited
    /// built-in handler.
    RegisterContract {
        /// The contract's committed interface record (identity, namespace,
        /// declared footprint, ABI/gas-schedule versions, built-in handler).
        manifest: ContractManifest,
    },
    /// Invokes a registered contract's handler behind the native declared-access
    /// and gas discipline (Phase 7a, ADR-0014 interim path (c)).
    ///
    /// Looks up the manifest by `code_id`, binds this signed operation to it
    /// (`namespace` and `declared_keys` must match the manifest exactly), meters
    /// the call against the sender's `gas_limit`, runs the audited handler over
    /// only its declared footprint, and commits its state writes. An over-gas call
    /// or an undeclared access rolls the whole transaction back atomically.
    InvokeContract {
        /// Registered contract identity (the manifest / `StateKey::module` key).
        code_id: Hash256,
        /// Application namespace the contract's state lives under; must equal the
        /// manifest's `namespace`. Carried in the signed operation so the access
        /// list is self-contained and the scheduler needs no manifest lookup.
        namespace: Hash256,
        /// The application key-hashes this call declares; must equal the manifest
        /// `footprint`. Each becomes a `StateKey::application(namespace, key_hash)`
        /// read_write in the access list.
        declared_keys: Vec<Hash256>,
        /// Bounded opaque input forwarded verbatim to the handler.
        #[serde(with = "crate::hex_bytes")]
        input: Vec<u8>,
    },
    /// Registers a deployer-supplied WASM contract, uploading and validating its
    /// bytecode for a flat, burned fee (Phase 7b, ADR-0014 path (a)).
    ///
    /// Commits the signed [`WasmContractManifest`] under `StateKey::module(code_id)`
    /// together with its [`WasmBytecode`], after checking the manifest, the
    /// code-hash binding, the size cap, and deterministic-engine acceptance of the
    /// module. Charges the configured registration fee (burned, supply-neutral).
    /// Fails if `code_id` is already registered (native OR wasm) or anything is
    /// malformed. Registers real untrusted bytecode — the engine sandbox and the
    /// declared-footprint discipline are what bound it. Default lane only.
    RegisterWasmContract {
        /// The contract's committed interface record (identity, namespace, declared
        /// footprint, ABI/gas-schedule versions, and code-hash binding).
        manifest: WasmContractManifest,
        /// The WASM module bytes, stored under the same `code_id` and bound to the
        /// manifest by `manifest.code_hash`.
        code: WasmBytecode,
    },
    /// Invokes a registered WASM contract's module behind the SAME declared-access
    /// and gas discipline as the native path (Phase 7b, ADR-0014 path (a)).
    ///
    /// Looks up the wasm manifest by `code_id`, binds this signed operation to it
    /// (`namespace` and `declared_keys` must match exactly), meters the call
    /// against the sender's `gas_limit`, runs the module on the deterministic
    /// engine over only its declared footprint, and commits its state writes. An
    /// over-gas call, a guest trap, or an undeclared access rolls the whole
    /// transaction back atomically.
    InvokeWasmContract {
        /// Registered wasm-contract identity (the manifest / `StateKey::module` key).
        code_id: Hash256,
        /// Application namespace the contract's state lives under; must equal the
        /// manifest's `namespace`. Carried in the signed operation so the access
        /// list is self-contained and the scheduler needs no manifest lookup.
        namespace: Hash256,
        /// The application key-hashes this call declares; must equal the manifest
        /// `footprint`. Each becomes a `StateKey::application(namespace, key_hash)`
        /// read_write in the access list.
        declared_keys: Vec<Hash256>,
        /// Bounded opaque input forwarded verbatim to the module's `webc_call`.
        #[serde(with = "crate::hex_bytes")]
        input: Vec<u8>,
    },
    /// Grants a pre-funded agent mandate and escrows its budget (Phase 9a, §15.32).
    ///
    /// Principal-signed (the sender is the principal). Derives the mandate id from
    /// `(sender, agent_key, grant_nonce)`, moves `budget_total` native base units
    /// from the sender's liquid balance into the `mandate_escrow` bucket, and
    /// records a [`crate::Mandate`]. Fails if the derived id already exists, the
    /// grant parameters are invalid, or the sender cannot cover `budget_total`
    /// plus the transaction fee. Default lane only.
    GrantMandate {
        /// The agent's Ed25519 signing key authorized to spend under this mandate.
        agent_key: PublicKeyBytes,
        /// Principal-chosen uniquifier so one principal may hold several mandates
        /// for the same agent key; part of the derived mandate id.
        grant_nonce: u64,
        /// Total native base units authorized over the mandate's whole life.
        budget_total: Amount,
        /// Last consensus epoch (inclusive) in which the mandate may be spent.
        expiry_epoch: Epoch,
        /// Maximum native principal one mandate-signed spend may move.
        per_tx_max: Amount,
        /// Maximum spends per rate-limit window; `0` means unlimited.
        rate_limit_per_day: u32,
        /// Which counterparties the mandate's spends may pay.
        counterparty_policy: MandateCounterpartyPolicy,
    },
    /// Adds native base units to an existing mandate's budget (Phase 9a, §15.32).
    ///
    /// Principal-signed. Moves `amount` from the sender's liquid balance into the
    /// `mandate_escrow` bucket and raises the mandate's `budget_total`. Only the
    /// mandate's principal may top it up; a revoked mandate cannot be topped up.
    /// Default lane only.
    TopUpMandate {
        /// The mandate to top up.
        mandate_id: MandateId,
        /// Native base units moved from liquid balance into the mandate budget.
        amount: Amount,
    },
    /// Spends against a mandate, signed by the agent key (Phase 9a, §15.32).
    ///
    /// Signed by the mandate's `agent_key` (the sender is the agent's own
    /// address). The runtime enforces, atomically, that the mandate exists, is not
    /// revoked, is unexpired, that `amount <= per_tx_max`, that `spent + amount +
    /// fee <= budget_total`, that the recipient is permitted, and that the per-day
    /// rate limit is not exceeded. On success it moves `amount` to the recipient
    /// and routes the fee through the normal burn/reward split — both drawn from
    /// the mandate escrow, so the agent needs no balance of its own. Default lane
    /// only.
    SpendUnderMandate {
        /// The mandate authorizing (and funding) this spend.
        mandate_id: MandateId,
        /// Recipient account credited the spent principal.
        recipient: Address,
        /// Native principal moved to the recipient (excludes the fee).
        amount: Amount,
    },
    /// Revokes a mandate and returns its unspent remainder (Phase 9a, §15.32).
    ///
    /// Principal-signed. Returns `budget_total - spent` from the `mandate_escrow`
    /// bucket to the principal's liquid balance and marks the mandate revoked so no
    /// further spend succeeds; revocation is effective from the block it lands in.
    /// Also the reclaim path for an expired mandate. Default lane only.
    RevokeMandate {
        /// The mandate to revoke and reclaim.
        mandate_id: MandateId,
    },
    /// Registers a service in the native registry (Phase 9b, §15.5).
    ///
    /// Owner-signed (the sender is the entry's `owner` and pay-to account).
    /// Derives the service id from `(namespace, sender, create_nonce)` and records
    /// a [`crate::ServiceEntry`] at revision [`crate::INITIAL_SERVICE_REVISION`]
    /// with status [`crate::ServiceStatus::Active`]. It records data only and locks
    /// NO native units; the spam price is this operation's HIGH `required_units`,
    /// so the ordinary transaction fee (which flows through the normal burn / fee-
    /// pool split) makes registration permissionless-for-a-fee. Fails if the derived
    /// id already exists or the entry is malformed (over-length/over-count/empty
    /// required field). Any authorization lane may pay the fee.
    RegisterService {
        /// Application namespace the entry lives under; bound into the service id.
        namespace: Hash256,
        /// Owner-chosen uniquifier so one owner may register several services under
        /// one namespace; part of the derived service id.
        create_nonce: u64,
        /// Taxonomy tags a mandate allowlist may reference (bounded count).
        categories: BTreeSet<Hash256>,
        /// Short human/machine label, lowercase hex on the wire (bounded length).
        #[serde(with = "crate::service_registry::bounded_title_hex")]
        title: Vec<u8>,
        /// HTTPS URL or on-chain entrypoint reference, lowercase hex (bounded).
        #[serde(with = "crate::service_registry::bounded_endpoint_hex")]
        endpoint: Vec<u8>,
        /// Manifest reference hash for the machine-readable interface description.
        interface: Hash256,
        /// Priced operations the service exposes (bounded count).
        pricing: Vec<ServicePrice>,
        /// Accepted payment flows.
        payment_flags: ServicePaymentFlags,
    },
    /// Updates a registered service's mutable fields (Phase 9b, §15.5).
    ///
    /// Owner-only. Replaces the entry's categories, title, endpoint, interface,
    /// pricing, and payment flows, keeping its owner, namespace, and status, and
    /// bumps `revision`. Only the CURRENT revision lives in committed active state.
    /// Fails if the service does not exist (`ServiceNotFound`), the sender is not
    /// its owner (`ServiceNotOwner`), or the resulting entry is malformed
    /// (`InvalidServiceEntry`). Any authorization lane may pay the fee.
    UpdateService {
        /// Identity of the service to update.
        service_id: ServiceId,
        /// Replacement taxonomy tags (bounded count).
        categories: BTreeSet<Hash256>,
        /// Replacement label, lowercase hex on the wire (bounded length).
        #[serde(with = "crate::service_registry::bounded_title_hex")]
        title: Vec<u8>,
        /// Replacement endpoint reference, lowercase hex (bounded length).
        #[serde(with = "crate::service_registry::bounded_endpoint_hex")]
        endpoint: Vec<u8>,
        /// Replacement manifest reference hash.
        interface: Hash256,
        /// Replacement priced operations (bounded count).
        pricing: Vec<ServicePrice>,
        /// Replacement accepted payment flows.
        payment_flags: ServicePaymentFlags,
    },
    /// Pauses, retires, or reactivates a registered service (Phase 9b, §15.5).
    ///
    /// Owner-only. Sets the entry's lifecycle `status` and bumps `revision`. A
    /// Paused or Retired service rejects service-scoped spends. Fails if the
    /// service does not exist (`ServiceNotFound`) or the sender is not its owner
    /// (`ServiceNotOwner`). Any authorization lane may pay the fee.
    SetServiceStatus {
        /// Identity of the service whose status changes.
        service_id: ServiceId,
        /// The new lifecycle status.
        status: ServiceStatus,
    },
    /// Spends against a mandate to pay a registered service (Phase 9b, §15.5).
    ///
    /// Signed by the mandate's `agent_key` (same auth model as
    /// [`Self::SpendUnderMandate`]). Pays the SERVICE's `owner` account from the
    /// mandate escrow, enforcing — O(1), no registry scan — every Phase 9a mandate
    /// check (exists, not revoked, not expired, `amount <= per_tx_max`, `spent +
    /// amount + fee <= budget_total`, daily rate limit) PLUS the counterparty policy
    /// resolved against the registry ([`MandateCounterpartyPolicy::permits_service`]:
    /// the service owner satisfies a recipient allowlist, and an active service's
    /// categories resolve a category allowlist), and additionally requires the
    /// service to be [`crate::ServiceStatus::Active`] (`ServiceNotActive`). On
    /// success it credits `amount` to the service owner and routes the fee exactly
    /// as [`Self::SpendUnderMandate`], both drawn from the mandate escrow. The
    /// service owner (the registry pay-to) is state-derived, so a caller must
    /// additionally declare its account in the signed access list — the runtime
    /// resolves it from the entry, exactly the HTTP-402 pay-to check
    /// ([`Transaction::for_service_spend`] builds this list). Default lane only.
    SpendUnderMandateToService {
        /// The mandate authorizing (and funding) this spend.
        mandate_id: MandateId,
        /// The service whose owner is credited the spent principal.
        service_id: ServiceId,
        /// Native principal moved to the service owner (excludes the fee).
        amount: Amount,
    },
    /// Creates a native fungible token (Phase 13a, §15).
    ///
    /// Creator-signed (the sender is the token's `creator`). Derives the token id
    /// from `(namespace, sender, create_nonce)` and records a
    /// [`crate::TokenRecord`] with the given authorities. It LOCKS a native WEBC
    /// creation deposit (`ChainConfig::token.creation_deposit`) from the creator's
    /// liquid balance into the `token_deposits` bucket — an anti-spam price that is
    /// NON-REFUNDABLE for the token's life; token creation NEVER mints or burns
    /// native WEBC. Optionally mints `initial_supply` to `initial_recipient` at
    /// creation. Fails if the derived id already exists (`TokenAlreadyExists`) or
    /// the metadata is malformed (`InvalidTokenMetadata`). Any authorization lane
    /// may pay the fee.
    CreateToken {
        /// Application namespace the token lives under; bound into the token id.
        namespace: Hash256,
        /// Creator-chosen uniquifier so one creator may create several tokens
        /// under one namespace; part of the derived token id.
        create_nonce: u64,
        /// Bounded metadata (name, symbol, decimals, off-chain commitment).
        metadata: TokenMetadata,
        /// Initial mint authority; `None` creates the token with minting
        /// permanently renounced (a fixed supply equal to `initial_supply`).
        mint_authority: Option<Address>,
        /// Initial freeze authority; `None` creates the token with freezing
        /// permanently renounced.
        freeze_authority: Option<Address>,
        /// Amount minted to `initial_recipient` at creation (may be zero).
        initial_supply: Amount,
        /// Account credited `initial_supply` at creation.
        initial_recipient: Address,
    },
    /// Mints new units of a token to a recipient (Phase 13a, §15).
    ///
    /// Must be signed by the token's current `mint_authority`; rejected if that
    /// authority is `None` (minting renounced) or the signer differs
    /// (`TokenMintNotAuthorized`). Increases the token's `issued_supply` and
    /// credits `recipient`. Rejected if `recipient` is frozen
    /// (`TokenAccountFrozen`). Moves no native WEBC beyond the fee. Any
    /// authorization lane may pay the fee.
    MintToken {
        /// Token to mint.
        token_id: TokenId,
        /// Account credited the newly minted units.
        recipient: Address,
        /// Units minted.
        amount: Amount,
    },
    /// Burns units of a token from the signer's own balance (Phase 13a, §15).
    ///
    /// A holder burns their OWN balance: decreases their balance and the token's
    /// `issued_supply`. Rejected if the holder is frozen (`TokenAccountFrozen`) or
    /// holds less than `amount` (`TokenInsufficientBalance`). Any authorization
    /// lane may pay the fee.
    BurnToken {
        /// Token to burn.
        token_id: TokenId,
        /// Units burned from the signer's balance.
        amount: Amount,
    },
    /// Transfers token units from the signer to a recipient (Phase 13a, §15).
    ///
    /// Holder→recipient. Rejected if the token is paused (`TokenPaused`), the
    /// sender or recipient is frozen (`TokenAccountFrozen`), or the sender holds
    /// less than `amount` (`TokenInsufficientBalance`). A sender balance that
    /// reaches zero is pruned. This writes ONLY the two `(token, account)` balance
    /// keys (the token record is read-only, consulted for the paused flag), so an
    /// ordinary transfer never writes a global per-token object (a Phase 13
    /// acceptance criterion). Any authorization lane may pay the fee.
    TransferToken {
        /// Token to transfer.
        token_id: TokenId,
        /// Account credited the transferred units.
        recipient: Address,
        /// Units transferred.
        amount: Amount,
    },
    /// Pauses or unpauses all transfers of a token (Phase 13a, §15).
    ///
    /// Only the token's current `mint_authority` may pause/unpause (the Phase 13a
    /// simplification keeps a single privileged authority rather than a dedicated
    /// pause authority); rejected if minting is renounced
    /// (`TokenMintNotAuthorized`). While paused, [`Self::TransferToken`] is
    /// rejected. Any authorization lane may pay the fee.
    SetTokenPaused {
        /// Token whose paused flag changes.
        token_id: TokenId,
        /// New paused state.
        paused: bool,
    },
    /// Freezes one account's balance of a token (Phase 13a, §15).
    ///
    /// Freeze-authority-signed; rejected if freezing is renounced or the signer is
    /// not the current freeze authority (`TokenFreezeNotAuthorized`). A frozen
    /// account can neither send nor receive the token. Any authorization lane may
    /// pay the fee.
    FreezeTokenAccount {
        /// Token whose account is frozen.
        token_id: TokenId,
        /// Account to freeze.
        account: Address,
    },
    /// Thaws (unfreezes) one account's balance of a token (Phase 13a, §15).
    ///
    /// Freeze-authority-signed (the same authority check as
    /// [`Self::FreezeTokenAccount`]). Removes the `(token, account)` freeze marker.
    /// Any authorization lane may pay the fee.
    ThawTokenAccount {
        /// Token whose account is thawed.
        token_id: TokenId,
        /// Account to thaw.
        account: Address,
    },
    /// Transfers or permanently renounces one of a token's authorities (Phase 13a,
    /// §15).
    ///
    /// The CURRENT holder of the named authority may transfer it to a new address
    /// (`Some`) or permanently renounce it (`None`). Rejected if the current
    /// authority is already `None` (nothing to transfer) or the signer is not the
    /// current authority (`TokenAuthorityNotAuthorized`). Renouncement is
    /// PERMANENT: a `None` authority can never be restored (a Phase 13 acceptance
    /// criterion, "revoked authority cannot return"). Any authorization lane may
    /// pay the fee.
    SetTokenAuthority {
        /// Token whose authority changes.
        token_id: TokenId,
        /// Which authority (mint or freeze) is transferred/renounced.
        authority_kind: TokenAuthorityKind,
        /// New holder, or `None` to permanently renounce.
        new_authority: Option<Address>,
    },
    /// Creates a native NFT collection (Phase 13b, §15).
    ///
    /// Creator-signed (the sender is the collection's `creator`). Derives the
    /// collection id from `(namespace, sender, create_nonce)` and records an
    /// [`crate::NftCollection`] with the given authorities, optional supply cap, and
    /// royalty commitment. It LOCKS a native WEBC creation deposit
    /// (`ChainConfig::nft.creation_deposit`) from the creator's liquid balance into
    /// the `nft_deposits` bucket — an anti-spam price that is NON-REFUNDABLE for the
    /// collection's life; creation NEVER mints or burns native WEBC and mints no
    /// items (minting is a separate [`Self::MintNft`]). Fails if the derived id
    /// already exists (`NftCollectionAlreadyExists`) or the metadata/royalty is
    /// malformed (`InvalidNftMetadata`). Any authorization lane may pay the fee.
    CreateNftCollection {
        /// Application namespace the collection lives under; bound into the id.
        namespace: Hash256,
        /// Creator-chosen uniquifier so one creator may create several collections
        /// under one namespace; part of the derived collection id.
        create_nonce: u64,
        /// Bounded metadata (name, symbol, off-chain commitment).
        metadata: NftMetadata,
        /// Initial mint authority; `None` creates the collection with minting
        /// permanently renounced (a collection that can never mint an item).
        mint_authority: Option<Address>,
        /// Initial freeze authority; `None` creates the collection with freezing
        /// permanently renounced.
        freeze_authority: Option<Address>,
        /// Optional hard cap on the total number of items ever minted (`None` = no
        /// cap).
        max_supply: Option<u64>,
        /// Creator royalty commitment in basis points (≤ 10_000). Recorded only; the
        /// chain does NOT enforce royalties on transfer (a marketplace concern).
        royalty_bps: u16,
    },
    /// Mints a new item of a collection to a recipient (Phase 13b, §15).
    ///
    /// Must be signed by the collection's current `mint_authority`; rejected if that
    /// authority is `None` (minting renounced) or the signer differs
    /// (`NftMintNotAuthorized`). Assigns `serial = next_serial`, increments
    /// `next_serial` and `minted_count`, and creates the item owned by `recipient`.
    /// Rejected if the collection is paused (`NftCollectionPaused`) or the cap is
    /// reached (`NftMaxSupplyReached`). The minted [`crate::NftId`] is carried in the
    /// receipt event. Moves no native WEBC beyond the fee. Any authorization lane may
    /// pay the fee.
    MintNft {
        /// Collection to mint into.
        collection_id: NftCollectionId,
        /// Account that will own the newly minted item.
        recipient: Address,
        /// Fixed-size commitment to the item's off-chain metadata.
        item_metadata_hash: Hash256,
    },
    /// Transfers one NFT item from its owner to a recipient (Phase 13b, §15).
    ///
    /// Signed by the CURRENT item owner (`NftNotOwner` otherwise). Moves ownership of
    /// the single item. Rejected if the item is frozen (`NftItemFrozen`), the
    /// collection is paused (`NftCollectionPaused`), or the item does not exist
    /// (`NftItemNotFound`). This writes ONLY the one item key (the collection record
    /// is read-only, consulted for the paused flag), so an ordinary transfer never
    /// writes a global per-collection object (a Phase 13 acceptance criterion). Any
    /// authorization lane may pay the fee.
    TransferNft {
        /// Collection the item belongs to.
        collection_id: NftCollectionId,
        /// Serial of the item to transfer.
        serial: u64,
        /// Account credited ownership of the item.
        recipient: Address,
    },
    /// Burns one NFT item held by the signer (Phase 13b, §15).
    ///
    /// The CURRENT owner burns their own item: removes it and increments
    /// `burned_count`. Rejected if the item is frozen (`NftItemFrozen`), not owned by
    /// the signer (`NftNotOwner`), or absent (`NftItemNotFound`). `next_serial` is
    /// NOT decremented, so a burned serial is never reminted. Any authorization lane
    /// may pay the fee.
    BurnNft {
        /// Collection the item belongs to.
        collection_id: NftCollectionId,
        /// Serial of the item to burn.
        serial: u64,
    },
    /// Pauses or unpauses minting of a collection (Phase 13b, §15).
    ///
    /// Only the collection's current `mint_authority` may pause/unpause (the Phase
    /// 13b simplification keeps a single privileged authority rather than a dedicated
    /// pause authority); rejected if minting is renounced (`NftMintNotAuthorized`).
    /// While paused, [`Self::MintNft`] is rejected. Any authorization lane may pay the
    /// fee.
    SetNftCollectionPaused {
        /// Collection whose paused flag changes.
        collection_id: NftCollectionId,
        /// New paused state.
        paused: bool,
    },
    /// Freezes one NFT item (Phase 13b, §15).
    ///
    /// Freeze-authority-signed; rejected if freezing is renounced or the signer is
    /// not the current freeze authority (`NftFreezeNotAuthorized`), or the item is
    /// absent (`NftItemNotFound`). A frozen item can be neither transferred nor
    /// burned. Any authorization lane may pay the fee.
    FreezeNftItem {
        /// Collection the item belongs to.
        collection_id: NftCollectionId,
        /// Serial of the item to freeze.
        serial: u64,
    },
    /// Thaws (unfreezes) one NFT item (Phase 13b, §15).
    ///
    /// Freeze-authority-signed (the same authority check as [`Self::FreezeNftItem`]).
    /// Clears the item's `frozen` flag. Any authorization lane may pay the fee.
    ThawNftItem {
        /// Collection the item belongs to.
        collection_id: NftCollectionId,
        /// Serial of the item to thaw.
        serial: u64,
    },
    /// Transfers or permanently renounces one of a collection's authorities
    /// (Phase 13b, §15).
    ///
    /// The CURRENT holder of the named authority may transfer it to a new address
    /// (`Some`) or permanently renounce it (`None`). Rejected if the current
    /// authority is already `None` (nothing to transfer) or the signer is not the
    /// current authority (`NftAuthorityNotAuthorized`). Renouncement is PERMANENT: a
    /// `None` authority can never be restored (a Phase 13 acceptance criterion,
    /// "revoked authority cannot return"). Any authorization lane may pay the fee.
    SetNftAuthority {
        /// Collection whose authority changes.
        collection_id: NftCollectionId,
        /// Which authority (mint or freeze) is transferred/renounced.
        authority_kind: NftAuthorityKind,
        /// New holder, or `None` to permanently renounce.
        new_authority: Option<Address>,
    },
    /// Creates a native application-governance instance (Phase 13c, §15).
    ///
    /// Creator-signed (the sender is the instance's `creator`). Derives the instance
    /// id from `(namespace, sender, create_nonce)` and records a
    /// [`crate::GovernanceInstance`] bound to `weight_token` under the given
    /// [`crate::GovernanceConfig`]. It LOCKS a native WEBC creation deposit
    /// (`ChainConfig::governance.creation_deposit`) from the creator's liquid balance
    /// into the `governance_deposits` bucket — a NON-REFUNDABLE anti-spam price;
    /// creation NEVER mints or burns native WEBC. Fails if the derived id already
    /// exists (`GovernanceInstanceAlreadyExists`), the config is malformed
    /// (`InvalidGovernanceConfig`), or `weight_token` does not exist (`TokenNotFound`).
    /// Any authorization lane may pay the fee.
    CreateGovernanceInstance {
        /// Application namespace the instance lives under; bound into the id.
        namespace: Hash256,
        /// Creator-chosen uniquifier so one creator may create several instances
        /// under one namespace; part of the derived instance id.
        create_nonce: u64,
        /// Fungible token whose per-account balance denominates voting weight.
        weight_token: TokenId,
        /// Immutable rule set (voting period, timelock, quorum, proposal threshold,
        /// approval threshold).
        config: GovernanceConfig,
    },
    /// Funds a governance instance's native-WEBC treasury (Phase 13c, §15).
    ///
    /// Anyone may deposit: moves `amount` native WEBC from the sender's liquid
    /// balance into the instance's `treasury` (tracked by the aggregate
    /// `governance_treasury` bucket). Supply-neutral — the units move from liquid to
    /// the treasury bucket, never minted or burned. Fails if the instance does not
    /// exist (`GovernanceInstanceNotFound`) or the sender cannot afford `amount`. Any
    /// authorization lane may pay the fee.
    FundGovernanceTreasury {
        /// Instance whose treasury grows.
        instance_id: GovernanceInstanceId,
        /// Native base units moved into the treasury.
        amount: Amount,
    },
    /// Opens a proposal on a governance instance (Phase 13c, §15).
    ///
    /// The proposer must currently hold at least the instance's
    /// `config.proposal_threshold` of the weight token (`GovernanceProposalThresholdNotMet`).
    /// Assigns the proposal a chain-derived [`crate::ProposalId`] from the instance's
    /// monotonic nonce, snapshots the weight token and rule set onto the proposal,
    /// and sets it `Active` until `created_epoch + voting_period_epochs`. A
    /// [`crate::GovernanceAction::TreasuryTransfer`] whose amount exceeds the CURRENT
    /// treasury is rejected at open (`GovernanceTreasuryInsufficient`) as a sanity
    /// check; execution re-checks the live treasury. Any authorization lane may pay
    /// the fee.
    OpenProposal {
        /// Instance the proposal belongs to.
        instance_id: GovernanceInstanceId,
        /// The single bounded typed effect the proposal carries.
        action: GovernanceAction,
    },
    /// Casts a lock-to-vote ballot on a proposal (Phase 13c, §15).
    ///
    /// LOCKS `weight_amount` of the proposal's weight token by MOVING it from the
    /// voter's balance into the proposal's deterministic escrow
    /// ([`crate::gov_vote_escrow_address`]); the locked amount is the vote's weight,
    /// added to the proposal's `choice` tally. A voter may vote only ONCE per
    /// proposal (`GovernanceAlreadyVoted`). Rejected if the proposal is not `Active`
    /// (`GovernanceProposalNotActive`), voting has ended (`GovernanceVotingClosed`),
    /// the weight is zero (`GovernanceVoteWeightZero`), the voter holds less than
    /// `weight_amount` (`TokenInsufficientBalance`), or the weight token is paused
    /// (`TokenPaused`) or the voter/escrow is frozen (`TokenAccountFrozen`) — the same
    /// freeze/pause rules a [`Self::TransferToken`] respects. Any authorization lane
    /// may pay the fee.
    CastVote {
        /// Proposal being voted on.
        proposal_id: ProposalId,
        /// The voter's choice.
        choice: VoteChoice,
        /// Weight-token units locked as this vote's weight (must be > 0).
        weight_amount: Amount,
    },
    /// Resolves a proposal after its voting period ends (Phase 13c, §15).
    ///
    /// Permissionless. Computes quorum against the weight token's issued supply and
    /// approval against the decisive tally, then sets the proposal `Passed` (with
    /// `eta_epoch = voting_ends_epoch + timelock_epochs`) or `Defeated`. Rejected
    /// before voting ends (`GovernanceVotingOpen`), if the proposal is not `Active`
    /// (`GovernanceProposalNotActive`), or if already resolved
    /// (`GovernanceAlreadyResolved`). Any authorization lane may pay the fee.
    ResolveProposal {
        /// Proposal to resolve.
        proposal_id: ProposalId,
    },
    /// Executes a passed proposal after its timelock (Phase 13c, §15).
    ///
    /// Permissionless. Requires the proposal to be `Passed` (`GovernanceProposalNotPassed`)
    /// and `current_epoch >= eta_epoch` (`GovernanceTimelockNotElapsed`). For a
    /// [`crate::GovernanceAction::TreasuryTransfer`] it RE-CHECKS the live treasury
    /// (fail-closed with `GovernanceTreasuryInsufficient`) and, on success, pays the
    /// recipient from the treasury and sets the proposal `Executed`. Once the
    /// execution window (one voting period past `eta_epoch`) has lapsed, it instead
    /// sets the proposal `Expired` (a stale approval can no longer drain the
    /// treasury). Any authorization lane may pay the fee.
    ExecuteProposal {
        /// Proposal to execute.
        proposal_id: ProposalId,
    },
    /// Reclaims a voter's locked weight after a proposal resolves (Phase 13c, §15).
    ///
    /// Moves the voter's locked weight-token units back from the proposal escrow to
    /// their balance and clears the lock, so the units can be transferred or re-used.
    /// Allowed only once the proposal is resolved (`Passed`/`Defeated`/`Executed`/`Expired`;
    /// otherwise `GovernanceProposalNotResolved`) and only if the voter has a lock
    /// (`GovernanceNothingToReclaim`). Any authorization lane may pay the fee.
    ReclaimVote {
        /// Proposal whose lock is reclaimed.
        proposal_id: ProposalId,
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
            Self::CreateObject { .. }
            | Self::MutateObject { .. }
            | Self::TransferObject { .. }
            | Self::DeleteObject { .. } => 20_000,
            Self::RegisterValidator { .. } => 25_000,
            Self::Delegate { .. }
            | Self::Undelegate { .. }
            | Self::UnstakeValidator { .. }
            | Self::ClaimUnbonded { .. } => 10_000,
            Self::ClaimValidatorRewards | Self::ClaimDelegatorRewards { .. } => 5_000,
            Self::CompoundValidatorRewards | Self::CompoundDelegatorRewards { .. } => 7_500,
            Self::SubmitSlashingEvidence { .. } => 20_000,
            Self::BridgeLock { .. } | Self::BridgeBurn { .. } => 50_000,
            Self::BridgeMint { .. } | Self::BridgeRelease { .. } => 75_000,
            Self::RegisterAppSponsor { .. }
            | Self::FundAppSponsor { .. }
            | Self::WithdrawAppSponsor { .. } => 10_000,
            Self::RegisterNamespace { .. } | Self::TransferNamespace { .. } => 10_000,
            // A grant creates one record and locks its budget; top-up/revoke move
            // units on one record; a spend moves units and writes one record —
            // comparable to the other single-record locked-value operations.
            Self::GrantMandate { .. }
            | Self::TopUpMandate { .. }
            | Self::SpendUnderMandate { .. }
            | Self::RevokeMandate { .. } => 10_000,
            // Registration is permissionless-for-a-fee: it records data and locks
            // no native units, so the anti-spam price is a HIGH ordinary fee (the
            // fee flows through the normal burn / fee-pool split, no new bucket).
            Self::RegisterService { .. } => 20_000,
            // Update / status-change rewrite one existing record; a service-scoped
            // spend moves units and writes one record — comparable to the other
            // single-record management / locked-value operations.
            Self::UpdateService { .. }
            | Self::SetServiceStatus { .. }
            | Self::SpendUnderMandateToService { .. } => 10_000,
            // Token creation is permissionless-for-a-fee: it records a record,
            // locks a native deposit, and optionally mints — so the anti-spam price
            // is a HIGH ordinary fee (comparable to contract registration).
            Self::CreateToken { .. } => 30_000,
            // Mint/burn/transfer move units on one or two balance records (transfer
            // is the hot path); comparable to a native Transfer plus a record touch.
            Self::MintToken { .. } | Self::BurnToken { .. } | Self::TransferToken { .. } => 1_000,
            // Pause/freeze/thaw/authority rewrite one record or one freeze marker —
            // single-record management operations.
            Self::SetTokenPaused { .. }
            | Self::FreezeTokenAccount { .. }
            | Self::ThawTokenAccount { .. }
            | Self::SetTokenAuthority { .. } => 5_000,
            // NFT collection creation is permissionless-for-a-fee: it records a
            // record and locks a native deposit — the anti-spam price is a HIGH
            // ordinary fee (comparable to token/contract creation).
            Self::CreateNftCollection { .. } => 30_000,
            // Mint/transfer/burn move one item and (for mint/burn) bump one record's
            // counters — comparable to a native token mint/burn/transfer.
            Self::MintNft { .. } | Self::TransferNft { .. } | Self::BurnNft { .. } => 1_000,
            // Pause/freeze/thaw/authority rewrite one collection record or one item —
            // single-record management operations.
            Self::SetNftCollectionPaused { .. }
            | Self::FreezeNftItem { .. }
            | Self::ThawNftItem { .. }
            | Self::SetNftAuthority { .. } => 5_000,
            // Instance creation is permissionless-for-a-fee: it records a record and
            // locks a native deposit — the anti-spam price is a HIGH ordinary fee
            // (comparable to token/collection creation).
            Self::CreateGovernanceInstance { .. } => 30_000,
            // Fund/open move units or write one record and (for open) read a balance;
            // vote/resolve/execute/reclaim each touch a small fixed set of records and
            // (for vote/execute/reclaim) move token or native units — comparable to
            // the other single-record locked-value operations.
            Self::OpenProposal { .. } | Self::ExecuteProposal { .. } => 10_000,
            Self::FundGovernanceTreasury { .. }
            | Self::CastVote { .. }
            | Self::ResolveProposal { .. }
            | Self::ReclaimVote { .. } => 5_000,
            Self::CreateFeed { .. } => 15_000,
            Self::RegisterReporter { .. }
            | Self::DeregisterReporter { .. }
            | Self::PayFeedRead { .. } => 10_000,
            Self::SubmitReport { .. } => 5_000,
            // A submit locks input and writes one order record; a cancel refunds and
            // removes it — comparable to the other single-record locked-value ops.
            // The batch settlement itself is a block-level cost amortized across all
            // orders (§15.13), not charged to a single submit.
            Self::SubmitOrder { .. } | Self::CancelOrder { .. } => 10_000,
            // Registration validates a manifest, writes one record, and burns the
            // fee — comparable to feed creation plus a record write.
            Self::RegisterContract { .. } => 30_000,
            // A contract call's admission cost is ahead-of-time boundable
            // (ADR-0014 §3): a base plus the declared footprint size and input
            // length. This is the fee settled up front; the runtime additionally
            // meters per-host-op consumption against `gas_limit` during execution
            // and hard-stops (fail-closed rollback) if it is exceeded. Saturating
            // arithmetic keeps this panic-free on hostile lengths; the real input
            // bound is enforced at execution.
            Self::InvokeContract {
                input,
                declared_keys,
                ..
            } => {
                let input_units = u64::try_from(input.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(CONTRACT_INPUT_BYTE_UNITS);
                let key_units = u64::try_from(declared_keys.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(CONTRACT_DECLARED_KEY_UNITS);
                CONTRACT_INVOKE_BASE_UNITS
                    .saturating_add(input_units)
                    .saturating_add(key_units)
            }
            // Registration additionally validates and stores the uploaded module,
            // so it is priced by a base plus a per-byte upload term. Saturating
            // arithmetic keeps this panic-free on hostile lengths; the real size
            // bound is enforced at execution.
            Self::RegisterWasmContract { code, .. } => {
                let code_units = u64::try_from(code.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(WASM_CODE_BYTE_UNITS);
                WASM_REGISTER_BASE_UNITS.saturating_add(code_units)
            }
            // A wasm invocation's admission cost mirrors the native invoke: a base
            // plus the declared footprint size and input length. Per-host-op and
            // compute consumption are metered against `gas_limit` at execution and
            // hard-stop (fail-closed rollback) if exceeded.
            Self::InvokeWasmContract {
                input,
                declared_keys,
                ..
            } => {
                let input_units = u64::try_from(input.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(CONTRACT_INPUT_BYTE_UNITS);
                let key_units = u64::try_from(declared_keys.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(CONTRACT_DECLARED_KEY_UNITS);
                CONTRACT_INVOKE_BASE_UNITS
                    .saturating_add(input_units)
                    .saturating_add(key_units)
            }
        }
    }

    /// The application namespace whose LOCALIZED base fee prices this operation.
    ///
    /// Only the object operations (create/mutate/transfer/delete) are
    /// namespace-scoped and therefore priced by their namespace's own localized
    /// base fee (Phase 6 §8 "Application isolation"): they carry object state under
    /// a namespace, and that namespace's congestion should move only its own price.
    /// Every other operation returns `None` and keeps the global base fee — this
    /// includes account-scoped operations like `Transfer`/staking *and* the
    /// sponsor- and namespace-registry management operations, which merely name a
    /// namespace to address a record rather than transacting object state under it.
    pub fn fee_namespace(&self) -> Option<Hash256> {
        match self {
            Self::CreateObject { namespace, .. }
            | Self::MutateObject { namespace, .. }
            | Self::TransferObject { namespace, .. }
            | Self::DeleteObject { namespace, .. } => Some(*namespace),
            _ => None,
        }
    }

    /// Whether this operation may have its fee paid by an application sponsor.
    ///
    /// Fee sponsorship is deliberately restricted to **simple operations** at
    /// launch (§15.35): only a native `Transfer` qualifies. Critical, structural,
    /// staking, bridge, object, and sponsor-management operations are never
    /// sponsorable, so a sponsor budget can only ever underwrite ordinary
    /// user-facing payments. The allowlist is intentionally minimal and can be
    /// widened later with measurement; it is defined in code (not config) so the
    /// set of sponsorable operations is fixed by the protocol, not by a sponsor.
    pub fn is_sponsorable(&self) -> bool {
        matches!(self, Self::Transfer { .. })
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
            }
            | Self::DeleteObject {
                object_id,
                namespace,
                ..
            } => {
                push_unique_key(&mut read_write, StateKey::object(*object_id));
                push_unique_key(
                    &mut read_write,
                    StateKey::application(*namespace, object_id.hash()),
                );
                // Create/mutate/delete lock or release a native storage deposit
                // from the sender's liquid balance, so they also touch the sender
                // account. TransferObject only reassigns ownership and leaves the
                // deposit in place, so it does not declare the account key.
                if matches!(
                    self,
                    Self::CreateObject { .. }
                        | Self::MutateObject { .. }
                        | Self::DeleteObject { .. }
                ) {
                    push_unique_key(&mut read_write, StateKey::account(sender));
                }
            }
            Self::Transfer { to, .. } => {
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::account(*to));
            }
            Self::RegisterValidator { .. }
            | Self::ClaimValidatorRewards
            | Self::CompoundValidatorRewards => {
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
            Self::CompoundDelegatorRewards { validator } => {
                // Same footprint as `Delegate`: the reward is restaked into the
                // position, touching the delegator account, the validator, the
                // delegation record, and the validator's exit queue (its queued
                // operator exit bounds the ratio).
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::validator(*validator));
                push_unique_key(&mut read_write, StateKey::delegation(sender, *validator));
                push_unique_key(&mut read_write, StateKey::unbonding_queue(*validator));
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
            Self::RegisterAppSponsor { namespace, .. }
            | Self::FundAppSponsor { namespace, .. }
            | Self::WithdrawAppSponsor { namespace, .. } => {
                // Sponsor management moves native units between the owner's liquid
                // balance and the app's sponsor budget, so it writes both the
                // sender account and the app's sponsor state key.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(
                    &mut read_write,
                    StateKey::application(*namespace, sponsor_state_key_hash()),
                );
            }
            Self::RegisterNamespace { namespace } | Self::TransferNamespace { namespace, .. } => {
                // The registry claim/transfer only reads and writes the namespace's
                // registry record; it moves no native units, so it does not declare
                // the sender account beyond what the fee lane already covers. The
                // record is domain-separated from object and sponsor state under the
                // same namespace by `namespace_state_key_hash()`.
                push_unique_key(
                    &mut read_write,
                    StateKey::application(*namespace, namespace_state_key_hash()),
                );
            }
            Self::CreateFeed { feed_id } => {
                // Creating a feed burns the creation fee from the sender's liquid
                // balance and writes the new feed-registry record.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::oracle_feed(*feed_id));
            }
            Self::RegisterReporter { feed_id } | Self::DeregisterReporter { feed_id } => {
                // Registering locks the feed's bond from liquid; deregistering
                // returns it. Both read the feed (for its bond/existence) and write
                // the sender's reporter record and account.
                push_unique_key(&mut read_only, StateKey::oracle_feed(*feed_id));
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::oracle_reporter(*feed_id, sender));
            }
            Self::SubmitReport { feed_id, .. } => {
                // Reporting moves no native units (only the ordinary tx fee): it
                // reads the feed for existence and writes the reporter record.
                push_unique_key(&mut read_only, StateKey::oracle_feed(*feed_id));
                push_unique_key(&mut read_write, StateKey::oracle_reporter(*feed_id, sender));
            }
            Self::PayFeedRead { feed_id, .. } => {
                // A read fee moves units from the payer's liquid balance into the
                // feed's revenue pool, so it writes both the account and the feed.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::oracle_feed(*feed_id));
            }
            Self::SubmitOrder {
                order_id,
                pair,
                side,
                ..
            } => {
                // A submit locks the order's input from the sender and writes the new
                // order record. The native fee already touches the sender account
                // (default-lane base). When the locked leg is a NON-native asset, the
                // lock debits that asset balance, so declare it; the locked leg is the
                // quote for a buy and the base for a sell. The block-level batch pass
                // that later fills/refunds the order is not access-list-bound.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::dex_order(*order_id));
                let locked_asset = match side {
                    crate::OrderSide::Buy => &pair.quote,
                    crate::OrderSide::Sell => &pair.base,
                };
                if *locked_asset != AssetId::NativeWebc {
                    push_unique_key(
                        &mut read_write,
                        StateKey::asset_balance(locked_asset.clone(), sender),
                    );
                }
            }
            Self::CancelOrder { order_id } => {
                // Cancel only marks the order for the block-level batch pass (which
                // performs the possibly-non-native refund without an access list),
                // so the transaction itself only writes the sender account (fee) and
                // the order record. Carrying just an order id keeps a cancel's signed
                // access list independent of the order's asset legs.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::dex_order(*order_id));
            }
            Self::RegisterContract { manifest } => {
                // Registration burns the fee from liquid and writes the contract's
                // module (manifest) record. The account key is already in the
                // default-lane base; declare the module record it creates.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::module(manifest.code_id));
            }
            Self::RegisterWasmContract { manifest, .. } => {
                // Identical shape to the native registration: burn the fee and write
                // the module record. Both the wasm manifest and its bytecode are
                // committed under this single reserved module key.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::module(manifest.code_id));
            }
            Self::GrantMandate {
                agent_key,
                grant_nonce,
                ..
            } => {
                // A grant locks the budget from the principal's liquid balance and
                // writes the new mandate record. The mandate id is derived from the
                // signer (principal), the agent key, and the grant nonce, so the
                // access list names the exact record at signing time.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(
                    &mut read_write,
                    StateKey::mandate(MandateId::derive(sender, agent_key, *grant_nonce)),
                );
            }
            Self::TopUpMandate { mandate_id, .. } | Self::RevokeMandate { mandate_id } => {
                // Top-up moves liquid into escrow; revoke returns the remainder to
                // liquid. Both touch the principal account and the mandate record.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::mandate(*mandate_id));
            }
            Self::SpendUnderMandate {
                mandate_id,
                recipient,
                ..
            } => {
                // The sender is the agent; the mandate escrow funds both the
                // principal moved and the fee, so no principal account key is
                // needed. The agent account (default-lane base) carries the spend's
                // nonce/replay state; declare the mandate record and the recipient.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::mandate(*mandate_id));
                push_unique_key(&mut read_write, StateKey::account(*recipient));
            }
            Self::RegisterService {
                namespace,
                create_nonce,
                ..
            } => {
                // Registration records only the service-registry entry and moves no
                // native units (the ordinary, spam-priced fee is drawn from the
                // fee lane, already covered by the default-lane base). The service
                // id is derived from the signer (owner), the namespace, and the
                // create nonce, so the access list names the exact record at signing
                // time (mirroring GrantMandate's derived id).
                push_unique_key(
                    &mut read_write,
                    StateKey::service(ServiceId::derive(*namespace, sender, *create_nonce)),
                );
            }
            Self::UpdateService { service_id, .. } | Self::SetServiceStatus { service_id, .. } => {
                // Update / status change only reads and writes the entry's record;
                // it moves no native units, so it does not declare the sender account
                // beyond the fee lane already covered by the default-lane base.
                push_unique_key(&mut read_write, StateKey::service(*service_id));
            }
            Self::SpendUnderMandateToService {
                mandate_id,
                service_id,
                ..
            } => {
                // The sender is the agent; the mandate escrow funds both the
                // principal moved and the fee. The agent account (default-lane base)
                // carries the spend's nonce/replay state; the mandate record is
                // written and the service entry is read to resolve the pay-to owner.
                // The service OWNER (the registry pay-to) account is state-derived —
                // it is not in the operation — so a caller adds it here via
                // `Transaction::for_service_spend`; the base list below is otherwise
                // complete.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::mandate(*mandate_id));
                push_unique_key(&mut read_only, StateKey::service(*service_id));
            }
            Self::CreateToken {
                namespace,
                create_nonce,
                initial_supply,
                initial_recipient,
                ..
            } => {
                // Creation locks a native deposit from the creator's liquid balance
                // and writes the new token record. The account key is in the
                // default-lane base; declare it explicitly so a non-default fee lane
                // is covered too. When it mints an initial supply, it also writes the
                // recipient's per-account token balance. The token id is derived from
                // the signer (creator), the namespace, and the create nonce, so the
                // access list names the exact record at signing time.
                let token_id = TokenId::derive(*namespace, sender, *create_nonce);
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::token(token_id));
                if !initial_supply.is_zero() {
                    push_unique_key(
                        &mut read_write,
                        StateKey::token_balance(token_id, *initial_recipient),
                    );
                }
            }
            Self::MintToken {
                token_id,
                recipient,
                ..
            } => {
                // Mint raises issued_supply (writes the record) and credits the
                // recipient's per-account token balance. Moves no native units
                // beyond the fee (already covered by the lane base).
                push_unique_key(&mut read_write, StateKey::token(*token_id));
                push_unique_key(
                    &mut read_write,
                    StateKey::token_balance(*token_id, *recipient),
                );
            }
            Self::BurnToken { token_id, .. } => {
                // Burn lowers issued_supply (writes the record) and debits the
                // signer's per-account token balance.
                push_unique_key(&mut read_write, StateKey::token(*token_id));
                push_unique_key(&mut read_write, StateKey::token_balance(*token_id, sender));
            }
            Self::TransferToken {
                token_id,
                recipient,
                ..
            } => {
                // The token record is READ-ONLY (only its paused flag is consulted);
                // the two per-account balance keys are the ONLY writes, so an
                // ordinary transfer never writes a global per-token object (a Phase
                // 13 acceptance criterion). Both parties' freeze markers are declared
                // READS so the parallel scheduler serializes this transfer against a
                // FreezeTokenAccount/ThawTokenAccount of either party — otherwise a
                // transfer and a concurrent freeze of the same account could race
                // (freeze bypass + nondeterministic state root under parallel exec).
                push_unique_key(&mut read_only, StateKey::token(*token_id));
                push_unique_key(&mut read_write, StateKey::token_balance(*token_id, sender));
                push_unique_key(
                    &mut read_write,
                    StateKey::token_balance(*token_id, *recipient),
                );
                push_unique_key(&mut read_only, StateKey::token_freeze(*token_id, sender));
                push_unique_key(
                    &mut read_only,
                    StateKey::token_freeze(*token_id, *recipient),
                );
            }
            Self::SetTokenPaused { token_id, .. } | Self::SetTokenAuthority { token_id, .. } => {
                // Pause / authority change rewrite one token record; move no native
                // units, so they declare only the record beyond the fee lane base.
                push_unique_key(&mut read_write, StateKey::token(*token_id));
            }
            Self::FreezeTokenAccount { token_id, account }
            | Self::ThawTokenAccount { token_id, account } => {
                // The record is read to check the freeze authority; the freeze marker
                // is the only write. Freezing moves no native units.
                push_unique_key(&mut read_only, StateKey::token(*token_id));
                push_unique_key(&mut read_write, StateKey::token_freeze(*token_id, *account));
            }
            Self::CreateNftCollection {
                namespace,
                create_nonce,
                ..
            } => {
                // Creation locks a native deposit from the creator's liquid balance
                // and writes the new collection record. The account key is in the
                // default-lane base; declare it explicitly so a non-default fee lane
                // is covered too. It mints no item, so no item key is written. The
                // collection id is derived from the signer (creator), the namespace,
                // and the create nonce, so the access list names the exact record at
                // signing time (mirrors CreateToken/CreateObject).
                let collection_id = NftCollectionId::derive(*namespace, sender, *create_nonce);
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::nft_collection(collection_id));
            }
            Self::MintNft { collection_id, .. } => {
                // A mint bumps `next_serial`/`minted_count` (writes the collection
                // record) and creates ONE brand-new item at the chain-assigned
                // `serial = next_serial`. That serial is state-dependent and NOT known
                // at signing time, so the new item key cannot be pre-declared. This is
                // safe because the collection record is declared READ_WRITE: every
                // mint of a collection therefore serializes on it, so two mints can
                // never race on the fresh serial, and any later op that references the
                // item (transfer/burn/freeze/thaw — which DO read/write the collection
                // record) is serialized after the mint. The fresh item is thus created
                // under the collection record's write scope; see the matching handler
                // note in `state.rs`.
                push_unique_key(&mut read_write, StateKey::nft_collection(*collection_id));
            }
            Self::TransferNft {
                collection_id,
                serial,
                ..
            } => {
                // The collection record is READ-ONLY (only its paused flag is
                // consulted); the single item key is the ONLY write, so an ordinary
                // transfer never writes a global per-collection object (a Phase 13
                // acceptance criterion). The item's `frozen` flag lives ON the item
                // record we already write, so it needs no separate declaration — the
                // read_write item key covers both the owner/frozen reads and the
                // ownership write, and the read-only collection key covers the paused
                // read.
                push_unique_key(&mut read_only, StateKey::nft_collection(*collection_id));
                push_unique_key(&mut read_write, StateKey::nft_item(*collection_id, *serial));
            }
            Self::BurnNft {
                collection_id,
                serial,
            } => {
                // A burn removes the item (writes the item key) and bumps
                // `burned_count` (writes the collection record). The owner and frozen
                // checks read the item key we already write.
                push_unique_key(&mut read_write, StateKey::nft_collection(*collection_id));
                push_unique_key(&mut read_write, StateKey::nft_item(*collection_id, *serial));
            }
            Self::SetNftCollectionPaused { collection_id, .. }
            | Self::SetNftAuthority { collection_id, .. } => {
                // Pause / authority change rewrite one collection record; move no
                // native units, so they declare only the record beyond the fee lane
                // base.
                push_unique_key(&mut read_write, StateKey::nft_collection(*collection_id));
            }
            Self::FreezeNftItem {
                collection_id,
                serial,
            }
            | Self::ThawNftItem {
                collection_id,
                serial,
            } => {
                // The collection record is read to check the freeze authority; the
                // item's `frozen` flag is the only write. Freezing moves no native
                // units.
                push_unique_key(&mut read_only, StateKey::nft_collection(*collection_id));
                push_unique_key(&mut read_write, StateKey::nft_item(*collection_id, *serial));
            }
            Self::CreateGovernanceInstance {
                namespace,
                create_nonce,
                weight_token,
                ..
            } => {
                // Creation locks a native deposit from the creator's liquid balance
                // and writes the new instance record; the weight token is read to
                // confirm it exists. The instance id is derived from the signer
                // (creator), the namespace, and the create nonce, so the access list
                // names the exact record at signing time (mirrors CreateToken).
                let instance_id = GovernanceInstanceId::derive(*namespace, sender, *create_nonce);
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::governance_instance(instance_id));
                push_unique_key(&mut read_only, StateKey::token(*weight_token));
            }
            Self::FundGovernanceTreasury { instance_id, .. } => {
                // Fund moves native units from the funder's liquid balance into the
                // instance treasury, so it writes both the funder account and the
                // instance record.
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::governance_instance(*instance_id));
            }
            Self::OpenProposal { instance_id, .. } => {
                // Open bumps the instance's proposal nonce (writes the instance
                // record) and creates ONE brand-new proposal at the chain-assigned
                // nonce. That proposal id is state-dependent and NOT known at signing
                // time, so the new proposal key cannot be pre-declared; it is created
                // under the instance record's WRITE scope (mirrors MintNft's fresh
                // serial). The proposer's weight-token balance is read to check the
                // proposal threshold — the weight token is state-derived (it lives on
                // the instance record), so a caller adds that balance key via
                // `Transaction::for_open_proposal`; the base list below is otherwise
                // complete.
                push_unique_key(&mut read_write, StateKey::governance_instance(*instance_id));
            }
            Self::CastVote { proposal_id, .. } => {
                // A vote writes the proposal tally and the voter's lock record. It
                // also LOCKS weight-token units by moving them from the voter to the
                // proposal escrow and reads the token's paused flag and both parties'
                // freeze markers — exactly the freeze/pause reads a TransferToken
                // declares. Those token keys need the weight token, which is
                // state-derived (it lives on the proposal record), so a caller adds
                // them via `Transaction::for_cast_vote`; the base list below is
                // otherwise complete.
                push_unique_key(&mut read_write, StateKey::governance_proposal(*proposal_id));
                push_unique_key(
                    &mut read_write,
                    StateKey::governance_vote(*proposal_id, sender),
                );
            }
            Self::ResolveProposal { proposal_id } => {
                // Resolve writes the proposal (status/eta) and reads the weight
                // token's issued supply for the quorum denominator. The token key
                // needs the weight token, which is state-derived (it lives on the
                // proposal record), so a caller adds it via
                // `Transaction::for_resolve_proposal`; the base list below is
                // otherwise complete.
                push_unique_key(&mut read_write, StateKey::governance_proposal(*proposal_id));
            }
            Self::ExecuteProposal { proposal_id } => {
                // Execute writes the proposal (status). A TreasuryTransfer payout also
                // writes the instance record (treasury) and credits the recipient
                // account — both state-derived (they come from the stored proposal),
                // so a caller adds them via `Transaction::for_execute_proposal`; the
                // base list below is otherwise complete (a Signaling proposal needs no
                // extra keys).
                push_unique_key(&mut read_write, StateKey::governance_proposal(*proposal_id));
            }
            Self::ReclaimVote { proposal_id } => {
                // Reclaim reads the proposal (resolved status) and writes the voter's
                // lock record, and moves the locked weight-token units back from the
                // proposal escrow to the voter. Those two token-balance keys need the
                // weight token, which is state-derived (it lives on the proposal
                // record), so a caller adds them via `Transaction::for_reclaim_vote`;
                // the base list below is otherwise complete.
                push_unique_key(&mut read_only, StateKey::governance_proposal(*proposal_id));
                push_unique_key(
                    &mut read_write,
                    StateKey::governance_vote(*proposal_id, sender),
                );
            }
            Self::InvokeContract {
                code_id,
                namespace,
                declared_keys,
                ..
            } => {
                // The manifest record is read to resolve and bind the contract;
                // the declared footprint keys (which must equal the manifest's) are
                // the contract's application state, declared read_write so the
                // signed access list and the scheduler agree with the manifest.
                // The example contract moves no native value, so no extra account
                // key beyond the default-lane fee source is required.
                push_unique_key(&mut read_only, StateKey::module(*code_id));
                for key_hash in declared_keys {
                    push_unique_key(
                        &mut read_write,
                        StateKey::application(*namespace, *key_hash),
                    );
                }
            }
            Self::InvokeWasmContract {
                code_id,
                namespace,
                declared_keys,
                ..
            } => {
                // Same access shape as the native invoke: read the module record to
                // resolve the contract, and declare its footprint keys read_write so
                // the signed access list and the scheduler agree with the manifest.
                // The module bytecode is committed under the same module key and is
                // immutable, so it needs no separate declared key.
                push_unique_key(&mut read_only, StateKey::module(*code_id));
                for key_hash in declared_keys {
                    push_unique_key(
                        &mut read_write,
                        StateKey::application(*namespace, *key_hash),
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

// `Serialize` is implemented manually (below) so the optional `sponsor` field is
// omitted in the self-describing (JSON) encoding when absent — keeping every
// non-sponsored transaction byte-identical to the pre-sponsorship struct — while
// always being written in the non-self-describing binary codec (bincode), where a
// skipped field would desynchronize positional decoding. `Deserialize` stays
// derived: `#[serde(default)]` restores `None` from an absent JSON field, and the
// binary codec always carries the field.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
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
    /// Optional sponsoring application namespace (fee sponsorship, §15.35).
    ///
    /// When `Some(namespace)`, the sender opts into having that application's
    /// pre-funded sponsor budget pay this transaction's fee, subject to hard
    /// per-user / per-operation / per-app-per-day caps and the simple-operation
    /// restriction ([`Operation::is_sponsorable`]). Sponsorship is **best-effort
    /// (fail-open)**: if any cap or the budget does not permit it — or the
    /// operation is not sponsorable — the sender pays normally, never more than
    /// the fee already authorized by `fee`. Must use the default authorization
    /// lane.
    ///
    /// `None` is the default and is **omitted from the wire**, so every existing
    /// (non-sponsored) transaction serializes byte-for-byte as before and the
    /// frozen `WEBC_SIGNED_TRANSACTION_V4` signing vectors are unchanged. The
    /// field is a purely additive, backward-compatible superset of V4.
    ///
    /// It is declared **last** so the manual [`Serialize`] impl can append it
    /// only for the JSON encoding when present. `#[serde(default)]` restores
    /// `None` when an absent JSON field is decoded; the binary codec always
    /// carries the field, so positional decoding never desynchronizes.
    #[serde(default)]
    pub sponsor: Option<Hash256>,
}

impl Serialize for Transaction {
    /// Serializes a transaction, omitting an absent `sponsor` in JSON only.
    ///
    /// In a self-describing encoding (JSON — the signing/hashing and cross-language
    /// path) a `None` sponsor is omitted, so a non-sponsored transaction is
    /// byte-identical to the pre-sponsorship struct and the frozen
    /// `WEBC_SIGNED_TRANSACTION_V4` vectors, the transaction hash, and the browser
    /// SDK are all unchanged. In a non-self-describing binary codec (bincode, used
    /// to gossip transactions on the network wire) the field is ALWAYS written,
    /// because skipping any field there would misalign every field decoded after
    /// it. Field order matches the struct declaration so the derived
    /// `Deserialize` reads binary fields positionally.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let omit_sponsor = serializer.is_human_readable() && self.sponsor.is_none();
        let field_count = if omit_sponsor { 11 } else { 12 };
        let mut state = serializer.serialize_struct("Transaction", field_count)?;
        state.serialize_field("protocol_version", &self.protocol_version)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.serialize_field("sender", &self.sender)?;
        state.serialize_field("public_key", &self.public_key)?;
        state.serialize_field("authorization_lane", &self.authorization_lane)?;
        state.serialize_field(
            "authorization_policy_revision",
            &self.authorization_policy_revision,
        )?;
        state.serialize_field("nonce", &self.nonce)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("access_list", &self.access_list)?;
        state.serialize_field("fee", &self.fee)?;
        state.serialize_field("signature", &self.signature)?;
        if omit_sponsor {
            state.skip_field("sponsor")?;
        } else {
            state.serialize_field("sponsor", &self.sponsor)?;
        }
        state.end()
    }
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
            sponsor: None,
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

    /// Builds access (including the sponsor state key), opts into fee sponsorship
    /// by `sponsor_namespace`, and signs for the devnet chain's default lane.
    ///
    /// Sponsorship is best-effort and applies only on the default lane and only
    /// to sponsorable operations; the runtime enforces the hard caps and falls
    /// open to normal self-payment when they do not permit it. The returned
    /// access list is a superset covering both the sponsored and the self-pay
    /// execution paths, so neither path can trigger an undeclared/unused
    /// access-list failure.
    pub fn for_sponsored_operation(
        keypair: &Keypair,
        nonce: u64,
        operation: Operation,
        fee: FeeBid,
        sponsor_namespace: Hash256,
    ) -> Result<Self, ChainError> {
        let sender = keypair.address();
        let mut access_list =
            operation.default_access_list_for_lane(sender, AuthorizationLaneId::DEFAULT)?;
        push_unique_key(
            &mut access_list.read_write,
            StateKey::application(sponsor_namespace, sponsor_state_key_hash()),
        );
        let mut tx = Self::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            sender,
            keypair.public_key(),
            AuthorizationLaneId::DEFAULT,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            nonce,
            operation,
            access_list,
            fee,
        );
        tx.sponsor = Some(sponsor_namespace);
        tx.sign(keypair)?;
        Ok(tx)
    }

    /// Builds and signs a mandate spend that pays a registered service's owner
    /// (Phase 9b, §15.5).
    ///
    /// The service `owner` (the registry pay-to account) is state-derived, so the
    /// pure default access list cannot name it; the agent resolves it by reading
    /// the on-chain service entry — the same pay-to check the HTTP-402 flow
    /// performs — and passes it here so the signed access list declares the
    /// credited account. If the owner changes on-chain before this lands, the spend
    /// fails closed on the access-list mismatch, exactly like a stale recipient in
    /// [`Operation::SpendUnderMandate`]. Signs for the devnet chain's default lane;
    /// the signer is the mandate's agent key.
    pub fn for_service_spend(
        agent_keypair: &Keypair,
        nonce: u64,
        mandate_id: MandateId,
        service_id: ServiceId,
        amount: Amount,
        service_owner: Address,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        let operation = Operation::SpendUnderMandateToService {
            mandate_id,
            service_id,
            amount,
        };
        let sender = agent_keypair.address();
        let mut access_list =
            operation.default_access_list_for_lane(sender, AuthorizationLaneId::DEFAULT)?;
        push_unique_key(
            &mut access_list.read_write,
            StateKey::account(service_owner),
        );
        let mut tx = Self::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            sender,
            agent_keypair.public_key(),
            AuthorizationLaneId::DEFAULT,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            nonce,
            operation,
            access_list,
            fee,
        );
        tx.sign(agent_keypair)?;
        Ok(tx)
    }

    /// Builds and signs an [`Operation::OpenProposal`] on the devnet default lane
    /// (Phase 13c, §15).
    ///
    /// The proposer's weight-token balance key is state-derived (the weight token
    /// lives on the instance record, not in the operation), so the caller resolves
    /// `weight_token` from the on-chain instance and passes it here; this builder
    /// adds `token_balance(weight_token, proposer)` as a read so the signed access
    /// list exactly equals what the handler touches. A stale `weight_token` fails
    /// closed on the access-list mismatch.
    pub fn for_open_proposal(
        keypair: &Keypair,
        nonce: u64,
        instance_id: GovernanceInstanceId,
        action: GovernanceAction,
        weight_token: TokenId,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        let sender = keypair.address();
        let operation = Operation::OpenProposal {
            instance_id,
            action,
        };
        let mut access_list =
            operation.default_access_list_for_lane(sender, AuthorizationLaneId::DEFAULT)?;
        push_unique_key(
            &mut access_list.read_only,
            StateKey::token_balance(weight_token, sender),
        );
        let mut tx = Self::new_unsigned_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            sender,
            keypair.public_key(),
            nonce,
            operation,
            access_list,
            fee,
        );
        tx.sign(keypair)?;
        Ok(tx)
    }

    /// Builds and signs an [`Operation::CastVote`] on the devnet default lane
    /// (Phase 13c, §15).
    ///
    /// The lock moves weight-token units from the voter to the proposal escrow, so
    /// the signed access list must name the token record (paused read), both freeze
    /// markers (voter + escrow), and both balance keys. The weight token is
    /// state-derived (it lives on the proposal record), so the caller resolves it
    /// and passes it here; a stale `weight_token` fails closed on the access-list
    /// mismatch.
    pub fn for_cast_vote(
        keypair: &Keypair,
        nonce: u64,
        proposal_id: ProposalId,
        choice: VoteChoice,
        weight_amount: Amount,
        weight_token: TokenId,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        let sender = keypair.address();
        let escrow = crate::gov_vote_escrow_address(proposal_id);
        let operation = Operation::CastVote {
            proposal_id,
            choice,
            weight_amount,
        };
        let mut access_list =
            operation.default_access_list_for_lane(sender, AuthorizationLaneId::DEFAULT)?;
        push_unique_key(&mut access_list.read_only, StateKey::token(weight_token));
        push_unique_key(
            &mut access_list.read_only,
            StateKey::token_freeze(weight_token, sender),
        );
        push_unique_key(
            &mut access_list.read_only,
            StateKey::token_freeze(weight_token, escrow),
        );
        push_unique_key(
            &mut access_list.read_write,
            StateKey::token_balance(weight_token, sender),
        );
        push_unique_key(
            &mut access_list.read_write,
            StateKey::token_balance(weight_token, escrow),
        );
        let mut tx = Self::new_unsigned_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            sender,
            keypair.public_key(),
            nonce,
            operation,
            access_list,
            fee,
        );
        tx.sign(keypair)?;
        Ok(tx)
    }

    /// Builds and signs an [`Operation::ResolveProposal`] on the devnet default lane
    /// (Phase 13c, §15).
    ///
    /// Resolve reads the weight token's issued supply for the quorum denominator;
    /// the token key is state-derived (the weight token lives on the proposal
    /// record), so the caller resolves it and passes it here.
    pub fn for_resolve_proposal(
        keypair: &Keypair,
        nonce: u64,
        proposal_id: ProposalId,
        weight_token: TokenId,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        let sender = keypair.address();
        let operation = Operation::ResolveProposal { proposal_id };
        let mut access_list =
            operation.default_access_list_for_lane(sender, AuthorizationLaneId::DEFAULT)?;
        push_unique_key(&mut access_list.read_only, StateKey::token(weight_token));
        let mut tx = Self::new_unsigned_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            sender,
            keypair.public_key(),
            nonce,
            operation,
            access_list,
            fee,
        );
        tx.sign(keypair)?;
        Ok(tx)
    }

    /// Builds and signs an [`Operation::ExecuteProposal`] on the devnet default lane
    /// (Phase 13c, §15).
    ///
    /// A [`GovernanceAction::TreasuryTransfer`] payout writes the instance record
    /// (treasury) and credits the recipient — both state-derived from the stored
    /// proposal — so the caller resolves them and passes `payout =
    /// Some((instance_id, recipient))`; a [`GovernanceAction::Signaling`] proposal
    /// needs no extra keys (`payout = None`). A mismatch with the stored action fails
    /// closed on the access-list check.
    pub fn for_execute_proposal(
        keypair: &Keypair,
        nonce: u64,
        proposal_id: ProposalId,
        payout: Option<(GovernanceInstanceId, Address)>,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        let sender = keypair.address();
        let operation = Operation::ExecuteProposal { proposal_id };
        let mut access_list =
            operation.default_access_list_for_lane(sender, AuthorizationLaneId::DEFAULT)?;
        if let Some((instance_id, recipient)) = payout {
            push_unique_key(
                &mut access_list.read_write,
                StateKey::governance_instance(instance_id),
            );
            push_unique_key(&mut access_list.read_write, StateKey::account(recipient));
        }
        let mut tx = Self::new_unsigned_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            sender,
            keypair.public_key(),
            nonce,
            operation,
            access_list,
            fee,
        );
        tx.sign(keypair)?;
        Ok(tx)
    }

    /// Builds and signs an [`Operation::ReclaimVote`] on the devnet default lane
    /// (Phase 13c, §15).
    ///
    /// Reclaim moves the locked weight-token units from the proposal escrow back to
    /// the voter, so the signed access list must name both balance keys. The weight
    /// token is state-derived (it lives on the proposal record), so the caller
    /// resolves it and passes it here.
    pub fn for_reclaim_vote(
        keypair: &Keypair,
        nonce: u64,
        proposal_id: ProposalId,
        weight_token: TokenId,
        fee: FeeBid,
    ) -> Result<Self, ChainError> {
        let sender = keypair.address();
        let escrow = crate::gov_vote_escrow_address(proposal_id);
        let operation = Operation::ReclaimVote { proposal_id };
        let mut access_list =
            operation.default_access_list_for_lane(sender, AuthorizationLaneId::DEFAULT)?;
        push_unique_key(
            &mut access_list.read_write,
            StateKey::token_balance(weight_token, escrow),
        );
        push_unique_key(
            &mut access_list.read_write,
            StateKey::token_balance(weight_token, sender),
        );
        let mut tx = Self::new_unsigned_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            sender,
            keypair.public_key(),
            nonce,
            operation,
            access_list,
            fee,
        );
        tx.sign(keypair)?;
        Ok(tx)
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
        // `sponsor` is skipped when `None`, so a non-sponsored transaction's
        // signing payload is byte-identical to the frozen V4 vectors; a sponsored
        // transaction adds exactly one `sponsor` key. The signed field binds the
        // sponsor choice to the sender's signature.
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
            #[serde(skip_serializing_if = "Option::is_none")]
            sponsor: Option<Hash256>,
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
            sponsor: self.sponsor,
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
            #[serde(skip_serializing_if = "Option::is_none")]
            sponsor: Option<Hash256>,
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
            sponsor: tx.sponsor,
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
    fn operation_rejects_unknown_variant_fields() {
        // T1: struct-variant decode is strict, matching AccessList/FeeBid/
        // Transaction. Pre-fix, serde silently ignored the extra field.
        let op = Operation::Transfer {
            to: Keypair::from_seed([3u8; 32]).address(),
            amount: Amount::from_units(1),
        };
        let mut value = serde_json::to_value(&op).expect("serializes");
        value["Transfer"]["unexpected"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<Operation>(value).is_err(),
            "unknown variant field must be rejected"
        );
    }

    #[test]
    fn bridge_lock_recipient_is_bounded_before_decode() {
        // B1: the bridge recipient uses the bounded codec, so an over-length
        // hex string is rejected before allocation.
        let op = Operation::BridgeLock {
            asset: AssetId::NativeWebc,
            destination_chain: ExternalChain::Ethereum,
            recipient: vec![0xab, 0xcd],
            amount: Amount::from_units(4),
        };
        let mut value = serde_json::to_value(&op).expect("serializes");
        value["BridgeLock"]["recipient"] =
            serde_json::Value::String("ab".repeat(crate::bridge::MAX_BRIDGE_RECIPIENT_BYTES + 1));
        assert!(serde_json::from_value::<Operation>(value).is_err());
    }

    #[test]
    fn delete_object_operation_has_a_stable_wire_vector() {
        // Pins the canonical JSON shape of the storage-deposit DeleteObject
        // operation (§15.22) so a browser SDK mirror must reproduce these exact
        // field names and sorted-key order. Adding this variant leaves the frozen
        // `every_native_operation_...` cross-language vector untouched, because
        // serde tags variants by name and existing variants are unchanged.
        let operation = Operation::DeleteObject {
            object_id: ObjectId::new(Hash256([0x33; 32])),
            namespace: Hash256([0x55; 32]),
            expected_version: ObjectVersion::new(4),
        };
        let canonical =
            crate::canonical::canonical_json_string(&operation).expect("delete object serializes");
        let expected = format!(
            r#"{{"DeleteObject":{{"expected_version":4,"namespace":"{ns}","object_id":"{id}"}}}}"#,
            ns = "55".repeat(32),
            id = "33".repeat(32),
        );
        assert_eq!(canonical, expected);

        // The decode is strict (deny_unknown_fields), matching its sibling ops.
        let mut value = serde_json::to_value(&operation).expect("serializes");
        value["DeleteObject"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
    }

    #[test]
    fn sponsor_management_operations_have_stable_wire_vectors() {
        // Pins the canonical JSON of the three sponsor-management operations
        // (§15.35) so a browser SDK mirror must reproduce these exact field names
        // and sorted-key order. Adding these variants leaves the frozen
        // `every_native_operation_...` cross-language vector untouched (serde tags
        // variants by name; existing variants are unchanged).
        let namespace = Hash256([0x55; 32]);
        let register = Operation::RegisterAppSponsor {
            namespace,
            daily_budget_cap: Amount::from_units(50_000),
            initial_funding: Amount::from_units(100_000),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&register).unwrap(),
            format!(
                r#"{{"RegisterAppSponsor":{{"daily_budget_cap":"50000","initial_funding":"100000","namespace":"{ns}"}}}}"#,
                ns = "55".repeat(32),
            )
        );
        let fund = Operation::FundAppSponsor {
            namespace,
            amount: Amount::from_units(7),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&fund).unwrap(),
            format!(
                r#"{{"FundAppSponsor":{{"amount":"7","namespace":"{ns}"}}}}"#,
                ns = "55".repeat(32),
            )
        );
        let withdraw = Operation::WithdrawAppSponsor {
            namespace,
            amount: Amount::from_units(9),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&withdraw).unwrap(),
            format!(
                r#"{{"WithdrawAppSponsor":{{"amount":"9","namespace":"{ns}"}}}}"#,
                ns = "55".repeat(32),
            )
        );

        // The decode is strict (deny_unknown_fields), matching sibling operations.
        let mut value = serde_json::to_value(&register).unwrap();
        value["RegisterAppSponsor"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
    }

    #[test]
    fn namespace_registry_operations_have_stable_wire_vectors() {
        // Pins the canonical JSON of the two namespace-registry operations (§8
        // application isolation) so a browser SDK mirror must reproduce these exact
        // field names and sorted-key order. Adding these variants leaves the frozen
        // `every_native_operation_...` cross-language vector untouched (serde tags
        // variants by name; existing variants are unchanged).
        let namespace = Hash256([0x55; 32]);
        let new_owner = Keypair::from_seed([2u8; 32]).address();
        let register = Operation::RegisterNamespace { namespace };
        assert_eq!(
            crate::canonical::canonical_json_string(&register).unwrap(),
            format!(
                r#"{{"RegisterNamespace":{{"namespace":"{ns}"}}}}"#,
                ns = "55".repeat(32),
            )
        );
        let transfer = Operation::TransferNamespace {
            namespace,
            new_owner,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&transfer).unwrap(),
            format!(
                r#"{{"TransferNamespace":{{"namespace":"{ns}","new_owner":"{owner}"}}}}"#,
                ns = "55".repeat(32),
                owner = new_owner.to_base58(),
            )
        );

        // The decode is strict (deny_unknown_fields), matching sibling operations.
        let mut value = serde_json::to_value(&register).unwrap();
        value["RegisterNamespace"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
    }

    #[test]
    fn oracle_operations_have_stable_wire_vectors() {
        // Pins the canonical JSON of the five native-oracle operations (Phase 7,
        // §15.17) so a browser SDK mirror must reproduce these exact field names
        // and sorted-key order. Adding these variants leaves the frozen
        // `every_native_operation_...` cross-language vector untouched (serde tags
        // variants by name; existing variants are unchanged). Note the feed value
        // is a decimal STRING (like Amount), never a bare JSON number.
        let feed_id = crate::FeedId::new(Hash256([0x88; 32]));
        let id = "88".repeat(32);
        let create = Operation::CreateFeed { feed_id };
        assert_eq!(
            crate::canonical::canonical_json_string(&create).unwrap(),
            format!(r#"{{"CreateFeed":{{"feed_id":"{id}"}}}}"#),
        );
        let register = Operation::RegisterReporter { feed_id };
        assert_eq!(
            crate::canonical::canonical_json_string(&register).unwrap(),
            format!(r#"{{"RegisterReporter":{{"feed_id":"{id}"}}}}"#),
        );
        let deregister = Operation::DeregisterReporter { feed_id };
        assert_eq!(
            crate::canonical::canonical_json_string(&deregister).unwrap(),
            format!(r#"{{"DeregisterReporter":{{"feed_id":"{id}"}}}}"#),
        );
        let report = Operation::SubmitReport {
            feed_id,
            value: crate::FeedValue::new(-123_456_789_012_345),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&report).unwrap(),
            format!(r#"{{"SubmitReport":{{"feed_id":"{id}","value":"-123456789012345"}}}}"#),
        );
        let pay = Operation::PayFeedRead {
            feed_id,
            amount: Amount::from_units(42),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&pay).unwrap(),
            format!(r#"{{"PayFeedRead":{{"amount":"42","feed_id":"{id}"}}}}"#),
        );

        // The decode is strict (deny_unknown_fields), matching sibling operations.
        let mut value = serde_json::to_value(&create).unwrap();
        value["CreateFeed"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
    }

    #[test]
    fn mandate_operations_have_stable_wire_vectors() {
        // Pins the canonical JSON of the four agent-mandate operations (Phase 9a,
        // §15.32) so a browser SDK mirror must reproduce these exact field names
        // and sorted-key order. Adding these variants leaves the frozen
        // `every_native_operation_...` cross-language vector untouched (serde tags
        // variants by name; existing variants are unchanged). Amounts are decimal
        // STRINGS (like Amount), never bare JSON numbers.
        let mandate_id = crate::MandateId::new(Hash256([0x88; 32]));
        let id = "88".repeat(32);
        let agent = Keypair::from_seed([9u8; 32]).public_key();
        let recipient = Keypair::from_seed([2u8; 32]).address();

        // GrantMandate carries an enum policy, so round-trip it rather than pin a
        // large fixed string; the simpler three are pinned exactly below.
        let grant = Operation::GrantMandate {
            agent_key: agent,
            grant_nonce: 3,
            budget_total: Amount::from_units(1_000),
            expiry_epoch: Epoch::new(100),
            per_tx_max: Amount::from_units(100),
            rate_limit_per_day: 5,
            counterparty_policy: MandateCounterpartyPolicy::Open,
        };
        let text = serde_json::to_string(&grant).expect("grant serializes");
        assert_eq!(serde_json::from_str::<Operation>(&text).unwrap(), grant);

        let top_up = Operation::TopUpMandate {
            mandate_id,
            amount: Amount::from_units(5),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&top_up).unwrap(),
            format!(r#"{{"TopUpMandate":{{"amount":"5","mandate_id":"{id}"}}}}"#),
        );
        let spend = Operation::SpendUnderMandate {
            mandate_id,
            recipient,
            amount: Amount::from_units(7),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&spend).unwrap(),
            format!(
                r#"{{"SpendUnderMandate":{{"amount":"7","mandate_id":"{id}","recipient":"{rec}"}}}}"#,
                rec = recipient.to_base58(),
            )
        );
        let revoke = Operation::RevokeMandate { mandate_id };
        assert_eq!(
            crate::canonical::canonical_json_string(&revoke).unwrap(),
            format!(r#"{{"RevokeMandate":{{"mandate_id":"{id}"}}}}"#),
        );

        // The decode is strict (deny_unknown_fields), matching sibling operations.
        let mut value = serde_json::to_value(&revoke).unwrap();
        value["RevokeMandate"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
    }

    #[test]
    fn service_registry_operations_have_stable_wire_vectors() {
        // Pins the canonical JSON of the four service-registry operations (Phase 9b,
        // §15.5) so a browser SDK mirror must reproduce these exact field names and
        // sorted-key order. Adding these variants leaves the frozen
        // `every_native_operation_...` cross-language vector untouched (serde tags
        // variants by name; existing variants are unchanged). Byte-string fields are
        // lowercase hex (like bridge addresses); amounts are decimal STRINGS.
        use std::collections::BTreeSet;
        let namespace = Hash256([0x55; 32]);
        let interface = Hash256([0x1f; 32]);
        let service_id = ServiceId::new(Hash256([0x88; 32]));
        let id = "88".repeat(32);
        let mut categories = BTreeSet::new();
        categories.insert(Hash256([0xc1; 32]));
        let pricing = vec![ServicePrice {
            operation: Hash256([0x0b; 32]),
            price: Amount::from_units(1_000),
            unit: b"call".to_vec(),
        }];
        let payment_flags = ServicePaymentFlags {
            on_chain_direct: true,
            http_402: false,
            subscription: false,
        };

        // RegisterService / UpdateService carry sets, lists, and bounded byte
        // strings, so round-trip them rather than pin a large fixed string; the two
        // simpler ops are pinned exactly below.
        let register = Operation::RegisterService {
            namespace,
            create_nonce: 7,
            categories: categories.clone(),
            title: b"inference".to_vec(),
            endpoint: b"https://api.example/infer".to_vec(),
            interface,
            pricing: pricing.clone(),
            payment_flags,
        };
        let text = serde_json::to_string(&register).expect("register serializes");
        assert_eq!(serde_json::from_str::<Operation>(&text).unwrap(), register);
        // The title field is lowercase hex on the wire ("inference" = 696e...).
        assert!(text.contains(&format!("\"title\":\"{}\"", hex::encode("inference"))));

        let update = Operation::UpdateService {
            service_id,
            categories,
            title: b"inference-v2".to_vec(),
            endpoint: b"https://api.example/infer".to_vec(),
            interface,
            pricing,
            payment_flags,
        };
        let text = serde_json::to_string(&update).expect("update serializes");
        assert_eq!(serde_json::from_str::<Operation>(&text).unwrap(), update);

        let set_status = Operation::SetServiceStatus {
            service_id,
            status: ServiceStatus::Paused,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&set_status).unwrap(),
            format!(r#"{{"SetServiceStatus":{{"service_id":"{id}","status":"Paused"}}}}"#),
        );

        let spend = Operation::SpendUnderMandateToService {
            mandate_id: MandateId::new(Hash256([0x99; 32])),
            service_id,
            amount: Amount::from_units(7),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&spend).unwrap(),
            format!(
                r#"{{"SpendUnderMandateToService":{{"amount":"7","mandate_id":"{mid}","service_id":"{id}"}}}}"#,
                mid = "99".repeat(32),
            )
        );

        // The decode is strict (deny_unknown_fields), matching sibling operations.
        // The bounded hex codec additionally rejects an over-length title.
        let mut value = serde_json::to_value(&set_status).unwrap();
        value["SetServiceStatus"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
        let mut value = serde_json::to_value(&register).unwrap();
        value["RegisterService"]["title"] = serde_json::Value::String(
            "61".repeat(crate::service_registry::MAX_SERVICE_TITLE_BYTES + 1),
        );
        assert!(serde_json::from_value::<Operation>(value).is_err());
    }

    #[test]
    fn token_operations_have_stable_wire_vectors() {
        // Pins the canonical JSON of the native token operations (Phase 13a, §15) so
        // a browser SDK mirror must reproduce these exact field names and sorted-key
        // order. Adding these variants leaves the frozen `every_native_operation_...`
        // cross-language vector untouched (serde tags variants by name; existing
        // variants are unchanged). Byte-string fields are lowercase hex; amounts are
        // decimal STRINGS; addresses are base58; an Option is the address or null.
        let token_id = TokenId::new(Hash256([0x88; 32]));
        let id = "88".repeat(32);
        let recipient = Keypair::from_seed([9u8; 32]).address();
        let rcpt = recipient.to_base58();
        let account = Keypair::from_seed([10u8; 32]).address();
        let acct = account.to_base58();

        // CreateToken carries the nested TokenMetadata struct, so round-trip it and
        // confirm the metadata name is lowercase hex on the wire.
        let create = Operation::CreateToken {
            namespace: Hash256([0x55; 32]),
            create_nonce: 7,
            metadata: TokenMetadata::new(
                b"Acme Dollar".to_vec(),
                b"ACME".to_vec(),
                6,
                Hash256([0x1f; 32]),
            )
            .expect("valid metadata"),
            mint_authority: Some(recipient),
            freeze_authority: None,
            initial_supply: Amount::from_units(1_000),
            initial_recipient: recipient,
        };
        let text = serde_json::to_string(&create).expect("create serializes");
        assert_eq!(serde_json::from_str::<Operation>(&text).unwrap(), create);
        assert!(text.contains(&format!("\"name\":\"{}\"", hex::encode("Acme Dollar"))));

        let mint = Operation::MintToken {
            token_id,
            recipient,
            amount: Amount::from_units(7),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&mint).unwrap(),
            format!(r#"{{"MintToken":{{"amount":"7","recipient":"{rcpt}","token_id":"{id}"}}}}"#),
        );

        let burn = Operation::BurnToken {
            token_id,
            amount: Amount::from_units(3),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&burn).unwrap(),
            format!(r#"{{"BurnToken":{{"amount":"3","token_id":"{id}"}}}}"#),
        );

        let transfer = Operation::TransferToken {
            token_id,
            recipient,
            amount: Amount::from_units(5),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&transfer).unwrap(),
            format!(
                r#"{{"TransferToken":{{"amount":"5","recipient":"{rcpt}","token_id":"{id}"}}}}"#
            ),
        );

        let pause = Operation::SetTokenPaused {
            token_id,
            paused: true,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&pause).unwrap(),
            format!(r#"{{"SetTokenPaused":{{"paused":true,"token_id":"{id}"}}}}"#),
        );

        let freeze = Operation::FreezeTokenAccount { token_id, account };
        assert_eq!(
            crate::canonical::canonical_json_string(&freeze).unwrap(),
            format!(r#"{{"FreezeTokenAccount":{{"account":"{acct}","token_id":"{id}"}}}}"#),
        );

        let thaw = Operation::ThawTokenAccount { token_id, account };
        assert_eq!(
            crate::canonical::canonical_json_string(&thaw).unwrap(),
            format!(r#"{{"ThawTokenAccount":{{"account":"{acct}","token_id":"{id}"}}}}"#),
        );

        // Authority transfer (Some) pins the address; renounce (None) pins null.
        let grant_auth = Operation::SetTokenAuthority {
            token_id,
            authority_kind: TokenAuthorityKind::Mint,
            new_authority: Some(recipient),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&grant_auth).unwrap(),
            format!(
                r#"{{"SetTokenAuthority":{{"authority_kind":"Mint","new_authority":"{rcpt}","token_id":"{id}"}}}}"#
            ),
        );
        let renounce = Operation::SetTokenAuthority {
            token_id,
            authority_kind: TokenAuthorityKind::Freeze,
            new_authority: None,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&renounce).unwrap(),
            format!(
                r#"{{"SetTokenAuthority":{{"authority_kind":"Freeze","new_authority":null,"token_id":"{id}"}}}}"#
            ),
        );

        // The decode is strict (deny_unknown_fields), matching sibling operations,
        // and the bounded hex codec rejects an over-length metadata name.
        let mut value = serde_json::to_value(&mint).unwrap();
        value["MintToken"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
        let mut value = serde_json::to_value(&create).unwrap();
        value["CreateToken"]["metadata"]["name"] =
            serde_json::Value::String("61".repeat(crate::token::MAX_TOKEN_NAME_BYTES + 1));
        assert!(serde_json::from_value::<Operation>(value).is_err());
    }

    #[test]
    fn dex_operations_have_stable_wire_vectors() {
        // Pins the canonical (sorted, JS-safe) JSON of the native DEX operations
        // (Phase 8, §15.37). `canonical_json_bytes` is the signing/state-root
        // encoder the browser SDK's `canonicalJson` mirrors: object keys are sorted
        // recursively, `Amount`/`Price` are decimal STRINGS, `order_id` is lowercase
        // hex, `deadline_height` a number, `fill_or_cancel` a bool. These exact
        // strings are cross-checked in `sdk/webc-js/src/native-ops.test.ts`, so DEX
        // has real Rust<->TS byte parity (it previously had none).
        let order_id = crate::OrderId::new(webc_crypto::Hash256([0x88; 32]));
        let submit = Operation::SubmitOrder {
            order_id,
            pair: crate::TradingPair {
                base: crate::AssetId::NativeWebc,
                quote: crate::AssetId::External {
                    origin_chain: crate::ExternalChain::Ethereum,
                    symbol: "USDC".to_owned(),
                    contract_or_mint: "0x1234".to_owned(),
                },
            },
            side: crate::OrderSide::Sell,
            amount: Amount::from_units(1_000),
            limit_price: crate::Price(5),
            deadline_height: 0,
            fill_or_cancel: false,
        };
        // Strict serde round-trip (the enum is `deny_unknown_fields`).
        let text = serde_json::to_string(&submit).expect("submit serializes");
        assert_eq!(serde_json::from_str::<Operation>(&text).unwrap(), submit);
        let submit_canonical = String::from_utf8(
            crate::canonical::canonical_json_bytes(&submit).expect("canonical submit"),
        )
        .unwrap();
        assert_eq!(
            submit_canonical,
            "{\"SubmitOrder\":{\"amount\":\"1000\",\"deadline_height\":0,\"fill_or_cancel\":false,\"limit_price\":\"5\",\"order_id\":\"8888888888888888888888888888888888888888888888888888888888888888\",\"pair\":{\"base\":\"NativeWebc\",\"quote\":{\"External\":{\"contract_or_mint\":\"0x1234\",\"origin_chain\":\"Ethereum\",\"symbol\":\"USDC\"}}},\"side\":\"Sell\"}}"
        );

        let cancel = Operation::CancelOrder { order_id };
        let cancel_canonical = String::from_utf8(
            crate::canonical::canonical_json_bytes(&cancel).expect("canonical cancel"),
        )
        .unwrap();
        assert_eq!(
            cancel_canonical,
            "{\"CancelOrder\":{\"order_id\":\"8888888888888888888888888888888888888888888888888888888888888888\"}}"
        );
    }

    #[test]
    fn nft_operations_have_stable_wire_vectors() {
        // Pins the canonical JSON of the native NFT operations (Phase 13b, §15) so a
        // browser SDK mirror must reproduce these exact field names and sorted-key
        // order. Adding these variants leaves the frozen `every_native_operation_...`
        // cross-language vector untouched (serde tags variants by name; existing
        // variants are unchanged). Byte-string fields are lowercase hex; hashes are
        // 32-byte lowercase hex; addresses are base58; an Option is the address/value
        // or null.
        let collection_id = crate::NftCollectionId::new(Hash256([0x88; 32]));
        let id = "88".repeat(32);
        let recipient = Keypair::from_seed([9u8; 32]).address();
        let rcpt = recipient.to_base58();
        let item_hash = Hash256([0x3a; 32]);
        let item_hex = "3a".repeat(32);

        // CreateNftCollection carries the nested NftMetadata struct, so round-trip it
        // and confirm the metadata name is lowercase hex on the wire.
        let create = Operation::CreateNftCollection {
            namespace: Hash256([0x55; 32]),
            create_nonce: 7,
            metadata: crate::NftMetadata::new(
                b"Acme Apes".to_vec(),
                b"APE".to_vec(),
                Hash256([0x1f; 32]),
            )
            .expect("valid metadata"),
            mint_authority: Some(recipient),
            freeze_authority: None,
            max_supply: Some(10_000),
            royalty_bps: 500,
        };
        let text = serde_json::to_string(&create).expect("create serializes");
        assert_eq!(serde_json::from_str::<Operation>(&text).unwrap(), create);
        assert!(text.contains(&format!("\"name\":\"{}\"", hex::encode("Acme Apes"))));

        let mint = Operation::MintNft {
            collection_id,
            recipient,
            item_metadata_hash: item_hash,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&mint).unwrap(),
            format!(
                r#"{{"MintNft":{{"collection_id":"{id}","item_metadata_hash":"{item_hex}","recipient":"{rcpt}"}}}}"#
            ),
        );

        let transfer = Operation::TransferNft {
            collection_id,
            serial: 3,
            recipient,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&transfer).unwrap(),
            format!(
                r#"{{"TransferNft":{{"collection_id":"{id}","recipient":"{rcpt}","serial":3}}}}"#
            ),
        );

        let burn = Operation::BurnNft {
            collection_id,
            serial: 3,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&burn).unwrap(),
            format!(r#"{{"BurnNft":{{"collection_id":"{id}","serial":3}}}}"#),
        );

        let pause = Operation::SetNftCollectionPaused {
            collection_id,
            paused: true,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&pause).unwrap(),
            format!(r#"{{"SetNftCollectionPaused":{{"collection_id":"{id}","paused":true}}}}"#),
        );

        let freeze = Operation::FreezeNftItem {
            collection_id,
            serial: 3,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&freeze).unwrap(),
            format!(r#"{{"FreezeNftItem":{{"collection_id":"{id}","serial":3}}}}"#),
        );

        let thaw = Operation::ThawNftItem {
            collection_id,
            serial: 3,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&thaw).unwrap(),
            format!(r#"{{"ThawNftItem":{{"collection_id":"{id}","serial":3}}}}"#),
        );

        // Authority transfer (Some) pins the address; renounce (None) pins null.
        let grant_auth = Operation::SetNftAuthority {
            collection_id,
            authority_kind: crate::NftAuthorityKind::Mint,
            new_authority: Some(recipient),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&grant_auth).unwrap(),
            format!(
                r#"{{"SetNftAuthority":{{"authority_kind":"Mint","collection_id":"{id}","new_authority":"{rcpt}"}}}}"#
            ),
        );
        let renounce = Operation::SetNftAuthority {
            collection_id,
            authority_kind: crate::NftAuthorityKind::Freeze,
            new_authority: None,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&renounce).unwrap(),
            format!(
                r#"{{"SetNftAuthority":{{"authority_kind":"Freeze","collection_id":"{id}","new_authority":null}}}}"#
            ),
        );

        // The decode is strict (deny_unknown_fields), matching sibling operations,
        // and the bounded hex codec rejects an over-length metadata name.
        let mut value = serde_json::to_value(&mint).unwrap();
        value["MintNft"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
        let mut value = serde_json::to_value(&create).unwrap();
        value["CreateNftCollection"]["metadata"]["name"] =
            serde_json::Value::String("61".repeat(crate::nft::MAX_NFT_NAME_BYTES + 1));
        assert!(serde_json::from_value::<Operation>(value).is_err());
    }

    #[test]
    fn governance_operations_have_stable_wire_vectors() {
        // Pins the canonical JSON of the native application-governance operations
        // (Phase 13c, §15) so a browser SDK mirror must reproduce these exact field
        // names and sorted-key order. Adding these variants leaves the frozen
        // `every_native_operation_...` cross-language vector untouched (serde tags
        // variants by name; existing variants are unchanged). Ids/tokens are 32-byte
        // lowercase hex; amounts are decimal strings; addresses are base58; the
        // choice/action/status enums tag by variant name.
        let instance_id = crate::GovernanceInstanceId::new(Hash256([0x88; 32]));
        let proposal_id = crate::ProposalId::new(Hash256([0x99; 32]));
        let weight_token = TokenId::new(Hash256([0x77; 32]));
        let iid = "88".repeat(32);
        let pid = "99".repeat(32);
        let tid = "77".repeat(32);
        let recipient = Keypair::from_seed([9u8; 32]).address();
        let rcpt = recipient.to_base58();

        // CreateGovernanceInstance carries the nested GovernanceConfig, so round-trip
        // it and confirm the nested threshold fields survive.
        let create = Operation::CreateGovernanceInstance {
            namespace: Hash256([0x55; 32]),
            create_nonce: 7,
            weight_token,
            config: GovernanceConfig {
                voting_period_epochs: 10,
                timelock_epochs: 3,
                quorum_bps: 3_000,
                proposal_threshold: Amount::from_units(10),
                approval_threshold_bps: 5_000,
            },
        };
        let text = crate::canonical::canonical_json_string(&create).unwrap();
        assert_eq!(serde_json::from_str::<Operation>(&text).unwrap(), create);
        assert_eq!(
            text,
            format!(
                r#"{{"CreateGovernanceInstance":{{"config":{{"approval_threshold_bps":5000,"proposal_threshold":"10","quorum_bps":3000,"timelock_epochs":3,"voting_period_epochs":10}},"create_nonce":7,"namespace":"{ns}","weight_token":"{tid}"}}}}"#,
                ns = "55".repeat(32),
            )
        );

        let fund = Operation::FundGovernanceTreasury {
            instance_id,
            amount: Amount::from_units(100),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&fund).unwrap(),
            format!(r#"{{"FundGovernanceTreasury":{{"amount":"100","instance_id":"{iid}"}}}}"#),
        );

        // OpenProposal with a signaling action, and with a treasury-transfer action.
        let open_signal = Operation::OpenProposal {
            instance_id,
            action: GovernanceAction::Signaling,
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&open_signal).unwrap(),
            format!(r#"{{"OpenProposal":{{"action":"Signaling","instance_id":"{iid}"}}}}"#),
        );
        let open_pay = Operation::OpenProposal {
            instance_id,
            action: GovernanceAction::TreasuryTransfer {
                recipient,
                amount: Amount::from_units(42),
            },
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&open_pay).unwrap(),
            format!(
                r#"{{"OpenProposal":{{"action":{{"TreasuryTransfer":{{"amount":"42","recipient":"{rcpt}"}}}},"instance_id":"{iid}"}}}}"#
            ),
        );

        let vote = Operation::CastVote {
            proposal_id,
            choice: VoteChoice::Yes,
            weight_amount: Amount::from_units(5),
        };
        assert_eq!(
            crate::canonical::canonical_json_string(&vote).unwrap(),
            format!(
                r#"{{"CastVote":{{"choice":"Yes","proposal_id":"{pid}","weight_amount":"5"}}}}"#
            ),
        );

        let resolve = Operation::ResolveProposal { proposal_id };
        assert_eq!(
            crate::canonical::canonical_json_string(&resolve).unwrap(),
            format!(r#"{{"ResolveProposal":{{"proposal_id":"{pid}"}}}}"#),
        );
        let execute = Operation::ExecuteProposal { proposal_id };
        assert_eq!(
            crate::canonical::canonical_json_string(&execute).unwrap(),
            format!(r#"{{"ExecuteProposal":{{"proposal_id":"{pid}"}}}}"#),
        );
        let reclaim = Operation::ReclaimVote { proposal_id };
        assert_eq!(
            crate::canonical::canonical_json_string(&reclaim).unwrap(),
            format!(r#"{{"ReclaimVote":{{"proposal_id":"{pid}"}}}}"#),
        );

        // The decode is strict (deny_unknown_fields), matching sibling operations,
        // including the nested config and action structs.
        let mut value = serde_json::to_value(&fund).unwrap();
        value["FundGovernanceTreasury"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
        let mut value = serde_json::to_value(&vote).unwrap();
        value["CastVote"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
        let mut value = serde_json::to_value(&create).unwrap();
        value["CreateGovernanceInstance"]["config"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Operation>(value).is_err());
    }

    #[test]
    fn sponsor_field_is_omitted_when_absent_and_signed_when_present() {
        // A non-sponsored transaction must serialize without a `sponsor` key, so
        // the frozen V4 vectors and the TS SDK stay valid; a sponsored one signs
        // over exactly one added `sponsor` key bound to the sender's signature.
        let sender = Keypair::from_seed([1u8; 32]);
        let recipient = Keypair::from_seed([2u8; 32]);
        let namespace = Hash256([0xab; 32]);

        let plain = Transaction::for_operation(
            &sender,
            0,
            Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(1),
            },
            FeeBid::default(),
        )
        .unwrap();
        assert!(
            !canonical_signing_text(&plain).contains("sponsor"),
            "an absent sponsor is omitted from the signed payload"
        );
        assert!(
            !crate::canonical::canonical_json_string(&plain)
                .unwrap()
                .contains("sponsor"),
            "an absent sponsor is omitted from the wire encoding"
        );

        let sponsored = Transaction::for_sponsored_operation(
            &sender,
            0,
            Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(1),
            },
            FeeBid::default(),
            namespace,
        )
        .unwrap();
        assert_eq!(sponsored.sponsor, Some(namespace));
        assert!(
            canonical_signing_text(&sponsored)
                .contains(&format!(r#""sponsor":"{}""#, "ab".repeat(32))),
            "a present sponsor is part of the signed payload"
        );
        // The signed payload binds the sponsor: the signature verifies, and the
        // declared access list covers the sponsor state key.
        sponsored.verify().expect("sponsored signature verifies");
        assert!(sponsored.access_list.read_write.iter().any(|k| matches!(
            &k.kind,
            crate::StateKeyKind::Application { namespace: ns, key_hash }
                if *ns == namespace && *key_hash == sponsor_state_key_hash()
        )));

        // Round-trips through canonical JSON preserving the sponsor field.
        let text = crate::canonical::canonical_json_string(&sponsored).unwrap();
        let decoded: Transaction = serde_json::from_str(&text).unwrap();
        assert_eq!(decoded, sponsored);
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
