//! Deterministic in-memory protocol state and native-operation execution.
//!
//! The module owns account, staking, fee, replay, and prototype bridge state. It
//! does not own networking, durable storage, or consensus voting. Signed
//! transactions enter through validation, execute against a cloned overlay, and
//! commit only on success. Block construction supplies the parent overlay, and
//! each transaction fails if its recorded logical access differs from its signed
//! versioned access list.

use crate::account::Account;
use crate::authorization::AuthorizationLane;
use crate::authorization_policy::{
    active_key_rotation_message, post_quantum_root_rotation_message, AccountAuthorizationPolicy,
};
use crate::bridge::{AssetId, BridgeConfig, BridgeEvent, BridgeMessage, ExternalChain};
use crate::contract::{
    builtin_contract, BuiltinContract, Contract, ContractContext, ContractManifest,
    ContractRuntimeConfig, ContractStateValue, GasMeter, CONTRACT_LEAF_DOMAIN,
    CONTRACT_STATE_LEAF_DOMAIN, MAX_CONTRACT_INPUT_BYTES,
};
use crate::dex::{
    prorata_fills, uniform_clearing_price, DexConfig, Order, OrderId, OrderSide, Price,
    TradingPair, DEX_ORDER_LEAF_DOMAIN,
};
use crate::fees::{
    next_base_fee, next_localized_base_fee, split_fee, FeeBreakdown, FeePolicy, NamespaceFeeState,
    StoragePricing, NAMESPACE_FEE_LEAF_DOMAIN,
};
use crate::genesis::GenesisConfig;
use crate::governance::{
    gov_vote_escrow_address, GovProposalStatus, GovernanceAction, GovernanceInstance,
    GovernanceInstanceId, GovernanceParams, Proposal as GovernanceProposal, ProposalId, VoteChoice,
    VoteRecord, GOVERNANCE_INSTANCE_LEAF_DOMAIN, GOVERNANCE_PROPOSAL_LEAF_DOMAIN,
    GOVERNANCE_VOTE_LEAF_DOMAIN,
};
use crate::mandate::{Mandate, MandateConfig, MandateId, MANDATE_LEAF_DOMAIN};
use crate::namespace::{namespace_state_key_hash, NamespaceRecord, NAMESPACE_LEAF_DOMAIN};
use crate::nft::{
    NftAuthorityKind, NftCollection, NftCollectionId, NftConfig, NftId, NftItem,
    NFT_COLLECTION_LEAF_DOMAIN, NFT_ITEM_LEAF_DOMAIN,
};
use crate::object::{validate_object_data, ObjectOwner, StateObject};
use crate::oracle::{
    accuracy_weight, median, Feed, FeedId, FeedValue, OracleConfig, OracleReporter,
    ORACLE_FEED_LEAF_DOMAIN, ORACLE_REPORTER_LEAF_DOMAIN,
};
use crate::service_registry::{
    ServiceEntry, ServiceId, ServiceStatus, SERVICE_REGISTRY_LEAF_DOMAIN,
};
use crate::session_key::{
    session_key_authorization_message, SessionAllowedOperations, SessionKey,
    SessionKeyAuthorizationAction, SessionKeyConfig, SessionKeyId,
};
use crate::slashing::{
    slash_validator_with_delegation_loss, slashing_bps, SlashingOutcome, SlashingPolicy,
};
#[cfg(test)]
use crate::sponsor_grant_book::SponsorGrantBookError;
use crate::sponsorship::{
    sponsor_state_key_hash, AppSponsor, SponsorshipConfig, SPONSOR_LEAF_DOMAIN,
};
use crate::staking::{Delegation, StakingConfig, Validator, ValidatorStatus};
use crate::state_key::StateAccessRecorder;
use crate::token::{
    TokenAuthorityKind, TokenConfig, TokenId, TokenRecord, FROZEN_TOKEN_LEAF_DOMAIN,
    TOKEN_BALANCE_LEAF_DOMAIN, TOKEN_LEAF_DOMAIN,
};
use crate::transaction::{Operation, Transaction};
use crate::unbonding::{
    UnbondingClaimJournalV1, UnbondingKind, UnbondingQueue, UnbondingRequestId, UnbondingTransition,
};
use crate::wasm_contract::{
    WasmBytecode, WasmContract, WasmContractManifest, WASM_CODE_LEAF_DOMAIN,
    WASM_CONTRACT_LEAF_DOMAIN,
};
use crate::{
    Amount, AuthorizationLaneId, BootstrapIssuance, ChainError, ChainId, Epoch,
    InactivityLeakConfig, InflationSchedule, ObjectId, ObjectVersion, ProtocolStateKey,
    ProtocolVersion, SlashingEvidence, SponsorGrantBookV1, SponsorGrantId, StateKey,
    CURRENT_PROTOCOL_VERSION, LEGACY_AUTHORIZATION_POLICY_REVISION,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use webc_crypto::{merkle_proof, merkle_root, verify_merkle_proof, Address, Hash256, MerkleProof};

/// Static chain configuration used by deterministic state transitions.
///
/// Production nodes should load this from genesis and never silently change it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Immutable schema version interpreted by deterministic state transitions.
    pub protocol_version: ProtocolVersion,
    /// Replay-protection domain shared by genesis, transactions, blocks, and votes.
    pub chain_id: ChainId,
    /// Maximum canonical serialized block size in bytes, including its header.
    pub max_block_bytes: u64,
    pub fee_policy: FeePolicy,
    pub staking: StakingConfig,
    pub slashing: SlashingPolicy,
    pub inflation: InflationSchedule,
    pub bridge: BridgeConfig,
    /// Occupancy-priced storage deposit + deletion rebate policy (§15.22).
    ///
    /// `#[serde(default)]` keeps a genesis written before storage pricing
    /// decodable; the default locks a cheap refundable deposit per object byte
    /// and refunds 90% on delete (burning 10% as the occupancy fee).
    #[serde(default)]
    pub storage_pricing: StoragePricing,
    /// Hard, deterministic caps for application fee sponsorship (§15.35).
    ///
    /// `#[serde(default)]` keeps a genesis written before sponsorship decodable;
    /// the launch values are measurement-tuned placeholders (per-user /
    /// per-operation / per-app-per-day bounds, simple operations only).
    #[serde(default)]
    pub sponsorship: SponsorshipConfig,
    /// Native oracle parameters (§15.17): feed-creation fee, minimum reporter
    /// bond, settlement cadence, and liveness window.
    ///
    /// `#[serde(default)]` keeps a genesis written before the oracle decodable;
    /// the launch values are measurement-tuned placeholders (§15.35 method).
    #[serde(default)]
    pub oracle: OracleConfig,
    /// Native DEX parameters (§15.13/§15.18/§15.37): minimum order size, default
    /// retry-deadline window, and the optional per-fill fee.
    ///
    /// `#[serde(default)]` keeps a genesis written before the DEX decodable; the
    /// launch values are measurement-tuned placeholders (§15.35 method).
    #[serde(default)]
    pub dex: DexConfig,
    /// Interim contract runtime parameters (Phase 7a, ADR-0014): the flat, burned
    /// contract-registration fee.
    ///
    /// `#[serde(default)]` keeps a genesis written before the contract runtime
    /// decodable; the launch value is a measurement-tuned placeholder.
    #[serde(default)]
    pub contracts: ContractRuntimeConfig,
    /// Constrained session-key lifetime and per-account count limits.
    #[serde(default)]
    pub session_keys: SessionKeyConfig,
    /// Agent-mandate parameters (Phase 9a, §15.32): the deterministic per-day
    /// rate-limit window.
    ///
    /// `#[serde(default)]` keeps a genesis written before mandates decodable; the
    /// launch value is a measurement-tuned placeholder (§15.35 method).
    #[serde(default)]
    pub mandate: MandateConfig,
    /// Native fungible-token parameters (Phase 13a, §15): the flat native creation
    /// deposit locked (non-refundable) as an anti-spam price.
    ///
    /// `#[serde(default)]` keeps a genesis written before native tokens decodable;
    /// the launch value is a measurement-tuned placeholder (§15.35 method).
    #[serde(default)]
    pub token: TokenConfig,
    /// Native NFT parameters (Phase 13b, §15): the flat native creation deposit
    /// locked (non-refundable) as an anti-spam price per collection.
    ///
    /// `#[serde(default)]` keeps a genesis written before native NFTs decodable; the
    /// launch value is a measurement-tuned placeholder (§15.35 method).
    #[serde(default)]
    pub nft: NftConfig,
    /// Native application-governance parameters (Phase 13c, §15): the flat native
    /// creation deposit locked (non-refundable) as an anti-spam price per instance.
    ///
    /// `#[serde(default)]` keeps a genesis written before governance decodable; the
    /// launch value is a measurement-tuned placeholder (§15.35 method).
    #[serde(default)]
    pub governance: GovernanceParams,
    /// Total native supply, in base units, that the genesis allocation must sum
    /// to. `Some` on production genesis — mainnet and devnet both pin
    /// [`GENESIS_TOTAL_SUPPLY`] — so `ChainState::from_genesis` rejects any
    /// allocation whose minted supply differs (finding G1; the supply invariant
    /// on its own is tautological and never pins the total). `None` skips the
    /// check for trusted in-crate test fixtures that use small allocations.
    ///
    /// [`GENESIS_TOTAL_SUPPLY`]: crate::GENESIS_TOTAL_SUPPLY
    #[serde(default)]
    pub expected_total_supply: Option<Amount>,
    /// Opt-in bootstrap-phase issuance (§15.2). `None` (default) uses only the
    /// base [`InflationSchedule`]; `Some` keys issuance to staked amount, capped
    /// by the base per-period budget, until [`BootstrapIssuance::sunset_epoch`].
    #[serde(default)]
    pub bootstrap_issuance: Option<BootstrapIssuance>,
    /// Opt-in inactivity leak (ADR-0012). `None` (default) keeps vanilla
    /// Tendermint liveness (halt on >1/3 offline) plus the ADR-0011 restart
    /// fallback; `Some` will drain offline validator weight to recover finality
    /// once the recovery-mode consensus design is confirmed and wired.
    #[serde(default)]
    pub inactivity_leak: Option<InactivityLeakConfig>,
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            max_block_bytes: 4 * 1024 * 1024,
            fee_policy: FeePolicy::default(),
            staking: StakingConfig::default(),
            slashing: SlashingPolicy::default(),
            inflation: InflationSchedule::default(),
            bridge: BridgeConfig::default(),
            storage_pricing: StoragePricing::default(),
            sponsorship: SponsorshipConfig::default(),
            oracle: OracleConfig::default(),
            dex: DexConfig::default(),
            contracts: ContractRuntimeConfig::default(),
            session_keys: SessionKeyConfig::default(),
            mandate: MandateConfig::default(),
            token: TokenConfig::default(),
            nft: NftConfig::default(),
            governance: GovernanceParams::default(),
            expected_total_supply: None,
            bootstrap_issuance: None,
            inactivity_leak: None,
        }
    }
}

/// Why a DEX order left the live order set (carried in [`Event::OrderClosed`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderCloseReason {
    /// The owner submitted an explicit `CancelOrder`.
    Cancelled,
    /// An immediate-or-cancel order had an unfilled remainder after its batch.
    FillOrCancel,
    /// The order's `deadline_height` passed with an unfilled remainder.
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Transfer {
        from: Address,
        to: Address,
        amount: Amount,
    },
    FeePaid {
        payer: Address,
        breakdown: FeeBreakdown,
    },
    /// An application sponsor's budget covered a transaction's fee (§15.35).
    FeeSponsored {
        /// Application namespace whose sponsor budget paid the fee.
        application: Hash256,
        /// User whose transaction fee was sponsored.
        beneficiary: Address,
        /// The burn + validator-reward split drawn from the sponsor budget.
        breakdown: FeeBreakdown,
    },
    /// A new application fee sponsor was registered and initially funded (§15.35).
    AppSponsorRegistered {
        /// Application namespace this sponsor underwrites.
        application: Hash256,
        /// Account that controls (funds/withdraws) the sponsor.
        owner: Address,
        /// App-chosen per-day-window sponsored-fee spend cap.
        daily_budget_cap: Amount,
        /// Native base units moved into the budget at registration.
        funded: Amount,
    },
    /// An application fee sponsor's budget was topped up (§15.35).
    AppSponsorFunded {
        /// Application namespace whose budget grew.
        application: Hash256,
        /// Native base units added to the budget.
        amount: Amount,
    },
    /// Unspent budget was withdrawn from an application fee sponsor (§15.35).
    AppSponsorWithdrawn {
        /// Application namespace whose budget shrank.
        application: Hash256,
        /// Native base units returned to the owner's liquid balance.
        amount: Amount,
    },
    /// An application namespace was claimed by an owner (§8 application isolation).
    NamespaceRegistered {
        /// Application namespace that was claimed.
        namespace: Hash256,
        /// Account now recorded as the namespace owner.
        owner: Address,
    },
    /// A registered application namespace changed owner (§8 application isolation).
    NamespaceTransferred {
        /// Application namespace whose ownership moved.
        namespace: Hash256,
        /// Previous owner that authorized the transfer.
        from: Address,
        /// New owner recorded in the registry.
        to: Address,
    },
    /// A native oracle feed was created for the creation fee (§15.6/§15.17).
    FeedCreated {
        /// New feed identity.
        feed_id: FeedId,
        /// Account that created and paid for the feed.
        creator: Address,
        /// Frozen reporter bond-size class for this feed.
        bond: Amount,
        /// Creation fee burned from the creator's liquid balance.
        fee_burned: Amount,
    },
    /// A reporter registered and bonded on a feed (§15.17).
    ReporterRegistered {
        /// Feed the reporter joined.
        feed_id: FeedId,
        /// Reporter that bonded.
        reporter: Address,
        /// Native base units locked as the bond.
        bond: Amount,
    },
    /// A reporter deregistered and had its bond returned (§15.17).
    ReporterDeregistered {
        /// Feed the reporter left.
        feed_id: FeedId,
        /// Reporter that unbonded.
        reporter: Address,
        /// Native base units returned to the reporter's liquid balance.
        bond: Amount,
    },
    /// A reporter submitted a value to a feed (§9 median aggregation).
    ReportSubmitted {
        /// Feed reported to.
        feed_id: FeedId,
        /// Reporter that submitted.
        reporter: Address,
        /// The submitted integer value.
        value: FeedValue,
        /// Epoch the value was reported for (liveness reference).
        epoch: u64,
    },
    /// A consumer paid a read fee into a feed's revenue pool (§15.17).
    FeedReadPaid {
        /// Feed whose value was consumed on-chain.
        feed_id: FeedId,
        /// Account that paid the read fee.
        payer: Address,
        /// Native base units added to the feed's revenue pool.
        amount: Amount,
    },
    /// A feed's accrued read-fee revenue was settled to its reporters (§15.17).
    ///
    /// Distributed weighted by accuracy (closeness to the accepted median) and
    /// liveness (reported within the window); `carried` is the integer-division
    /// remainder kept in the pool for the next settlement, so nothing is lost.
    FeedRevenueSettled {
        /// Feed that was settled.
        feed_id: FeedId,
        /// Epoch the settlement was performed for.
        epoch: u64,
        /// Accepted median at settlement (the accuracy reference), if any reporter
        /// had submitted a value.
        median: Option<FeedValue>,
        /// Native base units paid out to reporters this settlement.
        distributed: Amount,
        /// Native base units carried forward in the pool (division remainder).
        carried: Amount,
    },
    /// A DEX order intent was submitted and its input locked (§15.37).
    OrderSubmitted {
        /// New order identity.
        order_id: OrderId,
        /// Account that submitted and locked the order's input.
        owner: Address,
        /// Oriented pair the order trades on.
        pair: TradingPair,
        /// Buy or sell.
        side: OrderSide,
        /// Order size in base-asset base units.
        amount: Amount,
        /// Limit price in quote base-units per base base-unit.
        limit_price: Price,
        /// Effective deadline height after which the order auto-cancels.
        deadline_height: u64,
    },
    /// A DEX order was (partially or fully) filled in a block's batch (§15.37).
    ///
    /// Every order filled in the same pair's batch trades at the identical
    /// `clearing_price`, so no participant is ordered ahead of another. `filled` is
    /// this batch's base fill; `remaining` is what is left to retry afterward
    /// (`0` when fully filled and the order is then closed).
    OrderFilled {
        /// Order that filled.
        order_id: OrderId,
        /// Pair whose batch settled.
        pair: TradingPair,
        /// Buy or sell.
        side: OrderSide,
        /// Uniform clearing price for this pair's batch this block.
        clearing_price: Price,
        /// Base units filled this batch.
        filled: Amount,
        /// Base units still to fill after this batch.
        remaining: Amount,
        /// Quote base units the order paid (buy) or received net of fee (sell).
        quote: Amount,
    },
    /// A DEX order was cancelled and its remaining lock refunded (§15.37).
    ///
    /// Covers owner-requested cancels, immediate-or-cancel remainders, and
    /// deadline expiries; `reason` distinguishes them.
    OrderClosed {
        /// Order that was closed.
        order_id: OrderId,
        /// Account the remaining lock was refunded to.
        owner: Address,
        /// Why the order closed.
        reason: OrderCloseReason,
        /// Base units of the order left unfilled at closure.
        unfilled: Amount,
    },
    /// An interim Rust-authored contract was registered (Phase 7a, ADR-0014).
    ContractRegistered {
        /// Registered contract identity (the manifest / module key).
        code_id: Hash256,
        /// Application namespace the contract's state is isolated under.
        namespace: Hash256,
        /// Account that registered and owns the contract.
        owner: Address,
        /// Audited built-in handler the contract runs.
        builtin: BuiltinContract,
        /// Registration fee burned from the owner's liquid balance.
        fee_burned: Amount,
    },
    /// A registered contract's handler was invoked (Phase 7a, ADR-0014).
    ContractInvoked {
        /// Registered contract identity that ran.
        code_id: Hash256,
        /// Application namespace whose state the call touched.
        namespace: Hash256,
        /// Account that invoked the contract.
        caller: Address,
        /// Total execution units the call consumed (admission plus metered
        /// per-host-op consumption), within the sender's authorized `gas_limit`.
        gas_consumed: u64,
        /// Length in bytes of the handler's returned output.
        output_len: u64,
    },
    /// A deployer-supplied WASM contract was registered (Phase 7b, ADR-0014 (a)).
    WasmContractRegistered {
        /// Registered contract identity (the manifest / module key).
        code_id: Hash256,
        /// Application namespace the contract's state is isolated under.
        namespace: Hash256,
        /// Account that registered and owns the contract.
        owner: Address,
        /// Content hash binding the manifest to the uploaded module bytes.
        code_hash: Hash256,
        /// Size in bytes of the uploaded module.
        code_len: u64,
        /// Registration fee burned from the owner's liquid balance.
        fee_burned: Amount,
    },
    /// A registered WASM contract's module was invoked (Phase 7b, ADR-0014 (a)).
    WasmContractInvoked {
        /// Registered contract identity that ran.
        code_id: Hash256,
        /// Application namespace whose state the call touched.
        namespace: Hash256,
        /// Account that invoked the contract.
        caller: Address,
        /// Total execution units the call consumed (admission plus metered compute
        /// and per-host-op consumption), within the sender's authorized `gas_limit`.
        gas_consumed: u64,
        /// Length in bytes of the module's returned output.
        output_len: u64,
    },
    ValidatorRegistered {
        operator: Address,
        bootstrap: bool,
    },
    Delegated {
        delegator: Address,
        validator: Address,
        amount: Amount,
    },
    UnbondingRequested {
        request_id: UnbondingRequestId,
        delegator: Address,
        validator: Address,
        kind: UnbondingKind,
        amount: Amount,
    },
    UnbondingAdmitted {
        request_id: UnbondingRequestId,
        delegator: Address,
        validator: Address,
        kind: UnbondingKind,
        amount: Amount,
    },
    UnbondingMatured {
        request_id: UnbondingRequestId,
        delegator: Address,
        validator: Address,
        kind: UnbondingKind,
        amount: Amount,
    },
    UnbondingClaimed {
        request_id: UnbondingRequestId,
        delegator: Address,
        kind: UnbondingKind,
        amount: Amount,
    },
    ValidatorRewardsClaimed {
        validator: Address,
        amount: Amount,
    },
    DelegatorRewardsClaimed {
        delegator: Address,
        validator: Address,
        amount: Amount,
    },
    ValidatorRewardsCompounded {
        validator: Address,
        amount: Amount,
    },
    DelegatorRewardsCompounded {
        delegator: Address,
        validator: Address,
        amount: Amount,
    },
    Slashed {
        outcome: SlashingOutcome,
    },
    Bridge {
        event: BridgeEvent,
    },
    EpochRewardsDistributed {
        epoch: u64,
        total: Amount,
    },
    AuthorizationLaneOpened {
        owner: Address,
        lane: AuthorizationLaneId,
        fee_deposit: Amount,
    },
    AuthorizationLaneFunded {
        owner: Address,
        lane: AuthorizationLaneId,
        fee_deposit: Amount,
    },
    AuthorizationPolicyInstalled {
        /// Stable account address whose legacy key approved migration.
        owner: Address,
        /// First installed revision; currently always one.
        revision: crate::AuthorizationPolicyRevision,
        /// Committed post-quantum recovery root, not a verification claim.
        post_quantum_root: crate::PostQuantumRoot,
    },
    SessionKeyInstalled {
        /// Account that owns the new session key.
        owner: Address,
        /// Opaque session-key identity.
        session_key: SessionKeyId,
        /// Absolute last epoch the key may be used.
        expires_after_epoch: Epoch,
    },
    SessionKeyRevoked {
        /// Account whose session key was removed.
        owner: Address,
        /// Opaque identity of the revoked session key.
        session_key: SessionKeyId,
    },
    SessionKeyExpired {
        /// Account whose session key was pruned at an epoch boundary.
        owner: Address,
        /// Opaque identity of the expired session key.
        session_key: SessionKeyId,
    },
    ActiveTransactionKeyRotated {
        /// Account whose active transaction key was replaced.
        owner: Address,
        /// Revision after rotation; every prior-revision session key is now dead.
        new_revision: crate::AuthorizationPolicyRevision,
        /// New Ed25519 key now authorizing ordinary transactions.
        new_active_transaction_key: webc_crypto::PublicKeyBytes,
    },
    PostQuantumRootRotated {
        /// Account whose post-quantum recovery root was replaced.
        owner: Address,
        /// Revision after rotation; every prior-revision session key is now dead.
        new_revision: crate::AuthorizationPolicyRevision,
        /// New committed recovery root now required for critical actions.
        new_post_quantum_root: crate::PostQuantumRoot,
    },
    SessionKeyUsed {
        /// Account that owns the session key.
        owner: Address,
        /// Opaque identity of the session key that authorized the transaction.
        session_key: SessionKeyId,
        /// Native principal moved under this use.
        amount: Amount,
    },
    ObjectCreated {
        object_id: ObjectId,
        namespace: Hash256,
        owner: Address,
        version: ObjectVersion,
    },
    ObjectMutated {
        object_id: ObjectId,
        version: ObjectVersion,
    },
    ObjectTransferred {
        object_id: ObjectId,
        from: Address,
        to: Address,
        version: ObjectVersion,
    },
    ObjectDeleted {
        object_id: ObjectId,
        /// Object owner who authorized the deletion and received the refund.
        owner: Address,
        /// Native base units returned to the owner's liquid balance.
        refund: Amount,
        /// Native base units burned as the storage occupancy fee.
        burned: Amount,
    },
    /// An agent mandate was granted and its budget escrowed (§15.32).
    MandateGranted {
        /// New mandate identity.
        mandate_id: MandateId,
        /// Account that granted and funds the mandate.
        principal: Address,
        /// Agent key authorized to spend under the mandate.
        agent_key: webc_crypto::PublicKeyBytes,
        /// Native base units escrowed as the mandate's total budget.
        budget_total: Amount,
        /// Last epoch (inclusive) the mandate may be spent.
        expiry_epoch: Epoch,
    },
    /// An agent mandate's budget was topped up (§15.32).
    MandateToppedUp {
        /// Mandate whose budget grew.
        mandate_id: MandateId,
        /// Native base units added to the escrowed budget.
        amount: Amount,
        /// The mandate's total budget after the top-up.
        budget_total: Amount,
    },
    /// An agent spent against a mandate (§15.32) — the audit-trail record.
    MandateSpent {
        /// Mandate that authorized and funded the spend.
        mandate_id: MandateId,
        /// Agent key that signed the spend.
        agent_key: webc_crypto::PublicKeyBytes,
        /// Recipient credited the spent principal.
        recipient: Address,
        /// Native principal moved to the recipient.
        amount: Amount,
        /// Native fee drawn from the mandate escrow for this spend.
        fee: Amount,
    },
    /// An agent mandate was revoked and its remainder reclaimed (§15.32).
    MandateRevoked {
        /// Mandate that was revoked.
        mandate_id: MandateId,
        /// Principal that revoked it and received the remainder.
        principal: Address,
        /// Native base units returned from escrow to the principal.
        refunded: Amount,
    },
    /// A service was registered in the native registry (Phase 9b, §15.5).
    ServiceRegistered {
        /// New service identity.
        service_id: ServiceId,
        /// Account that owns (controls and is paid for) the service.
        owner: Address,
        /// Application namespace the entry lives under.
        namespace: Hash256,
    },
    /// A registered service's mutable fields were updated (Phase 9b, §15.5).
    ServiceUpdated {
        /// Service whose current revision was rewritten.
        service_id: ServiceId,
        /// The entry's revision after the update.
        revision: u64,
    },
    /// A registered service's lifecycle status changed (Phase 9b, §15.5).
    ServiceStatusChanged {
        /// Service whose status changed.
        service_id: ServiceId,
        /// The new lifecycle status.
        status: ServiceStatus,
        /// The entry's revision after the change.
        revision: u64,
    },
    /// An agent spent against a mandate to pay a service (Phase 9b, §15.5) — the
    /// service-scoped audit-trail record carrying both ids.
    MandateSpentToService {
        /// Mandate that authorized and funded the spend.
        mandate_id: MandateId,
        /// Service whose owner was paid.
        service_id: ServiceId,
        /// Agent key that signed the spend.
        agent_key: webc_crypto::PublicKeyBytes,
        /// Service owner credited the spent principal (the registry pay-to).
        recipient: Address,
        /// Native principal moved to the service owner.
        amount: Amount,
        /// Native fee drawn from the mandate escrow for this spend.
        fee: Amount,
    },
    /// A native fungible token was created (Phase 13a, §15).
    TokenCreated {
        /// Identity of the created token.
        token_id: TokenId,
        /// Account that created the token (its `creator`).
        creator: Address,
        /// Application namespace the token lives under.
        namespace: Hash256,
        /// Native deposit locked (non-refundable) as the anti-spam price.
        deposit: Amount,
        /// Amount minted to the initial recipient at creation (may be zero).
        initial_supply: Amount,
    },
    /// Units of a token were minted to a recipient (Phase 13a, §15).
    TokenMinted {
        /// Token minted.
        token_id: TokenId,
        /// Account credited the newly minted units.
        recipient: Address,
        /// Units minted.
        amount: Amount,
        /// Token issued supply after the mint.
        issued_supply: Amount,
    },
    /// Units of a token were burned from a holder (Phase 13a, §15).
    TokenBurned {
        /// Token burned.
        token_id: TokenId,
        /// Holder whose balance was reduced.
        holder: Address,
        /// Units burned.
        amount: Amount,
        /// Token issued supply after the burn.
        issued_supply: Amount,
    },
    /// Token units moved from one holder to another (Phase 13a, §15).
    TokenTransferred {
        /// Token transferred.
        token_id: TokenId,
        /// Sending account.
        from: Address,
        /// Receiving account.
        to: Address,
        /// Units transferred.
        amount: Amount,
    },
    /// A token's paused flag changed (Phase 13a, §15).
    TokenPausedChanged {
        /// Token whose paused flag changed.
        token_id: TokenId,
        /// New paused state.
        paused: bool,
    },
    /// A token account was frozen or thawed (Phase 13a, §15).
    TokenFreezeChanged {
        /// Token whose account freeze state changed.
        token_id: TokenId,
        /// Account whose freeze state changed.
        account: Address,
        /// Whether the account is now frozen.
        frozen: bool,
    },
    /// A token authority was transferred or permanently renounced (Phase 13a, §15).
    TokenAuthorityChanged {
        /// Token whose authority changed.
        token_id: TokenId,
        /// Which authority (mint or freeze) changed.
        authority_kind: TokenAuthorityKind,
        /// New holder, or `None` if the authority was permanently renounced.
        new_authority: Option<Address>,
    },
    /// A native NFT collection was created (Phase 13b, §15).
    NftCollectionCreated {
        /// Identity of the created collection.
        collection_id: NftCollectionId,
        /// Account that created the collection (its `creator`).
        creator: Address,
        /// Application namespace the collection lives under.
        namespace: Hash256,
        /// Native deposit locked (non-refundable) as the anti-spam price.
        deposit: Amount,
    },
    /// An NFT item was minted to a recipient (Phase 13b, §15).
    NftMinted {
        /// Full identity of the minted item (`(collection, serial)`).
        nft_id: NftId,
        /// Account that owns the newly minted item.
        recipient: Address,
        /// Per-item off-chain metadata commitment.
        item_metadata_hash: Hash256,
    },
    /// An NFT item changed owner (Phase 13b, §15).
    NftTransferred {
        /// Identity of the transferred item.
        nft_id: NftId,
        /// Previous owner.
        from: Address,
        /// New owner.
        to: Address,
    },
    /// An NFT item was burned (Phase 13b, §15).
    NftBurned {
        /// Identity of the burned item.
        nft_id: NftId,
        /// Owner who burned the item.
        owner: Address,
    },
    /// A collection's paused flag changed (Phase 13b, §15).
    NftCollectionPausedChanged {
        /// Collection whose paused flag changed.
        collection_id: NftCollectionId,
        /// New paused state.
        paused: bool,
    },
    /// An NFT item was frozen or thawed (Phase 13b, §15).
    NftItemFreezeChanged {
        /// Identity of the item whose freeze state changed.
        nft_id: NftId,
        /// Whether the item is now frozen.
        frozen: bool,
    },
    /// A collection authority was transferred or permanently renounced
    /// (Phase 13b, §15).
    NftAuthorityChanged {
        /// Collection whose authority changed.
        collection_id: NftCollectionId,
        /// Which authority (mint or freeze) changed.
        authority_kind: NftAuthorityKind,
        /// New holder, or `None` if the authority was permanently renounced.
        new_authority: Option<Address>,
    },
    /// A native governance instance was created (Phase 13c, §15).
    GovernanceInstanceCreated {
        /// Identity of the created instance.
        instance_id: GovernanceInstanceId,
        /// Account that created the instance (its `creator`).
        creator: Address,
        /// Application namespace the instance lives under.
        namespace: Hash256,
        /// Fungible token that denominates voting weight.
        weight_token: TokenId,
        /// Native deposit locked (non-refundable) as the anti-spam price.
        deposit: Amount,
    },
    /// A governance instance's treasury was funded (Phase 13c, §15).
    GovernanceTreasuryFunded {
        /// Instance whose treasury grew.
        instance_id: GovernanceInstanceId,
        /// Account that funded the treasury.
        funder: Address,
        /// Native base units moved into the treasury.
        amount: Amount,
        /// Treasury balance after the fund.
        treasury: Amount,
    },
    /// A governance proposal was opened (Phase 13c, §15).
    GovernanceProposalOpened {
        /// Identity of the opened proposal.
        proposal_id: ProposalId,
        /// Instance the proposal belongs to.
        instance_id: GovernanceInstanceId,
        /// Account that opened the proposal.
        proposer: Address,
        /// Last epoch votes are accepted.
        voting_ends_epoch: u64,
    },
    /// A lock-to-vote ballot was cast (Phase 13c, §15).
    GovernanceVoteCast {
        /// Proposal voted on.
        proposal_id: ProposalId,
        /// Account that voted.
        voter: Address,
        /// The voter's choice.
        choice: VoteChoice,
        /// Weight-token units locked as this vote's weight.
        weight: Amount,
    },
    /// A governance proposal was resolved (Phase 13c, §15).
    GovernanceProposalResolved {
        /// Proposal resolved.
        proposal_id: ProposalId,
        /// Resolved status (`Passed` or `Defeated`).
        status: GovProposalStatus,
        /// Execution-available epoch, set when the proposal passes.
        eta_epoch: Option<u64>,
    },
    /// A passed governance proposal was executed (Phase 13c, §15).
    GovernanceProposalExecuted {
        /// Proposal executed.
        proposal_id: ProposalId,
        /// Instance the proposal belongs to.
        instance_id: GovernanceInstanceId,
    },
    /// A passed governance proposal lapsed unexecuted (Phase 13c, §15).
    GovernanceProposalExpired {
        /// Proposal that expired.
        proposal_id: ProposalId,
    },
    /// A voter reclaimed their locked weight after resolution (Phase 13c, §15).
    GovernanceVoteReclaimed {
        /// Proposal whose lock was reclaimed.
        proposal_id: ProposalId,
        /// Account that reclaimed.
        voter: Address,
        /// Weight-token units returned to the voter.
        weight: Amount,
    },
    /// One protocol-2 sponsor grant was permanently revoked by its owner.
    ///
    /// Appended after every protocol-1 variant so existing bincode enum
    /// discriminants used by receipts and stored blocks remain unchanged.
    SponsorGrantRevoked {
        /// Account that originally signed and now revoked the grant.
        sponsor: Address,
        /// Wallet-generated identity of the revoked grant.
        grant_id: SponsorGrantId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: Hash256,
    pub success: bool,
    pub fee: FeeBreakdown,
    pub units_consumed: u64,
    pub events: Vec<Event>,
    pub error: Option<String>,
}

/// Inclusion proof for one account under the current account Merkle root.
///
/// This is the first practical light-wallet primitive: a browser can request an
/// account plus proof from an RPC node and verify that the account is committed
/// by a block header's `account_root` without downloading full state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountStateProof {
    pub address: Address,
    pub account: Account,
    pub account_root: Hash256,
    pub proof: MerkleProof,
}

impl AccountStateProof {
    pub fn verify(&self) -> Result<bool, ChainError> {
        let expected_leaf = ChainState::account_leaf_hash(self.address, &self.account)?;
        if self.proof.leaf != expected_leaf {
            return Ok(false);
        }
        Ok(verify_merkle_proof(self.account_root, &self.proof))
    }
}

/// In-memory deterministic chain state.
///
/// This is not a production database. It is the auditable state-transition model
/// that storage/networking layers should wrap later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainState {
    /// Protocol schema that must be used to interpret every stored field.
    pub protocol_version: ProtocolVersion,
    /// Network domain preventing state and signatures from crossing chains.
    pub chain_id: ChainId,
    pub accounts: BTreeMap<Address, Account>,
    /// Versioned account signing and recovery policy, absent only for migration.
    #[serde(default)]
    pub authorization_policies: BTreeMap<Address, AccountAuthorizationPolicy>,
    /// Non-default wallet lanes with independent nonce and prepaid fee state.
    pub authorization_lanes: BTreeMap<(Address, AuthorizationLaneId), AuthorizationLane>,
    /// Constrained session keys delegated under each account's policy.
    ///
    /// Keyed by owner and opaque session-key id. Records hold constraints and
    /// cumulative spend, never funds, so they do not enter supply reconciliation.
    #[serde(default)]
    pub session_keys: BTreeMap<(Address, SessionKeyId), SessionKey>,
    /// Replay, cumulative fee/use, bounded revocation, and expiry state for V5 grants.
    ///
    /// The map holds no funds; the payer account or authorization lane remains
    /// the single supply-accounted fee source.
    #[serde(default)]
    pub sponsor_grants: SponsorGrantBookV1,
    /// Persistent versioned application/NFT objects keyed by stable identity.
    pub objects: BTreeMap<ObjectId, StateObject>,
    pub validators: BTreeMap<Address, Validator>,
    pub delegations: BTreeMap<(Address, Address), Delegation>,
    /// FIFO stake-exit requests and cooling tranches.
    pub unbonding: UnbondingQueue,
    pub asset_balances: BTreeMap<(AssetId, Address), Amount>,
    /// Native WEBC locked for release on return from each external domain.
    pub native_bridge_escrow: BTreeMap<ExternalChain, Amount>,
    pub processed_bridge_messages: BTreeSet<Hash256>,
    pub processed_slashing_evidence: BTreeSet<Hash256>,
    pub burned_fees: Amount,
    /// Native units destroyed by verified objective penalties.
    pub slashed_units: Amount,
    /// Refundable native units locked as object storage deposits (§15.22).
    ///
    /// Total of every live object's recorded `deposit`. `CreateObject` moves
    /// units here from the creator's liquid balance; `MutateObject` resizes the
    /// lock; `DeleteObject` moves them out as an owner refund plus a burned
    /// occupancy remainder. Reconciled by [`SupplyInvariantReport`] like the
    /// other locked buckets, and committed by the state root as a scalar.
    #[serde(default)]
    pub storage_deposits: Amount,
    /// Registered application fee sponsors, keyed by application namespace (§15.35).
    ///
    /// Each [`AppSponsor`] holds a pre-funded budget and the hard per-user /
    /// per-app-per-day counters. Committed by the state root through a dedicated
    /// Merkle sub-root (`SPONSOR_LEAF_DOMAIN`), so any change to a sponsor's
    /// budget or counters changes the state root. A `BTreeMap` keeps iteration
    /// deterministic in the hashed/consensus path.
    #[serde(default)]
    pub sponsors: BTreeMap<Hash256, AppSponsor>,
    /// Refundable native units locked across every application sponsor budget (§15.35).
    ///
    /// Sum of every live [`AppSponsor::budget`]. Registering/funding a sponsor
    /// moves units here from the owner's liquid balance; a sponsored fee moves
    /// them out as the same burn + validator-reward split a normal fee uses;
    /// withdrawing moves them back to the owner. Reconciled by
    /// [`SupplyInvariantReport`] as a locked bucket and committed by the state
    /// root as a scalar (mirroring `storage_deposits`).
    #[serde(default)]
    pub sponsor_budgets: Amount,
    /// Application namespace ownership registry (§8 "Application isolation").
    ///
    /// Maps an application namespace to its [`NamespaceRecord`] (its owner). An app
    /// claims its namespace with `RegisterNamespace` and can prove ownership; the
    /// current owner may reassign it with `TransferNamespace`. Committed by the
    /// state root through a dedicated Merkle sub-root (`NAMESPACE_LEAF_DOMAIN`), so
    /// any change to a namespace's owner changes the state root. A `BTreeMap` keeps
    /// iteration deterministic in the hashed/consensus path.
    ///
    /// This registry holds no native units — registration is an ownership record
    /// only — so it does not enter supply reconciliation. Ownership is **not**
    /// required to create objects under a namespace today (open namespaces); gating
    /// object creation on ownership is a later-phase policy decision.
    #[serde(default)]
    pub namespaces: BTreeMap<Hash256, NamespaceRecord>,
    /// Native oracle feed registry, keyed by [`FeedId`] (§15.17).
    ///
    /// Each [`Feed`] holds its creator, its frozen reporter bond class, and its
    /// accrued read-fee revenue awaiting settlement. Committed by the state root
    /// through a dedicated Merkle sub-root (`ORACLE_FEED_LEAF_DOMAIN`), so any
    /// change to a feed (including its revenue) changes the state root. A
    /// `BTreeMap` keeps iteration deterministic in the hashed/consensus path.
    #[serde(default)]
    pub oracle_feeds: BTreeMap<FeedId, Feed>,
    /// Native oracle bonded reporters, keyed by `(FeedId, reporter)` (§15.17).
    ///
    /// Each [`OracleReporter`] holds the reporter's latest value and the epoch it
    /// was reported for (liveness). The record's existence means the reporter's
    /// bond (its feed's `bond`) is locked in `oracle_bonds`. Committed by the
    /// state root through a dedicated Merkle sub-root (`ORACLE_REPORTER_LEAF_DOMAIN`).
    #[serde(default)]
    pub oracle_reporters: BTreeMap<(FeedId, Address), OracleReporter>,
    /// Refundable native units locked across every oracle reporter bond (§15.17).
    ///
    /// Sum of every live reporter's feed `bond`. `RegisterReporter` moves units
    /// here from the reporter's liquid balance; `DeregisterReporter` moves them
    /// back. Reconciled by [`SupplyInvariantReport`] as a locked bucket and
    /// committed by the state root as a scalar (mirroring `sponsor_budgets`).
    #[serde(default)]
    pub oracle_bonds: Amount,
    /// Native units locked across every feed's accrued read-fee revenue (§15.17).
    ///
    /// Sum of every [`Feed::revenue`]. `PayFeedRead` moves units here from a
    /// consumer's liquid balance; epoch settlement moves them out to reporters'
    /// liquid balances (carrying the integer-division remainder to the next
    /// settlement). Reconciled by [`SupplyInvariantReport`] as a locked bucket and
    /// committed by the state root as a scalar.
    #[serde(default)]
    pub oracle_revenue: Amount,
    /// Native DEX live order intents, keyed by [`OrderId`] (§15.13/§15.18/§15.37).
    ///
    /// Each [`Order`] holds its owner, oriented pair, side, original and remaining
    /// size, limit price, deadline, and flags. An order exists only between a
    /// [`Operation::SubmitOrder`] and the batch/cancel/expiry that closes it. The
    /// per-block batch pass (`settle_dex_batch`) settles all orders on a pair at one
    /// uniform clearing price. Committed by the state root through a
    /// dedicated Merkle sub-root (`DEX_ORDER_LEAF_DOMAIN`), so any submit/fill/
    /// cancel/expire changes the state root. A `BTreeMap` keeps iteration
    /// deterministic in the hashed/consensus path.
    #[serde(default)]
    pub dex_orders: BTreeMap<OrderId, Order>,
    /// Refundable native units locked across every live DEX order (§15.37).
    ///
    /// Sum of every order's native locked leg (a buy locks `remaining × limit_price`
    /// quote, a sell locks `remaining` base; only the native leg counts here — a
    /// non-native leg is held out of the owner's `asset_balances`). `SubmitOrder`
    /// moves units here from the owner's liquid balance; settlement moves them out
    /// to counterparties plus an optional fee split; cancel/expiry returns them.
    /// Reconciled by [`SupplyInvariantReport`] as a locked bucket and committed by
    /// the state root as a scalar (mirroring `oracle_bonds`/`sponsor_budgets`).
    #[serde(default)]
    pub dex_escrow: Amount,
    /// Native agent mandates, keyed by [`MandateId`] (Phase 9a, §15.32).
    ///
    /// Each [`Mandate`] holds its principal, agent key, escrowed budget and spend,
    /// expiry, per-transaction cap, counterparty policy, revocation flag, and
    /// per-day rate-limit counters. A mandate exists only between a
    /// [`Operation::GrantMandate`] and the [`Operation::RevokeMandate`] that marks
    /// it revoked (which also reclaims its remainder). Committed by the state root
    /// through a dedicated Merkle sub-root (`MANDATE_LEAF_DOMAIN`), so a grant,
    /// top-up, spend, or revocation changes the state root. A `BTreeMap` keeps
    /// iteration deterministic in the hashed/consensus path.
    #[serde(default)]
    pub mandates: BTreeMap<MandateId, Mandate>,
    /// Refundable native units locked across every live agent mandate (Phase 9a,
    /// §15.32).
    ///
    /// Sum of every mandate's unspent remainder (`budget_total - spent`).
    /// `GrantMandate`/`TopUpMandate` move units here from the principal's liquid
    /// balance; `SpendUnderMandate` moves them out to the recipient plus the fee
    /// split; `RevokeMandate` returns the remainder to the principal. Reconciled by
    /// [`SupplyInvariantReport`] as a locked bucket and committed by the state root
    /// as a scalar (mirroring `dex_escrow`/`oracle_bonds`/`sponsor_budgets`).
    #[serde(default)]
    pub mandate_escrow: Amount,
    /// Native service registry, keyed by [`ServiceId`] (Phase 9b, §15.5).
    ///
    /// Each [`ServiceEntry`] holds a service's owner (its controller and pay-to
    /// account), namespace, taxonomy categories, bounded descriptive fields, price
    /// list, accepted payment flows, lifecycle status, and current revision. A
    /// service exists only after an explicit [`Operation::RegisterService`];
    /// [`Operation::UpdateService`] and [`Operation::SetServiceStatus`] rewrite the
    /// CURRENT revision in place (prior revisions are an event-log/archival concern,
    /// never active state, so committed size tracks live services, not edit
    /// history). Committed by the state root through a dedicated Merkle sub-root
    /// (`SERVICE_REGISTRY_LEAF_DOMAIN`), so a registration, update, or status change
    /// changes the state root. Holds no native units — registration is data only,
    /// its spam-priced fee is the ordinary transaction fee — so it does not enter
    /// supply reconciliation. A `BTreeMap` keeps iteration deterministic in the
    /// hashed/consensus path.
    #[serde(default)]
    pub services: BTreeMap<ServiceId, ServiceEntry>,
    /// Native fungible tokens, keyed by [`TokenId`] (Phase 13a, §15).
    ///
    /// Each [`TokenRecord`] holds a token's creator, bounded metadata, its two
    /// configurable authorities (`Option`, where `None` is a permanent renounce),
    /// its paused flag, and its running `issued_supply` (minted minus burned). A
    /// token exists only after an explicit [`Operation::CreateToken`]. This is a
    /// SEPARATE identity space from the bridge `asset_balances` map, so native-token
    /// supply accounting stays isolated from the bridge trust model. Committed by
    /// the state root through a dedicated Merkle sub-root (`TOKEN_LEAF_DOMAIN`), so
    /// a create, mint, burn, pause, or authority change changes the state root.
    /// Token supply is a separate asset and does NOT enter the native WEBC supply
    /// reconciliation. A `BTreeMap` keeps iteration deterministic in the
    /// hashed/consensus path.
    #[serde(default)]
    pub tokens: BTreeMap<TokenId, TokenRecord>,
    /// Native token balances, keyed by `(TokenId, holder)` (Phase 13a, §15).
    ///
    /// The per-`(token, holder)` key is what makes ordinary [`Operation::TransferToken`]
    /// parallel-schedulable: a transfer writes only the two account balance entries,
    /// never one global per-token object. A zero balance is PRUNED (the entry is
    /// removed when it hits zero) so the map stays bounded, mirroring how other maps
    /// avoid storing zeros. Committed by the state root through a dedicated Merkle
    /// sub-root (`TOKEN_BALANCE_LEAF_DOMAIN`). For every token,
    /// `sum(balances) == issued_supply` (the per-token supply invariant, checked by
    /// [`ChainState::token_supply_report`]).
    #[serde(default)]
    pub token_balances: BTreeMap<(TokenId, Address), Amount>,
    /// Frozen token accounts, as `(TokenId, account)` pairs (Phase 13a, §15).
    ///
    /// A frozen `(token, account)` pair cannot SEND or RECEIVE that token. Only
    /// currently-frozen pairs are present, so the committed set stays bounded — a
    /// thaw removes the pair. Written only by [`Operation::FreezeTokenAccount`] /
    /// [`Operation::ThawTokenAccount`] and read on the mint/burn/transfer value
    /// paths. Committed by the state root through a dedicated Merkle sub-root
    /// (`FROZEN_TOKEN_LEAF_DOMAIN`).
    #[serde(default)]
    pub frozen_token_accounts: BTreeSet<(TokenId, Address)>,
    /// Native units LOCKED across every live token's non-refundable creation
    /// deposit (Phase 13a, §15).
    ///
    /// Sum of every [`Operation::CreateToken`]'s `ChainConfig::token.creation_deposit`.
    /// Creation moves units here from the creator's liquid balance; they stay locked
    /// for the token's life (a non-refundable anti-spam price — a burn-to-zero +
    /// close refund path is a later pass). Reconciled by [`SupplyInvariantReport`]
    /// as a locked bucket and committed by the state root as a scalar (mirroring
    /// `storage_deposits`/`sponsor_budgets`). Token BALANCES are a separate asset and
    /// are NOT part of this native reconciliation.
    #[serde(default)]
    pub token_deposits: Amount,
    /// Native NFT collections, keyed by [`NftCollectionId`] (Phase 13b, §15).
    ///
    /// Each [`NftCollection`] holds a collection's creator, bounded metadata, its two
    /// configurable authorities (`Option`, where `None` is a permanent renounce), its
    /// paused flag, the monotonic `next_serial` mint counter, the running
    /// minted/burned counts, the optional supply cap, and the royalty commitment. A
    /// collection exists only after an explicit [`Operation::CreateNftCollection`].
    /// This is a SEPARATE identity space from fungible `tokens` / `token_balances`.
    /// Committed by the state root through a dedicated Merkle sub-root
    /// (`NFT_COLLECTION_LEAF_DOMAIN`), so a create, mint, burn, pause, or authority
    /// change changes the state root. NFT items are NOT fungible balances and do not
    /// enter the native WEBC supply reconciliation. A `BTreeMap` keeps iteration
    /// deterministic in the hashed/consensus path.
    #[serde(default)]
    pub nft_collections: BTreeMap<NftCollectionId, NftCollection>,
    /// Native NFT items, keyed by [`NftId`] = `(collection, serial)` (Phase 13b, §15).
    ///
    /// The per-[`NftId`] key is what makes ordinary [`Operation::TransferNft`]
    /// parallel-schedulable: a transfer writes only the one item entry, never one
    /// global per-collection object. A burned item is REMOVED (there is no tombstone;
    /// the serial is never reminted because `next_serial` only grows), so the map
    /// holds exactly the live items. The item's `frozen` flag lives ON the item
    /// record (there is no separate freeze set). Committed by the state root through a
    /// dedicated Merkle sub-root (`NFT_ITEM_LEAF_DOMAIN`). For every collection,
    /// `minted_count - burned_count == count(live items)` (the per-collection item
    /// invariant, checked by [`ChainState::nft_collection_supply_report`]).
    #[serde(default)]
    pub nft_items: BTreeMap<NftId, NftItem>,
    /// Native units LOCKED across every live NFT collection's non-refundable creation
    /// deposit (Phase 13b, §15).
    ///
    /// Sum of every [`Operation::CreateNftCollection`]'s
    /// `ChainConfig::nft.creation_deposit`. Creation moves units here from the
    /// creator's liquid balance; they stay locked for the collection's life (a
    /// non-refundable anti-spam price). Reconciled by [`SupplyInvariantReport`] as a
    /// locked bucket and committed by the state root as a scalar (mirroring
    /// `token_deposits`). NFT items are a separate, non-fungible asset and are NOT
    /// part of this native reconciliation.
    #[serde(default)]
    pub nft_deposits: Amount,
    /// Native application-governance instances, keyed by [`GovernanceInstanceId`]
    /// (Phase 13c, §15).
    ///
    /// Each [`GovernanceInstance`] holds its creator, the fungible token that
    /// denominates voting weight, its immutable rule set, the native-WEBC `treasury`
    /// it controls, and the monotonic proposal-nonce counter. An instance exists
    /// only after an explicit [`Operation::CreateGovernanceInstance`]. Committed by
    /// the state root through a dedicated Merkle sub-root
    /// (`GOVERNANCE_INSTANCE_LEAF_DOMAIN`), so a create, a treasury fund, or a
    /// proposal open (which bumps the nonce) changes the state root. A `BTreeMap`
    /// keeps iteration deterministic in the hashed/consensus path.
    #[serde(default)]
    pub governance_instances: BTreeMap<GovernanceInstanceId, GovernanceInstance>,
    /// Native governance proposals, keyed by [`ProposalId`] (Phase 13c, §15).
    ///
    /// Each [`GovernanceProposal`] holds its instance, proposer, the snapshot weight
    /// token and rule set captured at open, its bounded typed action, epoch bounds,
    /// execution-availability epoch, lifecycle status, and running weight tallies.
    /// A proposal exists only after an explicit [`Operation::OpenProposal`] and is
    /// never removed (its terminal status is a permanent record). Committed by the
    /// state root through a dedicated Merkle sub-root
    /// (`GOVERNANCE_PROPOSAL_LEAF_DOMAIN`), so an open, a vote (tally), a resolve, or
    /// an execute changes the state root. A `BTreeMap` keeps iteration deterministic
    /// in the hashed/consensus path.
    #[serde(default)]
    pub governance_proposals: BTreeMap<ProposalId, GovernanceProposal>,
    /// Native governance vote locks, keyed by `(ProposalId, voter)` (Phase 13c, §15).
    ///
    /// Each [`VoteRecord`] holds one voter's choice and the weight-token units they
    /// LOCKED into the proposal escrow. Its presence prevents a second vote from the
    /// same voter (double-vote protection); an [`Operation::ReclaimVote`] removes it
    /// after the proposal resolves, so the map holds exactly the currently-locked
    /// votes. Committed by the state root through a dedicated Merkle sub-root
    /// (`GOVERNANCE_VOTE_LEAF_DOMAIN`). The locked weight itself lives in
    /// `token_balances` under the proposal's escrow address, so it is a token asset,
    /// not native WEBC, and does not enter the native supply reconciliation. A
    /// `BTreeMap` keeps iteration deterministic in the hashed/consensus path.
    #[serde(default)]
    pub governance_votes: BTreeMap<(ProposalId, Address), VoteRecord>,
    /// Native units LOCKED across every governance instance's non-refundable
    /// creation deposit (Phase 13c, §15).
    ///
    /// Sum of every [`Operation::CreateGovernanceInstance`]'s
    /// `ChainConfig::governance.creation_deposit`. Creation moves units here from the
    /// creator's liquid balance; they stay locked for the instance's life (a
    /// non-refundable anti-spam price). Reconciled by [`SupplyInvariantReport`] as a
    /// locked bucket and committed by the state root as a scalar (mirroring
    /// `token_deposits`/`nft_deposits`).
    #[serde(default)]
    pub governance_deposits: Amount,
    /// Native units held across every governance instance's treasury (Phase 13c, §15).
    ///
    /// Sum of every [`GovernanceInstance::treasury`]. [`Operation::FundGovernanceTreasury`]
    /// moves units here from a funder's liquid balance; a passed
    /// [`GovernanceAction::TreasuryTransfer`] moves them out to a recipient's liquid
    /// balance on execution. Reconciled by [`SupplyInvariantReport`] as a locked
    /// bucket and committed by the state root as a scalar (mirroring `mandate_escrow`).
    #[serde(default)]
    pub governance_treasury: Amount,
    /// Interim contract registry, keyed by `code_id` (Phase 7a, ADR-0014).
    ///
    /// Each [`ContractManifest`] describes one registered contract (its identity,
    /// application namespace, declared footprint, ABI/gas-schedule versions, and
    /// audited built-in handler). Addressed for declared access by
    /// `StateKey::module(code_id)`. Committed by the state root through a dedicated
    /// Merkle sub-root (`CONTRACT_LEAF_DOMAIN`), so registering a contract changes
    /// the state root. Holds no native units — the registration fee is burned — so
    /// it does not enter supply reconciliation. A `BTreeMap` keeps iteration
    /// deterministic in the hashed/consensus path.
    #[serde(default)]
    pub contracts: BTreeMap<Hash256, ContractManifest>,
    /// Interim contract application state, keyed by `(namespace, key_hash)` (Phase
    /// 7a, ADR-0014).
    ///
    /// A contract's state lives under `StateKey::application(namespace, key_hash)`
    /// for each `key_hash` in its manifest footprint; this map is the physical
    /// backing store. Committed by the state root through a dedicated Merkle
    /// sub-root (`CONTRACT_STATE_LEAF_DOMAIN`), so any contract write changes the
    /// state root. Holds only opaque contract-owned bytes, never native units, so
    /// it does not enter supply reconciliation. A `BTreeMap` keeps iteration
    /// deterministic in the hashed/consensus path.
    #[serde(default)]
    pub contract_state: BTreeMap<(Hash256, Hash256), ContractStateValue>,
    /// WASM contract registry, keyed by `code_id` (Phase 7b, ADR-0014 path (a)).
    ///
    /// Each [`WasmContractManifest`] describes one registered deployer-supplied
    /// WASM contract (identity, namespace, declared footprint, ABI/gas-schedule
    /// versions, and the code-hash binding to its bytecode). Addressed for declared
    /// access by `StateKey::module(code_id)` — the SAME reserved keyspace as native
    /// contracts, so a `code_id` is unique across both paths. Committed by the state
    /// root through a dedicated Merkle sub-root (`WASM_CONTRACT_LEAF_DOMAIN`), so
    /// registering a wasm contract changes the state root. Its application state
    /// shares the `contract_state` map above (namespaces are collision-resistant, so
    /// the two paths never alias). Holds no native units — the registration fee is
    /// burned — so it does not enter supply reconciliation. A `BTreeMap` keeps
    /// iteration deterministic in the hashed/consensus path.
    #[serde(default)]
    pub wasm_contracts: BTreeMap<Hash256, WasmContractManifest>,
    /// WASM contract bytecode, keyed by the owning contract's `code_id` (Phase 7b).
    ///
    /// Each contract owns its own immutable module bytes under `code_id`, committed
    /// by the state root through a dedicated Merkle sub-root (`WASM_CODE_LEAF_DOMAIN`)
    /// so uploading bytecode changes the state root. Bound to its manifest by
    /// `manifest.code_hash`. Holds only opaque module bytes, never native units, so
    /// it does not enter supply reconciliation. A `BTreeMap` keeps iteration
    /// deterministic in the hashed/consensus path.
    #[serde(default)]
    pub wasm_code: BTreeMap<Hash256, WasmBytecode>,
    /// Localized (per-application-namespace) base-fee state (Phase 6, §8 isolation).
    ///
    /// Maps a currently-congested application namespace to its [`NamespaceFeeState`]
    /// (its own EIP-1559 base fee). Object operations under a namespace are priced
    /// by this localized fee; account-scoped operations keep
    /// `current_base_fee_per_unit`. A namespace's fee adjusts each block from only
    /// that namespace's own usage vs `FeePolicy::per_namespace_target_units`, so one
    /// application's congestion never raises another's price. A namespace resting at
    /// `min_base_fee_per_unit` carries no entry (pricing at the floor is identical to
    /// having none), so the map holds only congested namespaces and stays bounded.
    /// Committed by the state root through a dedicated Merkle sub-root
    /// (`NAMESPACE_FEE_LEAF_DOMAIN`), so any localized-fee change changes the state
    /// root. Holds no native units — it changes the fee *rate*, never the accounting
    /// — so it does not enter supply reconciliation. A `BTreeMap` keeps iteration
    /// deterministic in the hashed/consensus path.
    #[serde(default)]
    pub namespace_fees: BTreeMap<Hash256, NamespaceFeeState>,
    pub validator_fee_pool: Amount,
    pub minted_supply: Amount,
    /// Gross issued supply captured at the start of the current inflation year.
    pub inflation_year_start_supply: Amount,
    pub current_base_fee_per_unit: u64,
    pub current_epoch: u64,
    /// Height of the block currently being built/imported, set at the start of
    /// `build_block` before transactions execute so height-dependent logic (DEX
    /// order deadlines, §15.37) reads a stable committed value on both build and
    /// import. Genesis leaves it `0` (the genesis "height"); the first block sets
    /// it to `1`. Committed by the state root so all nodes agree.
    #[serde(default)]
    pub current_height: u64,
    pub bridge_nonce: u64,
    /// Consensus timestamp (Unix ms) of the most recently applied block.
    ///
    /// E2: block timestamps must strictly increase. `build_block` rejects a
    /// candidate whose `timestamp_ms` is not greater than this, so a proposer
    /// cannot rewind or freeze consensus time (which future epoch/expiry/fee
    /// logic may read). Genesis leaves it `0`, so the first block's timestamp
    /// only has to be positive.
    #[serde(default)]
    pub last_block_timestamp_ms: u64,
}

/// Deterministic reconciliation of gross native issuance and all value buckets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyInvariantReport {
    /// Total native units ever issued by genesis and inflation.
    pub issued: Amount,
    /// Native units available for immediate transfer.
    pub liquid: Amount,
    /// Native units locked as validator operator stake.
    pub staked: Amount,
    /// Native units locked in delegation positions.
    pub delegated: Amount,
    /// Native principal admitted out of active stake but not yet claimed.
    pub unbonding: Amount,
    /// Native units locked for wrapped WEBC on external bridge domains.
    pub escrowed: Amount,
    /// Native units prepaid into non-default authorization lanes.
    pub lane_fees: Amount,
    /// Issued rewards that have not yet been claimed.
    pub pending_rewards: Amount,
    /// Collected fee rewards awaiting distribution.
    pub fee_reward_pool: Amount,
    /// Refundable native units locked as object storage deposits (§15.22).
    pub storage_deposits: Amount,
    /// Native units locked across every application fee-sponsor budget (§15.35).
    pub sponsor_budgets: Amount,
    /// Native units locked across every oracle reporter bond (§15.17).
    pub oracle_bonds: Amount,
    /// Native units locked across every feed's accrued read-fee revenue (§15.17).
    pub oracle_revenue: Amount,
    /// Native units locked across every live DEX order (§15.37).
    pub dex_escrow: Amount,
    /// Native units locked across every live agent mandate (§15.32).
    pub mandate_escrow: Amount,
    /// Native units locked across every live token's creation deposit (§15).
    pub token_deposits: Amount,
    /// Native units locked across every live NFT collection's creation deposit (§15).
    pub nft_deposits: Amount,
    /// Native units locked across every governance instance's creation deposit (§15).
    pub governance_deposits: Amount,
    /// Native units held across every governance instance's treasury (§15).
    pub governance_treasury: Amount,
    /// Native units permanently removed by base-fee burning.
    pub burned: Amount,
    /// Native units permanently removed by objective slashing.
    pub slashed: Amount,
    /// Checked sum of all non-duplicated buckets.
    pub accounted: Amount,
    /// Whether gross issuance exactly equals all buckets.
    pub balanced: bool,
}

/// Deterministic per-token supply reconciliation (Phase 13a, §15).
///
/// For any one token, the running [`TokenRecord::issued_supply`] must equal the
/// sum of every held balance. This report is a SEPARATE asset from native WEBC and
/// never enters [`SupplyInvariantReport`]; it exists so tests and RPC callers can
/// assert `sum(balances) == issued` after any token state transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSupplyReport {
    /// The token's recorded issued supply (total minted minus total burned).
    pub issued: Amount,
    /// Checked sum of every held balance for this token.
    pub held: Amount,
    /// Whether `issued` exactly equals `held`.
    pub balanced: bool,
}

/// Deterministic per-collection item reconciliation (Phase 13b, §15).
///
/// For any one collection, the running counters must satisfy
/// `minted_count - burned_count == count(live NftItems in that collection)`. NFT
/// items are NOT fungible balances and this report never enters
/// [`SupplyInvariantReport`]; it exists so tests and RPC callers can assert the
/// per-collection item invariant after any NFT state transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftCollectionSupplyReport {
    /// Total items ever minted in this collection.
    pub minted: u64,
    /// Total items ever burned in this collection.
    pub burned: u64,
    /// `minted - burned`: the number of items that should be live.
    pub expected_live: u64,
    /// Actual count of live [`NftItem`] entries for this collection.
    pub live_items: u64,
    /// Whether `expected_live` exactly equals `live_items`.
    pub balanced: bool,
}

/// Validated fields for an outgoing bridge message before nonce assignment.
///
/// This private value prevents positional argument mix-ups between two chains,
/// sender/recipient byte strings, and amount/source transaction fields.
struct OutgoingBridgeMessage {
    source_chain: ExternalChain,
    destination_chain: ExternalChain,
    asset: AssetId,
    sender: Vec<u8>,
    recipient: Vec<u8>,
    amount: Amount,
    source_tx: Hash256,
}

/// Incoming bridge action fixes which asset class may change on WEBC.
enum IncomingBridgeAction {
    /// Mint a representation of an externally locked asset.
    MintRepresentation,
    /// Release native WEBC previously escrowed for one external domain.
    ReleaseNative,
}

/// Which account authority approved a verified transaction.
///
/// Returned by `verify_transaction_authorization` and consumed by execution so
/// session-key constraint enforcement runs only for session-signed transactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransactionAuthorization {
    /// The account's active transaction key, or its legacy address-derived key.
    AccountKey,
    /// A registered constrained session key, identified for constraint checks.
    SessionKey(SessionKeyId),
    /// A recovery/rotation transaction whose envelope is signed by the *new*
    /// active key. Its real authority is the post-quantum root signature, which
    /// the `RotateActiveTransactionKey` arm verifies before mutating the policy.
    /// Produced only for that operation and only when the signing key equals the
    /// proposed new key, so a stranger's key can never take this path.
    PostQuantumRootRecovery,
}

impl Default for ChainState {
    fn default() -> Self {
        Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            accounts: BTreeMap::new(),
            authorization_policies: BTreeMap::new(),
            authorization_lanes: BTreeMap::new(),
            session_keys: BTreeMap::new(),
            sponsor_grants: SponsorGrantBookV1::default(),
            objects: BTreeMap::new(),
            validators: BTreeMap::new(),
            delegations: BTreeMap::new(),
            unbonding: UnbondingQueue::default(),
            asset_balances: BTreeMap::new(),
            native_bridge_escrow: BTreeMap::new(),
            processed_bridge_messages: BTreeSet::new(),
            processed_slashing_evidence: BTreeSet::new(),
            burned_fees: Amount::ZERO,
            slashed_units: Amount::ZERO,
            storage_deposits: Amount::ZERO,
            sponsors: BTreeMap::new(),
            sponsor_budgets: Amount::ZERO,
            namespaces: BTreeMap::new(),
            oracle_feeds: BTreeMap::new(),
            oracle_reporters: BTreeMap::new(),
            oracle_bonds: Amount::ZERO,
            oracle_revenue: Amount::ZERO,
            dex_orders: BTreeMap::new(),
            dex_escrow: Amount::ZERO,
            mandates: BTreeMap::new(),
            mandate_escrow: Amount::ZERO,
            services: BTreeMap::new(),
            tokens: BTreeMap::new(),
            token_balances: BTreeMap::new(),
            frozen_token_accounts: BTreeSet::new(),
            token_deposits: Amount::ZERO,
            nft_collections: BTreeMap::new(),
            nft_items: BTreeMap::new(),
            nft_deposits: Amount::ZERO,
            governance_instances: BTreeMap::new(),
            governance_proposals: BTreeMap::new(),
            governance_votes: BTreeMap::new(),
            governance_deposits: Amount::ZERO,
            governance_treasury: Amount::ZERO,
            contracts: BTreeMap::new(),
            contract_state: BTreeMap::new(),
            wasm_contracts: BTreeMap::new(),
            wasm_code: BTreeMap::new(),
            namespace_fees: BTreeMap::new(),
            validator_fee_pool: Amount::ZERO,
            minted_supply: Amount::ZERO,
            inflation_year_start_supply: Amount::ZERO,
            current_base_fee_per_unit: 0,
            current_epoch: 0,
            current_height: 0,
            bridge_nonce: 0,
            last_block_timestamp_ms: 0,
        }
    }
}

/// Caller-owned logical access and event sinks for one native action.
///
/// Fee, nonce, authorization, and overlay commit policy deliberately remain
/// outside this bundle so protocol-1 and protocol-2 envelopes can share native
/// state transitions without sharing their different transaction semantics.
pub(crate) struct NativeActionEffects<'a> {
    access: &'a mut StateAccessRecorder,
    events: &'a mut Vec<Event>,
}

impl<'a> NativeActionEffects<'a> {
    /// Borrows the access recorder and raw event sink owned by the caller.
    pub(crate) const fn new(
        access: &'a mut StateAccessRecorder,
        events: &'a mut Vec<Event>,
    ) -> Self {
        Self { access, events }
    }
}

/// The resolved specification of one contract invocation handed to
/// [`ChainState::run_contract_call`].
///
/// Groups the per-call parameters the native and wasm invoke paths each compute,
/// so the shared execution core takes one named descriptor instead of a long,
/// error-prone positional argument list. Everything here is borrowed for the
/// duration of the single call.
struct ContractCall<'a> {
    /// Application namespace the call's state lives under.
    namespace: Hash256,
    /// The contract's declared footprint keys (equal to the committed manifest's).
    footprint: &'a [Hash256],
    /// The resolved handler — an audited built-in, or a [`WasmContract`] over
    /// uploaded bytecode. The core is engine-agnostic; it only calls `Contract`.
    handler: &'a dyn Contract,
    /// Bounded opaque input forwarded verbatim to the handler.
    input: &'a [u8],
    /// Admission units already priced into the fee, seeding the gas meter.
    admission_units: u64,
    /// The sender's authorized gas cap for the whole call.
    gas_limit: u64,
}

impl ChainState {
    /// Prunes expired V5 sponsor records at one consensus block boundary.
    ///
    /// Grants remain valid at their inclusive expiry height. Materialization
    /// units bound ingress while the derived expiry index limits deterministic
    /// cleanup to a fixed number per block. The caller's whole-block overlay
    /// supplies rollback if this detects corrupted durable state.
    #[cfg(test)]
    pub(crate) fn prune_expired_sponsor_grants_v1(
        &mut self,
        height: crate::BlockHeight,
    ) -> Result<usize, ChainError> {
        self.sponsor_grants
            .prune_expired(height)
            .map_err(|_error: SponsorGrantBookError| ChainError::InvalidSponsorGrantState)
    }

    /// Creates empty deterministic state for one supported protocol config.
    ///
    /// This operation allocates no supply and performs no external I/O. Unknown
    /// versions fail before state exists so a node cannot silently interpret a
    /// future genesis using version-1 rules.
    pub fn new(config: &ChainConfig) -> Result<Self, ChainError> {
        if config.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(ChainError::UnsupportedProtocolVersion {
                actual: config.protocol_version,
            });
        }
        Ok(Self {
            protocol_version: config.protocol_version,
            chain_id: config.chain_id.clone(),
            current_base_fee_per_unit: config.fee_policy.min_base_fee_per_unit,
            ..Self::default()
        })
    }

    /// Builds initial state from a versioned genesis allocation.
    ///
    /// Genesis data is consensus-critical hostile input. Failure leaves no
    /// partially constructed state and returns a typed error. Phase 1 adds full
    /// supply reconciliation and prevents stake from being counted twice.
    pub fn from_genesis(genesis: &GenesisConfig) -> Result<Self, ChainError> {
        let mut state = Self::new(&genesis.chain)?;
        // Reject a malformed sponsorship window (zero epochs) before any state
        // exists, so a chain never runs with an undefined "per day" boundary.
        genesis.chain.sponsorship.validate()?;
        // Reject a malformed oracle config (zero settlement cadence or liveness
        // window) so settlement never divides by zero and liveness is well-defined.
        genesis.chain.oracle.validate()?;
        // Reject a malformed DEX config (per-fill fee above 100%) so settlement can
        // never carve more than the proceeds and underflow.
        genesis.chain.dex.validate()?;
        // Reject a malformed mandate config (zero rate-limit window) so the per-day
        // rate limit has a well-defined, non-divide-by-zero window boundary.
        genesis.chain.mandate.validate()?;

        for account in &genesis.accounts {
            if state.accounts.contains_key(&account.address) {
                return Err(ChainError::DuplicateGenesisAccount(account.address));
            }
            state
                .accounts
                .insert(account.address, Account::with_balance(account.balance));
            state.minted_supply = state
                .minted_supply
                .checked_add(account.balance)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }

        for genesis_validator in &genesis.validators {
            if state.validators.contains_key(&genesis_validator.operator) {
                return Err(ChainError::ValidatorAlreadyExists(
                    genesis_validator.operator,
                ));
            }
            if genesis_validator.commission_bps > genesis.chain.staking.max_commission_bps {
                return Err(ChainError::CommissionTooHigh);
            }
            if genesis_validator.bootstrap {
                return Err(ChainError::BootstrapDisabled);
            }
            if genesis_validator.self_stake < genesis.chain.staking.min_validator_self_stake {
                return Err(ChainError::StakeTooSmall);
            }

            state.debit_native(genesis_validator.operator, genesis_validator.self_stake)?;
            let account = state.account_mut(genesis_validator.operator)?;
            account.staked = account
                .staked
                .checked_add(genesis_validator.self_stake)
                .ok_or(ChainError::ArithmeticOverflow)?;

            state.validators.insert(
                genesis_validator.operator,
                Validator {
                    operator: genesis_validator.operator,
                    consensus_key: genesis_validator.consensus_key,
                    self_stake: genesis_validator.self_stake,
                    delegated_stake: Amount::ZERO,
                    commission_bps: genesis_validator.commission_bps,
                    status: ValidatorStatus::PendingActivation,
                    bootstrap: false,
                    accumulated_rewards: Amount::ZERO,
                },
            );
            let validator = state
                .validators
                .get_mut(&genesis_validator.operator)
                .ok_or(ChainError::ValidatorNotFound(genesis_validator.operator))?;
            validator.refresh_stake_status(&genesis.chain.staking)?;
        }

        state.inflation_year_start_supply = state.minted_supply;

        // G1: pin the declared total supply. `minted_supply` is the checked sum
        // of all genesis account balances; staking only relocates units between
        // an account's liquid and staked buckets and never changes gross
        // issuance, so this is the single place a wrong-total genesis is caught.
        // The `balanced` invariant below cannot catch it because it is
        // tautological (it re-sums the very buckets `minted_supply` was defined
        // from). Production genesis sets `Some(GENESIS_TOTAL_SUPPLY)`; trusted
        // in-crate fixtures leave it `None`.
        if let Some(expected) = genesis.chain.expected_total_supply {
            if state.minted_supply != expected {
                return Err(ChainError::GenesisSupplyMismatch {
                    expected,
                    actual: state.minted_supply,
                });
            }
        }

        if !state.supply_invariant_report()?.balanced {
            return Err(ChainError::SupplyInvariantViolation);
        }

        Ok(state)
    }

    /// Reconciles native supply without counting mirrored validator/delegation indexes twice.
    pub fn supply_invariant_report(&self) -> Result<SupplyInvariantReport, ChainError> {
        let mut liquid = Amount::ZERO;
        let mut staked = Amount::ZERO;
        let mut delegated = Amount::ZERO;
        let mut unbonding = Amount::ZERO;
        for account in self.accounts.values() {
            liquid = liquid
                .checked_add(account.balance)
                .ok_or(ChainError::ArithmeticOverflow)?;
            staked = staked
                .checked_add(account.staked)
                .ok_or(ChainError::ArithmeticOverflow)?;
            delegated = delegated
                .checked_add(account.delegated)
                .ok_or(ChainError::ArithmeticOverflow)?;
            unbonding = unbonding
                .checked_add(account.unbonding)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        let mut pending_rewards = Amount::ZERO;
        for validator in self.validators.values() {
            pending_rewards = pending_rewards
                .checked_add(validator.accumulated_rewards)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        for delegation in self.delegations.values() {
            pending_rewards = pending_rewards
                .checked_add(delegation.accumulated_rewards)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        let escrowed =
            self.native_bridge_escrow
                .values()
                .try_fold(Amount::ZERO, |total, amount| {
                    total
                        .checked_add(*amount)
                        .ok_or(ChainError::ArithmeticOverflow)
                })?;
        let lane_fees =
            self.authorization_lanes
                .values()
                .try_fold(Amount::ZERO, |total, lane| {
                    total
                        .checked_add(lane.fee_balance)
                        .ok_or(ChainError::ArithmeticOverflow)
                })?;
        let accounted = liquid
            .checked_add(staked)
            .and_then(|amount| amount.checked_add(delegated))
            .and_then(|amount| amount.checked_add(unbonding))
            .and_then(|amount| amount.checked_add(escrowed))
            .and_then(|amount| amount.checked_add(lane_fees))
            .and_then(|amount| amount.checked_add(pending_rewards))
            .and_then(|amount| amount.checked_add(self.validator_fee_pool))
            .and_then(|amount| amount.checked_add(self.storage_deposits))
            .and_then(|amount| amount.checked_add(self.sponsor_budgets))
            .and_then(|amount| amount.checked_add(self.oracle_bonds))
            .and_then(|amount| amount.checked_add(self.oracle_revenue))
            .and_then(|amount| amount.checked_add(self.dex_escrow))
            .and_then(|amount| amount.checked_add(self.mandate_escrow))
            .and_then(|amount| amount.checked_add(self.token_deposits))
            .and_then(|amount| amount.checked_add(self.nft_deposits))
            .and_then(|amount| amount.checked_add(self.governance_deposits))
            .and_then(|amount| amount.checked_add(self.governance_treasury))
            .and_then(|amount| amount.checked_add(self.burned_fees))
            .and_then(|amount| amount.checked_add(self.slashed_units))
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(SupplyInvariantReport {
            issued: self.minted_supply,
            liquid,
            staked,
            delegated,
            unbonding,
            escrowed,
            lane_fees,
            pending_rewards,
            fee_reward_pool: self.validator_fee_pool,
            storage_deposits: self.storage_deposits,
            sponsor_budgets: self.sponsor_budgets,
            oracle_bonds: self.oracle_bonds,
            oracle_revenue: self.oracle_revenue,
            dex_escrow: self.dex_escrow,
            mandate_escrow: self.mandate_escrow,
            token_deposits: self.token_deposits,
            nft_deposits: self.nft_deposits,
            governance_deposits: self.governance_deposits,
            governance_treasury: self.governance_treasury,
            burned: self.burned_fees,
            slashed: self.slashed_units,
            accounted,
            balanced: accounted == self.minted_supply,
        })
    }

    /// Executes a signed transaction atomically.
    ///
    /// The method clones state, applies all checks/mutations, and commits only on
    /// success. This is slower than production storage but safer for a prototype
    /// because invalid transactions cannot leave partial changes behind.
    pub fn execute_transaction(
        &mut self,
        tx: &Transaction,
        config: &ChainConfig,
    ) -> Result<Receipt, ChainError> {
        if tx.protocol_version != config.protocol_version {
            return Err(ChainError::UnsupportedProtocolVersion {
                actual: tx.protocol_version,
            });
        }
        if tx.chain_id != config.chain_id {
            return Err(ChainError::TransactionChainIdMismatch);
        }
        tx.verify()?;
        let authorization = self.verify_transaction_authorization(tx)?;
        let tx_hash = tx.hash()?;
        let mut next = self.clone();
        let receipt = next.apply_verified_transaction(tx, config, tx_hash, authorization)?;
        *self = next;
        Ok(receipt)
    }

    /// Verifies the stateful sender/key binding before any fee or nonce change.
    ///
    /// Accounts without a policy are restricted to revision zero and the
    /// address-derived Ed25519 key so only the existing owner can install the
    /// first policy. Installed accounts require an exact revision and active
    /// key match; address derivation is no longer consulted, allowing later key
    /// rotation without changing the stable account address.
    fn verify_transaction_authorization(
        &self,
        tx: &Transaction,
    ) -> Result<TransactionAuthorization, ChainError> {
        tx.authorization_policy_revision.validate()?;
        let Some(policy) = self.authorization_policies.get(&tx.sender) else {
            if tx.authorization_policy_revision != LEGACY_AUTHORIZATION_POLICY_REVISION {
                return Err(ChainError::AuthorizationPolicyRevisionMismatch {
                    expected: LEGACY_AUTHORIZATION_POLICY_REVISION.get(),
                    actual: tx.authorization_policy_revision.get(),
                });
            }
            if Address::from_public_key(&tx.public_key) != tx.sender {
                return Err(ChainError::SenderPublicKeyMismatch);
            }
            return Ok(TransactionAuthorization::AccountKey);
        };

        policy.validate()?;
        if tx.authorization_policy_revision != policy.revision() {
            return Err(ChainError::AuthorizationPolicyRevisionMismatch {
                expected: policy.revision().get(),
                actual: tx.authorization_policy_revision.get(),
            });
        }
        if &tx.public_key == policy.active_transaction_key() {
            return Ok(TransactionAuthorization::AccountKey);
        }

        // Recovery/rotation may be signed by the *new* key so a lost or
        // compromised active key can still be replaced. The envelope signature
        // only proves control of the proposed new key here; the real authority
        // is the post-quantum root signature verified in the rotation arm. Any
        // other signer for this operation is rejected, and this path is reachable
        // for no other operation.
        if let Operation::RotateActiveTransactionKey {
            new_active_transaction_key,
            ..
        } = &tx.operation
        {
            if &tx.public_key == new_active_transaction_key {
                return Ok(TransactionAuthorization::PostQuantumRootRecovery);
            }
            return Err(ChainError::AuthorizationKeyMismatch);
        }

        // The active key did not sign. The only other acceptable signer is a
        // registered, policy-current, lane-bound session key. Expiry and spend
        // limits are enforced in execution, where the operation and epoch are in
        // hand and rollback is atomic; here we only bind the key to the account.
        let id = SessionKeyId::derive(&tx.public_key);
        let Some(session) = self.session_keys.get(&(tx.sender, id)) else {
            return Err(ChainError::AuthorizationKeyMismatch);
        };
        if session.session_public_key != tx.public_key
            || session.policy_revision != policy.revision()
        {
            return Err(ChainError::AuthorizationKeyMismatch);
        }
        if tx.authorization_lane != session.constraints.authorization_lane {
            return Err(ChainError::SessionKeyLaneMismatch);
        }
        Ok(TransactionAuthorization::SessionKey(id))
    }

    /// The base fee in base units per execution unit that prices `operation`.
    ///
    /// Object operations are priced by their namespace's localized base fee (Phase 6
    /// §8); every other operation keeps the global `current_base_fee_per_unit`. Both
    /// are read as block-constant values (localized fees are only adjusted by
    /// [`ChainState::finish_block`] after every transaction has executed), so all
    /// transactions in a block observe a single stable price.
    pub fn base_fee_per_unit_for(&self, operation: &Operation, config: &ChainConfig) -> u64 {
        match operation.fee_namespace() {
            Some(namespace) => self.localized_base_fee_per_unit(&namespace, config),
            None => self.current_base_fee_per_unit,
        }
    }

    /// A namespace's current localized base fee, floored at the network minimum.
    ///
    /// A namespace with no record is priced at `min_base_fee_per_unit` — pricing at
    /// the floor is what "no record" means — so an uncongested namespace is charged
    /// exactly the network minimum and is never affected by any other namespace.
    fn localized_base_fee_per_unit(&self, namespace: &Hash256, config: &ChainConfig) -> u64 {
        self.namespace_fees
            .get(namespace)
            .map(|state| state.base_fee_per_unit)
            .unwrap_or(config.fee_policy.min_base_fee_per_unit)
            .max(config.fee_policy.min_base_fee_per_unit)
    }

    /// Commits the next deterministic base fees after a completed block.
    ///
    /// `units_used` is the block's total execution units (must not exceed the
    /// configured block maximum); `namespace_units` is each namespace's own
    /// execution-unit usage this block. The global base fee reacts to total
    /// fullness; each namespace's localized base fee reacts to only its own usage,
    /// so one application's congestion never moves another's price. Invalid policy
    /// or overflow leaves state unchanged and returns an error to the whole-block
    /// overlay.
    pub fn finish_block(
        &mut self,
        units_used: u64,
        namespace_units: &BTreeMap<Hash256, u64>,
        config: &ChainConfig,
    ) -> Result<(), ChainError> {
        self.current_base_fee_per_unit = next_base_fee(
            self.current_base_fee_per_unit,
            units_used,
            &config.fee_policy,
        )?;
        self.adjust_namespace_fees(namespace_units, config)?;
        Ok(())
    }

    /// Re-prices every congested namespace from its own per-block usage.
    ///
    /// Adjusts the union of currently-tracked namespaces (so idle ones decay) and
    /// namespaces used this block (so newly hot ones rise), each by the same
    /// EIP-1559 rule as the global fee but against `per_namespace_target_units`
    /// using only that namespace's own units. A namespace whose new fee returns to
    /// the network floor loses its record, keeping the committed map bounded to
    /// currently-congested namespaces. Deterministic ordered iteration.
    fn adjust_namespace_fees(
        &mut self,
        namespace_units: &BTreeMap<Hash256, u64>,
        config: &ChainConfig,
    ) -> Result<(), ChainError> {
        let min = config.fee_policy.min_base_fee_per_unit;
        let mut namespaces: BTreeSet<Hash256> = self.namespace_fees.keys().copied().collect();
        namespaces.extend(namespace_units.keys().copied());
        for namespace in namespaces {
            let current = self
                .namespace_fees
                .get(&namespace)
                .map(|state| state.base_fee_per_unit)
                .unwrap_or(min)
                .max(min);
            let used = namespace_units.get(&namespace).copied().unwrap_or(0);
            let next = next_localized_base_fee(current, used, &config.fee_policy)?;
            if next <= min {
                // Back at the network floor: identical to having no record, so drop
                // it to keep the committed map bounded to congested namespaces.
                self.namespace_fees.remove(&namespace);
            } else {
                self.namespace_fees.insert(
                    namespace,
                    NamespaceFeeState {
                        base_fee_per_unit: next,
                    },
                );
            }
        }
        Ok(())
    }

    pub fn distribute_epoch_rewards(
        &mut self,
        config: &ChainConfig,
    ) -> Result<Vec<Event>, ChainError> {
        let mut next = self.clone();
        let events = next.apply_epoch_rewards(config)?;
        *self = next;
        Ok(events)
    }

    fn apply_epoch_rewards(&mut self, config: &ChainConfig) -> Result<Vec<Event>, ChainError> {
        let periods_per_year = config.inflation.validated_periods_per_year()?;
        if self.current_epoch.is_multiple_of(periods_per_year) {
            self.inflation_year_start_supply = self.minted_supply;
        }

        // Total active stake is needed both for reward weighting and to size the
        // stake-keyed bootstrap budget, so it is computed before the issuance.
        let total_active_stake = self
            .validators
            .values()
            .filter(|validator| validator.is_active())
            .try_fold(Amount::ZERO, |sum, validator| {
                sum.checked_add(validator.total_stake()?)
                    .ok_or(ChainError::ArithmeticOverflow)
            })?;

        // Base schedule budget for this period. During a configured, not-yet-sunset
        // bootstrap phase (§15.2), issuance is instead keyed to staked amount and
        // capped by this base budget, so a thin early staking base cannot capture
        // the full base issuance. Supply conservation is unaffected: whatever the
        // issued `inflation` is, `minted_supply` grows by exactly it and the F1
        // distribution accounts for exactly it (see below).
        let base_budget = config
            .inflation
            .reward_for_period(self.inflation_year_start_supply, self.current_epoch)?;
        let inflation = match &config.bootstrap_issuance {
            Some(bootstrap) if bootstrap.is_active(self.current_epoch) => {
                bootstrap.budget_for_period(total_active_stake, periods_per_year, base_budget)?
            }
            _ => base_budget,
        };
        let total_reward = inflation
            .checked_add(self.validator_fee_pool)
            .ok_or(ChainError::ArithmeticOverflow)?;

        if total_reward.is_zero() {
            return self.finish_epoch(config, Amount::ZERO);
        }

        if total_active_stake.is_zero() {
            // If no one is eligible, avoid minting rewards into nowhere. Fees stay
            // in the pool and can be distributed once validators exist.
            return self.finish_epoch(config, Amount::ZERO);
        }

        let active_validators = self
            .validators
            .values()
            .filter(|validator| validator.is_active())
            .map(|validator| {
                Ok((
                    validator.operator,
                    validator.total_stake()?,
                    validator.self_stake,
                    validator.commission_bps,
                ))
            })
            .collect::<Result<Vec<_>, ChainError>>()?;

        // F1: sum every validator's floored share so the outer cross-validator
        // remainder can be carried forward instead of dropped (see below).
        let mut distributed_total = Amount::ZERO;
        for (validator_address, validator_total_stake, self_stake, commission_bps) in
            active_validators
        {
            let validator_share = total_reward
                .checked_mul_ratio(validator_total_stake.0, total_active_stake.0)
                .ok_or(ChainError::ArithmeticOverflow)?;
            distributed_total = distributed_total
                .checked_add(validator_share)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let commission = validator_share
                .checked_mul_bps(commission_bps)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let staker_reward_pool = validator_share
                .checked_sub(commission)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let self_reward = if validator_total_stake.is_zero() {
                Amount::ZERO
            } else {
                staker_reward_pool
                    .checked_mul_ratio(self_stake.0, validator_total_stake.0)
                    .ok_or(ChainError::ArithmeticOverflow)?
            };

            let mut distributed = commission
                .checked_add(self_reward)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let mut delegation_rewards = Vec::new();
            for delegation in self
                .delegations
                .values()
                .filter(|delegation| delegation.validator == validator_address)
            {
                let reward = if validator_total_stake.is_zero() {
                    Amount::ZERO
                } else {
                    staker_reward_pool
                        .checked_mul_ratio(delegation.amount.0, validator_total_stake.0)
                        .ok_or(ChainError::ArithmeticOverflow)?
                };
                distributed = distributed
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                delegation_rewards.push((delegation.delegator, reward));
            }

            // Integer division can leave tiny dust. Assign it to the validator so
            // total rewards are conserved and accounting remains deterministic.
            let dust = validator_share
                .checked_sub(distributed)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let validator_reward = commission
                .checked_add(self_reward)
                .and_then(|reward| reward.checked_add(dust))
                .ok_or(ChainError::ArithmeticOverflow)?;

            let validator = self
                .validators
                .get_mut(&validator_address)
                .ok_or(ChainError::ValidatorNotFound(validator_address))?;
            validator.accumulated_rewards = validator
                .accumulated_rewards
                .checked_add(validator_reward)
                .ok_or(ChainError::ArithmeticOverflow)?;

            for (delegator, reward) in delegation_rewards {
                let delegation = self
                    .delegations
                    .get_mut(&(delegator, validator_address))
                    .ok_or(ChainError::DelegationNotFound)?;
                delegation.accumulated_rewards = delegation
                    .accumulated_rewards
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
            }
        }

        self.minted_supply = self
            .minted_supply
            .checked_add(inflation)
            .ok_or(ChainError::ArithmeticOverflow)?;
        // F1: retain the outer division remainder (total_reward minus the sum of
        // the floored per-validator shares) in the fee pool, carrying it to the
        // next epoch. Each validator's share is fully distributed internally (its
        // inner dust is recaptured to the validator), but the SUM of floored
        // shares is <= total_reward; the difference is 0..num_validators-1 base
        // units. Zeroing the pool while minting the full inflation would destroy
        // those units and break supply conservation (accounted < minted_supply)
        // by that amount every epoch. Carrying it keeps
        // accounted_new == minted_old + inflation == minted_new.
        let outer_leftover = total_reward
            .checked_sub(distributed_total)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.validator_fee_pool = outer_leftover;
        self.finish_epoch(config, total_reward)
    }

    fn finish_epoch(
        &mut self,
        config: &ChainConfig,
        distributed_reward: Amount,
    ) -> Result<Vec<Event>, ChainError> {
        let event_epoch = self.current_epoch;
        // Native oracle read-fee settlement (§15.17) runs at the epoch boundary on
        // the just-completed epoch, before it is incremented, so a report's
        // liveness is measured against the settlement epoch. Gated by the
        // configured cadence. Supply-neutral (revenue pool -> reporter liquid, with
        // the division remainder carried), so it does not disturb the reward math
        // above. Runs on the same whole-epoch overlay, so any failure rolls the
        // epoch advance back atomically.
        let oracle_events = if config.oracle.is_settlement_epoch(self.current_epoch) {
            self.settle_oracle_feeds(config, self.current_epoch)?
        } else {
            Vec::new()
        };
        let next_epoch = self
            .current_epoch
            .checked_add(1)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let transitions = self.unbonding.advance_epoch(
            Epoch::new(next_epoch),
            config.staking.max_unbonding_units_per_epoch,
            config.staking.unbonding_cooldown_epochs,
            config.staking.slashable_unbonding_epochs,
        )?;
        let mut events = vec![Event::EpochRewardsDistributed {
            epoch: event_epoch,
            total: distributed_reward,
        }];
        events.extend(oracle_events);
        for transition in transitions {
            match transition {
                UnbondingTransition::Admitted {
                    request_id,
                    owner,
                    validator,
                    kind,
                    amount,
                } => {
                    let validator_state = self
                        .validators
                        .get_mut(&validator)
                        .ok_or(ChainError::ValidatorNotFound(validator))?;
                    match kind {
                        UnbondingKind::Delegation => {
                            let delegation = self
                                .delegations
                                .get_mut(&(owner, validator))
                                .ok_or(ChainError::DelegationNotFound)?;
                            delegation.amount = delegation
                                .amount
                                .checked_sub(amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                            validator_state.delegated_stake = validator_state
                                .delegated_stake
                                .checked_sub(amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                        }
                        UnbondingKind::OperatorStake => {
                            validator_state.self_stake = validator_state
                                .self_stake
                                .checked_sub(amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                        }
                    }
                    validator_state.refresh_stake_status(&config.staking)?;
                    let account = self.account_mut(owner)?;
                    match kind {
                        UnbondingKind::Delegation => {
                            account.delegated = account
                                .delegated
                                .checked_sub(amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                        }
                        UnbondingKind::OperatorStake => {
                            account.staked = account
                                .staked
                                .checked_sub(amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                        }
                    }
                    account.unbonding = account
                        .unbonding
                        .checked_add(amount)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    events.push(Event::UnbondingAdmitted {
                        request_id,
                        delegator: owner,
                        validator,
                        kind,
                        amount,
                    });
                }
                UnbondingTransition::Matured {
                    request_id,
                    owner,
                    validator,
                    kind,
                    amount,
                } => events.push(Event::UnbondingMatured {
                    request_id,
                    delegator: owner,
                    validator,
                    kind,
                    amount,
                }),
            }
        }
        self.current_epoch = next_epoch;

        // Epoch-boundary pruning of expired session keys. A key is usable while
        // `current_epoch <= expires_after_epoch`; once the epoch passes it, the
        // key can never authorize again (epochs only ever increase), so removing
        // it is safe. The use-time check already rejects expired keys, so this
        // changes no authorization outcome — it only reclaims space and bounds
        // session-key map growth. It is deterministic: `next_epoch` is committed
        // state, iteration is sorted, and it is a pure function of the snapshot,
        // so replaying from a serialized state prunes identically.
        let expired: Vec<(Address, SessionKeyId)> = self
            .session_keys
            .iter()
            .filter(|(_, session)| session.expires_after_epoch.get() < next_epoch)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.session_keys.remove(&key);
            events.push(Event::SessionKeyExpired {
                owner: key.0,
                session_key: key.1,
            });
        }

        Ok(events)
    }

    /// Commits to all major state subtrees and global accounting counters.
    ///
    /// The account subtree is exposed separately through `account_root()` so
    /// browser light wallets can verify balances. Other roots are included to
    /// prevent validators from committing only account balances while hiding
    /// validator, delegation, asset, bridge, or fee state changes.
    pub fn state_root(&self) -> Result<Hash256, ChainError> {
        #[derive(Serialize)]
        struct StateCommitment {
            domain: &'static str,
            protocol_version: ProtocolVersion,
            chain_id: ChainId,
            account_root: Hash256,
            authorization_policy_root: Hash256,
            authorization_lane_root: Hash256,
            session_key_root: Hash256,
            #[serde(skip_serializing_if = "Option::is_none")]
            sponsor_grant_root: Option<Hash256>,
            object_root: Hash256,
            validator_root: Hash256,
            delegation_root: Hash256,
            asset_root: Hash256,
            native_bridge_escrow_root: Hash256,
            processed_bridge_root: Hash256,
            processed_slashing_root: Hash256,
            unbonding_root: Hash256,
            sponsor_root: Hash256,
            namespace_root: Hash256,
            oracle_feed_root: Hash256,
            oracle_reporter_root: Hash256,
            dex_order_root: Hash256,
            mandate_root: Hash256,
            service_registry_root: Hash256,
            token_root: Hash256,
            token_balance_root: Hash256,
            frozen_token_root: Hash256,
            nft_collection_root: Hash256,
            nft_item_root: Hash256,
            governance_instance_root: Hash256,
            governance_proposal_root: Hash256,
            governance_vote_root: Hash256,
            contract_root: Hash256,
            contract_state_root: Hash256,
            wasm_contract_root: Hash256,
            wasm_code_root: Hash256,
            namespace_fee_root: Hash256,
            burned_fees: Amount,
            slashed_units: Amount,
            storage_deposits: Amount,
            sponsor_budgets: Amount,
            oracle_bonds: Amount,
            oracle_revenue: Amount,
            dex_escrow: Amount,
            mandate_escrow: Amount,
            token_deposits: Amount,
            nft_deposits: Amount,
            governance_deposits: Amount,
            governance_treasury: Amount,
            validator_fee_pool: Amount,
            minted_supply: Amount,
            inflation_year_start_supply: Amount,
            current_base_fee_per_unit: u64,
            current_epoch: u64,
            current_height: u64,
            bridge_nonce: u64,
            last_block_timestamp_ms: u64,
        }

        let (domain, sponsor_grant_root) =
            if self.protocol_version == crate::TRANSACTION_V5_PROTOCOL_VERSION {
                (
                    "WEBC_STATE_COMMITMENT_V21",
                    Some(ordered_value_root(
                        b"WEBC_SPONSOR_GRANT_STATE_LEAF_V2",
                        self.sponsor_grants.iter(),
                    )?),
                )
            } else if self.protocol_version == ProtocolVersion::new(1) {
                if !self.sponsor_grants.is_empty() {
                    return Err(ChainError::InvalidSponsorGrantState);
                }
                ("WEBC_STATE_COMMITMENT_V20", None)
            } else {
                return Err(ChainError::UnsupportedProtocolVersion {
                    actual: self.protocol_version,
                });
            };

        let commitment = StateCommitment {
            // V19 adds native application governance (Phase 13c, §15): the
            // `governance_instance_root` sub-root commits every instance record
            // (creator, weight token, immutable config, native treasury, proposal
            // nonce), the `governance_proposal_root` sub-root commits every proposal
            // (instance, proposer, weight/config snapshot, bounded action, epoch
            // bounds, eta, status, tallies), and the `governance_vote_root` sub-root
            // commits every live `((proposal, voter), VoteRecord)` lock, while the
            // `governance_deposits` scalar commits the aggregate locked native
            // creation-deposit bucket and the `governance_treasury` scalar commits the
            // aggregate native treasury bucket (mirroring how
            // `token_deposits`/`mandate_escrow` pair with their sub-roots). So a
            // create / fund / open / vote / resolve / execute / reclaim always changes
            // the state root. Voting WEIGHT is locked weight-token balance (a token
            // asset committed by `token_balance_root`), so it never enters the native
            // supply reconciliation; the only native units that move are the ordinary
            // fee, the creation deposit, and the treasury fund/payout. The domain bump
            // is a deliberate consensus-format change; no external fixture pins a prior
            // root.
            // V18 adds the native NFT system (Phase 13b, §15): the
            // `nft_collection_root` sub-root commits every collection record
            // (creator, bounded metadata, both `Option` authorities, paused flag,
            // monotonic `next_serial`, minted/burned counts, optional supply cap,
            // royalty commitment), the `nft_item_root` sub-root commits every live
            // `(NftId, NftItem)` (single owner, per-item metadata commitment, frozen
            // flag), and the `nft_deposits` scalar commits the aggregate locked native
            // creation-deposit bucket (a SEPARATE bucket from `token_deposits`,
            // matching the fungible-token precedent). So a create / mint / transfer /
            // burn / pause / freeze / thaw / authority change always changes the state
            // root. NFT items are a SEPARATE, non-fungible asset from native WEBC and
            // never enter the native supply reconciliation; the only native units that
            // move are the ordinary fee and the creation deposit. The domain bump is a
            // deliberate consensus-format change; no external fixture pins a prior
            // root.
            // V17 adds the native fungible-token system (Phase 13a, §15): the
            // `token_root` sub-root commits every token record (creator, bounded
            // metadata, both `Option` authorities, paused flag, issued supply), the
            // `token_balance_root` sub-root commits every per-`(token, holder)`
            // balance, and the `frozen_token_root` sub-root commits every frozen
            // `(token, account)` pair, while the `token_deposits` scalar commits the
            // aggregate locked native creation-deposit bucket (mirroring how
            // `storage_deposits`/`sponsor_budgets` pair with their sub-roots). So a
            // create / mint / burn / transfer / pause / freeze / thaw / authority
            // change always changes the state root. Token supply is a SEPARATE asset
            // from native WEBC and never enters the native supply reconciliation; the
            // only native units that move are the ordinary fee and the creation
            // deposit. The domain bump is a deliberate consensus-format change; no
            // external fixture pins a prior root.
            // V16 adds the native service registry (Phase 9b, §15.5): the
            // `service_registry_root` sub-root commits every live service entry
            // (owner, namespace, categories, bounded fields, pricing, payment flows,
            // status, and current revision), so a registration, update, or status
            // change always changes the state root. It adds a committed MAP but NO
            // new scalar and locks no native units (registration is data only; its
            // spam-priced fee flows through the existing `burned_fees`/fee-pool
            // scalars), so the supply invariant is unchanged. The domain bump is a
            // deliberate consensus-format change; no external fixture pins a prior
            // root.
            // V15 adds the native agent-mandate primitive (Phase 9a, §15.32): the
            // `mandate_root` sub-root commits every live mandate record (principal,
            // agent key, escrowed budget/spend, expiry, per-tx cap, counterparty
            // policy, revocation flag, per-day rate-limit counters), and the
            // `mandate_escrow` scalar commits the aggregate locked native bucket
            // (mirroring how `dex_escrow`/`oracle_bonds`/`sponsor_budgets` pair with
            // their sub-roots). So a grant / top-up / spend / revoke always changes
            // the state root. The domain bump is a deliberate consensus-format
            // change; no external fixture pins a prior root.
            // V14 adds the native DEX (Phase 8, §15.13/§15.18/§15.37): the
            // `dex_order_root` sub-root commits every live order intent (owner, pair,
            // side, amount/remaining, limit price, deadline, flags), and the
            // `dex_escrow` scalar commits the aggregate locked native bucket
            // (mirroring how `oracle_bonds`/`sponsor_budgets` pair with their
            // sub-roots). So a submit / partial-or-full fill / cancel / expire always
            // changes the state root, and the deterministic per-block batch pass is
            // therefore consensus-bound identically on build and import. The domain
            // bump is a deliberate consensus-format change; no external fixture pins a
            // prior root.
            // V13 adds the interim contract runtime (Phase 7a, ADR-0014): the
            // `contract_root` sub-root commits every registered contract manifest
            // (identity, namespace, footprint, ABI/gas-schedule versions, handler)
            // and the `contract_state_root` sub-root commits every contract state
            // value, so a register or any contract write always changes the state
            // root. It adds no new scalar and locks no native units (the
            // registration fee is burned into the existing `burned_fees` scalar).
            // The domain bump is a deliberate consensus-format change; no external
            // fixture pins a prior root.
            // V12 adds the native oracle (Phase 7, §15.17): the `oracle_feed_root`
            // and `oracle_reporter_root` sub-roots commit every feed record
            // (creator, bond class, accrued revenue) and every bonded-reporter
            // record (latest value, report epoch), and the `oracle_bonds` and
            // `oracle_revenue` scalars commit the two aggregate locked buckets
            // (mirroring how `sponsor_budgets`/`storage_deposits` pair with their
            // sub-roots). So a create/register/report/pay/settle/deregister always
            // changes the state root. The domain bump is a deliberate
            // consensus-format change; no external fixture pins a prior root.
            // V11 adds localized (per-application-namespace) fee state (Phase 6, §8
            // isolation): the `namespace_fee_root` sub-root commits every congested
            // namespace's localized base fee, so a localized-fee change changes the
            // state root. It adds no new scalar and locks no native units (localized
            // pricing changes the fee rate, never the accounting). The domain bump is
            // a deliberate consensus-format change; no external fixture pins a prior
            // root. V10 added the application namespace registry (§8 isolation): the
            // `namespace_root` sub-root commits every namespace ownership record, so
            // a claim or transfer changes the state root. V9 added the
            // fee-sponsorship state (§15.35): the `sponsor_root` sub-root commits
            // every per-app sponsor record (budget, caps, and per-user/day counters),
            // and the `sponsor_budgets` scalar commits the aggregate locked bucket
            // (mirroring how `storage_deposits` pairs with the object sub-root). V8
            // added the `storage_deposits` scalar (§15.22); V7 added
            // `last_block_timestamp_ms` (finding E2).
            // V20 adds the untrusted-bytecode WASM contract runtime (Phase 7b,
            // ADR-0014 path (a)): the `wasm_contract_root` sub-root commits every
            // registered wasm manifest (identity, namespace, footprint, versions,
            // code-hash binding) and the `wasm_code_root` sub-root commits every
            // uploaded module's bytes, so a wasm registration always changes the
            // state root; a wasm contract's state writes reuse the existing
            // `contract_state_root`. It adds no new scalar and locks no native units
            // (the registration fee is burned into the existing `burned_fees`
            // scalar). The domain bump is a deliberate consensus-format change; no
            // external fixture pins a prior root.
            // Protocol 1 remains byte-identical to main's V20 commitment. V21
            // exists only for protocol 2 and authenticates the V5 grant subtree.
            domain,
            protocol_version: self.protocol_version,
            chain_id: self.chain_id.clone(),
            account_root: self.account_root()?,
            authorization_policy_root: ordered_value_root(
                b"WEBC_AUTHORIZATION_POLICY_LEAF_V1",
                self.authorization_policies.iter(),
            )?,
            authorization_lane_root: ordered_value_root(
                b"WEBC_AUTHORIZATION_LANE_LEAF_V1",
                self.authorization_lanes.iter(),
            )?,
            session_key_root: ordered_value_root(
                b"WEBC_SESSION_KEY_LEAF_V1",
                self.session_keys.iter(),
            )?,
            sponsor_grant_root,
            // V2: the object leaf now includes the recorded storage deposit
            // (§15.22), so a resize/refund changes the object sub-root.
            object_root: ordered_value_root(b"WEBC_OBJECT_LEAF_V2", self.objects.iter())?,
            validator_root: ordered_value_root(b"WEBC_VALIDATOR_LEAF_V1", self.validators.iter())?,
            delegation_root: ordered_value_root(
                b"WEBC_DELEGATION_LEAF_V1",
                self.delegations.iter(),
            )?,
            asset_root: ordered_value_root(
                b"WEBC_ASSET_BALANCE_LEAF_V1",
                self.asset_balances.iter(),
            )?,
            native_bridge_escrow_root: ordered_value_root(
                b"WEBC_NATIVE_BRIDGE_ESCROW_LEAF_V1",
                self.native_bridge_escrow.iter(),
            )?,
            processed_bridge_root: ordered_set_root(
                b"WEBC_PROCESSED_BRIDGE_LEAF_V1",
                self.processed_bridge_messages.iter(),
            )?,
            processed_slashing_root: ordered_set_root(
                b"WEBC_PROCESSED_SLASHING_LEAF_V1",
                self.processed_slashing_evidence.iter(),
            )?,
            unbonding_root: leaf_hash(b"WEBC_UNBONDING_QUEUE_V1", &self.unbonding)?,
            // Per-map bucket committed by its own ordered sub-root (§15.35): a
            // change to any sponsor's budget, caps, or per-user/day counters
            // changes this root and therefore the state root.
            sponsor_root: ordered_value_root(SPONSOR_LEAF_DOMAIN, self.sponsors.iter())?,
            // Namespace ownership registry committed by its own ordered sub-root
            // (§8 isolation): a claim or ownership transfer changes this root and
            // therefore the state root.
            namespace_root: ordered_value_root(NAMESPACE_LEAF_DOMAIN, self.namespaces.iter())?,
            // Native oracle registry committed by its own ordered sub-roots (§15.17):
            // a feed change (including accrued revenue) or a reporter change
            // (register/report/deregister) changes these roots and the state root.
            oracle_feed_root: ordered_value_root(
                ORACLE_FEED_LEAF_DOMAIN,
                self.oracle_feeds.iter(),
            )?,
            oracle_reporter_root: ordered_value_root(
                ORACLE_REPORTER_LEAF_DOMAIN,
                self.oracle_reporters.iter(),
            )?,
            // Native DEX order registry committed by its own ordered sub-root
            // (§15.37): a submit, a partial/full fill, a cancel, or an expiry changes
            // this root and therefore the state root, binding the per-block batch pass
            // to consensus.
            dex_order_root: ordered_value_root(DEX_ORDER_LEAF_DOMAIN, self.dex_orders.iter())?,
            // Native agent-mandate registry committed by its own ordered sub-root
            // (§15.32): a grant, top-up, spend, or revocation changes this root and
            // therefore the state root.
            mandate_root: ordered_value_root(MANDATE_LEAF_DOMAIN, self.mandates.iter())?,
            // Native service registry committed by its own ordered sub-root (§15.5):
            // a registration, update, or status change (each bumps the entry's
            // revision) changes this root and therefore the state root.
            service_registry_root: ordered_value_root(
                SERVICE_REGISTRY_LEAF_DOMAIN,
                self.services.iter(),
            )?,
            // Native fungible-token system committed by its own ordered sub-roots
            // (Phase 13a, §15): a create/mint/burn/pause/authority change moves
            // `token_root`; a mint/burn/transfer moves `token_balance_root`; a
            // freeze/thaw moves `frozen_token_root`; any of them changes the state
            // root. The `token_deposits` scalar (below) commits the aggregate locked
            // native creation-deposit bucket.
            token_root: ordered_value_root(TOKEN_LEAF_DOMAIN, self.tokens.iter())?,
            token_balance_root: ordered_value_root(
                TOKEN_BALANCE_LEAF_DOMAIN,
                self.token_balances.iter(),
            )?,
            frozen_token_root: ordered_set_root(
                FROZEN_TOKEN_LEAF_DOMAIN,
                self.frozen_token_accounts.iter(),
            )?,
            // Native NFT system committed by its own ordered sub-roots (Phase 13b,
            // §15): a create/mint/burn/pause/authority change moves
            // `nft_collection_root`; a mint/transfer/burn/freeze/thaw moves
            // `nft_item_root`; any of them changes the state root. The `nft_deposits`
            // scalar (below) commits the aggregate locked native creation-deposit
            // bucket.
            nft_collection_root: ordered_value_root(
                NFT_COLLECTION_LEAF_DOMAIN,
                self.nft_collections.iter(),
            )?,
            nft_item_root: ordered_value_root(NFT_ITEM_LEAF_DOMAIN, self.nft_items.iter())?,
            // Native application-governance system committed by its own ordered
            // sub-roots (Phase 13c, §15): a create/fund/open moves
            // `governance_instance_root`; an open/vote/resolve/execute moves
            // `governance_proposal_root`; a vote/reclaim moves `governance_vote_root`;
            // any of them changes the state root. The `governance_deposits` and
            // `governance_treasury` scalars (below) commit the two aggregate locked
            // native buckets.
            governance_instance_root: ordered_value_root(
                GOVERNANCE_INSTANCE_LEAF_DOMAIN,
                self.governance_instances.iter(),
            )?,
            governance_proposal_root: ordered_value_root(
                GOVERNANCE_PROPOSAL_LEAF_DOMAIN,
                self.governance_proposals.iter(),
            )?,
            governance_vote_root: ordered_value_root(
                GOVERNANCE_VOTE_LEAF_DOMAIN,
                self.governance_votes.iter(),
            )?,
            // Interim contract runtime committed by its own ordered sub-roots (Phase
            // 7a, ADR-0014): registering a contract changes `contract_root`; any
            // contract state write changes `contract_state_root`; either changes the
            // state root.
            contract_root: ordered_value_root(CONTRACT_LEAF_DOMAIN, self.contracts.iter())?,
            contract_state_root: ordered_value_root(
                CONTRACT_STATE_LEAF_DOMAIN,
                self.contract_state.iter(),
            )?,
            // WASM contract runtime committed by its own ordered sub-roots (Phase 7b,
            // ADR-0014 path (a)): registering a wasm contract changes both
            // `wasm_contract_root` (the manifest) and `wasm_code_root` (its bytecode);
            // any wasm contract state write changes `contract_state_root` (shared with
            // the native path); any of them changes the state root.
            wasm_contract_root: ordered_value_root(
                WASM_CONTRACT_LEAF_DOMAIN,
                self.wasm_contracts.iter(),
            )?,
            wasm_code_root: ordered_value_root(WASM_CODE_LEAF_DOMAIN, self.wasm_code.iter())?,
            // Localized per-namespace fee state committed by its own ordered sub-root
            // (Phase 6, §8 isolation): a change to any namespace's localized base fee
            // changes this root and therefore the state root.
            namespace_fee_root: ordered_value_root(
                NAMESPACE_FEE_LEAF_DOMAIN,
                self.namespace_fees.iter(),
            )?,
            burned_fees: self.burned_fees,
            slashed_units: self.slashed_units,
            storage_deposits: self.storage_deposits,
            sponsor_budgets: self.sponsor_budgets,
            oracle_bonds: self.oracle_bonds,
            oracle_revenue: self.oracle_revenue,
            dex_escrow: self.dex_escrow,
            mandate_escrow: self.mandate_escrow,
            token_deposits: self.token_deposits,
            nft_deposits: self.nft_deposits,
            governance_deposits: self.governance_deposits,
            governance_treasury: self.governance_treasury,
            validator_fee_pool: self.validator_fee_pool,
            minted_supply: self.minted_supply,
            inflation_year_start_supply: self.inflation_year_start_supply,
            current_base_fee_per_unit: self.current_base_fee_per_unit,
            current_epoch: self.current_epoch,
            current_height: self.current_height,
            bridge_nonce: self.bridge_nonce,
            last_block_timestamp_ms: self.last_block_timestamp_ms,
        };

        // Canonical JSON so the state root can, in principle, be recomputed
        // from browser-visible state once browser helpers for validator and
        // delegation leaves exist. The account_root (already browser-verifiable)
        // is the primary cross-language commitment today.
        let bytes = crate::canonical::canonical_json_bytes(&commitment)?;
        Ok(Hash256::digest(bytes))
    }

    pub fn account_root(&self) -> Result<Hash256, ChainError> {
        let leaves = self.account_leaf_entries()?;
        Ok(merkle_root(
            &leaves.into_iter().map(|(_, leaf)| leaf).collect::<Vec<_>>(),
        ))
    }

    pub fn account_leaf(&self, address: Address) -> Result<Option<Hash256>, ChainError> {
        let Some(account) = self.accounts.get(&address) else {
            return Ok(None);
        };
        Ok(Some(Self::account_leaf_hash(address, account)?))
    }

    pub fn account_state_proof(
        &self,
        address: Address,
    ) -> Result<Option<AccountStateProof>, ChainError> {
        let Some(account) = self.accounts.get(&address).cloned() else {
            return Ok(None);
        };
        let leaves = self.account_leaf_entries()?;
        let Some(index) = leaves
            .iter()
            .position(|(candidate, _)| *candidate == address)
        else {
            return Ok(None);
        };
        let hashes = leaves.into_iter().map(|(_, leaf)| leaf).collect::<Vec<_>>();
        let Some(proof) = merkle_proof(&hashes, index) else {
            return Ok(None);
        };
        Ok(Some(AccountStateProof {
            address,
            account,
            account_root: merkle_root(&hashes),
            proof,
        }))
    }

    pub fn account_leaf_hash(address: Address, account: &Account) -> Result<Hash256, ChainError> {
        // Account proofs must be verifiable from browser JavaScript without a
        // Rust bincode implementation. Use an explicit byte layout:
        // domain || address[32] || balance[u128be] || nonce[u64be]
        //        || staked[u128be] || delegated[u128be] || unbonding[u128be]
        let balance = account.balance.0.to_be_bytes();
        let nonce = account.nonce.to_be_bytes();
        let staked = account.staked.0.to_be_bytes();
        let delegated = account.delegated.0.to_be_bytes();
        let unbonding = account.unbonding.0.to_be_bytes();
        let parts: [&[u8]; 7] = [
            b"WEBC_ACCOUNT_LEAF_V2".as_slice(),
            address.as_bytes().as_slice(),
            balance.as_slice(),
            nonce.as_slice(),
            staked.as_slice(),
            delegated.as_slice(),
            unbonding.as_slice(),
        ];
        Ok(Hash256::digest_many(parts))
    }

    fn account_leaf_entries(&self) -> Result<Vec<(Address, Hash256)>, ChainError> {
        self.accounts
            .iter()
            .map(|(address, account)| Ok((*address, Self::account_leaf_hash(*address, account)?)))
            .collect()
    }

    /// Runs a resolved contract handler over its declared footprint under the
    /// shared contract-call discipline, and returns `(output, gas_consumed)`.
    ///
    /// This is the single execution core the native ([`Operation::InvokeContract`])
    /// and wasm ([`Operation::InvokeWasmContract`]) paths both go through, so both
    /// enforce byte-for-byte the same rules: a fresh [`GasMeter`] seeded with the
    /// admission units and capped at the gas limit; the contract's whole declared
    /// footprint loaded into a working set (every footprint key recorded through the
    /// shared `access` recorder by [`ContractContext`], so an omitted or padded
    /// access list fails closed); the handler run over only that footprint; and its
    /// declared writes committed back to `contract_state`. Any handler error
    /// (`OutOfGas`, an undeclared access, a guest trap) propagates as a
    /// [`ChainError`] and rolls the whole transaction back atomically — no partial
    /// contract state survives — because the caller applies this to a cloned overlay.
    ///
    /// The paths differ ONLY in how the caller resolves the handler (an audited
    /// built-in vs. a [`WasmContract`] over uploaded bytecode); everything about
    /// metering, access enforcement, and rollback lives here, once.
    fn run_contract_call(
        &mut self,
        call: ContractCall<'_>,
        access: &mut StateAccessRecorder,
    ) -> Result<(Vec<u8>, u64), ChainError> {
        let ContractCall {
            namespace,
            footprint,
            handler,
            input,
            admission_units,
            gas_limit,
        } = call;
        let mut meter = GasMeter::new(gas_limit, admission_units)?;
        let mut working = BTreeMap::new();
        for key_hash in footprint {
            let current = self
                .contract_state
                .get(&(namespace, *key_hash))
                .map(|value| value.0.clone());
            working.insert(*key_hash, current);
        }
        let mut ctx = ContractContext::new(
            namespace,
            footprint,
            working,
            access,
            &mut meter,
            self.current_epoch,
        );
        let output = handler.call(&mut ctx, input)?;
        let writes = ctx.into_writes()?;
        let gas_consumed = meter.consumed();
        // Commit the contract's declared writes back to committed state.
        for (key_hash, value) in writes {
            let key = (namespace, key_hash);
            match value {
                Some(bytes) => {
                    self.contract_state.insert(key, ContractStateValue(bytes));
                }
                None => {
                    self.contract_state.remove(&key);
                }
            }
        }
        Ok((output, gas_consumed))
    }

    fn apply_verified_transaction(
        &mut self,
        tx: &Transaction,
        config: &ChainConfig,
        tx_hash: Hash256,
        authorization: TransactionAuthorization,
    ) -> Result<Receipt, ChainError> {
        // Fee sponsorship is a default-lane-only feature (a prepaid lane already
        // funds its own fees). Reject a sponsor named on a non-default lane up
        // front — before any lane/nonce lookup — so the combination fails fast
        // with a precise error regardless of whether the named lane exists.
        if tx.sponsor.is_some() && !tx.authorization_lane.is_default() {
            return Err(ChainError::SponsorshipRequiresDefaultLane);
        }
        // A mandate spend is authorized by the agent key's signature; the agent
        // holds no balance of its own (the mandate escrow funds both the principal
        // moved and the fee). Ensure the agent account exists before the nonce
        // lookup, so default-lane replay protection applies even to an agent that
        // was never separately funded. This runs on the cloned overlay, so it
        // persists only if the whole spend succeeds.
        if matches!(
            tx.operation,
            Operation::SpendUnderMandate { .. } | Operation::SpendUnderMandateToService { .. }
        ) {
            self.accounts.entry(tx.sender).or_default();
        }
        let mut access =
            StateAccessRecorder::new(&tx.access_list.read_only, &tx.access_list.read_write)?;
        // Authorization policy is consensus state even though it is consulted
        // before mutation. Ordinary transactions read it; first installation
        // writes the same key and therefore conflicts with concurrent spends.
        if matches!(
            &tx.operation,
            Operation::InstallAuthorizationPolicy { .. }
                | Operation::RotateActiveTransactionKey { .. }
                | Operation::RotatePostQuantumRoot { .. }
        ) {
            access.write(StateKey::authorization_policy(tx.sender))?;
        } else {
            access.read(StateKey::authorization_policy(tx.sender))?;
        }
        // The selected lane owns both replay state and the fee source. This is
        // recorded before reading either value so a forged list fails closed.
        let expected_nonce = if tx.authorization_lane.is_default() {
            access.write(StateKey::account(tx.sender))?;
            self.accounts
                .get(&tx.sender)
                .ok_or(ChainError::AccountNotFound(tx.sender))?
                .nonce
        } else {
            access.write(StateKey::authorization_lane(
                tx.sender,
                tx.authorization_lane,
            ))?;
            self.authorization_lanes
                .get(&(tx.sender, tx.authorization_lane))
                .ok_or(ChainError::AuthorizationLaneNotFound)?
                .next_nonce
                .get()
        };
        if expected_nonce != tx.nonce {
            return Err(ChainError::NonceMismatch {
                address: tx.sender,
                expected: expected_nonce,
                actual: tx.nonce,
            });
        }

        let units = tx.required_units();
        if tx.fee.gas_limit < units {
            return Err(ChainError::GasLimitTooLow);
        }
        // The base fee this transaction pays is the global one for account-scoped
        // operations and the operation's namespace-localized one for object
        // operations (Phase 6 §8). Both are block-constant reads committed by the
        // `BaseFee` protocol key already declared in every access list, so localized
        // pricing needs no new access-list key or scheduler change.
        access.read(StateKey::protocol(ProtocolStateKey::BaseFee))?;
        let base_fee_per_unit = self.base_fee_per_unit_for(&tx.operation, config);
        let fee_per_unit = tx.fee.effective_fee_per_unit(base_fee_per_unit)?;
        let total_fee = Amount(
            u128::from(units)
                .checked_mul(u128::from(fee_per_unit))
                .ok_or(ChainError::ArithmeticOverflow)?,
        );
        let fee = split_fee(total_fee);

        // Choose the fee source. On the default lane a transaction may opt into
        // application fee sponsorship (§15.35): when it names a sponsor, the
        // operation is sponsorable, and the app's hard per-user / per-operation /
        // per-app-per-day caps and funded budget permit it, the fee is drawn from
        // the app's sponsor budget instead of the sender's liquid balance.
        // Best-effort (fail-open): an unavailable, non-sponsorable, or exhausted
        // sponsor never fails the transaction — the sender pays exactly as a
        // non-sponsored transaction would, never more than `fee` already
        // authorized. The burn + validator-reward split below is identical
        // whichever source pays, so supply is conserved either way.
        let mut sponsored_by: Option<Hash256> = None;
        // A mandate spend pays its fee out of the mandate escrow, not the agent's
        // balance (the prepaid-card model). The escrow debit happens atomically in
        // the `SpendUnderMandate` / `SpendUnderMandateToService` arm after the
        // mandate's budget check; the burn + validator-reward split below is applied
        // here identically to any other fee, so supply is conserved whichever source
        // pays.
        let fee_from_mandate = matches!(
            &tx.operation,
            Operation::SpendUnderMandate { .. } | Operation::SpendUnderMandateToService { .. }
        );
        if tx.authorization_lane.is_default() {
            let mut paid_by_sponsor = false;
            if let Some(namespace) = tx.sponsor {
                // The sponsor record is consensus state this transaction touches
                // whether or not it ultimately pays, so record the declared write
                // up front (the recorder requires every declared key be used).
                access.write(StateKey::application(namespace, sponsor_state_key_hash()))?;
                if tx.operation.is_sponsorable()
                    && self.try_charge_sponsor(namespace, tx.sender, total_fee, config)?
                {
                    paid_by_sponsor = true;
                    sponsored_by = Some(namespace);
                }
            }
            if !paid_by_sponsor && !fee_from_mandate {
                self.debit_native(tx.sender, total_fee)?;
            }
        } else {
            let lane = self
                .authorization_lanes
                .get_mut(&(tx.sender, tx.authorization_lane))
                .ok_or(ChainError::AuthorizationLaneNotFound)?;
            if lane.fee_balance < total_fee {
                return Err(ChainError::InsufficientLaneFeeBalance {
                    needed: total_fee,
                    available: lane.fee_balance,
                });
            }
            lane.fee_balance = lane
                .fee_balance
                .checked_sub(total_fee)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        // Fee deltas are declared per payer. The sequential Phase 1 state folds
        // them into aggregate counters with checked addition; a future parallel
        // overlay can merge independent payer deltas without a global scheduler
        // lock while preserving the same deterministic totals.
        access.write(StateKey::fee_accumulator_for_lane(
            tx.sender,
            tx.authorization_lane,
        ))?;
        self.burned_fees = self
            .burned_fees
            .checked_add(fee.burned)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.validator_fee_pool = self
            .validator_fee_pool
            .checked_add(fee.validator_reward)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if tx.authorization_lane.is_default() {
            let sender_account = self.account_mut(tx.sender)?;
            sender_account.nonce = sender_account
                .nonce
                .checked_add(1)
                .ok_or(ChainError::ArithmeticOverflow)?;
        } else {
            let lane = self
                .authorization_lanes
                .get_mut(&(tx.sender, tx.authorization_lane))
                .ok_or(ChainError::AuthorizationLaneNotFound)?;
            lane.next_nonce = lane
                .next_nonce
                .checked_next()
                .ok_or(ChainError::ArithmeticOverflow)?;
        }

        let mut events = vec![Event::FeePaid {
            payer: tx.sender,
            breakdown: fee,
        }];
        // When an application sponsor covered the fee, additionally record which
        // application paid and for whom, so wallets/indexers can attribute the
        // subsidy. `FeePaid` above still records the burn + reward split.
        if let Some(application) = sponsored_by {
            events.push(Event::FeeSponsored {
                application,
                beneficiary: tx.sender,
                breakdown: fee,
            });
        }

        // A session key authorizes only within its fixed constraints. This runs
        // before the operation mutates balances; any failure rolls back the
        // whole transaction because execution is applied to a cloned overlay.
        if let TransactionAuthorization::SessionKey(id) = authorization {
            self.enforce_session_key_use(tx, id, total_fee, &mut access, &mut events)?;
        }

        match &tx.operation {
            Operation::InstallAuthorizationPolicy { post_quantum_root } => {
                self.apply_native_install_authorization_policy(
                    tx.sender,
                    tx.public_key,
                    tx.authorization_lane,
                    *post_quantum_root,
                    NativeActionEffects::new(&mut access, &mut events),
                )?;
            }
            Operation::OpenAuthorizationLane { lane, fee_deposit } => {
                self.apply_native_lane_open(
                    tx.sender,
                    tx.authorization_lane,
                    *lane,
                    *fee_deposit,
                    NativeActionEffects::new(&mut access, &mut events),
                )?;
            }
            Operation::FundAuthorizationLane { lane, fee_deposit } => {
                self.apply_native_lane_fund(
                    tx.sender,
                    tx.authorization_lane,
                    *lane,
                    *fee_deposit,
                    NativeActionEffects::new(&mut access, &mut events),
                )?;
            }
            Operation::InstallSessionKey {
                session_public_key,
                constraints,
                post_quantum_root_reveal,
            } => {
                // Installing a session key is a critical action: it must use the
                // default lane and prove knowledge of the account's committed
                // post-quantum root. A legacy account without a policy has no
                // root to gate the action and therefore cannot own session keys.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::SessionKeyManagementRequiresDefaultLane);
                }
                let (policy_revision, root) = {
                    let policy = self
                        .authorization_policies
                        .get(&tx.sender)
                        .ok_or(ChainError::SessionKeyRequiresInstalledPolicy)?;
                    policy.validate()?;
                    (policy.revision(), *policy.post_quantum_root())
                };
                // The root must sign this exact install (its lane-bound
                // constraints and session key) under the current policy revision
                // and account nonce, not merely prove knowledge of the public
                // root key. A signature captured for any other action, nonce, or
                // policy revision rebuilds a different message and fails here.
                let authorization = SessionKeyAuthorizationAction::Install {
                    session_public_key: *session_public_key,
                    constraints: constraints.clone(),
                };
                let message = session_key_authorization_message(
                    &config.chain_id,
                    tx.sender,
                    policy_revision,
                    tx.nonce,
                    &authorization,
                )?;
                if !post_quantum_root_reveal.verify(&root, &message)? {
                    return Err(ChainError::InvalidPostQuantumRootReveal);
                }
                constraints.validate()?;
                if constraints.lifetime_epochs > config.session_keys.max_lifetime_epochs {
                    return Err(ChainError::SessionKeyLifetimeTooLong);
                }
                // Expiry is an absolute epoch derived from the install epoch, so
                // the deadline never depends on a wall clock.
                let expires_after_epoch = Epoch::new(
                    self.current_epoch
                        .checked_add(constraints.lifetime_epochs)
                        .ok_or(ChainError::ArithmeticOverflow)?,
                );
                let id = SessionKeyId::derive(session_public_key);
                access.write(StateKey::session_key(tx.sender, id))?;
                if self.session_keys.contains_key(&(tx.sender, id)) {
                    return Err(ChainError::SessionKeyAlreadyExists);
                }
                let installed = self
                    .session_keys
                    .keys()
                    .filter(|(owner, _)| *owner == tx.sender)
                    .count();
                if installed >= config.session_keys.max_session_keys_per_account as usize {
                    return Err(ChainError::SessionKeyLimitExceeded);
                }
                let record = SessionKey::new(
                    tx.sender,
                    *session_public_key,
                    policy_revision,
                    constraints.clone(),
                    expires_after_epoch,
                )?;
                self.session_keys.insert((tx.sender, id), record);
                events.push(Event::SessionKeyInstalled {
                    owner: tx.sender,
                    session_key: id,
                    expires_after_epoch,
                });
            }
            Operation::RevokeSessionKey {
                session_key,
                post_quantum_root_reveal,
            } => {
                // Revocation is immediate and unconditional so a compromised key
                // can be killed at once. It is a critical action under the same
                // default-lane and post-quantum-root gate as installation.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::SessionKeyManagementRequiresDefaultLane);
                }
                let (policy_revision, root) = {
                    let policy = self
                        .authorization_policies
                        .get(&tx.sender)
                        .ok_or(ChainError::SessionKeyRequiresInstalledPolicy)?;
                    policy.validate()?;
                    (policy.revision(), *policy.post_quantum_root())
                };
                // Revocation is gated by the same root signature as installation,
                // bound to this exact session-key id, policy revision, and nonce.
                let authorization = SessionKeyAuthorizationAction::Revoke {
                    session_key: *session_key,
                };
                let message = session_key_authorization_message(
                    &config.chain_id,
                    tx.sender,
                    policy_revision,
                    tx.nonce,
                    &authorization,
                )?;
                if !post_quantum_root_reveal.verify(&root, &message)? {
                    return Err(ChainError::InvalidPostQuantumRootReveal);
                }
                access.write(StateKey::session_key(tx.sender, *session_key))?;
                if self
                    .session_keys
                    .remove(&(tx.sender, *session_key))
                    .is_none()
                {
                    return Err(ChainError::SessionKeyNotFound);
                }
                events.push(Event::SessionKeyRevoked {
                    owner: tx.sender,
                    session_key: *session_key,
                });
            }
            Operation::RotateActiveTransactionKey {
                new_active_transaction_key,
                post_quantum_root_reveal,
            } => {
                // Rotating the sole active key is the account recovery path and a
                // critical action: default lane, an installed policy with a
                // post-quantum root, and a real root signature over this exact
                // rotation. A legacy account without a policy has no root to gate
                // the change and therefore cannot rotate this way.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::ActiveKeyRotationRequiresDefaultLane);
                }
                let (policy_revision, root, current_active) = {
                    let policy = self
                        .authorization_policies
                        .get(&tx.sender)
                        .ok_or(ChainError::ActiveKeyRotationRequiresInstalledPolicy)?;
                    policy.validate()?;
                    (
                        policy.revision(),
                        *policy.post_quantum_root(),
                        *policy.active_transaction_key(),
                    )
                };
                // A no-op rotation would waste a revision and could be used to
                // grief outstanding session keys without any real key change.
                if *new_active_transaction_key == current_active {
                    return Err(ChainError::ActiveKeyRotationToSameKey);
                }
                // The root must sign this exact new key under the current policy
                // revision and account nonce. A signature captured for any other
                // key, nonce, or revision rebuilds a different message and fails,
                // so it cannot be replayed after this rotation bumps the revision.
                let message = active_key_rotation_message(
                    &config.chain_id,
                    tx.sender,
                    policy_revision,
                    tx.nonce,
                    new_active_transaction_key,
                )?;
                if !post_quantum_root_reveal.verify(&root, &message)? {
                    return Err(ChainError::InvalidPostQuantumRootReveal);
                }
                // The policy state key was already recorded as a write at the top
                // of apply, so the rotation conflicts with concurrent spends.
                let rotated = self
                    .authorization_policies
                    .get(&tx.sender)
                    .ok_or(ChainError::ActiveKeyRotationRequiresInstalledPolicy)?
                    .rotate_active_key(*new_active_transaction_key)?;
                let new_revision = rotated.revision();
                self.authorization_policies.insert(tx.sender, rotated);
                events.push(Event::ActiveTransactionKeyRotated {
                    owner: tx.sender,
                    new_revision,
                    new_active_transaction_key: *new_active_transaction_key,
                });
            }
            Operation::RotatePostQuantumRoot {
                new_post_quantum_root,
                post_quantum_root_reveal,
            } => {
                // Replacing the recovery root is a critical action gated on a
                // signature by the CURRENT root, so only the present recovery-root
                // holder can change it. The envelope is signed by the active key
                // (the AccountKey path), so a stolen root alone cannot rotate the
                // root without also holding the active key.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::PostQuantumRootRotationRequiresDefaultLane);
                }
                let (policy_revision, current_root) = {
                    let policy = self
                        .authorization_policies
                        .get(&tx.sender)
                        .ok_or(ChainError::PostQuantumRootRotationRequiresInstalledPolicy)?;
                    policy.validate()?;
                    (policy.revision(), *policy.post_quantum_root())
                };
                new_post_quantum_root.validate()?;
                // A no-op rotation would waste a revision and needlessly grief
                // outstanding session keys without changing the root.
                if *new_post_quantum_root == current_root {
                    return Err(ChainError::PostQuantumRootRotationToSameRoot);
                }
                // The CURRENT root must sign this exact new commitment under the
                // current revision and nonce. A signature captured for any other
                // root, nonce, or revision rebuilds a different message and fails.
                let message = post_quantum_root_rotation_message(
                    &config.chain_id,
                    tx.sender,
                    policy_revision,
                    tx.nonce,
                    new_post_quantum_root,
                )?;
                if !post_quantum_root_reveal.verify(&current_root, &message)? {
                    return Err(ChainError::InvalidPostQuantumRootReveal);
                }
                // The policy state key was already recorded as a write at the top
                // of apply, so the rotation conflicts with concurrent spends.
                let rotated = self
                    .authorization_policies
                    .get(&tx.sender)
                    .ok_or(ChainError::PostQuantumRootRotationRequiresInstalledPolicy)?
                    .rotate_post_quantum_root(*new_post_quantum_root)?;
                let new_revision = rotated.revision();
                self.authorization_policies.insert(tx.sender, rotated);
                events.push(Event::PostQuantumRootRotated {
                    owner: tx.sender,
                    new_revision,
                    new_post_quantum_root: *new_post_quantum_root,
                });
            }
            Operation::CreateObject {
                object_id,
                namespace,
                data,
            } => {
                access.write(StateKey::object(*object_id))?;
                access.write(StateKey::application(*namespace, object_id.hash()))?;
                // The storage deposit is locked from the creator's liquid
                // balance, so this operation also writes the sender account
                // (already recorded on the default lane; declared explicitly so
                // it is covered on a non-default fee lane too).
                access.write(StateKey::account(tx.sender))?;
                if self.objects.contains_key(object_id) {
                    return Err(ChainError::ObjectAlreadyExists);
                }
                let mut object =
                    StateObject::new_owned(*object_id, *namespace, tx.sender, data.clone())?;
                // §15.22: lock a refundable storage deposit proportional to the
                // deterministic stored byte count. `debit_native` fails closed
                // (rolling the whole transaction back) if the creator cannot
                // afford it, so an object can never exist without its deposit.
                let deposit = config
                    .storage_pricing
                    .deposit_for_bytes(object.data.len())?;
                self.debit_native(tx.sender, deposit)?;
                object.deposit = deposit;
                self.storage_deposits = self
                    .storage_deposits
                    .checked_add(deposit)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let version = object.version;
                self.objects.insert(*object_id, object);
                events.push(Event::ObjectCreated {
                    object_id: *object_id,
                    namespace: *namespace,
                    owner: tx.sender,
                    version,
                });
            }
            Operation::MutateObject {
                object_id,
                namespace,
                expected_version,
                data,
            } => {
                access.write(StateKey::object(*object_id))?;
                access.write(StateKey::application(*namespace, object_id.hash()))?;
                // A resize locks or refunds the difference against the sender's
                // liquid balance, so the sender account is written here too.
                access.write(StateKey::account(tx.sender))?;
                validate_object_data(data)?;
                let new_deposit = config.storage_pricing.deposit_for_bytes(data.len())?;
                // Validate ownership/version and read the current deposit, then
                // release the object borrow before touching balances (which
                // borrow `self` mutably through the native credit/debit helpers).
                let old_deposit = {
                    let object = self
                        .objects
                        .get_mut(object_id)
                        .ok_or(ChainError::ObjectNotFound)?;
                    validate_owned_object(object, tx.sender, *namespace, *expected_version)?;
                    object.deposit
                };
                // Keep the locked deposit exactly matching the new byte size:
                // lock the extra when growing (fail closed if unaffordable),
                // refund the difference when shrinking. Both conserve supply
                // (liquid <-> storage_deposits).
                if new_deposit > old_deposit {
                    let extra = new_deposit
                        .checked_sub(old_deposit)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    self.debit_native(tx.sender, extra)?;
                    self.storage_deposits = self
                        .storage_deposits
                        .checked_add(extra)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                } else if old_deposit > new_deposit {
                    let refund = old_deposit
                        .checked_sub(new_deposit)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    self.storage_deposits = self
                        .storage_deposits
                        .checked_sub(refund)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    self.credit_native(tx.sender, refund)?;
                }
                // Commit the new revision, bytes, and matching deposit only after
                // the balance move succeeded.
                let object = self
                    .objects
                    .get_mut(object_id)
                    .ok_or(ChainError::ObjectNotFound)?;
                object.version = object.version.checked_next()?;
                object.data = data.clone();
                object.deposit = new_deposit;
                events.push(Event::ObjectMutated {
                    object_id: *object_id,
                    version: object.version,
                });
            }
            Operation::TransferObject {
                object_id,
                namespace,
                expected_version,
                new_owner,
            } => {
                self.apply_native_object_transfer(
                    tx.sender,
                    *object_id,
                    *namespace,
                    *expected_version,
                    *new_owner,
                    NativeActionEffects::new(&mut access, &mut events),
                )?;
            }
            Operation::DeleteObject {
                object_id,
                namespace,
                expected_version,
            } => {
                access.write(StateKey::object(*object_id))?;
                access.write(StateKey::application(*namespace, object_id.hash()))?;
                // The deletion refund credits the owner's liquid balance.
                access.write(StateKey::account(tx.sender))?;
                // Validate ownership/version and read the recorded deposit, then
                // release the borrow before settling balances.
                let deposit = {
                    let object = self
                        .objects
                        .get(object_id)
                        .ok_or(ChainError::ObjectNotFound)?;
                    validate_owned_object(object, tx.sender, *namespace, *expected_version)?;
                    object.deposit
                };
                // §15.22: refund the majority to the owner, burn the occupancy
                // remainder. `refund + burned == deposit`, so the deposit leaves
                // `storage_deposits` with no mint or loss.
                let split = config.storage_pricing.refund_split(deposit)?;
                self.storage_deposits = self
                    .storage_deposits
                    .checked_sub(deposit)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.credit_native(tx.sender, split.refund)?;
                self.burned_fees = self
                    .burned_fees
                    .checked_add(split.burned)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.objects.remove(object_id);
                events.push(Event::ObjectDeleted {
                    object_id: *object_id,
                    owner: tx.sender,
                    refund: split.refund,
                    burned: split.burned,
                });
            }
            Operation::Transfer { to, amount } => {
                self.apply_native_transfer(
                    tx.sender,
                    *to,
                    *amount,
                    NativeActionEffects::new(&mut access, &mut events),
                )?;
            }
            Operation::RegisterValidator {
                consensus_key,
                self_stake,
                commission_bps,
                bootstrap,
            } => {
                access.write(StateKey::validator(tx.sender))?;
                if self.validators.contains_key(&tx.sender) {
                    return Err(ChainError::ValidatorAlreadyExists(tx.sender));
                }
                if *commission_bps > config.staking.max_commission_bps {
                    return Err(ChainError::CommissionTooHigh);
                }
                if *bootstrap {
                    return Err(ChainError::BootstrapDisabled);
                }
                if *self_stake < config.staking.min_validator_self_stake {
                    return Err(ChainError::StakeTooSmall);
                }
                if !self_stake.is_zero() {
                    self.debit_native(tx.sender, *self_stake)?;
                    let account = self.account_mut(tx.sender)?;
                    account.staked = account
                        .staked
                        .checked_add(*self_stake)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                }
                self.validators.insert(
                    tx.sender,
                    Validator {
                        operator: tx.sender,
                        consensus_key: *consensus_key,
                        self_stake: *self_stake,
                        delegated_stake: Amount::ZERO,
                        commission_bps: *commission_bps,
                        status: ValidatorStatus::PendingActivation,
                        bootstrap: false,
                        accumulated_rewards: Amount::ZERO,
                    },
                );
                let validator = self
                    .validators
                    .get_mut(&tx.sender)
                    .ok_or(ChainError::ValidatorNotFound(tx.sender))?;
                validator.refresh_stake_status(&config.staking)?;
                events.push(Event::ValidatorRegistered {
                    operator: tx.sender,
                    bootstrap: false,
                });
            }
            Operation::Delegate { validator, amount } => {
                access.write(StateKey::validator(*validator))?;
                access.write(StateKey::delegation(tx.sender, *validator))?;
                access.write(StateKey::unbonding_queue(*validator))?;
                if *amount < config.staking.min_delegation {
                    return Err(ChainError::DelegationTooSmall);
                }
                let target = self
                    .validators
                    .get(validator)
                    .ok_or(ChainError::ValidatorNotFound(*validator))?;
                if matches!(
                    target.status,
                    ValidatorStatus::Jailed { .. } | ValidatorStatus::Tombstoned { .. }
                ) {
                    return Err(ChainError::ValidatorNotActive(*validator));
                }
                // A queued operator exit remains slashable and voting-active
                // until admission, but it cannot safely back new delegation:
                // otherwise a delegator could enter after a full exit request
                // and be stranded when the epoch snapshot admits that exit.
                let queued_operator_stake = self.unbonding.queued_for(
                    *validator,
                    *validator,
                    UnbondingKind::OperatorStake,
                )?;
                let available_operator_stake = target
                    .self_stake
                    .checked_sub(queued_operator_stake)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let maximum_delegated = available_operator_stake
                    .checked_mul_u64(4)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let proposed_delegated = target
                    .delegated_stake
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if proposed_delegated > maximum_delegated {
                    return Err(ChainError::DelegationRatioExceeded);
                }

                self.debit_native(tx.sender, *amount)?;
                let account = self.account_mut(tx.sender)?;
                account.delegated = account
                    .delegated
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;

                let validator_state = self
                    .validators
                    .get_mut(validator)
                    .ok_or(ChainError::ValidatorNotFound(*validator))?;
                validator_state.delegated_stake = validator_state
                    .delegated_stake
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                validator_state.refresh_stake_status(&config.staking)?;

                let key = (tx.sender, *validator);
                let delegation = self.delegations.entry(key).or_insert(Delegation {
                    delegator: tx.sender,
                    validator: *validator,
                    amount: Amount::ZERO,
                    accumulated_rewards: Amount::ZERO,
                });
                delegation.amount = delegation
                    .amount
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::Delegated {
                    delegator: tx.sender,
                    validator: *validator,
                    amount: *amount,
                });
            }
            Operation::Undelegate { validator, amount } => {
                access.write(StateKey::delegation(tx.sender, *validator))?;
                access.write(StateKey::unbonding_queue(*validator))?;
                let key = (tx.sender, *validator);
                let existing = self
                    .delegations
                    .get(&key)
                    .ok_or(ChainError::DelegationNotFound)?;
                let already_queued =
                    self.unbonding
                        .queued_for(tx.sender, *validator, UnbondingKind::Delegation)?;
                let available = existing
                    .amount
                    .checked_sub(already_queued)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if available < *amount {
                    return Err(ChainError::InsufficientBalance {
                        address: tx.sender,
                        needed: *amount,
                        available,
                    });
                }
                let remaining_active = available
                    .checked_sub(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if !remaining_active.is_zero() && remaining_active < config.staking.min_delegation {
                    return Err(ChainError::DelegationTooSmall);
                }
                let request_id = self.unbonding.request(
                    tx.sender,
                    *validator,
                    UnbondingKind::Delegation,
                    *amount,
                    Epoch::new(self.current_epoch),
                    existing.accumulated_rewards,
                )?;
                events.push(Event::UnbondingRequested {
                    request_id,
                    delegator: tx.sender,
                    validator: *validator,
                    kind: UnbondingKind::Delegation,
                    amount: *amount,
                });
            }
            Operation::UnstakeValidator { amount } => {
                access.write(StateKey::validator(tx.sender))?;
                access.write(StateKey::unbonding_queue(tx.sender))?;
                let validator = self
                    .validators
                    .get(&tx.sender)
                    .ok_or(ChainError::ValidatorNotFound(tx.sender))?;
                let already_queued = self.unbonding.queued_for(
                    tx.sender,
                    tx.sender,
                    UnbondingKind::OperatorStake,
                )?;
                let available = validator
                    .self_stake
                    .checked_sub(already_queued)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if available < *amount {
                    return Err(ChainError::InsufficientBalance {
                        address: tx.sender,
                        needed: *amount,
                        available,
                    });
                }
                let remaining = available
                    .checked_sub(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if remaining.is_zero() {
                    if !validator.delegated_stake.is_zero() {
                        return Err(ChainError::OperatorExitHasDelegations);
                    }
                } else {
                    let maximum_delegated = remaining
                        .checked_mul_u64(4)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    let projected_total = remaining
                        .checked_add(validator.delegated_stake)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    if remaining < config.staking.min_validator_self_stake
                        || validator.delegated_stake > maximum_delegated
                        || projected_total < config.staking.min_validator_total_stake
                    {
                        return Err(ChainError::OperatorExitWouldDeactivatePool);
                    }
                }
                let request_id = self.unbonding.request(
                    tx.sender,
                    tx.sender,
                    UnbondingKind::OperatorStake,
                    *amount,
                    Epoch::new(self.current_epoch),
                    validator.accumulated_rewards,
                )?;
                events.push(Event::UnbondingRequested {
                    request_id,
                    delegator: tx.sender,
                    validator: tx.sender,
                    kind: UnbondingKind::OperatorStake,
                    amount: *amount,
                });
            }
            Operation::ClaimUnbonded {
                validator,
                request_id,
            } => {
                self.apply_native_claim_unbonded(
                    tx.sender,
                    *validator,
                    *request_id,
                    NativeActionEffects::new(&mut access, &mut events),
                )?;
            }
            Operation::ClaimValidatorRewards => {
                self.apply_native_claim_validator_rewards(
                    tx.sender,
                    NativeActionEffects::new(&mut access, &mut events),
                )?;
            }
            Operation::ClaimDelegatorRewards { validator } => {
                self.apply_native_claim_delegator_rewards(
                    tx.sender,
                    *validator,
                    NativeActionEffects::new(&mut access, &mut events),
                )?;
            }
            Operation::CompoundValidatorRewards => {
                access.write(StateKey::validator(tx.sender))?;
                access.write(StateKey::account(tx.sender))?;
                // Move accumulated operator rewards straight into self-stake. This
                // shifts units from the pending-rewards bucket to the staked
                // bucket (supply-neutral) without a claim-then-restake round trip.
                let reward = {
                    let validator = self
                        .validators
                        .get_mut(&tx.sender)
                        .ok_or(ChainError::ValidatorNotFound(tx.sender))?;
                    let reward = validator.accumulated_rewards;
                    validator.accumulated_rewards = Amount::ZERO;
                    validator.self_stake = validator
                        .self_stake
                        .checked_add(reward)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    validator.refresh_stake_status(&config.staking)?;
                    reward
                };
                let account = self.account_mut(tx.sender)?;
                account.staked = account
                    .staked
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::ValidatorRewardsCompounded {
                    validator: tx.sender,
                    amount: reward,
                });
            }
            Operation::CompoundDelegatorRewards { validator } => {
                access.write(StateKey::validator(*validator))?;
                access.write(StateKey::delegation(tx.sender, *validator))?;
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::unbonding_queue(*validator))?;
                let target = self
                    .validators
                    .get(validator)
                    .ok_or(ChainError::ValidatorNotFound(*validator))?;
                if matches!(
                    target.status,
                    ValidatorStatus::Jailed { .. } | ValidatorStatus::Tombstoned { .. }
                ) {
                    return Err(ChainError::ValidatorNotActive(*validator));
                }
                let reward = self
                    .delegations
                    .get(&(tx.sender, *validator))
                    .ok_or(ChainError::DelegationNotFound)?
                    .accumulated_rewards;
                // Adding the reward to the position must respect the operator/
                // delegator ratio, exactly as a fresh delegation would (a queued
                // operator exit still cannot back new delegated stake).
                let queued_operator_stake = self.unbonding.queued_for(
                    *validator,
                    *validator,
                    UnbondingKind::OperatorStake,
                )?;
                let available_operator_stake = target
                    .self_stake
                    .checked_sub(queued_operator_stake)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let maximum_delegated = available_operator_stake
                    .checked_mul_u64(4)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let proposed_delegated = target
                    .delegated_stake
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                if proposed_delegated > maximum_delegated {
                    return Err(ChainError::DelegationRatioExceeded);
                }

                {
                    let delegation = self
                        .delegations
                        .get_mut(&(tx.sender, *validator))
                        .ok_or(ChainError::DelegationNotFound)?;
                    delegation.accumulated_rewards = Amount::ZERO;
                    delegation.amount = delegation
                        .amount
                        .checked_add(reward)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                }
                let validator_state = self
                    .validators
                    .get_mut(validator)
                    .ok_or(ChainError::ValidatorNotFound(*validator))?;
                validator_state.delegated_stake = validator_state
                    .delegated_stake
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                validator_state.refresh_stake_status(&config.staking)?;
                let account = self.account_mut(tx.sender)?;
                account.delegated = account
                    .delegated
                    .checked_add(reward)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::DelegatorRewardsCompounded {
                    delegator: tx.sender,
                    validator: *validator,
                    amount: reward,
                });
            }
            Operation::SubmitSlashingEvidence { evidence } => {
                let outcome = self.apply_slashing_evidence(evidence, config, Some(&mut access))?;
                events.push(Event::Slashed { outcome });
            }
            Operation::BridgeLock {
                asset,
                destination_chain,
                recipient,
                amount,
            } => {
                if amount.is_zero() {
                    return Err(ChainError::BridgeAmountZero);
                }
                if *asset != AssetId::NativeWebc || *destination_chain == ExternalChain::Webc {
                    return Err(ChainError::InvalidBridgeAssetFlow);
                }
                access.write(StateKey::bridge_escrow(destination_chain.clone()))?;
                self.debit_asset_or_native(tx.sender, asset, *amount)?;
                self.credit_native_bridge_escrow(destination_chain.clone(), *amount)?;
                let message = self.next_bridge_message(
                    OutgoingBridgeMessage {
                        source_chain: ExternalChain::Webc,
                        destination_chain: destination_chain.clone(),
                        asset: asset.clone(),
                        sender: tx.sender.as_bytes().to_vec(),
                        recipient: recipient.clone(),
                        amount: *amount,
                        source_tx: tx_hash,
                    },
                    &mut access,
                )?;
                let message_hash = message.hash()?;
                events.push(Event::Bridge {
                    event: BridgeEvent::Locked {
                        message,
                        message_hash,
                    },
                });
            }
            Operation::BridgeBurn {
                asset,
                destination_chain,
                recipient,
                amount,
            } => {
                if amount.is_zero() {
                    return Err(ChainError::BridgeAmountZero);
                }
                let AssetId::External { origin_chain, .. } = asset else {
                    return Err(ChainError::InvalidBridgeAssetFlow);
                };
                if *origin_chain != *destination_chain || *destination_chain == ExternalChain::Webc
                {
                    return Err(ChainError::BridgeSourceMismatch);
                }
                access.write(StateKey::asset_balance(asset.clone(), tx.sender))?;
                self.debit_asset_or_native(tx.sender, asset, *amount)?;
                let message = self.next_bridge_message(
                    OutgoingBridgeMessage {
                        source_chain: ExternalChain::Webc,
                        destination_chain: destination_chain.clone(),
                        asset: asset.clone(),
                        sender: tx.sender.as_bytes().to_vec(),
                        recipient: recipient.clone(),
                        amount: *amount,
                        source_tx: tx_hash,
                    },
                    &mut access,
                )?;
                let message_hash = message.hash()?;
                events.push(Event::Bridge {
                    event: BridgeEvent::Burned {
                        message,
                        message_hash,
                    },
                });
            }
            Operation::BridgeMint { message } => {
                if !config.bridge.can_submit_incoming(tx.sender) {
                    return Err(ChainError::UnauthorizedBridgeRelayer);
                }
                let message_hash = self.process_incoming_bridge_message(
                    message,
                    IncomingBridgeAction::MintRepresentation,
                    &mut access,
                )?;
                events.push(Event::Bridge {
                    event: BridgeEvent::Minted {
                        message: message.clone(),
                        message_hash,
                    },
                });
            }
            Operation::BridgeRelease { message } => {
                if !config.bridge.can_submit_incoming(tx.sender) {
                    return Err(ChainError::UnauthorizedBridgeRelayer);
                }
                let message_hash = self.process_incoming_bridge_message(
                    message,
                    IncomingBridgeAction::ReleaseNative,
                    &mut access,
                )?;
                events.push(Event::Bridge {
                    event: BridgeEvent::Released {
                        message: message.clone(),
                        message_hash,
                    },
                });
            }
            Operation::RegisterAppSponsor {
                namespace,
                daily_budget_cap,
                initial_funding,
            } => {
                // Owner financial action: default lane only (the account balance
                // is the funding source). The sender account key is already
                // recorded by the default-lane path; declare the sponsor state key.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::SponsorshipRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::application(*namespace, sponsor_state_key_hash()))?;
                // The app-chosen per-day cap must stay within the protocol ceiling
                // (§15.35 "within hard protocol caps").
                if *daily_budget_cap > config.sponsorship.max_app_daily_budget {
                    return Err(ChainError::AppSponsorDailyCapTooHigh);
                }
                if self.sponsors.contains_key(namespace) {
                    return Err(ChainError::AppSponsorAlreadyExists);
                }
                // Lock the initial funding: liquid -> sponsor_budgets. `debit_native`
                // fails closed if the owner cannot afford it, rolling back the tx.
                self.debit_native(tx.sender, *initial_funding)?;
                self.sponsor_budgets = self
                    .sponsor_budgets
                    .checked_add(*initial_funding)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let mut sponsor = AppSponsor::new(tx.sender, *daily_budget_cap);
                sponsor.budget = *initial_funding;
                self.sponsors.insert(*namespace, sponsor);
                events.push(Event::AppSponsorRegistered {
                    application: *namespace,
                    owner: tx.sender,
                    daily_budget_cap: *daily_budget_cap,
                    funded: *initial_funding,
                });
            }
            Operation::FundAppSponsor { namespace, amount } => {
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::SponsorshipRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::application(*namespace, sponsor_state_key_hash()))?;
                // Validate existence and ownership before touching balances; only
                // the owner may fund. Read-only borrow is dropped before `debit`.
                {
                    let sponsor = self
                        .sponsors
                        .get(namespace)
                        .ok_or(ChainError::AppSponsorNotFound)?;
                    if sponsor.owner != tx.sender {
                        return Err(ChainError::AppSponsorNotOwner);
                    }
                }
                self.debit_native(tx.sender, *amount)?;
                self.sponsor_budgets = self
                    .sponsor_budgets
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let sponsor = self
                    .sponsors
                    .get_mut(namespace)
                    .ok_or(ChainError::AppSponsorNotFound)?;
                sponsor.budget = sponsor
                    .budget
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::AppSponsorFunded {
                    application: *namespace,
                    amount: *amount,
                });
            }
            Operation::WithdrawAppSponsor { namespace, amount } => {
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::SponsorshipRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::application(*namespace, sponsor_state_key_hash()))?;
                // Validate ownership and sufficient budget before moving units.
                {
                    let sponsor = self
                        .sponsors
                        .get(namespace)
                        .ok_or(ChainError::AppSponsorNotFound)?;
                    if sponsor.owner != tx.sender {
                        return Err(ChainError::AppSponsorNotOwner);
                    }
                    if sponsor.budget < *amount {
                        return Err(ChainError::AppSponsorBudgetInsufficient {
                            needed: *amount,
                            available: sponsor.budget,
                        });
                    }
                }
                // Move sponsor_budgets -> owner liquid, keeping the per-app budget
                // and the aggregate bucket in lockstep (no mint, no loss).
                {
                    let sponsor = self
                        .sponsors
                        .get_mut(namespace)
                        .ok_or(ChainError::AppSponsorNotFound)?;
                    sponsor.budget = sponsor
                        .budget
                        .checked_sub(*amount)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                }
                self.sponsor_budgets = self
                    .sponsor_budgets
                    .checked_sub(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.credit_native(tx.sender, *amount)?;
                events.push(Event::AppSponsorWithdrawn {
                    application: *namespace,
                    amount: *amount,
                });
            }
            Operation::RegisterNamespace { namespace } => {
                // Claiming a namespace records an owner; it locks no native units,
                // so the supply invariant is unaffected (only the ordinary fee
                // moves). Any authorization lane may pay the fee — there is no
                // account balance to draw from — so no default-lane restriction.
                access.write(StateKey::application(
                    *namespace,
                    namespace_state_key_hash(),
                ))?;
                if self.namespaces.contains_key(namespace) {
                    return Err(ChainError::NamespaceAlreadyRegistered);
                }
                self.namespaces
                    .insert(*namespace, NamespaceRecord::new(tx.sender));
                events.push(Event::NamespaceRegistered {
                    namespace: *namespace,
                    owner: tx.sender,
                });
            }
            Operation::TransferNamespace {
                namespace,
                new_owner,
            } => {
                access.write(StateKey::application(
                    *namespace,
                    namespace_state_key_hash(),
                ))?;
                // Only the current owner may transfer. Validate existence and
                // ownership before mutating, so a non-owner's attempt fails closed
                // and leaves the record unchanged (the whole tx rolls back).
                let record = self
                    .namespaces
                    .get_mut(namespace)
                    .ok_or(ChainError::NamespaceNotFound)?;
                if record.owner != tx.sender {
                    return Err(ChainError::NamespaceNotOwner);
                }
                record.owner = *new_owner;
                events.push(Event::NamespaceTransferred {
                    namespace: *namespace,
                    from: tx.sender,
                    to: *new_owner,
                });
            }
            Operation::CreateFeed { feed_id } => {
                // Permissionless-for-a-fee (§15.6): default lane only (the creation
                // fee draws from the sender's liquid balance) and the fee is BURNED,
                // so a creation is never free. Supply-neutral: liquid -> burned.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::OracleRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::oracle_feed(*feed_id))?;
                if self.oracle_feeds.contains_key(feed_id) {
                    return Err(ChainError::OracleFeedAlreadyExists);
                }
                let creation_fee = config.oracle.feed_creation_fee;
                self.debit_native(tx.sender, creation_fee)?;
                self.burned_fees = self
                    .burned_fees
                    .checked_add(creation_fee)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let bond = config.oracle.min_reporter_bond;
                self.oracle_feeds
                    .insert(*feed_id, Feed::new(tx.sender, bond));
                events.push(Event::FeedCreated {
                    feed_id: *feed_id,
                    creator: tx.sender,
                    bond,
                    fee_burned: creation_fee,
                });
            }
            Operation::RegisterReporter { feed_id } => {
                // Default lane only: the bond draws from the sender's liquid
                // balance. Supply-neutral: liquid -> oracle_bonds.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::OracleRequiresDefaultLane);
                }
                access.read(StateKey::oracle_feed(*feed_id))?;
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::oracle_reporter(*feed_id, tx.sender))?;
                // The bond is the feed's frozen bond class (reading it also
                // confirms the feed exists).
                let bond = self
                    .oracle_feeds
                    .get(feed_id)
                    .ok_or(ChainError::OracleFeedNotFound)?
                    .bond;
                if self.oracle_reporters.contains_key(&(*feed_id, tx.sender)) {
                    return Err(ChainError::OracleReporterAlreadyRegistered);
                }
                self.debit_native(tx.sender, bond)?;
                self.oracle_bonds = self
                    .oracle_bonds
                    .checked_add(bond)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.oracle_reporters
                    .insert((*feed_id, tx.sender), OracleReporter::new());
                events.push(Event::ReporterRegistered {
                    feed_id: *feed_id,
                    reporter: tx.sender,
                    bond,
                });
            }
            Operation::DeregisterReporter { feed_id } => {
                // Default lane only: the bond returns to the sender's liquid
                // balance. Supply-neutral: oracle_bonds -> liquid.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::OracleRequiresDefaultLane);
                }
                access.read(StateKey::oracle_feed(*feed_id))?;
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::oracle_reporter(*feed_id, tx.sender))?;
                // The reporter's locked bond equals its feed's frozen bond.
                let bond = self
                    .oracle_feeds
                    .get(feed_id)
                    .ok_or(ChainError::OracleFeedNotFound)?
                    .bond;
                if !self.oracle_reporters.contains_key(&(*feed_id, tx.sender)) {
                    return Err(ChainError::OracleReporterNotFound);
                }
                self.oracle_bonds = self
                    .oracle_bonds
                    .checked_sub(bond)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.oracle_reporters.remove(&(*feed_id, tx.sender));
                self.credit_native(tx.sender, bond)?;
                events.push(Event::ReporterDeregistered {
                    feed_id: *feed_id,
                    reporter: tx.sender,
                    bond,
                });
            }
            Operation::SubmitReport { feed_id, value } => {
                // Reporting moves no native units (only the ordinary tx fee), so it
                // may run on any authorization lane. It records the value and the
                // epoch it was reported for (liveness).
                access.read(StateKey::oracle_feed(*feed_id))?;
                access.write(StateKey::oracle_reporter(*feed_id, tx.sender))?;
                if !self.oracle_feeds.contains_key(feed_id) {
                    return Err(ChainError::OracleFeedNotFound);
                }
                let epoch = self.current_epoch;
                let reporter = self
                    .oracle_reporters
                    .get_mut(&(*feed_id, tx.sender))
                    .ok_or(ChainError::OracleReporterNotFound)?;
                reporter.value = Some(*value);
                reporter.reported_epoch = epoch;
                events.push(Event::ReportSubmitted {
                    feed_id: *feed_id,
                    reporter: tx.sender,
                    value: *value,
                    epoch,
                });
            }
            Operation::PayFeedRead { feed_id, amount } => {
                // A consumer pays a read fee into the feed's revenue pool
                // (§15.17). Default lane only: the payment draws from the payer's
                // liquid balance. Supply-neutral: liquid -> oracle_revenue.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::OracleRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::oracle_feed(*feed_id))?;
                if amount.is_zero() {
                    return Err(ChainError::OracleReadAmountZero);
                }
                if !self.oracle_feeds.contains_key(feed_id) {
                    return Err(ChainError::OracleFeedNotFound);
                }
                self.debit_native(tx.sender, *amount)?;
                self.oracle_revenue = self
                    .oracle_revenue
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let feed = self
                    .oracle_feeds
                    .get_mut(feed_id)
                    .ok_or(ChainError::OracleFeedNotFound)?;
                feed.revenue = feed
                    .revenue
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::FeedReadPaid {
                    feed_id: *feed_id,
                    payer: tx.sender,
                    amount: *amount,
                });
            }
            Operation::SubmitOrder {
                order_id,
                pair,
                side,
                amount,
                limit_price,
                deadline_height,
                fill_or_cancel,
            } => {
                // Default lane only: the order's input is locked from the sender's
                // liquid balance (native leg -> dex_escrow) or asset balance
                // (non-native leg). The block-level batch pass later settles/refunds
                // it; that pass is not access-list-bound (like epoch settlement).
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::DexRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::dex_order(*order_id))?;
                // Validate the hostile order intent before touching any supply.
                pair.validate()?;
                if amount.is_zero() || *amount < config.dex.min_order_amount {
                    return Err(ChainError::DexOrderAmountTooSmall);
                }
                if limit_price.is_zero() {
                    return Err(ChainError::DexOrderPriceZero);
                }
                if self.dex_orders.contains_key(order_id) {
                    return Err(ChainError::DexOrderAlreadyExists);
                }
                // Resolve the effective deadline: 0 is the "use the default window"
                // sentinel; an explicit deadline must not already be in the past.
                let effective_deadline = if *deadline_height == 0 {
                    self.current_height
                        .checked_add(config.dex.default_deadline_blocks)
                        .ok_or(ChainError::ArithmeticOverflow)?
                } else {
                    if *deadline_height < self.current_height {
                        return Err(ChainError::DexOrderDeadlineInPast);
                    }
                    *deadline_height
                };
                // The locked leg and its asset: a buy locks quote = amount*price, a
                // sell locks base = amount. Compute the quote lock overflow-safely.
                let (locked_asset, locked_amount) = match side {
                    OrderSide::Buy => (
                        pair.quote.clone(),
                        limit_price
                            .quote_for(*amount)
                            .ok_or(ChainError::ArithmeticOverflow)?,
                    ),
                    OrderSide::Sell => (pair.base.clone(), *amount),
                };
                if locked_asset != AssetId::NativeWebc {
                    access.write(StateKey::asset_balance(locked_asset.clone(), tx.sender))?;
                }
                self.dex_lock(tx.sender, &locked_asset, locked_amount)?;
                let order = Order {
                    owner: tx.sender,
                    pair: pair.clone(),
                    side: *side,
                    amount: *amount,
                    remaining: *amount,
                    limit_price: *limit_price,
                    deadline_height: effective_deadline,
                    fill_or_cancel: *fill_or_cancel,
                    cancel_requested: false,
                };
                self.dex_orders.insert(*order_id, order);
                events.push(Event::OrderSubmitted {
                    order_id: *order_id,
                    owner: tx.sender,
                    pair: pair.clone(),
                    side: *side,
                    amount: *amount,
                    limit_price: *limit_price,
                    deadline_height: effective_deadline,
                });
            }
            Operation::CancelOrder { order_id } => {
                // Default lane only. Only marks the order for the block-level batch
                // pass, which performs the refund (possibly a non-native asset the
                // access list cannot name) and removal. Marking is a write to the
                // order's own state key; the fee already touches the account.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::DexRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::dex_order(*order_id))?;
                let order = self
                    .dex_orders
                    .get_mut(order_id)
                    .ok_or(ChainError::DexOrderNotFound)?;
                if order.owner != tx.sender {
                    return Err(ChainError::DexOrderNotOwner);
                }
                order.cancel_requested = true;
            }
            Operation::GrantMandate {
                agent_key,
                grant_nonce,
                budget_total,
                expiry_epoch,
                per_tx_max,
                rate_limit_per_day,
                counterparty_policy,
            } => {
                // Principal-signed financial action: default lane only (the budget
                // is escrowed from the sender's liquid balance). Supply-neutral:
                // liquid -> mandate_escrow.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::MandateRequiresDefaultLane);
                }
                let mandate_id = MandateId::derive(tx.sender, agent_key, *grant_nonce);
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::mandate(mandate_id))?;
                // Validate the grant parameters before touching any supply.
                let mandate = Mandate::new(
                    tx.sender,
                    *agent_key,
                    *budget_total,
                    *expiry_epoch,
                    *per_tx_max,
                    *rate_limit_per_day,
                    counterparty_policy.clone(),
                )?;
                if self.mandates.contains_key(&mandate_id) {
                    return Err(ChainError::MandateAlreadyExists);
                }
                // Escrow the budget. `debit_native` fails closed if the principal
                // cannot afford it (after the fee was already charged above), so the
                // whole transaction rolls back and no mandate is created.
                self.debit_native(tx.sender, *budget_total)?;
                self.mandate_escrow = self
                    .mandate_escrow
                    .checked_add(*budget_total)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.mandates.insert(mandate_id, mandate);
                events.push(Event::MandateGranted {
                    mandate_id,
                    principal: tx.sender,
                    agent_key: *agent_key,
                    budget_total: *budget_total,
                    expiry_epoch: *expiry_epoch,
                });
            }
            Operation::TopUpMandate { mandate_id, amount } => {
                // Principal-signed: default lane only (liquid -> mandate_escrow).
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::MandateRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::mandate(*mandate_id))?;
                if amount.is_zero() {
                    return Err(ChainError::InvalidMandate);
                }
                // Validate existence, ownership, and liveness before moving units.
                {
                    let mandate = self
                        .mandates
                        .get(mandate_id)
                        .ok_or(ChainError::MandateNotFound)?;
                    if mandate.principal != tx.sender {
                        return Err(ChainError::MandateNotOwner);
                    }
                    if mandate.revoked {
                        return Err(ChainError::MandateRevoked);
                    }
                }
                self.debit_native(tx.sender, *amount)?;
                self.mandate_escrow = self
                    .mandate_escrow
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let mandate = self
                    .mandates
                    .get_mut(mandate_id)
                    .ok_or(ChainError::MandateNotFound)?;
                mandate.budget_total = mandate
                    .budget_total
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::MandateToppedUp {
                    mandate_id: *mandate_id,
                    amount: *amount,
                    budget_total: mandate.budget_total,
                });
            }
            Operation::SpendUnderMandate {
                mandate_id,
                recipient,
                amount,
            } => {
                // Agent-signed spend: default lane only. The agent account (its
                // nonce/replay state and the default-lane base key) was ensured to
                // exist above; the mandate escrow — not the agent's balance — funds
                // both the principal moved and the fee. Every rejection path is a
                // distinct typed error, checked in the spec's fixed order.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::MandateRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::mandate(*mandate_id))?;
                access.write(StateKey::account(*recipient))?;
                // Validate the whole spend against an immutable borrow, then drop it
                // before mutating balances and the record.
                let (charge, next_spent, next_window, next_count) = {
                    let mandate = self
                        .mandates
                        .get(mandate_id)
                        .ok_or(ChainError::MandateNotFound)?;
                    // Bind the agent key: only the mandate's own agent key may
                    // spend. The envelope already proved the signer controls
                    // `tx.public_key`; this ties that key to this mandate.
                    if tx.public_key != mandate.agent_key {
                        return Err(ChainError::MandateAgentKeyMismatch);
                    }
                    if mandate.revoked {
                        return Err(ChainError::MandateRevoked);
                    }
                    if self.current_epoch > mandate.expiry_epoch.get() {
                        return Err(ChainError::MandateExpired);
                    }
                    if amount.is_zero() {
                        return Err(ChainError::MandateZeroAmount);
                    }
                    // The budget covers BOTH the principal and the fee, so the
                    // per-transaction cap must bound their SUM, not the principal
                    // alone. The fee is agent-chosen (via the priority bid) and is
                    // drawn from the same escrow; bounding only `amount` would let a
                    // single high-fee spend drain the whole budget past the per-tx
                    // and per-day limits the principal set. Checking `amount + fee`
                    // is what makes `per_tx_max` a real per-spend blast-radius cap.
                    let charge = amount
                        .checked_add(total_fee)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    if charge > mandate.per_tx_max {
                        return Err(ChainError::MandatePerTxExceeded);
                    }
                    let next_spent = mandate
                        .spent
                        .checked_add(charge)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    if next_spent > mandate.budget_total {
                        return Err(ChainError::MandateBudgetExceeded);
                    }
                    if !mandate.counterparty_policy.permits(recipient) {
                        return Err(ChainError::MandateCounterpartyNotAllowed);
                    }
                    // Per-day rate limit, in a deterministic epoch window. A window
                    // roll resets the counter; `0` means unlimited.
                    let window = config.mandate.window_index(self.current_epoch);
                    let current_count = if mandate.window_index == window {
                        mandate.spends_in_window
                    } else {
                        0
                    };
                    if mandate.rate_limit_per_day != 0
                        && current_count >= mandate.rate_limit_per_day
                    {
                        return Err(ChainError::MandateRateLimited);
                    }
                    let next_count = current_count
                        .checked_add(1)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    (charge, next_spent, window, next_count)
                };
                // Commit: escrow -> recipient (principal) + fee split (already added
                // to burned/pool above). Supply-neutral: mandate_escrow decreases by
                // exactly `amount + fee`, matching the recipient credit plus the
                // burn + validator-reward split.
                self.mandate_escrow = self
                    .mandate_escrow
                    .checked_sub(charge)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.credit_native(*recipient, *amount)?;
                let mandate = self
                    .mandates
                    .get_mut(mandate_id)
                    .ok_or(ChainError::MandateNotFound)?;
                mandate.spent = next_spent;
                mandate.window_index = next_window;
                mandate.spends_in_window = next_count;
                events.push(Event::MandateSpent {
                    mandate_id: *mandate_id,
                    agent_key: tx.public_key,
                    recipient: *recipient,
                    amount: *amount,
                    fee: total_fee,
                });
            }
            Operation::RevokeMandate { mandate_id } => {
                // Principal-signed: default lane only. Returns the unspent remainder
                // (mandate_escrow -> principal liquid) and marks the mandate revoked
                // so no further spend succeeds. Also the reclaim path for an expired
                // mandate. Supply-neutral.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::MandateRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::mandate(*mandate_id))?;
                let remainder = {
                    let mandate = self
                        .mandates
                        .get(mandate_id)
                        .ok_or(ChainError::MandateNotFound)?;
                    if mandate.principal != tx.sender {
                        return Err(ChainError::MandateNotOwner);
                    }
                    if mandate.revoked {
                        // Already revoked: nothing left to reclaim.
                        return Err(ChainError::MandateRevoked);
                    }
                    mandate.remaining()?
                };
                self.mandate_escrow = self
                    .mandate_escrow
                    .checked_sub(remainder)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.credit_native(tx.sender, remainder)?;
                let mandate = self
                    .mandates
                    .get_mut(mandate_id)
                    .ok_or(ChainError::MandateNotFound)?;
                mandate.revoked = true;
                // The remainder is now returned, so this mandate contributes zero to
                // `mandate_escrow`: set `spent` to the full budget to keep the
                // per-record `budget_total - spent` invariant in lockstep.
                mandate.spent = mandate.budget_total;
                events.push(Event::MandateRevoked {
                    mandate_id: *mandate_id,
                    principal: tx.sender,
                    refunded: remainder,
                });
            }
            Operation::RegisterService {
                namespace,
                create_nonce,
                categories,
                title,
                endpoint,
                interface,
                pricing,
                payment_flags,
            } => {
                // Permissionless-for-a-fee registry write (§15.5): records data only
                // and locks NO native units, so the supply invariant is unaffected
                // (only the ordinary, spam-priced transaction fee moves through the
                // existing burn / fee-pool split). Any authorization lane may pay the
                // fee — there is no per-op balance to draw from — so no default-lane
                // restriction (mirrors RegisterNamespace).
                let service_id = ServiceId::derive(*namespace, tx.sender, *create_nonce);
                access.write(StateKey::service(service_id))?;
                if self.services.contains_key(&service_id) {
                    return Err(ChainError::ServiceAlreadyExists);
                }
                // `new` validates every bounded field before the record is committed;
                // a malformed entry fails closed and rolls the whole tx back.
                let entry = ServiceEntry::new(
                    tx.sender,
                    *namespace,
                    categories.clone(),
                    title.clone(),
                    endpoint.clone(),
                    *interface,
                    pricing.clone(),
                    *payment_flags,
                )?;
                self.services.insert(service_id, entry);
                events.push(Event::ServiceRegistered {
                    service_id,
                    owner: tx.sender,
                    namespace: *namespace,
                });
            }
            Operation::UpdateService {
                service_id,
                categories,
                title,
                endpoint,
                interface,
                pricing,
                payment_flags,
            } => {
                access.write(StateKey::service(*service_id))?;
                // Only the current owner may update. Validate existence and ownership
                // before building the replacement, so a non-owner's attempt fails
                // closed and leaves the record unchanged.
                let existing = self
                    .services
                    .get(service_id)
                    .ok_or(ChainError::ServiceNotFound)?;
                if existing.owner != tx.sender {
                    return Err(ChainError::ServiceNotOwner);
                }
                // Rewrite the CURRENT revision in place, keeping owner/namespace/
                // status and bumping the revision. Only the current revision lives in
                // committed active state (prior revisions are an event-log concern).
                let mut updated = existing.clone();
                updated.categories = categories.clone();
                updated.title = title.clone();
                updated.endpoint = endpoint.clone();
                updated.interface = *interface;
                updated.pricing = pricing.clone();
                updated.payment_flags = *payment_flags;
                updated.revision = updated
                    .revision
                    .checked_add(1)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                updated.validate()?;
                let revision = updated.revision;
                self.services.insert(*service_id, updated);
                events.push(Event::ServiceUpdated {
                    service_id: *service_id,
                    revision,
                });
            }
            Operation::SetServiceStatus { service_id, status } => {
                access.write(StateKey::service(*service_id))?;
                let entry = self
                    .services
                    .get_mut(service_id)
                    .ok_or(ChainError::ServiceNotFound)?;
                if entry.owner != tx.sender {
                    return Err(ChainError::ServiceNotOwner);
                }
                entry.status = *status;
                entry.revision = entry
                    .revision
                    .checked_add(1)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let revision = entry.revision;
                events.push(Event::ServiceStatusChanged {
                    service_id: *service_id,
                    status: *status,
                    revision,
                });
            }
            Operation::SpendUnderMandateToService {
                mandate_id,
                service_id,
                amount,
            } => {
                // Agent-signed spend paying a registered service's owner. Default
                // lane only (the mandate escrow — not the agent's balance — funds
                // both the principal moved and the fee). Every rejection path is a
                // distinct typed error. The service entry is read-only (only its
                // owner's account is credited); the pay-to owner account is
                // state-derived and declared by the signer (fails closed if stale).
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::MandateRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::mandate(*mandate_id))?;
                access.read(StateKey::service(*service_id))?;
                // Resolve the service and validate the whole spend against immutable
                // borrows, then drop them before mutating balances and the record.
                let (service_owner, charge, next_spent, next_window, next_count) = {
                    let service = self
                        .services
                        .get(service_id)
                        .ok_or(ChainError::ServiceNotFound)?;
                    // Paying a Paused/Retired service is rejected before any
                    // counterparty or budget work.
                    if !service.status.is_active() {
                        return Err(ChainError::ServiceNotActive);
                    }
                    let mandate = self
                        .mandates
                        .get(mandate_id)
                        .ok_or(ChainError::MandateNotFound)?;
                    // Bind the agent key: only the mandate's own agent key may spend.
                    if tx.public_key != mandate.agent_key {
                        return Err(ChainError::MandateAgentKeyMismatch);
                    }
                    if mandate.revoked {
                        return Err(ChainError::MandateRevoked);
                    }
                    if self.current_epoch > mandate.expiry_epoch.get() {
                        return Err(ChainError::MandateExpired);
                    }
                    if amount.is_zero() {
                        return Err(ChainError::MandateZeroAmount);
                    }
                    // `per_tx_max` bounds the TOTAL leaving escrow per spend
                    // (principal + agent-chosen fee), not the principal alone — see
                    // the `SpendUnderMandate` arm for why bounding `amount` alone
                    // would let one high-fee spend drain the whole budget.
                    let charge = amount
                        .checked_add(total_fee)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    if charge > mandate.per_tx_max {
                        return Err(ChainError::MandatePerTxExceeded);
                    }
                    let next_spent = mandate
                        .spent
                        .checked_add(charge)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    if next_spent > mandate.budget_total {
                        return Err(ChainError::MandateBudgetExceeded);
                    }
                    // Category-allowlist resolution against the registry (§2 loop):
                    // the service OWNER satisfies a recipient allowlist, and an
                    // active service's categories resolve a category allowlist.
                    if !mandate.counterparty_policy.permits_service(service) {
                        return Err(ChainError::MandateCounterpartyNotAllowed);
                    }
                    // Per-day rate limit, in a deterministic epoch window.
                    let window = config.mandate.window_index(self.current_epoch);
                    let current_count = if mandate.window_index == window {
                        mandate.spends_in_window
                    } else {
                        0
                    };
                    if mandate.rate_limit_per_day != 0
                        && current_count >= mandate.rate_limit_per_day
                    {
                        return Err(ChainError::MandateRateLimited);
                    }
                    let next_count = current_count
                        .checked_add(1)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    (service.owner, charge, next_spent, window, next_count)
                };
                // The pay-to owner account is credited, so it must be a declared
                // writable key; the signer names it (state-derived pay-to), and an
                // undeclared or stale owner fails closed here.
                access.write(StateKey::account(service_owner))?;
                // Commit: escrow -> service owner (principal) + fee split (already
                // added to burned/pool above). Supply-neutral: mandate_escrow falls
                // by exactly `amount + fee`.
                self.mandate_escrow = self
                    .mandate_escrow
                    .checked_sub(charge)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.credit_native(service_owner, *amount)?;
                let mandate = self
                    .mandates
                    .get_mut(mandate_id)
                    .ok_or(ChainError::MandateNotFound)?;
                mandate.spent = next_spent;
                mandate.window_index = next_window;
                mandate.spends_in_window = next_count;
                events.push(Event::MandateSpentToService {
                    mandate_id: *mandate_id,
                    service_id: *service_id,
                    agent_key: tx.public_key,
                    recipient: service_owner,
                    amount: *amount,
                    fee: total_fee,
                });
            }
            Operation::CreateToken {
                namespace,
                create_nonce,
                metadata,
                mint_authority,
                freeze_authority,
                initial_supply,
                initial_recipient,
            } => {
                // Self-contained native token creation (§15): records a token in its
                // OWN identity space (never the bridge `asset_balances`) and locks a
                // NON-REFUNDABLE native creation deposit (liquid -> token_deposits) as
                // the anti-spam price. Token creation NEVER mints or burns native
                // WEBC. The account key is declared explicitly so a non-default fee
                // lane is covered (mirrors CreateObject).
                let token_id = TokenId::derive(*namespace, tx.sender, *create_nonce);
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::token(token_id))?;
                if !initial_supply.is_zero() {
                    access.write(StateKey::token_balance(token_id, *initial_recipient))?;
                }
                if self.tokens.contains_key(&token_id) {
                    return Err(ChainError::TokenAlreadyExists);
                }
                // Validate metadata before locking any deposit; a malformed record
                // fails closed and rolls the whole transaction back. `issued_supply`
                // starts at the optional initial mint, keeping the per-token invariant
                // (`sum(balances) == issued_supply`) true from creation.
                let record = TokenRecord::new(
                    tx.sender,
                    metadata.clone(),
                    *mint_authority,
                    *freeze_authority,
                    *initial_supply,
                )?;
                // Lock the deposit; `debit_native` fails closed if the creator cannot
                // afford it, so a token can never exist without its deposit.
                let deposit = config.token.creation_deposit;
                self.debit_native(tx.sender, deposit)?;
                self.token_deposits = self
                    .token_deposits
                    .checked_add(deposit)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.tokens.insert(token_id, record);
                // A brand-new token has no frozen accounts, so the initial mint needs
                // no freeze check.
                self.credit_token(token_id, *initial_recipient, *initial_supply)?;
                events.push(Event::TokenCreated {
                    token_id,
                    creator: tx.sender,
                    namespace: *namespace,
                    deposit,
                    initial_supply: *initial_supply,
                });
            }
            Operation::MintToken {
                token_id,
                recipient,
                amount,
            } => {
                access.write(StateKey::token(*token_id))?;
                access.write(StateKey::token_balance(*token_id, *recipient))?;
                // Authorize against the CURRENT mint authority: a renounced (None)
                // authority rejects, and any signer that is not the authority rejects.
                // The checked-add of `issued_supply` is computed under the immutable
                // borrow, then applied after crediting so the borrow is released.
                let next_issued = {
                    let token = self.tokens.get(token_id).ok_or(ChainError::TokenNotFound)?;
                    match token.mint_authority {
                        Some(authority) if authority == tx.sender => {}
                        _ => return Err(ChainError::TokenMintNotAuthorized),
                    }
                    token
                        .issued_supply
                        .checked_add(*amount)
                        .ok_or(ChainError::TokenSupplyOverflow)?
                };
                // A frozen recipient cannot receive. Freeze state is read directly on
                // the value path (not via the access recorder), matching the minimal
                // transfer access list.
                if self
                    .frozen_token_accounts
                    .contains(&(*token_id, *recipient))
                {
                    return Err(ChainError::TokenAccountFrozen);
                }
                // Credit the recipient and raise issued supply by the same amount.
                // Token mint NEVER touches native WEBC supply.
                self.credit_token(*token_id, *recipient, *amount)?;
                self.tokens
                    .get_mut(token_id)
                    .ok_or(ChainError::TokenNotFound)?
                    .issued_supply = next_issued;
                events.push(Event::TokenMinted {
                    token_id: *token_id,
                    recipient: *recipient,
                    amount: *amount,
                    issued_supply: next_issued,
                });
            }
            Operation::BurnToken { token_id, amount } => {
                access.write(StateKey::token(*token_id))?;
                access.write(StateKey::token_balance(*token_id, tx.sender))?;
                if !self.tokens.contains_key(token_id) {
                    return Err(ChainError::TokenNotFound);
                }
                // A frozen holder cannot burn.
                if self.frozen_token_accounts.contains(&(*token_id, tx.sender)) {
                    return Err(ChainError::TokenAccountFrozen);
                }
                // Debit the holder's OWN balance first (fails closed on insufficient
                // balance, pruning a zero remainder), then lower issued supply by the
                // same amount. Since a successful debit proves `balance >= amount` and
                // the per-token invariant keeps `issued_supply >= balance`, the
                // issued-supply subtraction cannot underflow. Burn NEVER touches
                // native WEBC supply.
                self.debit_token(*token_id, tx.sender, *amount)?;
                let token = self
                    .tokens
                    .get_mut(token_id)
                    .ok_or(ChainError::TokenNotFound)?;
                token.issued_supply = token
                    .issued_supply
                    .checked_sub(*amount)
                    .ok_or(ChainError::TokenSupplyOverflow)?;
                let issued_supply = token.issued_supply;
                events.push(Event::TokenBurned {
                    token_id: *token_id,
                    holder: tx.sender,
                    amount: *amount,
                    issued_supply,
                });
            }
            Operation::TransferToken {
                token_id,
                recipient,
                amount,
            } => {
                // The token record is READ-ONLY (only its paused flag is consulted);
                // the two per-account balance keys are the ONLY writes — an ordinary
                // transfer never writes a global per-token object (Phase 13 acceptance
                // criterion). A transfer conserves the token's supply, so
                // `issued_supply` (and thus the record) is never written.
                access.read(StateKey::token(*token_id))?;
                access.write(StateKey::token_balance(*token_id, tx.sender))?;
                access.write(StateKey::token_balance(*token_id, *recipient))?;
                // Both freeze markers are declared reads (see the matching access
                // list in `transaction.rs`), recorded UNCONDITIONALLY here — before
                // the short-circuiting frozen check — so the observed access always
                // equals the declaration and the parallel scheduler serializes this
                // transfer against a freeze/thaw of either party.
                access.read(StateKey::token_freeze(*token_id, tx.sender))?;
                access.read(StateKey::token_freeze(*token_id, *recipient))?;
                let paused = self
                    .tokens
                    .get(token_id)
                    .ok_or(ChainError::TokenNotFound)?
                    .paused;
                if paused {
                    return Err(ChainError::TokenPaused);
                }
                // Neither sender nor recipient may be frozen.
                if self.frozen_token_accounts.contains(&(*token_id, tx.sender))
                    || self
                        .frozen_token_accounts
                        .contains(&(*token_id, *recipient))
                {
                    return Err(ChainError::TokenAccountFrozen);
                }
                // Debit the sender (pruning a zero remainder), then credit the
                // recipient by the same amount.
                self.debit_token(*token_id, tx.sender, *amount)?;
                self.credit_token(*token_id, *recipient, *amount)?;
                events.push(Event::TokenTransferred {
                    token_id: *token_id,
                    from: tx.sender,
                    to: *recipient,
                    amount: *amount,
                });
            }
            Operation::SetTokenPaused { token_id, paused } => {
                access.write(StateKey::token(*token_id))?;
                let token = self
                    .tokens
                    .get_mut(token_id)
                    .ok_or(ChainError::TokenNotFound)?;
                // Only the current mint authority may pause/unpause (Phase 13a keeps a
                // single privileged authority); a renounced (None) mint authority
                // rejects.
                match token.mint_authority {
                    Some(authority) if authority == tx.sender => {}
                    _ => return Err(ChainError::TokenMintNotAuthorized),
                }
                token.paused = *paused;
                events.push(Event::TokenPausedChanged {
                    token_id: *token_id,
                    paused: *paused,
                });
            }
            Operation::FreezeTokenAccount { token_id, account } => {
                access.read(StateKey::token(*token_id))?;
                access.write(StateKey::token_freeze(*token_id, *account))?;
                // Authorize against the CURRENT freeze authority; a renounced (None)
                // authority rejects.
                let authority = self
                    .tokens
                    .get(token_id)
                    .ok_or(ChainError::TokenNotFound)?
                    .freeze_authority;
                match authority {
                    Some(a) if a == tx.sender => {}
                    _ => return Err(ChainError::TokenFreezeNotAuthorized),
                }
                self.frozen_token_accounts.insert((*token_id, *account));
                events.push(Event::TokenFreezeChanged {
                    token_id: *token_id,
                    account: *account,
                    frozen: true,
                });
            }
            Operation::ThawTokenAccount { token_id, account } => {
                access.read(StateKey::token(*token_id))?;
                access.write(StateKey::token_freeze(*token_id, *account))?;
                let authority = self
                    .tokens
                    .get(token_id)
                    .ok_or(ChainError::TokenNotFound)?
                    .freeze_authority;
                match authority {
                    Some(a) if a == tx.sender => {}
                    _ => return Err(ChainError::TokenFreezeNotAuthorized),
                }
                self.frozen_token_accounts.remove(&(*token_id, *account));
                events.push(Event::TokenFreezeChanged {
                    token_id: *token_id,
                    account: *account,
                    frozen: false,
                });
            }
            Operation::SetTokenAuthority {
                token_id,
                authority_kind,
                new_authority,
            } => {
                access.write(StateKey::token(*token_id))?;
                let token = self
                    .tokens
                    .get_mut(token_id)
                    .ok_or(ChainError::TokenNotFound)?;
                let current = match authority_kind {
                    TokenAuthorityKind::Mint => token.mint_authority,
                    TokenAuthorityKind::Freeze => token.freeze_authority,
                };
                // Only the CURRENT holder may transfer/renounce. A renounced (None)
                // authority has nothing to transfer, so it can never be restored —
                // renouncement is PERMANENT (a Phase 13 acceptance criterion).
                match current {
                    Some(authority) if authority == tx.sender => {}
                    _ => return Err(ChainError::TokenAuthorityNotAuthorized),
                }
                match authority_kind {
                    TokenAuthorityKind::Mint => token.mint_authority = *new_authority,
                    TokenAuthorityKind::Freeze => token.freeze_authority = *new_authority,
                }
                events.push(Event::TokenAuthorityChanged {
                    token_id: *token_id,
                    authority_kind: *authority_kind,
                    new_authority: *new_authority,
                });
            }
            Operation::CreateNftCollection {
                namespace,
                create_nonce,
                metadata,
                mint_authority,
                freeze_authority,
                max_supply,
                royalty_bps,
            } => {
                // Self-contained native NFT collection creation (§15): records a
                // collection in its OWN identity space and locks a NON-REFUNDABLE
                // native creation deposit (liquid -> nft_deposits) as the anti-spam
                // price. Creation NEVER mints or burns native WEBC and mints no items.
                // The account key is declared explicitly so a non-default fee lane is
                // covered (mirrors CreateToken).
                let collection_id = NftCollectionId::derive(*namespace, tx.sender, *create_nonce);
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::nft_collection(collection_id))?;
                if self.nft_collections.contains_key(&collection_id) {
                    return Err(ChainError::NftCollectionAlreadyExists);
                }
                // Validate metadata + royalty before locking any deposit; a malformed
                // record fails closed and rolls the whole transaction back.
                let record = NftCollection::new(
                    tx.sender,
                    metadata.clone(),
                    *mint_authority,
                    *freeze_authority,
                    *max_supply,
                    *royalty_bps,
                )?;
                // Lock the deposit; `debit_native` fails closed if the creator cannot
                // afford it, so a collection can never exist without its deposit.
                let deposit = config.nft.creation_deposit;
                self.debit_native(tx.sender, deposit)?;
                self.nft_deposits = self
                    .nft_deposits
                    .checked_add(deposit)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.nft_collections.insert(collection_id, record);
                events.push(Event::NftCollectionCreated {
                    collection_id,
                    creator: tx.sender,
                    namespace: *namespace,
                    deposit,
                });
            }
            Operation::MintNft {
                collection_id,
                recipient,
                item_metadata_hash,
            } => {
                // Mint bumps `next_serial`/`minted_count` (writes the collection
                // record) and creates ONE brand-new item at the chain-assigned
                // `serial = next_serial`. Reads of the collection's authority, paused
                // flag, cap, and counters are all covered by the read_write collection
                // declaration.
                access.write(StateKey::nft_collection(*collection_id))?;
                let (serial, next_serial, next_minted) = {
                    let collection = self
                        .nft_collections
                        .get(collection_id)
                        .ok_or(ChainError::NftCollectionNotFound)?;
                    // Authorize against the CURRENT mint authority: a renounced (None)
                    // authority rejects, and any non-authority signer rejects.
                    match collection.mint_authority {
                        Some(authority) if authority == tx.sender => {}
                        _ => return Err(ChainError::NftMintNotAuthorized),
                    }
                    // A paused collection cannot mint.
                    if collection.paused {
                        return Err(ChainError::NftCollectionPaused);
                    }
                    // Enforce the optional cap on total items ever minted. Because a
                    // burned serial is never reminted, burning does not free capacity.
                    if let Some(cap) = collection.max_supply {
                        if collection.minted_count >= cap {
                            return Err(ChainError::NftMaxSupplyReached);
                        }
                    }
                    let serial = collection.next_serial;
                    let next_serial = serial.checked_add(1).ok_or(ChainError::NftSerialOverflow)?;
                    let next_minted = collection
                        .minted_count
                        .checked_add(1)
                        .ok_or(ChainError::NftSerialOverflow)?;
                    (serial, next_serial, next_minted)
                };
                let nft_id = NftId::new(*collection_id, serial);
                // The new item's key is state-dependent (serial == next_serial) and
                // cannot be pre-declared in the signed access list, so the item is
                // created under the collection record's WRITE scope rather than via
                // the access recorder: the collection record is declared read_write,
                // so every mint of this collection serializes on it and no concurrent
                // transaction can reference this fresh serial. This is the ONE
                // deliberate exception (a chain-assigned id); every other item access
                // (transfer/burn/freeze/thaw) names a caller-supplied serial and DOES
                // declare its item key. See the matching note in `transaction.rs`.
                self.nft_items
                    .insert(nft_id, NftItem::new_owned(*recipient, *item_metadata_hash));
                // Commit the bumped counters after the item write releases the borrow.
                let collection = self
                    .nft_collections
                    .get_mut(collection_id)
                    .ok_or(ChainError::NftCollectionNotFound)?;
                collection.next_serial = next_serial;
                collection.minted_count = next_minted;
                events.push(Event::NftMinted {
                    nft_id,
                    recipient: *recipient,
                    item_metadata_hash: *item_metadata_hash,
                });
            }
            Operation::TransferNft {
                collection_id,
                serial,
                recipient,
            } => {
                // The collection record is READ-ONLY (only its paused flag is
                // consulted); the single item key is the ONLY write — an ordinary
                // transfer never writes a global per-collection object (Phase 13
                // acceptance criterion). The item's `frozen` flag lives ON the item
                // key we already write, so it needs no separate declaration.
                access.read(StateKey::nft_collection(*collection_id))?;
                access.write(StateKey::nft_item(*collection_id, *serial))?;
                let paused = self
                    .nft_collections
                    .get(collection_id)
                    .ok_or(ChainError::NftCollectionNotFound)?
                    .paused;
                if paused {
                    return Err(ChainError::NftCollectionPaused);
                }
                let nft_id = NftId::new(*collection_id, *serial);
                let item = self
                    .nft_items
                    .get_mut(&nft_id)
                    .ok_or(ChainError::NftItemNotFound)?;
                // Only the current owner may transfer.
                if item.owner != tx.sender {
                    return Err(ChainError::NftNotOwner);
                }
                // A frozen item cannot be transferred.
                if item.frozen {
                    return Err(ChainError::NftItemFrozen);
                }
                let from = item.owner;
                item.owner = *recipient;
                events.push(Event::NftTransferred {
                    nft_id,
                    from,
                    to: *recipient,
                });
            }
            Operation::BurnNft {
                collection_id,
                serial,
            } => {
                // A burn removes the item (writes the item key) and bumps
                // `burned_count` (writes the collection record). `next_serial` is NOT
                // decremented, so a burned serial is never reminted.
                access.write(StateKey::nft_collection(*collection_id))?;
                access.write(StateKey::nft_item(*collection_id, *serial))?;
                if !self.nft_collections.contains_key(collection_id) {
                    return Err(ChainError::NftCollectionNotFound);
                }
                let nft_id = NftId::new(*collection_id, *serial);
                let (owner, frozen) = {
                    let item = self
                        .nft_items
                        .get(&nft_id)
                        .ok_or(ChainError::NftItemNotFound)?;
                    (item.owner, item.frozen)
                };
                // Only the current owner may burn, and a frozen item cannot be burned.
                if owner != tx.sender {
                    return Err(ChainError::NftNotOwner);
                }
                if frozen {
                    return Err(ChainError::NftItemFrozen);
                }
                self.nft_items.remove(&nft_id);
                let collection = self
                    .nft_collections
                    .get_mut(collection_id)
                    .ok_or(ChainError::NftCollectionNotFound)?;
                collection.burned_count = collection
                    .burned_count
                    .checked_add(1)
                    .ok_or(ChainError::NftSerialOverflow)?;
                events.push(Event::NftBurned { nft_id, owner });
            }
            Operation::SetNftCollectionPaused {
                collection_id,
                paused,
            } => {
                access.write(StateKey::nft_collection(*collection_id))?;
                let collection = self
                    .nft_collections
                    .get_mut(collection_id)
                    .ok_or(ChainError::NftCollectionNotFound)?;
                // Only the current mint authority may pause/unpause (Phase 13b keeps a
                // single privileged authority); a renounced (None) mint authority
                // rejects.
                match collection.mint_authority {
                    Some(authority) if authority == tx.sender => {}
                    _ => return Err(ChainError::NftMintNotAuthorized),
                }
                collection.paused = *paused;
                events.push(Event::NftCollectionPausedChanged {
                    collection_id: *collection_id,
                    paused: *paused,
                });
            }
            Operation::FreezeNftItem {
                collection_id,
                serial,
            } => {
                access.read(StateKey::nft_collection(*collection_id))?;
                access.write(StateKey::nft_item(*collection_id, *serial))?;
                // Authorize against the CURRENT freeze authority; a renounced (None)
                // authority rejects.
                let authority = self
                    .nft_collections
                    .get(collection_id)
                    .ok_or(ChainError::NftCollectionNotFound)?
                    .freeze_authority;
                match authority {
                    Some(a) if a == tx.sender => {}
                    _ => return Err(ChainError::NftFreezeNotAuthorized),
                }
                let nft_id = NftId::new(*collection_id, *serial);
                let item = self
                    .nft_items
                    .get_mut(&nft_id)
                    .ok_or(ChainError::NftItemNotFound)?;
                item.frozen = true;
                events.push(Event::NftItemFreezeChanged {
                    nft_id,
                    frozen: true,
                });
            }
            Operation::ThawNftItem {
                collection_id,
                serial,
            } => {
                access.read(StateKey::nft_collection(*collection_id))?;
                access.write(StateKey::nft_item(*collection_id, *serial))?;
                let authority = self
                    .nft_collections
                    .get(collection_id)
                    .ok_or(ChainError::NftCollectionNotFound)?
                    .freeze_authority;
                match authority {
                    Some(a) if a == tx.sender => {}
                    _ => return Err(ChainError::NftFreezeNotAuthorized),
                }
                let nft_id = NftId::new(*collection_id, *serial);
                let item = self
                    .nft_items
                    .get_mut(&nft_id)
                    .ok_or(ChainError::NftItemNotFound)?;
                item.frozen = false;
                events.push(Event::NftItemFreezeChanged {
                    nft_id,
                    frozen: false,
                });
            }
            Operation::SetNftAuthority {
                collection_id,
                authority_kind,
                new_authority,
            } => {
                access.write(StateKey::nft_collection(*collection_id))?;
                let collection = self
                    .nft_collections
                    .get_mut(collection_id)
                    .ok_or(ChainError::NftCollectionNotFound)?;
                let current = match authority_kind {
                    NftAuthorityKind::Mint => collection.mint_authority,
                    NftAuthorityKind::Freeze => collection.freeze_authority,
                };
                // Only the CURRENT holder may transfer/renounce. A renounced (None)
                // authority has nothing to transfer, so it can never be restored —
                // renouncement is PERMANENT (a Phase 13 acceptance criterion).
                match current {
                    Some(authority) if authority == tx.sender => {}
                    _ => return Err(ChainError::NftAuthorityNotAuthorized),
                }
                match authority_kind {
                    NftAuthorityKind::Mint => collection.mint_authority = *new_authority,
                    NftAuthorityKind::Freeze => collection.freeze_authority = *new_authority,
                }
                events.push(Event::NftAuthorityChanged {
                    collection_id: *collection_id,
                    authority_kind: *authority_kind,
                    new_authority: *new_authority,
                });
            }
            Operation::CreateGovernanceInstance {
                namespace,
                create_nonce,
                weight_token,
                config: gov_config,
            } => {
                // Self-contained native governance instance creation (§15): records
                // an instance in its OWN identity space and locks a NON-REFUNDABLE
                // native creation deposit (liquid -> governance_deposits) as the
                // anti-spam price. Creation NEVER mints or burns native WEBC. The
                // account key is declared explicitly so a non-default fee lane is
                // covered (mirrors CreateToken).
                let instance_id =
                    GovernanceInstanceId::derive(*namespace, tx.sender, *create_nonce);
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::governance_instance(instance_id))?;
                access.read(StateKey::token(*weight_token))?;
                if self.governance_instances.contains_key(&instance_id) {
                    return Err(ChainError::GovernanceInstanceAlreadyExists);
                }
                // The instance must bind an EXISTING fungible token; otherwise votes
                // and quorum could never resolve.
                if !self.tokens.contains_key(weight_token) {
                    return Err(ChainError::TokenNotFound);
                }
                // Validate the config before locking any deposit; a malformed config
                // fails closed and rolls the whole transaction back.
                let instance = GovernanceInstance::new(tx.sender, *weight_token, *gov_config)?;
                let deposit = config.governance.creation_deposit;
                self.debit_native(tx.sender, deposit)?;
                self.governance_deposits = self
                    .governance_deposits
                    .checked_add(deposit)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.governance_instances.insert(instance_id, instance);
                events.push(Event::GovernanceInstanceCreated {
                    instance_id,
                    creator: tx.sender,
                    namespace: *namespace,
                    weight_token: *weight_token,
                    deposit,
                });
            }
            Operation::FundGovernanceTreasury {
                instance_id,
                amount,
            } => {
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::governance_instance(*instance_id))?;
                if !self.governance_instances.contains_key(instance_id) {
                    return Err(ChainError::GovernanceInstanceNotFound);
                }
                // Move native units liquid -> treasury bucket (supply-neutral). The
                // debit fails closed if the funder cannot afford it, so the treasury
                // can never grow without a matching liquid decrease.
                self.debit_native(tx.sender, *amount)?;
                self.governance_treasury = self
                    .governance_treasury
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let instance = self
                    .governance_instances
                    .get_mut(instance_id)
                    .ok_or(ChainError::GovernanceInstanceNotFound)?;
                instance.treasury = instance
                    .treasury
                    .checked_add(*amount)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let treasury = instance.treasury;
                events.push(Event::GovernanceTreasuryFunded {
                    instance_id: *instance_id,
                    funder: tx.sender,
                    amount: *amount,
                    treasury,
                });
            }
            Operation::OpenProposal {
                instance_id,
                action,
            } => {
                access.write(StateKey::governance_instance(*instance_id))?;
                // Read the instance (weight token, config, nonce, treasury) under an
                // immutable borrow first, then mutate after the proposal write.
                let (weight_token, gov_config, proposal_nonce, treasury) = {
                    let instance = self
                        .governance_instances
                        .get(instance_id)
                        .ok_or(ChainError::GovernanceInstanceNotFound)?;
                    (
                        instance.weight_token,
                        instance.config,
                        instance.next_proposal_nonce,
                        instance.treasury,
                    )
                };
                // The proposer must currently hold at least the proposal threshold of
                // the weight token. The balance key is declared read (state-derived
                // weight token); recorded here so observed == declared on success.
                access.read(StateKey::token_balance(weight_token, tx.sender))?;
                let held = self
                    .token_balances
                    .get(&(weight_token, tx.sender))
                    .copied()
                    .unwrap_or(Amount::ZERO);
                if held < gov_config.proposal_threshold {
                    return Err(ChainError::GovernanceProposalThresholdNotMet);
                }
                // Sanity-check a treasury payout against the CURRENT treasury.
                // Execution re-checks the LIVE treasury (mandatory), since it can
                // shrink via a competing payout between open and execute.
                if let GovernanceAction::TreasuryTransfer { amount, .. } = action {
                    if *amount > treasury {
                        return Err(ChainError::GovernanceTreasuryInsufficient);
                    }
                }
                let proposal_id = ProposalId::derive(*instance_id, proposal_nonce);
                let created_epoch = self.current_epoch;
                let voting_ends_epoch = created_epoch
                    .checked_add(gov_config.voting_period_epochs)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                // The new proposal key is state-dependent (the nonce) and cannot be
                // pre-declared in the signed access list, so the proposal is created
                // under the instance record's WRITE scope (mirrors MintNft's fresh
                // serial): the instance record is declared read_write, so every open
                // of this instance serializes on it and no concurrent transaction can
                // reference this fresh proposal id.
                self.governance_proposals.insert(
                    proposal_id,
                    GovernanceProposal {
                        instance_id: *instance_id,
                        proposer: tx.sender,
                        weight_token,
                        config: gov_config,
                        action: action.clone(),
                        created_epoch,
                        voting_ends_epoch,
                        eta_epoch: None,
                        status: GovProposalStatus::Active,
                        yes: Amount::ZERO,
                        no: Amount::ZERO,
                        abstain: Amount::ZERO,
                    },
                );
                // Bump the monotonic nonce after the proposal write releases the
                // borrow, so a proposal id is never reused.
                let instance = self
                    .governance_instances
                    .get_mut(instance_id)
                    .ok_or(ChainError::GovernanceInstanceNotFound)?;
                instance.next_proposal_nonce = proposal_nonce
                    .checked_add(1)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                events.push(Event::GovernanceProposalOpened {
                    proposal_id,
                    instance_id: *instance_id,
                    proposer: tx.sender,
                    voting_ends_epoch,
                });
            }
            Operation::CastVote {
                proposal_id,
                choice,
                weight_amount,
            } => {
                access.write(StateKey::governance_proposal(*proposal_id))?;
                access.write(StateKey::governance_vote(*proposal_id, tx.sender))?;
                // Read the proposal (weight token, status, voting window) under an
                // immutable borrow first.
                let (weight_token, status, voting_ends) = {
                    let proposal = self
                        .governance_proposals
                        .get(proposal_id)
                        .ok_or(ChainError::GovernanceProposalNotFound)?;
                    (
                        proposal.weight_token,
                        proposal.status,
                        proposal.voting_ends_epoch,
                    )
                };
                let escrow = gov_vote_escrow_address(*proposal_id);
                // Declare the token record (paused), both freeze markers, and both
                // balance keys UNCONDITIONALLY before the value checks, so the
                // observed access always equals the declaration and the parallel
                // scheduler serializes this vote against a freeze/thaw of either the
                // voter or the escrow (mirrors TransferToken).
                access.read(StateKey::token(weight_token))?;
                access.read(StateKey::token_freeze(weight_token, tx.sender))?;
                access.read(StateKey::token_freeze(weight_token, escrow))?;
                access.write(StateKey::token_balance(weight_token, tx.sender))?;
                access.write(StateKey::token_balance(weight_token, escrow))?;
                // A zero-weight lock is a no-op that would still block a later real
                // vote (the lock is the double-vote guard), so reject it.
                if weight_amount.is_zero() {
                    return Err(ChainError::GovernanceVoteWeightZero);
                }
                if status != GovProposalStatus::Active {
                    return Err(ChainError::GovernanceProposalNotActive);
                }
                if self.current_epoch > voting_ends {
                    return Err(ChainError::GovernanceVotingClosed);
                }
                // A voter may vote only ONCE per proposal (they already locked).
                if self
                    .governance_votes
                    .contains_key(&(*proposal_id, tx.sender))
                {
                    return Err(ChainError::GovernanceAlreadyVoted);
                }
                // Respect the weight token's freeze/pause exactly as TransferToken
                // does: a paused token or a frozen voter/escrow blocks the lock.
                if self
                    .tokens
                    .get(&weight_token)
                    .ok_or(ChainError::TokenNotFound)?
                    .paused
                {
                    return Err(ChainError::TokenPaused);
                }
                if self
                    .frozen_token_accounts
                    .contains(&(weight_token, tx.sender))
                    || self.frozen_token_accounts.contains(&(weight_token, escrow))
                {
                    return Err(ChainError::TokenAccountFrozen);
                }
                // LOCK: move weight-token units voter -> escrow. The debit fails
                // closed on an insufficient balance, so a voter locks only what they
                // hold. Because this is a MOVE within `token_balances`, the per-token
                // invariant `sum(balances) == issued_supply` is preserved, and the
                // recorded weight is the IMMUTABLE locked amount — a later transfer or
                // mint cannot inflate it (no after-snapshot manipulation), and the
                // units are no longer in the voter's balance to lock again (no double
                // voting).
                self.debit_token(weight_token, tx.sender, *weight_amount)?;
                self.credit_token(weight_token, escrow, *weight_amount)?;
                self.governance_votes.insert(
                    (*proposal_id, tx.sender),
                    VoteRecord {
                        choice: *choice,
                        weight: *weight_amount,
                    },
                );
                let proposal = self
                    .governance_proposals
                    .get_mut(proposal_id)
                    .ok_or(ChainError::GovernanceProposalNotFound)?;
                match choice {
                    VoteChoice::Yes => {
                        proposal.yes = proposal
                            .yes
                            .checked_add(*weight_amount)
                            .ok_or(ChainError::ArithmeticOverflow)?
                    }
                    VoteChoice::No => {
                        proposal.no = proposal
                            .no
                            .checked_add(*weight_amount)
                            .ok_or(ChainError::ArithmeticOverflow)?
                    }
                    VoteChoice::Abstain => {
                        proposal.abstain = proposal
                            .abstain
                            .checked_add(*weight_amount)
                            .ok_or(ChainError::ArithmeticOverflow)?
                    }
                }
                events.push(Event::GovernanceVoteCast {
                    proposal_id: *proposal_id,
                    voter: tx.sender,
                    choice: *choice,
                    weight: *weight_amount,
                });
            }
            Operation::ResolveProposal { proposal_id } => {
                access.write(StateKey::governance_proposal(*proposal_id))?;
                let (weight_token, status, voting_ends) = {
                    let proposal = self
                        .governance_proposals
                        .get(proposal_id)
                        .ok_or(ChainError::GovernanceProposalNotFound)?;
                    (
                        proposal.weight_token,
                        proposal.status,
                        proposal.voting_ends_epoch,
                    )
                };
                // The weight token's issued supply is the quorum DENOMINATOR (a
                // documented choice: voting WEIGHT is the immutable locked amount, so
                // double-voting/weight-manipulation are prevented regardless of
                // supply; the denominator only scales the participation bar). Declared
                // read so resolve serializes against a concurrent mint/burn.
                access.read(StateKey::token(weight_token))?;
                // Idempotent: only an Active proposal may be resolved.
                if status != GovProposalStatus::Active {
                    return Err(ChainError::GovernanceAlreadyResolved);
                }
                // Callable only AFTER voting ends.
                if self.current_epoch <= voting_ends {
                    return Err(ChainError::GovernanceVotingOpen);
                }
                let issued_supply = self
                    .tokens
                    .get(&weight_token)
                    .ok_or(ChainError::TokenNotFound)?
                    .issued_supply;
                let (new_status, eta) = {
                    let proposal = self
                        .governance_proposals
                        .get(proposal_id)
                        .ok_or(ChainError::GovernanceProposalNotFound)?;
                    // Both quorum-not-met and approval-not-met resolve to Defeated;
                    // only quorum AND approval yield Passed (with the timelock eta).
                    if proposal.quorum_met(issued_supply)? && proposal.approval_met()? {
                        let eta = proposal
                            .voting_ends_epoch
                            .checked_add(proposal.config.timelock_epochs)
                            .ok_or(ChainError::ArithmeticOverflow)?;
                        (GovProposalStatus::Passed, Some(eta))
                    } else {
                        (GovProposalStatus::Defeated, None)
                    }
                };
                let proposal = self
                    .governance_proposals
                    .get_mut(proposal_id)
                    .ok_or(ChainError::GovernanceProposalNotFound)?;
                proposal.status = new_status;
                proposal.eta_epoch = eta;
                events.push(Event::GovernanceProposalResolved {
                    proposal_id: *proposal_id,
                    status: new_status,
                    eta_epoch: eta,
                });
            }
            Operation::ExecuteProposal { proposal_id } => {
                access.write(StateKey::governance_proposal(*proposal_id))?;
                let (instance_id, action, status, eta_opt, voting_period) = {
                    let proposal = self
                        .governance_proposals
                        .get(proposal_id)
                        .ok_or(ChainError::GovernanceProposalNotFound)?;
                    (
                        proposal.instance_id,
                        proposal.action.clone(),
                        proposal.status,
                        proposal.eta_epoch,
                        proposal.config.voting_period_epochs,
                    )
                };
                if status != GovProposalStatus::Passed {
                    return Err(ChainError::GovernanceProposalNotPassed);
                }
                // A Passed proposal always carries an eta (set at resolve).
                let eta = eta_opt.ok_or(ChainError::GovernanceProposalNotPassed)?;
                if self.current_epoch < eta {
                    return Err(ChainError::GovernanceTimelockNotElapsed);
                }
                // Execution window `[eta, eta + voting_period)`: past it a stale
                // approval can no longer act on the treasury and the proposal expires
                // (the canonical governance "expired" state). `voting_period` is
                // non-zero, so the window is always non-empty.
                let window_end = eta
                    .checked_add(voting_period)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                let expired = self.current_epoch >= window_end;
                // Record the payout access in BOTH branches so observed == declared
                // regardless of expiry: a TreasuryTransfer always declares the
                // instance + recipient keys; a Signaling proposal declares neither.
                match &action {
                    GovernanceAction::TreasuryTransfer { recipient, amount } => {
                        access.write(StateKey::governance_instance(instance_id))?;
                        access.write(StateKey::account(*recipient))?;
                        if expired {
                            let proposal = self
                                .governance_proposals
                                .get_mut(proposal_id)
                                .ok_or(ChainError::GovernanceProposalNotFound)?;
                            proposal.status = GovProposalStatus::Expired;
                            events.push(Event::GovernanceProposalExpired {
                                proposal_id: *proposal_id,
                            });
                        } else {
                            // RE-CHECK the LIVE treasury (fail-closed): it may have
                            // shrunk since open/resolve via a competing payout.
                            let treasury = self
                                .governance_instances
                                .get(&instance_id)
                                .ok_or(ChainError::GovernanceInstanceNotFound)?
                                .treasury;
                            if *amount > treasury {
                                return Err(ChainError::GovernanceTreasuryInsufficient);
                            }
                            // Move native units treasury bucket -> recipient liquid
                            // (supply-neutral).
                            self.governance_treasury = self
                                .governance_treasury
                                .checked_sub(*amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                            let instance = self
                                .governance_instances
                                .get_mut(&instance_id)
                                .ok_or(ChainError::GovernanceInstanceNotFound)?;
                            instance.treasury = instance
                                .treasury
                                .checked_sub(*amount)
                                .ok_or(ChainError::ArithmeticOverflow)?;
                            self.credit_native(*recipient, *amount)?;
                            let proposal = self
                                .governance_proposals
                                .get_mut(proposal_id)
                                .ok_or(ChainError::GovernanceProposalNotFound)?;
                            proposal.status = GovProposalStatus::Executed;
                            events.push(Event::GovernanceProposalExecuted {
                                proposal_id: *proposal_id,
                                instance_id,
                            });
                        }
                    }
                    GovernanceAction::Signaling => {
                        let proposal = self
                            .governance_proposals
                            .get_mut(proposal_id)
                            .ok_or(ChainError::GovernanceProposalNotFound)?;
                        if expired {
                            proposal.status = GovProposalStatus::Expired;
                            events.push(Event::GovernanceProposalExpired {
                                proposal_id: *proposal_id,
                            });
                        } else {
                            proposal.status = GovProposalStatus::Executed;
                            events.push(Event::GovernanceProposalExecuted {
                                proposal_id: *proposal_id,
                                instance_id,
                            });
                        }
                    }
                }
            }
            Operation::ReclaimVote { proposal_id } => {
                access.read(StateKey::governance_proposal(*proposal_id))?;
                access.write(StateKey::governance_vote(*proposal_id, tx.sender))?;
                let (weight_token, status) = {
                    let proposal = self
                        .governance_proposals
                        .get(proposal_id)
                        .ok_or(ChainError::GovernanceProposalNotFound)?;
                    (proposal.weight_token, proposal.status)
                };
                let escrow = gov_vote_escrow_address(*proposal_id);
                access.write(StateKey::token_balance(weight_token, escrow))?;
                access.write(StateKey::token_balance(weight_token, tx.sender))?;
                // Reclaim only AFTER the proposal has resolved (Active is the only
                // non-resolved status).
                if !status.is_resolved() {
                    return Err(ChainError::GovernanceProposalNotResolved);
                }
                // The voter must have a lock to reclaim.
                let weight = self
                    .governance_votes
                    .get(&(*proposal_id, tx.sender))
                    .ok_or(ChainError::GovernanceNothingToReclaim)?
                    .weight;
                // Move the locked units escrow -> voter (the reverse of the vote
                // lock), preserving `sum(balances) == issued_supply`. The debit
                // cannot underflow: the escrow holds exactly the sum of live locks.
                self.debit_token(weight_token, escrow, weight)?;
                self.credit_token(weight_token, tx.sender, weight)?;
                self.governance_votes.remove(&(*proposal_id, tx.sender));
                events.push(Event::GovernanceVoteReclaimed {
                    proposal_id: *proposal_id,
                    voter: tx.sender,
                    weight,
                });
            }
            Operation::RegisterContract { manifest } => {
                // Default lane only: the registration fee draws from and burns
                // liquid (supply-neutral, like feed creation). The manifest record
                // is committed under the reserved module key.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::ContractRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::module(manifest.code_id))?;
                // Validate the hostile manifest before touching supply or state.
                manifest.validate(tx.sender)?;
                if self.contracts.contains_key(&manifest.code_id) {
                    return Err(ChainError::ContractAlreadyExists);
                }
                let fee = config.contracts.registration_fee;
                self.debit_native(tx.sender, fee)?;
                self.burned_fees = self
                    .burned_fees
                    .checked_add(fee)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.contracts.insert(manifest.code_id, manifest.clone());
                events.push(Event::ContractRegistered {
                    code_id: manifest.code_id,
                    namespace: manifest.namespace,
                    owner: tx.sender,
                    builtin: manifest.builtin,
                    fee_burned: fee,
                });
            }
            Operation::InvokeContract {
                code_id,
                namespace,
                declared_keys,
                input,
            } => {
                // Bound the hostile input before any work.
                if input.len() > MAX_CONTRACT_INPUT_BYTES {
                    return Err(ChainError::ContractInputTooLarge {
                        actual: input.len(),
                        maximum: MAX_CONTRACT_INPUT_BYTES,
                    });
                }
                // Resolve the manifest through the declared (read-only) module key.
                access.read(StateKey::module(*code_id))?;
                let manifest = self
                    .contracts
                    .get(code_id)
                    .ok_or(ChainError::ContractNotFound)?
                    .clone();
                // Bind the signed operation to the committed manifest so the access
                // list and the scheduler agree with the manifest and a call cannot
                // under- or mis-declare what it touches.
                if *namespace != manifest.namespace {
                    return Err(ChainError::ContractNamespaceMismatch);
                }
                if declared_keys.as_slice() != manifest.footprint.as_slice() {
                    return Err(ChainError::ContractFootprintMismatch);
                }
                // Run the audited built-in handler over its declared footprint under
                // the shared contract-call discipline (fresh gas meter seeded with
                // the admission `units` and capped at `gas_limit`, working-set load,
                // atomic write-back). The native and wasm paths differ ONLY in how the
                // handler is resolved; the metering, access enforcement, and rollback
                // are identical because both go through `run_contract_call`.
                let handler = builtin_contract(manifest.builtin);
                let (output, gas_consumed) = self.run_contract_call(
                    ContractCall {
                        namespace: manifest.namespace,
                        footprint: &manifest.footprint,
                        handler,
                        input,
                        admission_units: units,
                        gas_limit: tx.fee.gas_limit,
                    },
                    &mut access,
                )?;
                events.push(Event::ContractInvoked {
                    code_id: *code_id,
                    namespace: *namespace,
                    caller: tx.sender,
                    gas_consumed,
                    output_len: u64::try_from(output.len()).unwrap_or(u64::MAX),
                });
            }
            Operation::RegisterWasmContract { manifest, code } => {
                // Default lane only, like the native registration: the fee draws from
                // and burns liquid (supply-neutral). The manifest and its bytecode are
                // committed under the reserved module key.
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::ContractRequiresDefaultLane);
                }
                access.write(StateKey::account(tx.sender))?;
                access.write(StateKey::module(manifest.code_id))?;
                // Validate the hostile manifest AND its module bytes (size cap,
                // code-hash binding, deterministic-engine acceptance) before touching
                // supply or state — an invalid module is never stored.
                manifest.validate(tx.sender, code)?;
                // A `code_id` is unique across BOTH contract paths, since both address
                // their record by `StateKey::module(code_id)`.
                if self.contracts.contains_key(&manifest.code_id)
                    || self.wasm_contracts.contains_key(&manifest.code_id)
                {
                    return Err(ChainError::ContractAlreadyExists);
                }
                let fee = config.contracts.registration_fee;
                self.debit_native(tx.sender, fee)?;
                self.burned_fees = self
                    .burned_fees
                    .checked_add(fee)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                self.wasm_contracts
                    .insert(manifest.code_id, manifest.clone());
                self.wasm_code.insert(manifest.code_id, code.clone());
                events.push(Event::WasmContractRegistered {
                    code_id: manifest.code_id,
                    namespace: manifest.namespace,
                    owner: tx.sender,
                    code_hash: manifest.code_hash,
                    code_len: u64::try_from(code.len()).unwrap_or(u64::MAX),
                    fee_burned: fee,
                });
            }
            Operation::InvokeWasmContract {
                code_id,
                namespace,
                declared_keys,
                input,
            } => {
                // Bound the hostile input before any work.
                if input.len() > MAX_CONTRACT_INPUT_BYTES {
                    return Err(ChainError::ContractInputTooLarge {
                        actual: input.len(),
                        maximum: MAX_CONTRACT_INPUT_BYTES,
                    });
                }
                // Resolve the manifest through the declared (read-only) module key.
                access.read(StateKey::module(*code_id))?;
                let manifest = self
                    .wasm_contracts
                    .get(code_id)
                    .ok_or(ChainError::ContractNotFound)?
                    .clone();
                // Bind the signed operation to the committed manifest (identical
                // discipline to the native invoke): a call cannot under- or
                // mis-declare what it touches.
                if *namespace != manifest.namespace {
                    return Err(ChainError::ContractNamespaceMismatch);
                }
                if declared_keys.as_slice() != manifest.footprint.as_slice() {
                    return Err(ChainError::ContractFootprintMismatch);
                }
                // Load the immutable module bytes (committed under the same module
                // key) and run them on the deterministic engine through the SAME
                // shared discipline as the native path.
                let code = self
                    .wasm_code
                    .get(code_id)
                    .ok_or(ChainError::ContractNotFound)?
                    .clone();
                let handler = WasmContract::new(&code.0);
                let (output, gas_consumed) = self.run_contract_call(
                    ContractCall {
                        namespace: manifest.namespace,
                        footprint: &manifest.footprint,
                        handler: &handler,
                        input,
                        admission_units: units,
                        gas_limit: tx.fee.gas_limit,
                    },
                    &mut access,
                )?;
                events.push(Event::WasmContractInvoked {
                    code_id: *code_id,
                    namespace: *namespace,
                    caller: tx.sender,
                    gas_consumed,
                    output_len: u64::try_from(output.len()).unwrap_or(u64::MAX),
                });
            }
        }

        access.finish()?;

        Ok(Receipt {
            tx_hash,
            success: true,
            fee,
            units_consumed: units,
            events,
            error: None,
        })
    }

    /// Applies block-carried objective evidence without a transaction access list.
    ///
    /// Block construction already runs on a whole-block overlay, so any failure
    /// rolls back this slash together with every other block transition. The
    /// evidence is still independently signature-verified and replay-protected;
    /// only the transaction-specific declared-access bookkeeping is skipped.
    pub(crate) fn apply_block_slashing_evidence(
        &mut self,
        evidence: &SlashingEvidence,
        config: &ChainConfig,
    ) -> Result<SlashingOutcome, ChainError> {
        self.apply_slashing_evidence(evidence, config, None)
    }

    /// Shared deterministic slashing transition used by signed transactions and
    /// header-committed block evidence.
    fn apply_slashing_evidence(
        &mut self,
        evidence: &SlashingEvidence,
        config: &ChainConfig,
        mut access: Option<&mut StateAccessRecorder>,
    ) -> Result<SlashingOutcome, ChainError> {
        let validator_address = evidence.validator();
        Self::record_slashing_write(&mut access, StateKey::validator(validator_address))?;
        let consensus_key = self
            .validators
            .get(&validator_address)
            .ok_or(ChainError::ValidatorNotFound(validator_address))?
            .consensus_key;
        evidence.verify(config.protocol_version, &config.chain_id, &consensus_key)?;
        let evidence_hash = evidence.hash()?;
        Self::record_slashing_write(&mut access, StateKey::slashing_evidence(evidence_hash))?;
        if self.processed_slashing_evidence.contains(&evidence_hash) {
            return Err(ChainError::SlashingReplay);
        }

        let penalty_bps = slashing_bps(evidence, &config.slashing);
        Self::record_slashing_write(&mut access, StateKey::unbonding_queue(validator_address))?;
        let delegation_losses = self
            .delegations
            .iter()
            .filter(|((_, validator), _)| *validator == validator_address)
            .map(|(key, delegation)| {
                Ok((
                    *key,
                    delegation
                        .amount
                        .checked_mul_bps(penalty_bps)
                        .ok_or(ChainError::ArithmeticOverflow)?,
                ))
            })
            .filter(|result| result.as_ref().map_or(true, |(_, loss)| !loss.is_zero()))
            .collect::<Result<Vec<_>, ChainError>>()?;
        let delegated_slashed =
            delegation_losses
                .iter()
                .try_fold(Amount::ZERO, |total, (_, loss)| {
                    total
                        .checked_add(*loss)
                        .ok_or(ChainError::ArithmeticOverflow)
                })?;

        for ((delegator, validator), loss) in &delegation_losses {
            self.unbonding.apply_active_slash(
                *delegator,
                *validator,
                UnbondingKind::Delegation,
                *loss,
            )?;
        }
        let locked_slash = self.unbonding.slash_locked(
            validator_address,
            penalty_bps,
            Epoch::new(self.current_epoch),
        )?;
        for owner in locked_slash.locked_losses.keys() {
            Self::record_slashing_write(&mut access, StateKey::account(*owner))?;
        }

        Self::record_slashing_write(&mut access, StateKey::account(validator_address))?;
        for ((delegator, validator), _) in &delegation_losses {
            Self::record_slashing_write(&mut access, StateKey::delegation(*delegator, *validator))?;
            Self::record_slashing_write(&mut access, StateKey::account(*delegator))?;
        }
        let validator = self
            .validators
            .get_mut(&validator_address)
            .ok_or(ChainError::ValidatorNotFound(validator_address))?;
        let outcome = slash_validator_with_delegation_loss(
            validator,
            evidence,
            &config.slashing,
            delegated_slashed,
        )?;
        self.unbonding.apply_active_slash(
            validator_address,
            validator_address,
            UnbondingKind::OperatorStake,
            outcome.self_slashed,
        )?;
        let operator = self.account_mut(validator_address)?;
        operator.staked = operator
            .staked
            .checked_sub(outcome.self_slashed)
            .ok_or(ChainError::ArithmeticOverflow)?;
        for ((delegator, validator), loss) in delegation_losses {
            let delegation = self
                .delegations
                .get_mut(&(delegator, validator))
                .ok_or(ChainError::DelegationNotFound)?;
            delegation.amount = delegation
                .amount
                .checked_sub(loss)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let account = self.account_mut(delegator)?;
            account.delegated = account
                .delegated
                .checked_sub(loss)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        let locked_total_slashed = locked_slash.total_locked_slashed;
        for (owner, loss) in locked_slash.locked_losses {
            let account = self.account_mut(owner)?;
            account.unbonding = account
                .unbonding
                .checked_sub(loss)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        let total_slashed = outcome
            .self_slashed
            .checked_add(outcome.delegated_slashed)
            .and_then(|amount| amount.checked_add(locked_total_slashed))
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.slashed_units = self
            .slashed_units
            .checked_add(total_slashed)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.processed_slashing_evidence.insert(evidence_hash);
        Ok(outcome)
    }

    /// Records a slashing write for a user transaction, or deliberately skips
    /// access-list bookkeeping for authenticated block-system evidence.
    fn record_slashing_write(
        access: &mut Option<&mut StateAccessRecorder>,
        key: StateKey,
    ) -> Result<(), ChainError> {
        if let Some(recorder) = access.as_deref_mut() {
            recorder.write(key)?;
        }
        Ok(())
    }

    fn process_incoming_bridge_message(
        &mut self,
        message: &BridgeMessage,
        action: IncomingBridgeAction,
        access: &mut StateAccessRecorder,
    ) -> Result<Hash256, ChainError> {
        if message.destination_chain != ExternalChain::Webc {
            return Err(ChainError::BridgeDestinationMismatch);
        }
        if message.amount.is_zero() {
            return Err(ChainError::BridgeAmountZero);
        }
        let message_hash = message.hash()?;
        access.write(StateKey::bridge_message(message_hash))?;
        if self.processed_bridge_messages.contains(&message_hash) {
            return Err(ChainError::BridgeReplay);
        }
        let recipient_bytes: [u8; 32] = message
            .recipient
            .as_slice()
            .try_into()
            .map_err(|_| ChainError::InvalidBridgeRecipient)?;
        let recipient = Address::from_bytes(recipient_bytes);
        match action {
            IncomingBridgeAction::MintRepresentation => {
                let AssetId::External { origin_chain, .. } = &message.asset else {
                    return Err(ChainError::InvalidBridgeAssetFlow);
                };
                if *origin_chain != message.source_chain
                    || message.source_chain == ExternalChain::Webc
                {
                    return Err(ChainError::BridgeSourceMismatch);
                }
                access.write(StateKey::asset_balance(message.asset.clone(), recipient))?;
                self.credit_asset_or_native(recipient, &message.asset, message.amount)?;
            }
            IncomingBridgeAction::ReleaseNative => {
                if message.asset != AssetId::NativeWebc
                    || message.source_chain == ExternalChain::Webc
                {
                    return Err(ChainError::InvalidBridgeAssetFlow);
                }
                access.write(StateKey::account(recipient))?;
                access.write(StateKey::bridge_escrow(message.source_chain.clone()))?;
                self.debit_native_bridge_escrow(message.source_chain.clone(), message.amount)?;
                self.credit_native(recipient, message.amount)?;
            }
        }
        self.processed_bridge_messages.insert(message_hash);
        Ok(message_hash)
    }

    fn next_bridge_message(
        &mut self,
        draft: OutgoingBridgeMessage,
        access: &mut StateAccessRecorder,
    ) -> Result<BridgeMessage, ChainError> {
        access.write(StateKey::protocol(ProtocolStateKey::BridgeNonce))?;
        let nonce = self.bridge_nonce;
        self.bridge_nonce = self
            .bridge_nonce
            .checked_add(1)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(BridgeMessage {
            source_chain: draft.source_chain,
            destination_chain: draft.destination_chain,
            nonce,
            asset: draft.asset,
            sender: draft.sender,
            recipient: draft.recipient,
            amount: draft.amount,
            source_tx: draft.source_tx,
        })
    }

    fn credit_native_bridge_escrow(
        &mut self,
        domain: ExternalChain,
        amount: Amount,
    ) -> Result<(), ChainError> {
        let current = self
            .native_bridge_escrow
            .get(&domain)
            .copied()
            .unwrap_or(Amount::ZERO);
        self.native_bridge_escrow.insert(
            domain,
            current
                .checked_add(amount)
                .ok_or(ChainError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    fn debit_native_bridge_escrow(
        &mut self,
        domain: ExternalChain,
        amount: Amount,
    ) -> Result<(), ChainError> {
        let available = self
            .native_bridge_escrow
            .get(&domain)
            .copied()
            .unwrap_or(Amount::ZERO);
        if available < amount {
            return Err(ChainError::InsufficientBridgeEscrow {
                needed: amount,
                available,
            });
        }
        let remaining = available
            .checked_sub(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if remaining.is_zero() {
            self.native_bridge_escrow.remove(&domain);
        } else {
            self.native_bridge_escrow.insert(domain, remaining);
        }
        Ok(())
    }

    /// Enforces a session key's constraints and advances its cumulative spend.
    ///
    /// Runs during execution before the operation mutates balances. Every
    /// failure returns a typed error and, because execution runs on a cloned
    /// overlay, rolls back the entire transaction. A session key never gains
    /// authority beyond its declared lane, operations, per-use amount,
    /// cumulative budget, per-use fee, and expiry epoch. The lane binding was
    /// already checked in `verify_transaction_authorization`.
    fn enforce_session_key_use(
        &mut self,
        tx: &Transaction,
        id: SessionKeyId,
        total_fee: Amount,
        access: &mut StateAccessRecorder,
        events: &mut Vec<Event>,
    ) -> Result<(), ChainError> {
        access.write(StateKey::session_key(tx.sender, id))?;
        let session = self
            .session_keys
            .get(&(tx.sender, id))
            .ok_or(ChainError::SessionKeyNotFound)?;
        if self.current_epoch > session.expires_after_epoch.get() {
            return Err(ChainError::SessionKeyExpired);
        }
        let principal =
            session_permitted_principal(&tx.operation, session.constraints.allowed_operations)?;
        if principal > session.constraints.max_amount_per_use {
            return Err(ChainError::SessionKeyAmountExceeded);
        }
        let next_spent = session
            .spent_amount
            .checked_add(principal)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if next_spent > session.constraints.total_amount_budget {
            return Err(ChainError::SessionKeyBudgetExceeded);
        }
        // Bound the maximum fee the transaction authorizes, independent of the
        // current base fee, matching the off-chain grant's per-transaction cap.
        let max_fee = Amount(
            u128::from(tx.fee.gas_limit)
                .checked_mul(u128::from(tx.fee.max_fee_per_unit))
                .ok_or(ChainError::ArithmeticOverflow)?,
        );
        if max_fee > session.constraints.max_fee_per_use {
            return Err(ChainError::SessionKeyFeeExceeded);
        }
        // Bound cumulative fees on the fee actually charged, so a compromised key
        // cannot drain the account through fees on unlimited tiny transfers.
        let next_fees = session
            .spent_fees
            .checked_add(total_fee)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if next_fees > session.constraints.total_fee_budget {
            return Err(ChainError::SessionKeyFeeBudgetExceeded);
        }
        let record = self
            .session_keys
            .get_mut(&(tx.sender, id))
            .ok_or(ChainError::SessionKeyNotFound)?;
        record.spent_amount = next_spent;
        record.spent_fees = next_fees;
        events.push(Event::SessionKeyUsed {
            owner: tx.sender,
            session_key: id,
            amount: principal,
        });
        Ok(())
    }

    fn account_mut(&mut self, address: Address) -> Result<&mut Account, ChainError> {
        self.accounts
            .get_mut(&address)
            .ok_or(ChainError::AccountNotFound(address))
    }

    fn debit_native(&mut self, address: Address, amount: Amount) -> Result<(), ChainError> {
        if amount.is_zero() {
            return Ok(());
        }
        let account = self.account_mut(address)?;
        if account.balance < amount {
            return Err(ChainError::InsufficientBalance {
                address,
                needed: amount,
                available: account.balance,
            });
        }
        account.balance = account
            .balance
            .checked_sub(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Opens one prepaid fee lane under a caller-owned transaction overlay.
    ///
    /// Lane management is intentionally authorized only by the default lane.
    /// Both transaction versions call this helper after their distinct parent
    /// fee and replay rules have run.
    pub(crate) fn apply_native_lane_open(
        &mut self,
        sender: Address,
        authorization_lane: AuthorizationLaneId,
        lane: AuthorizationLaneId,
        fee_deposit: Amount,
        effects: NativeActionEffects<'_>,
    ) -> Result<(), ChainError> {
        if !authorization_lane.is_default() {
            return Err(ChainError::LaneManagementRequiresDefault);
        }
        if lane.is_default() {
            return Err(ChainError::DefaultAuthorizationLaneReserved);
        }
        if fee_deposit.is_zero() {
            return Err(ChainError::AuthorizationLaneDepositZero);
        }
        let NativeActionEffects { access, events } = effects;
        access.write(StateKey::authorization_lane(sender, lane))?;
        if self.authorization_lanes.contains_key(&(sender, lane)) {
            return Err(ChainError::AuthorizationLaneExists);
        }
        self.debit_native(sender, fee_deposit)?;
        self.authorization_lanes.insert(
            (sender, lane),
            AuthorizationLane::new(sender, lane, fee_deposit),
        );
        events.push(Event::AuthorizationLaneOpened {
            owner: sender,
            lane,
            fee_deposit,
        });
        Ok(())
    }

    /// Installs the first versioned account policy in the caller action overlay.
    ///
    /// The signing key becomes the active transaction key. Both protocol paths
    /// require the default lane and reject replacement through this migration
    /// action; later rotations use their separately authorized transitions.
    pub(crate) fn apply_native_install_authorization_policy(
        &mut self,
        sender: Address,
        active_transaction_key: webc_crypto::PublicKeyBytes,
        authorization_lane: AuthorizationLaneId,
        post_quantum_root: crate::PostQuantumRoot,
        effects: NativeActionEffects<'_>,
    ) -> Result<(), ChainError> {
        if !authorization_lane.is_default() {
            return Err(ChainError::AuthorizationPolicyRequiresDefaultLane);
        }
        let NativeActionEffects { access, events } = effects;
        access.write(StateKey::authorization_policy(sender))?;
        if self.authorization_policies.contains_key(&sender) {
            return Err(ChainError::AuthorizationPolicyAlreadyExists);
        }
        let policy = AccountAuthorizationPolicy::new_v1(active_transaction_key, post_quantum_root)?;
        let revision = policy.revision();
        self.authorization_policies.insert(sender, policy);
        events.push(Event::AuthorizationPolicyInstalled {
            owner: sender,
            revision,
            post_quantum_root,
        });
        Ok(())
    }

    /// Adds native fee units to one existing prepaid lane in the caller overlay.
    pub(crate) fn apply_native_lane_fund(
        &mut self,
        sender: Address,
        authorization_lane: AuthorizationLaneId,
        lane: AuthorizationLaneId,
        fee_deposit: Amount,
        effects: NativeActionEffects<'_>,
    ) -> Result<(), ChainError> {
        if !authorization_lane.is_default() {
            return Err(ChainError::LaneManagementRequiresDefault);
        }
        if fee_deposit.is_zero() {
            return Err(ChainError::AuthorizationLaneDepositZero);
        }
        let NativeActionEffects { access, events } = effects;
        access.write(StateKey::authorization_lane(sender, lane))?;
        self.debit_native(sender, fee_deposit)?;
        let target = self
            .authorization_lanes
            .get_mut(&(sender, lane))
            .ok_or(ChainError::AuthorizationLaneNotFound)?;
        target.fee_balance = target
            .fee_balance
            .checked_add(fee_deposit)
            .ok_or(ChainError::ArithmeticOverflow)?;
        events.push(Event::AuthorizationLaneFunded {
            owner: sender,
            lane,
            fee_deposit,
        });
        Ok(())
    }

    /// Claims all pending operator rewards in the caller's disposable overlay.
    pub(crate) fn apply_native_claim_validator_rewards(
        &mut self,
        sender: Address,
        effects: NativeActionEffects<'_>,
    ) -> Result<(), ChainError> {
        let NativeActionEffects { access, events } = effects;
        access.write(StateKey::account(sender))?;
        access.write(StateKey::validator(sender))?;
        let reward = {
            let validator = self
                .validators
                .get_mut(&sender)
                .ok_or(ChainError::ValidatorNotFound(sender))?;
            let reward = validator.accumulated_rewards;
            validator.accumulated_rewards = Amount::ZERO;
            reward
        };
        self.credit_native(sender, reward)?;
        events.push(Event::ValidatorRewardsClaimed {
            validator: sender,
            amount: reward,
        });
        Ok(())
    }

    /// Claims one delegation position's pending rewards in the caller overlay.
    pub(crate) fn apply_native_claim_delegator_rewards(
        &mut self,
        sender: Address,
        validator: Address,
        effects: NativeActionEffects<'_>,
    ) -> Result<(), ChainError> {
        let NativeActionEffects { access, events } = effects;
        access.write(StateKey::account(sender))?;
        access.write(StateKey::delegation(sender, validator))?;
        let reward = {
            let delegation = self
                .delegations
                .get_mut(&(sender, validator))
                .ok_or(ChainError::DelegationNotFound)?;
            let reward = delegation.accumulated_rewards;
            delegation.accumulated_rewards = Amount::ZERO;
            reward
        };
        self.credit_native(sender, reward)?;
        events.push(Event::DelegatorRewardsClaimed {
            delegator: sender,
            validator,
            amount: reward,
        });
        Ok(())
    }

    /// Claims matured unbonding principal inside the caller's action overlay.
    pub(crate) fn apply_native_claim_unbonded(
        &mut self,
        sender: Address,
        validator: Address,
        request_id: UnbondingRequestId,
        effects: NativeActionEffects<'_>,
    ) -> Result<(), ChainError> {
        let NativeActionEffects { access, events } = effects;
        access.write(StateKey::account(sender))?;
        access.write(StateKey::unbonding_queue(validator))?;
        let request = self
            .unbonding
            .get(request_id)
            .ok_or(ChainError::UnbondingRequestNotFound)?;
        if request.validator != validator {
            return Err(ChainError::UnbondingRequestNotFound);
        }
        let kind = request.kind;
        let amount = self.unbonding.claim(request_id, sender)?;
        self.credit_claimed_unbonding_principal(sender, request_id, kind, amount, events)
    }

    /// Stages a V5 matured-principal claim without cloning the global queue.
    ///
    /// The request journal owns ordered claim visibility and commit validation;
    /// this sparse `ChainState` owns only the declared account and event effects.
    pub(crate) fn apply_native_claim_unbonded_staged(
        &mut self,
        sender: Address,
        validator: Address,
        request_id: UnbondingRequestId,
        journal: &mut UnbondingClaimJournalV1,
        effects: NativeActionEffects<'_>,
    ) -> Result<(), ChainError> {
        let NativeActionEffects { access, events } = effects;
        access.write(StateKey::account(sender))?;
        access.write(StateKey::unbonding_queue(validator))?;
        let (kind, amount) = journal.stage_claim(request_id, sender, validator)?;
        self.credit_claimed_unbonding_principal(sender, request_id, kind, amount, events)
    }

    /// Credits one already-authorized claim and updates its account mirror.
    fn credit_claimed_unbonding_principal(
        &mut self,
        sender: Address,
        request_id: UnbondingRequestId,
        kind: UnbondingKind,
        amount: Amount,
        events: &mut Vec<Event>,
    ) -> Result<(), ChainError> {
        let account = self.account_mut(sender)?;
        account.unbonding = account
            .unbonding
            .checked_sub(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.credit_native(sender, amount)?;
        events.push(Event::UnbondingClaimed {
            request_id,
            delegator: sender,
            kind,
            amount,
        });
        Ok(())
    }

    /// Applies one checked owned-object authority transfer in the caller's overlay.
    ///
    /// The helper changes no account balance, fee, nonce, or authorization state;
    /// those remain transaction-envelope responsibilities in both protocol paths.
    pub(crate) fn apply_native_object_transfer(
        &mut self,
        sender: Address,
        object_id: ObjectId,
        namespace: Hash256,
        expected_version: ObjectVersion,
        new_owner: Address,
        effects: NativeActionEffects<'_>,
    ) -> Result<(), ChainError> {
        let NativeActionEffects { access, events } = effects;
        access.write(StateKey::object(object_id))?;
        access.write(StateKey::application(namespace, object_id.hash()))?;
        let object = self
            .objects
            .get_mut(&object_id)
            .ok_or(ChainError::ObjectNotFound)?;
        validate_owned_object(object, sender, namespace, expected_version)?;
        object.version = object.version.checked_next()?;
        object.owner = ObjectOwner::Address(new_owner);
        events.push(Event::ObjectTransferred {
            object_id,
            from: sender,
            to: new_owner,
            version: object.version,
        });
        Ok(())
    }

    /// Applies one native transfer under a caller-owned transaction overlay.
    ///
    /// Both V4 single-operation execution and V5 ordered action execution use
    /// this exact transition. The caller owns fee/nonce handling and rollback;
    /// this helper only records action access, moves principal, and emits the
    /// native event. Any error leaves the caller's cloned overlay disposable.
    pub(crate) fn apply_native_transfer(
        &mut self,
        sender: Address,
        recipient: Address,
        amount: Amount,
        effects: NativeActionEffects<'_>,
    ) -> Result<(), ChainError> {
        let NativeActionEffects { access, events } = effects;
        // On the default lane the parent fee step already records the sender
        // account write. Non-default lanes pay fees elsewhere, so recording it
        // here is required to consume the signed action declaration.
        access.write(StateKey::account(sender))?;
        access.write(StateKey::account(recipient))?;
        self.debit_native(sender, amount)?;
        self.credit_native(recipient, amount)?;
        events.push(Event::Transfer {
            from: sender,
            to: recipient,
            amount,
        });
        Ok(())
    }

    fn credit_native(&mut self, address: Address, amount: Amount) -> Result<(), ChainError> {
        if amount.is_zero() {
            return Ok(());
        }
        let account = self.accounts.entry(address).or_default();
        account.balance = account
            .balance
            .checked_add(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Credits `amount` of `token_id` to `holder`'s token balance (Phase 13a, §15).
    ///
    /// A zero credit is a no-op (so no zero entry is ever created). Checked
    /// addition; overflow returns [`ChainError::TokenSupplyOverflow`]. This moves
    /// only the token's own balance — never native WEBC.
    fn credit_token(
        &mut self,
        token_id: TokenId,
        holder: Address,
        amount: Amount,
    ) -> Result<(), ChainError> {
        if amount.is_zero() {
            return Ok(());
        }
        let entry = self
            .token_balances
            .entry((token_id, holder))
            .or_insert(Amount::ZERO);
        *entry = entry
            .checked_add(amount)
            .ok_or(ChainError::TokenSupplyOverflow)?;
        Ok(())
    }

    /// Debits `amount` of `token_id` from `holder`'s token balance, PRUNING a
    /// balance that reaches zero (Phase 13a, §15).
    ///
    /// A zero debit is a no-op. Rejects an insufficient balance with
    /// [`ChainError::TokenInsufficientBalance`] (a missing entry is a zero balance).
    /// When the remaining balance is zero the entry is removed, so the balance map
    /// never stores zeros and stays bounded. Moves only the token's own balance —
    /// never native WEBC.
    fn debit_token(
        &mut self,
        token_id: TokenId,
        holder: Address,
        amount: Amount,
    ) -> Result<(), ChainError> {
        if amount.is_zero() {
            return Ok(());
        }
        let current = self
            .token_balances
            .get(&(token_id, holder))
            .copied()
            .unwrap_or(Amount::ZERO);
        let remaining = current
            .checked_sub(amount)
            .ok_or(ChainError::TokenInsufficientBalance)?;
        if remaining.is_zero() {
            self.token_balances.remove(&(token_id, holder));
        } else {
            self.token_balances.insert((token_id, holder), remaining);
        }
        Ok(())
    }

    /// Reconciles one token's issued supply against the sum of its held balances
    /// (Phase 13a, §15).
    ///
    /// For any token, `issued_supply` must equal the sum of every held balance.
    /// This is a SEPARATE asset from native WEBC and never enters
    /// [`Self::supply_invariant_report`]. Returns [`ChainError::TokenNotFound`] if
    /// the token does not exist. Checked addition over the held balances.
    pub fn token_supply_report(&self, token_id: TokenId) -> Result<TokenSupplyReport, ChainError> {
        let issued = self
            .tokens
            .get(&token_id)
            .ok_or(ChainError::TokenNotFound)?
            .issued_supply;
        let mut held = Amount::ZERO;
        for ((token, _holder), balance) in self.token_balances.iter() {
            if *token == token_id {
                held = held
                    .checked_add(*balance)
                    .ok_or(ChainError::TokenSupplyOverflow)?;
            }
        }
        Ok(TokenSupplyReport {
            issued,
            held,
            balanced: issued == held,
        })
    }

    /// Reconciles one collection's mint/burn counters against its live item count
    /// (Phase 13b, §15).
    ///
    /// For any collection, `minted_count - burned_count` must equal the number of
    /// live [`NftItem`] entries for that collection. NFT items are a SEPARATE,
    /// non-fungible asset from native WEBC and never enter
    /// [`Self::supply_invariant_report`]. Returns [`ChainError::NftCollectionNotFound`]
    /// if the collection does not exist, or [`ChainError::ArithmeticOverflow`] if the
    /// counters are inconsistent (which the state transitions never allow).
    pub fn nft_collection_supply_report(
        &self,
        collection_id: NftCollectionId,
    ) -> Result<NftCollectionSupplyReport, ChainError> {
        let collection = self
            .nft_collections
            .get(&collection_id)
            .ok_or(ChainError::NftCollectionNotFound)?;
        let minted = collection.minted_count;
        let burned = collection.burned_count;
        let expected_live = collection.live_count()?;
        // Count live items for exactly this collection. Items are keyed by
        // `NftId { collection, serial }`, so this scans the whole item map; a
        // per-collection secondary index is a later optimization if needed.
        let mut live_items: u64 = 0;
        for nft_id in self.nft_items.keys() {
            if nft_id.collection == collection_id {
                live_items = live_items
                    .checked_add(1)
                    .ok_or(ChainError::ArithmeticOverflow)?;
            }
        }
        Ok(NftCollectionSupplyReport {
            minted,
            burned,
            expected_live,
            live_items,
            balanced: expected_live == live_items,
        })
    }

    /// Attempts to draw `total_fee` from application `namespace`'s sponsor budget.
    ///
    /// Returns `true` and relocates the fee out of the aggregate `sponsor_budgets`
    /// bucket (the caller then applies the identical burn + validator-reward split
    /// a normal fee uses) iff the app is a registered sponsor and its hard
    /// per-user / per-operation / per-app-per-day caps and funded budget all
    /// permit charging `user` in the current day-window. Returns `false` with no
    /// mutation of the aggregate bucket otherwise, so the caller self-pays.
    /// Deterministic (the day-window comes from `current_epoch`, never a clock);
    /// checked arithmetic; never panics.
    fn try_charge_sponsor(
        &mut self,
        namespace: Hash256,
        user: Address,
        total_fee: Amount,
        config: &ChainConfig,
    ) -> Result<bool, ChainError> {
        let window = config.sponsorship.window_index(self.current_epoch);
        let Some(sponsor) = self.sponsors.get_mut(&namespace) else {
            return Ok(false);
        };
        if !sponsor.try_charge(user, total_fee, window, &config.sponsorship)? {
            return Ok(false);
        }
        // The per-app budget already decremented inside `try_charge`; keep the
        // aggregate locked bucket in lockstep so the supply invariant reconciles
        // (issued == liquid + … + sponsor_budgets + burned + slashed).
        self.sponsor_budgets = self
            .sponsor_budgets
            .checked_sub(total_fee)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(true)
    }

    /// Returns the current median aggregate of a feed, or `None` (§9, §15.21).
    ///
    /// The aggregate is the deterministic integer [`median`] of every registered
    /// reporter's latest submitted value (see the lower-mid tie-break rule on
    /// [`median`]). Returns `None` if the feed does not exist or no reporter has
    /// yet submitted a value.
    ///
    /// This is a pure read (a query), not an operation: display-only reads are
    /// free (§15.21) and pay no fee, and a browser reads the committed reporter
    /// state via a light-client proof. Freshness-gating the aggregate to only
    /// live reporters is a deferred refinement — liveness is applied at revenue
    /// settlement, not to the displayed value — so this method needs no epoch or
    /// config input and is a pure function of committed state.
    pub fn feed_value(&self, feed_id: FeedId) -> Option<FeedValue> {
        if !self.oracle_feeds.contains_key(&feed_id) {
            return None;
        }
        let values: Vec<FeedValue> = self
            .oracle_reporters
            .iter()
            .filter(|((fid, _), _)| *fid == feed_id)
            .filter_map(|(_, reporter)| reporter.value)
            .collect();
        median(&values)
    }

    /// Settles every feed's accrued read-fee revenue for settlement `epoch`.
    ///
    /// Deterministic: feeds are settled in sorted `FeedId` order. Supply-neutral:
    /// see [`ChainState::settle_one_feed`]. Reporter slashing (persistent-outlier
    /// penalties) is deliberately NOT applied here — §15.6/§15.17 defer slashing
    /// mechanics to the security documents and the severity schedule is an
    /// owner-deferred decision (ADR-0012); an outlier instead earns zero revenue
    /// because its accuracy weight decays to zero.
    fn settle_oracle_feeds(
        &mut self,
        config: &ChainConfig,
        epoch: u64,
    ) -> Result<Vec<Event>, ChainError> {
        // Snapshot the feed ids first so the per-feed mutation does not alias an
        // outstanding immutable borrow of the map. Sorted iteration is deterministic.
        let feed_ids: Vec<FeedId> = self.oracle_feeds.keys().copied().collect();
        let mut events = Vec::new();
        for feed_id in feed_ids {
            if let Some(event) = self.settle_one_feed(feed_id, config, epoch)? {
                events.push(event);
            }
        }
        Ok(events)
    }

    /// Distributes one feed's accrued revenue to its reporters for `epoch`.
    ///
    /// The accepted median is the integer [`median`] of the feed's reporters'
    /// latest values. Each reporter's score is its integer [`accuracy_weight`]
    /// (closeness to that median) if it is live (reported within
    /// `liveness_window_epochs` of `epoch`), else zero. Revenue is split
    /// proportionally to score with floored shares; the integer-division
    /// remainder stays in the feed's pool for the next settlement, exactly like
    /// the F1 epoch-reward dust carry, so nothing is minted or lost.
    ///
    /// Supply move: `oracle_revenue` (and the feed's `revenue`) decrease by the
    /// distributed total, and reporters' liquid balances increase by the same
    /// total; the carried remainder stays locked in the feed's `revenue`. Returns
    /// `None` (revenue fully carried, no state move) when the feed has no accrued
    /// revenue, no reporter has submitted a value, or no reporter is live.
    fn settle_one_feed(
        &mut self,
        feed_id: FeedId,
        config: &ChainConfig,
        epoch: u64,
    ) -> Result<Option<Event>, ChainError> {
        let revenue = match self.oracle_feeds.get(&feed_id) {
            Some(feed) => feed.revenue,
            None => return Ok(None),
        };
        if revenue.is_zero() {
            return Ok(None);
        }
        // Collect this feed's reporters that have submitted a value, in sorted
        // address order (BTreeMap iteration), so scoring is deterministic.
        let reporters: Vec<(Address, FeedValue, u64)> = self
            .oracle_reporters
            .iter()
            .filter(|((fid, _), _)| *fid == feed_id)
            .filter_map(|((_, address), reporter)| {
                reporter
                    .value
                    .map(|value| (*address, value, reporter.reported_epoch))
            })
            .collect();
        let values: Vec<FeedValue> = reporters.iter().map(|(_, value, _)| *value).collect();
        let Some(median_value) = median(&values) else {
            // No reporter has a value: carry the accrued revenue untouched.
            return Ok(None);
        };
        // Score = accuracy weight, gated by liveness (a stale reporter earns 0).
        let scores: Vec<(Address, u128)> = reporters
            .iter()
            .map(|(address, value, reported_epoch)| {
                let score = if config.oracle.report_is_live(*reported_epoch, epoch) {
                    accuracy_weight(*value, median_value)
                } else {
                    0
                };
                (*address, score)
            })
            .collect();
        let total_score = scores.iter().try_fold(0u128, |total, (_, score)| {
            total
                .checked_add(*score)
                .ok_or(ChainError::ArithmeticOverflow)
        })?;
        if total_score == 0 {
            // No live reporter earned a positive weight: carry the revenue.
            return Ok(None);
        }
        // Proportional floored distribution; the remainder is carried (F1 pattern).
        let mut distributed = Amount::ZERO;
        for (address, score) in &scores {
            if *score == 0 {
                continue;
            }
            let share = revenue
                .checked_mul_ratio(*score, total_score)
                .ok_or(ChainError::ArithmeticOverflow)?;
            if share.is_zero() {
                continue;
            }
            self.credit_native(*address, share)?;
            distributed = distributed
                .checked_add(share)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        let carried = revenue
            .checked_sub(distributed)
            .ok_or(ChainError::ArithmeticOverflow)?;
        // Move the distributed total out of the locked revenue bucket; the carried
        // remainder stays locked in the feed's pool for the next settlement.
        self.oracle_revenue = self
            .oracle_revenue
            .checked_sub(distributed)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let feed = self
            .oracle_feeds
            .get_mut(&feed_id)
            .ok_or(ChainError::OracleFeedNotFound)?;
        feed.revenue = carried;
        Ok(Some(Event::FeedRevenueSettled {
            feed_id,
            epoch,
            median: Some(median_value),
            distributed,
            carried,
        }))
    }

    fn debit_asset_or_native(
        &mut self,
        owner: Address,
        asset: &AssetId,
        amount: Amount,
    ) -> Result<(), ChainError> {
        if *asset == AssetId::NativeWebc {
            return self.debit_native(owner, amount);
        }
        if amount.is_zero() {
            return Ok(());
        }
        let key = (asset.clone(), owner);
        let balance = self
            .asset_balances
            .get(&key)
            .copied()
            .unwrap_or(Amount::ZERO);
        if balance < amount {
            return Err(ChainError::InsufficientBalance {
                address: owner,
                needed: amount,
                available: balance,
            });
        }
        let remaining = balance
            .checked_sub(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        if remaining.is_zero() {
            self.asset_balances.remove(&key);
        } else {
            self.asset_balances.insert(key, remaining);
        }
        Ok(())
    }

    fn credit_asset_or_native(
        &mut self,
        owner: Address,
        asset: &AssetId,
        amount: Amount,
    ) -> Result<(), ChainError> {
        if *asset == AssetId::NativeWebc {
            return self.credit_native(owner, amount);
        }
        if amount.is_zero() {
            return Ok(());
        }
        let key = (asset.clone(), owner);
        let balance = self
            .asset_balances
            .get(&key)
            .copied()
            .unwrap_or(Amount::ZERO);
        self.asset_balances.insert(
            key,
            balance
                .checked_add(amount)
                .ok_or(ChainError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    // ----- native DEX escrow + batch settlement (§15.13/§15.18/§15.37) -----

    /// Locks `amount` of `asset` from `owner` into DEX escrow (a `SubmitOrder`).
    ///
    /// Native leg: debit the owner's liquid balance and grow `dex_escrow`
    /// (supply-neutral: liquid -> dex_escrow). Non-native leg: debit the owner's
    /// asset balance (held out of circulation; a non-native asset has no native
    /// supply bucket). Fails closed on an insufficient balance or overflow.
    fn dex_lock(
        &mut self,
        owner: Address,
        asset: &AssetId,
        amount: Amount,
    ) -> Result<(), ChainError> {
        self.debit_asset_or_native(owner, asset, amount)?;
        if *asset == AssetId::NativeWebc {
            self.dex_escrow = self
                .dex_escrow
                .checked_add(amount)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        Ok(())
    }

    /// Releases `amount` of `asset` from DEX escrow to `recipient`.
    ///
    /// Used both for refunds (recipient is the original owner) and for settlement
    /// legs (recipient is a counterparty), since escrow-out is the same operation
    /// either way. Native leg: shrink `dex_escrow` and credit the recipient's
    /// liquid balance. Non-native leg: credit the recipient's asset balance. The
    /// native decrement is checked, so an accounting bug fails closed rather than
    /// silently under-flowing the supply invariant.
    fn dex_release(
        &mut self,
        recipient: Address,
        asset: &AssetId,
        amount: Amount,
    ) -> Result<(), ChainError> {
        if *asset == AssetId::NativeWebc {
            self.dex_escrow = self
                .dex_escrow
                .checked_sub(amount)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        self.credit_asset_or_native(recipient, asset, amount)
    }

    /// Removes `amount` of native quote from DEX escrow as the protocol per-fill
    /// fee, split 50/50 burn/validator by [`split_fee`] (only ever called when the
    /// pair's quote leg is native WEBC). Supply-neutral: dex_escrow -> burned +
    /// validator pool. A zero fee is a no-op.
    fn dex_take_native_fee(&mut self, amount: Amount) -> Result<(), ChainError> {
        if amount.is_zero() {
            return Ok(());
        }
        self.dex_escrow = self
            .dex_escrow
            .checked_sub(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        let split = split_fee(amount);
        self.burned_fees = self
            .burned_fees
            .checked_add(split.burned)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.validator_fee_pool = self
            .validator_fee_pool
            .checked_add(split.validator_reward)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(())
    }

    /// Refunds an order's remaining locked input to its owner and removes it.
    ///
    /// Used by owner cancellation, immediate-or-cancel remainders, and deadline
    /// expiry. Supply-neutral: the currently-locked leg (a buy's
    /// `remaining * limit_price` quote, a sell's `remaining` base) returns to the
    /// owner via [`ChainState::dex_release`]. A fully-filled order carries no lock
    /// and is removed elsewhere without a refund.
    fn close_dex_order(
        &mut self,
        order_id: OrderId,
        reason: OrderCloseReason,
        events: &mut Vec<Event>,
    ) -> Result<(), ChainError> {
        let order = self
            .dex_orders
            .get(&order_id)
            .ok_or(ChainError::DexOrderNotFound)?
            .clone();
        let (asset, amount) = order.locked_input().ok_or(ChainError::ArithmeticOverflow)?;
        self.dex_release(order.owner, &asset, amount)?;
        self.dex_orders.remove(&order_id);
        events.push(Event::OrderClosed {
            order_id,
            owner: order.owner,
            reason,
            unfilled: order.remaining,
        });
        Ok(())
    }

    /// Runs the mandatory per-block uniform-price batch settlement (§15.37).
    ///
    /// Deterministic and a pure function of the committed order map and
    /// `self.current_height`, so it runs identically on `build_block` and
    /// `apply_block` (the `dex_order_root`/`dex_escrow` commitment binds it). Whole
    /// step is atomic with the block: any failure rolls the block back.
    ///
    /// Ordering (all deterministic, sorted iteration):
    /// 1. Honor owner cancellations — a cancel included in this block takes effect
    ///    before this block's batch (doc §3.1).
    /// 2. Expire orders whose `deadline_height` has passed (refund + remove).
    /// 3. Settle each pair (sorted) at one uniform clearing price.
    /// 4. Close immediate-or-cancel orders still carrying an unfilled remainder.
    ///
    /// Supply-neutral in native units across every step.
    pub(crate) fn settle_dex_batch(
        &mut self,
        config: &ChainConfig,
    ) -> Result<Vec<Event>, ChainError> {
        let mut events = Vec::new();
        let height = self.current_height;

        // 1. Owner-requested cancellations.
        let cancelled: Vec<OrderId> = self
            .dex_orders
            .iter()
            .filter(|(_, order)| order.cancel_requested)
            .map(|(id, _)| *id)
            .collect();
        for order_id in cancelled {
            self.close_dex_order(order_id, OrderCloseReason::Cancelled, &mut events)?;
        }

        // 2. Deadline expiries: the retry window is inclusive of `deadline_height`,
        // so an order is expired only once the block height strictly passes it.
        let expired: Vec<OrderId> = self
            .dex_orders
            .iter()
            .filter(|(_, order)| height > order.deadline_height)
            .map(|(id, _)| *id)
            .collect();
        for order_id in expired {
            self.close_dex_order(order_id, OrderCloseReason::Expired, &mut events)?;
        }

        // 3. Settle each pair independently at its own uniform clearing price. Two
        // disjoint pairs never interact. `BTreeSet` keeps the pair order deterministic.
        let pairs: BTreeSet<TradingPair> = self
            .dex_orders
            .values()
            .map(|order| order.pair.clone())
            .collect();
        for pair in pairs {
            self.settle_dex_pair(&pair, config, &mut events)?;
        }

        // 4. Immediate-or-cancel: any FoC order with a surviving remainder cancels
        // this block instead of retrying (§15.37). A fully-filled FoC order was
        // already removed during matching.
        let fill_or_cancel: Vec<OrderId> = self
            .dex_orders
            .iter()
            .filter(|(_, order)| order.fill_or_cancel && !order.remaining.is_zero())
            .map(|(id, _)| *id)
            .collect();
        for order_id in fill_or_cancel {
            self.close_dex_order(order_id, OrderCloseReason::FillOrCancel, &mut events)?;
        }

        Ok(events)
    }

    /// Settles all live orders on one pair at a single uniform clearing price.
    ///
    /// The clearing price and matched volume come from the pure
    /// [`uniform_clearing_price`]; the surplus side is rationed by the dust-free
    /// [`prorata_fills`]; every filled order trades at the identical price, so no
    /// order is ordered ahead of another (no intra-block MEV). Base and quote are
    /// each conserved exactly (integer prices make the value leg exact; the pro-rata
    /// quantity leg is dust-free), and an optional per-fill fee on a native quote
    /// leg is split by [`split_fee`]. Fully-filled orders are removed; partial
    /// remainders retry in the next block's batch.
    fn settle_dex_pair(
        &mut self,
        pair: &TradingPair,
        config: &ChainConfig,
        events: &mut Vec<Event>,
    ) -> Result<(), ChainError> {
        // Gather this pair's live buys and sells in sorted OrderId order (BTreeMap
        // iteration), so scoring, eligibility, and pro-rata are all deterministic.
        let mut buy_ids: Vec<OrderId> = Vec::new();
        let mut buys: Vec<(Price, Amount)> = Vec::new();
        let mut sell_ids: Vec<OrderId> = Vec::new();
        let mut sells: Vec<(Price, Amount)> = Vec::new();
        for (id, order) in &self.dex_orders {
            if &order.pair != pair || order.remaining.is_zero() {
                continue;
            }
            match order.side {
                OrderSide::Buy => {
                    buy_ids.push(*id);
                    buys.push((order.limit_price, order.remaining));
                }
                OrderSide::Sell => {
                    sell_ids.push(*id);
                    sells.push((order.limit_price, order.remaining));
                }
            }
        }
        let Some((clearing, _volume)) = uniform_clearing_price(&buys, &sells) else {
            // The books did not cross: every order stays pending for the next batch.
            return Ok(());
        };

        // Eligible orders at the clearing price, keeping the sorted OrderId order.
        let mut eligible_buys: Vec<(OrderId, Amount)> = Vec::new();
        for id in &buy_ids {
            let order = &self.dex_orders[id];
            if order.limit_price.get() >= clearing.get() {
                eligible_buys.push((*id, order.remaining));
            }
        }
        let mut eligible_sells: Vec<(OrderId, Amount)> = Vec::new();
        for id in &sell_ids {
            let order = &self.dex_orders[id];
            if order.limit_price.get() <= clearing.get() {
                eligible_sells.push((*id, order.remaining));
            }
        }
        let demand = eligible_buys
            .iter()
            .try_fold(Amount::ZERO, |sum, (_, remaining)| {
                sum.checked_add(*remaining)
            })
            .ok_or(ChainError::ArithmeticOverflow)?;
        let supply = eligible_sells
            .iter()
            .try_fold(Amount::ZERO, |sum, (_, remaining)| {
                sum.checked_add(*remaining)
            })
            .ok_or(ChainError::ArithmeticOverflow)?;
        if demand.is_zero() || supply.is_zero() {
            return Ok(());
        }

        // The short side fills fully; the long (surplus) side is rationed pro-rata
        // to the short side's total, so total filled base is min(demand, supply).
        let (buy_fills, sell_fills) = if demand.0 <= supply.0 {
            let buy_fills: Vec<Amount> = eligible_buys.iter().map(|(_, r)| *r).collect();
            let sell_remainings: Vec<Amount> = eligible_sells.iter().map(|(_, r)| *r).collect();
            let sell_fills = prorata_fills(&sell_remainings, demand)?;
            (buy_fills, sell_fills)
        } else {
            let buy_remainings: Vec<Amount> = eligible_buys.iter().map(|(_, r)| *r).collect();
            let buy_fills = prorata_fills(&buy_remainings, supply)?;
            let sell_fills: Vec<Amount> = eligible_sells.iter().map(|(_, r)| *r).collect();
            (buy_fills, sell_fills)
        };

        // Whether a native-quote per-fill fee applies (external-asset quote fee
        // routing is deferred, so a non-native quote leg carries no protocol fee).
        let native_quote = pair.quote == AssetId::NativeWebc;
        let fee_bps = if native_quote { config.dex.fee_bps } else { 0 };

        // Buy legs: each filled buyer receives base and is refunded the price
        // improvement (they locked at their own limit but pay only the clearing
        // price). The clearing-price quote they pay stays in escrow for the sellers.
        for ((order_id, _), fill) in eligible_buys.iter().zip(buy_fills.iter()) {
            if fill.is_zero() {
                continue;
            }
            let owner = self.dex_orders[order_id].owner;
            let limit = self.dex_orders[order_id].limit_price;
            // Buyer receives `fill` base out of escrow (put there by the sellers).
            self.dex_release(owner, &pair.base, *fill)?;
            // Price-improvement refund: fill * (limit - clearing) of quote.
            let improvement = Price::new(limit.get() - clearing.get())
                .quote_for(*fill)
                .ok_or(ChainError::ArithmeticOverflow)?;
            self.dex_release(owner, &pair.quote, improvement)?;
            let paid = clearing
                .quote_for(*fill)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let order = self
                .dex_orders
                .get_mut(order_id)
                .ok_or(ChainError::DexOrderNotFound)?;
            order.remaining = order
                .remaining
                .checked_sub(*fill)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let remaining = order.remaining;
            events.push(Event::OrderFilled {
                order_id: *order_id,
                pair: pair.clone(),
                side: OrderSide::Buy,
                clearing_price: clearing,
                filled: *fill,
                remaining,
                quote: paid,
            });
            if remaining.is_zero() {
                self.dex_orders.remove(order_id);
            }
        }

        // Sell legs: each filled seller delivers base (already released to buyers
        // above, so it only reduces the seller's remaining) and receives the
        // clearing-price quote net of any protocol fee.
        for ((order_id, _), fill) in eligible_sells.iter().zip(sell_fills.iter()) {
            if fill.is_zero() {
                continue;
            }
            let gross = clearing
                .quote_for(*fill)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let fee = gross
                .checked_mul_bps(fee_bps)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let net = gross
                .checked_sub(fee)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let owner = self.dex_orders[order_id].owner;
            self.dex_release(owner, &pair.quote, net)?;
            self.dex_take_native_fee(fee)?;
            let order = self
                .dex_orders
                .get_mut(order_id)
                .ok_or(ChainError::DexOrderNotFound)?;
            order.remaining = order
                .remaining
                .checked_sub(*fill)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let remaining = order.remaining;
            events.push(Event::OrderFilled {
                order_id: *order_id,
                pair: pair.clone(),
                side: OrderSide::Sell,
                clearing_price: clearing,
                filled: *fill,
                remaining,
                quote: net,
            });
            if remaining.is_zero() {
                self.dex_orders.remove(order_id);
            }
        }

        Ok(())
    }
}

fn validate_owned_object(
    object: &StateObject,
    sender: Address,
    namespace: Hash256,
    expected_version: ObjectVersion,
) -> Result<(), ChainError> {
    if object.namespace != namespace {
        return Err(ChainError::ObjectNamespaceMismatch);
    }
    match object.owner {
        ObjectOwner::Address(owner) if owner == sender => {}
        ObjectOwner::Address(_) => return Err(ChainError::ObjectOwnerMismatch),
        ObjectOwner::Shared => return Err(ChainError::SharedObjectMutationUnsupported),
    }
    if object.version != expected_version {
        return Err(ChainError::ObjectVersionMismatch {
            expected: expected_version.get(),
            actual: object.version.get(),
        });
    }
    Ok(())
}

/// Returns the native principal a session key would move for an operation, or
/// rejects an operation kind the session key is not permitted to authorize.
///
/// v1 permits only native transfers. Critical, staking, bridge, object, and
/// lane/policy operations are never delegable to a session key, so they fall
/// through to a rejection regardless of the grant's allow-list.
fn session_permitted_principal(
    operation: &Operation,
    allowed: SessionAllowedOperations,
) -> Result<Amount, ChainError> {
    match operation {
        Operation::Transfer { amount, .. } if allowed.transfer => Ok(*amount),
        _ => Err(ChainError::SessionKeyOperationNotPermitted),
    }
}

fn ordered_value_root<'a, K, V, I>(domain: &'static [u8], entries: I) -> Result<Hash256, ChainError>
where
    K: Serialize + 'a,
    V: Serialize + 'a,
    I: Iterator<Item = (&'a K, &'a V)>,
{
    let leaves = entries
        .map(|entry| leaf_hash(domain, &entry))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(merkle_root(&leaves))
}

fn ordered_set_root<'a, T, I>(domain: &'static [u8], entries: I) -> Result<Hash256, ChainError>
where
    T: Serialize + 'a,
    I: Iterator<Item = &'a T>,
{
    let leaves = entries
        .map(|entry| leaf_hash(domain, entry))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(merkle_root(&leaves))
}

fn leaf_hash<T: Serialize + ?Sized>(
    domain: &'static [u8],
    value: &T,
) -> Result<Hash256, ChainError> {
    // Previously this used bincode. Canonical JSON keeps leaves reproducible
    // from any language once equivalent browser SDK helpers exist. The domain
    // bytes are prepended verbatim so the leaf space stays namespace-separated
    // and cannot collide with other WEBC artifacts.
    let bytes = crate::canonical::canonical_json_bytes(value)?;
    let parts: [&[u8]; 2] = [domain, bytes.as_slice()];
    Ok(Hash256::digest_many(parts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::kv_command;
    use crate::{
        AuthorizationPolicyRevision, DoubleVoteEvidence, FeeBid, GenesisAccount, GenesisValidator,
        Nonce, Operation, PostQuantumRoot, PostQuantumRootReveal, PostQuantumScheme,
        SessionKeyConstraints, SignedVote, SlashingEvidence, ValidatorSet, Vote, VoteType,
        GENESIS_TOTAL_SUPPLY, MAX_AUTHORIZATION_POLICY_REVISION,
    };
    use proptest::prelude::*;
    use std::sync::OnceLock;
    use webc_crypto::{
        ml_dsa65_keygen, Keypair, MlDsa65PublicKey, MlDsa65SecretKey, PublicKeyBytes,
        ML_DSA_65_SIGNATURE_LEN,
    };

    /// Round-trips `state` through the storage-at-rest bincode config — WEBC
    /// §15.14 variable-length integers, exactly what `webc-storage` writes to
    /// disk — so these crash-restart tests exercise the real on-disk format
    /// rather than a throwaway one. The whole chain state uses tuple-keyed maps,
    /// so it must go through bincode (a non-string-key binary format) rather than
    /// the canonical-JSON path that drives `state_root` and signing.
    fn bincode_restart(state: &ChainState) -> ChainState {
        use bincode::Options;
        let options = bincode::DefaultOptions::new()
            .with_varint_encoding()
            .reject_trailing_bytes();
        let bytes = options.serialize(state).expect("state serializes");
        options.deserialize(&bytes).expect("state deserializes")
    }

    fn funded_state() -> (ChainConfig, ChainState, Keypair, Keypair) {
        let config = ChainConfig::default();
        let alice = Keypair::from_seed([1u8; 32]);
        let bob = Keypair::from_seed([2u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).unwrap();
        (config, state, alice, bob)
    }

    // ----- G1: genesis total-supply pinning -----

    #[test]
    fn genesis_pins_the_declared_total_supply() {
        // A production genesis pins the total; an allocation that does not sum
        // to it is rejected (finding G1). Before this fix `from_genesis`
        // accepted any total, because the supply invariant is tautological.
        let faucet = Keypair::from_seed([9u8; 32]);
        let chain = ChainConfig {
            expected_total_supply: Some(GENESIS_TOTAL_SUPPLY),
            ..ChainConfig::default()
        };
        let short = GenesisConfig {
            chain,
            accounts: vec![GenesisAccount {
                address: faucet.address(),
                balance: Amount::from_webc(1_000_000), // only 1M, not the pinned 10M
            }],
            validators: Vec::new(),
        };
        match ChainState::from_genesis(&short) {
            Err(ChainError::GenesisSupplyMismatch { expected, actual }) => {
                assert_eq!(expected, GENESIS_TOTAL_SUPPLY);
                assert_eq!(actual, Amount::from_webc(1_000_000));
            }
            other => panic!("expected GenesisSupplyMismatch, got {other:?}"),
        }
    }

    #[test]
    fn genesis_accepts_an_allocation_matching_the_declared_total() {
        let faucet = Keypair::from_seed([9u8; 32]);
        let genesis = GenesisConfig {
            chain: ChainConfig {
                expected_total_supply: Some(GENESIS_TOTAL_SUPPLY),
                ..ChainConfig::default()
            },
            accounts: vec![GenesisAccount {
                address: faucet.address(),
                balance: GENESIS_TOTAL_SUPPLY,
            }],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).expect("exact declared total is accepted");
        assert_eq!(state.minted_supply, GENESIS_TOTAL_SUPPLY);
    }

    #[test]
    fn genesis_without_a_declared_total_skips_the_pin() {
        // Trusted in-crate fixtures leave the expectation unset (the default)
        // and may use any small allocation.
        let alice = Keypair::from_seed([1u8; 32]);
        let genesis = GenesisConfig {
            chain: ChainConfig::default(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        assert!(ChainState::from_genesis(&genesis).is_ok());
    }

    // ----- F1: epoch-reward supply conservation with multiple validators -----

    fn two_active_validators_with_odd_fee_pool() -> (ChainConfig, ChainState) {
        let config = ChainConfig::default();
        let mut state = ChainState::new(&config).expect("empty state");
        let stake = Amount::from_webc(100);
        for seed in [21u8, 22u8] {
            let address = Keypair::from_seed([seed; 32]).address();
            let mut account = Account::with_balance(Amount::ZERO);
            account.staked = stake;
            state.accounts.insert(address, account);
            state.validators.insert(
                address,
                Validator {
                    operator: address,
                    consensus_key: PublicKeyBytes([seed; 32]),
                    self_stake: stake,
                    delegated_stake: Amount::ZERO,
                    commission_bps: 0,
                    status: ValidatorStatus::Active,
                    bootstrap: false,
                    accumulated_rewards: Amount::ZERO,
                },
            );
        }
        // An odd fee pool guarantees the outer remainder: two equal-stake
        // validators each floor to (pool - 1) / 2, leaving one base unit over.
        let fee_pool = 101u128;
        state.validator_fee_pool = Amount::from_units(fee_pool);
        // Balanced by construction: staked principal plus the fee pool == minted.
        state.minted_supply = Amount::from_units(2 * stake.0 + fee_pool);
        // Zero year-start supply => zero inflation; epoch 1 is not a year
        // boundary, so `apply_epoch_rewards` does not reset the year-start.
        state.inflation_year_start_supply = Amount::ZERO;
        state.current_epoch = 1;
        (config, state)
    }

    #[test]
    fn epoch_rewards_conserve_supply_across_multiple_validators() {
        // F1: the outer cross-validator division remainder must be retained in
        // the fee pool, not dropped. Dropping it breaks supply conservation by
        // up to num_validators-1 base units per epoch (invisible with a single
        // validator, where the whole reward is one exact share).
        let (config, mut state) = two_active_validators_with_odd_fee_pool();
        assert!(
            state.supply_invariant_report().unwrap().balanced,
            "state is balanced before distribution"
        );

        state
            .distribute_epoch_rewards(&config)
            .expect("epoch reward distribution");

        assert!(
            state.supply_invariant_report().unwrap().balanced,
            "supply must still reconcile after distributing rewards to two validators"
        );
        // The remainder that was previously dropped now carries forward.
        assert_eq!(state.validator_fee_pool, Amount::from_units(1));
    }

    #[test]
    fn bootstrap_issuance_keys_to_stake_caps_at_base_and_conserves_supply() {
        // Task 12 (§15.2): during the bootstrap phase issuance is keyed to the
        // staked amount and capped by the base per-period budget, and supply must
        // still reconcile exactly. Here the staking base is thin relative to the
        // circulating supply, so the (small) stake-keyed budget binds, not the
        // (large) base budget — the whole point of §15.2.
        let config = ChainConfig {
            bootstrap_issuance: Some(BootstrapIssuance {
                annual_rate_bps: 1_000,
                sunset_epoch: 1_000_000,
            }),
            ..ChainConfig::default()
        };
        let mut state = ChainState::new(&config).expect("empty state");
        let stake = Amount::from_webc(100);
        for seed in [31u8, 32u8] {
            let address = Keypair::from_seed([seed; 32]).address();
            let mut account = Account::with_balance(Amount::ZERO);
            account.staked = stake;
            state.accounts.insert(address, account);
            state.validators.insert(
                address,
                Validator {
                    operator: address,
                    consensus_key: PublicKeyBytes([seed; 32]),
                    self_stake: stake,
                    delegated_stake: Amount::ZERO,
                    commission_bps: 0,
                    status: ValidatorStatus::Active,
                    bootstrap: false,
                    accumulated_rewards: Amount::ZERO,
                },
            );
        }
        // A large liquid holder makes the base schedule budget far exceed the
        // stake-keyed budget, so the stake-keying (not the cap) binds.
        let holder = Keypair::from_seed([33u8; 32]).address();
        let extra = Amount::from_webc(1_000_000);
        state.accounts.insert(holder, Account::with_balance(extra));
        state.minted_supply = Amount::from_units(2 * stake.0 + extra.0);
        state.inflation_year_start_supply = state.minted_supply;
        state.current_epoch = 1;
        assert!(state.supply_invariant_report().unwrap().balanced);

        let minted_before = state.minted_supply;
        state
            .distribute_epoch_rewards(&config)
            .expect("bootstrap epoch reward distribution");

        assert!(
            state.supply_invariant_report().unwrap().balanced,
            "supply must reconcile after bootstrap issuance"
        );
        // Minted grew by exactly the stake-keyed budget (below the base cap):
        // 200 WEBC * 1000 bps / (10_000 * 365) base units.
        let minted_growth = state.minted_supply.0 - minted_before.0;
        let expected_stake_keyed = (2 * stake.0) * 1_000 / (10_000 * 365);
        assert_eq!(minted_growth, expected_stake_keyed);
        assert!(minted_growth > 0);
    }

    #[test]
    fn compound_validator_rewards_restakes_and_conserves_supply() {
        // Task 6b: compounding moves accumulated operator rewards straight into
        // self-stake (pending-rewards bucket -> staked bucket), supply-neutral.
        let config = ChainConfig::default();
        let mut state = ChainState::new(&config).expect("empty state");
        let alice = Keypair::from_seed([41u8; 32]);
        let self_stake = Amount::from_webc(100);
        let reward = Amount::from_webc(10);
        let mut account = Account::with_balance(Amount::from_webc(1));
        account.staked = self_stake;
        state.accounts.insert(alice.address(), account);
        state.validators.insert(
            alice.address(),
            Validator {
                operator: alice.address(),
                consensus_key: alice.public_key(),
                self_stake,
                delegated_stake: Amount::ZERO,
                commission_bps: 0,
                status: ValidatorStatus::Active,
                bootstrap: false,
                accumulated_rewards: reward,
            },
        );
        state.minted_supply = Amount::from_units(self_stake.0 + reward.0 + Amount::from_webc(1).0);
        state.inflation_year_start_supply = state.minted_supply;
        assert!(state.supply_invariant_report().unwrap().balanced);

        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::CompoundValidatorRewards,
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("compound signs");
        state
            .execute_transaction(&tx, &config)
            .expect("compound executes");

        let compounded = self_stake.checked_add(reward).unwrap();
        let v = state.validators.get(&alice.address()).unwrap();
        assert_eq!(v.self_stake, compounded);
        assert_eq!(v.accumulated_rewards, Amount::ZERO);
        assert_eq!(
            state.accounts.get(&alice.address()).unwrap().staked,
            compounded
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn compound_delegator_rewards_restakes_within_ratio_and_conserves_supply() {
        // Task 6b: compounding a delegation restakes its rewards into the position
        // (pending -> delegated), supply-neutral, respecting the 4x ratio.
        let config = ChainConfig::default();
        let mut state = ChainState::new(&config).expect("empty state");
        let alice = Keypair::from_seed([42u8; 32]); // operator
        let bob = Keypair::from_seed([43u8; 32]); // delegator
        let self_stake = Amount::from_webc(100);
        let delegated = Amount::from_webc(40);
        let reward = Amount::from_webc(5);

        let mut op_account = Account::with_balance(Amount::ZERO);
        op_account.staked = self_stake;
        state.accounts.insert(alice.address(), op_account);
        let mut del_account = Account::with_balance(Amount::from_webc(1));
        del_account.delegated = delegated;
        state.accounts.insert(bob.address(), del_account);
        state.validators.insert(
            alice.address(),
            Validator {
                operator: alice.address(),
                consensus_key: alice.public_key(),
                self_stake,
                delegated_stake: delegated,
                commission_bps: 0,
                status: ValidatorStatus::Active,
                bootstrap: false,
                accumulated_rewards: Amount::ZERO,
            },
        );
        state.delegations.insert(
            (bob.address(), alice.address()),
            Delegation {
                delegator: bob.address(),
                validator: alice.address(),
                amount: delegated,
                accumulated_rewards: reward,
            },
        );
        state.minted_supply =
            Amount::from_units(self_stake.0 + delegated.0 + reward.0 + Amount::from_webc(1).0);
        state.inflation_year_start_supply = state.minted_supply;
        assert!(state.supply_invariant_report().unwrap().balanced);

        let tx = Transaction::for_operation(
            &bob,
            0,
            Operation::CompoundDelegatorRewards {
                validator: alice.address(),
            },
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("compound signs");
        state
            .execute_transaction(&tx, &config)
            .expect("compound executes");

        let compounded = delegated.checked_add(reward).unwrap();
        assert_eq!(
            state
                .delegations
                .get(&(bob.address(), alice.address()))
                .unwrap()
                .amount,
            compounded
        );
        assert_eq!(
            state
                .delegations
                .get(&(bob.address(), alice.address()))
                .unwrap()
                .accumulated_rewards,
            Amount::ZERO
        );
        assert_eq!(
            state
                .validators
                .get(&alice.address())
                .unwrap()
                .delegated_stake,
            compounded
        );
        assert_eq!(
            state.accounts.get(&bob.address()).unwrap().delegated,
            compounded
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn compound_delegator_rewards_rejects_ratio_violation() {
        // Compounding cannot push delegated stake past 4x the operator self-stake,
        // exactly as a fresh delegation cannot.
        let config = ChainConfig::default();
        let mut state = ChainState::new(&config).expect("empty state");
        let alice = Keypair::from_seed([44u8; 32]);
        let bob = Keypair::from_seed([45u8; 32]);
        let self_stake = Amount::from_webc(20);
        let delegated = Amount::from_webc(80); // exactly at the 4x cap
        let reward = Amount::from_webc(5); // would exceed the cap

        let mut op_account = Account::with_balance(Amount::ZERO);
        op_account.staked = self_stake;
        state.accounts.insert(alice.address(), op_account);
        let mut del_account = Account::with_balance(Amount::from_webc(1));
        del_account.delegated = delegated;
        state.accounts.insert(bob.address(), del_account);
        state.validators.insert(
            alice.address(),
            Validator {
                operator: alice.address(),
                consensus_key: alice.public_key(),
                self_stake,
                delegated_stake: delegated,
                commission_bps: 0,
                status: ValidatorStatus::Active,
                bootstrap: false,
                accumulated_rewards: Amount::ZERO,
            },
        );
        state.delegations.insert(
            (bob.address(), alice.address()),
            Delegation {
                delegator: bob.address(),
                validator: alice.address(),
                amount: delegated,
                accumulated_rewards: reward,
            },
        );
        state.minted_supply =
            Amount::from_units(self_stake.0 + delegated.0 + reward.0 + Amount::from_webc(1).0);
        state.inflation_year_start_supply = state.minted_supply;

        let tx = Transaction::for_operation(
            &bob,
            0,
            Operation::CompoundDelegatorRewards {
                validator: alice.address(),
            },
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("compound signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::DelegationRatioExceeded)
        ));
        assert_eq!(state, before, "rejected compound leaves state unchanged");
    }

    #[test]
    fn protocol_one_empty_state_keeps_the_v20_root_fixture() {
        assert_eq!(
            ChainState::default().state_root().unwrap().to_hex(),
            "ddb1a0d463e7ef12b73b2408c344e9b7799570b16f06b7cb7f83727c9644127f"
        );
    }

    #[test]
    fn every_scalar_state_counter_is_committed_by_the_state_root() {
        // E8: the state root (canonical JSON) must commit every consensus field,
        // so no field can be mutated on disk (the bincode restart path) without
        // changing the committed root — otherwise two nodes could diverge on a
        // JSON-invisible field yet share a state root. Map fields are covered by
        // their dedicated sub-roots; this guards the scalar counters, which are
        // the easiest to add and forget.
        let (_config, base, _a, _b) = funded_state();
        let root = base.state_root().unwrap();
        type StateMutator = fn(&mut ChainState);
        let mutators: Vec<(&str, StateMutator)> = vec![
            ("burned_fees", |s| {
                s.burned_fees = Amount::from_units(s.burned_fees.0 + 1)
            }),
            ("slashed_units", |s| {
                s.slashed_units = Amount::from_units(s.slashed_units.0 + 1)
            }),
            ("storage_deposits", |s| {
                s.storage_deposits = Amount::from_units(s.storage_deposits.0 + 1)
            }),
            ("sponsor_budgets", |s| {
                s.sponsor_budgets = Amount::from_units(s.sponsor_budgets.0 + 1)
            }),
            ("oracle_bonds", |s| {
                s.oracle_bonds = Amount::from_units(s.oracle_bonds.0 + 1)
            }),
            ("oracle_revenue", |s| {
                s.oracle_revenue = Amount::from_units(s.oracle_revenue.0 + 1)
            }),
            ("dex_escrow", |s| {
                s.dex_escrow = Amount::from_units(s.dex_escrow.0 + 1)
            }),
            ("mandate_escrow", |s| {
                s.mandate_escrow = Amount::from_units(s.mandate_escrow.0 + 1)
            }),
            ("token_deposits", |s| {
                s.token_deposits = Amount::from_units(s.token_deposits.0 + 1)
            }),
            ("nft_deposits", |s| {
                s.nft_deposits = Amount::from_units(s.nft_deposits.0 + 1)
            }),
            ("governance_deposits", |s| {
                s.governance_deposits = Amount::from_units(s.governance_deposits.0 + 1)
            }),
            ("governance_treasury", |s| {
                s.governance_treasury = Amount::from_units(s.governance_treasury.0 + 1)
            }),
            ("validator_fee_pool", |s| {
                s.validator_fee_pool = Amount::from_units(s.validator_fee_pool.0 + 1)
            }),
            ("minted_supply", |s| {
                s.minted_supply = Amount::from_units(s.minted_supply.0 + 1)
            }),
            ("inflation_year_start_supply", |s| {
                s.inflation_year_start_supply =
                    Amount::from_units(s.inflation_year_start_supply.0 + 1)
            }),
            ("current_base_fee_per_unit", |s| {
                s.current_base_fee_per_unit += 1
            }),
            ("current_epoch", |s| s.current_epoch += 1),
            ("current_height", |s| s.current_height += 1),
            ("bridge_nonce", |s| s.bridge_nonce += 1),
            ("last_block_timestamp_ms", |s| {
                s.last_block_timestamp_ms += 1
            }),
        ];
        for (name, mutate) in mutators {
            let mut mutated = base.clone();
            mutate(&mut mutated);
            assert_ne!(
                mutated.state_root().unwrap(),
                root,
                "mutating {name} must change the state root (E8)"
            );
        }
    }

    // ----- native agent mandate (Phase 9a, §15.32) -----

    use crate::mandate::{MandateCounterparty, MandateCounterpartyPolicy};

    /// Mandate-tuned config with an explicit per-day rate-limit window.
    fn mandate_config(day_window_epochs: u64) -> ChainConfig {
        ChainConfig {
            mandate: MandateConfig { day_window_epochs },
            ..ChainConfig::default()
        }
    }

    /// Genesis funding only the principal (no validators, so epoch advance mints
    /// nothing). The agent is deliberately UNFUNDED: it must be able to spend with
    /// no balance of its own, and recipients are created lazily on credit.
    fn mandate_fixture(config: &ChainConfig) -> (ChainState, Keypair, Keypair, Keypair, Keypair) {
        let principal = Keypair::from_seed([11u8; 32]);
        let agent = Keypair::from_seed([12u8; 32]);
        let recipient = Keypair::from_seed([13u8; 32]);
        let stranger = Keypair::from_seed([14u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: principal.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).expect("mandate genesis");
        (state, principal, agent, recipient, stranger)
    }

    /// Executes one mandate operation at the floor base fee (1 base unit/unit) and
    /// a gas limit above any mandate op's cost, so the fee is exactly 10_000 units.
    fn mandate_exec(
        state: &mut ChainState,
        config: &ChainConfig,
        signer: &Keypair,
        nonce: u64,
        operation: Operation,
    ) -> Result<Receipt, ChainError> {
        let tx = Transaction::for_operation(
            signer,
            nonce,
            operation,
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("mandate tx signs");
        state.execute_transaction(&tx, config)
    }

    /// Grants a mandate from `principal` to `agent` and returns its derived id.
    #[allow(clippy::too_many_arguments)]
    fn grant_mandate(
        state: &mut ChainState,
        config: &ChainConfig,
        principal: &Keypair,
        agent: &Keypair,
        nonce: u64,
        grant_nonce: u64,
        budget_total: Amount,
        expiry_epoch: Epoch,
        per_tx_max: Amount,
        rate_limit_per_day: u32,
        counterparty_policy: MandateCounterpartyPolicy,
    ) -> Result<MandateId, ChainError> {
        mandate_exec(
            state,
            config,
            principal,
            nonce,
            Operation::GrantMandate {
                agent_key: agent.public_key(),
                grant_nonce,
                budget_total,
                expiry_epoch,
                per_tx_max,
                rate_limit_per_day,
                counterparty_policy,
            },
        )?;
        Ok(MandateId::derive(
            principal.address(),
            &agent.public_key(),
            grant_nonce,
        ))
    }

    #[test]
    fn grant_escrows_budget_and_supply_stays_balanced() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, _recipient, _stranger) = mandate_fixture(&config);
        let before = balance(&state, principal.address());
        let budget = Amount::from_units(500_000);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            budget,
            Epoch::new(100),
            Amount::from_units(200_000),
            5,
            MandateCounterpartyPolicy::Open,
        )
        .expect("grant succeeds");
        // Budget is escrowed; the fee (10_000) is additionally debited.
        assert_eq!(state.mandate_escrow, budget);
        assert_eq!(
            balance(&state, principal.address()),
            before - 500_000 - 10_000
        );
        let mandate = state.mandates.get(&mandate_id).expect("mandate exists");
        assert_eq!(mandate.principal, principal.address());
        assert_eq!(mandate.agent_key, agent.public_key());
        assert_eq!(mandate.spent, Amount::ZERO);
        assert!(!mandate.revoked);
        // Most important: escrow keeps the supply invariant balanced.
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn spend_moves_principal_and_fee_from_escrow_agent_needs_no_balance() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, recipient, _stranger) = mandate_fixture(&config);
        let budget = Amount::from_units(500_000);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            budget,
            Epoch::new(100),
            Amount::from_units(200_000),
            5,
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        let burned_before = state.burned_fees.0;
        let pool_before = state.validator_fee_pool.0;
        let mandate_count = state.mandates.len();

        let amount = Amount::from_units(100_000);
        let receipt = mandate_exec(
            &mut state,
            &config,
            &agent,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount,
            },
        )
        .expect("spend succeeds");

        // Recipient credited exactly the principal; the fee left escrow too.
        assert_eq!(balance(&state, recipient.address()), 100_000);
        // The agent holds no balance of its own — it never was funded.
        assert_eq!(balance(&state, agent.address()), 0);
        // Escrow fell by amount + fee; the mandate's spent grew by the same.
        assert_eq!(state.mandate_escrow, Amount::from_units(500_000 - 110_000));
        let mandate = state.mandates.get(&mandate_id).unwrap();
        assert_eq!(mandate.spent, Amount::from_units(110_000));
        // The fee was split into burn + validator reward exactly as any tx.
        assert_eq!(
            state.burned_fees.0 + state.validator_fee_pool.0,
            burned_before + pool_before + 10_000
        );
        // No re-delegation: a spend never mints or removes a mandate.
        assert_eq!(state.mandates.len(), mandate_count);
        // The receipt carries the mandate id — the complete audit trail.
        assert!(receipt.events.iter().any(|event| matches!(
            event,
            Event::MandateSpent { mandate_id: id, .. } if *id == mandate_id
        )));
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn spend_over_budget_is_rejected() {
        // Because grant enforces `per_tx_max <= budget_total`, a single spend can
        // never exceed the budget without first exceeding the per-tx cap, so the
        // budget bound is a CUMULATIVE limit: two within-cap spends whose running
        // total overflows the budget must be rejected on the second.
        let config = mandate_config(1_440);
        let (mut state, principal, agent, recipient, _stranger) = mandate_fixture(&config);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(100_000), // budget covers one 60_000 spend, not two
            Epoch::new(100),
            Amount::from_units(60_000), // per-tx cap (<= budget_total)
            0,                          // unlimited rate, so only the budget binds
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        // First spend: 50_000 + 10_000 fee = 60_000, within both cap and budget.
        mandate_exec(
            &mut state,
            &config,
            &agent,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(50_000),
            },
        )
        .expect("first within-budget spend succeeds");
        let before = state.clone();
        // Second identical spend brings cumulative spent to 120_000 > 100_000.
        let err = mandate_exec(
            &mut state,
            &config,
            &agent,
            1,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(50_000),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::MandateBudgetExceeded));
        assert_eq!(state, before, "rejected spend leaves state unchanged");
    }

    #[test]
    fn spend_exceeding_per_tx_max_is_rejected() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, recipient, _stranger) = mandate_fixture(&config);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(500_000),
            Epoch::new(100),
            Amount::from_units(10_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        let err = mandate_exec(
            &mut state,
            &config,
            &agent,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(10_001),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::MandatePerTxExceeded));
    }

    #[test]
    fn fee_bid_cannot_inflate_a_spend_past_per_tx_max() {
        // Regression: a mandate spend draws BOTH the principal and the fee from
        // escrow, and the fee is agent-chosen via the priority bid. If the per-tx
        // cap bounded only the principal, one spend with a huge fee could drain the
        // whole budget past the per-tx and per-day limits the principal set (with
        // ~half recoverable through the validator fee pool). The cap must bound
        // principal + fee.
        let config = mandate_config(1_440);
        let (mut state, principal, agent, recipient, _stranger) = mandate_fixture(&config);
        let budget = Amount::from_units(2_000_000);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            budget,
            Epoch::new(100),
            Amount::from_units(1_000), // the tiny per-tx cap the principal intends
            1,                         // and one spend per day
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        let before = state.clone();
        // A within-cap principal (1_000) but a fee inflated via the priority bid:
        // base fee is 1/unit, so a max/priority of 100/99 pays 100/unit over 10_000
        // units = 1_000_000 fee — 1000x the per-tx cap, still inside the 2_000_000
        // budget. Pre-fix this spend succeeded and drained ~1_000_000 in one tx.
        let tx = Transaction::for_operation(
            &agent,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(1_000),
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 100,
                priority_fee_per_unit: 99,
            },
        )
        .expect("spend tx signs");
        let err = state.execute_transaction(&tx, &config).unwrap_err();
        assert!(
            matches!(err, ChainError::MandatePerTxExceeded),
            "a fee-inflated spend must be capped, got {err:?}"
        );
        // The drain was fully rejected: escrow and all state are untouched.
        assert_eq!(state, before, "rejected spend leaves state unchanged");
    }

    #[test]
    fn zero_amount_spend_is_rejected() {
        // A zero-principal spend delivers nothing but would still burn budget via
        // the fee; reject it so a mandate cannot be bled by fee-only spends.
        let config = mandate_config(1_440);
        let (mut state, principal, agent, recipient, _stranger) = mandate_fixture(&config);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(500_000),
            Epoch::new(100),
            Amount::from_units(200_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        let before = state.clone();
        let err = mandate_exec(
            &mut state,
            &config,
            &agent,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::ZERO,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::MandateZeroAmount));
        assert_eq!(state, before, "rejected spend leaves state unchanged");
    }

    #[test]
    fn spend_on_expired_mandate_is_rejected_but_reclaimable() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, recipient, _stranger) = mandate_fixture(&config);
        let budget = Amount::from_units(500_000);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            budget,
            Epoch::new(10),
            Amount::from_units(200_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        // Advance past expiry (inclusive at epoch 10).
        state.current_epoch = 11;
        let err = mandate_exec(
            &mut state,
            &config,
            &agent,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(1_000),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::MandateExpired));
        // The principal reclaims the full remainder from an expired mandate.
        let before = balance(&state, principal.address());
        mandate_exec(
            &mut state,
            &config,
            &principal,
            1,
            Operation::RevokeMandate { mandate_id },
        )
        .expect("reclaim on expired mandate");
        // Remainder = full budget (nothing spent); the fee is separately debited.
        assert_eq!(
            balance(&state, principal.address()),
            before + 500_000 - 10_000
        );
        assert_eq!(state.mandate_escrow, Amount::ZERO);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn revoked_mid_flight_refunds_remainder_and_rejects_further_spend() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, recipient, _stranger) = mandate_fixture(&config);
        let budget = Amount::from_units(500_000);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            budget,
            Epoch::new(100),
            Amount::from_units(200_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        // One spend goes through.
        mandate_exec(
            &mut state,
            &config,
            &agent,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(100_000),
            },
        )
        .expect("first spend");
        let spent = state.mandates.get(&mandate_id).unwrap().spent;
        assert_eq!(spent, Amount::from_units(110_000));

        // Principal revokes; the unspent remainder returns.
        let principal_before = balance(&state, principal.address());
        let receipt = mandate_exec(
            &mut state,
            &config,
            &principal,
            1,
            Operation::RevokeMandate { mandate_id },
        )
        .expect("revoke");
        let remainder: u128 = 500_000 - 110_000;
        assert!(receipt.events.iter().any(|event| matches!(
            event,
            Event::MandateRevoked { refunded, .. } if refunded.0 == remainder
        )));
        assert_eq!(
            balance(&state, principal.address()),
            principal_before + remainder - 10_000
        );
        assert_eq!(state.mandate_escrow, Amount::ZERO);
        assert!(state.mandates.get(&mandate_id).unwrap().revoked);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // A further spend against the revoked mandate fails.
        let err = mandate_exec(
            &mut state,
            &config,
            &agent,
            1,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(1_000),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::MandateRevoked));
    }

    #[test]
    fn rate_limit_binds_within_a_day_then_resets_next_window() {
        // A tight day window so a single epoch advance crosses it.
        let config = mandate_config(10);
        let (mut state, principal, agent, recipient, _stranger) = mandate_fixture(&config);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(1_000_000),
            Epoch::new(1_000),
            Amount::from_units(1_000_000),
            2, // at most two spends per window
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        let spend = |state: &mut ChainState, nonce: u64| {
            mandate_exec(
                state,
                &config,
                &agent,
                nonce,
                Operation::SpendUnderMandate {
                    mandate_id,
                    recipient: recipient.address(),
                    amount: Amount::from_units(1_000),
                },
            )
        };
        // Two spends in window 0 (epoch 0) succeed; the third is rate-limited.
        spend(&mut state, 0).expect("first spend");
        spend(&mut state, 1).expect("second spend");
        assert!(matches!(
            spend(&mut state, 2).unwrap_err(),
            ChainError::MandateRateLimited
        ));
        // Cross into the next window (epoch 10 -> window 1); the counter resets.
        state.current_epoch = 10;
        spend(&mut state, 2).expect("spend in the next window");
        let mandate = state.mandates.get(&mandate_id).unwrap();
        assert_eq!(mandate.window_index, 1);
        assert_eq!(mandate.spends_in_window, 1);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn counterparty_allowlist_admits_only_listed_recipients() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, recipient, stranger) = mandate_fixture(&config);
        let mut entries = BTreeSet::new();
        entries.insert(MandateCounterparty::Recipient(recipient.address()));
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(500_000),
            Epoch::new(100),
            Amount::from_units(200_000),
            0,
            MandateCounterpartyPolicy::Allowlist(entries),
        )
        .unwrap();
        // A spend to a non-listed recipient is rejected.
        let err = mandate_exec(
            &mut state,
            &config,
            &agent,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: stranger.address(),
                amount: Amount::from_units(1_000),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::MandateCounterpartyNotAllowed));
        // A spend to the listed recipient succeeds.
        mandate_exec(
            &mut state,
            &config,
            &agent,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(1_000),
            },
        )
        .expect("allowlisted spend");
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn spend_signed_by_wrong_key_is_rejected() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, recipient, stranger) = mandate_fixture(&config);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(500_000),
            Epoch::new(100),
            Amount::from_units(200_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        // `stranger` signs a spend against the agent's mandate. The envelope is
        // valid for the stranger's own address, but the mandate binds `agent_key`.
        let before = state.clone();
        let err = mandate_exec(
            &mut state,
            &config,
            &stranger,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(1_000),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::MandateAgentKeyMismatch));
        assert_eq!(state, before, "a wrong-key spend must not mutate state");
    }

    #[test]
    fn agent_cannot_re_delegate_the_principals_escrow() {
        // No-re-delegation: an agent-signed grant funds a sub-mandate from the
        // AGENT's own liquid balance, never from the principal's escrow. With no
        // balance, the agent cannot mint a sub-mandate, and the original escrow is
        // untouched. There is likewise no operation by which a spend mints a mandate.
        let config = mandate_config(1_440);
        let (mut state, principal, agent, _recipient, sub_agent) = mandate_fixture(&config);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(500_000),
            Epoch::new(100),
            Amount::from_units(200_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        // Fund the agent just enough to pay a grant fee (10_000) but far less than
        // a sub-budget, so a grant draws from the agent's OWN balance and cannot
        // reach the principal's escrow.
        mandate_exec(
            &mut state,
            &config,
            &principal,
            1,
            Operation::Transfer {
                to: agent.address(),
                amount: Amount::from_units(20_000),
            },
        )
        .expect("fund agent minimally");
        let escrow_before = state.mandate_escrow;
        let mandate_count = state.mandates.len();
        // The agent tries to grant a 100_000 sub-mandate to `sub_agent`: the fee is
        // affordable, but the sub-budget exceeds the agent's own balance.
        let err = grant_mandate(
            &mut state,
            &config,
            &agent,
            &sub_agent,
            0,
            0,
            Amount::from_units(100_000),
            Epoch::new(100),
            Amount::from_units(100_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .unwrap_err();
        // The grant draws from the agent's own balance, not any mandate escrow.
        assert!(matches!(err, ChainError::InsufficientBalance { .. }));
        assert_eq!(state.mandate_escrow, escrow_before, "escrow untouched");
        assert_eq!(state.mandates.len(), mandate_count, "no sub-mandate minted");
        assert!(state.mandates.contains_key(&mandate_id));
    }

    #[test]
    fn double_grant_same_nonce_collides_and_distinct_nonce_coexists() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, _recipient, _stranger) = mandate_fixture(&config);
        grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            7,
            Amount::from_units(100_000),
            Epoch::new(100),
            Amount::from_units(100_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .expect("first grant");
        // Same (principal, agent_key, grant_nonce) derives the same id -> rejected.
        let err = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            1,
            7,
            Amount::from_units(100_000),
            Epoch::new(100),
            Amount::from_units(100_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::MandateAlreadyExists));
        // A different grant nonce derives a distinct id -> both coexist.
        grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            1,
            8,
            Amount::from_units(100_000),
            Epoch::new(100),
            Amount::from_units(100_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .expect("distinct-nonce grant");
        assert_eq!(state.mandates.len(), 2);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn top_up_raises_budget_and_keeps_supply_balanced() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, recipient, _stranger) = mandate_fixture(&config);
        // Original budget is exactly one 40_000 spend (+10_000 fee = 50_000).
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(50_000),
            Epoch::new(100),
            Amount::from_units(50_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .unwrap();
        mandate_exec(
            &mut state,
            &config,
            &principal,
            1,
            Operation::TopUpMandate {
                mandate_id,
                amount: Amount::from_units(200_000),
            },
        )
        .expect("top up");
        assert_eq!(
            state.mandates.get(&mandate_id).unwrap().budget_total,
            Amount::from_units(250_000)
        );
        assert_eq!(state.mandate_escrow, Amount::from_units(250_000));
        // Two 40_000 spends (charge 50_000 each) need 100_000 total — impossible
        // under the original 50_000 budget, now comfortably within the raised one.
        mandate_exec(
            &mut state,
            &config,
            &agent,
            0,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(40_000),
            },
        )
        .expect("first spend under raised budget");
        mandate_exec(
            &mut state,
            &config,
            &agent,
            1,
            Operation::SpendUnderMandate {
                mandate_id,
                recipient: recipient.address(),
                amount: Amount::from_units(40_000),
            },
        )
        .expect("second spend under raised budget");
        assert_eq!(
            state.mandates.get(&mandate_id).unwrap().spent,
            Amount::from_units(100_000)
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn mandate_ops_reject_non_default_lane() {
        // All four mandate ops require the default lane, like the oracle/DEX
        // financial operations. Open a funded non-default lane first so its
        // nonce/fee lookup succeeds and the default-lane guard is the check that
        // actually fires (rather than an incidental lane-not-found).
        let config = mandate_config(1_440);
        let (mut state, principal, agent, _recipient, _stranger) = mandate_fixture(&config);
        let lane = AuthorizationLaneId::new(Hash256([0x5a; 32]));
        let fee = FeeBid {
            gas_limit: 100_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        };
        let open = Transaction::for_operation(
            &principal,
            0,
            Operation::OpenAuthorizationLane {
                lane,
                fee_deposit: Amount::from_webc(1),
            },
            fee,
        )
        .expect("open lane signs");
        state
            .execute_transaction(&open, &config)
            .expect("lane opens");

        let grant = Transaction::for_operation_in_lane(
            &principal,
            lane,
            0,
            Operation::GrantMandate {
                agent_key: agent.public_key(),
                grant_nonce: 0,
                budget_total: Amount::from_units(100_000),
                expiry_epoch: Epoch::new(100),
                per_tx_max: Amount::from_units(100_000),
                rate_limit_per_day: 0,
                counterparty_policy: MandateCounterpartyPolicy::Open,
            },
            fee,
        )
        .expect("grant signs");
        assert!(matches!(
            state.execute_transaction(&grant, &config),
            Err(ChainError::MandateRequiresDefaultLane)
        ));
        assert!(state.mandates.is_empty());
    }

    // ----- native service registry (Phase 9b, §15.5) -----

    use crate::service_registry::{
        ServicePaymentFlags, ServicePrice, MAX_SERVICE_CATEGORIES, MAX_SERVICE_PRICING_ENTRIES,
    };

    /// The application namespace all service-registry tests register under.
    fn service_namespace() -> Hash256 {
        Hash256([0x55; 32])
    }

    /// Genesis funding a mandate principal AND two prospective service owners
    /// (owners pay the spam-priced registration fee and are the pay-to accounts).
    /// The agent is deliberately UNFUNDED: it must spend with no balance of its own.
    fn service_fixture(config: &ChainConfig) -> (ChainState, Keypair, Keypair, Keypair, Keypair) {
        let principal = Keypair::from_seed([31u8; 32]);
        let agent = Keypair::from_seed([32u8; 32]);
        let owner = Keypair::from_seed([33u8; 32]);
        let other_owner = Keypair::from_seed([34u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![
                GenesisAccount {
                    address: principal.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: owner.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: other_owner.address(),
                    balance: Amount::from_webc(1_000),
                },
            ],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).expect("service genesis");
        (state, principal, agent, owner, other_owner)
    }

    fn one_category(tag: u8) -> BTreeSet<Hash256> {
        let mut set = BTreeSet::new();
        set.insert(Hash256([tag; 32]));
        set
    }

    fn active_flags() -> ServicePaymentFlags {
        ServicePaymentFlags {
            on_chain_direct: true,
            http_402: false,
            subscription: false,
        }
    }

    /// Registers a service owned by `owner` with `categories`, returning its id.
    fn register_service(
        state: &mut ChainState,
        config: &ChainConfig,
        owner: &Keypair,
        nonce: u64,
        create_nonce: u64,
        categories: BTreeSet<Hash256>,
    ) -> Result<ServiceId, ChainError> {
        mandate_exec(
            state,
            config,
            owner,
            nonce,
            Operation::RegisterService {
                namespace: service_namespace(),
                create_nonce,
                categories,
                title: b"inference".to_vec(),
                endpoint: b"https://api.example/infer".to_vec(),
                interface: Hash256([0x1f; 32]),
                pricing: vec![ServicePrice {
                    operation: Hash256([0x0b; 32]),
                    price: Amount::from_units(1_000),
                    unit: b"call".to_vec(),
                }],
                payment_flags: active_flags(),
            },
        )?;
        Ok(ServiceId::derive(
            service_namespace(),
            owner.address(),
            create_nonce,
        ))
    }

    /// Builds and executes a service-scoped spend (declaring the pay-to owner).
    #[allow(clippy::too_many_arguments)]
    fn spend_to_service(
        state: &mut ChainState,
        config: &ChainConfig,
        agent: &Keypair,
        nonce: u64,
        mandate_id: MandateId,
        service_id: ServiceId,
        amount: Amount,
        service_owner: Address,
    ) -> Result<Receipt, ChainError> {
        let tx = Transaction::for_service_spend(
            agent,
            nonce,
            mandate_id,
            service_id,
            amount,
            service_owner,
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("service spend signs");
        state.execute_transaction(&tx, config)
    }

    #[test]
    fn register_records_entry_and_reads_back() {
        let config = mandate_config(1_440);
        let (mut state, _principal, _agent, owner, _other) = service_fixture(&config);
        let service_id = register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1))
            .expect("register succeeds");
        let entry = state.services.get(&service_id).expect("entry exists");
        assert_eq!(entry.owner, owner.address());
        assert_eq!(entry.namespace, service_namespace());
        assert_eq!(entry.title, b"inference");
        assert_eq!(entry.revision, crate::INITIAL_SERVICE_REVISION);
        assert_eq!(entry.status, ServiceStatus::Active);
        assert!(entry.categories.contains(&Hash256([0xc1; 32])));
        // Registration locks no native units, so supply stays balanced.
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn duplicate_service_id_is_rejected() {
        let config = mandate_config(1_440);
        let (mut state, _principal, _agent, owner, _other) = service_fixture(&config);
        register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1))
            .expect("first register");
        // Same (namespace, owner, create_nonce) derives the same id: rejected.
        let before = state.clone();
        let err =
            register_service(&mut state, &config, &owner, 1, 0, one_category(0xc2)).unwrap_err();
        assert!(matches!(err, ChainError::ServiceAlreadyExists));
        assert_eq!(state, before, "rejected duplicate leaves state unchanged");
    }

    #[test]
    fn update_by_non_owner_is_rejected_and_by_owner_bumps_revision() {
        let config = mandate_config(1_440);
        let (mut state, _principal, _agent, owner, other) = service_fixture(&config);
        let service_id = register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1))
            .expect("register");
        let update = |new_title: &[u8]| Operation::UpdateService {
            service_id,
            categories: one_category(0xc3),
            title: new_title.to_vec(),
            endpoint: b"https://api.example/v2".to_vec(),
            interface: Hash256([0x2f; 32]),
            pricing: vec![],
            payment_flags: active_flags(),
        };
        // A non-owner cannot update.
        let before = state.clone();
        let err = mandate_exec(&mut state, &config, &other, 0, update(b"hijack")).unwrap_err();
        assert!(matches!(err, ChainError::ServiceNotOwner));
        assert_eq!(state, before, "rejected update leaves state unchanged");
        // The owner can, and the revision bumps.
        mandate_exec(&mut state, &config, &owner, 1, update(b"inference-v2"))
            .expect("owner update");
        let entry = state.services.get(&service_id).unwrap();
        assert_eq!(entry.revision, crate::INITIAL_SERVICE_REVISION + 1);
        assert_eq!(entry.title, b"inference-v2");
        assert_eq!(entry.interface, Hash256([0x2f; 32]));
        assert!(entry.categories.contains(&Hash256([0xc3; 32])));
    }

    #[test]
    fn update_or_status_on_missing_service_is_rejected() {
        let config = mandate_config(1_440);
        let (mut state, _principal, _agent, owner, _other) = service_fixture(&config);
        let missing = ServiceId::new(Hash256([0xab; 32]));
        let err = mandate_exec(
            &mut state,
            &config,
            &owner,
            0,
            Operation::SetServiceStatus {
                service_id: missing,
                status: ServiceStatus::Paused,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::ServiceNotFound));
    }

    #[test]
    fn over_count_categories_and_pricing_are_rejected_on_apply() {
        let config = mandate_config(1_440);
        let (mut state, _principal, _agent, owner, _other) = service_fixture(&config);
        // Too many categories.
        let too_many_categories: BTreeSet<Hash256> = (0..=MAX_SERVICE_CATEGORIES as u8)
            .map(|i| Hash256([i; 32]))
            .collect();
        let err = mandate_exec(
            &mut state,
            &config,
            &owner,
            0,
            Operation::RegisterService {
                namespace: service_namespace(),
                create_nonce: 0,
                categories: too_many_categories,
                title: b"svc".to_vec(),
                endpoint: b"https://x".to_vec(),
                interface: Hash256([0x1f; 32]),
                pricing: vec![],
                payment_flags: active_flags(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::InvalidServiceEntry));
        assert!(state.services.is_empty());
        // Too many pricing entries.
        let too_many_pricing: Vec<ServicePrice> = (0..=MAX_SERVICE_PRICING_ENTRIES as u8)
            .map(|i| ServicePrice {
                operation: Hash256([i; 32]),
                price: Amount::from_units(1),
                unit: b"call".to_vec(),
            })
            .collect();
        let err = mandate_exec(
            &mut state,
            &config,
            &owner,
            0,
            Operation::RegisterService {
                namespace: service_namespace(),
                create_nonce: 1,
                categories: BTreeSet::new(),
                title: b"svc".to_vec(),
                endpoint: b"https://x".to_vec(),
                interface: Hash256([0x1f; 32]),
                pricing: too_many_pricing,
                payment_flags: active_flags(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::InvalidServiceEntry));
        assert!(state.services.is_empty());
    }

    #[test]
    fn service_scoped_spend_pays_owner_and_supply_stays_balanced() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, owner, _other) = service_fixture(&config);
        let service_id = register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1))
            .expect("register");
        let budget = Amount::from_units(500_000);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            budget,
            Epoch::new(100),
            Amount::from_units(200_000),
            5,
            MandateCounterpartyPolicy::Open,
        )
        .expect("grant");
        let owner_before = balance(&state, owner.address());
        let burned_before = state.burned_fees.0;
        let pool_before = state.validator_fee_pool.0;

        let amount = Amount::from_units(100_000);
        let receipt = spend_to_service(
            &mut state,
            &config,
            &agent,
            0,
            mandate_id,
            service_id,
            amount,
            owner.address(),
        )
        .expect("service spend succeeds");

        // The service owner is credited exactly the principal; the agent stays broke.
        assert_eq!(balance(&state, owner.address()), owner_before + 100_000);
        assert_eq!(balance(&state, agent.address()), 0);
        // Escrow fell by amount + fee (10_000); the mandate's spent grew by the same.
        assert_eq!(state.mandate_escrow, Amount::from_units(500_000 - 110_000));
        assert_eq!(
            state.mandates.get(&mandate_id).unwrap().spent,
            Amount::from_units(110_000)
        );
        // The fee split (burn + validator reward) is exactly one ordinary tx fee.
        assert_eq!(
            state.burned_fees.0 + state.validator_fee_pool.0,
            burned_before + pool_before + 10_000
        );
        // The receipt carries BOTH ids — the service-scoped audit trail.
        assert!(receipt.events.iter().any(|event| matches!(
            event,
            Event::MandateSpentToService { mandate_id: m, service_id: s, .. }
                if *m == mandate_id && *s == service_id
        )));
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn paused_or_retired_service_rejects_the_spend() {
        let config = mandate_config(1_440);
        for status in [ServiceStatus::Paused, ServiceStatus::Retired] {
            let (mut state, principal, agent, owner, _other) = service_fixture(&config);
            let service_id =
                register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1))
                    .expect("register");
            mandate_exec(
                &mut state,
                &config,
                &owner,
                1,
                Operation::SetServiceStatus { service_id, status },
            )
            .expect("status change");
            let mandate_id = grant_mandate(
                &mut state,
                &config,
                &principal,
                &agent,
                0,
                0,
                Amount::from_units(500_000),
                Epoch::new(100),
                Amount::from_units(200_000),
                0,
                MandateCounterpartyPolicy::Open,
            )
            .expect("grant");
            let before = state.clone();
            let err = spend_to_service(
                &mut state,
                &config,
                &agent,
                0,
                mandate_id,
                service_id,
                Amount::from_units(100_000),
                owner.address(),
            )
            .unwrap_err();
            assert!(matches!(err, ChainError::ServiceNotActive));
            assert_eq!(state, before, "rejected spend leaves state unchanged");
        }
    }

    #[test]
    fn category_allowlist_pays_matching_service_and_rejects_non_intersecting() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, owner, other) = service_fixture(&config);
        // A service tagged with the allowed category, and one that is not.
        let allowed_category = Hash256([0xaa; 32]);
        let matching = register_service(&mut state, &config, &owner, 0, 0, {
            let mut set = BTreeSet::new();
            set.insert(allowed_category);
            set
        })
        .expect("register matching");
        let non_matching = register_service(&mut state, &config, &other, 0, 1, one_category(0xbb))
            .expect("register non-matching");
        // Mandate whose allowlist references ONLY the category tag.
        let mut allowlist = BTreeSet::new();
        allowlist.insert(MandateCounterparty::Category(allowed_category));
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(500_000),
            Epoch::new(100),
            Amount::from_units(200_000),
            0,
            MandateCounterpartyPolicy::Allowlist(allowlist),
        )
        .expect("grant");
        // The category-tagged service is paid.
        spend_to_service(
            &mut state,
            &config,
            &agent,
            0,
            mandate_id,
            matching,
            Amount::from_units(50_000),
            owner.address(),
        )
        .expect("matching category is paid");
        // The non-intersecting service is rejected.
        let err = spend_to_service(
            &mut state,
            &config,
            &agent,
            1,
            mandate_id,
            non_matching,
            Amount::from_units(50_000),
            other.address(),
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::MandateCounterpartyNotAllowed));
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn recipient_allowlist_matches_service_owner() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, owner, other) = service_fixture(&config);
        let owned = register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1))
            .expect("register owned");
        let other_service = register_service(&mut state, &config, &other, 0, 1, one_category(0xc1))
            .expect("register other");
        // Allowlist references the OWNER address (not a category).
        let mut allowlist = BTreeSet::new();
        allowlist.insert(MandateCounterparty::Recipient(owner.address()));
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(500_000),
            Epoch::new(100),
            Amount::from_units(200_000),
            0,
            MandateCounterpartyPolicy::Allowlist(allowlist),
        )
        .expect("grant");
        // The service owned by the allowlisted owner is paid.
        spend_to_service(
            &mut state,
            &config,
            &agent,
            0,
            mandate_id,
            owned,
            Amount::from_units(50_000),
            owner.address(),
        )
        .expect("owner recipient match is paid");
        // A service owned by a different account is rejected.
        let err = spend_to_service(
            &mut state,
            &config,
            &agent,
            1,
            mandate_id,
            other_service,
            Amount::from_units(50_000),
            other.address(),
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::MandateCounterpartyNotAllowed));
    }

    #[test]
    fn every_phase_9a_mandate_check_binds_on_the_service_path() {
        let config = mandate_config(2);
        let base_grant = |state: &mut ChainState,
                          principal: &Keypair,
                          agent: &Keypair,
                          per_tx: Amount,
                          budget: Amount,
                          expiry: u64,
                          rate: u32| {
            grant_mandate(
                state,
                &config,
                principal,
                agent,
                0,
                0,
                budget,
                Epoch::new(expiry),
                per_tx,
                rate,
                MandateCounterpartyPolicy::Open,
            )
            .expect("grant")
        };

        // Wrong key: a spend signed by a non-agent key is rejected.
        {
            let (mut state, principal, agent, owner, stranger) = service_fixture(&config);
            let service_id =
                register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1)).unwrap();
            let mandate_id = base_grant(
                &mut state,
                &principal,
                &agent,
                Amount::from_units(200_000),
                Amount::from_units(500_000),
                100,
                0,
            );
            let err = spend_to_service(
                &mut state,
                &config,
                &stranger,
                0,
                mandate_id,
                service_id,
                Amount::from_units(50_000),
                owner.address(),
            )
            .unwrap_err();
            assert!(matches!(err, ChainError::MandateAgentKeyMismatch));
        }

        // Per-tx cap, over-budget, expired, revoked, and rate-limit all bind.
        {
            let (mut state, principal, agent, owner, _other) = service_fixture(&config);
            let service_id =
                register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1)).unwrap();
            let mandate_id = base_grant(
                &mut state,
                &principal,
                &agent,
                Amount::from_units(40_000),
                Amount::from_units(500_000),
                100,
                1,
            );
            // Per-tx cap: 50_000 > 40_000.
            let err = spend_to_service(
                &mut state,
                &config,
                &agent,
                0,
                mandate_id,
                service_id,
                Amount::from_units(50_000),
                owner.address(),
            )
            .unwrap_err();
            assert!(matches!(err, ChainError::MandatePerTxExceeded));
        }

        // Over-budget is a CUMULATIVE limit (per_tx_max <= budget_total): two
        // within-cap spends whose running total overflows the budget are rejected
        // on the second.
        {
            let (mut state, principal, agent, owner, _other) = service_fixture(&config);
            let service_id =
                register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1)).unwrap();
            let mandate_id = base_grant(
                &mut state,
                &principal,
                &agent,
                Amount::from_units(60_000),  // per_tx
                Amount::from_units(100_000), // budget covers one 60_000 spend, not two
                100,
                0,
            );
            spend_to_service(
                &mut state,
                &config,
                &agent,
                0,
                mandate_id,
                service_id,
                Amount::from_units(50_000),
                owner.address(),
            )
            .expect("first within-budget spend succeeds");
            let err = spend_to_service(
                &mut state,
                &config,
                &agent,
                1,
                mandate_id,
                service_id,
                Amount::from_units(50_000),
                owner.address(),
            )
            .unwrap_err();
            assert!(matches!(err, ChainError::MandateBudgetExceeded));
        }

        // Expired: current epoch past the mandate's expiry.
        {
            let (mut state, principal, agent, owner, _other) = service_fixture(&config);
            let service_id =
                register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1)).unwrap();
            let mandate_id = base_grant(
                &mut state,
                &principal,
                &agent,
                Amount::from_units(200_000),
                Amount::from_units(500_000),
                0,
                0,
            );
            state.current_epoch = 1;
            let err = spend_to_service(
                &mut state,
                &config,
                &agent,
                0,
                mandate_id,
                service_id,
                Amount::from_units(50_000),
                owner.address(),
            )
            .unwrap_err();
            assert!(matches!(err, ChainError::MandateExpired));
        }

        // Revoked: a revoked mandate rejects the spend.
        {
            let (mut state, principal, agent, owner, _other) = service_fixture(&config);
            let service_id =
                register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1)).unwrap();
            let mandate_id = base_grant(
                &mut state,
                &principal,
                &agent,
                Amount::from_units(200_000),
                Amount::from_units(500_000),
                100,
                0,
            );
            mandate_exec(
                &mut state,
                &config,
                &principal,
                1,
                Operation::RevokeMandate { mandate_id },
            )
            .expect("revoke");
            let err = spend_to_service(
                &mut state,
                &config,
                &agent,
                0,
                mandate_id,
                service_id,
                Amount::from_units(50_000),
                owner.address(),
            )
            .unwrap_err();
            assert!(matches!(err, ChainError::MandateRevoked));
        }

        // Rate limit: a single-spend-per-window mandate rejects the second spend.
        {
            let (mut state, principal, agent, owner, _other) = service_fixture(&config);
            let service_id =
                register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1)).unwrap();
            let mandate_id = base_grant(
                &mut state,
                &principal,
                &agent,
                Amount::from_units(200_000),
                Amount::from_units(500_000),
                100,
                1,
            );
            spend_to_service(
                &mut state,
                &config,
                &agent,
                0,
                mandate_id,
                service_id,
                Amount::from_units(50_000),
                owner.address(),
            )
            .expect("first spend");
            let err = spend_to_service(
                &mut state,
                &config,
                &agent,
                1,
                mandate_id,
                service_id,
                Amount::from_units(50_000),
                owner.address(),
            )
            .unwrap_err();
            assert!(matches!(err, ChainError::MandateRateLimited));
        }
    }

    #[test]
    fn supply_is_balanced_after_register_spend_and_revoke_reclaim() {
        let config = mandate_config(1_440);
        let (mut state, principal, agent, owner, _other) = service_fixture(&config);
        assert!(state.supply_invariant_report().unwrap().balanced);
        let service_id = register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1))
            .expect("register");
        assert!(state.supply_invariant_report().unwrap().balanced);
        let mandate_id = grant_mandate(
            &mut state,
            &config,
            &principal,
            &agent,
            0,
            0,
            Amount::from_units(500_000),
            Epoch::new(100),
            Amount::from_units(200_000),
            0,
            MandateCounterpartyPolicy::Open,
        )
        .expect("grant");
        spend_to_service(
            &mut state,
            &config,
            &agent,
            0,
            mandate_id,
            service_id,
            Amount::from_units(100_000),
            owner.address(),
        )
        .expect("spend");
        assert!(state.supply_invariant_report().unwrap().balanced);
        // Revoke returns the unspent remainder; supply stays balanced.
        mandate_exec(
            &mut state,
            &config,
            &principal,
            1,
            Operation::RevokeMandate { mandate_id },
        )
        .expect("revoke");
        assert_eq!(state.mandate_escrow, Amount::ZERO);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn service_registry_is_committed_by_the_state_root() {
        // E8 extension: the service registry map is a committed consensus field (via
        // the service_registry_root sub-root), so a registration or any in-place
        // revision bump must change the state root. Otherwise two nodes could
        // diverge on registry state yet share a root.
        let config = mandate_config(1_440);
        let (mut state, _principal, _agent, owner, _other) = service_fixture(&config);
        let root = state.state_root().unwrap();
        let service_id = register_service(&mut state, &config, &owner, 0, 0, one_category(0xc1))
            .expect("register");
        assert_ne!(
            state.state_root().unwrap(),
            root,
            "registering a service must change the state root (E8)"
        );
        let after_register = state.state_root().unwrap();
        // A status change bumps the entry's revision in place, moving the root.
        mandate_exec(
            &mut state,
            &config,
            &owner,
            1,
            Operation::SetServiceStatus {
                service_id,
                status: ServiceStatus::Paused,
            },
        )
        .expect("status change");
        assert_ne!(
            state.state_root().unwrap(),
            after_register,
            "a status/revision change must change the state root (E8)"
        );
    }

    // ----- native oracle (Phase 7, §15.17) -----

    /// Oracle-tuned config with small, exact fee/bond placeholders and a fixed
    /// settlement cadence and liveness window.
    fn oracle_config(settlement_epochs: u64, liveness_window_epochs: u64) -> ChainConfig {
        ChainConfig {
            oracle: OracleConfig {
                feed_creation_fee: Amount::from_units(1_000),
                min_reporter_bond: Amount::from_units(10_000),
                settlement_epochs,
                liveness_window_epochs,
            },
            ..ChainConfig::default()
        }
    }

    /// Genesis funding four accounts (no validators) under an oracle config, so
    /// epoch advance mints nothing and every balance change is an oracle move.
    fn oracle_fixture(config: &ChainConfig) -> (ChainState, Keypair, Keypair, Keypair, Keypair) {
        let alice = Keypair::from_seed([1u8; 32]);
        let bob = Keypair::from_seed([2u8; 32]);
        let carol = Keypair::from_seed([3u8; 32]);
        let dave = Keypair::from_seed([4u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
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
                    address: carol.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: dave.address(),
                    balance: Amount::from_webc(1_000),
                },
            ],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).expect("oracle genesis");
        (state, alice, bob, carol, dave)
    }

    /// Executes one oracle operation with a gas limit above any oracle op's cost
    /// and the floor base fee (1 base unit/unit), so tx fees are exact.
    fn oracle_exec(
        state: &mut ChainState,
        config: &ChainConfig,
        keypair: &Keypair,
        nonce: u64,
        operation: Operation,
    ) -> Result<Receipt, ChainError> {
        let tx = Transaction::for_operation(
            keypair,
            nonce,
            operation,
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("oracle tx signs");
        state.execute_transaction(&tx, config)
    }

    fn balance(state: &ChainState, address: Address) -> u128 {
        state.accounts.get(&address).map_or(0, |a| a.balance.0)
    }

    fn find_settlement(
        events: &[Event],
        feed_id: FeedId,
    ) -> Option<(Amount, Amount, Option<FeedValue>)> {
        events.iter().find_map(|event| match event {
            Event::FeedRevenueSettled {
                feed_id: id,
                distributed,
                carried,
                median,
                ..
            } if *id == feed_id => Some((*distributed, *carried, *median)),
            _ => None,
        })
    }

    #[test]
    fn create_feed_charges_fee_and_rejects_duplicate() {
        let config = oracle_config(1, 5);
        let (mut state, alice, ..) = oracle_fixture(&config);
        let feed = FeedId::new(Hash256([9u8; 32]));
        let before = balance(&state, alice.address());
        let burned_before = state.burned_fees.0;

        oracle_exec(
            &mut state,
            &config,
            &alice,
            0,
            Operation::CreateFeed { feed_id: feed },
        )
        .expect("create feed");
        assert!(state.oracle_feeds.contains_key(&feed));
        assert_eq!(state.oracle_feeds[&feed].creator, alice.address());
        assert_eq!(
            state.oracle_feeds[&feed].bond,
            config.oracle.min_reporter_bond
        );
        // The creation fee was burned (on top of the ordinary tx fee).
        assert_eq!(
            state.burned_fees.0,
            burned_before + config.oracle.feed_creation_fee.0 + 15_000 / 2 // creation burn + half the tx fee
        );
        // Liquid dropped by at least the creation fee.
        assert!(before - balance(&state, alice.address()) >= config.oracle.feed_creation_fee.0);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // A duplicate feed id is rejected.
        assert!(matches!(
            oracle_exec(
                &mut state,
                &config,
                &alice,
                1,
                Operation::CreateFeed { feed_id: feed }
            ),
            Err(ChainError::OracleFeedAlreadyExists)
        ));
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn register_and_deregister_reporter_locks_and_returns_bond() {
        let config = oracle_config(1, 5);
        let (mut state, alice, bob, ..) = oracle_fixture(&config);
        let feed = FeedId::new(Hash256([9u8; 32]));
        let bond = config.oracle.min_reporter_bond;
        oracle_exec(
            &mut state,
            &config,
            &alice,
            0,
            Operation::CreateFeed { feed_id: feed },
        )
        .expect("create feed");

        // Registering on a missing feed fails.
        let missing = FeedId::new(Hash256([0xee; 32]));
        assert!(matches!(
            oracle_exec(
                &mut state,
                &config,
                &bob,
                0,
                Operation::RegisterReporter { feed_id: missing }
            ),
            Err(ChainError::OracleFeedNotFound)
        ));

        let bob_before = balance(&state, bob.address());
        oracle_exec(
            &mut state,
            &config,
            &bob,
            0,
            Operation::RegisterReporter { feed_id: feed },
        )
        .expect("register reporter");
        assert_eq!(state.oracle_bonds, bond);
        // Bond + the register tx fee (10_000 units at the floor fee) left liquid.
        assert_eq!(bob_before - balance(&state, bob.address()), bond.0 + 10_000);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // A duplicate registration is rejected.
        assert!(matches!(
            oracle_exec(
                &mut state,
                &config,
                &bob,
                1,
                Operation::RegisterReporter { feed_id: feed }
            ),
            Err(ChainError::OracleReporterAlreadyRegistered)
        ));

        let before = balance(&state, bob.address());
        oracle_exec(
            &mut state,
            &config,
            &bob,
            1,
            Operation::DeregisterReporter { feed_id: feed },
        )
        .expect("deregister reporter");
        assert_eq!(state.oracle_bonds, Amount::ZERO);
        // The bond returned, minus the deregister tx fee (10_000 units at floor).
        assert_eq!(balance(&state, bob.address()), before + bond.0 - 10_000);
        assert!(!state.oracle_reporters.contains_key(&(feed, bob.address())));
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Deregistering again fails.
        assert!(matches!(
            oracle_exec(
                &mut state,
                &config,
                &bob,
                2,
                Operation::DeregisterReporter { feed_id: feed }
            ),
            Err(ChainError::OracleReporterNotFound)
        ));
    }

    #[test]
    fn median_aggregation_over_single_even_and_odd_reporters() {
        let config = oracle_config(1, 5);
        let (mut state, alice, bob, carol, dave) = oracle_fixture(&config);
        let feed = FeedId::new(Hash256([9u8; 32]));
        oracle_exec(
            &mut state,
            &config,
            &alice,
            0,
            Operation::CreateFeed { feed_id: feed },
        )
        .expect("create feed");

        // No feed / no reports -> None.
        assert_eq!(state.feed_value(FeedId::new(Hash256([1u8; 32]))), None);
        assert_eq!(state.feed_value(feed), None);

        // A reporter cannot report before registering.
        assert!(matches!(
            oracle_exec(
                &mut state,
                &config,
                &bob,
                0,
                Operation::SubmitReport {
                    feed_id: feed,
                    value: FeedValue::new(42)
                }
            ),
            Err(ChainError::OracleReporterNotFound)
        ));

        // Single reporter: the median is that value.
        oracle_exec(
            &mut state,
            &config,
            &bob,
            0,
            Operation::RegisterReporter { feed_id: feed },
        )
        .expect("register bob");
        oracle_exec(
            &mut state,
            &config,
            &bob,
            1,
            Operation::SubmitReport {
                feed_id: feed,
                value: FeedValue::new(42),
            },
        )
        .expect("bob reports");
        assert_eq!(state.feed_value(feed), Some(FeedValue::new(42)));

        // Even count (2): lower-mid of sorted [10, 42] is 10.
        oracle_exec(
            &mut state,
            &config,
            &carol,
            0,
            Operation::RegisterReporter { feed_id: feed },
        )
        .expect("register carol");
        oracle_exec(
            &mut state,
            &config,
            &carol,
            1,
            Operation::SubmitReport {
                feed_id: feed,
                value: FeedValue::new(10),
            },
        )
        .expect("carol reports");
        assert_eq!(state.feed_value(feed), Some(FeedValue::new(10)));

        // Odd count (3): middle of sorted [10, 42, 100] is 42.
        oracle_exec(
            &mut state,
            &config,
            &dave,
            0,
            Operation::RegisterReporter { feed_id: feed },
        )
        .expect("register dave");
        oracle_exec(
            &mut state,
            &config,
            &dave,
            1,
            Operation::SubmitReport {
                feed_id: feed,
                value: FeedValue::new(100),
            },
        )
        .expect("dave reports");
        assert_eq!(state.feed_value(feed), Some(FeedValue::new(42)));
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn read_fee_revenue_is_accuracy_weighted_with_exact_conservation() {
        let config = oracle_config(1, 5);
        let (mut state, alice, bob, carol, dave) = oracle_fixture(&config);
        let feed = FeedId::new(Hash256([9u8; 32]));
        oracle_exec(
            &mut state,
            &config,
            &alice,
            0,
            Operation::CreateFeed { feed_id: feed },
        )
        .expect("create feed");

        // Three reporters at distances 0, 1, 10 from the median 100.
        for (kp, value) in [(&bob, 100i128), (&carol, 101), (&dave, 90)] {
            oracle_exec(
                &mut state,
                &config,
                kp,
                0,
                Operation::RegisterReporter { feed_id: feed },
            )
            .expect("register");
            oracle_exec(
                &mut state,
                &config,
                kp,
                1,
                Operation::SubmitReport {
                    feed_id: feed,
                    value: FeedValue::new(value),
                },
            )
            .expect("report");
        }
        assert_eq!(state.feed_value(feed), Some(FeedValue::new(100)));

        // A zero read-fee is rejected; a real one accrues to the pool.
        assert!(matches!(
            oracle_exec(
                &mut state,
                &config,
                &alice,
                1,
                Operation::PayFeedRead {
                    feed_id: feed,
                    amount: Amount::ZERO
                }
            ),
            Err(ChainError::OracleReadAmountZero)
        ));
        let revenue = Amount::from_units(1_000_000);
        oracle_exec(
            &mut state,
            &config,
            &alice,
            1,
            Operation::PayFeedRead {
                feed_id: feed,
                amount: revenue,
            },
        )
        .expect("pay read fee");
        assert_eq!(state.oracle_revenue, revenue);
        assert_eq!(state.oracle_feeds[&feed].revenue, revenue);
        assert!(state.supply_invariant_report().unwrap().balanced);

        let (bob_b, carol_b, dave_b) = (
            balance(&state, bob.address()),
            balance(&state, carol.address()),
            balance(&state, dave.address()),
        );
        let events = state.distribute_epoch_rewards(&config).expect("settle");
        let (distributed, carried, median_value) =
            find_settlement(&events, feed).expect("settlement event");
        assert_eq!(median_value, Some(FeedValue::new(100)));

        let bob_share = balance(&state, bob.address()) - bob_b;
        let carol_share = balance(&state, carol.address()) - carol_b;
        let dave_share = balance(&state, dave.address()) - dave_b;
        // Accuracy ordering: nearer the median earns strictly more.
        assert!(bob_share > carol_share);
        assert!(carol_share > dave_share);
        assert!(dave_share > 0);
        // Exact conservation: shares sum to the distributed total, and the
        // integer-division remainder is carried in the feed pool (nothing lost).
        assert_eq!(bob_share + carol_share + dave_share, distributed.0);
        assert_eq!(distributed.0 + carried.0, revenue.0);
        assert_eq!(state.oracle_feeds[&feed].revenue, carried);
        assert_eq!(state.oracle_revenue, carried);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn stale_reporter_earns_no_liveness_reward() {
        // Liveness window 1: a report is live only for the reporting epoch and the
        // next one.
        let config = oracle_config(1, 1);
        let (mut state, alice, bob, carol, _dave) = oracle_fixture(&config);
        let feed = FeedId::new(Hash256([9u8; 32]));
        oracle_exec(
            &mut state,
            &config,
            &alice,
            0,
            Operation::CreateFeed { feed_id: feed },
        )
        .expect("create feed");
        for kp in [&bob, &carol] {
            oracle_exec(
                &mut state,
                &config,
                kp,
                0,
                Operation::RegisterReporter { feed_id: feed },
            )
            .expect("register");
            oracle_exec(
                &mut state,
                &config,
                kp,
                1,
                Operation::SubmitReport {
                    feed_id: feed,
                    value: FeedValue::new(100),
                },
            )
            .expect("report at epoch 0");
        }

        // Advance to epoch 2 (both intermediate settlements have no revenue).
        state
            .distribute_epoch_rewards(&config)
            .expect("advance to epoch 1");
        state
            .distribute_epoch_rewards(&config)
            .expect("advance to epoch 2");
        assert_eq!(state.current_epoch, 2);

        // Bob refreshes at epoch 2 (live); carol stays stale (last report epoch 0).
        oracle_exec(
            &mut state,
            &config,
            &bob,
            2,
            Operation::SubmitReport {
                feed_id: feed,
                value: FeedValue::new(100),
            },
        )
        .expect("bob refreshes");
        let revenue = Amount::from_units(500_000);
        oracle_exec(
            &mut state,
            &config,
            &alice,
            1,
            Operation::PayFeedRead {
                feed_id: feed,
                amount: revenue,
            },
        )
        .expect("pay read fee");

        let (bob_b, carol_b) = (
            balance(&state, bob.address()),
            balance(&state, carol.address()),
        );
        let events = state
            .distribute_epoch_rewards(&config)
            .expect("settle epoch 2");
        let (distributed, carried, _median) = find_settlement(&events, feed).expect("settled");

        let bob_share = balance(&state, bob.address()) - bob_b;
        let carol_share = balance(&state, carol.address()) - carol_b;
        assert_eq!(carol_share, 0, "a stale reporter earns nothing");
        assert!(bob_share > 0, "the live reporter earns the revenue");
        assert_eq!(bob_share, distributed.0);
        // Bob is the only live reporter and sits on the median, so he takes all of
        // the revenue with no remainder.
        assert_eq!(distributed, revenue);
        assert_eq!(carried, Amount::ZERO);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn oracle_state_survives_bincode_restart() {
        let config = oracle_config(4, 5);
        let (mut state, alice, bob, carol, dave) = oracle_fixture(&config);
        let feed = FeedId::new(Hash256([9u8; 32]));
        oracle_exec(
            &mut state,
            &config,
            &alice,
            0,
            Operation::CreateFeed { feed_id: feed },
        )
        .expect("create feed");
        // A reporter with a value, a reporter without a value, and accrued
        // (unsettled) revenue exercise every oracle field on disk.
        oracle_exec(
            &mut state,
            &config,
            &bob,
            0,
            Operation::RegisterReporter { feed_id: feed },
        )
        .expect("register bob");
        oracle_exec(
            &mut state,
            &config,
            &bob,
            1,
            Operation::SubmitReport {
                feed_id: feed,
                value: FeedValue::new(-987_654_321),
            },
        )
        .expect("bob reports");
        oracle_exec(
            &mut state,
            &config,
            &carol,
            0,
            Operation::RegisterReporter { feed_id: feed },
        )
        .expect("register carol (no report)");
        oracle_exec(
            &mut state,
            &config,
            &dave,
            0,
            Operation::PayFeedRead {
                feed_id: feed,
                amount: Amount::from_units(777),
            },
        )
        .expect("dave pays a read fee");

        let root = state.state_root().unwrap();
        let restored = bincode_restart(&state);
        assert_eq!(restored, state, "oracle state round-trips through bincode");
        assert_eq!(
            restored.state_root().unwrap(),
            root,
            "state root is preserved across a crash-restart"
        );
        assert_eq!(restored.feed_value(feed), state.feed_value(feed));
        assert_eq!(restored.oracle_bonds, state.oracle_bonds);
        assert_eq!(restored.oracle_revenue, state.oracle_revenue);
        assert!(restored.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn oracle_settlement_is_deterministic_across_runs() {
        fn run() -> Hash256 {
            let config = oracle_config(1, 5);
            let (mut state, alice, bob, carol, dave) = oracle_fixture(&config);
            let feed = FeedId::new(Hash256([9u8; 32]));
            oracle_exec(
                &mut state,
                &config,
                &alice,
                0,
                Operation::CreateFeed { feed_id: feed },
            )
            .unwrap();
            for (kp, value) in [(&bob, 100i128), (&carol, 103), (&dave, 88)] {
                oracle_exec(
                    &mut state,
                    &config,
                    kp,
                    0,
                    Operation::RegisterReporter { feed_id: feed },
                )
                .unwrap();
                oracle_exec(
                    &mut state,
                    &config,
                    kp,
                    1,
                    Operation::SubmitReport {
                        feed_id: feed,
                        value: FeedValue::new(value),
                    },
                )
                .unwrap();
            }
            oracle_exec(
                &mut state,
                &config,
                &alice,
                1,
                Operation::PayFeedRead {
                    feed_id: feed,
                    amount: Amount::from_units(999_983),
                },
            )
            .unwrap();
            state.distribute_epoch_rewards(&config).unwrap();
            state.state_root().unwrap()
        }
        assert_eq!(run(), run(), "oracle settlement is deterministic");
    }

    // ----- session-key test helpers -----

    /// Process-wide ML-DSA-65 recovery keypair for session-key tests.
    ///
    /// One keypair is generated once and reused so the committed root and every
    /// signed reveal agree. Generation draws OS randomness (fine in tests);
    /// verification inside the state machine stays deterministic.
    fn pq_keypair() -> &'static (MlDsa65PublicKey, MlDsa65SecretKey) {
        static KEYPAIR: OnceLock<(MlDsa65PublicKey, MlDsa65SecretKey)> = OnceLock::new();
        KEYPAIR.get_or_init(|| ml_dsa65_keygen().expect("ml-dsa-65 keygen"))
    }

    /// The committed root public key bytes for `installed_policy_state`.
    fn pq_public_key() -> Vec<u8> {
        pq_keypair().0.to_bytes()
    }

    /// Signs an authorization message for `action` at `nonce` under Alice's
    /// installed policy (revision 1) on the devnet chain, matching exactly what
    /// the state machine rebuilds and verifies.
    fn signed_reveal(
        owner: Address,
        nonce: u64,
        action: &SessionKeyAuthorizationAction,
    ) -> PostQuantumRootReveal {
        let (public_key, secret) = pq_keypair();
        let message = session_key_authorization_message(
            &ChainId::devnet(),
            owner,
            AuthorizationPolicyRevision::new(1),
            nonce,
            action,
        )
        .unwrap();
        // Empty context: the domain lives in the signed message, matching the
        // verifier's `POST_QUANTUM_AUTHORIZATION_CONTEXT`.
        let signature = secret.sign(&message, b"").unwrap();
        PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: public_key.to_bytes(),
            signature,
        }
    }

    /// A reveal whose signature is over exactly `message` (a test may sign a
    /// message that disagrees with what the chain will rebuild, to prove a
    /// specific binding axis is enforced).
    fn reveal_over_message(message: &[u8]) -> PostQuantumRootReveal {
        let (public_key, secret) = pq_keypair();
        PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: public_key.to_bytes(),
            signature: secret.sign(message, b"").unwrap(),
        }
    }

    /// A valid install reveal for the given session key and constraints.
    fn install_reveal(
        owner: Address,
        nonce: u64,
        session_public_key: PublicKeyBytes,
        constraints: &SessionKeyConstraints,
    ) -> PostQuantumRootReveal {
        signed_reveal(
            owner,
            nonce,
            &SessionKeyAuthorizationAction::Install {
                session_public_key,
                constraints: constraints.clone(),
            },
        )
    }

    /// A valid revoke reveal for the given session-key id.
    fn revoke_reveal(
        owner: Address,
        nonce: u64,
        session_key: SessionKeyId,
    ) -> PostQuantumRootReveal {
        signed_reveal(
            owner,
            nonce,
            &SessionKeyAuthorizationAction::Revoke { session_key },
        )
    }

    /// A well-formed reveal used only where the action is rejected *before* the
    /// root signature is checked (wrong lane, no installed policy). Its signature
    /// is never verified, so a correctly sized placeholder is enough.
    fn unverified_reveal() -> PostQuantumRootReveal {
        PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: pq_public_key(),
            signature: vec![0u8; ML_DSA_65_SIGNATURE_LEN],
        }
    }

    /// Funded Alice with an installed policy whose post-quantum root commits to
    /// `pq_public_key()`. Alice's account nonce is 1 after installation.
    fn installed_policy_state() -> (ChainConfig, ChainState, Keypair, Keypair) {
        let (config, mut state, alice, bob) = funded_state();
        let root =
            PostQuantumRoot::from_public_key(PostQuantumScheme::MlDsa65, &pq_public_key()).unwrap();
        let install = Transaction::for_operation(
            &alice,
            0,
            Operation::InstallAuthorizationPolicy {
                post_quantum_root: root,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&install, &config).unwrap();
        (config, state, alice, bob)
    }

    /// Default-lane transfer constraints: 5 WEBC per use, 20 WEBC budget.
    fn session_constraints() -> SessionKeyConstraints {
        SessionKeyConstraints {
            authorization_lane: AuthorizationLaneId::DEFAULT,
            allowed_operations: SessionAllowedOperations::transfers_only(),
            max_amount_per_use: Amount::from_webc(5),
            total_amount_budget: Amount::from_webc(20),
            max_fee_per_use: Amount::from_webc(1),
            total_fee_budget: Amount::from_webc(5),
            lifetime_epochs: 60,
        }
    }

    fn install_session_key_tx(
        owner: &Keypair,
        session: &Keypair,
        nonce: u64,
        constraints: SessionKeyConstraints,
    ) -> Transaction {
        let reveal = install_reveal(owner.address(), nonce, session.public_key(), &constraints);
        install_session_key_tx_with_reveal(owner, session, nonce, constraints, reveal)
    }

    fn install_session_key_tx_with_reveal(
        owner: &Keypair,
        session: &Keypair,
        nonce: u64,
        constraints: SessionKeyConstraints,
        reveal: PostQuantumRootReveal,
    ) -> Transaction {
        Transaction::for_operation_with_policy(
            owner,
            AuthorizationPolicyRevision::new(1),
            nonce,
            Operation::InstallSessionKey {
                session_public_key: session.public_key(),
                constraints,
                post_quantum_root_reveal: reveal,
            },
            FeeBid {
                gas_limit: 20_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap()
    }

    /// Builds and signs a transfer authorized by a session key.
    fn session_transfer_tx(
        owner: &Keypair,
        session: &Keypair,
        lane: AuthorizationLaneId,
        nonce: u64,
        to: Address,
        amount: Amount,
        fee: FeeBid,
    ) -> Transaction {
        let id = SessionKeyId::derive(&session.public_key());
        let operation = Operation::Transfer { to, amount };
        let access_list = operation
            .default_access_list_for_session(owner.address(), lane, id)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            owner.address(),
            session.public_key(),
            lane,
            AuthorizationPolicyRevision::new(1),
            nonce,
            operation,
            access_list,
            fee,
        );
        tx.sign_with_policy_key(session).unwrap();
        tx
    }

    fn small_fee() -> FeeBid {
        FeeBid {
            gas_limit: 1_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        }
    }

    // ----- session-key tests -----

    #[test]
    fn session_key_install_use_and_revoke_lifecycle() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());

        let before_install = state.state_root().unwrap();
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();
        assert!(state.session_keys.contains_key(&(alice.address(), id)));
        assert_ne!(state.state_root().unwrap(), before_install);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // A within-limits transfer signed by the session key succeeds and moves
        // the owner's funds, advancing only the session's cumulative spend.
        let bob_before = state.accounts.get(&bob.address()).map(|a| a.balance);
        let transfer = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(4),
            small_fee(),
        );
        state.execute_transaction(&transfer, &config).unwrap();
        assert_eq!(
            state.session_keys[&(alice.address(), id)].spent_amount,
            Amount::from_webc(4)
        );
        let bob_after = state.accounts.get(&bob.address()).unwrap().balance;
        assert_eq!(
            bob_after,
            bob_before
                .unwrap_or(Amount::ZERO)
                .checked_add(Amount::from_webc(4))
                .unwrap()
        );
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Revocation removes the key; the same key can no longer authorize.
        let revoke = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            3,
            Operation::RevokeSessionKey {
                session_key: id,
                post_quantum_root_reveal: revoke_reveal(alice.address(), 3, id),
            },
            small_fee_with_units(20_000),
        )
        .unwrap();
        state.execute_transaction(&revoke, &config).unwrap();
        assert!(!state.session_keys.contains_key(&(alice.address(), id)));

        let after_revoke = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            3,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&after_revoke, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    fn small_fee_with_units(gas_limit: u64) -> FeeBid {
        FeeBid {
            gas_limit,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        }
    }

    #[test]
    fn session_transfer_respects_per_use_budget_and_fee_caps() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());
        // Per-use 5 WEBC, cumulative budget 12 WEBC, per-use fee cap 1 WEBC.
        let mut constraints = session_constraints();
        constraints.total_amount_budget = Amount::from_webc(12);
        let install = install_session_key_tx(&alice, &session, 1, constraints);
        state.execute_transaction(&install, &config).unwrap();

        // Over the per-use cap (5 WEBC): rejected atomically, nonce unchanged.
        let over_use = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(6),
            small_fee(),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&over_use, &config),
            Err(ChainError::SessionKeyAmountExceeded)
        ));
        assert_eq!(state, before);

        // Two 5 WEBC transfers succeed and reach 10 WEBC cumulative spend.
        for nonce in [2u64, 3] {
            let tx = session_transfer_tx(
                &alice,
                &session,
                AuthorizationLaneId::DEFAULT,
                nonce,
                bob.address(),
                Amount::from_webc(5),
                small_fee(),
            );
            state.execute_transaction(&tx, &config).unwrap();
        }
        assert_eq!(
            state.session_keys[&(alice.address(), id)].spent_amount,
            Amount::from_webc(10)
        );

        // A third 5 WEBC transfer would reach 15 WEBC, above the 12 WEBC budget,
        // and is rejected atomically.
        let over_budget = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            4,
            bob.address(),
            Amount::from_webc(5),
            small_fee(),
        );
        let before_budget = state.clone();
        assert!(matches!(
            state.execute_transaction(&over_budget, &config),
            Err(ChainError::SessionKeyBudgetExceeded)
        ));
        assert_eq!(state, before_budget);

        // A fee bid whose ceiling exceeds the per-use fee cap (1 WEBC) fails,
        // even though the 1 WEBC principal is within budget.
        let over_fee = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            4,
            bob.address(),
            Amount::from_webc(1),
            FeeBid {
                gas_limit: 2_000_000_000,
                max_fee_per_unit: 1_000,
                priority_fee_per_unit: 0,
            },
        );
        let before_fee = state.clone();
        assert!(matches!(
            state.execute_transaction(&over_fee, &config),
            Err(ChainError::SessionKeyFeeExceeded)
        ));
        assert_eq!(state, before_fee);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn expired_session_key_is_rejected_at_the_boundary() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let mut constraints = session_constraints();
        constraints.lifetime_epochs = 2;
        let install = install_session_key_tx(&alice, &session, 1, constraints);
        state.execute_transaction(&install, &config).unwrap();

        // Valid through the expiry epoch (inclusive). Advancing the epoch is a
        // deterministic integer step; expiry never reads a wall clock.
        state.current_epoch = 2;
        let at_expiry = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        state.execute_transaction(&at_expiry, &config).unwrap();

        // One epoch later the key is expired and cannot authorize.
        state.current_epoch = 3;
        let after_expiry = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            3,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&after_expiry, &config),
            Err(ChainError::SessionKeyExpired)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_key_cannot_authorize_a_non_transfer_operation() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();

        // A claim operation is not in the session allow-list and is refused
        // before any state change, even though the key is otherwise valid.
        let operation = Operation::ClaimValidatorRewards;
        let id = SessionKeyId::derive(&session.public_key());
        let access_list = operation
            .default_access_list_for_session(alice.address(), AuthorizationLaneId::DEFAULT, id)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            session.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(1),
            2,
            operation,
            access_list,
            small_fee_with_units(10_000),
        );
        tx.sign_with_policy_key(&session).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::SessionKeyOperationNotPermitted)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_key_bound_lane_mismatch_is_rejected() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let bound_lane = AuthorizationLaneId::new(Hash256([0x77; 32]));
        let mut constraints = session_constraints();
        constraints.authorization_lane = bound_lane;
        let install = install_session_key_tx(&alice, &session, 1, constraints);
        state.execute_transaction(&install, &config).unwrap();

        // The key is bound to `bound_lane`; a transfer on the default lane is
        // refused during authorization, before any fee or state change.
        let wrong_lane = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&wrong_lane, &config),
            Err(ChainError::SessionKeyLaneMismatch)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_key_is_invalidated_when_bound_policy_revision_changes() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();

        // A key rotation bumps the account policy revision. Simulate the stored
        // effect: the session was installed under revision 1, so a policy now at
        // revision 2 must invalidate it.
        state
            .session_keys
            .get_mut(&(alice.address(), id))
            .unwrap()
            .policy_revision = AuthorizationPolicyRevision::new(2);
        let transfer = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&transfer, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn install_session_key_fail_closed_paths() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);

        // Wrong post-quantum root reveal: a well-formed reveal whose public key
        // does not match the committed root, so the commitment check rejects it
        // before any signature verification.
        let bad_reveal = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: vec![0xC4u8; 1_952],
            signature: vec![0u8; ML_DSA_65_SIGNATURE_LEN],
        };
        let install_bad = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            session_constraints(),
            bad_reveal,
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&install_bad, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // Lifetime beyond the configured maximum.
        let mut too_long = session_constraints();
        too_long.lifetime_epochs = config.session_keys.max_lifetime_epochs + 1;
        let install_long = install_session_key_tx(&alice, &session, 1, too_long);
        assert!(matches!(
            state.execute_transaction(&install_long, &config),
            Err(ChainError::SessionKeyLifetimeTooLong)
        ));

        // Invalid constraints (budget below per-use).
        let mut invalid = session_constraints();
        invalid.total_amount_budget = Amount::from_webc(1);
        let install_invalid = install_session_key_tx(&alice, &session, 1, invalid);
        assert!(matches!(
            state.execute_transaction(&install_invalid, &config),
            Err(ChainError::InvalidSessionKeyConstraints)
        ));

        // Duplicate installation is rejected.
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();
        let dup = install_session_key_tx(&alice, &session, 2, session_constraints());
        assert!(matches!(
            state.execute_transaction(&dup, &config),
            Err(ChainError::SessionKeyAlreadyExists)
        ));
    }

    /// The root-signature gate must reject a reveal that does not carry a real
    /// ML-DSA signature by the committed root over this exact install. These are
    /// the attacks the commitment-only reveal could not stop.
    #[test]
    fn install_session_key_rejects_misbound_or_forged_root_signature() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let constraints = session_constraints();
        let before = state.clone();

        // (a) Correct root key and action, but signed for a different nonce than
        // the transaction runs at: a captured signature cannot be replayed at a
        // new nonce because the message binds the nonce.
        let wrong_nonce = install_reveal(alice.address(), 2, session.public_key(), &constraints);
        let install_wrong_nonce = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            constraints.clone(),
            wrong_nonce,
        );
        assert!(matches!(
            state.execute_transaction(&install_wrong_nonce, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (b) A real signature over a *different action* (a revoke) cannot be
        // repurposed to authorize this install.
        let wrong_action = revoke_reveal(
            alice.address(),
            1,
            SessionKeyId::derive(&session.public_key()),
        );
        let install_wrong_action = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            constraints.clone(),
            wrong_action,
        );
        assert!(matches!(
            state.execute_transaction(&install_wrong_action, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (c) The committed public key but a garbage signature of the right
        // length: the commitment check passes, the signature check fails closed.
        let garbage = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: pq_public_key(),
            signature: vec![0x7u8; ML_DSA_65_SIGNATURE_LEN],
        };
        let install_garbage =
            install_session_key_tx_with_reveal(&alice, &session, 1, constraints.clone(), garbage);
        assert!(matches!(
            state.execute_transaction(&install_garbage, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (d) A *different* ML-DSA key with a genuine signature over the correct
        // message: this models a compromised active key trying to substitute its
        // own post-quantum key. The commitment check binds the reveal to the
        // account's committed root, so it is rejected.
        let (other_public, other_secret) = ml_dsa65_keygen().unwrap();
        let action = SessionKeyAuthorizationAction::Install {
            session_public_key: session.public_key(),
            constraints: constraints.clone(),
        };
        let message = session_key_authorization_message(
            &ChainId::devnet(),
            alice.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &action,
        )
        .unwrap();
        let wrong_key = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: other_public.to_bytes(),
            signature: other_secret.sign(&message, b"").unwrap(),
        };
        let install_wrong_key =
            install_session_key_tx_with_reveal(&alice, &session, 1, constraints, wrong_key);
        assert!(matches!(
            state.execute_transaction(&install_wrong_key, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // The correctly bound install still succeeds, so the gate is not simply
        // rejecting everything.
        let good = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&good, &config).unwrap();
        assert!(state
            .session_keys
            .contains_key(&(alice.address(), SessionKeyId::derive(&session.public_key()))));
    }

    /// The install root signature must bind the exact constraints, the owner, and
    /// the chain id — not just the nonce and action. Each sub-case signs a message
    /// that disagrees with the submitted transaction on exactly one axis and must
    /// be rejected, so a future regression that drops any binding is caught.
    #[test]
    fn install_session_key_binds_signature_to_constraints_owner_and_chain() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let revision = AuthorizationPolicyRevision::new(1);
        let before = state.clone();

        // (a) Constraint escalation: sign a modest grant but submit a larger one.
        // The chain rebuilds the message from the *submitted* constraints, so the
        // signature over the smaller grant does not verify.
        let signed_constraints = session_constraints();
        let mut submitted_constraints = session_constraints();
        submitted_constraints.max_amount_per_use = Amount::from_webc(4);
        submitted_constraints.total_amount_budget = Amount::from_webc(80);
        assert_ne!(signed_constraints, submitted_constraints);
        let signed_action = SessionKeyAuthorizationAction::Install {
            session_public_key: session.public_key(),
            constraints: signed_constraints,
        };
        let message = session_key_authorization_message(
            &ChainId::devnet(),
            alice.address(),
            revision,
            1,
            &signed_action,
        )
        .unwrap();
        let install_escalated = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            submitted_constraints,
            reveal_over_message(&message),
        );
        assert!(matches!(
            state.execute_transaction(&install_escalated, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // The correctly bound install action, reused for the owner and chain axes.
        let action = SessionKeyAuthorizationAction::Install {
            session_public_key: session.public_key(),
            constraints: session_constraints(),
        };

        // (b) Cross-account replay: sign with a different owner than the submitting
        // account. Even if two accounts shared a post-quantum root, the owner
        // binding stops a signature made for one account authorizing the other.
        let wrong_owner_message = session_key_authorization_message(
            &ChainId::devnet(),
            bob.address(),
            revision,
            1,
            &action,
        )
        .unwrap();
        let install_wrong_owner = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            session_constraints(),
            reveal_over_message(&wrong_owner_message),
        );
        assert!(matches!(
            state.execute_transaction(&install_wrong_owner, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (c) Cross-chain replay: sign for a different chain id than the one the
        // transaction executes on.
        let other_chain = ChainId::new("webc-testnet-9").unwrap();
        let wrong_chain_message =
            session_key_authorization_message(&other_chain, alice.address(), revision, 1, &action)
                .unwrap();
        let install_wrong_chain = install_session_key_tx_with_reveal(
            &alice,
            &session,
            1,
            session_constraints(),
            reveal_over_message(&wrong_chain_message),
        );
        assert!(matches!(
            state.execute_transaction(&install_wrong_chain, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);
    }

    /// The revoke gate binds the root signature to the exact session-key id, so a
    /// signature prepared for another id cannot revoke this one.
    #[test]
    fn revoke_session_key_rejects_misbound_root_signature() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();

        // Revoke at nonce 2 with a reveal signed for a different session-key id.
        let other_id = SessionKeyId::new(Hash256([0x33; 32]));
        let revoke = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            2,
            Operation::RevokeSessionKey {
                session_key: id,
                post_quantum_root_reveal: revoke_reveal(alice.address(), 2, other_id),
            },
            small_fee_with_units(20_000),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&revoke, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);
        // The key is still installed because the misbound revoke was rejected.
        assert!(state.session_keys.contains_key(&(alice.address(), id)));
    }

    #[test]
    fn session_key_management_requires_default_lane() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let lane = AuthorizationLaneId::new(Hash256([0x55; 32]));
        // Open a funded non-default lane so its nonce/fee lookup succeeds and the
        // critical-action default-lane guard is the check that actually fires.
        let open = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::OpenAuthorizationLane {
                lane,
                fee_deposit: Amount::from_webc(1),
            },
            small_fee_with_units(10_000),
        )
        .unwrap();
        state.execute_transaction(&open, &config).unwrap();

        let session = Keypair::from_seed([9u8; 32]);
        let operation = Operation::InstallSessionKey {
            session_public_key: session.public_key(),
            constraints: session_constraints(),
            // Rejected by the default-lane guard before the reveal is verified.
            post_quantum_root_reveal: unverified_reveal(),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), lane)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            alice.public_key(),
            lane,
            AuthorizationPolicyRevision::new(1),
            0,
            operation,
            access_list,
            small_fee_with_units(20_000),
        );
        tx.sign_with_policy_key(&alice).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::SessionKeyManagementRequiresDefaultLane)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn legacy_account_cannot_own_session_keys() {
        let (config, mut state, alice, _bob) = funded_state();
        let session = Keypair::from_seed([9u8; 32]);
        // Alice has no installed policy, so `for_operation` uses revision zero.
        let install = Transaction::for_operation(
            &alice,
            0,
            Operation::InstallSessionKey {
                session_public_key: session.public_key(),
                constraints: session_constraints(),
                // Rejected for having no installed policy before reveal checks.
                post_quantum_root_reveal: unverified_reveal(),
            },
            small_fee_with_units(20_000),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&install, &config),
            Err(ChainError::SessionKeyRequiresInstalledPolicy)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_key_count_cap_is_enforced() {
        let (mut config, mut state, alice, _bob) = installed_policy_state();
        config.session_keys.max_session_keys_per_account = 2;
        for (i, seed) in [[10u8; 32], [11u8; 32]].into_iter().enumerate() {
            let session = Keypair::from_seed(seed);
            let install =
                install_session_key_tx(&alice, &session, 1 + i as u64, session_constraints());
            state.execute_transaction(&install, &config).unwrap();
        }
        let third = Keypair::from_seed([12u8; 32]);
        let install = install_session_key_tx(&alice, &third, 3, session_constraints());
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&install, &config),
            Err(ChainError::SessionKeyLimitExceeded)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn revoke_unknown_session_key_is_rejected() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let missing = SessionKeyId::new(Hash256([0xEE; 32]));
        let revoke = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::RevokeSessionKey {
                session_key: missing,
                post_quantum_root_reveal: revoke_reveal(alice.address(), 1, missing),
            },
            small_fee_with_units(20_000),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&revoke, &config),
            Err(ChainError::SessionKeyNotFound)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_keys_survive_serialization_restart() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();
        let transfer = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            2,
            bob.address(),
            Amount::from_webc(3),
            small_fee(),
        );
        state.execute_transaction(&transfer, &config).unwrap();

        // The whole chain state uses tuple-keyed maps, so it round-trips through
        // bincode (a non-string-key format) rather than JSON.
        let restored = bincode_restart(&state);
        assert_eq!(restored, state);
        assert_eq!(restored.state_root().unwrap(), state.state_root().unwrap());
    }

    #[test]
    fn cumulative_fee_budget_bounds_a_compromised_key() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());
        // Tiny principal, but a cumulative fee budget of 3,000 base units. Each
        // transfer below charges exactly 1,000 base units in real fees.
        let mut constraints = session_constraints();
        constraints.max_fee_per_use = Amount::from_units(2_000);
        constraints.total_fee_budget = Amount::from_units(3_000);
        let install = install_session_key_tx(&alice, &session, 1, constraints);
        state.execute_transaction(&install, &config).unwrap();

        // A fee bid that charges 1,000 base units per transfer (500 units * 2).
        let drain_fee = FeeBid {
            gas_limit: 500,
            max_fee_per_unit: 2,
            priority_fee_per_unit: 2,
        };
        for nonce in [2u64, 3, 4] {
            let tx = session_transfer_tx(
                &alice,
                &session,
                AuthorizationLaneId::DEFAULT,
                nonce,
                bob.address(),
                Amount::from_units(1),
                drain_fee,
            );
            state.execute_transaction(&tx, &config).unwrap();
        }
        assert_eq!(
            state.session_keys[&(alice.address(), id)].spent_fees,
            Amount::from_units(3_000)
        );

        // The fourth transfer would push cumulative fees to 4,000 > 3,000 and is
        // rejected, so the total fee drain is bounded regardless of use count.
        let over = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            5,
            bob.address(),
            Amount::from_units(1),
            drain_fee,
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&over, &config),
            Err(ChainError::SessionKeyFeeBudgetExceeded)
        ));
        assert_eq!(state, before);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn session_transfer_works_on_a_bound_non_default_lane() {
        let (config, mut state, alice, bob) = installed_policy_state();
        let lane = AuthorizationLaneId::new(Hash256::digest(b"origin-lane"));
        // Open and fund the origin lane from the default lane.
        let open = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::OpenAuthorizationLane {
                lane,
                fee_deposit: Amount::from_webc(1),
            },
            small_fee_with_units(10_000),
        )
        .unwrap();
        state.execute_transaction(&open, &config).unwrap();

        // Install a session key bound to that lane.
        let session = Keypair::from_seed([9u8; 32]);
        let id = SessionKeyId::derive(&session.public_key());
        let mut constraints = session_constraints();
        constraints.authorization_lane = lane;
        let install = install_session_key_tx(&alice, &session, 2, constraints);
        state.execute_transaction(&install, &config).unwrap();

        // A session transfer on the bound lane succeeds: principal leaves the
        // owner account, the lane nonce advances, and cumulative spend updates.
        let transfer = session_transfer_tx(
            &alice,
            &session,
            lane,
            0,
            bob.address(),
            Amount::from_webc(3),
            small_fee(),
        );
        state.execute_transaction(&transfer, &config).unwrap();
        assert_eq!(
            state.accounts.get(&bob.address()).unwrap().balance,
            Amount::from_webc(3)
        );
        assert_eq!(
            state.session_keys[&(alice.address(), id)].spent_amount,
            Amount::from_webc(3)
        );
        assert_eq!(
            state.authorization_lanes[&(alice.address(), lane)].next_nonce,
            Nonce::new(1)
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn session_spend_never_exceeds_budget(
            amounts in proptest::collection::vec(1u64..8, 1..24)
        ) {
            let (config, mut state, alice, bob) = installed_policy_state();
            let session = Keypair::from_seed([9u8; 32]);
            let id = SessionKeyId::derive(&session.public_key());
            let install = install_session_key_tx(
                &alice, &session, 1, session_constraints());
            state.execute_transaction(&install, &config).unwrap();

            let per_use = Amount::from_webc(5);
            let budget = Amount::from_webc(20);
            let mut expected_spent = Amount::ZERO;
            let mut nonce = 2u64;
            for raw in amounts {
                let amount = Amount::from_webc(raw);
                let next = expected_spent.checked_add(amount).unwrap();
                let accepted = amount <= per_use && next <= budget;
                let tx = session_transfer_tx(
                    &alice, &session, AuthorizationLaneId::DEFAULT,
                    nonce, bob.address(), amount, small_fee());
                let before = state.clone();
                let result = state.execute_transaction(&tx, &config);
                if accepted {
                    prop_assert!(result.is_ok());
                    expected_spent = next;
                    nonce += 1;
                } else {
                    prop_assert!(result.is_err());
                    prop_assert_eq!(&state, &before);
                }
                prop_assert_eq!(
                    state.session_keys[&(alice.address(), id)].spent_amount,
                    expected_spent
                );
                prop_assert!(state.session_keys[&(alice.address(), id)].spent_amount <= budget);
                prop_assert!(state.supply_invariant_report().unwrap().balanced);
            }
        }
    }

    #[test]
    fn policy_installation_commits_root_and_invalidates_legacy_revision() {
        let (config, mut state, alice, bob) = funded_state();
        let root = PostQuantumRoot::new(
            PostQuantumScheme::MlDsa65,
            Hash256::digest(b"alice ML-DSA-65 candidate public key"),
        )
        .unwrap();
        let before_root = state.state_root().unwrap();
        let install = Transaction::for_operation(
            &alice,
            0,
            Operation::InstallAuthorizationPolicy {
                post_quantum_root: root,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&install, &config).unwrap();

        let policy = state
            .authorization_policies
            .get(&alice.address())
            .expect("policy committed");
        assert_eq!(policy.revision(), AuthorizationPolicyRevision::new(1));
        assert_eq!(policy.active_transaction_key(), &alice.public_key());
        assert_ne!(state.state_root().unwrap(), before_root);

        let legacy_revision = Transaction::for_operation(
            &alice,
            1,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_units(1),
            },
            FeeBid::default(),
        )
        .unwrap();
        let before_rejected = state.clone();
        assert!(matches!(
            state.execute_transaction(&legacy_revision, &config),
            Err(ChainError::AuthorizationPolicyRevisionMismatch {
                expected: 1,
                actual: 0
            })
        ));
        assert_eq!(state, before_rejected);

        let authorized = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_units(1),
            },
            FeeBid::default(),
        )
        .unwrap();
        state.execute_transaction(&authorized, &config).unwrap();
    }

    #[test]
    fn installed_policy_rejects_another_valid_signature_key_atomically() {
        let (config, mut state, alice, attacker) = funded_state();
        let root = PostQuantumRoot::new(
            PostQuantumScheme::MlDsa65,
            Hash256::digest(b"alice recovery root"),
        )
        .unwrap();
        let install = Transaction::for_operation(
            &alice,
            0,
            Operation::InstallAuthorizationPolicy {
                post_quantum_root: root,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&install, &config).unwrap();

        let operation = Operation::Transfer {
            to: attacker.address(),
            amount: Amount::from_units(1),
        };
        let access_list = operation.default_access_list(alice.address()).unwrap();
        let mut forged = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            config.chain_id.clone(),
            alice.address(),
            attacker.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(1),
            1,
            operation,
            access_list,
            FeeBid::default(),
        );
        forged.sign_with_policy_key(&attacker).unwrap();
        forged.verify().expect("signature itself is valid");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&forged, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn malformed_root_and_inexact_revision_fail_before_state_commit() {
        let (config, mut state, alice, _) = funded_state();
        let invalid_root = PostQuantumRoot {
            scheme: PostQuantumScheme::MlDsa65,
            public_key_hash: Hash256::ZERO,
        };
        let install = Transaction::for_operation(
            &alice,
            0,
            Operation::InstallAuthorizationPolicy {
                post_quantum_root: invalid_root,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        let before_root = state.clone();
        assert!(matches!(
            state.execute_transaction(&install, &config),
            Err(ChainError::InvalidPostQuantumRoot)
        ));
        assert_eq!(state, before_root);

        // An authorization revision beyond the JS-safe wire bound (which equals
        // MAX_AUTHORIZATION_POLICY_REVISION = 2^53-1) can no longer even be
        // signed: the canonical encoder rejects the out-of-range integer (X3), a
        // stricter and earlier guard than the execution-time range check. The
        // transaction therefore never becomes a valid signed payload and cannot
        // reach a state commit.
        let mut over_range = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: alice.address(),
                amount: Amount::from_units(1),
            },
            FeeBid::default(),
        )
        .unwrap();
        over_range.authorization_policy_revision =
            AuthorizationPolicyRevision::new(MAX_AUTHORIZATION_POLICY_REVISION + 1);
        assert!(matches!(
            over_range.sign(&alice),
            Err(ChainError::CanonicalIntegerOutOfSafeRange)
        ));
    }

    fn double_vote_evidence(
        validator: &Keypair,
        chain_id: ChainId,
        first_block: Hash256,
        second_block: Hash256,
    ) -> SlashingEvidence {
        double_vote_evidence_at_height(validator, chain_id, 1, first_block, second_block)
    }

    fn double_vote_evidence_at_height(
        validator: &Keypair,
        chain_id: ChainId,
        height: u64,
        first_block: Hash256,
        second_block: Hash256,
    ) -> SlashingEvidence {
        let vote = |block_hash| Vote {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            chain_id: chain_id.clone(),
            height,
            round: 0,
            vote_type: VoteType::Precommit,
            block_hash,
            validator: validator.address(),
        };
        SlashingEvidence::DoubleVote(DoubleVoteEvidence {
            first: SignedVote::sign(vote(first_block), validator).expect("first vote signs"),
            second: SignedVote::sign(vote(second_block), validator).expect("second vote signs"),
        })
    }

    fn active_delegated_state() -> (ChainConfig, ChainState, Keypair, Keypair) {
        let (config, mut state, alice, bob) = funded_state();
        let fund = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(200),
            },
            FeeBid::default(),
        )
        .expect("funding signs");
        state.execute_transaction(&fund, &config).expect("funding");
        let register = Transaction::for_operation(
            &alice,
            1,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("registration signs");
        state
            .execute_transaction(&register, &config)
            .expect("registration");
        let delegate = Transaction::for_operation(
            &bob,
            0,
            Operation::Delegate {
                validator: alice.address(),
                amount: Amount::from_webc(80),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("delegation signs");
        state
            .execute_transaction(&delegate, &config)
            .expect("delegation");
        (config, state, alice, bob)
    }

    fn randomized_staking_state() -> (ChainConfig, ChainState, Keypair, [Keypair; 2]) {
        let mut config = ChainConfig::default();
        // Short test-only epochs expose queue admission, partial churn, maturity,
        // and claims inside each generated operation sequence.
        config.staking.unbonding_cooldown_epochs = 2;
        config.staking.slashable_unbonding_epochs = 2;
        config.staking.max_unbonding_units_per_epoch = Amount::from_webc(30);

        let operator = Keypair::from_seed([31u8; 32]);
        let delegators = [
            Keypair::from_seed([32u8; 32]),
            Keypair::from_seed([33u8; 32]),
        ];
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![
                GenesisAccount {
                    address: operator.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: delegators[0].address(),
                    balance: Amount::from_webc(500),
                },
                GenesisAccount {
                    address: delegators[1].address(),
                    balance: Amount::from_webc(500),
                },
            ],
            validators: Vec::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).expect("property genesis");
        let register = Transaction::for_operation(
            &operator,
            0,
            Operation::RegisterValidator {
                consensus_key: operator.public_key(),
                self_stake: Amount::from_webc(100),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("property registration signs");
        state
            .execute_transaction(&register, &config)
            .expect("property validator registration");
        (config, state, operator, delegators)
    }

    fn checked_test_sum(values: impl Iterator<Item = Amount>) -> Amount {
        values.fold(Amount::ZERO, |total, value| {
            total.checked_add(value).expect("test amount sum")
        })
    }

    fn assert_staking_invariants(state: &ChainState, config: &ChainConfig) {
        for (address, account) in &state.accounts {
            let expected_staked = state
                .validators
                .get(address)
                .map_or(Amount::ZERO, |validator| validator.self_stake);
            assert_eq!(account.staked, expected_staked, "operator mirror mismatch");

            let expected_delegated = checked_test_sum(
                state
                    .delegations
                    .values()
                    .filter(|delegation| delegation.delegator == *address)
                    .map(|delegation| delegation.amount),
            );
            assert_eq!(
                account.delegated, expected_delegated,
                "delegator mirror mismatch"
            );

            let expected_unbonding = checked_test_sum(
                state
                    .unbonding
                    .requests()
                    .filter(|request| request.owner == *address)
                    .map(|request| {
                        checked_test_sum(request.cooling.iter().map(|tranche| tranche.amount))
                            .checked_add(request.withdrawable)
                            .expect("test locked principal sum")
                    }),
            );
            assert_eq!(
                account.unbonding, expected_unbonding,
                "cooling/withdrawable mirror mismatch"
            );
        }

        for (operator, validator) in &state.validators {
            let expected_delegated = checked_test_sum(
                state
                    .delegations
                    .values()
                    .filter(|delegation| delegation.validator == *operator)
                    .map(|delegation| delegation.amount),
            );
            assert_eq!(
                validator.delegated_stake, expected_delegated,
                "validator delegation aggregate mismatch"
            );

            if validator.status == ValidatorStatus::Active {
                let total = validator.total_stake().expect("active total stake");
                let maximum_delegated = validator
                    .self_stake
                    .checked_mul_u64(4)
                    .expect("active ratio capacity");
                assert!(validator.self_stake >= config.staking.min_validator_self_stake);
                assert!(total >= config.staking.min_validator_total_stake);
                assert!(validator.delegated_stake <= maximum_delegated);
            }

            let queued_operator = state
                .unbonding
                .queued_for(*operator, *operator, UnbondingKind::OperatorStake)
                .expect("queued operator total");
            assert!(queued_operator <= validator.self_stake);
        }

        for ((delegator, validator), delegation) in &state.delegations {
            let queued = state
                .unbonding
                .queued_for(*delegator, *validator, UnbondingKind::Delegation)
                .expect("queued delegation total");
            assert!(queued <= delegation.amount);
        }

        assert!(
            state
                .supply_invariant_report()
                .expect("property supply report")
                .balanced,
            "native supply buckets must reconcile after every step"
        );
    }

    fn execute_with_rollback_check(
        state: &mut ChainState,
        config: &ChainConfig,
        transaction: &Transaction,
    ) {
        let before = state.clone();
        if state.execute_transaction(transaction, config).is_err() {
            assert_eq!(*state, before, "failed transaction mutated chain state");
        }
    }

    fn property_transaction(
        state: &ChainState,
        signer: &Keypair,
        operation: Operation,
    ) -> Transaction {
        let nonce = state
            .accounts
            .get(&signer.address())
            .expect("property signer account")
            .nonce;
        Transaction::for_operation(
            signer,
            nonce,
            operation,
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("property transaction signs")
    }

    fn property_slash_transaction(
        state: &ChainState,
        config: &ChainConfig,
        operator: &Keypair,
        height: u64,
        entropy: u8,
    ) -> Transaction {
        let evidence = double_vote_evidence_at_height(
            operator,
            config.chain_id.clone(),
            height,
            Hash256::digest([entropy, 0]),
            Hash256::digest([entropy, 1]),
        );
        let mut transaction = property_transaction(
            state,
            operator,
            Operation::SubmitSlashingEvidence { evidence },
        );

        let mut declare_write = |key: StateKey| {
            if !transaction.access_list.read_write.contains(&key) {
                transaction.access_list.read_write.push(key);
            }
        };
        for delegation in state.delegations.values().filter(|delegation| {
            delegation.validator == operator.address()
                && delegation
                    .amount
                    .checked_mul_bps(config.slashing.double_sign_bps)
                    .is_some_and(|loss| !loss.is_zero())
        }) {
            declare_write(StateKey::delegation(
                delegation.delegator,
                delegation.validator,
            ));
            declare_write(StateKey::account(delegation.delegator));
        }
        for request in state.unbonding.requests().filter(|request| {
            request.validator == operator.address()
                && (request.cooling.iter().any(|tranche| {
                    tranche
                        .amount
                        .checked_mul_bps(config.slashing.double_sign_bps)
                        .is_some_and(|loss| !loss.is_zero())
                }) || request
                    .withdrawable
                    .checked_mul_bps(config.slashing.double_sign_bps)
                    .is_some_and(|loss| !loss.is_zero()))
        }) {
            declare_write(StateKey::account(request.owner));
        }
        transaction
            .sign(operator)
            .expect("expanded property slash signs");
        transaction
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Generated operation streams exercise success, rejection, rollback,
        /// epoch admission, reward, slash, maturity, and claim interleavings.
        #[test]
        fn arbitrary_stake_sequences_preserve_all_accounting_mirrors(
            actions in prop::collection::vec((any::<u8>(), any::<u8>()), 1..128)
        ) {
            let (config, mut state, operator, delegators) = randomized_staking_state();
            assert_staking_invariants(&state, &config);

            for (step, (selector, entropy)) in actions.into_iter().enumerate() {
                let delegator = &delegators[usize::from(selector & 1)];
                let amount = Amount::from_webc(u64::from(entropy % 40) + 1);
                match selector % 8 {
                    0 => {
                        let transaction = property_transaction(
                            &state,
                            delegator,
                            Operation::Delegate {
                                validator: operator.address(),
                                amount,
                            },
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    1 => {
                        let transaction = property_transaction(
                            &state,
                            delegator,
                            Operation::Undelegate {
                                validator: operator.address(),
                                amount,
                            },
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    2 => {
                        state
                            .distribute_epoch_rewards(&config)
                            .expect("property epoch transition");
                    }
                    3 => {
                        let transaction = property_transaction(
                            &state,
                            delegator,
                            Operation::ClaimUnbonded {
                                validator: operator.address(),
                                request_id: UnbondingRequestId::new(u64::from(entropy % 32)),
                            },
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    4 => {
                        let transaction = property_transaction(
                            &state,
                            &operator,
                            Operation::UnstakeValidator { amount },
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    5 => {
                        let transaction = property_transaction(
                            &state,
                            delegator,
                            Operation::ClaimDelegatorRewards {
                                validator: operator.address(),
                            },
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    6 => {
                        let transaction = property_transaction(
                            &state,
                            &operator,
                            Operation::ClaimValidatorRewards,
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                    _ => {
                        let height = u64::try_from(step)
                            .expect("property sequence length fits u64")
                            .checked_add(1)
                            .expect("property height");
                        let transaction = property_slash_transaction(
                            &state,
                            &config,
                            &operator,
                            height,
                            entropy,
                        );
                        execute_with_rollback_check(&mut state, &config, &transaction);
                    }
                }
                assert_staking_invariants(&state, &config);
            }
        }
    }

    #[test]
    fn transfer_updates_balances_and_splits_fee() {
        let (config, mut state, alice, bob) = funded_state();
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();

        let receipt = state.execute_transaction(&tx, &config).unwrap();
        assert!(receipt.success);
        assert_eq!(
            state.accounts.get(&bob.address()).unwrap().balance,
            Amount::from_webc(10)
        );
        assert_eq!(state.burned_fees.0 + state.validator_fee_pool.0, 500);
    }

    #[test]
    fn undeclared_write_rejects_and_rolls_back_transaction() {
        let (config, mut state, alice, bob) = funded_state();
        let mut tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .expect("default transfer is valid");
        tx.access_list
            .read_write
            .retain(|key| key != &StateKey::account(bob.address()));
        tx.sign(&alice).expect("modified declaration is signed");
        let before = state.clone();

        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::UndeclaredStateWrite { key })
                if key == StateKey::account(bob.address())
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn undeclared_read_rejects_before_fee_state_changes() {
        let (config, mut state, alice, bob) = funded_state();
        let mut tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .expect("default transfer is valid");
        tx.access_list.read_only.clear();
        tx.sign(&alice).expect("modified declaration is signed");
        let before = state.clone();

        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::UndeclaredStateRead { key })
                if key == StateKey::authorization_policy(alice.address())
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn read_only_key_cannot_be_written_and_rolls_back_transaction() {
        let (config, mut state, alice, bob) = funded_state();
        let recipient_key = StateKey::account(bob.address());
        let mut tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .expect("default transfer is valid");
        tx.access_list
            .read_write
            .retain(|key| key != &recipient_key);
        tx.access_list.read_only.push(recipient_key.clone());
        tx.access_list.read_only.sort();
        tx.sign(&alice).expect("modified declaration is signed");
        let before = state.clone();

        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::UndeclaredStateWrite { key }) if key == recipient_key
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn unused_declared_key_rejects_and_rolls_back_transaction() {
        let (config, mut state, alice, bob) = funded_state();
        let unrelated = StateKey::application(
            Hash256::digest(b"unrelated-site"),
            Hash256::digest(b"unused-key"),
        );
        let mut tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .expect("default transfer is valid");
        tx.access_list.read_write.push(unrelated);
        tx.access_list.read_write.sort();
        tx.sign(&alice).expect("modified declaration is signed");
        let before = state.clone();

        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::UnusedDeclaredStateAccess)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn genesis_stake_is_debited_and_supply_reconciles() {
        let config = ChainConfig::default();
        let operator = Keypair::from_seed([41u8; 32]);
        let genesis = GenesisConfig {
            chain: config,
            accounts: vec![GenesisAccount {
                address: operator.address(),
                balance: Amount::from_webc(100),
            }],
            validators: vec![GenesisValidator {
                operator: operator.address(),
                consensus_key: PublicKeyBytes([7u8; 32]),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            }],
        };
        let state = ChainState::from_genesis(&genesis).expect("valid staked genesis");
        let account = state
            .accounts
            .get(&operator.address())
            .expect("operator account");
        assert_eq!(account.balance, Amount::from_webc(80));
        assert_eq!(account.staked, Amount::from_webc(20));
        let report = state.supply_invariant_report().expect("checked report");
        assert!(report.balanced);
        assert_eq!(report.issued, Amount::from_webc(100));
    }

    #[test]
    fn duplicate_genesis_accounts_are_rejected() {
        let config = ChainConfig::default();
        let account = Keypair::from_seed([42u8; 32]).address();
        let genesis = GenesisConfig {
            chain: config,
            accounts: vec![
                GenesisAccount {
                    address: account,
                    balance: Amount::from_webc(1),
                },
                GenesisAccount {
                    address: account,
                    balance: Amount::from_webc(1),
                },
            ],
            validators: Vec::new(),
        };
        assert!(matches!(
            ChainState::from_genesis(&genesis),
            Err(ChainError::DuplicateGenesisAccount(duplicate)) if duplicate == account
        ));
    }

    #[test]
    fn invalid_nonce_does_not_mutate_state() {
        let (config, mut state, alice, bob) = funded_state();
        let before = state.clone();
        let tx = Transaction::for_operation(
            &alice,
            7,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .unwrap();
        assert!(state.execute_transaction(&tx, &config).is_err());
        assert_eq!(state, before);
    }

    #[test]
    fn transaction_protocol_and_chain_context_prevent_replay() {
        let (config, mut state, alice, bob) = funded_state();
        let operation = Operation::Transfer {
            to: bob.address(),
            amount: Amount::from_webc(1),
        };
        let other_chain = Transaction::for_operation_on_chain(
            &alice,
            config.protocol_version,
            ChainId::new("webc-other-1").expect("valid alternate chain"),
            0,
            operation.clone(),
            FeeBid::default(),
        )
        .expect("alternate-chain transaction signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&other_chain, &config),
            Err(ChainError::TransactionChainIdMismatch)
        ));
        assert_eq!(state, before);

        let other_protocol = Transaction::for_operation_on_chain(
            &alice,
            ProtocolVersion::new(2),
            config.chain_id.clone(),
            0,
            operation,
            FeeBid::default(),
        )
        .expect("future-version transaction can be encoded");
        assert!(matches!(
            state.execute_transaction(&other_protocol, &config),
            Err(ChainError::UnsupportedProtocolVersion { actual })
                if actual == ProtocolVersion::new(2)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn unsupported_protocol_version_cannot_create_state() {
        let config = ChainConfig {
            protocol_version: ProtocolVersion::new(2),
            ..ChainConfig::default()
        };
        assert!(matches!(
            ChainState::new(&config),
            Err(ChainError::UnsupportedProtocolVersion { actual })
                if actual == ProtocolVersion::new(2)
        ));
    }

    #[test]
    fn bootstrap_validator_registration_is_rejected() {
        let (config, mut state, alice, _) = funded_state();
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: true,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::BootstrapDisabled)
        ));
        assert!(!state.validators.contains_key(&alice.address()));
    }

    #[test]
    fn slashing_evidence_replay_is_rejected() {
        let (config, mut state, alice, _) = funded_state();
        let register_validator = Transaction::for_operation(
            &alice,
            0,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state
            .execute_transaction(&register_validator, &config)
            .unwrap();

        let evidence = double_vote_evidence(
            &alice,
            config.chain_id.clone(),
            Hash256::digest(b"block-a"),
            Hash256::digest(b"block-b"),
        );
        let reversed = match evidence.clone() {
            SlashingEvidence::DoubleVote(pair) => {
                SlashingEvidence::DoubleVote(DoubleVoteEvidence {
                    first: pair.second,
                    second: pair.first,
                })
            }
        };
        let slash = Transaction::for_operation(
            &alice,
            1,
            Operation::SubmitSlashingEvidence {
                evidence: evidence.clone(),
            },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&slash, &config).unwrap();

        let replay = Transaction::for_operation(
            &alice,
            2,
            Operation::SubmitSlashingEvidence { evidence: reversed },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            state.execute_transaction(&replay, &config),
            Err(ChainError::SlashingReplay)
        ));
    }

    #[test]
    fn forged_and_cross_chain_slashing_evidence_rolls_back() {
        let (config, mut state, alice, bob) = funded_state();
        let register_validator = Transaction::for_operation(
            &alice,
            0,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("registration signs");
        state
            .execute_transaction(&register_validator, &config)
            .expect("registration succeeds");

        let forged = double_vote_evidence(
            &bob,
            config.chain_id.clone(),
            Hash256::digest(b"forged-a"),
            Hash256::digest(b"forged-b"),
        );
        let forged = match forged {
            SlashingEvidence::DoubleVote(mut pair) => {
                pair.first.payload.validator = alice.address();
                pair.second.payload.validator = alice.address();
                SlashingEvidence::DoubleVote(pair)
            }
        };
        let forged_tx = Transaction::for_operation(
            &alice,
            1,
            Operation::SubmitSlashingEvidence { evidence: forged },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("submission signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&forged_tx, &config),
            Err(ChainError::InvalidSlashingEvidence)
        ));
        assert_eq!(state, before);

        let wrong_chain = double_vote_evidence(
            &alice,
            ChainId::new("webc-other-1").expect("valid alternate chain ID"),
            Hash256::digest(b"other-a"),
            Hash256::digest(b"other-b"),
        );
        let wrong_chain_tx = Transaction::for_operation(
            &alice,
            1,
            Operation::SubmitSlashingEvidence {
                evidence: wrong_chain,
            },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("submission signs");
        assert!(matches!(
            state.execute_transaction(&wrong_chain_tx, &config),
            Err(ChainError::InvalidSlashingEvidence)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn invalid_slashing_evidence_is_rejected() {
        let (config, mut state, alice, _) = funded_state();
        let register_validator = Transaction::for_operation(
            &alice,
            0,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state
            .execute_transaction(&register_validator, &config)
            .unwrap();

        let invalid = double_vote_evidence(
            &alice,
            config.chain_id.clone(),
            Hash256::digest(b"same-block"),
            Hash256::digest(b"same-block"),
        );
        let tx = Transaction::for_operation(
            &alice,
            1,
            Operation::SubmitSlashingEvidence { evidence: invalid },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::InvalidSlashingEvidence)
        ));
    }

    #[test]
    fn slashing_reconciles_operator_delegator_and_supply_buckets() {
        let (config, mut state, alice, bob) = funded_state();
        let fund_bob = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(200),
            },
            FeeBid::default(),
        )
        .expect("funding transfer signs");
        state
            .execute_transaction(&fund_bob, &config)
            .expect("funding succeeds");
        let register = Transaction::for_operation(
            &alice,
            1,
            Operation::RegisterValidator {
                consensus_key: alice.public_key(),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("registration signs");
        state
            .execute_transaction(&register, &config)
            .expect("registration succeeds");
        let delegate = Transaction::for_operation(
            &bob,
            0,
            Operation::Delegate {
                validator: alice.address(),
                amount: Amount::from_webc(80),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("delegation signs");
        state
            .execute_transaction(&delegate, &config)
            .expect("delegation succeeds");

        let evidence = double_vote_evidence(
            &alice,
            config.chain_id.clone(),
            Hash256::digest(b"slash-a"),
            Hash256::digest(b"slash-b"),
        );
        let mut slash = Transaction::for_operation(
            &alice,
            2,
            Operation::SubmitSlashingEvidence { evidence },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("slash submission signs");
        slash
            .access_list
            .read_write
            .push(StateKey::delegation(bob.address(), alice.address()));
        slash
            .access_list
            .read_write
            .push(StateKey::account(bob.address()));
        slash.sign(&alice).expect("expanded access list signs");
        state
            .execute_transaction(&slash, &config)
            .expect("verified slash succeeds");

        let validator = state
            .validators
            .get(&alice.address())
            .expect("validator remains tombstoned");
        assert_eq!(validator.self_stake, Amount::from_webc(4));
        assert_eq!(validator.delegated_stake, Amount::from_webc(16));
        assert_eq!(
            state
                .accounts
                .get(&alice.address())
                .expect("operator")
                .staked,
            Amount::from_webc(4)
        );
        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("delegator")
                .delegated,
            Amount::from_webc(16)
        );
        assert_eq!(
            state
                .delegations
                .get(&(bob.address(), alice.address()))
                .expect("position")
                .amount,
            Amount::from_webc(16)
        );
        assert_eq!(state.slashed_units, Amount::from_webc(80));
        assert!(
            state
                .supply_invariant_report()
                .expect("checked supply report")
                .balanced
        );
    }

    #[test]
    fn unbonding_request_preserves_snapshot_then_matures_and_claims() {
        let (config, mut state, alice, bob) = active_delegated_state();
        let request = Transaction::for_operation(
            &bob,
            1,
            Operation::Undelegate {
                validator: alice.address(),
                amount: Amount::from_webc(80),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("request signs");
        let receipt = state
            .execute_transaction(&request, &config)
            .expect("request succeeds");
        let request_id = receipt
            .events
            .iter()
            .find_map(|event| match event {
                Event::UnbondingRequested { request_id, .. } => Some(*request_id),
                _ => None,
            })
            .expect("request event");

        assert_eq!(
            state
                .validators
                .get(&alice.address())
                .expect("validator")
                .delegated_stake,
            Amount::from_webc(80)
        );
        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("delegator")
                .unbonding,
            Amount::ZERO
        );

        state
            .distribute_epoch_rewards(&config)
            .expect("epoch admission");
        assert_eq!(state.current_epoch, 1);
        assert_eq!(
            state
                .validators
                .get(&alice.address())
                .expect("validator")
                .delegated_stake,
            Amount::ZERO
        );
        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("delegator")
                .unbonding,
            Amount::from_webc(80)
        );
        assert_eq!(
            state
                .validators
                .get(&alice.address())
                .expect("validator")
                .status,
            ValidatorStatus::Draining
        );

        assert!(
            state
                .delegations
                .get(&(bob.address(), alice.address()))
                .expect("position retained for rewards")
                .accumulated_rewards
                > Amount::ZERO
        );
        let reward_claim = Transaction::for_operation(
            &bob,
            2,
            Operation::ClaimDelegatorRewards {
                validator: alice.address(),
            },
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("reward claim signs");
        state
            .execute_transaction(&reward_claim, &config)
            .expect("earned rewards survive full exit admission");

        let early_claim = Transaction::for_operation(
            &bob,
            3,
            Operation::ClaimUnbonded {
                validator: alice.address(),
                request_id,
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("claim signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&early_claim, &config),
            Err(ChainError::UnbondingNotWithdrawable)
        ));
        assert_eq!(state, before);

        while state.current_epoch < 9 {
            state
                .distribute_epoch_rewards(&config)
                .expect("deterministic epoch advance");
        }
        state
            .execute_transaction(&early_claim, &config)
            .expect("mature claim succeeds");
        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("delegator")
                .unbonding,
            Amount::ZERO
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("supply report")
                .balanced
        );
    }

    #[test]
    fn cooling_principal_is_slashed_before_release() {
        let (config, mut state, alice, bob) = active_delegated_state();
        let request = Transaction::for_operation(
            &bob,
            1,
            Operation::Undelegate {
                validator: alice.address(),
                amount: Amount::from_webc(80),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("request signs");
        state
            .execute_transaction(&request, &config)
            .expect("request");
        state
            .distribute_epoch_rewards(&config)
            .expect("admit to cooldown");

        let evidence = double_vote_evidence(
            &alice,
            config.chain_id.clone(),
            Hash256::digest(b"cooling-slash-a"),
            Hash256::digest(b"cooling-slash-b"),
        );
        let mut slash = Transaction::for_operation(
            &alice,
            2,
            Operation::SubmitSlashingEvidence { evidence },
            FeeBid {
                gas_limit: 25_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("slash signs");
        slash
            .access_list
            .read_write
            .push(StateKey::account(bob.address()));
        slash.sign(&alice).expect("expanded slash signs");
        state
            .execute_transaction(&slash, &config)
            .expect("cooling slash");

        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("delegator")
                .unbonding,
            Amount::from_webc(16)
        );
        assert_eq!(state.slashed_units, Amount::from_webc(80));
        assert!(
            state
                .supply_invariant_report()
                .expect("supply report")
                .balanced
        );
    }

    #[test]
    fn operator_exit_is_delayed_and_cannot_abandon_delegators() {
        let (config, mut delegated_state, delegated_operator, _) = active_delegated_state();
        let blocked = Transaction::for_operation(
            &delegated_operator,
            2,
            Operation::UnstakeValidator {
                amount: Amount::from_webc(20),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("operator request signs");
        let before = delegated_state.clone();
        assert!(matches!(
            delegated_state.execute_transaction(&blocked, &config),
            Err(ChainError::OperatorExitHasDelegations)
        ));
        assert_eq!(delegated_state, before);

        let (config, mut state, operator, prospective_delegator) = funded_state();
        let register = Transaction::for_operation(
            &operator,
            0,
            Operation::RegisterValidator {
                consensus_key: operator.public_key(),
                self_stake: Amount::from_webc(100),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("registration signs");
        state
            .execute_transaction(&register, &config)
            .expect("operator-only pool activates");
        let current_epoch_snapshot = ValidatorSet::from_state(&state).expect("snapshot");
        let exit = Transaction::for_operation(
            &operator,
            1,
            Operation::UnstakeValidator {
                amount: Amount::from_webc(100),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("full exit signs");
        state
            .execute_transaction(&exit, &config)
            .expect("full exit queues");
        assert_eq!(
            ValidatorSet::from_state(&state).expect("same-epoch snapshot"),
            current_epoch_snapshot,
            "exit request must not change current-epoch voting power"
        );
        let fund_delegator = Transaction::for_operation(
            &operator,
            2,
            Operation::Transfer {
                to: prospective_delegator.address(),
                amount: Amount::from_webc(2),
            },
            FeeBid::default(),
        )
        .expect("funding signs");
        state
            .execute_transaction(&fund_delegator, &config)
            .expect("prospective delegator funded");
        let late_delegation = Transaction::for_operation(
            &prospective_delegator,
            0,
            Operation::Delegate {
                validator: operator.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("late delegation signs");
        let before_late_delegation = state.clone();
        assert!(matches!(
            state.execute_transaction(&late_delegation, &config),
            Err(ChainError::DelegationRatioExceeded)
        ));
        assert_eq!(state, before_late_delegation);
        assert_eq!(
            state
                .validators
                .get(&operator.address())
                .expect("validator")
                .self_stake,
            Amount::from_webc(100)
        );
        state
            .distribute_epoch_rewards(&config)
            .expect("snapshot transition");
        assert_eq!(
            ValidatorSet::from_state(&state)
                .expect("next snapshot")
                .power_of(operator.address()),
            Amount::ZERO
        );
        assert_eq!(
            state
                .validators
                .get(&operator.address())
                .expect("validator")
                .status,
            ValidatorStatus::Draining
        );
        assert_eq!(
            state
                .accounts
                .get(&operator.address())
                .expect("operator")
                .unbonding,
            Amount::from_webc(100)
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("supply report")
                .balanced
        );
    }

    #[test]
    fn non_default_lane_uses_independent_nonce_and_prepaid_fees() {
        let (config, mut state, validator, delegator) = active_delegated_state();
        let lane_id = AuthorizationLaneId::new(Hash256::digest(b"site-a-lane"));
        let open = Transaction::for_operation(
            &delegator,
            1,
            Operation::OpenAuthorizationLane {
                lane: lane_id,
                fee_deposit: Amount::from_webc(1),
            },
            FeeBid {
                gas_limit: 20_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("lane opening signs");
        state
            .execute_transaction(&open, &config)
            .expect("lane opens from default account");
        let default_nonce_after_open = state
            .accounts
            .get(&delegator.address())
            .expect("delegator")
            .nonce;
        assert_eq!(default_nonce_after_open, 2);

        let exit = Transaction::for_operation_in_lane(
            &delegator,
            lane_id,
            0,
            Operation::Undelegate {
                validator: validator.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid {
                gas_limit: 20_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("lane transaction signs");
        state
            .execute_transaction(&exit, &config)
            .expect("lane pays its own fee and nonce");
        let lane = state
            .authorization_lanes
            .get(&(delegator.address(), lane_id))
            .expect("lane persists");
        assert_eq!(lane.next_nonce, Nonce::new(1));
        assert_eq!(
            lane.fee_balance,
            Amount::from_webc(1)
                .checked_sub(Amount::from_units(10_000))
                .expect("test fee fits")
        );
        assert_eq!(
            state
                .accounts
                .get(&delegator.address())
                .expect("delegator")
                .nonce,
            default_nonce_after_open
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("lane report")
                .balanced
        );

        let replay_before = state.clone();
        assert!(matches!(
            state.execute_transaction(&exit, &config),
            Err(ChainError::NonceMismatch { .. })
        ));
        assert_eq!(state, replay_before);
    }

    #[test]
    fn owned_object_lifecycle_enforces_namespace_owner_version_and_size() {
        let (config, mut state, alice, bob) = funded_state();
        let lane_id = AuthorizationLaneId::new(Hash256::digest(b"object-site-lane"));
        let namespace = Hash256::digest(b"object-site");
        let object_id = ObjectId::new(Hash256::digest(b"object-1"));
        let open = Transaction::for_operation(
            &alice,
            0,
            Operation::OpenAuthorizationLane {
                lane: lane_id,
                fee_deposit: Amount::from_webc(1),
            },
            FeeBid {
                gas_limit: 20_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("object lane opens");
        state
            .execute_transaction(&open, &config)
            .expect("object lane funded");

        let create = Transaction::for_operation_in_lane(
            &alice,
            lane_id,
            0,
            Operation::CreateObject {
                object_id,
                namespace,
                data: b"v1".to_vec(),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("create signs");
        state
            .execute_transaction(&create, &config)
            .expect("object created");
        assert_eq!(
            state.objects.get(&object_id).expect("object").version,
            ObjectVersion::INITIAL
        );

        let mutate = Transaction::for_operation_in_lane(
            &alice,
            lane_id,
            1,
            Operation::MutateObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::INITIAL,
                data: b"v2".to_vec(),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("mutation signs");
        state
            .execute_transaction(&mutate, &config)
            .expect("owned mutation succeeds");
        assert_eq!(
            state.objects.get(&object_id).expect("object").version,
            ObjectVersion::new(2)
        );

        let stale = Transaction::for_operation_in_lane(
            &alice,
            lane_id,
            2,
            Operation::MutateObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::INITIAL,
                data: b"stale".to_vec(),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("stale mutation signs");
        let before_stale = state.clone();
        assert!(matches!(
            state.execute_transaction(&stale, &config),
            Err(ChainError::ObjectVersionMismatch { .. })
        ));
        assert_eq!(state, before_stale);

        let transfer = Transaction::for_operation_in_lane(
            &alice,
            lane_id,
            2,
            Operation::TransferObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::new(2),
                new_owner: bob.address(),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("transfer signs");
        state
            .execute_transaction(&transfer, &config)
            .expect("owned transfer succeeds");
        let object = state.objects.get(&object_id).expect("object");
        assert_eq!(object.version, ObjectVersion::new(3));
        assert_eq!(object.owner, ObjectOwner::Address(bob.address()));

        let oversized_id = ObjectId::new(Hash256::digest(b"oversized"));
        let oversized = Transaction::for_operation_in_lane(
            &alice,
            lane_id,
            3,
            Operation::CreateObject {
                object_id: oversized_id,
                namespace,
                data: vec![0u8; crate::MAX_OBJECT_DATA_BYTES + 1],
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("oversized object signs");
        let before_oversized = state.clone();
        assert!(matches!(
            state.execute_transaction(&oversized, &config),
            Err(ChainError::ObjectDataTooLarge { .. })
        ));
        assert_eq!(state, before_oversized);
        assert!(
            state
                .supply_invariant_report()
                .expect("object report")
                .balanced
        );
    }

    #[test]
    fn storage_deposit_locks_on_create_resizes_on_mutate_and_refunds_on_delete() {
        // §15.22: writing object state locks a refundable native deposit
        // proportional to stored bytes; deleting refunds the majority and burns
        // the occupancy remainder. Supply must reconcile at every step.
        let (config, mut state, alice, _bob) = funded_state();
        let namespace = Hash256::digest(b"deposit-ns");
        let object_id = ObjectId::new(Hash256::digest(b"deposit-obj"));
        let per_byte = config.storage_pricing.deposit_per_byte;
        assert!(per_byte > 0, "default pricing must lock a real deposit");
        let deposit_for = |len: usize| Amount::from_units(u128::from(per_byte) * len as u128);
        let issued = state.minted_supply;
        let assert_balanced = |s: &ChainState| {
            assert!(
                s.supply_invariant_report().expect("report").balanced,
                "supply must reconcile"
            );
        };

        let fee = FeeBid {
            gas_limit: 30_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        };

        // --- Create: liquid -> storage_deposits ---
        let liquid_before = state.accounts[&alice.address()].balance;
        let create = Transaction::for_operation(
            &alice,
            0,
            Operation::CreateObject {
                object_id,
                namespace,
                data: vec![0u8; 10],
            },
            fee,
        )
        .expect("create signs");
        let create_fee = Amount::from_units(u128::from(create.required_units())); // base fee 1/unit
        state
            .execute_transaction(&create, &config)
            .expect("object created");
        assert_eq!(state.storage_deposits, deposit_for(10));
        assert_eq!(state.objects[&object_id].deposit, deposit_for(10));
        assert_eq!(
            state.accounts[&alice.address()].balance,
            liquid_before
                .checked_sub(create_fee)
                .and_then(|b| b.checked_sub(deposit_for(10)))
                .unwrap(),
            "create must debit both the fee and the storage deposit"
        );
        assert_eq!(state.minted_supply, issued, "create mints no supply");
        assert_balanced(&state);

        // --- Mutate grow: 10 -> 30 bytes locks the extra ---
        let liquid_before = state.accounts[&alice.address()].balance;
        let grow = Transaction::for_operation(
            &alice,
            1,
            Operation::MutateObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::INITIAL,
                data: vec![0u8; 30],
            },
            fee,
        )
        .expect("grow signs");
        let grow_fee = Amount::from_units(u128::from(grow.required_units()));
        state.execute_transaction(&grow, &config).expect("grew");
        assert_eq!(state.storage_deposits, deposit_for(30));
        assert_eq!(state.objects[&object_id].deposit, deposit_for(30));
        let extra = deposit_for(30).checked_sub(deposit_for(10)).unwrap();
        assert_eq!(
            state.accounts[&alice.address()].balance,
            liquid_before
                .checked_sub(grow_fee)
                .and_then(|b| b.checked_sub(extra))
                .unwrap(),
        );
        assert_balanced(&state);

        // --- Mutate shrink: 30 -> 5 bytes refunds the difference ---
        let liquid_before = state.accounts[&alice.address()].balance;
        let shrink = Transaction::for_operation(
            &alice,
            2,
            Operation::MutateObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::new(2),
                data: vec![0u8; 5],
            },
            fee,
        )
        .expect("shrink signs");
        let shrink_fee = Amount::from_units(u128::from(shrink.required_units()));
        state.execute_transaction(&shrink, &config).expect("shrank");
        assert_eq!(state.storage_deposits, deposit_for(5));
        assert_eq!(state.objects[&object_id].deposit, deposit_for(5));
        let refunded = deposit_for(30).checked_sub(deposit_for(5)).unwrap();
        assert_eq!(
            state.accounts[&alice.address()].balance,
            liquid_before
                .checked_sub(shrink_fee)
                .and_then(|b| b.checked_add(refunded))
                .unwrap(),
        );
        assert_balanced(&state);

        // --- Delete: storage_deposits -> refund + burned ---
        let liquid_before = state.accounts[&alice.address()].balance;
        let burned_before = state.burned_fees;
        let split = config
            .storage_pricing
            .refund_split(deposit_for(5))
            .expect("split");
        assert_eq!(
            split.refund.checked_add(split.burned).unwrap(),
            deposit_for(5)
        );
        assert!(
            !split.burned.is_zero(),
            "occupancy fee must burn a remainder"
        );
        let delete = Transaction::for_operation(
            &alice,
            3,
            Operation::DeleteObject {
                object_id,
                namespace,
                expected_version: ObjectVersion::new(3),
            },
            fee,
        )
        .expect("delete signs");
        let delete_fee = Amount::from_units(u128::from(delete.required_units()));
        let receipt = state
            .execute_transaction(&delete, &config)
            .expect("deleted");
        assert!(!state.objects.contains_key(&object_id), "object removed");
        assert_eq!(state.storage_deposits, Amount::ZERO);
        assert!(receipt.events.iter().any(|event| matches!(
            event,
            Event::ObjectDeleted { refund, burned, .. }
                if *refund == split.refund && *burned == split.burned
        )));
        // The delete fee burns half its fee too, so account for both burn sources.
        let delete_fee_burn = split_fee(delete_fee).burned;
        assert_eq!(
            state.burned_fees,
            burned_before
                .checked_add(split.burned)
                .and_then(|b| b.checked_add(delete_fee_burn))
                .unwrap(),
            "deletion burns the occupancy remainder plus the fee burn"
        );
        assert_eq!(
            state.accounts[&alice.address()].balance,
            liquid_before
                .checked_sub(delete_fee)
                .and_then(|b| b.checked_add(split.refund))
                .unwrap(),
            "owner is refunded the majority of the deposit"
        );
        assert_eq!(state.minted_supply, issued, "delete mints no supply");
        assert_balanced(&state);
    }

    #[test]
    fn insufficient_balance_storage_deposit_create_fails_closed() {
        // A creator who cannot afford the storage deposit fails closed and leaves
        // no partial object or deposit behind (the whole transaction rolls back).
        let (config, mut state, alice, bob) = funded_state();
        // Fund bob with just enough for one fee but far less than a big deposit.
        let seed = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_units(30_000),
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("seed signs");
        state
            .execute_transaction(&seed, &config)
            .expect("bob funded");

        let namespace = Hash256::digest(b"poor-ns");
        let object_id = ObjectId::new(Hash256::digest(b"poor-obj"));
        // Deposit for 100 bytes = 100_000 base units, above bob's post-fee balance.
        let create = Transaction::for_operation(
            &bob,
            0,
            Operation::CreateObject {
                object_id,
                namespace,
                data: vec![0u8; 100],
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("create signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&create, &config),
            Err(ChainError::InsufficientBalance { .. })
        ));
        assert_eq!(state, before, "failed create leaves no partial state");
        assert!(!state.objects.contains_key(&object_id));
        assert_eq!(state.storage_deposits, Amount::ZERO);
        assert!(state.supply_invariant_report().expect("report").balanced);
    }

    #[test]
    fn storage_deposits_survive_bincode_restart_with_stable_state_root() {
        // A crash-restart (bincode round-trip of the whole state) must preserve
        // the locked storage deposits and the committed state root, so a node
        // cannot silently diverge on the new bucket after reloading from disk.
        let (config, mut state, alice, _bob) = funded_state();
        let namespace = Hash256::digest(b"restart-ns");
        let object_id = ObjectId::new(Hash256::digest(b"restart-obj"));
        let create = Transaction::for_operation(
            &alice,
            0,
            Operation::CreateObject {
                object_id,
                namespace,
                data: vec![7u8; 42],
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("create signs");
        state
            .execute_transaction(&create, &config)
            .expect("created");
        assert!(!state.storage_deposits.is_zero());

        let restored = bincode_restart(&state);
        assert_eq!(restored.storage_deposits, state.storage_deposits);
        assert_eq!(
            restored.objects[&object_id].deposit,
            state.objects[&object_id].deposit
        );
        assert_eq!(restored, state, "restart preserves full state");
        assert_eq!(
            restored.state_root().expect("restored root"),
            state.state_root().expect("root"),
            "storage_deposits is committed by the state root across a restart"
        );
    }

    #[test]
    fn delegated_rewards_can_be_claimed_by_delegator() {
        let (config, mut state, alice, bob) = funded_state();

        let fund_bob = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(200),
            },
            FeeBid::default(),
        )
        .unwrap();
        state.execute_transaction(&fund_bob, &config).unwrap();

        let register_validator = Transaction::for_operation(
            &alice,
            1,
            Operation::RegisterValidator {
                consensus_key: PublicKeyBytes([9u8; 32]),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state
            .execute_transaction(&register_validator, &config)
            .unwrap();

        let delegate = Transaction::for_operation(
            &bob,
            0,
            Operation::Delegate {
                validator: alice.address(),
                amount: Amount::from_webc(80),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&delegate, &config).unwrap();
        assert!(state
            .validators
            .get(&alice.address())
            .expect("registered validator")
            .is_active());

        state.distribute_epoch_rewards(&config).unwrap();
        let delegation = state
            .delegations
            .get(&(bob.address(), alice.address()))
            .unwrap();
        assert!(delegation.accumulated_rewards > Amount::ZERO);
        assert!(
            state
                .validators
                .get(&alice.address())
                .unwrap()
                .accumulated_rewards
                > Amount::ZERO
        );

        let balance_before_claim = state.accounts.get(&bob.address()).unwrap().balance;
        let claim = Transaction::for_operation(
            &bob,
            1,
            Operation::ClaimDelegatorRewards {
                validator: alice.address(),
            },
            FeeBid {
                gas_limit: 10_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&claim, &config).unwrap();
        assert!(state.accounts.get(&bob.address()).unwrap().balance > balance_before_claim);
        assert_eq!(
            state
                .delegations
                .get(&(bob.address(), alice.address()))
                .unwrap()
                .accumulated_rewards,
            Amount::ZERO
        );
    }

    #[test]
    fn delegation_above_eighty_percent_is_rejected_atomically() {
        let (config, mut state, alice, bob) = funded_state();
        let fund_bob = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(100),
            },
            FeeBid::default(),
        )
        .expect("valid funding transaction");
        state
            .execute_transaction(&fund_bob, &config)
            .expect("funding succeeds");
        let register = Transaction::for_operation(
            &alice,
            1,
            Operation::RegisterValidator {
                consensus_key: PublicKeyBytes([9u8; 32]),
                self_stake: Amount::from_webc(20),
                commission_bps: 500,
                bootstrap: false,
            },
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("valid registration transaction");
        state
            .execute_transaction(&register, &config)
            .expect("registration succeeds");
        let before = state.clone();
        let excessive = Transaction::for_operation(
            &bob,
            0,
            Operation::Delegate {
                validator: alice.address(),
                amount: Amount::from_webc(81),
            },
            FeeBid {
                gas_limit: 15_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("signed delegation transaction");

        assert!(matches!(
            state.execute_transaction(&excessive, &config),
            Err(ChainError::DelegationRatioExceeded)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn account_state_proof_verifies_and_rejects_tampering() {
        let (config, mut state, alice, bob) = funded_state();
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_webc(10),
            },
            FeeBid::default(),
        )
        .unwrap();
        state.execute_transaction(&tx, &config).unwrap();

        let proof = state.account_state_proof(bob.address()).unwrap().unwrap();
        assert!(proof.verify().unwrap());

        let mut tampered = proof.clone();
        tampered.account.balance = Amount::from_units(1);
        assert!(!tampered.verify().unwrap());
    }

    #[test]
    fn unauthorized_bridge_relayer_is_rejected() {
        let (config, mut state, alice, bob) = funded_state();
        let message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 99,
            asset: AssetId::WrappedWebc {
                origin_chain: ExternalChain::Webc,
            },
            sender: vec![1u8; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(5),
            source_tx: Hash256::digest(b"eth-lock-unauthorized"),
        };
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::BridgeMint { message },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::UnauthorizedBridgeRelayer)
        ));
    }

    #[test]
    fn bridge_message_replay_is_rejected() {
        let (mut config, mut state, alice, bob) = funded_state();
        config.bridge.incoming_messages_enabled = true;
        config.bridge.trusted_relayers.push(alice.address());
        let message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 1,
            asset: AssetId::External {
                origin_chain: ExternalChain::Ethereum,
                symbol: "MOCK".to_owned(),
                contract_or_mint: "0xmock".to_owned(),
            },
            sender: vec![1u8; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(5),
            source_tx: Hash256::digest(b"eth-lock"),
        };
        let tx = Transaction::for_operation(
            &alice,
            0,
            Operation::BridgeMint {
                message: message.clone(),
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        state.execute_transaction(&tx, &config).unwrap();

        let replay = Transaction::for_operation(
            &alice,
            1,
            Operation::BridgeMint { message },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .unwrap();
        assert!(matches!(
            state.execute_transaction(&replay, &config),
            Err(ChainError::BridgeReplay)
        ));
    }

    #[test]
    fn native_bridge_escrow_reconciles_lock_release_and_domain_limits() {
        let (mut config, mut state, alice, bob) = funded_state();
        config.bridge.incoming_messages_enabled = true;
        config.bridge.trusted_relayers.push(alice.address());

        let zero_lock = Transaction::for_operation(
            &alice,
            0,
            Operation::BridgeLock {
                asset: AssetId::NativeWebc,
                destination_chain: ExternalChain::Ethereum,
                recipient: vec![0x10; 20],
                amount: Amount::ZERO,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("zero lock signs");
        let before_zero = state.clone();
        assert!(matches!(
            state.execute_transaction(&zero_lock, &config),
            Err(ChainError::BridgeAmountZero)
        ));
        assert_eq!(state, before_zero);

        let lock = Transaction::for_operation(
            &alice,
            0,
            Operation::BridgeLock {
                asset: AssetId::NativeWebc,
                destination_chain: ExternalChain::Ethereum,
                recipient: vec![0x11; 20],
                amount: Amount::from_webc(10),
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("lock signs");
        state
            .execute_transaction(&lock, &config)
            .expect("native lock enters escrow");
        assert_eq!(
            state.native_bridge_escrow.get(&ExternalChain::Ethereum),
            Some(&Amount::from_webc(10))
        );
        let locked_report = state.supply_invariant_report().expect("lock report");
        assert_eq!(locked_report.escrowed, Amount::from_webc(10));
        assert!(locked_report.balanced);

        let over_release_message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 1,
            asset: AssetId::NativeWebc,
            sender: vec![0x21; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(11),
            source_tx: Hash256::digest(b"ethereum-over-release"),
        };
        let over_release = Transaction::for_operation(
            &alice,
            1,
            Operation::BridgeRelease {
                message: over_release_message,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("over-release signs");
        let before_over_release = state.clone();
        assert!(matches!(
            state.execute_transaction(&over_release, &config),
            Err(ChainError::InsufficientBridgeEscrow { .. })
        ));
        assert_eq!(state, before_over_release);

        let wrong_domain = BridgeMessage {
            source_chain: ExternalChain::Solana,
            destination_chain: ExternalChain::Webc,
            nonce: 1,
            asset: AssetId::NativeWebc,
            sender: vec![0x22; 32],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(1),
            source_tx: Hash256::digest(b"solana-burn-without-solana-escrow"),
        };
        let wrong_release = Transaction::for_operation(
            &alice,
            1,
            Operation::BridgeRelease {
                message: wrong_domain,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("wrong-domain release signs");
        let before_wrong_domain = state.clone();
        assert!(matches!(
            state.execute_transaction(&wrong_release, &config),
            Err(ChainError::InsufficientBridgeEscrow { .. })
        ));
        assert_eq!(state, before_wrong_domain);

        let release_message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 2,
            asset: AssetId::NativeWebc,
            sender: vec![0x33; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(7),
            source_tx: Hash256::digest(b"ethereum-wrapped-webc-burn"),
        };
        let release = Transaction::for_operation(
            &alice,
            1,
            Operation::BridgeRelease {
                message: release_message,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("release signs");
        state
            .execute_transaction(&release, &config)
            .expect("same-domain escrow release");
        assert_eq!(
            state.native_bridge_escrow.get(&ExternalChain::Ethereum),
            Some(&Amount::from_webc(3))
        );
        assert_eq!(
            state
                .accounts
                .get(&bob.address())
                .expect("recipient")
                .balance,
            Amount::from_webc(7)
        );
        let released_report = state.supply_invariant_report().expect("release report");
        assert_eq!(released_report.escrowed, Amount::from_webc(3));
        assert!(released_report.balanced);
    }

    #[test]
    fn external_asset_mint_preserves_native_supply_and_rejects_native_mint() {
        let (mut config, mut state, alice, bob) = funded_state();
        config.bridge.incoming_messages_enabled = true;
        config.bridge.trusted_relayers.push(alice.address());
        let external_asset = AssetId::External {
            origin_chain: ExternalChain::Ethereum,
            symbol: "MOCK".to_owned(),
            contract_or_mint: "0xmock".to_owned(),
        };
        let external_message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 1,
            asset: external_asset.clone(),
            sender: vec![0x44; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(5),
            source_tx: Hash256::digest(b"external-mock-lock"),
        };
        let mint = Transaction::for_operation(
            &alice,
            0,
            Operation::BridgeMint {
                message: external_message,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("mint signs");
        state
            .execute_transaction(&mint, &config)
            .expect("external representation mints");
        assert_eq!(
            state.asset_balances.get(&(external_asset, bob.address())),
            Some(&Amount::from_webc(5))
        );
        assert!(
            state
                .supply_invariant_report()
                .expect("mint report")
                .balanced
        );

        let invalid_native_mint = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 2,
            asset: AssetId::NativeWebc,
            sender: vec![0x55; 20],
            recipient: bob.address().as_bytes().to_vec(),
            amount: Amount::from_webc(1),
            source_tx: Hash256::digest(b"invalid-native-mint"),
        };
        let invalid = Transaction::for_operation(
            &alice,
            1,
            Operation::BridgeMint {
                message: invalid_native_mint,
            },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("invalid native mint signs");
        let before_invalid = state.clone();
        assert!(matches!(
            state.execute_transaction(&invalid, &config),
            Err(ChainError::InvalidBridgeAssetFlow)
        ));
        assert_eq!(state, before_invalid);
    }

    // ----- active-key rotation (recovery) tests -----

    /// A rotation reveal: the post-quantum root signs the exact rotation to
    /// `new_key` at `nonce` under Alice's installed policy (revision 1), matching
    /// what the state machine rebuilds and verifies.
    fn rotation_reveal(
        owner: Address,
        nonce: u64,
        new_key: &PublicKeyBytes,
    ) -> PostQuantumRootReveal {
        let message = crate::active_key_rotation_message(
            &ChainId::devnet(),
            owner,
            AuthorizationPolicyRevision::new(1),
            nonce,
            new_key,
        )
        .unwrap();
        reveal_over_message(&message)
    }

    /// Builds a default-lane rotation transaction whose envelope is signed by
    /// `signer` (the new key for recovery, or the current active key for an
    /// ordinary rotation) and carries `reveal` as the root authority.
    fn rotate_key_tx(
        owner: &Keypair,
        signer: &Keypair,
        nonce: u64,
        new_key: PublicKeyBytes,
        reveal: PostQuantumRootReveal,
    ) -> Transaction {
        let operation = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_key,
            post_quantum_root_reveal: reveal,
        };
        let access_list = operation
            .default_access_list_for_lane(owner.address(), AuthorizationLaneId::DEFAULT)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            owner.address(),
            signer.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(1),
            nonce,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(signer).unwrap();
        tx
    }

    #[test]
    fn active_key_rotation_recovers_with_the_new_key_and_invalidates_sessions() {
        let (config, mut state, alice, bob) = installed_policy_state();
        // Install a session key under revision 1; rotation must invalidate it.
        let session = Keypair::from_seed([9u8; 32]);
        let session_id = SessionKeyId::derive(&session.public_key());
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();
        assert!(state
            .session_keys
            .contains_key(&(alice.address(), session_id)));

        let new_key = Keypair::from_seed([42u8; 32]);
        let before_root = state.state_root().unwrap();
        // Recovery: the NEW key signs the envelope (the old key is never used) and
        // the real authority is the post-quantum root signature.
        let rotate = rotate_key_tx(
            &alice,
            &new_key,
            2,
            new_key.public_key(),
            rotation_reveal(alice.address(), 2, &new_key.public_key()),
        );
        state.execute_transaction(&rotate, &config).unwrap();

        let policy = state.authorization_policies.get(&alice.address()).unwrap();
        assert_eq!(policy.active_transaction_key(), &new_key.public_key());
        assert_eq!(policy.revision(), AuthorizationPolicyRevision::new(2));
        // The recovery root is preserved, never silently dropped.
        assert_eq!(
            *policy.post_quantum_root(),
            PostQuantumRoot::from_public_key(PostQuantumScheme::MlDsa65, &pq_public_key()).unwrap()
        );
        assert_ne!(state.state_root().unwrap(), before_root);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // The session key installed under revision 1 can no longer be used: the
        // policy is now at revision 2, so a transfer it signs fails.
        let session_tx = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            3,
            bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        assert!(matches!(
            state.execute_transaction(&session_tx, &config),
            Err(ChainError::AuthorizationPolicyRevisionMismatch { .. })
        ));

        // The new active key authorizes an ordinary transfer at revision 2.
        let operation = Operation::Transfer {
            to: bob.address(),
            amount: Amount::from_webc(1),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), AuthorizationLaneId::DEFAULT)
            .unwrap();
        let mut new_tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            new_key.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(2),
            3,
            operation,
            access_list,
            small_fee(),
        );
        new_tx.sign_with_policy_key(&new_key).unwrap();
        state.execute_transaction(&new_tx, &config).unwrap();
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn active_key_rotation_also_works_when_signed_by_the_current_key() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let new_key = Keypair::from_seed([42u8; 32]);
        // Ordinary rotation: the CURRENT active key signs the envelope (the
        // AccountKey authorization path), still gated by the root signature.
        let rotate = rotate_key_tx(
            &alice,
            &alice,
            1,
            new_key.public_key(),
            rotation_reveal(alice.address(), 1, &new_key.public_key()),
        );
        state.execute_transaction(&rotate, &config).unwrap();
        let policy = state.authorization_policies.get(&alice.address()).unwrap();
        assert_eq!(policy.active_transaction_key(), &new_key.public_key());
        assert_eq!(policy.revision(), AuthorizationPolicyRevision::new(2));

        // The old active key can no longer authorize a transfer.
        let old_key_tx = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(2),
            2,
            Operation::Transfer {
                to: _bob.address(),
                amount: Amount::from_webc(1),
            },
            small_fee(),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&old_key_tx, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn active_key_rotation_rejects_rotating_to_the_same_key() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let same = alice.public_key();
        // The current active key signs a rotation whose new key equals the old
        // one; the no-op guard fires before the (valid) root signature is checked.
        let rotate = rotate_key_tx(
            &alice,
            &alice,
            1,
            same,
            rotation_reveal(alice.address(), 1, &same),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&rotate, &config),
            Err(ChainError::ActiveKeyRotationToSameKey)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn active_key_rotation_requires_default_lane() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let lane = AuthorizationLaneId::new(Hash256([0x55; 32]));
        let open = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::OpenAuthorizationLane {
                lane,
                fee_deposit: Amount::from_webc(1),
            },
            small_fee_with_units(10_000),
        )
        .unwrap();
        state.execute_transaction(&open, &config).unwrap();

        let new_key = Keypair::from_seed([42u8; 32]);
        let operation = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_key.public_key(),
            // Rejected by the default-lane guard before the reveal is verified.
            post_quantum_root_reveal: unverified_reveal(),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), lane)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            alice.public_key(),
            lane,
            AuthorizationPolicyRevision::new(1),
            0,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&alice).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::ActiveKeyRotationRequiresDefaultLane)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn active_key_rotation_requires_an_installed_policy() {
        let (config, mut state, alice, _bob) = funded_state();
        let new_key = Keypair::from_seed([42u8; 32]);
        // No policy is installed, so the account is still on the legacy revision.
        // Signing with the address-deriving key at the legacy revision lets the
        // authorization check pass so the arm's installed-policy guard is what
        // actually fires.
        let operation = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_key.public_key(),
            post_quantum_root_reveal: unverified_reveal(),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), AuthorizationLaneId::DEFAULT)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            alice.public_key(),
            AuthorizationLaneId::DEFAULT,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            0,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&alice).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::ActiveKeyRotationRequiresInstalledPolicy)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn active_key_rotation_rejects_a_third_party_envelope_signer() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let new_key = Keypair::from_seed([42u8; 32]);
        let stranger = Keypair::from_seed([44u8; 32]);
        // The envelope is signed by a key that is neither the current active key
        // nor the proposed new key; authorization fails before execution.
        let rotate = rotate_key_tx(
            &alice,
            &stranger,
            1,
            new_key.public_key(),
            rotation_reveal(alice.address(), 1, &new_key.public_key()),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&rotate, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    /// The root-signature gate must reject any reveal that is not a real ML-DSA
    /// signature by the committed root over this exact rotation. Every binding
    /// axis (new key, nonce, owner, chain) and forgery is checked, and each
    /// rejection leaves state unchanged.
    #[test]
    fn active_key_rotation_rejects_misbound_or_forged_root_signature() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let new_key = Keypair::from_seed([42u8; 32]);
        let before = state.clone();

        // (a) Signed for a different new key.
        let other_key = Keypair::from_seed([43u8; 32]);
        let tx_a = rotate_key_tx(
            &alice,
            &new_key,
            1,
            new_key.public_key(),
            rotation_reveal(alice.address(), 1, &other_key.public_key()),
        );
        assert!(matches!(
            state.execute_transaction(&tx_a, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (b) Signed for a different nonce: no replay at another nonce.
        let tx_b = rotate_key_tx(
            &alice,
            &new_key,
            1,
            new_key.public_key(),
            rotation_reveal(alice.address(), 2, &new_key.public_key()),
        );
        assert!(matches!(
            state.execute_transaction(&tx_b, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (c) Signed for a different owner: no cross-account reuse.
        let stranger = Keypair::from_seed([44u8; 32]);
        let wrong_owner_msg = crate::active_key_rotation_message(
            &ChainId::devnet(),
            stranger.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_key.public_key(),
        )
        .unwrap();
        let tx_c = rotate_key_tx(
            &alice,
            &new_key,
            1,
            new_key.public_key(),
            reveal_over_message(&wrong_owner_msg),
        );
        assert!(matches!(
            state.execute_transaction(&tx_c, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (d) Signed for a different chain: no cross-chain reuse.
        let wrong_chain_msg = crate::active_key_rotation_message(
            &ChainId::new("webc-testnet-9").unwrap(),
            alice.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_key.public_key(),
        )
        .unwrap();
        let tx_d = rotate_key_tx(
            &alice,
            &new_key,
            1,
            new_key.public_key(),
            reveal_over_message(&wrong_chain_msg),
        );
        assert!(matches!(
            state.execute_transaction(&tx_d, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (e) The committed public key but a garbage signature of the right
        // length: the commitment check passes, the signature check fails closed.
        let garbage = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: pq_public_key(),
            signature: vec![0x7u8; ML_DSA_65_SIGNATURE_LEN],
        };
        let tx_e = rotate_key_tx(&alice, &new_key, 1, new_key.public_key(), garbage);
        assert!(matches!(
            state.execute_transaction(&tx_e, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (f) A different ML-DSA key with a genuine signature over the correct
        // message: a compromised active key cannot substitute its own root key,
        // because the commitment binds the reveal to the account's stored root.
        let (other_public, other_secret) = ml_dsa65_keygen().unwrap();
        let correct_msg = crate::active_key_rotation_message(
            &ChainId::devnet(),
            alice.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_key.public_key(),
        )
        .unwrap();
        let mismatched = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: other_public.to_bytes(),
            signature: other_secret.sign(&correct_msg, b"").unwrap(),
        };
        let tx_f = rotate_key_tx(&alice, &new_key, 1, new_key.public_key(), mismatched);
        assert!(matches!(
            state.execute_transaction(&tx_f, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn session_key_cannot_authorize_a_rotation() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let session = Keypair::from_seed([9u8; 32]);
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();

        // A session key tries to sign a rotation. Authorization only accepts the
        // current active key or the exact proposed new key as a rotation envelope
        // signer, so a session key (which is neither) is rejected outright with
        // `AuthorizationKeyMismatch` and never reaches the rotation arm. The
        // session-constraint gate would also refuse it, but this earlier check is
        // what fires, so a session key can never rotate the account key.
        let new_key = Keypair::from_seed([42u8; 32]);
        let operation = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_key.public_key(),
            post_quantum_root_reveal: rotation_reveal(alice.address(), 2, &new_key.public_key()),
        };
        let id = SessionKeyId::derive(&session.public_key());
        let access_list = operation
            .default_access_list_for_session(alice.address(), AuthorizationLaneId::DEFAULT, id)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            session.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(1),
            2,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&session).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    // ----- post-quantum root rotation tests -----

    /// A second process-wide ML-DSA-65 keypair used as the *new* recovery root in
    /// root-rotation tests (the first keypair is the current committed root).
    fn pq_keypair_b() -> &'static (MlDsa65PublicKey, MlDsa65SecretKey) {
        static KEYPAIR_B: OnceLock<(MlDsa65PublicKey, MlDsa65SecretKey)> = OnceLock::new();
        KEYPAIR_B.get_or_init(|| ml_dsa65_keygen().expect("ml-dsa-65 keygen b"))
    }

    /// The new post-quantum root committing to keypair B.
    fn new_root_b() -> PostQuantumRoot {
        PostQuantumRoot::from_public_key(PostQuantumScheme::MlDsa65, &pq_keypair_b().0.to_bytes())
            .unwrap()
    }

    /// A reveal whose public key and signature come from `keypair`, over exactly
    /// `message`. Used to sign with either the current root (A) or a candidate
    /// new root (B / a stranger).
    fn reveal_with_keypair(
        keypair: &(MlDsa65PublicKey, MlDsa65SecretKey),
        message: &[u8],
    ) -> PostQuantumRootReveal {
        PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: keypair.0.to_bytes(),
            signature: keypair.1.sign(message, b"").unwrap(),
        }
    }

    /// A root-rotation reveal: the CURRENT root (keypair A) signs the rotation to
    /// `new_root` at `nonce` under revision 1, matching what the state machine
    /// rebuilds and verifies.
    fn root_rotation_reveal(
        owner: Address,
        nonce: u64,
        new_root: &PostQuantumRoot,
    ) -> PostQuantumRootReveal {
        let message = crate::post_quantum_root_rotation_message(
            &ChainId::devnet(),
            owner,
            AuthorizationPolicyRevision::new(1),
            nonce,
            new_root,
        )
        .unwrap();
        reveal_over_message(&message)
    }

    /// Builds a default-lane root-rotation transaction signed by the current
    /// active key (the AccountKey authorization path).
    fn rotate_root_tx(
        owner: &Keypair,
        nonce: u64,
        new_root: PostQuantumRoot,
        reveal: PostQuantumRootReveal,
    ) -> Transaction {
        Transaction::for_operation_with_policy(
            owner,
            AuthorizationPolicyRevision::new(1),
            nonce,
            Operation::RotatePostQuantumRoot {
                new_post_quantum_root: new_root,
                post_quantum_root_reveal: reveal,
            },
            small_fee_with_units(25_000),
        )
        .unwrap()
    }

    #[test]
    fn post_quantum_root_rotation_replaces_the_root_and_preserves_the_active_key() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        // A session key installed under revision 1 must die on any policy bump.
        let session = Keypair::from_seed([9u8; 32]);
        let session_id = SessionKeyId::derive(&session.public_key());
        let install = install_session_key_tx(&alice, &session, 1, session_constraints());
        state.execute_transaction(&install, &config).unwrap();
        assert!(state
            .session_keys
            .contains_key(&(alice.address(), session_id)));

        let new_root = new_root_b();
        let before_root = state.state_root().unwrap();
        let rotate = rotate_root_tx(
            &alice,
            2,
            new_root,
            root_rotation_reveal(alice.address(), 2, &new_root),
        );
        state.execute_transaction(&rotate, &config).unwrap();

        let policy = state.authorization_policies.get(&alice.address()).unwrap();
        assert_eq!(*policy.post_quantum_root(), new_root);
        // The everyday signing key is untouched by a root rotation.
        assert_eq!(policy.active_transaction_key(), &alice.public_key());
        assert_eq!(policy.revision(), AuthorizationPolicyRevision::new(2));
        assert_ne!(state.state_root().unwrap(), before_root);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // The session key installed under revision 1 can no longer be used.
        let session_tx = session_transfer_tx(
            &alice,
            &session,
            AuthorizationLaneId::DEFAULT,
            3,
            _bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        assert!(matches!(
            state.execute_transaction(&session_tx, &config),
            Err(ChainError::AuthorizationPolicyRevisionMismatch { .. })
        ));
    }

    #[test]
    fn post_quantum_root_rotation_rejects_rotating_to_the_same_root() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let same_root =
            PostQuantumRoot::from_public_key(PostQuantumScheme::MlDsa65, &pq_public_key()).unwrap();
        let rotate = rotate_root_tx(
            &alice,
            1,
            same_root,
            root_rotation_reveal(alice.address(), 1, &same_root),
        );
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&rotate, &config),
            Err(ChainError::PostQuantumRootRotationToSameRoot)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn post_quantum_root_rotation_requires_default_lane() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let lane = AuthorizationLaneId::new(Hash256([0x55; 32]));
        let open = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(1),
            1,
            Operation::OpenAuthorizationLane {
                lane,
                fee_deposit: Amount::from_webc(1),
            },
            small_fee_with_units(10_000),
        )
        .unwrap();
        state.execute_transaction(&open, &config).unwrap();

        let new_root = new_root_b();
        let operation = Operation::RotatePostQuantumRoot {
            new_post_quantum_root: new_root,
            // Rejected by the default-lane guard before the reveal is verified.
            post_quantum_root_reveal: unverified_reveal(),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), lane)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            alice.public_key(),
            lane,
            AuthorizationPolicyRevision::new(1),
            0,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&alice).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::PostQuantumRootRotationRequiresDefaultLane)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn post_quantum_root_rotation_requires_an_installed_policy() {
        let (config, mut state, alice, _bob) = funded_state();
        let new_root = new_root_b();
        // No policy installed: sign with the address-deriving key at the legacy
        // revision so authorization passes and the arm's policy guard fires.
        let operation = Operation::RotatePostQuantumRoot {
            new_post_quantum_root: new_root,
            post_quantum_root_reveal: unverified_reveal(),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), AuthorizationLaneId::DEFAULT)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            alice.public_key(),
            AuthorizationLaneId::DEFAULT,
            LEGACY_AUTHORIZATION_POLICY_REVISION,
            0,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&alice).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::PostQuantumRootRotationRequiresInstalledPolicy)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn post_quantum_root_rotation_rejects_a_non_active_envelope_signer() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let new_root = new_root_b();
        let stranger = Keypair::from_seed([44u8; 32]);
        // A non-active Ed25519 key signs the envelope. Unlike active-key rotation,
        // root rotation has no recovery signer path, so this is just an ordinary
        // authorization failure.
        let operation = Operation::RotatePostQuantumRoot {
            new_post_quantum_root: new_root,
            post_quantum_root_reveal: root_rotation_reveal(alice.address(), 1, &new_root),
        };
        let access_list = operation
            .default_access_list_for_lane(alice.address(), AuthorizationLaneId::DEFAULT)
            .unwrap();
        let mut tx = Transaction::new_unsigned_in_lane_on_chain(
            CURRENT_PROTOCOL_VERSION,
            ChainId::devnet(),
            alice.address(),
            stranger.public_key(),
            AuthorizationLaneId::DEFAULT,
            AuthorizationPolicyRevision::new(1),
            1,
            operation,
            access_list,
            small_fee_with_units(25_000),
        );
        tx.sign_with_policy_key(&stranger).unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::AuthorizationKeyMismatch)
        ));
        assert_eq!(state, before);
    }

    /// The gate must reject any reveal that is not a real ML-DSA signature by the
    /// *current* committed root over this exact root rotation. Every binding axis
    /// and forgery is checked, each leaving state unchanged.
    #[test]
    fn post_quantum_root_rotation_rejects_misbound_or_forged_current_root_signature() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let new_root = new_root_b();
        let before = state.clone();

        // (a) Signed over a different new root.
        let other_root =
            PostQuantumRoot::from_public_key(PostQuantumScheme::MlDsa65, b"a third root").unwrap();
        let tx_a = rotate_root_tx(
            &alice,
            1,
            new_root,
            root_rotation_reveal(alice.address(), 1, &other_root),
        );
        assert!(matches!(
            state.execute_transaction(&tx_a, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (b) Signed for a different nonce.
        let tx_b = rotate_root_tx(
            &alice,
            1,
            new_root,
            root_rotation_reveal(alice.address(), 2, &new_root),
        );
        assert!(matches!(
            state.execute_transaction(&tx_b, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (c) Signed for a different owner.
        let stranger = Keypair::from_seed([44u8; 32]);
        let wrong_owner_msg = crate::post_quantum_root_rotation_message(
            &ChainId::devnet(),
            stranger.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_root,
        )
        .unwrap();
        let tx_c = rotate_root_tx(&alice, 1, new_root, reveal_over_message(&wrong_owner_msg));
        assert!(matches!(
            state.execute_transaction(&tx_c, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (d) Signed for a different chain.
        let wrong_chain_msg = crate::post_quantum_root_rotation_message(
            &ChainId::new("webc-testnet-9").unwrap(),
            alice.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_root,
        )
        .unwrap();
        let tx_d = rotate_root_tx(&alice, 1, new_root, reveal_over_message(&wrong_chain_msg));
        assert!(matches!(
            state.execute_transaction(&tx_d, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (e) The current root's public key but a garbage signature.
        let garbage = PostQuantumRootReveal {
            scheme: PostQuantumScheme::MlDsa65,
            public_key: pq_public_key(),
            signature: vec![0x7u8; ML_DSA_65_SIGNATURE_LEN],
        };
        let tx_e = rotate_root_tx(&alice, 1, new_root, garbage);
        assert!(matches!(
            state.execute_transaction(&tx_e, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // (f) Signed by the NEW root instead of the current one: the current root
        // must authorize its own replacement, so the future root cannot.
        let correct_msg = crate::post_quantum_root_rotation_message(
            &ChainId::devnet(),
            alice.address(),
            AuthorizationPolicyRevision::new(1),
            1,
            &new_root,
        )
        .unwrap();
        let signed_by_new = reveal_with_keypair(pq_keypair_b(), &correct_msg);
        let tx_f = rotate_root_tx(&alice, 1, new_root, signed_by_new);
        assert!(matches!(
            state.execute_transaction(&tx_f, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn after_root_rotation_the_new_root_holds_authority_and_the_old_root_does_not() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        // Rotate the root from A to B (envelope signed by the active key).
        let new_root = new_root_b();
        let rotate = rotate_root_tx(
            &alice,
            1,
            new_root,
            root_rotation_reveal(alice.address(), 1, &new_root),
        );
        state.execute_transaction(&rotate, &config).unwrap();
        assert_eq!(
            *state
                .authorization_policies
                .get(&alice.address())
                .unwrap()
                .post_quantum_root(),
            new_root
        );

        // Now attempt an active-key rotation at the new revision 2. The rotation
        // message binds revision 2; the active key (alice) signs the envelope.
        let new_ed = Keypair::from_seed([50u8; 32]);
        let msg = crate::active_key_rotation_message(
            &ChainId::devnet(),
            alice.address(),
            AuthorizationPolicyRevision::new(2),
            2,
            &new_ed.public_key(),
        )
        .unwrap();

        // The OLD root (A) can no longer authorize: the commitment now binds B.
        let signed_by_old = reveal_over_message(&msg);
        let operation_old = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_ed.public_key(),
            post_quantum_root_reveal: signed_by_old,
        };
        let old_tx = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(2),
            2,
            operation_old,
            small_fee_with_units(25_000),
        )
        .unwrap();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&old_tx, &config),
            Err(ChainError::InvalidPostQuantumRootReveal)
        ));
        assert_eq!(state, before);

        // The NEW root (B) now authorizes the same active-key rotation.
        let signed_by_new = reveal_with_keypair(pq_keypair_b(), &msg);
        let operation_new = Operation::RotateActiveTransactionKey {
            new_active_transaction_key: new_ed.public_key(),
            post_quantum_root_reveal: signed_by_new,
        };
        let new_tx = Transaction::for_operation_with_policy(
            &alice,
            AuthorizationPolicyRevision::new(2),
            2,
            operation_new,
            small_fee_with_units(25_000),
        )
        .unwrap();
        state.execute_transaction(&new_tx, &config).unwrap();
        let policy = state.authorization_policies.get(&alice.address()).unwrap();
        assert_eq!(policy.active_transaction_key(), &new_ed.public_key());
        assert_eq!(policy.revision(), AuthorizationPolicyRevision::new(3));
        // The recovery root is still B after the active-key rotation.
        assert_eq!(*policy.post_quantum_root(), new_root);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    // ----- epoch-boundary session-key pruning -----

    #[test]
    fn expired_session_keys_are_pruned_at_the_epoch_boundary_deterministically() {
        let (config, mut state, alice, _bob) = installed_policy_state();
        let short = Keypair::from_seed([9u8; 32]);
        let long = Keypair::from_seed([10u8; 32]);
        let short_id = SessionKeyId::derive(&short.public_key());
        let long_id = SessionKeyId::derive(&long.public_key());

        // Installed at epoch 0: `short` expires after epoch 1, `long` after 50.
        let mut short_c = session_constraints();
        short_c.lifetime_epochs = 1;
        let mut long_c = session_constraints();
        long_c.lifetime_epochs = 50;
        state
            .execute_transaction(&install_session_key_tx(&alice, &short, 1, short_c), &config)
            .unwrap();
        state
            .execute_transaction(&install_session_key_tx(&alice, &long, 2, long_c), &config)
            .unwrap();

        // Advance to epoch 1: `short` is still usable at its expiry epoch, so
        // nothing is pruned yet.
        state.distribute_epoch_rewards(&config).unwrap();
        assert_eq!(state.current_epoch, 1);
        assert!(state
            .session_keys
            .contains_key(&(alice.address(), short_id)));
        assert!(state.session_keys.contains_key(&(alice.address(), long_id)));

        // Snapshot at epoch 1, then advance to epoch 2 on both the live state and
        // a serialized-then-restored copy. Pruning is a pure function of committed
        // state, so both must produce identical state, root, and events.
        // bincode (not JSON) because state maps use non-string tuple keys.
        let mut restored = bincode_restart(&state);
        let live_events = state.distribute_epoch_rewards(&config).unwrap();
        let restored_events = restored.distribute_epoch_rewards(&config).unwrap();
        assert_eq!(state, restored);
        assert_eq!(state.state_root().unwrap(), restored.state_root().unwrap());
        assert_eq!(live_events, restored_events);

        // At epoch 2 the short key is gone (its expiry epoch has passed) and the
        // long key survives; a prune event was emitted for the short key.
        assert_eq!(state.current_epoch, 2);
        assert!(!state
            .session_keys
            .contains_key(&(alice.address(), short_id)));
        assert!(state.session_keys.contains_key(&(alice.address(), long_id)));
        assert!(live_events.iter().any(|event| matches!(
            event,
            Event::SessionKeyExpired { owner, session_key }
                if *owner == alice.address() && *session_key == short_id
        )));
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Pruning removes only unusable keys, so it never changes an authorization
        // outcome: the surviving long key still authorizes a transfer.
        let transfer = session_transfer_tx(
            &alice,
            &long,
            AuthorizationLaneId::DEFAULT,
            3,
            _bob.address(),
            Amount::from_webc(1),
            small_fee(),
        );
        state.execute_transaction(&transfer, &config).unwrap();
    }

    // ----- §15.35 fee sponsorship (paymaster) -----

    /// Devnet-style state whose sponsorship caps are small enough to exhaust in
    /// a test. Alice (seed 1) is funded with 1,000 WEBC; Bob (seed 2) has nothing.
    fn sponsored_setup() -> (ChainConfig, ChainState, Keypair, Keypair, Hash256) {
        let config = ChainConfig {
            sponsorship: SponsorshipConfig {
                enabled: true,
                max_ops_per_user_per_app_per_day: 2,
                max_sponsored_fee_per_op: Amount::from_units(1_000),
                max_app_daily_budget: Amount::from_units(1_000_000),
                day_window_epochs: 10,
            },
            ..ChainConfig::default()
        };
        let alice = Keypair::from_seed([1u8; 32]);
        let bob = Keypair::from_seed([2u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![GenesisAccount {
                address: alice.address(),
                balance: Amount::from_webc(1_000),
            }],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).expect("genesis builds");
        (
            config,
            state,
            alice,
            bob,
            Hash256::digest(b"demo-app-namespace"),
        )
    }

    /// Fee bid whose effective per-unit price is exactly 1, so a `Transfer`'s fee
    /// is exactly 500 base units (its 500 execution units × 1).
    fn unit_fee(gas_limit: u64) -> FeeBid {
        FeeBid {
            gas_limit,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        }
    }

    /// Registers `owner` as the sponsor of `namespace`, funding `funding` and
    /// setting a `daily_cap`, at `nonce`; asserts the transaction succeeds.
    fn register_sponsor(
        state: &mut ChainState,
        config: &ChainConfig,
        owner: &Keypair,
        namespace: Hash256,
        daily_cap: u128,
        funding: u128,
        nonce: u64,
    ) {
        let tx = Transaction::for_operation(
            owner,
            nonce,
            Operation::RegisterAppSponsor {
                namespace,
                daily_budget_cap: Amount::from_units(daily_cap),
                initial_funding: Amount::from_units(funding),
            },
            unit_fee(20_000),
        )
        .expect("register signs");
        state
            .execute_transaction(&tx, config)
            .expect("sponsor registered");
    }

    /// Transfers `amount` base units from `from` to `to` at `nonce` (self-paid).
    fn seed_balance(
        state: &mut ChainState,
        config: &ChainConfig,
        from: &Keypair,
        to: Address,
        amount: u128,
        nonce: u64,
    ) {
        let tx = Transaction::for_operation(
            from,
            nonce,
            Operation::Transfer {
                to,
                amount: Amount::from_units(amount),
            },
            unit_fee(1_000),
        )
        .expect("seed signs");
        state.execute_transaction(&tx, config).expect("seeded");
    }

    /// Builds a sponsored `Transfer` of `amount` from `from` to `to` at `nonce`,
    /// opting into fee sponsorship by `namespace`. The transfer fee is 500.
    fn sponsored_transfer(
        from: &Keypair,
        to: Address,
        amount: u128,
        nonce: u64,
        namespace: Hash256,
    ) -> Transaction {
        Transaction::for_sponsored_operation(
            from,
            nonce,
            Operation::Transfer {
                to,
                amount: Amount::from_units(amount),
            },
            unit_fee(1_000),
            namespace,
        )
        .expect("sponsored transfer signs")
    }

    #[test]
    fn register_and_fund_app_sponsor_locks_budget_and_conserves_supply() {
        let (config, mut state, alice, _bob, namespace) = sponsored_setup();
        let issued = state.minted_supply;

        register_sponsor(&mut state, &config, &alice, namespace, 50_000, 100_000, 0);
        let sponsor = &state.sponsors[&namespace];
        assert_eq!(sponsor.owner, alice.address());
        assert_eq!(sponsor.budget, Amount::from_units(100_000));
        assert_eq!(sponsor.daily_budget_cap, Amount::from_units(50_000));
        assert_eq!(state.sponsor_budgets, Amount::from_units(100_000));
        assert_eq!(
            state.minted_supply, issued,
            "registering a sponsor mints no supply"
        );
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Top up the same sponsor; the aggregate bucket tracks the per-app budget.
        let fund = Transaction::for_operation(
            &alice,
            1,
            Operation::FundAppSponsor {
                namespace,
                amount: Amount::from_units(50_000),
            },
            unit_fee(20_000),
        )
        .expect("fund signs");
        let receipt = state.execute_transaction(&fund, &config).expect("funded");
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(150_000)
        );
        assert_eq!(state.sponsor_budgets, Amount::from_units(150_000));
        assert!(receipt.events.iter().any(|e| matches!(
            e,
            Event::AppSponsorFunded { application, amount }
                if *application == namespace && *amount == Amount::from_units(50_000)
        )));
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Only the owner may fund; a stranger's fund is rejected and rolls back.
        let stranger = Keypair::from_seed([9u8; 32]);
        seed_balance(&mut state, &config, &alice, stranger.address(), 100_000, 2);
        let bad = Transaction::for_operation(
            &stranger,
            0,
            Operation::FundAppSponsor {
                namespace,
                amount: Amount::from_units(10),
            },
            unit_fee(20_000),
        )
        .expect("stranger fund signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&bad, &config),
            Err(ChainError::AppSponsorNotOwner)
        ));
        assert_eq!(state, before, "rejected fund leaves state unchanged");
    }

    #[test]
    fn sponsored_transfer_draws_fee_from_sponsor_leaving_sender_fee_untouched() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 200_000, 0,
        );

        // Fund Bob with EXACTLY one transfer principal and no fee headroom: a
        // self-paid transfer would fail, so success proves the sponsor paid.
        let principal = 100u128;
        seed_balance(&mut state, &config, &alice, bob.address(), principal, 1);
        assert_eq!(
            state.accounts[&bob.address()].balance,
            Amount::from_units(principal)
        );

        let carol = Keypair::from_seed([3u8; 32]).address();
        let issued = state.minted_supply;
        let burned_before = state.burned_fees;
        let pool_before = state.validator_fee_pool;

        let tx = sponsored_transfer(&bob, carol, principal, 0, namespace);
        let receipt = state
            .execute_transaction(&tx, &config)
            .expect("sponsored transfer succeeds despite zero fee headroom");

        // Bob's balance fell by the principal only — the 500 fee never touched it.
        assert_eq!(state.accounts[&bob.address()].balance, Amount::ZERO);
        assert_eq!(
            state.accounts[&carol].balance,
            Amount::from_units(principal)
        );
        // The fee came out of the sponsor budget and split into burn + reward.
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(199_500)
        );
        assert_eq!(state.sponsor_budgets, Amount::from_units(199_500));
        assert_eq!(
            state.sponsors[&namespace].spent_in_window,
            Amount::from_units(500)
        );
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            1
        );
        assert_eq!(
            state.burned_fees,
            burned_before.checked_add(Amount::from_units(250)).unwrap()
        );
        assert_eq!(
            state.validator_fee_pool,
            pool_before.checked_add(Amount::from_units(250)).unwrap()
        );
        assert!(receipt.events.iter().any(|e| matches!(
            e,
            Event::FeeSponsored { application, beneficiary, .. }
                if *application == namespace && *beneficiary == bob.address()
        )));
        assert_eq!(
            state.minted_supply, issued,
            "a sponsored fee mints no supply"
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn per_user_daily_cap_exhausts_then_falls_back_to_self_pay() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        // per-user cap is 2. Fund Bob for 3 principals + exactly one self-paid fee.
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        seed_balance(&mut state, &config, &alice, bob.address(), 3 * 10 + 500, 1);
        let carol = Keypair::from_seed([3u8; 32]).address();

        // First two sponsored operations are covered by the sponsor.
        for nonce in 0..2 {
            let tx = sponsored_transfer(&bob, carol, 10, nonce, namespace);
            let receipt = state.execute_transaction(&tx, &config).expect("sponsored");
            assert!(receipt
                .events
                .iter()
                .any(|e| matches!(e, Event::FeeSponsored { .. })));
        }
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(99_000)
        );
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            2
        );

        // The third exceeds the per-user daily cap and falls back to self-pay.
        let bob_before = state.accounts[&bob.address()].balance;
        let tx = sponsored_transfer(&bob, carol, 10, 2, namespace);
        let receipt = state
            .execute_transaction(&tx, &config)
            .expect("third op still succeeds via self-pay");
        assert!(
            !receipt
                .events
                .iter()
                .any(|e| matches!(e, Event::FeeSponsored { .. })),
            "over-cap op is not sponsored"
        );
        // Bob paid the 500 fee himself plus the 10 principal; sponsor unchanged.
        assert_eq!(
            state.accounts[&bob.address()].balance,
            bob_before.checked_sub(Amount::from_units(510)).unwrap()
        );
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(99_000),
            "the sponsor budget did not move for the self-paid op"
        );
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            2
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn per_app_budget_exhaustion_falls_back_to_self_pay() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        // Fund the sponsor with only enough for a single 500-unit fee.
        register_sponsor(&mut state, &config, &alice, namespace, 1_000_000, 600, 0);
        seed_balance(&mut state, &config, &alice, bob.address(), 2 * 10 + 500, 1);
        let carol = Keypair::from_seed([3u8; 32]).address();

        let first = sponsored_transfer(&bob, carol, 10, 0, namespace);
        let receipt = state.execute_transaction(&first, &config).expect("first");
        assert!(receipt
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(state.sponsors[&namespace].budget, Amount::from_units(100));

        // Budget (100) can no longer cover the 500 fee -> self-pay.
        let bob_before = state.accounts[&bob.address()].balance;
        let second = sponsored_transfer(&bob, carol, 10, 1, namespace);
        let receipt = state.execute_transaction(&second, &config).expect("second");
        assert!(!receipt
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(
            state.accounts[&bob.address()].balance,
            bob_before.checked_sub(Amount::from_units(510)).unwrap()
        );
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(100),
            "an underfunded sponsor is never overdrawn"
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn per_app_daily_spend_cap_binds_then_self_pays() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        // Well-funded, but the app's per-day spend cap only covers one 500 fee.
        register_sponsor(&mut state, &config, &alice, namespace, 700, 100_000, 0);
        seed_balance(&mut state, &config, &alice, bob.address(), 2 * 10 + 500, 1);
        let carol = Keypair::from_seed([3u8; 32]).address();

        let first = sponsored_transfer(&bob, carol, 10, 0, namespace);
        assert!(state
            .execute_transaction(&first, &config)
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(
            state.sponsors[&namespace].spent_in_window,
            Amount::from_units(500)
        );

        // 500 + 500 > 700 day cap -> self-pay; the daily spend counter stays put.
        let second = sponsored_transfer(&bob, carol, 10, 1, namespace);
        assert!(!state
            .execute_transaction(&second, &config)
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(
            state.sponsors[&namespace].spent_in_window,
            Amount::from_units(500)
        );
        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(99_500)
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn a_non_simple_operation_is_never_sponsored() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        // CreateObject costs a 20,000 fee + a 1,000 storage deposit (1 byte).
        seed_balance(&mut state, &config, &alice, bob.address(), 21_000, 1);
        let sponsor_before = state.sponsors[&namespace].clone();

        let object_id = ObjectId::new(Hash256::digest(b"sponsor-nonsimple-obj"));
        let tx = Transaction::for_sponsored_operation(
            &bob,
            0,
            Operation::CreateObject {
                object_id,
                namespace,
                data: vec![0u8; 1],
            },
            unit_fee(20_000),
            namespace,
        )
        .expect("sponsored non-simple op signs");
        let receipt = state
            .execute_transaction(&tx, &config)
            .expect("CreateObject self-pays and succeeds");

        assert!(
            !receipt
                .events
                .iter()
                .any(|e| matches!(e, Event::FeeSponsored { .. })),
            "a non-sponsorable operation must never draw from a sponsor"
        );
        assert_eq!(
            state.sponsors[&namespace], sponsor_before,
            "the sponsor budget and counters are untouched by a non-simple op"
        );
        assert!(state.objects.contains_key(&object_id));
        // Bob self-paid the 20,000 fee and the 1,000 deposit out of 21,000.
        assert_eq!(state.accounts[&bob.address()].balance, Amount::ZERO);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn day_window_counter_resets_deterministically_across_windows() {
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        // window 0: two sponsored + one self-paid (per-user cap 2); window 1: one more.
        seed_balance(&mut state, &config, &alice, bob.address(), 4 * 10 + 500, 1);
        let carol = Keypair::from_seed([3u8; 32]).address();

        for nonce in 0..2 {
            let tx = sponsored_transfer(&bob, carol, 10, nonce, namespace);
            state
                .execute_transaction(&tx, &config)
                .expect("window-0 sponsored");
        }
        // Third in window 0 hits the per-user cap and self-pays.
        let capped = sponsored_transfer(&bob, carol, 10, 2, namespace);
        assert!(!state
            .execute_transaction(&capped, &config)
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            2
        );
        let budget_after_window0 = state.sponsors[&namespace].budget;
        assert_eq!(budget_after_window0, Amount::from_units(99_000));

        // Advance the consensus epoch into the next day-window (10 epochs/window).
        state.current_epoch = 10;

        // The per-user and per-app daily counters reset, so Bob can be sponsored again.
        let next_window = sponsored_transfer(&bob, carol, 10, 3, namespace);
        assert!(state
            .execute_transaction(&next_window, &config)
            .unwrap()
            .events
            .iter()
            .any(|e| matches!(e, Event::FeeSponsored { .. })));
        assert_eq!(state.sponsors[&namespace].window_index, 1);
        assert_eq!(
            state.sponsors[&namespace].spent_in_window,
            Amount::from_units(500)
        );
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 1),
            1
        );
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            0,
            "the previous window reads as zero after rollover"
        );
        assert_eq!(
            state.sponsors[&namespace].budget,
            budget_after_window0
                .checked_sub(Amount::from_units(500))
                .unwrap()
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn withdraw_returns_unspent_budget_and_conserves_supply() {
        let (config, mut state, alice, _bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        let liquid_before = state.accounts[&alice.address()].balance;

        let withdraw = Transaction::for_operation(
            &alice,
            1,
            Operation::WithdrawAppSponsor {
                namespace,
                amount: Amount::from_units(40_000),
            },
            unit_fee(20_000),
        )
        .expect("withdraw signs");
        let withdraw_fee = Amount::from_units(u128::from(withdraw.required_units()));
        state
            .execute_transaction(&withdraw, &config)
            .expect("withdrew");

        assert_eq!(
            state.sponsors[&namespace].budget,
            Amount::from_units(60_000)
        );
        assert_eq!(state.sponsor_budgets, Amount::from_units(60_000));
        // Alice regained the withdrawal minus the withdrawal transaction's own fee.
        assert_eq!(
            state.accounts[&alice.address()].balance,
            liquid_before
                .checked_add(Amount::from_units(40_000))
                .and_then(|b| b.checked_sub(withdraw_fee))
                .unwrap()
        );
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Over-withdrawing the remaining budget is rejected and rolls back.
        let over = Transaction::for_operation(
            &alice,
            2,
            Operation::WithdrawAppSponsor {
                namespace,
                amount: Amount::from_units(60_001),
            },
            unit_fee(20_000),
        )
        .expect("over-withdraw signs");
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&over, &config),
            Err(ChainError::AppSponsorBudgetInsufficient { .. })
        ));
        assert_eq!(state, before, "rejected withdraw leaves state unchanged");
    }

    #[test]
    fn sponsorship_on_a_non_default_lane_is_rejected() {
        let (config, mut state, alice, _bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        // Hand-craft a transfer that names a sponsor but selects a non-default lane.
        let carol = Keypair::from_seed([3u8; 32]).address();
        let lane = AuthorizationLaneId::new(Hash256([0x42; 32]));
        let mut tx = Transaction::new_unsigned_in_lane(
            alice.address(),
            alice.public_key(),
            lane,
            0,
            Operation::Transfer {
                to: carol,
                amount: Amount::from_units(1),
            },
            Operation::Transfer {
                to: carol,
                amount: Amount::from_units(1),
            }
            .default_access_list_for_lane(alice.address(), lane)
            .unwrap(),
            unit_fee(1_000),
        );
        tx.sponsor = Some(namespace);
        tx.sign(&alice).expect("signs");
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::SponsorshipRequiresDefaultLane)
        ));
    }

    #[test]
    fn sponsor_registry_and_counters_survive_bincode_restart_with_stable_state_root() {
        // A crash-restart (bincode round-trip of the whole state) must preserve
        // the sponsor registry, per-user/day counters, the sponsor_budgets bucket,
        // and the committed state root, so a node cannot silently diverge on the
        // new sponsorship state after reloading from disk.
        let (config, mut state, alice, bob, namespace) = sponsored_setup();
        register_sponsor(
            &mut state, &config, &alice, namespace, 1_000_000, 100_000, 0,
        );
        seed_balance(&mut state, &config, &alice, bob.address(), 100, 1);
        let carol = Keypair::from_seed([3u8; 32]).address();
        let tx = sponsored_transfer(&bob, carol, 100, 0, namespace);
        state
            .execute_transaction(&tx, &config)
            .expect("sponsored transfer");
        assert_eq!(
            state.sponsors[&namespace].user_ops_in_window(&bob.address(), 0),
            1
        );
        assert!(!state.sponsor_budgets.is_zero());

        let restored = bincode_restart(&state);
        assert_eq!(
            restored.sponsors, state.sponsors,
            "restart preserves the sponsor registry and its per-user/day counters"
        );
        assert_eq!(restored.sponsor_budgets, state.sponsor_budgets);
        assert_eq!(restored, state, "restart preserves full state");
        assert_eq!(
            restored.state_root().expect("restored root"),
            state.state_root().expect("root"),
            "sponsor state is committed by the state root across a restart"
        );
    }

    // ----- §8 application namespace ownership registry -----

    /// Builds and signs a `RegisterNamespace` for `owner` at `nonce`.
    fn register_namespace_tx(owner: &Keypair, namespace: Hash256, nonce: u64) -> Transaction {
        Transaction::for_operation(
            owner,
            nonce,
            Operation::RegisterNamespace { namespace },
            unit_fee(10_000),
        )
        .expect("register-namespace signs")
    }

    /// Builds and signs a `TransferNamespace` from `owner` to `new_owner` at `nonce`.
    fn transfer_namespace_tx(
        owner: &Keypair,
        namespace: Hash256,
        new_owner: Address,
        nonce: u64,
    ) -> Transaction {
        Transaction::for_operation(
            owner,
            nonce,
            Operation::TransferNamespace {
                namespace,
                new_owner,
            },
            unit_fee(10_000),
        )
        .expect("transfer-namespace signs")
    }

    #[test]
    fn register_namespace_records_owner_commits_root_and_conserves_supply() {
        let (config, mut state, alice, _bob) = funded_state();
        let namespace = Hash256([0x77; 32]);
        let issued = state.minted_supply;
        let root_before = state.state_root().expect("root before");

        let receipt = state
            .execute_transaction(&register_namespace_tx(&alice, namespace, 0), &config)
            .expect("namespace registered");

        assert_eq!(
            state.namespaces[&namespace],
            NamespaceRecord::new(alice.address()),
            "the sender is recorded as the namespace owner"
        );
        assert!(receipt.events.iter().any(|e| matches!(
            e,
            Event::NamespaceRegistered { namespace: ns, owner }
                if *ns == namespace && *owner == alice.address()
        )));
        // A registration locks no native units: only the ordinary fee moved.
        assert_eq!(state.minted_supply, issued, "registration mints no supply");
        assert!(
            state.supply_invariant_report().unwrap().balanced,
            "supply invariant is unaffected by the registry"
        );
        // The registry is committed state: the state root must have changed.
        assert_ne!(
            state.state_root().expect("root after"),
            root_before,
            "claiming a namespace changes the committed state root"
        );
    }

    #[test]
    fn double_register_namespace_is_rejected_and_leaves_owner_unchanged() {
        let (config, mut state, alice, _bob) = funded_state();
        let namespace = Hash256([0x77; 32]);
        state
            .execute_transaction(&register_namespace_tx(&alice, namespace, 0), &config)
            .expect("first registration");

        let before = state.clone();
        // A second claim of the same namespace (even by the original owner) fails.
        assert!(matches!(
            state.execute_transaction(&register_namespace_tx(&alice, namespace, 1), &config),
            Err(ChainError::NamespaceAlreadyRegistered)
        ));
        assert_eq!(
            state, before,
            "a rejected duplicate registration leaves state unchanged"
        );
        assert_eq!(state.namespaces.len(), 1);
    }

    #[test]
    fn transfer_namespace_by_owner_updates_the_owner() {
        let (config, mut state, alice, bob) = funded_state();
        let namespace = Hash256([0x77; 32]);
        state
            .execute_transaction(&register_namespace_tx(&alice, namespace, 0), &config)
            .expect("registration");

        let receipt = state
            .execute_transaction(
                &transfer_namespace_tx(&alice, namespace, bob.address(), 1),
                &config,
            )
            .expect("owner transfer");

        assert_eq!(
            state.namespaces[&namespace],
            NamespaceRecord::new(bob.address()),
            "the namespace is now owned by the new owner"
        );
        assert!(receipt.events.iter().any(|e| matches!(
            e,
            Event::NamespaceTransferred { namespace: ns, from, to }
                if *ns == namespace && *from == alice.address() && *to == bob.address()
        )));
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn transfer_namespace_by_non_owner_is_rejected_and_state_unchanged() {
        let (config, mut state, alice, bob) = funded_state();
        let namespace = Hash256([0x77; 32]);
        state
            .execute_transaction(&register_namespace_tx(&alice, namespace, 0), &config)
            .expect("registration");
        // Fund Bob (a non-owner) so his transaction reaches the ownership check
        // rather than failing on fees or a missing account.
        seed_balance(&mut state, &config, &alice, bob.address(), 1_000_000, 1);

        let carol = Keypair::from_seed([3u8; 32]).address();
        let before = state.clone();
        assert!(matches!(
            state.execute_transaction(&transfer_namespace_tx(&bob, namespace, carol, 0), &config),
            Err(ChainError::NamespaceNotOwner)
        ));
        assert_eq!(
            state, before,
            "a non-owner transfer attempt leaves the registry unchanged"
        );
        assert_eq!(
            state.namespaces[&namespace],
            NamespaceRecord::new(alice.address()),
            "ownership still belongs to the original owner"
        );
    }

    #[test]
    fn transfer_unregistered_namespace_reports_not_found() {
        let (config, mut state, alice, bob) = funded_state();
        let namespace = Hash256([0x99; 32]);
        assert!(matches!(
            state.execute_transaction(
                &transfer_namespace_tx(&alice, namespace, bob.address(), 0),
                &config
            ),
            Err(ChainError::NamespaceNotFound)
        ));
    }

    #[test]
    fn namespace_registry_survives_bincode_restart_with_stable_state_root() {
        // A crash-restart (bincode round-trip of the whole state) must preserve the
        // namespace registry and the committed state root, so a node cannot silently
        // diverge on the new registry state after reloading from disk.
        let (config, mut state, alice, bob) = funded_state();
        let namespace = Hash256([0x77; 32]);
        state
            .execute_transaction(&register_namespace_tx(&alice, namespace, 0), &config)
            .expect("registration");
        state
            .execute_transaction(
                &transfer_namespace_tx(&alice, namespace, bob.address(), 1),
                &config,
            )
            .expect("transfer");
        assert_eq!(
            state.namespaces[&namespace].owner,
            bob.address(),
            "registry reflects the transfer before restart"
        );

        let restored = bincode_restart(&state);
        assert_eq!(
            restored.namespaces, state.namespaces,
            "restart preserves the namespace registry"
        );
        assert_eq!(restored, state, "restart preserves full state");
        assert_eq!(
            restored.state_root().expect("restored root"),
            state.state_root().expect("root"),
            "namespace registry is committed by the state root across a restart"
        );
    }

    #[test]
    fn object_creation_is_not_gated_on_namespace_ownership() {
        // Regression: the registry is an additive ownership record. Object
        // create/mutate/transfer/delete keep working on OPEN namespaces exactly as
        // before — creating an object never requires (or is blocked by) a namespace
        // claim. Gating is a deliberately deferred later-phase policy decision.
        let (config, mut state, alice, bob) = funded_state();
        let namespace = Hash256([0x77; 32]);
        let create = |creator: &Keypair, id: u8, nonce: u64| {
            Transaction::for_operation(
                creator,
                nonce,
                Operation::CreateObject {
                    object_id: ObjectId::new(Hash256([id; 32])),
                    namespace,
                    data: vec![0xaa, 0xbb],
                },
                unit_fee(20_000),
            )
            .expect("create signs")
        };

        // 1. Create an object under a completely unclaimed namespace: succeeds.
        state
            .execute_transaction(&create(&alice, 0x01, 0), &config)
            .expect("object creation works without any namespace claim");

        // 2. Fund Bob and let him claim the namespace (a different account from the
        //    object creator).
        seed_balance(&mut state, &config, &alice, bob.address(), 1_000_000, 1);
        state
            .execute_transaction(&register_namespace_tx(&bob, namespace, 0), &config)
            .expect("bob claims the namespace");

        // 3. Create another object under the now-claimed namespace as Alice, who is
        //    NOT the namespace owner: still succeeds (open namespaces).
        state
            .execute_transaction(&create(&alice, 0x02, 2), &config)
            .expect("object creation is not blocked by another account's namespace claim");

        assert!(state
            .objects
            .contains_key(&ObjectId::new(Hash256([0x01; 32]))));
        assert!(state
            .objects
            .contains_key(&ObjectId::new(Hash256([0x02; 32]))));
        assert_eq!(state.namespaces[&namespace].owner, bob.address());
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    // ----- Phase 6: localized (per-namespace) fee pricing -----

    /// Runs one block's fee finalization with `namespace` charged `units` this
    /// block and a zero total (so the global base fee decays), asserting success.
    fn finish_block_with_namespace_usage(
        state: &mut ChainState,
        config: &ChainConfig,
        namespace: Hash256,
        units: u64,
    ) {
        let mut usage = BTreeMap::new();
        usage.insert(namespace, units);
        state
            .finish_block(0, &usage, config)
            .expect("block finalization succeeds");
    }

    fn create_in(namespace: Hash256, seed: &[u8]) -> Operation {
        Operation::CreateObject {
            object_id: ObjectId::new(Hash256::digest(seed)),
            namespace,
            data: Vec::new(),
        }
    }

    #[test]
    fn namespace_congestion_raises_only_its_own_localized_price() {
        // Phase 6 headline acceptance: heavy load in namespace A raises A's own
        // localized base fee, while an unrelated namespace B stays at the network
        // floor — one application's congestion never raises another's price.
        let (config, mut state, _alice, bob) = funded_state();
        let min = config.fee_policy.min_base_fee_per_unit;
        let ns_a = Hash256::digest(b"app-a");
        let ns_b = Hash256::digest(b"app-b");
        let hot = config.fee_policy.per_namespace_target_units * 3;

        // Drive many blocks that saturate ONLY namespace A.
        for _ in 0..24 {
            finish_block_with_namespace_usage(&mut state, &config, ns_a, hot);
        }

        let a_fee = state.namespace_fees[&ns_a].base_fee_per_unit;
        assert!(
            a_fee > min,
            "namespace A congestion must raise A's localized fee"
        );

        // Namespace B never appeared in any usage map: it carries no record and is
        // priced at exactly the network minimum, unaffected by A's congestion.
        assert!(!state.namespace_fees.contains_key(&ns_b));
        assert_eq!(
            state.base_fee_per_unit_for(&create_in(ns_b, b"b-obj"), &config),
            min,
            "an idle namespace prices at the floor regardless of another's congestion"
        );
        // A's object operations are priced by A's raised localized fee.
        assert_eq!(
            state.base_fee_per_unit_for(&create_in(ns_a, b"a-obj"), &config),
            a_fee
        );
        // Account-scoped operations keep the global base fee, independent of A.
        assert_eq!(
            state.base_fee_per_unit_for(
                &Operation::Transfer {
                    to: bob.address(),
                    amount: Amount::from_units(1),
                },
                &config,
            ),
            state.current_base_fee_per_unit
        );
    }

    #[test]
    fn localized_base_fee_never_drops_below_the_network_minimum() {
        let (config, mut state, _alice, _bob) = funded_state();
        let min = config.fee_policy.min_base_fee_per_unit;
        let ns = Hash256::digest(b"floor-ns");
        for _ in 0..20 {
            finish_block_with_namespace_usage(
                &mut state,
                &config,
                ns,
                config.fee_policy.per_namespace_target_units * 3,
            );
        }
        let raised = state.namespace_fees[&ns].base_fee_per_unit;
        assert!(raised > min);

        // Idle it: the localized fee decays monotonically, never below the floor,
        // and once it returns to the floor the record is dropped entirely (so the
        // committed map stays bounded to currently-congested namespaces).
        let idle = BTreeMap::new();
        let mut previous = raised;
        for _ in 0..2_000 {
            state.finish_block(0, &idle, &config).expect("finish");
            let now = state
                .namespace_fees
                .get(&ns)
                .map(|s| s.base_fee_per_unit)
                .unwrap_or(min);
            assert!(
                now <= previous,
                "localized fee decays monotonically while idle"
            );
            assert!(
                now >= min,
                "localized fee never drops below the network minimum"
            );
            previous = now;
        }
        assert!(
            !state.namespace_fees.contains_key(&ns),
            "a namespace back at the floor carries no committed record"
        );
    }

    #[test]
    fn object_op_pays_localized_fee_and_account_ops_are_unaffected() {
        // End-to-end charging: after congesting namespace `ns`, an object op there
        // is charged its raised localized fee, while a native Transfer keeps paying
        // the global base fee. Supply still reconciles.
        let (config, mut state, alice, bob) = funded_state();
        let min = config.fee_policy.min_base_fee_per_unit;
        let ns = Hash256::digest(b"hot-app");
        for _ in 0..24 {
            finish_block_with_namespace_usage(
                &mut state,
                &config,
                ns,
                config.fee_policy.per_namespace_target_units * 3,
            );
        }
        let localized = state.namespace_fees[&ns].base_fee_per_unit;
        assert!(localized > min);
        // The global fee decayed to the floor across those idle-total blocks.
        assert_eq!(state.current_base_fee_per_unit, min);

        // A native Transfer (account-scoped) pays the GLOBAL base fee, so a max-fee
        // at the floor still clears despite the namespace congestion.
        let before = state.accounts[&alice.address()].balance.0;
        let transfer = Transaction::for_operation(
            &alice,
            0,
            Operation::Transfer {
                to: bob.address(),
                amount: Amount::from_units(1),
            },
            unit_fee(1_000),
        )
        .expect("transfer signs");
        state
            .execute_transaction(&transfer, &config)
            .expect("transfer clears at the global base fee");
        let spent = before - state.accounts[&alice.address()].balance.0;
        assert_eq!(
            spent,
            1 + 500 * u128::from(min),
            "transfer pays amount + units*global_base_fee, not the localized fee"
        );

        // An object op in the congested namespace priced with a floor max-fee is now
        // rejected (its localized base fee is above the floor)...
        let cheap = Transaction::for_operation(&alice, 1, create_in(ns, b"o1"), unit_fee(30_000))
            .expect("create signs");
        assert!(matches!(
            state.execute_transaction(&cheap, &config),
            Err(ChainError::FeeTooLow)
        ));

        // ...and clears when the bid covers the localized fee, charged units*localized.
        let burned_before = state.burned_fees.0;
        let pool_before = state.validator_fee_pool.0;
        let create = Transaction::for_operation(
            &alice,
            1,
            create_in(ns, b"o1"),
            FeeBid {
                gas_limit: 30_000,
                max_fee_per_unit: localized,
                priority_fee_per_unit: 0,
            },
        )
        .expect("create signs");
        state
            .execute_transaction(&create, &config)
            .expect("object op clears at the localized fee");
        let fee_charged =
            (state.burned_fees.0 - burned_before) + (state.validator_fee_pool.0 - pool_before);
        assert_eq!(
            fee_charged,
            20_000 * u128::from(localized),
            "object op is charged units*localized_base_fee"
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn localized_base_fees_are_deterministic_across_runs() {
        // Determinism: identical usage sequences produce identical localized fees
        // and state roots, independent of run.
        let (config, _seed_state, _a, _b) = funded_state();
        let ns1 = Hash256::digest(b"n1");
        let ns2 = Hash256::digest(b"n2");
        let run = || {
            let (_c, mut state, _a, _b) = funded_state();
            for round in 0..15u64 {
                let mut usage = BTreeMap::new();
                usage.insert(
                    ns1,
                    config.fee_policy.per_namespace_target_units * 2 + round,
                );
                usage.insert(ns2, config.fee_policy.per_namespace_target_units / 2);
                state
                    .finish_block(round + 1, &usage, &config)
                    .expect("finish");
            }
            (
                state.namespace_fees.clone(),
                state.state_root().expect("root"),
            )
        };
        assert_eq!(
            run(),
            run(),
            "localized fees are a deterministic function of usage"
        );
    }

    #[test]
    fn namespace_fee_state_survives_bincode_restart_with_stable_state_root() {
        // Crash-restart (bincode round-trip): the committed localized fee state and
        // the state root must survive, so a node cannot silently diverge on
        // localized pricing after reloading from disk.
        let (config, mut state, _alice, _bob) = funded_state();
        let ns = Hash256::digest(b"restart-fee-ns");
        for _ in 0..12 {
            finish_block_with_namespace_usage(
                &mut state,
                &config,
                ns,
                config.fee_policy.per_namespace_target_units * 3,
            );
        }
        assert!(
            state.namespace_fees[&ns].base_fee_per_unit > config.fee_policy.min_base_fee_per_unit
        );

        let restored = bincode_restart(&state);
        assert_eq!(
            restored.namespace_fees, state.namespace_fees,
            "restart preserves the per-namespace fee state"
        );
        assert_eq!(restored, state, "restart preserves full state");
        assert_eq!(
            restored.state_root().expect("restored root"),
            state.state_root().expect("root"),
            "localized fee state is committed by the state root across a restart"
        );
    }

    #[test]
    fn namespace_fee_state_is_committed_by_the_state_root() {
        // E8 extension: the localized per-namespace fee map is a committed consensus
        // field (via the namespace_fee_root sub-root), so inserting or changing a
        // namespace's localized fee must change the state root. Otherwise two nodes
        // could diverge on localized pricing yet share a state root.
        let (_config, base, _a, _b) = funded_state();
        let root = base.state_root().unwrap();
        let ns = Hash256::digest(b"fee-commit-ns");

        let mut inserted = base.clone();
        inserted.namespace_fees.insert(
            ns,
            NamespaceFeeState {
                base_fee_per_unit: 7,
            },
        );
        assert_ne!(
            inserted.state_root().unwrap(),
            root,
            "adding a localized fee must change the state root (E8)"
        );

        let mut changed = inserted.clone();
        changed
            .namespace_fees
            .get_mut(&ns)
            .unwrap()
            .base_fee_per_unit = 8;
        assert_ne!(
            changed.state_root().unwrap(),
            inserted.state_root().unwrap(),
            "changing a localized fee must change the state root (E8)"
        );
    }

    // ----- interim contract runtime (Phase 7a, ADR-0014) -----

    /// Genesis funding three accounts (no validators) so epoch advance mints
    /// nothing and every balance change is a contract move (fee/burn only).
    fn contract_fixture() -> (ChainConfig, ChainState, Keypair, Keypair, Keypair) {
        let config = ChainConfig::default();
        let alice = Keypair::from_seed([1u8; 32]);
        let bob = Keypair::from_seed([2u8; 32]);
        let carol = Keypair::from_seed([3u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
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
                    address: carol.address(),
                    balance: Amount::from_webc(1_000),
                },
            ],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).expect("contract genesis");
        (config, state, alice, bob, carol)
    }

    fn kv_manifest(code_id: Hash256, namespace: Hash256, owner: Address) -> ContractManifest {
        ContractManifest::new(
            code_id,
            namespace,
            BuiltinContract::KeyValue,
            [Hash256([0xa1; 32])],
            owner,
        )
    }

    /// Registers a key/value contract; returns the receipt.
    fn register_kv(
        state: &mut ChainState,
        config: &ChainConfig,
        keypair: &Keypair,
        nonce: u64,
        manifest: ContractManifest,
    ) -> Result<Receipt, ChainError> {
        let tx = Transaction::for_operation(
            keypair,
            nonce,
            Operation::RegisterContract { manifest },
            FeeBid {
                gas_limit: 100_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("register tx signs");
        state.execute_transaction(&tx, config)
    }

    /// Builds a signed contract-invocation transaction with an explicit gas limit.
    fn invoke_tx(
        keypair: &Keypair,
        nonce: u64,
        manifest: &ContractManifest,
        input: Vec<u8>,
        gas_limit: u64,
    ) -> Transaction {
        Transaction::for_operation(
            keypair,
            nonce,
            Operation::InvokeContract {
                code_id: manifest.code_id,
                namespace: manifest.namespace,
                declared_keys: manifest.footprint.clone(),
                input,
            },
            FeeBid {
                gas_limit,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("invoke tx signs")
    }

    #[test]
    fn register_contract_charges_fee_and_rejects_duplicate() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let manifest = kv_manifest(code_id, namespace, alice.address());
        let before = balance(&state, alice.address());
        let burned_before = state.burned_fees.0;

        register_kv(&mut state, &config, &alice, 0, manifest.clone()).expect("register");
        assert_eq!(state.contracts.get(&code_id), Some(&manifest));
        // The registration fee was burned (plus half the ordinary tx fee).
        assert_eq!(
            state.burned_fees.0,
            burned_before + config.contracts.registration_fee.0 + 30_000 / 2
        );
        assert!(before - balance(&state, alice.address()) >= config.contracts.registration_fee.0);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // A duplicate code id is rejected and leaves state unchanged.
        let snapshot = state.clone();
        assert!(matches!(
            register_kv(&mut state, &config, &alice, 1, manifest),
            Err(ChainError::ContractAlreadyExists)
        ));
        assert_eq!(state, snapshot, "rejected duplicate leaves state unchanged");
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn register_contract_rejects_malformed_manifest() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        // A manifest whose owner is not the registrant fails closed.
        let bob = Keypair::from_seed([2u8; 32]);
        let mut manifest = kv_manifest(code_id, namespace, bob.address());
        let snapshot = state.clone();
        assert!(matches!(
            register_kv(&mut state, &config, &alice, 0, manifest.clone()),
            Err(ChainError::InvalidContractManifest)
        ));
        assert_eq!(state, snapshot);
        // An empty footprint fails closed.
        manifest.owner = alice.address();
        manifest.footprint = Vec::new();
        assert!(matches!(
            register_kv(&mut state, &config, &alice, 0, manifest),
            Err(ChainError::InvalidContractManifest)
        ));
        assert_eq!(state, snapshot);
    }

    #[test]
    fn invoke_contract_mutates_declared_state_and_conserves_supply() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let manifest = kv_manifest(code_id, namespace, alice.address());
        let key = manifest.footprint[0];
        register_kv(&mut state, &config, &alice, 0, manifest.clone()).expect("register");
        assert!(state.supply_invariant_report().unwrap().balanced);

        // Increment the counter from zero to 5.
        let tx = invoke_tx(&alice, 1, &manifest, kv_command::increment(key, 5), 100_000);
        let receipt = state.execute_transaction(&tx, &config).expect("invoke");
        assert_eq!(
            state.contract_state.get(&(namespace, key)),
            Some(&ContractStateValue(5u128.to_be_bytes().to_vec()))
        );
        // The invocation moved no native value beyond the ordinary tx fee.
        assert!(receipt.events.iter().any(|event| matches!(
            event,
            Event::ContractInvoked { code_id: c, .. } if *c == code_id
        )));
        assert!(state.supply_invariant_report().unwrap().balanced);

        // A second increment accumulates: 5 + 37 = 42.
        let tx = invoke_tx(
            &alice,
            2,
            &manifest,
            kv_command::increment(key, 37),
            100_000,
        );
        state.execute_transaction(&tx, &config).expect("invoke2");
        assert_eq!(
            state.contract_state.get(&(namespace, key)),
            Some(&ContractStateValue(42u128.to_be_bytes().to_vec()))
        );

        // Set then delete round-trips the value out of state.
        let tx = invoke_tx(&alice, 3, &manifest, kv_command::set(key, b"data"), 100_000);
        state.execute_transaction(&tx, &config).expect("set");
        assert_eq!(
            state.contract_state.get(&(namespace, key)),
            Some(&ContractStateValue(b"data".to_vec()))
        );
        let tx = invoke_tx(&alice, 4, &manifest, kv_command::delete(key), 100_000);
        state.execute_transaction(&tx, &config).expect("delete");
        assert!(!state.contract_state.contains_key(&(namespace, key)));
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn invoke_contract_fails_closed_on_undeclared_key() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let manifest = kv_manifest(code_id, namespace, alice.address());
        register_kv(&mut state, &config, &alice, 0, manifest.clone()).expect("register");

        // The handler references a key OUTSIDE the declared footprint: the
        // ContractContext rejects it (via the shared recorder discipline) and the
        // whole transaction rolls back atomically.
        let stranger = Hash256([0x99; 32]);
        let tx = invoke_tx(
            &alice,
            1,
            &manifest,
            kv_command::increment(stranger, 1),
            100_000,
        );
        let snapshot = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::ContractUndeclaredKey)
        ));
        assert_eq!(state, snapshot, "undeclared access leaves state unchanged");
    }

    #[test]
    fn invoke_contract_fails_closed_when_access_list_omits_a_footprint_key() {
        // Directly exercises the StateAccessRecorder reuse: a signed access list
        // that omits a declared footprint key fails closed when the runtime records
        // the whole footprint through the recorder.
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        // A two-key footprint so one key can be dropped from the access list.
        let manifest = ContractManifest::new(
            code_id,
            namespace,
            BuiltinContract::KeyValue,
            [Hash256([0x21; 32]), Hash256([0x22; 32])],
            alice.address(),
        );
        register_kv(&mut state, &config, &alice, 0, manifest.clone()).expect("register");

        let dropped = StateKey::application(namespace, manifest.footprint[1]);
        let mut tx = invoke_tx(
            &alice,
            1,
            &manifest,
            kv_command::set(manifest.footprint[0], b"x"),
            100_000,
        );
        tx.access_list.read_write.retain(|key| key != &dropped);
        tx.sign(&alice).expect("re-sign truncated access list");
        let snapshot = state.clone();
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::ContractUndeclaredKey)
        ));
        assert_eq!(state, snapshot);
    }

    #[test]
    fn invoke_contract_over_gas_rolls_back_atomically() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let manifest = kv_manifest(code_id, namespace, alice.address());
        let key = manifest.footprint[0];
        register_kv(&mut state, &config, &alice, 0, manifest.clone()).expect("register");

        // Seed a value so the state is non-trivially present before the over-gas call.
        let tx = invoke_tx(&alice, 1, &manifest, kv_command::set(key, b"seed"), 100_000);
        state.execute_transaction(&tx, &config).expect("seed set");
        let snapshot = state.clone();

        // A gas limit just above the admission cost cannot cover the metered
        // per-host-op consumption, so the call aborts with ContractOutOfGas and the
        // whole transaction (including its fee) rolls back — state is unchanged.
        let op = Operation::InvokeContract {
            code_id,
            namespace,
            declared_keys: manifest.footprint.clone(),
            input: kv_command::increment(key, 1),
        };
        let admission = op.required_units();
        let tx = invoke_tx(
            &alice,
            2,
            &manifest,
            kv_command::increment(key, 1),
            admission + 100,
        );
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::ContractOutOfGas)
        ));
        assert_eq!(state, snapshot, "over-gas call leaves state unchanged");
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn contracts_in_different_namespaces_parallelize_while_same_serializes() {
        let (config, mut state, alice, bob, carol) = contract_fixture();
        let ns_a = Hash256([0x11; 32]);
        let ns_b = Hash256([0x22; 32]);
        let manifest_a = kv_manifest(Hash256([0xaa; 32]), ns_a, alice.address());
        let manifest_b = kv_manifest(Hash256([0xbb; 32]), ns_b, alice.address());
        register_kv(&mut state, &config, &alice, 0, manifest_a.clone()).expect("register A");
        register_kv(&mut state, &config, &alice, 1, manifest_b.clone()).expect("register B");
        let key_a = manifest_a.footprint[0];
        let key_b = manifest_b.footprint[0];

        // Two invocations of DIFFERENT contracts in different namespaces, from
        // different senders, share no read_write key -> one parallel batch.
        let inv_a = invoke_tx(
            &bob,
            0,
            &manifest_a,
            kv_command::increment(key_a, 1),
            100_000,
        );
        let inv_b = invoke_tx(
            &carol,
            0,
            &manifest_b,
            kv_command::increment(key_b, 1),
            100_000,
        );
        let batches = crate::parallel_batches(&[inv_a.clone(), inv_b]);
        assert_eq!(batches.len(), 1, "disjoint-namespace contracts parallelize");

        // Two invocations of the SAME contract, from different senders, both write
        // its application state key -> they must serialize into two batches.
        let inv_a2 = invoke_tx(
            &carol,
            0,
            &manifest_a,
            kv_command::increment(key_a, 1),
            100_000,
        );
        let batches = crate::parallel_batches(&[inv_a, inv_a2]);
        assert_eq!(
            batches.len(),
            2,
            "same-contract invocations serialize on the shared footprint key"
        );
    }

    #[test]
    fn supply_reconciles_across_register_and_invoke() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let manifest = kv_manifest(code_id, namespace, alice.address());
        let key = manifest.footprint[0];
        assert!(state.supply_invariant_report().unwrap().balanced);
        register_kv(&mut state, &config, &alice, 0, manifest.clone()).expect("register");
        assert!(state.supply_invariant_report().unwrap().balanced);
        for (nonce, input) in [
            (1, kv_command::increment(key, 3)),
            (2, kv_command::set(key, b"hello world")),
            (3, kv_command::delete(key)),
        ] {
            let tx = invoke_tx(&alice, nonce, &manifest, input, 100_000);
            state.execute_transaction(&tx, &config).expect("invoke");
            assert!(state.supply_invariant_report().unwrap().balanced);
        }
    }

    #[test]
    fn bincode_restart_preserves_contract_registry_and_state_root() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let manifest = kv_manifest(code_id, namespace, alice.address());
        let key = manifest.footprint[0];
        register_kv(&mut state, &config, &alice, 0, manifest.clone()).expect("register");
        let tx = invoke_tx(&alice, 1, &manifest, kv_command::increment(key, 9), 100_000);
        state.execute_transaction(&tx, &config).expect("invoke");

        let restored = bincode_restart(&state);
        assert_eq!(
            restored.contracts, state.contracts,
            "restart preserves the contract registry"
        );
        assert_eq!(
            restored.contract_state, state.contract_state,
            "restart preserves contract state"
        );
        assert_eq!(restored, state, "restart preserves full state");
        assert_eq!(
            restored.state_root().expect("restored root"),
            state.state_root().expect("root"),
            "the contract registry and state are committed by the state root across a restart"
        );
    }

    #[test]
    fn contract_registry_and_state_are_committed_by_the_state_root() {
        // E8 extension: the contract registry and contract state maps are committed
        // consensus fields (via the contract_root / contract_state_root sub-roots),
        // so registering a contract or writing contract state must change the state
        // root. Otherwise two nodes could diverge on contract state yet share a root.
        let (_config, base, alice, ..) = contract_fixture();
        let root = base.state_root().unwrap();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let key = Hash256([0xa1; 32]);

        let mut with_contract = base.clone();
        with_contract
            .contracts
            .insert(code_id, kv_manifest(code_id, namespace, alice.address()));
        assert_ne!(
            with_contract.state_root().unwrap(),
            root,
            "registering a contract must change the state root (E8)"
        );

        let mut with_state = with_contract.clone();
        with_state
            .contract_state
            .insert((namespace, key), ContractStateValue(vec![1, 2, 3]));
        assert_ne!(
            with_state.state_root().unwrap(),
            with_contract.state_root().unwrap(),
            "writing contract state must change the state root (E8)"
        );
    }

    #[test]
    fn contract_execution_is_deterministic_across_runs() {
        let build = || {
            let (config, mut state, alice, ..) = contract_fixture();
            let code_id = Hash256([0xc0; 32]);
            let namespace = Hash256([0x11; 32]);
            let manifest = kv_manifest(code_id, namespace, alice.address());
            let key = manifest.footprint[0];
            register_kv(&mut state, &config, &alice, 0, manifest.clone()).expect("register");
            for (nonce, delta) in [(1u64, 7u128), (2, 35)] {
                let tx = invoke_tx(
                    &alice,
                    nonce,
                    &manifest,
                    kv_command::increment(key, delta),
                    100_000,
                );
                state.execute_transaction(&tx, &config).expect("invoke");
            }
            state.state_root().expect("root")
        };
        assert_eq!(
            build(),
            build(),
            "identical inputs produce an identical root"
        );
    }

    // ----- untrusted-bytecode WASM contract runtime (Phase 7b, ADR-0014 (a)) -----
    //
    // These tests drive REAL WebAssembly modules (compiled from WAT at test time)
    // end-to-end through register -> invoke on the deterministic engine, proving the
    // whole stack: input delivery, host state get/set over the declared footprint,
    // gas metering against the sender's limit, atomic rollback, state-root
    // commitment, and cross-node determinism.

    /// The 32-byte declared key both WASM fixtures operate on, as WAT `\xx` data
    /// escapes for a `(data ...)` segment.
    fn wasm_key() -> Hash256 {
        Hash256([0xa1; 32])
    }

    fn wasm_key_escapes(k: Hash256) -> String {
        k.0.iter().map(|b| format!("\\{b:02x}")).collect()
    }

    /// A real WASM contract: copies the call `input` into the declared key and
    /// echoes it back. Exercises `webc_input_read`, `webc_set`, `webc_output`.
    fn store_and_echo_module() -> WasmBytecode {
        let wat = format!(
            r#"(module
              (import "webc" "webc_input_len" (func $input_len (result i32)))
              (import "webc" "webc_input_read" (func $input_read (param i32)))
              (import "webc" "webc_set" (func $set (param i32 i32 i32 i32) (result i32)))
              (import "webc" "webc_output" (func $output (param i32 i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "{key}")
              (func (export "webc_call")
                (local $len i32)
                (local.set $len (call $input_len))
                (call $input_read (i32.const 64))
                (drop (call $set (i32.const 0) (i32.const 32) (i32.const 64) (local.get $len)))
                (call $output (i32.const 64) (local.get $len))))"#,
            key = wasm_key_escapes(wasm_key())
        );
        WasmBytecode(wat::parse_str(&wat).expect("valid store/echo WAT"))
    }

    /// A real, STATEFUL WASM contract: an 8-byte little-endian counter persisted in
    /// the declared key, incremented by one each call. Exercises `webc_get`
    /// (including the absent `-1` path), integer arithmetic, `webc_set`, and
    /// persistence across separate transactions.
    fn counter_module() -> WasmBytecode {
        let wat = format!(
            r#"(module
              (import "webc" "webc_get" (func $get (param i32 i32 i32 i32) (result i32)))
              (import "webc" "webc_set" (func $set (param i32 i32 i32 i32) (result i32)))
              (import "webc" "webc_output" (func $output (param i32 i32)))
              (memory (export "memory") 1)
              (data (i32.const 0) "{key}")
              (func (export "webc_call")
                (local $rc i32)
                (local.set $rc
                  (call $get (i32.const 0) (i32.const 32) (i32.const 64) (i32.const 8)))
                (if (i32.eq (local.get $rc) (i32.const -1))
                  (then (i64.store (i32.const 64) (i64.const 0))))
                (i64.store (i32.const 64)
                  (i64.add (i64.load (i32.const 64)) (i64.const 1)))
                (drop (call $set (i32.const 0) (i32.const 32) (i32.const 64) (i32.const 8)))
                (call $output (i32.const 64) (i32.const 8))))"#,
            key = wasm_key_escapes(wasm_key())
        );
        WasmBytecode(wat::parse_str(&wat).expect("valid counter WAT"))
    }

    fn wasm_manifest(
        code_id: Hash256,
        namespace: Hash256,
        owner: Address,
        code: &WasmBytecode,
    ) -> WasmContractManifest {
        WasmContractManifest::new(code_id, namespace, code.code_hash(), [wasm_key()], owner)
    }

    fn register_wasm(
        state: &mut ChainState,
        config: &ChainConfig,
        keypair: &Keypair,
        nonce: u64,
        manifest: WasmContractManifest,
        code: WasmBytecode,
    ) -> Result<Receipt, ChainError> {
        let tx = Transaction::for_operation(
            keypair,
            nonce,
            Operation::RegisterWasmContract { manifest, code },
            FeeBid {
                gas_limit: 500_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("register-wasm tx signs");
        state.execute_transaction(&tx, config)
    }

    fn invoke_wasm_tx(
        keypair: &Keypair,
        nonce: u64,
        manifest: &WasmContractManifest,
        input: Vec<u8>,
        gas_limit: u64,
    ) -> Transaction {
        Transaction::for_operation(
            keypair,
            nonce,
            Operation::InvokeWasmContract {
                code_id: manifest.code_id,
                namespace: manifest.namespace,
                declared_keys: manifest.footprint.clone(),
                input,
            },
            FeeBid {
                gas_limit,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("invoke-wasm tx signs")
    }

    #[test]
    fn register_wasm_contract_charges_fee_and_rejects_duplicate() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let code = store_and_echo_module();
        let manifest = wasm_manifest(code_id, namespace, alice.address(), &code);
        let burned_before = state.burned_fees.0;

        register_wasm(
            &mut state,
            &config,
            &alice,
            0,
            manifest.clone(),
            code.clone(),
        )
        .expect("register wasm");
        assert_eq!(state.wasm_contracts.get(&code_id), Some(&manifest));
        assert_eq!(state.wasm_code.get(&code_id), Some(&code));
        // The registration fee (plus half the tx fee) was burned.
        assert!(state.burned_fees.0 >= burned_before + config.contracts.registration_fee.0);
        assert!(state.supply_invariant_report().unwrap().balanced);

        // A duplicate code id is rejected and leaves state unchanged.
        let snapshot = state.clone();
        assert!(matches!(
            register_wasm(&mut state, &config, &alice, 1, manifest, code),
            Err(ChainError::ContractAlreadyExists)
        ));
        assert_eq!(state, snapshot, "rejected duplicate leaves state unchanged");
    }

    #[test]
    fn register_wasm_and_native_share_one_code_id_namespace() {
        // Native and wasm contracts address their record by the SAME
        // StateKey::module(code_id), so a code_id must be unique across both paths.
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let code = store_and_echo_module();

        // Register a native contract first, then a wasm contract reusing its id.
        register_kv(
            &mut state,
            &config,
            &alice,
            0,
            kv_manifest(code_id, namespace, alice.address()),
        )
        .expect("register native");
        let snapshot = state.clone();
        assert!(matches!(
            register_wasm(
                &mut state,
                &config,
                &alice,
                1,
                wasm_manifest(code_id, namespace, alice.address(), &code),
                code.clone(),
            ),
            Err(ChainError::ContractAlreadyExists)
        ));
        assert_eq!(state, snapshot);
    }

    #[test]
    fn register_wasm_contract_rejects_bad_manifest_and_module() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let code = store_and_echo_module();

        // A module the deterministic engine refuses (not wasm at all).
        let garbage = WasmBytecode(vec![1, 2, 3, 4, 5]);
        let garbage_manifest = wasm_manifest(code_id, namespace, alice.address(), &garbage);
        assert!(matches!(
            register_wasm(&mut state, &config, &alice, 0, garbage_manifest, garbage),
            Err(ChainError::InvalidWasmModule)
        ));

        // A manifest whose code_hash does not match the uploaded bytes.
        let mut mismatched = wasm_manifest(code_id, namespace, alice.address(), &code);
        mismatched.code_hash = Hash256([0xff; 32]);
        assert!(matches!(
            register_wasm(&mut state, &config, &alice, 0, mismatched, code.clone()),
            Err(ChainError::WasmCodeHashMismatch)
        ));

        // A manifest whose owner is not the registrant.
        let bob = Keypair::from_seed([2u8; 32]);
        let wrong_owner = wasm_manifest(code_id, namespace, bob.address(), &code);
        assert!(matches!(
            register_wasm(&mut state, &config, &alice, 0, wrong_owner, code),
            Err(ChainError::InvalidContractManifest)
        ));
        // Every rejection left the registry empty.
        assert!(state.wasm_contracts.is_empty());
        assert!(state.wasm_code.is_empty());
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn invoke_wasm_contract_runs_module_and_commits_state() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let code = store_and_echo_module();
        let manifest = wasm_manifest(code_id, namespace, alice.address(), &code);
        register_wasm(&mut state, &config, &alice, 0, manifest.clone(), code).expect("register");

        let tx = invoke_wasm_tx(&alice, 1, &manifest, b"hello wasm".to_vec(), 10_000_000);
        let receipt = state
            .execute_transaction(&tx, &config)
            .expect("invoke wasm");

        // The module stored its input under the declared key.
        assert_eq!(
            state.contract_state.get(&(namespace, wasm_key())),
            Some(&ContractStateValue(b"hello wasm".to_vec()))
        );
        // A WasmContractInvoked event reports the echoed output length and real gas.
        let invoked = receipt
            .events
            .iter()
            .find_map(|event| match event {
                Event::WasmContractInvoked {
                    code_id: c,
                    gas_consumed,
                    output_len,
                    ..
                } if *c == code_id => Some((*gas_consumed, *output_len)),
                _ => None,
            })
            .expect("WasmContractInvoked event");
        assert_eq!(invoked.1, 10, "echoed output is the 10-byte input");
        assert!(invoked.0 > 0, "the call metered real gas");
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn invoke_wasm_counter_accumulates_state_across_calls() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc7; 32]);
        let namespace = Hash256([0x33; 32]);
        let code = counter_module();
        let manifest = wasm_manifest(code_id, namespace, alice.address(), &code);
        register_wasm(&mut state, &config, &alice, 0, manifest.clone(), code).expect("register");

        // Three calls increment a persistent little-endian u64 counter 1 -> 2 -> 3.
        for (nonce, expected) in [(1u64, 1u64), (2, 2), (3, 3)] {
            let tx = invoke_wasm_tx(&alice, nonce, &manifest, Vec::new(), 10_000_000);
            state
                .execute_transaction(&tx, &config)
                .expect("invoke counter");
            assert_eq!(
                state.contract_state.get(&(namespace, wasm_key())),
                Some(&ContractStateValue(expected.to_le_bytes().to_vec())),
                "counter persisted across calls"
            );
        }
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn invoke_wasm_contract_over_gas_rolls_back_atomically() {
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let code = store_and_echo_module();
        let manifest = wasm_manifest(code_id, namespace, alice.address(), &code);
        register_wasm(&mut state, &config, &alice, 0, manifest.clone(), code).expect("register");
        let snapshot = state.clone();

        // A gas limit just above the admission cost cannot cover the module's
        // metered compute + state write, so the call fails closed and the whole
        // transaction (including its fee) rolls back — state is unchanged.
        let op = Operation::InvokeWasmContract {
            code_id,
            namespace,
            declared_keys: manifest.footprint.clone(),
            input: b"data".to_vec(),
        };
        let admission = op.required_units();
        let tx = invoke_wasm_tx(&alice, 1, &manifest, b"data".to_vec(), admission + 100);
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::ContractOutOfGas)
        ));
        assert_eq!(state, snapshot, "over-gas wasm call leaves state unchanged");
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn invoke_wasm_contract_fails_closed_on_undeclared_key() {
        // The module hard-codes a write to wasm_key(); declaring a DIFFERENT
        // footprint makes that write undeclared, so the ContractContext rejects it
        // and the whole transaction rolls back atomically.
        let (config, mut state, alice, ..) = contract_fixture();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let code = store_and_echo_module();
        let manifest = WasmContractManifest::new(
            code_id,
            namespace,
            code.code_hash(),
            [Hash256([0xb2; 32])],
            alice.address(),
        );
        register_wasm(&mut state, &config, &alice, 0, manifest.clone(), code).expect("register");
        let snapshot = state.clone();

        let tx = invoke_wasm_tx(&alice, 1, &manifest, b"x".to_vec(), 10_000_000);
        assert!(matches!(
            state.execute_transaction(&tx, &config),
            Err(ChainError::ContractUndeclaredKey)
        ));
        assert_eq!(
            state, snapshot,
            "undeclared wasm access leaves state unchanged"
        );
    }

    #[test]
    fn wasm_registry_is_committed_by_the_state_root() {
        // The wasm registry and bytecode maps are committed consensus fields (via the
        // wasm_contract_root / wasm_code_root sub-roots), so registering a wasm
        // contract must change the state root.
        let (config, mut state, alice, ..) = contract_fixture();
        let root_before = state.state_root().unwrap();
        let code_id = Hash256([0xc0; 32]);
        let namespace = Hash256([0x11; 32]);
        let code = store_and_echo_module();
        let manifest = wasm_manifest(code_id, namespace, alice.address(), &code);
        register_wasm(&mut state, &config, &alice, 0, manifest, code).expect("register");
        assert_ne!(
            state.state_root().unwrap(),
            root_before,
            "registering a wasm contract must change the state root"
        );

        // A bincode restart preserves the wasm registry, bytecode, and root.
        let restored = bincode_restart(&state);
        assert_eq!(restored.wasm_contracts, state.wasm_contracts);
        assert_eq!(restored.wasm_code, state.wasm_code);
        assert_eq!(
            restored.state_root().expect("restored root"),
            state.state_root().expect("root"),
            "the wasm registry and bytecode are committed across a restart"
        );
    }

    #[test]
    fn wasm_contract_execution_is_deterministic_across_runs() {
        let build = || {
            let (config, mut state, alice, ..) = contract_fixture();
            let code_id = Hash256([0xc7; 32]);
            let namespace = Hash256([0x33; 32]);
            let code = counter_module();
            let manifest = wasm_manifest(code_id, namespace, alice.address(), &code);
            register_wasm(&mut state, &config, &alice, 0, manifest.clone(), code)
                .expect("register");
            for nonce in 1..=3u64 {
                let tx = invoke_wasm_tx(&alice, nonce, &manifest, Vec::new(), 10_000_000);
                state.execute_transaction(&tx, &config).expect("invoke");
            }
            state.state_root().expect("root")
        };
        assert_eq!(
            build(),
            build(),
            "identical wasm inputs produce an identical root across nodes"
        );
    }

    // ----- native DEX batch settlement (Phase 8, §15.13/§15.18/§15.37) -----

    use crate::block_builder::{apply_block, build_block, BlockBuildInput};
    use crate::dex::{OrderId, OrderSide, Price, TradingPair};
    use crate::Block;

    /// One external (bridged) asset used as a DEX pair leg in tests.
    fn ext_asset(tag: u8) -> AssetId {
        AssetId::External {
            origin_chain: ExternalChain::Ethereum,
            symbol: format!("EXT{tag}"),
            contract_or_mint: format!("0x{tag:02x}"),
        }
    }

    fn order_id(tag: u8) -> OrderId {
        OrderId::new(Hash256([tag; 32]))
    }

    /// A DEX-tuned config: no epoch rollover noise, an optional per-fill fee.
    fn dex_config(fee_bps: u16) -> ChainConfig {
        let mut config = ChainConfig {
            dex: DexConfig {
                min_order_amount: Amount::ZERO,
                default_deadline_blocks: 5,
                fee_bps,
            },
            ..ChainConfig::default()
        };
        // Disable the height-boundary epoch rollover so a DEX block advances only
        // DEX state (no reward minting), keeping the supply-invariant assertions
        // about exactly the order flow.
        config.staking.blocks_per_epoch = 0;
        config
    }

    /// Genesis funding four native accounts and seeding each with `ext_units` of
    /// two external assets, so any of them can be a buyer (locks native) or a
    /// seller (locks the external base).
    fn dex_fixture(
        config: &ChainConfig,
        ext_units: u128,
    ) -> (ChainState, Keypair, Keypair, Keypair, Keypair) {
        let alice = Keypair::from_seed([1u8; 32]);
        let bob = Keypair::from_seed([2u8; 32]);
        let carol = Keypair::from_seed([3u8; 32]);
        let dave = Keypair::from_seed([4u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: [&alice, &bob, &carol, &dave]
                .iter()
                .map(|kp| GenesisAccount {
                    address: kp.address(),
                    balance: Amount::from_webc(1_000),
                })
                .collect(),
            validators: Vec::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).expect("dex genesis");
        // Seed external-asset balances directly (bridged assets are not part of the
        // native supply invariant, so this does not disturb `balanced`).
        for kp in [&alice, &bob, &carol, &dave] {
            for tag in [1u8, 2] {
                state.asset_balances.insert(
                    (ext_asset(tag), kp.address()),
                    Amount::from_units(ext_units),
                );
            }
        }
        (state, alice, bob, carol, dave)
    }

    #[allow(clippy::too_many_arguments)]
    fn submit_order(
        keypair: &Keypair,
        nonce: u64,
        id: OrderId,
        pair: TradingPair,
        side: OrderSide,
        amount: u128,
        price: u128,
        deadline_height: u64,
        fill_or_cancel: bool,
    ) -> Transaction {
        Transaction::for_operation(
            keypair,
            nonce,
            Operation::SubmitOrder {
                order_id: id,
                pair,
                side,
                amount: Amount::from_units(amount),
                limit_price: Price::new(price),
                deadline_height,
                fill_or_cancel,
            },
            FeeBid {
                gas_limit: 20_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("submit order signs")
    }

    fn cancel_order(keypair: &Keypair, nonce: u64, id: OrderId) -> Transaction {
        Transaction::for_operation(
            keypair,
            nonce,
            Operation::CancelOrder { order_id: id },
            FeeBid {
                gas_limit: 20_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("cancel order signs")
    }

    /// Builds one block at `height` carrying `txs`, running the DEX batch pass.
    fn dex_block(
        state: &mut ChainState,
        config: &ChainConfig,
        height: u64,
        txs: Vec<Transaction>,
    ) -> Result<Block, ChainError> {
        build_block(
            state,
            config,
            BlockBuildInput {
                chain_id: config.chain_id.clone(),
                height,
                epoch: 0,
                previous_hash: Hash256::ZERO,
                proposer: Keypair::from_seed([1u8; 32]).address(),
                timestamp_ms: height.saturating_mul(1_000).max(1),
            },
            txs,
            Vec::new(),
        )
    }

    fn native_balance(state: &ChainState, addr: Address) -> Amount {
        state
            .accounts
            .get(&addr)
            .map(|a| a.balance)
            .unwrap_or(Amount::ZERO)
    }

    fn ext_balance(state: &ChainState, asset: &AssetId, addr: Address) -> Amount {
        state
            .asset_balances
            .get(&(asset.clone(), addr))
            .copied()
            .unwrap_or(Amount::ZERO)
    }

    #[test]
    fn crossing_orders_fill_at_one_uniform_price_and_supply_balances() {
        // Pair (base = EXT1, quote = native WEBC): a buyer locks native, a seller
        // locks EXT. A buy 100 @ 10 and a sell 100 @ 8 cross; the marginal spread
        // [8, 10] clears at the midpoint 9, both fully fill in the same block.
        // Driven through `settle_dex_batch` directly so the settlement events can be
        // inspected (the block path discards them like oracle-settlement events).
        let config = dex_config(0);
        let (mut state, alice, bob, _c, _d) = dex_fixture(&config, 1_000);
        state.current_height = 1;
        let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        let alice_native_before = native_balance(&state, alice.address());
        let bob_native_before = native_balance(&state, bob.address());

        state
            .execute_transaction(
                &submit_order(
                    &alice,
                    0,
                    order_id(1),
                    pair.clone(),
                    OrderSide::Buy,
                    100,
                    10,
                    50,
                    false,
                ),
                &config,
            )
            .expect("alice submits");
        state
            .execute_transaction(
                &submit_order(
                    &bob,
                    0,
                    order_id(2),
                    pair.clone(),
                    OrderSide::Sell,
                    100,
                    8,
                    50,
                    false,
                ),
                &config,
            )
            .expect("bob submits");
        let events = state.settle_dex_batch(&config).expect("batch settles");

        // Both orders fully filled and removed.
        assert!(state.dex_orders.is_empty(), "both orders fully filled");
        assert_eq!(state.dex_escrow, Amount::ZERO, "escrow fully settled");

        // Every fill in the batch trades at the single clearing price 9.
        let clearing: Vec<Price> = events
            .iter()
            .filter_map(|e| match e {
                Event::OrderFilled { clearing_price, .. } => Some(*clearing_price),
                _ => None,
            })
            .collect();
        assert_eq!(clearing, vec![Price::new(9), Price::new(9)]);

        // Buyer received 100 EXT and paid 100*9 = 900 native (locked 1000, refunded
        // the 100 price improvement). Fees for this block are only the tx fees.
        assert_eq!(
            ext_balance(&state, &ext_asset(1), alice.address()),
            Amount::from_units(1_100)
        );
        let fee_per_submit = Amount::from_units(10_000); // 10_000 units * 1 base unit
        assert_eq!(
            native_balance(&state, alice.address()),
            alice_native_before
                .checked_sub(Amount::from_units(900))
                .and_then(|a| a.checked_sub(fee_per_submit))
                .unwrap()
        );
        // Seller delivered 100 EXT and received 900 native.
        assert_eq!(
            ext_balance(&state, &ext_asset(1), bob.address()),
            Amount::from_units(900)
        );
        assert_eq!(
            native_balance(&state, bob.address()),
            bob_native_before
                .checked_add(Amount::from_units(900))
                .and_then(|a| a.checked_sub(fee_per_submit))
                .unwrap()
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn non_crossing_orders_stay_pending_and_retry() {
        // Buy 100 @ 8 and sell 100 @ 10 do not cross; both stay pending across
        // blocks (chain-native retry) until a crossing order arrives.
        let config = dex_config(0);
        let (mut state, alice, bob, carol, _d) = dex_fixture(&config, 1_000);
        let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        dex_block(
            &mut state,
            &config,
            1,
            vec![
                submit_order(
                    &alice,
                    0,
                    order_id(1),
                    pair.clone(),
                    OrderSide::Buy,
                    100,
                    8,
                    50,
                    false,
                ),
                submit_order(
                    &bob,
                    0,
                    order_id(2),
                    pair.clone(),
                    OrderSide::Sell,
                    100,
                    10,
                    50,
                    false,
                ),
            ],
        )
        .expect("non-crossing block");
        assert_eq!(
            state.dex_orders.len(),
            2,
            "non-crossing orders stay pending"
        );

        // An empty block retries them; still no cross, still pending.
        dex_block(&mut state, &config, 2, Vec::new()).expect("retry block");
        assert_eq!(state.dex_orders.len(), 2);

        // Carol adds a crossing sell @ 8; now the buy @ 8 fills against it.
        dex_block(
            &mut state,
            &config,
            3,
            vec![submit_order(
                &carol,
                0,
                order_id(3),
                pair.clone(),
                OrderSide::Sell,
                100,
                8,
                50,
                false,
            )],
        )
        .expect("crossing block");
        // Alice's buy (100 @ 8) and Carol's sell (100 @ 8) cleared and were removed;
        // Bob's non-crossing sell @ 10 remains pending.
        assert!(!state.dex_orders.contains_key(&order_id(1)));
        assert!(!state.dex_orders.contains_key(&order_id(3)));
        assert!(state.dex_orders.contains_key(&order_id(2)));
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn short_side_is_rationed_prorata_with_no_dust_and_the_remainder_retries() {
        // Three buyers of 100 each (limit 10) against one seller of 100 (limit 8).
        // Demand 300 > supply 100, so buyers are rationed pro-rata to 100:
        // cumulative rounding gives [33, 33, 34], summing to exactly 100 (no dust).
        let config = dex_config(0);
        let (mut state, alice, bob, carol, dave) = dex_fixture(&config, 1_000);
        let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        dex_block(
            &mut state,
            &config,
            1,
            vec![
                submit_order(
                    &alice,
                    0,
                    order_id(1),
                    pair.clone(),
                    OrderSide::Buy,
                    100,
                    10,
                    50,
                    false,
                ),
                submit_order(
                    &bob,
                    0,
                    order_id(2),
                    pair.clone(),
                    OrderSide::Buy,
                    100,
                    10,
                    50,
                    false,
                ),
                submit_order(
                    &carol,
                    0,
                    order_id(3),
                    pair.clone(),
                    OrderSide::Buy,
                    100,
                    10,
                    50,
                    false,
                ),
                submit_order(
                    &dave,
                    0,
                    order_id(4),
                    pair.clone(),
                    OrderSide::Sell,
                    100,
                    8,
                    50,
                    false,
                ),
            ],
        )
        .expect("prorata block");

        // The seller fully filled and is gone; the three buyers keep pro-rata
        // remainders whose fills sum to exactly the 100 that traded.
        assert!(!state.dex_orders.contains_key(&order_id(4)));
        let fills: Vec<u128> = [order_id(1), order_id(2), order_id(3)]
            .iter()
            .map(|id| {
                let order = &state.dex_orders[id];
                Amount::from_units(100).0 - order.remaining.0
            })
            .collect();
        assert_eq!(fills, vec![33, 33, 34]);
        assert_eq!(fills.iter().sum::<u128>(), 100, "no dust lost");
        // Remainders retry: each buyer still has an order with the residual amount.
        for (id, filled) in [order_id(1), order_id(2), order_id(3)].iter().zip(&fills) {
            assert_eq!(
                state.dex_orders[id].remaining,
                Amount::from_units(100 - filled)
            );
        }
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn uniform_price_gives_no_participant_a_worse_price_than_a_peer() {
        // Two buyers with different limits (10 and 12) and one seller (8). Both
        // buyers trade at the identical clearing price — the aggressive buyer is not
        // charged more than the marginal one (no intra-block ordering advantage).
        let config = dex_config(0);
        let (mut state, alice, bob, carol, _d) = dex_fixture(&config, 1_000);
        state.current_height = 1;
        let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        for tx in [
            submit_order(
                &alice,
                0,
                order_id(1),
                pair.clone(),
                OrderSide::Buy,
                100,
                10,
                50,
                false,
            ),
            submit_order(
                &carol,
                0,
                order_id(3),
                pair.clone(),
                OrderSide::Buy,
                100,
                12,
                50,
                false,
            ),
            submit_order(
                &bob,
                0,
                order_id(2),
                pair.clone(),
                OrderSide::Sell,
                100,
                8,
                50,
                false,
            ),
        ] {
            state.execute_transaction(&tx, &config).expect("submit");
        }
        let events = state.settle_dex_batch(&config).expect("batch settles");

        // Both buy fills carry the same clearing price and the same per-unit quote.
        let buy_fills: Vec<(Price, u128, u128)> = events
            .iter()
            .filter_map(|e| match e {
                Event::OrderFilled {
                    side: OrderSide::Buy,
                    clearing_price,
                    filled,
                    quote,
                    ..
                } => Some((*clearing_price, filled.0, quote.0)),
                _ => None,
            })
            .collect::<Vec<(Price, u128, u128)>>();
        assert_eq!(buy_fills.len(), 2);
        let price = buy_fills[0].0;
        for (p, filled, quote) in &buy_fills {
            assert_eq!(*p, price, "both buyers clear at one uniform price");
            // Per-unit price is identical: quote == filled * clearing_price.
            assert_eq!(*quote, filled * price.get());
        }
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn fill_or_cancel_cancels_an_unfilled_order_same_block() {
        // A fill-or-cancel buy with no crossing counter-order is cancelled and fully
        // refunded in the same block it is submitted.
        let config = dex_config(0);
        let (mut state, alice, _b, _c, _d) = dex_fixture(&config, 1_000);
        let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        let before = native_balance(&state, alice.address());
        dex_block(
            &mut state,
            &config,
            1,
            vec![submit_order(
                &alice,
                0,
                order_id(1),
                pair.clone(),
                OrderSide::Buy,
                100,
                8,
                50,
                true,
            )],
        )
        .expect("foc block");
        assert!(
            state.dex_orders.is_empty(),
            "unfilled FoC order cancels same block"
        );
        assert_eq!(state.dex_escrow, Amount::ZERO);
        // Alice paid only the transaction fee; her 100*8 lock was refunded.
        assert_eq!(
            native_balance(&state, alice.address()),
            before.checked_sub(Amount::from_units(10_000)).unwrap()
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn fill_or_cancel_partial_fill_cancels_the_remainder_same_block() {
        // A FoC buy of 100 @ 10 against a sell of 40 @ 8: 40 fills at the clearing
        // price, the 60 remainder is cancelled and refunded the same block.
        let config = dex_config(0);
        let (mut state, alice, bob, _c, _d) = dex_fixture(&config, 1_000);
        let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        dex_block(
            &mut state,
            &config,
            1,
            vec![
                submit_order(
                    &alice,
                    0,
                    order_id(1),
                    pair.clone(),
                    OrderSide::Buy,
                    100,
                    10,
                    50,
                    true,
                ),
                submit_order(
                    &bob,
                    0,
                    order_id(2),
                    pair.clone(),
                    OrderSide::Sell,
                    40,
                    8,
                    50,
                    false,
                ),
            ],
        )
        .expect("foc partial block");
        // Both orders gone: the seller fully filled, the FoC buyer filled 40 and
        // cancelled the remaining 60.
        assert!(state.dex_orders.is_empty());
        assert_eq!(state.dex_escrow, Amount::ZERO);
        assert_eq!(
            ext_balance(&state, &ext_asset(1), alice.address()),
            Amount::from_units(1_040)
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn an_order_past_its_deadline_auto_refunds() {
        // An order with deadline height 1 settles in block 1 (no cross) then expires
        // at block 2, refunding its lock.
        let config = dex_config(0);
        let (mut state, alice, _b, _c, _d) = dex_fixture(&config, 1_000);
        let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        let before = native_balance(&state, alice.address());
        dex_block(
            &mut state,
            &config,
            1,
            vec![submit_order(
                &alice,
                0,
                order_id(1),
                pair.clone(),
                OrderSide::Buy,
                100,
                8,
                1,
                false,
            )],
        )
        .expect("submit block");
        assert!(
            state.dex_orders.contains_key(&order_id(1)),
            "still live on its deadline block"
        );

        dex_block(&mut state, &config, 2, Vec::new()).expect("expiry block");
        assert!(
            !state.dex_orders.contains_key(&order_id(1)),
            "expired past its deadline"
        );
        assert_eq!(state.dex_escrow, Amount::ZERO);
        assert_eq!(
            native_balance(&state, alice.address()),
            before.checked_sub(Amount::from_units(10_000)).unwrap(),
            "lock refunded on expiry; only the tx fee is spent"
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn cancel_refunds_the_locked_remainder() {
        // Submit in block 1, cancel in block 2; the batch pass refunds the lock.
        let config = dex_config(0);
        let (mut state, alice, _b, _c, _d) = dex_fixture(&config, 1_000);
        let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        let before = native_balance(&state, alice.address());
        dex_block(
            &mut state,
            &config,
            1,
            vec![submit_order(
                &alice,
                0,
                order_id(1),
                pair.clone(),
                OrderSide::Buy,
                100,
                8,
                50,
                false,
            )],
        )
        .expect("submit block");
        // Escrow holds the 100*8 = 800 native lock while the order is live.
        assert_eq!(state.dex_escrow, Amount::from_units(800));

        dex_block(
            &mut state,
            &config,
            2,
            vec![cancel_order(&alice, 1, order_id(1))],
        )
        .expect("cancel block");
        assert!(state.dex_orders.is_empty(), "cancelled order removed");
        assert_eq!(state.dex_escrow, Amount::ZERO);
        assert_eq!(
            native_balance(&state, alice.address()),
            before.checked_sub(Amount::from_units(20_000)).unwrap(),
            "lock refunded; two tx fees spent (submit + cancel)"
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn two_disjoint_pairs_settle_independently() {
        // A crossing pair on EXT1 and a crossing pair on EXT2 both settle in one
        // block without interacting.
        let config = dex_config(0);
        let (mut state, alice, bob, carol, dave) = dex_fixture(&config, 1_000);
        let pair1 = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        let pair2 = TradingPair::new(ext_asset(2), AssetId::NativeWebc);
        dex_block(
            &mut state,
            &config,
            1,
            vec![
                submit_order(
                    &alice,
                    0,
                    order_id(1),
                    pair1.clone(),
                    OrderSide::Buy,
                    100,
                    10,
                    50,
                    false,
                ),
                submit_order(
                    &bob,
                    0,
                    order_id(2),
                    pair1.clone(),
                    OrderSide::Sell,
                    100,
                    8,
                    50,
                    false,
                ),
                submit_order(
                    &carol,
                    0,
                    order_id(3),
                    pair2.clone(),
                    OrderSide::Buy,
                    50,
                    20,
                    50,
                    false,
                ),
                submit_order(
                    &dave,
                    0,
                    order_id(4),
                    pair2.clone(),
                    OrderSide::Sell,
                    50,
                    18,
                    50,
                    false,
                ),
            ],
        )
        .expect("two-pair block");
        // Both pairs fully cleared and every order was removed.
        assert!(state.dex_orders.is_empty());
        assert_eq!(state.dex_escrow, Amount::ZERO);
        // EXT1 traded 100 at pc 9; EXT2 traded 50 at pc 19.
        assert_eq!(
            ext_balance(&state, &ext_asset(1), alice.address()),
            Amount::from_units(1_100)
        );
        assert_eq!(
            ext_balance(&state, &ext_asset(2), carol.address()),
            Amount::from_units(1_050)
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn per_fill_fee_on_a_native_quote_is_split_and_supply_balances() {
        // With a 100 bps (1%) per-fill fee and a native quote, the seller's proceeds
        // are taxed and the fee is split 50/50 burn/validator. Supply still balances.
        let config = dex_config(100);
        let (mut state, alice, bob, _c, _d) = dex_fixture(&config, 1_000);
        let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        let burned_before = state.burned_fees;
        let pool_before = state.validator_fee_pool;
        dex_block(
            &mut state,
            &config,
            1,
            vec![
                submit_order(
                    &alice,
                    0,
                    order_id(1),
                    pair.clone(),
                    OrderSide::Buy,
                    100,
                    10,
                    50,
                    false,
                ),
                submit_order(
                    &bob,
                    0,
                    order_id(2),
                    pair.clone(),
                    OrderSide::Sell,
                    100,
                    8,
                    50,
                    false,
                ),
            ],
        )
        .expect("fee block");
        // Gross proceeds 100*9 = 900; fee 1% = 9; seller nets 891.
        // The 9-unit fee (split 4 burned / 5 validator) is on top of the two tx fees.
        let submit_fees_burned = Amount::from_units(10_000); // 2 tx * 5_000 burned half
        assert_eq!(
            state.burned_fees,
            burned_before
                .checked_add(submit_fees_burned)
                .and_then(|b| b.checked_add(Amount::from_units(4)))
                .unwrap()
        );
        assert_eq!(
            state.validator_fee_pool,
            pool_before
                .checked_add(Amount::from_units(10_000))
                .and_then(|p| p.checked_add(Amount::from_units(5)))
                .unwrap()
        );
        assert_eq!(state.dex_escrow, Amount::ZERO);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn settlement_is_deterministic_and_identical_on_build_and_import() {
        // The batch pass is a pure function of committed state + height, so a second
        // producer builds the identical block and an importer reproduces it exactly.
        let config = dex_config(30);
        let build_once = || {
            let (mut state, alice, bob, carol, dave) = dex_fixture(&config, 1_000);
            let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
            let block = dex_block(
                &mut state,
                &config,
                1,
                vec![
                    submit_order(
                        &alice,
                        0,
                        order_id(1),
                        pair.clone(),
                        OrderSide::Buy,
                        100,
                        10,
                        50,
                        false,
                    ),
                    submit_order(
                        &carol,
                        0,
                        order_id(3),
                        pair.clone(),
                        OrderSide::Buy,
                        70,
                        9,
                        50,
                        false,
                    ),
                    submit_order(
                        &bob,
                        0,
                        order_id(2),
                        pair.clone(),
                        OrderSide::Sell,
                        120,
                        8,
                        50,
                        false,
                    ),
                    submit_order(
                        &dave,
                        0,
                        order_id(4),
                        pair.clone(),
                        OrderSide::Sell,
                        30,
                        9,
                        50,
                        false,
                    ),
                ],
            )
            .expect("block builds");
            (state, block)
        };
        let (producer_a, block_a) = build_once();
        let (producer_b, block_b) = build_once();
        assert_eq!(block_a.header, block_b.header, "deterministic across runs");
        assert_eq!(
            producer_a.state_root().unwrap(),
            producer_b.state_root().unwrap()
        );

        // An importer re-executes the block onto fresh genesis and lands identically.
        let (mut importer, _a, _b, _c, _d) = dex_fixture(&config, 1_000);
        apply_block(&mut importer, &config, &block_a).expect("import");
        assert_eq!(
            importer.state_root().unwrap(),
            producer_a.state_root().unwrap(),
            "build == import"
        );
        assert_eq!(importer.dex_orders, producer_a.dex_orders);
        assert_eq!(importer.dex_escrow, producer_a.dex_escrow);
        assert!(importer.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn bincode_restart_preserves_orders_escrow_and_state_root() {
        // A crash-restart round trip through the on-disk bincode config must
        // preserve every live order, the escrow scalar, and the committed state root.
        let config = dex_config(0);
        let (mut state, alice, bob, carol, _d) = dex_fixture(&config, 1_000);
        let pair = TradingPair::new(ext_asset(1), AssetId::NativeWebc);
        // One partial fill (remainder retries) plus a pending non-crossing order, so
        // both a live remainder and escrow are non-trivial across the restart.
        dex_block(
            &mut state,
            &config,
            1,
            vec![
                submit_order(
                    &alice,
                    0,
                    order_id(1),
                    pair.clone(),
                    OrderSide::Buy,
                    100,
                    10,
                    50,
                    false,
                ),
                submit_order(
                    &bob,
                    0,
                    order_id(2),
                    pair.clone(),
                    OrderSide::Sell,
                    40,
                    8,
                    50,
                    false,
                ),
                submit_order(
                    &carol,
                    0,
                    order_id(3),
                    pair.clone(),
                    OrderSide::Sell,
                    100,
                    20,
                    50,
                    false,
                ),
            ],
        )
        .expect("mixed block");
        assert!(!state.dex_orders.is_empty());
        assert!(!state.dex_escrow.is_zero());

        let restored = bincode_restart(&state);
        assert_eq!(restored.dex_orders, state.dex_orders);
        assert_eq!(restored.dex_escrow, state.dex_escrow);
        assert_eq!(restored.current_height, state.current_height);
        assert_eq!(
            restored.state_root().unwrap(),
            state.state_root().unwrap(),
            "orders and escrow are committed by the state root across a restart"
        );
        assert!(restored.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn a_native_base_sell_locks_and_settles_through_dex_escrow() {
        // Orientation check: pair (base = native WEBC, quote = EXT). A sell of native
        // WEBC locks native into `dex_escrow`; the buyer pays EXT. Exercises the
        // native-base escrow routing (the mirror of the native-quote tests above).
        let config = dex_config(0);
        let (mut state, alice, bob, _c, _d) = dex_fixture(&config, 100_000);
        let pair = TradingPair::new(AssetId::NativeWebc, ext_asset(1));
        let bob_native_before = native_balance(&state, bob.address());
        dex_block(
            &mut state,
            &config,
            1,
            vec![
                // Bob sells 500 native WEBC @ 8 EXT each (locks 500 native).
                submit_order(
                    &bob,
                    0,
                    order_id(2),
                    pair.clone(),
                    OrderSide::Sell,
                    500,
                    8,
                    50,
                    false,
                ),
                // Alice buys 500 native WEBC @ 10 EXT each (locks 5000 EXT).
                submit_order(
                    &alice,
                    0,
                    order_id(1),
                    pair.clone(),
                    OrderSide::Buy,
                    500,
                    10,
                    50,
                    false,
                ),
            ],
        )
        .expect("native-base block");
        assert!(state.dex_orders.is_empty());
        assert_eq!(
            state.dex_escrow,
            Amount::ZERO,
            "native base escrow fully settled"
        );
        // Alice received 500 native WEBC; Bob delivered 500 (minus his tx fee).
        assert_eq!(
            native_balance(&state, alice.address()),
            // started 1000 WEBC, minus tx fee, plus 500 received.
            Amount::from_webc(1_000)
                .checked_sub(Amount::from_units(10_000))
                .and_then(|a| a.checked_add(Amount::from_units(500)))
                .unwrap()
        );
        assert_eq!(
            native_balance(&state, bob.address()),
            bob_native_before
                .checked_sub(Amount::from_units(500))
                .and_then(|a| a.checked_sub(Amount::from_units(10_000)))
                .unwrap()
        );
        // Alice paid 500*9 = 4500 EXT; Bob received 4500 EXT.
        assert_eq!(
            ext_balance(&state, &ext_asset(1), bob.address()),
            Amount::from_units(104_500)
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    // ----- native fungible tokens (Phase 13a, §15) -----

    /// The application namespace all native-token tests create under.
    fn token_namespace() -> Hash256 {
        Hash256([0x77; 32])
    }

    /// A valid sample token metadata record (name "Acme Dollar", symbol "ACME").
    fn sample_token_metadata() -> crate::TokenMetadata {
        crate::TokenMetadata::new(
            b"Acme Dollar".to_vec(),
            b"ACME".to_vec(),
            6,
            Hash256([0x1f; 32]),
        )
        .expect("valid metadata")
    }

    /// Genesis funding a token creator (also the default authority holder), a
    /// holder, and an outsider — all with room for the creation deposit + fees.
    fn token_fixture() -> (ChainConfig, ChainState, Keypair, Keypair, Keypair) {
        let config = ChainConfig::default();
        let creator = Keypair::from_seed([51u8; 32]);
        let holder = Keypair::from_seed([52u8; 32]);
        let outsider = Keypair::from_seed([53u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![
                GenesisAccount {
                    address: creator.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: holder.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: outsider.address(),
                    balance: Amount::from_webc(1_000),
                },
            ],
            validators: Vec::new(),
        };
        let state = ChainState::from_genesis(&genesis).expect("token genesis");
        (config, state, creator, holder, outsider)
    }

    /// The token units `addr` holds of `token_id` (0 when the entry is pruned).
    fn token_balance(state: &ChainState, token_id: TokenId, addr: Address) -> u128 {
        state
            .token_balances
            .get(&(token_id, addr))
            .map_or(0, |a| a.0)
    }

    /// Creates a token owned by `creator` and returns its derived id.
    #[allow(clippy::too_many_arguments)]
    fn create_token(
        state: &mut ChainState,
        config: &ChainConfig,
        creator: &Keypair,
        nonce: u64,
        create_nonce: u64,
        mint_authority: Option<Address>,
        freeze_authority: Option<Address>,
        initial_supply: Amount,
        initial_recipient: Address,
    ) -> Result<TokenId, ChainError> {
        mandate_exec(
            state,
            config,
            creator,
            nonce,
            Operation::CreateToken {
                namespace: token_namespace(),
                create_nonce,
                metadata: sample_token_metadata(),
                mint_authority,
                freeze_authority,
                initial_supply,
                initial_recipient,
            },
        )?;
        Ok(TokenId::derive(
            token_namespace(),
            creator.address(),
            create_nonce,
        ))
    }

    #[test]
    fn create_records_token_and_reads_back_with_supply_balanced() {
        let (config, mut state, creator, _holder, _outsider) = token_fixture();
        assert!(state.supply_invariant_report().unwrap().balanced);
        let creator_liquid_before = balance(&state, creator.address());
        let token_id = create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            Amount::from_units(1_000),
            creator.address(),
        )
        .expect("create succeeds");

        let record = state.tokens.get(&token_id).expect("token exists");
        assert_eq!(record.creator, creator.address());
        assert_eq!(record.mint_authority, Some(creator.address()));
        assert_eq!(record.freeze_authority, Some(creator.address()));
        assert!(!record.paused);
        assert_eq!(record.issued_supply, Amount::from_units(1_000));
        assert_eq!(record.metadata.symbol, b"ACME");
        // The initial supply is credited to the recipient.
        assert_eq!(token_balance(&state, token_id, creator.address()), 1_000);

        // The deposit is locked into token_deposits; native supply still balances
        // (only the deposit + fee left the creator's liquid balance — no WEBC minted
        // or burned by token creation).
        let deposit = config.token.creation_deposit;
        assert_eq!(state.token_deposits, deposit);
        let report = state.supply_invariant_report().unwrap();
        assert!(report.balanced);
        assert_eq!(report.token_deposits, deposit);
        assert!(balance(&state, creator.address()) < creator_liquid_before);

        // The per-token supply invariant holds: issued == held.
        let tok = state.token_supply_report(token_id).unwrap();
        assert!(tok.balanced);
        assert_eq!(tok.issued, Amount::from_units(1_000));
        assert_eq!(tok.held, Amount::from_units(1_000));
    }

    #[test]
    fn duplicate_token_id_is_rejected() {
        let (config, mut state, creator, _holder, _outsider) = token_fixture();
        create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            None,
            Amount::ZERO,
            creator.address(),
        )
        .expect("first create");
        // Same (namespace, creator, create_nonce) derives the same id: rejected.
        let before = state.clone();
        let err = create_token(
            &mut state,
            &config,
            &creator,
            1,
            0,
            Some(creator.address()),
            None,
            Amount::ZERO,
            creator.address(),
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenAlreadyExists));
        assert_eq!(state, before, "rejected duplicate leaves state unchanged");
    }

    #[test]
    fn over_length_metadata_and_bad_decimals_are_rejected_on_apply() {
        let (config, mut state, creator, _holder, _outsider) = token_fixture();
        let bad_create = |metadata: crate::TokenMetadata, nonce: u64| Operation::CreateToken {
            namespace: token_namespace(),
            create_nonce: nonce,
            metadata,
            mint_authority: Some(creator.address()),
            freeze_authority: None,
            initial_supply: Amount::ZERO,
            initial_recipient: creator.address(),
        };
        // Over-length name.
        let mut m = sample_token_metadata();
        m.name = vec![0x61; crate::MAX_TOKEN_NAME_BYTES + 1];
        let err = mandate_exec(&mut state, &config, &creator, 0, bad_create(m, 0)).unwrap_err();
        assert!(matches!(err, ChainError::InvalidTokenMetadata));
        // Over-length symbol.
        let mut m = sample_token_metadata();
        m.symbol = vec![0x61; crate::MAX_TOKEN_SYMBOL_BYTES + 1];
        let err = mandate_exec(&mut state, &config, &creator, 0, bad_create(m, 1)).unwrap_err();
        assert!(matches!(err, ChainError::InvalidTokenMetadata));
        // Out-of-range decimals.
        let mut m = sample_token_metadata();
        m.decimals = crate::MAX_TOKEN_DECIMALS + 1;
        let err = mandate_exec(&mut state, &config, &creator, 0, bad_create(m, 2)).unwrap_err();
        assert!(matches!(err, ChainError::InvalidTokenMetadata));
        // No token was recorded and no deposit was locked on any rejected create.
        assert!(state.tokens.is_empty());
        assert_eq!(state.token_deposits, Amount::ZERO);
    }

    #[test]
    fn mint_requires_authority_and_raises_supply() {
        let (config, mut state, creator, holder, outsider) = token_fixture();
        let token_id = create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            None,
            Amount::ZERO,
            creator.address(),
        )
        .expect("create");
        // A non-authority cannot mint.
        let before = state.clone();
        let err = mandate_exec(
            &mut state,
            &config,
            &outsider,
            0,
            Operation::MintToken {
                token_id,
                recipient: holder.address(),
                amount: Amount::from_units(500),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenMintNotAuthorized));
        assert_eq!(state, before, "rejected mint leaves state unchanged");
        // The authority mints: recipient credited, issued_supply raised.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::MintToken {
                token_id,
                recipient: holder.address(),
                amount: Amount::from_units(500),
            },
        )
        .expect("authority mint");
        assert_eq!(token_balance(&state, token_id, holder.address()), 500);
        assert_eq!(
            state.tokens.get(&token_id).unwrap().issued_supply,
            Amount::from_units(500)
        );
        // Both invariants hold, and no native WEBC was created by the mint.
        assert!(state.token_supply_report(token_id).unwrap().balanced);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn mint_to_frozen_account_is_rejected() {
        let (config, mut state, creator, holder, _outsider) = token_fixture();
        let token_id = create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            Amount::ZERO,
            creator.address(),
        )
        .expect("create");
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::FreezeTokenAccount {
                token_id,
                account: holder.address(),
            },
        )
        .expect("freeze");
        let before = state.clone();
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::MintToken {
                token_id,
                recipient: holder.address(),
                amount: Amount::from_units(100),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenAccountFrozen));
        assert_eq!(state, before, "rejected mint leaves state unchanged");
    }

    #[test]
    fn burn_reduces_holder_and_supply_with_guards() {
        let (config, mut state, creator, holder, _outsider) = token_fixture();
        let token_id = create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            Amount::from_units(1_000),
            holder.address(),
        )
        .expect("create");
        // Burning more than held is rejected.
        let before = state.clone();
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::BurnToken {
                token_id,
                amount: Amount::from_units(2_000),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenInsufficientBalance));
        assert_eq!(state, before, "rejected burn leaves state unchanged");
        // Burning while frozen is rejected.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::FreezeTokenAccount {
                token_id,
                account: holder.address(),
            },
        )
        .expect("freeze");
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::BurnToken {
                token_id,
                amount: Amount::from_units(100),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenAccountFrozen));
        // Thaw, then a burn reduces the holder AND the issued supply by the same.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::ThawTokenAccount {
                token_id,
                account: holder.address(),
            },
        )
        .expect("thaw");
        mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::BurnToken {
                token_id,
                amount: Amount::from_units(400),
            },
        )
        .expect("burn");
        assert_eq!(token_balance(&state, token_id, holder.address()), 600);
        assert_eq!(
            state.tokens.get(&token_id).unwrap().issued_supply,
            Amount::from_units(600)
        );
        assert!(state.token_supply_report(token_id).unwrap().balanced);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn transfer_moves_balance_prunes_zero_and_guards() {
        let (config, mut state, creator, holder, outsider) = token_fixture();
        let token_id = create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            Amount::from_units(1_000),
            holder.address(),
        )
        .expect("create");
        // Insufficient balance is rejected.
        let before = state.clone();
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::TransferToken {
                token_id,
                recipient: outsider.address(),
                amount: Amount::from_units(2_000),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenInsufficientBalance));
        assert_eq!(state, before, "rejected transfer leaves state unchanged");
        // A full-balance transfer moves the units and PRUNES the zero sender entry.
        mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::TransferToken {
                token_id,
                recipient: outsider.address(),
                amount: Amount::from_units(1_000),
            },
        )
        .expect("transfer all");
        assert_eq!(token_balance(&state, token_id, outsider.address()), 1_000);
        assert!(
            !state
                .token_balances
                .contains_key(&(token_id, holder.address())),
            "a sender balance that reaches zero is pruned"
        );
        // A transfer conserves supply: issued_supply is unchanged and both invariants
        // still hold.
        assert_eq!(
            state.tokens.get(&token_id).unwrap().issued_supply,
            Amount::from_units(1_000)
        );
        assert!(state.token_supply_report(token_id).unwrap().balanced);
        assert!(state.supply_invariant_report().unwrap().balanced);
        // Pausing rejects further transfers.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::SetTokenPaused {
                token_id,
                paused: true,
            },
        )
        .expect("pause");
        let err = mandate_exec(
            &mut state,
            &config,
            &outsider,
            0,
            Operation::TransferToken {
                token_id,
                recipient: holder.address(),
                amount: Amount::from_units(10),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenPaused));
        // Unpause, then a frozen RECIPIENT rejects the transfer.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::SetTokenPaused {
                token_id,
                paused: false,
            },
        )
        .expect("unpause");
        mandate_exec(
            &mut state,
            &config,
            &creator,
            3,
            Operation::FreezeTokenAccount {
                token_id,
                account: holder.address(),
            },
        )
        .expect("freeze recipient");
        let err = mandate_exec(
            &mut state,
            &config,
            &outsider,
            0,
            Operation::TransferToken {
                token_id,
                recipient: holder.address(),
                amount: Amount::from_units(10),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenAccountFrozen));
    }

    #[test]
    fn freeze_blocks_sending_and_thaw_restores_it() {
        let (config, mut state, creator, holder, outsider) = token_fixture();
        let token_id = create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            Amount::from_units(1_000),
            holder.address(),
        )
        .expect("create");
        // Freeze the SENDER: a transfer from it is rejected.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::FreezeTokenAccount {
                token_id,
                account: holder.address(),
            },
        )
        .expect("freeze");
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::TransferToken {
                token_id,
                recipient: outsider.address(),
                amount: Amount::from_units(100),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenAccountFrozen));
        // Thaw: the transfer now succeeds.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::ThawTokenAccount {
                token_id,
                account: holder.address(),
            },
        )
        .expect("thaw");
        mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::TransferToken {
                token_id,
                recipient: outsider.address(),
                amount: Amount::from_units(100),
            },
        )
        .expect("transfer after thaw");
        assert_eq!(token_balance(&state, token_id, outsider.address()), 100);
        assert_eq!(token_balance(&state, token_id, holder.address()), 900);
        assert!(state.token_supply_report(token_id).unwrap().balanced);
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn authority_transfer_moves_control_and_renounce_is_permanent() {
        let (config, mut state, creator, holder, outsider) = token_fixture();
        let token_id = create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            Amount::ZERO,
            creator.address(),
        )
        .expect("create");
        // Transfer the mint authority from creator to holder.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::SetTokenAuthority {
                token_id,
                authority_kind: crate::TokenAuthorityKind::Mint,
                new_authority: Some(holder.address()),
            },
        )
        .expect("transfer mint authority");
        assert_eq!(
            state.tokens.get(&token_id).unwrap().mint_authority,
            Some(holder.address())
        );
        // The OLD authority (creator) can no longer mint.
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::MintToken {
                token_id,
                recipient: creator.address(),
                amount: Amount::from_units(1),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenMintNotAuthorized));
        // The NEW authority (holder) can mint.
        mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::MintToken {
                token_id,
                recipient: holder.address(),
                amount: Amount::from_units(50),
            },
        )
        .expect("new authority mint");
        // A non-authority cannot transfer/renounce the authority.
        let err = mandate_exec(
            &mut state,
            &config,
            &outsider,
            0,
            Operation::SetTokenAuthority {
                token_id,
                authority_kind: crate::TokenAuthorityKind::Mint,
                new_authority: Some(outsider.address()),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenAuthorityNotAuthorized));
        // The current authority (holder) RENOUNCES minting: Some -> None, permanent.
        mandate_exec(
            &mut state,
            &config,
            &holder,
            1,
            Operation::SetTokenAuthority {
                token_id,
                authority_kind: crate::TokenAuthorityKind::Mint,
                new_authority: None,
            },
        )
        .expect("renounce mint");
        assert_eq!(state.tokens.get(&token_id).unwrap().mint_authority, None);
        // Minting is now impossible for anyone.
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            2,
            Operation::MintToken {
                token_id,
                recipient: holder.address(),
                amount: Amount::from_units(1),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenMintNotAuthorized));
        // The renounced authority can NEVER be restored (a Phase 13 criterion).
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            2,
            Operation::SetTokenAuthority {
                token_id,
                authority_kind: crate::TokenAuthorityKind::Mint,
                new_authority: Some(holder.address()),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenAuthorityNotAuthorized));
        // Renouncing the freeze authority likewise permanently disables freezing.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::SetTokenAuthority {
                token_id,
                authority_kind: crate::TokenAuthorityKind::Freeze,
                new_authority: None,
            },
        )
        .expect("renounce freeze");
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            3,
            Operation::FreezeTokenAccount {
                token_id,
                account: holder.address(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenFreezeNotAuthorized));
    }

    #[test]
    fn both_supply_invariants_hold_after_every_step() {
        let (config, mut state, creator, holder, outsider) = token_fixture();
        let assert_both = |state: &ChainState, token_id: TokenId| {
            assert!(
                state.supply_invariant_report().unwrap().balanced,
                "native WEBC supply must stay balanced (token ops never mint/burn WEBC)"
            );
            assert!(
                state.token_supply_report(token_id).unwrap().balanced,
                "per-token supply must equal the sum of held balances"
            );
        };
        // Create with an initial mint to the creator.
        let token_id = create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            Amount::from_units(1_000),
            creator.address(),
        )
        .expect("create");
        assert_both(&state, token_id);
        // Mint more to the holder.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::MintToken {
                token_id,
                recipient: holder.address(),
                amount: Amount::from_units(500),
            },
        )
        .expect("mint");
        assert_both(&state, token_id);
        // Burn part of the creator's own balance.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::BurnToken {
                token_id,
                amount: Amount::from_units(200),
            },
        )
        .expect("burn");
        assert_both(&state, token_id);
        // Transfer from the holder to the outsider.
        mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::TransferToken {
                token_id,
                recipient: outsider.address(),
                amount: Amount::from_units(300),
            },
        )
        .expect("transfer");
        assert_both(&state, token_id);
        // Final tallies: issued = 1000 + 500 - 200 = 1300; held sums to 1300.
        assert_eq!(
            state.tokens.get(&token_id).unwrap().issued_supply,
            Amount::from_units(1_300)
        );
        assert_eq!(token_balance(&state, token_id, creator.address()), 800);
        assert_eq!(token_balance(&state, token_id, holder.address()), 200);
        assert_eq!(token_balance(&state, token_id, outsider.address()), 300);
        assert_eq!(
            state.token_supply_report(token_id).unwrap().held,
            Amount::from_units(1_300)
        );
    }

    #[test]
    fn token_state_is_committed_by_the_state_root() {
        let (config, mut state, creator, holder, _outsider) = token_fixture();
        let root_empty = state.state_root().unwrap();
        let token_id = create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            Amount::from_units(1_000),
            holder.address(),
        )
        .expect("create");
        let root_after_create = state.state_root().unwrap();
        assert_ne!(
            root_after_create, root_empty,
            "creating a token moves the state root"
        );
        // A bincode restart preserves the token collections and the deposit scalar,
        // so the committed state root is stable across a crash/restart.
        let restored = bincode_restart(&state);
        assert_eq!(restored.tokens, state.tokens);
        assert_eq!(restored.token_balances, state.token_balances);
        assert_eq!(restored.frozen_token_accounts, state.frozen_token_accounts);
        assert_eq!(restored.token_deposits, state.token_deposits);
        assert_eq!(
            restored.state_root().unwrap(),
            root_after_create,
            "token state is committed by the state root across a restart"
        );
        // Freezing an account moves the frozen sub-root and thus the state root.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::FreezeTokenAccount {
                token_id,
                account: holder.address(),
            },
        )
        .expect("freeze");
        assert_ne!(
            state.state_root().unwrap(),
            root_after_create,
            "freezing an account moves the state root"
        );
    }

    // ----- native NFTs (Phase 13b, §15) -----

    fn nft_namespace() -> Hash256 {
        Hash256([0x99; 32])
    }

    /// A valid sample collection metadata record (name "Acme Apes", symbol "APE").
    fn sample_nft_metadata() -> crate::NftMetadata {
        crate::NftMetadata::new(b"Acme Apes".to_vec(), b"APE".to_vec(), Hash256([0x2f; 32]))
            .expect("valid metadata")
    }

    /// Creates a collection owned by `creator` and returns its derived id.
    #[allow(clippy::too_many_arguments)]
    fn create_collection(
        state: &mut ChainState,
        config: &ChainConfig,
        creator: &Keypair,
        nonce: u64,
        create_nonce: u64,
        mint_authority: Option<Address>,
        freeze_authority: Option<Address>,
        max_supply: Option<u64>,
        royalty_bps: u16,
    ) -> Result<NftCollectionId, ChainError> {
        mandate_exec(
            state,
            config,
            creator,
            nonce,
            Operation::CreateNftCollection {
                namespace: nft_namespace(),
                create_nonce,
                metadata: sample_nft_metadata(),
                mint_authority,
                freeze_authority,
                max_supply,
                royalty_bps,
            },
        )?;
        Ok(NftCollectionId::derive(
            nft_namespace(),
            creator.address(),
            create_nonce,
        ))
    }

    /// Mints one item and returns its chain-assigned [`NftId`] (from the receipt
    /// event, proving the id is discoverable from the receipt).
    fn mint_nft(
        state: &mut ChainState,
        config: &ChainConfig,
        signer: &Keypair,
        nonce: u64,
        collection_id: NftCollectionId,
        recipient: Address,
    ) -> Result<NftId, ChainError> {
        let receipt = mandate_exec(
            state,
            config,
            signer,
            nonce,
            Operation::MintNft {
                collection_id,
                recipient,
                item_metadata_hash: Hash256([0xab; 32]),
            },
        )?;
        Ok(receipt
            .events
            .iter()
            .find_map(|event| match event {
                Event::NftMinted { nft_id, .. } => Some(*nft_id),
                _ => None,
            })
            .expect("mint event carries the nft id"))
    }

    /// Asserts BOTH invariants: native WEBC supply is balanced, and the
    /// per-collection item invariant `minted - burned == live items` holds.
    fn assert_nft_invariants(state: &ChainState, collection_id: NftCollectionId) {
        assert!(
            state.supply_invariant_report().unwrap().balanced,
            "native WEBC supply must stay balanced across every NFT op"
        );
        assert!(
            state
                .nft_collection_supply_report(collection_id)
                .unwrap()
                .balanced,
            "minted - burned must equal the live item count"
        );
    }

    #[test]
    fn create_records_collection_and_reads_back_with_supply_balanced() {
        let (config, mut state, creator, _holder, _outsider) = token_fixture();
        assert!(state.supply_invariant_report().unwrap().balanced);
        let creator_liquid_before = balance(&state, creator.address());
        let collection_id = create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            Some(3),
            500,
        )
        .expect("create succeeds");

        let record = state
            .nft_collections
            .get(&collection_id)
            .expect("collection exists");
        assert_eq!(record.creator, creator.address());
        assert_eq!(record.mint_authority, Some(creator.address()));
        assert_eq!(record.freeze_authority, Some(creator.address()));
        assert!(!record.paused);
        assert_eq!(record.next_serial, 0);
        assert_eq!(record.minted_count, 0);
        assert_eq!(record.burned_count, 0);
        assert_eq!(record.max_supply, Some(3));
        assert_eq!(record.royalty_bps, 500);
        assert_eq!(record.metadata.symbol, b"APE");

        // The deposit is locked into nft_deposits; native supply still balances (only
        // the deposit + fee left the creator's liquid balance — no WEBC minted/burned
        // by collection creation).
        let deposit = config.nft.creation_deposit;
        assert_eq!(state.nft_deposits, deposit);
        let report = state.supply_invariant_report().unwrap();
        assert!(report.balanced);
        assert_eq!(report.nft_deposits, deposit);
        assert!(balance(&state, creator.address()) < creator_liquid_before);

        // The per-collection item invariant holds from creation: 0 minted, 0 live.
        assert_nft_invariants(&state, collection_id);
    }

    #[test]
    fn duplicate_collection_id_is_rejected() {
        let (config, mut state, creator, _holder, _outsider) = token_fixture();
        create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            None,
            None,
            0,
        )
        .expect("first create");
        // Same (namespace, creator, create_nonce) derives the same id: rejected.
        let before = state.clone();
        let err = create_collection(
            &mut state,
            &config,
            &creator,
            1,
            0,
            Some(creator.address()),
            None,
            None,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftCollectionAlreadyExists));
        assert_eq!(state, before, "rejected duplicate leaves state unchanged");
    }

    #[test]
    fn over_length_metadata_and_bad_royalty_are_rejected_on_apply() {
        let (config, mut state, creator, _holder, _outsider) = token_fixture();
        let bad_create = |metadata: crate::NftMetadata, royalty_bps: u16, nonce: u64| {
            Operation::CreateNftCollection {
                namespace: nft_namespace(),
                create_nonce: nonce,
                metadata,
                mint_authority: Some(creator.address()),
                freeze_authority: None,
                max_supply: None,
                royalty_bps,
            }
        };
        // Over-length name.
        let mut m = sample_nft_metadata();
        m.name = vec![0x61; crate::MAX_NFT_NAME_BYTES + 1];
        let err = mandate_exec(&mut state, &config, &creator, 0, bad_create(m, 0, 0)).unwrap_err();
        assert!(matches!(err, ChainError::InvalidNftMetadata));
        // Over-length symbol.
        let mut m = sample_nft_metadata();
        m.symbol = vec![0x61; crate::MAX_NFT_SYMBOL_BYTES + 1];
        let err = mandate_exec(&mut state, &config, &creator, 0, bad_create(m, 0, 1)).unwrap_err();
        assert!(matches!(err, ChainError::InvalidNftMetadata));
        // Out-of-range royalty.
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            0,
            bad_create(sample_nft_metadata(), crate::MAX_NFT_ROYALTY_BPS + 1, 2),
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::InvalidNftMetadata));
        // No collection was recorded and no deposit was locked on any rejected create.
        assert!(state.nft_collections.is_empty());
        assert_eq!(state.nft_deposits, Amount::ZERO);
    }

    #[test]
    fn mint_requires_authority_and_creates_item_owned_by_recipient() {
        let (config, mut state, creator, holder, outsider) = token_fixture();
        let collection_id = create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            None,
            None,
            0,
        )
        .expect("create");
        // A non-authority cannot mint.
        let before = state.clone();
        let err = mandate_exec(
            &mut state,
            &config,
            &outsider,
            0,
            Operation::MintNft {
                collection_id,
                recipient: holder.address(),
                item_metadata_hash: Hash256([0xab; 32]),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftMintNotAuthorized));
        assert_eq!(state, before, "rejected mint leaves state unchanged");

        // The authority mints: item owned by recipient, counters/serial bumped.
        let nft_id = mint_nft(
            &mut state,
            &config,
            &creator,
            1,
            collection_id,
            holder.address(),
        )
        .expect("mint succeeds");
        assert_eq!(nft_id, NftId::new(collection_id, 0));
        let item = state.nft_items.get(&nft_id).expect("item exists");
        assert_eq!(item.owner, holder.address());
        assert!(!item.frozen);
        assert_eq!(item.item_metadata_hash, Hash256([0xab; 32]));
        let record = state.nft_collections.get(&collection_id).unwrap();
        assert_eq!(record.next_serial, 1);
        assert_eq!(record.minted_count, 1);
        assert_eq!(record.burned_count, 0);
        assert_nft_invariants(&state, collection_id);

        // A second mint assigns serial 1 (monotonic).
        let nft_id_1 = mint_nft(
            &mut state,
            &config,
            &creator,
            2,
            collection_id,
            holder.address(),
        )
        .expect("second mint");
        assert_eq!(nft_id_1, NftId::new(collection_id, 1));
        assert_eq!(
            state
                .nft_collections
                .get(&collection_id)
                .unwrap()
                .next_serial,
            2
        );
        assert_nft_invariants(&state, collection_id);
    }

    #[test]
    fn mint_past_max_supply_is_rejected() {
        let (config, mut state, creator, holder, _outsider) = token_fixture();
        let collection_id = create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            None,
            Some(2),
            0,
        )
        .expect("create");
        mint_nft(
            &mut state,
            &config,
            &creator,
            1,
            collection_id,
            holder.address(),
        )
        .expect("mint 0");
        mint_nft(
            &mut state,
            &config,
            &creator,
            2,
            collection_id,
            holder.address(),
        )
        .expect("mint 1");
        // The cap of 2 is now reached; a third mint is rejected.
        let before = state.clone();
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            3,
            Operation::MintNft {
                collection_id,
                recipient: holder.address(),
                item_metadata_hash: Hash256([0xac; 32]),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftMaxSupplyReached));
        assert_eq!(state, before, "rejected mint leaves state unchanged");
        assert_nft_invariants(&state, collection_id);
    }

    #[test]
    fn mint_into_paused_collection_is_rejected() {
        let (config, mut state, creator, holder, _outsider) = token_fixture();
        let collection_id = create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            None,
            None,
            0,
        )
        .expect("create");
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::SetNftCollectionPaused {
                collection_id,
                paused: true,
            },
        )
        .expect("pause");
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::MintNft {
                collection_id,
                recipient: holder.address(),
                item_metadata_hash: Hash256([0xab; 32]),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftCollectionPaused));
    }

    #[test]
    fn transfer_requires_owner_and_moves_ownership() {
        let (config, mut state, creator, holder, outsider) = token_fixture();
        let collection_id = create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            None,
            None,
            0,
        )
        .expect("create");
        let nft_id = mint_nft(
            &mut state,
            &config,
            &creator,
            1,
            collection_id,
            holder.address(),
        )
        .expect("mint");

        // A non-owner cannot transfer.
        let before = state.clone();
        let err = mandate_exec(
            &mut state,
            &config,
            &outsider,
            0,
            Operation::TransferNft {
                collection_id,
                serial: nft_id.serial,
                recipient: outsider.address(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftNotOwner));
        assert_eq!(state, before, "rejected transfer leaves state unchanged");

        // The owner transfers: ownership moves; the item key is the only item written.
        mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::TransferNft {
                collection_id,
                serial: nft_id.serial,
                recipient: outsider.address(),
            },
        )
        .expect("transfer");
        assert_eq!(
            state.nft_items.get(&nft_id).unwrap().owner,
            outsider.address()
        );
        assert_nft_invariants(&state, collection_id);
    }

    #[test]
    fn transfer_of_frozen_item_or_paused_collection_is_rejected() {
        let (config, mut state, creator, holder, outsider) = token_fixture();
        let collection_id = create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            None,
            0,
        )
        .expect("create");
        let nft_id = mint_nft(
            &mut state,
            &config,
            &creator,
            1,
            collection_id,
            holder.address(),
        )
        .expect("mint");

        // Pause blocks transfer.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::SetNftCollectionPaused {
                collection_id,
                paused: true,
            },
        )
        .expect("pause");
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::TransferNft {
                collection_id,
                serial: nft_id.serial,
                recipient: outsider.address(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftCollectionPaused));
        // Unpause, then freeze the item: transfer blocked by the frozen flag.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            3,
            Operation::SetNftCollectionPaused {
                collection_id,
                paused: false,
            },
        )
        .expect("unpause");
        mandate_exec(
            &mut state,
            &config,
            &creator,
            4,
            Operation::FreezeNftItem {
                collection_id,
                serial: nft_id.serial,
            },
        )
        .expect("freeze");
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::TransferNft {
                collection_id,
                serial: nft_id.serial,
                recipient: outsider.address(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftItemFrozen));
        // Ownership never moved.
        assert_eq!(
            state.nft_items.get(&nft_id).unwrap().owner,
            holder.address()
        );
    }

    #[test]
    fn freeze_blocks_transfer_and_burn_until_thawed() {
        let (config, mut state, creator, holder, outsider) = token_fixture();
        let collection_id = create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            None,
            0,
        )
        .expect("create");
        let nft_id = mint_nft(
            &mut state,
            &config,
            &creator,
            1,
            collection_id,
            holder.address(),
        )
        .expect("mint");

        // A non-authority cannot freeze.
        let err = mandate_exec(
            &mut state,
            &config,
            &outsider,
            0,
            Operation::FreezeNftItem {
                collection_id,
                serial: nft_id.serial,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftFreezeNotAuthorized));

        // Freeze, then transfer and burn are both rejected.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::FreezeNftItem {
                collection_id,
                serial: nft_id.serial,
            },
        )
        .expect("freeze");
        assert!(state.nft_items.get(&nft_id).unwrap().frozen);
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::BurnNft {
                collection_id,
                serial: nft_id.serial,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftItemFrozen));

        // Thaw, then the owner can transfer.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            3,
            Operation::ThawNftItem {
                collection_id,
                serial: nft_id.serial,
            },
        )
        .expect("thaw");
        assert!(!state.nft_items.get(&nft_id).unwrap().frozen);
        mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::TransferNft {
                collection_id,
                serial: nft_id.serial,
                recipient: outsider.address(),
            },
        )
        .expect("transfer after thaw");
        assert_eq!(
            state.nft_items.get(&nft_id).unwrap().owner,
            outsider.address()
        );
        assert_nft_invariants(&state, collection_id);
    }

    #[test]
    fn burn_removes_item_bumps_counter_and_serial_is_never_reminted() {
        let (config, mut state, creator, holder, _outsider) = token_fixture();
        let collection_id = create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            None,
            None,
            0,
        )
        .expect("create");
        let nft_id_0 = mint_nft(
            &mut state,
            &config,
            &creator,
            1,
            collection_id,
            holder.address(),
        )
        .expect("mint 0");
        let _nft_id_1 = mint_nft(
            &mut state,
            &config,
            &creator,
            2,
            collection_id,
            holder.address(),
        )
        .expect("mint 1");

        // A non-owner cannot burn.
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            3,
            Operation::BurnNft {
                collection_id,
                serial: nft_id_0.serial,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftNotOwner));

        // The owner burns serial 0: item removed, burned_count bumped, next_serial
        // UNCHANGED (still 2).
        mandate_exec(
            &mut state,
            &config,
            &holder,
            0,
            Operation::BurnNft {
                collection_id,
                serial: nft_id_0.serial,
            },
        )
        .expect("burn");
        assert!(!state.nft_items.contains_key(&nft_id_0));
        let record = state.nft_collections.get(&collection_id).unwrap();
        assert_eq!(record.burned_count, 1);
        assert_eq!(record.next_serial, 2, "next_serial never decrements");
        assert_eq!(record.minted_count, 2);
        assert_nft_invariants(&state, collection_id);

        // The next mint assigns serial 2 — the burned serial 0 is NEVER reminted.
        // (The rejected non-owner burn above did not commit, so the creator's nonce
        // is still 3.)
        let nft_id_2 = mint_nft(
            &mut state,
            &config,
            &creator,
            3,
            collection_id,
            holder.address(),
        )
        .expect("mint after burn");
        assert_eq!(nft_id_2, NftId::new(collection_id, 2));
        assert!(!state.nft_items.contains_key(&NftId::new(collection_id, 0)));
        assert_nft_invariants(&state, collection_id);
    }

    #[test]
    fn nft_authority_transfer_moves_control_and_renounce_is_permanent() {
        let (config, mut state, creator, holder, outsider) = token_fixture();
        let collection_id = create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            None,
            0,
        )
        .expect("create");

        // Transfer the mint authority to the holder; the old holder (creator) can no
        // longer mint, and the new holder can.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::SetNftAuthority {
                collection_id,
                authority_kind: crate::NftAuthorityKind::Mint,
                new_authority: Some(holder.address()),
            },
        )
        .expect("transfer mint authority");
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::MintNft {
                collection_id,
                recipient: outsider.address(),
                item_metadata_hash: Hash256([0xab; 32]),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftMintNotAuthorized));
        mint_nft(
            &mut state,
            &config,
            &holder,
            0,
            collection_id,
            outsider.address(),
        )
        .expect("new authority mints");

        // The new holder renounces the mint authority (Some -> None): PERMANENT.
        mandate_exec(
            &mut state,
            &config,
            &holder,
            1,
            Operation::SetNftAuthority {
                collection_id,
                authority_kind: crate::NftAuthorityKind::Mint,
                new_authority: None,
            },
        )
        .expect("renounce mint authority");
        assert_eq!(
            state
                .nft_collections
                .get(&collection_id)
                .unwrap()
                .mint_authority,
            None
        );
        // Nobody can mint anymore.
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            2,
            Operation::MintNft {
                collection_id,
                recipient: outsider.address(),
                item_metadata_hash: Hash256([0xab; 32]),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftMintNotAuthorized));
        // And the renounce is UNRECOVERABLE: no one can re-grant a None authority.
        // (The rejected mint above did not commit, so the holder's nonce is still 2.)
        let err = mandate_exec(
            &mut state,
            &config,
            &holder,
            2,
            Operation::SetNftAuthority {
                collection_id,
                authority_kind: crate::NftAuthorityKind::Mint,
                new_authority: Some(holder.address()),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftAuthorityNotAuthorized));

        // Freeze authority renounce is likewise permanent: freezing then rejected.
        // (The creator's rejected mint did not commit, so its nonce is still 2.)
        mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::SetNftAuthority {
                collection_id,
                authority_kind: crate::NftAuthorityKind::Freeze,
                new_authority: None,
            },
        )
        .expect("renounce freeze authority");
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            3,
            Operation::FreezeNftItem {
                collection_id,
                serial: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NftFreezeNotAuthorized));
    }

    #[test]
    fn nft_state_is_committed_by_the_state_root() {
        let (config, mut state, creator, holder, _outsider) = token_fixture();
        let root_empty = state.state_root().unwrap();
        let collection_id = create_collection(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            None,
            0,
        )
        .expect("create");
        let root_after_create = state.state_root().unwrap();
        assert_ne!(
            root_after_create, root_empty,
            "creating a collection moves the state root"
        );
        let nft_id = mint_nft(
            &mut state,
            &config,
            &creator,
            1,
            collection_id,
            holder.address(),
        )
        .expect("mint");
        let root_after_mint = state.state_root().unwrap();
        assert_ne!(
            root_after_mint, root_after_create,
            "minting an item moves the state root"
        );

        // A bincode restart preserves the collections, items, and deposit scalar, so
        // the committed state root is stable across a crash/restart.
        let restored = bincode_restart(&state);
        assert_eq!(restored.nft_collections, state.nft_collections);
        assert_eq!(restored.nft_items, state.nft_items);
        assert_eq!(restored.nft_deposits, state.nft_deposits);
        assert_eq!(
            restored.state_root().unwrap(),
            root_after_mint,
            "nft state is committed by the state root across a restart"
        );

        // Freezing the item moves the item sub-root and thus the state root.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::FreezeNftItem {
                collection_id,
                serial: nft_id.serial,
            },
        )
        .expect("freeze");
        assert_ne!(
            state.state_root().unwrap(),
            root_after_mint,
            "freezing an item moves the state root"
        );
    }

    // ----- native application governance (Phase 13c, §15) -----

    /// The application namespace all governance tests create instances under.
    fn gov_namespace() -> Hash256 {
        Hash256([0x7c; 32])
    }

    /// The standard fee bid used by every governance test transaction (floor base
    /// fee, gas above any governance op's cost).
    fn gov_fee() -> FeeBid {
        FeeBid {
            gas_limit: 100_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        }
    }

    /// A representative valid governance config: 10-epoch voting, 3-epoch timelock,
    /// 30% quorum, 10-unit proposal threshold, 50% approval.
    fn gov_config_default() -> crate::GovernanceConfig {
        crate::GovernanceConfig {
            voting_period_epochs: 10,
            timelock_epochs: 3,
            quorum_bps: 3_000,
            proposal_threshold: Amount::from_units(10),
            approval_threshold_bps: 5_000,
        }
    }

    /// Builds a governance fixture: a weight token with 1000 units split 600/400
    /// between two voters, and a governance instance bound to it under
    /// [`gov_config_default`]. Returns `(config, state, creator, voter_a, voter_b,
    /// recipient, token_id, instance_id)`. The creator is the token's mint AND
    /// freeze authority (so freeze/pause paths are exercisable); everyone is funded
    /// with room for deposits and fees.
    #[allow(clippy::type_complexity)]
    fn gov_setup() -> (
        ChainConfig,
        ChainState,
        Keypair,
        Keypair,
        Keypair,
        Keypair,
        TokenId,
        GovernanceInstanceId,
    ) {
        let config = ChainConfig::default();
        let creator = Keypair::from_seed([71u8; 32]);
        let voter_a = Keypair::from_seed([72u8; 32]);
        let voter_b = Keypair::from_seed([73u8; 32]);
        let recipient = Keypair::from_seed([74u8; 32]);
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![
                GenesisAccount {
                    address: creator.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: voter_a.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: voter_b.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: recipient.address(),
                    balance: Amount::from_webc(1_000),
                },
            ],
            validators: Vec::new(),
        };
        let mut state = ChainState::from_genesis(&genesis).expect("gov genesis");
        // Weight token: creator is mint + freeze authority, no initial supply.
        let token_id = create_token(
            &mut state,
            &config,
            &creator,
            0,
            0,
            Some(creator.address()),
            Some(creator.address()),
            Amount::ZERO,
            creator.address(),
        )
        .expect("create weight token");
        // Mint 600 to voter_a and 400 to voter_b (1000 total supply).
        mandate_exec(
            &mut state,
            &config,
            &creator,
            1,
            Operation::MintToken {
                token_id,
                recipient: voter_a.address(),
                amount: Amount::from_units(600),
            },
        )
        .expect("mint a");
        mandate_exec(
            &mut state,
            &config,
            &creator,
            2,
            Operation::MintToken {
                token_id,
                recipient: voter_b.address(),
                amount: Amount::from_units(400),
            },
        )
        .expect("mint b");
        // Governance instance bound to the token.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            3,
            Operation::CreateGovernanceInstance {
                namespace: gov_namespace(),
                create_nonce: 0,
                weight_token: token_id,
                config: gov_config_default(),
            },
        )
        .expect("create instance");
        let instance_id = GovernanceInstanceId::derive(gov_namespace(), creator.address(), 0);
        (
            config,
            state,
            creator,
            voter_a,
            voter_b,
            recipient,
            token_id,
            instance_id,
        )
    }

    /// Funds an instance treasury via `FundGovernanceTreasury` (default access list).
    fn gov_fund(
        state: &mut ChainState,
        config: &ChainConfig,
        funder: &Keypair,
        nonce: u64,
        instance_id: GovernanceInstanceId,
        amount: Amount,
    ) -> Result<Receipt, ChainError> {
        let tx = Transaction::for_operation(
            funder,
            nonce,
            Operation::FundGovernanceTreasury {
                instance_id,
                amount,
            },
            gov_fee(),
        )
        .expect("fund tx signs");
        state.execute_transaction(&tx, config)
    }

    /// Opens a proposal and returns its derived id (the escrow/id use the instance's
    /// current proposal nonce, captured before execution).
    fn gov_open(
        state: &mut ChainState,
        config: &ChainConfig,
        proposer: &Keypair,
        nonce: u64,
        instance_id: GovernanceInstanceId,
        action: GovernanceAction,
        weight_token: TokenId,
    ) -> Result<ProposalId, ChainError> {
        let proposal_nonce = state
            .governance_instances
            .get(&instance_id)
            .expect("instance exists")
            .next_proposal_nonce;
        let tx = Transaction::for_open_proposal(
            proposer,
            nonce,
            instance_id,
            action,
            weight_token,
            gov_fee(),
        )
        .expect("open tx signs");
        state.execute_transaction(&tx, config)?;
        Ok(ProposalId::derive(instance_id, proposal_nonce))
    }

    /// Casts a lock-to-vote ballot.
    #[allow(clippy::too_many_arguments)]
    fn gov_vote(
        state: &mut ChainState,
        config: &ChainConfig,
        voter: &Keypair,
        nonce: u64,
        proposal_id: ProposalId,
        choice: VoteChoice,
        weight: Amount,
        weight_token: TokenId,
    ) -> Result<Receipt, ChainError> {
        let tx = Transaction::for_cast_vote(
            voter,
            nonce,
            proposal_id,
            choice,
            weight,
            weight_token,
            gov_fee(),
        )
        .expect("vote tx signs");
        state.execute_transaction(&tx, config)
    }

    /// Resolves a proposal after voting ends.
    fn gov_resolve(
        state: &mut ChainState,
        config: &ChainConfig,
        caller: &Keypair,
        nonce: u64,
        proposal_id: ProposalId,
        weight_token: TokenId,
    ) -> Result<Receipt, ChainError> {
        let tx =
            Transaction::for_resolve_proposal(caller, nonce, proposal_id, weight_token, gov_fee())
                .expect("resolve tx signs");
        state.execute_transaction(&tx, config)
    }

    /// Executes a passed proposal.
    fn gov_execute(
        state: &mut ChainState,
        config: &ChainConfig,
        caller: &Keypair,
        nonce: u64,
        proposal_id: ProposalId,
        payout: Option<(GovernanceInstanceId, Address)>,
    ) -> Result<Receipt, ChainError> {
        let tx = Transaction::for_execute_proposal(caller, nonce, proposal_id, payout, gov_fee())
            .expect("execute tx signs");
        state.execute_transaction(&tx, config)
    }

    /// Reclaims a voter's locked weight after resolution.
    fn gov_reclaim(
        state: &mut ChainState,
        config: &ChainConfig,
        voter: &Keypair,
        nonce: u64,
        proposal_id: ProposalId,
        weight_token: TokenId,
    ) -> Result<Receipt, ChainError> {
        let tx = Transaction::for_reclaim_vote(voter, nonce, proposal_id, weight_token, gov_fee())
            .expect("reclaim tx signs");
        state.execute_transaction(&tx, config)
    }

    /// The token units held by the per-proposal vote escrow.
    fn escrow_balance(state: &ChainState, token_id: TokenId, proposal_id: ProposalId) -> u128 {
        token_balance(state, token_id, gov_vote_escrow_address(proposal_id))
    }

    #[test]
    fn create_records_instance_and_reads_back_with_supply_balanced() {
        let (config, state, creator, _a, _b, _r, token_id, instance_id) = gov_setup();
        let instance = state
            .governance_instances
            .get(&instance_id)
            .expect("instance exists");
        assert_eq!(instance.creator, creator.address());
        assert_eq!(instance.weight_token, token_id);
        assert_eq!(instance.treasury, Amount::ZERO);
        assert_eq!(instance.next_proposal_nonce, 0);
        assert_eq!(instance.config, gov_config_default());
        // The deposit is locked into governance_deposits; native supply balances.
        let deposit = config.governance.creation_deposit;
        assert_eq!(state.governance_deposits, deposit);
        let report = state.supply_invariant_report().unwrap();
        assert!(report.balanced);
        assert_eq!(report.governance_deposits, deposit);
        assert_eq!(report.governance_treasury, Amount::ZERO);
        assert!(state.token_supply_report(token_id).unwrap().balanced);
    }

    #[test]
    fn duplicate_instance_id_and_invalid_config_are_rejected() {
        let (config, mut state, creator, _a, _b, _r, token_id, _instance_id) = gov_setup();
        // Same (namespace, creator, create_nonce) derives the same id: rejected.
        let before = state.clone();
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            4,
            Operation::CreateGovernanceInstance {
                namespace: gov_namespace(),
                create_nonce: 0,
                weight_token: token_id,
                config: gov_config_default(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::GovernanceInstanceAlreadyExists));
        assert_eq!(state, before, "rejected duplicate leaves state unchanged");

        // Zero voting period is an invalid config: rejected, no instance recorded.
        let mut bad = gov_config_default();
        bad.voting_period_epochs = 0;
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            4,
            Operation::CreateGovernanceInstance {
                namespace: gov_namespace(),
                create_nonce: 1,
                weight_token: token_id,
                config: bad,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::InvalidGovernanceConfig));

        // An over-range approval threshold is also rejected.
        let mut bad = gov_config_default();
        bad.approval_threshold_bps = crate::MAX_GOVERNANCE_BPS + 1;
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            4,
            Operation::CreateGovernanceInstance {
                namespace: gov_namespace(),
                create_nonce: 2,
                weight_token: token_id,
                config: bad,
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::InvalidGovernanceConfig));

        // Binding a nonexistent weight token is rejected.
        let err = mandate_exec(
            &mut state,
            &config,
            &creator,
            4,
            Operation::CreateGovernanceInstance {
                namespace: gov_namespace(),
                create_nonce: 3,
                weight_token: TokenId::new(Hash256([0xde; 32])),
                config: gov_config_default(),
            },
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenNotFound));
    }

    #[test]
    fn open_proposal_below_threshold_is_rejected() {
        let (config, mut state, _creator, _a, _b, recipient, token_id, instance_id) = gov_setup();
        // `recipient` holds zero weight tokens, below the 10-unit threshold.
        let err = gov_open(
            &mut state,
            &config,
            &recipient,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::GovernanceProposalThresholdNotMet));
        assert!(state.governance_proposals.is_empty());
    }

    #[test]
    fn vote_locks_tokens_and_preserves_per_token_supply() {
        let (config, mut state, _creator, voter_a, _b, _r, token_id, instance_id) = gov_setup();
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open");
        assert_eq!(token_balance(&state, token_id, voter_a.address()), 600);
        assert_eq!(escrow_balance(&state, token_id, proposal_id), 0);

        gov_vote(
            &mut state,
            &config,
            &voter_a,
            1,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote");

        // The voter's balance moved wholesale into the escrow: the lock is a MOVE
        // within token_balances, so the per-token supply invariant still holds.
        assert_eq!(token_balance(&state, token_id, voter_a.address()), 0);
        assert_eq!(escrow_balance(&state, token_id, proposal_id), 600);
        let tok = state.token_supply_report(token_id).unwrap();
        assert!(tok.balanced);
        assert_eq!(tok.issued, Amount::from_units(1_000));
        assert!(state.supply_invariant_report().unwrap().balanced);

        // The proposal tally records the locked weight, and the lock record exists.
        let proposal = state.governance_proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.yes, Amount::from_units(600));
        assert_eq!(
            state
                .governance_votes
                .get(&(proposal_id, voter_a.address()))
                .unwrap()
                .weight,
            Amount::from_units(600)
        );
    }

    #[test]
    fn double_vote_by_same_voter_is_rejected() {
        let (config, mut state, _creator, voter_a, _b, _r, token_id, instance_id) = gov_setup();
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open");
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            1,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(100),
            token_id,
        )
        .expect("first vote");
        // A second vote from the same voter is rejected — they already locked.
        let err = gov_vote(
            &mut state,
            &config,
            &voter_a,
            2,
            proposal_id,
            VoteChoice::No,
            Amount::from_units(100),
            token_id,
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::GovernanceAlreadyVoted));
        // Only the first lock stands.
        assert_eq!(token_balance(&state, token_id, voter_a.address()), 500);
        assert_eq!(escrow_balance(&state, token_id, proposal_id), 100);
    }

    #[test]
    fn a_voter_cannot_transfer_locked_tokens() {
        let (config, mut state, _creator, voter_a, voter_b, _r, token_id, instance_id) =
            gov_setup();
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open");
        // Lock the voter's ENTIRE balance.
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            1,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote");
        assert_eq!(token_balance(&state, token_id, voter_a.address()), 0);
        // The locked tokens left the voter's balance, so they cannot be transferred
        // (no double-spend of voting weight): a 1-unit transfer fails closed.
        let transfer = Transaction::for_operation(
            &voter_a,
            2,
            Operation::TransferToken {
                token_id,
                recipient: voter_b.address(),
                amount: Amount::from_units(1),
            },
            gov_fee(),
        )
        .expect("transfer signs");
        let err = state.execute_transaction(&transfer, &config).unwrap_err();
        assert!(matches!(err, ChainError::TokenInsufficientBalance));
        // The escrow still holds the full lock, and supply is intact.
        assert_eq!(escrow_balance(&state, token_id, proposal_id), 600);
        assert!(state.token_supply_report(token_id).unwrap().balanced);
    }

    #[test]
    fn vote_after_voting_ends_is_rejected() {
        let (config, mut state, _creator, voter_a, _b, _r, token_id, instance_id) = gov_setup();
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open");
        // voting_ends_epoch = created(0) + 10; move past it.
        state.current_epoch = 11;
        let err = gov_vote(
            &mut state,
            &config,
            &voter_a,
            1,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(100),
            token_id,
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::GovernanceVotingClosed));
    }

    #[test]
    fn resolve_before_voting_ends_is_rejected() {
        let (config, mut state, _creator, voter_a, _b, _r, token_id, instance_id) = gov_setup();
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open");
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            1,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote");
        // current_epoch (0) <= voting_ends (10): resolve is not yet callable.
        let err = gov_resolve(&mut state, &config, &voter_a, 2, proposal_id, token_id).unwrap_err();
        assert!(matches!(err, ChainError::GovernanceVotingOpen));
    }

    #[test]
    fn quorum_not_met_resolves_to_defeated() {
        let (config, mut state, _creator, voter_a, _b, _r, token_id, instance_id) = gov_setup();
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open");
        // 200 participation of 1000 supply is below the 30% (300) quorum.
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            1,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(200),
            token_id,
        )
        .expect("vote");
        state.current_epoch = 11;
        gov_resolve(&mut state, &config, &voter_a, 2, proposal_id, token_id).expect("resolve");
        let proposal = state.governance_proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.status, GovProposalStatus::Defeated);
        assert_eq!(proposal.eta_epoch, None);
        // Resolving again is rejected (idempotent).
        let err = gov_resolve(&mut state, &config, &voter_a, 3, proposal_id, token_id).unwrap_err();
        assert!(matches!(err, ChainError::GovernanceAlreadyResolved));
    }

    #[test]
    fn approval_not_met_resolves_to_defeated() {
        let (config, mut state, _creator, voter_a, _b, _r, token_id, instance_id) = gov_setup();
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open");
        // 600 No votes meet quorum (>=300) but fail the 50% approval ratio (0% yes).
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            1,
            proposal_id,
            VoteChoice::No,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote");
        state.current_epoch = 11;
        gov_resolve(&mut state, &config, &voter_a, 2, proposal_id, token_id).expect("resolve");
        assert_eq!(
            state.governance_proposals.get(&proposal_id).unwrap().status,
            GovProposalStatus::Defeated
        );
    }

    #[test]
    fn quorum_and_approval_met_resolves_to_passed() {
        let (config, mut state, _creator, voter_a, _b, _r, token_id, instance_id) = gov_setup();
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open");
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            1,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote");
        state.current_epoch = 11;
        gov_resolve(&mut state, &config, &voter_a, 2, proposal_id, token_id).expect("resolve");
        let proposal = state.governance_proposals.get(&proposal_id).unwrap();
        assert_eq!(proposal.status, GovProposalStatus::Passed);
        // eta = voting_ends(10) + timelock(3).
        assert_eq!(proposal.eta_epoch, Some(13));
    }

    #[test]
    fn execute_before_timelock_is_rejected() {
        let (config, mut state, _creator, voter_a, _b, recipient, token_id, instance_id) =
            gov_setup();
        gov_fund(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            Amount::from_webc(5),
        )
        .expect("fund");
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            1,
            instance_id,
            GovernanceAction::TreasuryTransfer {
                recipient: recipient.address(),
                amount: Amount::from_webc(5),
            },
            token_id,
        )
        .expect("open");
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            2,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote");
        state.current_epoch = 11;
        gov_resolve(&mut state, &config, &voter_a, 3, proposal_id, token_id).expect("resolve");
        // eta = 13; at epoch 12 the timelock has not elapsed.
        state.current_epoch = 12;
        let err = gov_execute(
            &mut state,
            &config,
            &voter_a,
            4,
            proposal_id,
            Some((instance_id, recipient.address())),
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::GovernanceTimelockNotElapsed));
    }

    #[test]
    fn execute_defeated_proposal_is_rejected() {
        let (config, mut state, _creator, voter_a, _b, recipient, token_id, instance_id) =
            gov_setup();
        gov_fund(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            Amount::from_webc(5),
        )
        .expect("fund");
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            1,
            instance_id,
            GovernanceAction::TreasuryTransfer {
                recipient: recipient.address(),
                amount: Amount::from_webc(5),
            },
            token_id,
        )
        .expect("open");
        // Below quorum -> Defeated.
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            2,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(100),
            token_id,
        )
        .expect("vote");
        state.current_epoch = 11;
        gov_resolve(&mut state, &config, &voter_a, 3, proposal_id, token_id).expect("resolve");
        state.current_epoch = 20;
        let err = gov_execute(
            &mut state,
            &config,
            &voter_a,
            4,
            proposal_id,
            Some((instance_id, recipient.address())),
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::GovernanceProposalNotPassed));
    }

    #[test]
    fn execute_treasury_transfer_exceeding_treasury_fails_closed() {
        let (config, mut state, _creator, voter_a, voter_b, recipient, token_id, instance_id) =
            gov_setup();
        // Fund exactly 10 WEBC; open TWO 10-WEBC payouts (both pass the open sanity
        // check, since the treasury is still 10 when each opens).
        gov_fund(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            Amount::from_webc(10),
        )
        .expect("fund");
        let p1 = gov_open(
            &mut state,
            &config,
            &voter_a,
            1,
            instance_id,
            GovernanceAction::TreasuryTransfer {
                recipient: recipient.address(),
                amount: Amount::from_webc(10),
            },
            token_id,
        )
        .expect("open p1");
        let p2 = gov_open(
            &mut state,
            &config,
            &voter_b,
            0,
            instance_id,
            GovernanceAction::TreasuryTransfer {
                recipient: recipient.address(),
                amount: Amount::from_webc(10),
            },
            token_id,
        )
        .expect("open p2");
        // Each voter passes one proposal (600 and 400 both exceed the 300 quorum).
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            2,
            p1,
            VoteChoice::Yes,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote p1");
        gov_vote(
            &mut state,
            &config,
            &voter_b,
            1,
            p2,
            VoteChoice::Yes,
            Amount::from_units(400),
            token_id,
        )
        .expect("vote p2");
        state.current_epoch = 11;
        gov_resolve(&mut state, &config, &voter_a, 3, p1, token_id).expect("resolve p1");
        gov_resolve(&mut state, &config, &voter_b, 2, p2, token_id).expect("resolve p2");
        state.current_epoch = 13;
        // Executing p1 drains the treasury to zero.
        gov_execute(
            &mut state,
            &config,
            &voter_a,
            4,
            p1,
            Some((instance_id, recipient.address())),
        )
        .expect("execute p1");
        assert_eq!(
            state
                .governance_instances
                .get(&instance_id)
                .unwrap()
                .treasury,
            Amount::ZERO
        );
        // Executing p2 now RE-CHECKS the live treasury and fails closed; the proposal
        // stays Passed (the whole transaction rolled back).
        let err = gov_execute(
            &mut state,
            &config,
            &voter_b,
            3,
            p2,
            Some((instance_id, recipient.address())),
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::GovernanceTreasuryInsufficient));
        assert_eq!(
            state.governance_proposals.get(&p2).unwrap().status,
            GovProposalStatus::Passed
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn successful_execute_pays_recipient_and_keeps_native_supply_balanced() {
        let (config, mut state, _creator, voter_a, _b, recipient, token_id, instance_id) =
            gov_setup();
        let recipient_before = balance(&state, recipient.address());
        gov_fund(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            Amount::from_webc(7),
        )
        .expect("fund");
        assert!(state.supply_invariant_report().unwrap().balanced);
        assert_eq!(state.governance_treasury, Amount::from_webc(7));
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            1,
            instance_id,
            GovernanceAction::TreasuryTransfer {
                recipient: recipient.address(),
                amount: Amount::from_webc(7),
            },
            token_id,
        )
        .expect("open");
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            2,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote");
        state.current_epoch = 11;
        gov_resolve(&mut state, &config, &voter_a, 3, proposal_id, token_id).expect("resolve");
        state.current_epoch = 13;
        gov_execute(
            &mut state,
            &config,
            &voter_a,
            4,
            proposal_id,
            Some((instance_id, recipient.address())),
        )
        .expect("execute");
        assert_eq!(
            state.governance_proposals.get(&proposal_id).unwrap().status,
            GovProposalStatus::Executed
        );
        // The recipient received exactly the payout; treasury bucket is empty; native
        // supply stays balanced (bucket -> liquid).
        assert_eq!(
            balance(&state, recipient.address()),
            recipient_before + Amount::from_webc(7).0
        );
        assert_eq!(state.governance_treasury, Amount::ZERO);
        assert_eq!(
            state
                .governance_instances
                .get(&instance_id)
                .unwrap()
                .treasury,
            Amount::ZERO
        );
        assert!(state.supply_invariant_report().unwrap().balanced);
    }

    #[test]
    fn reclaim_before_resolution_is_rejected_and_after_returns_exact_weight() {
        let (config, mut state, _creator, voter_a, _b, _r, token_id, instance_id) = gov_setup();
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open");
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            1,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote");
        // Reclaim before the proposal resolves is rejected. A rejected transaction
        // rolls back entirely (its nonce is NOT consumed), so the following txs
        // reuse nonce 2.
        let err = gov_reclaim(&mut state, &config, &voter_a, 2, proposal_id, token_id).unwrap_err();
        assert!(matches!(err, ChainError::GovernanceProposalNotResolved));
        assert_eq!(escrow_balance(&state, token_id, proposal_id), 600);

        // Resolve, then reclaim returns EXACTLY the locked amount and restores the
        // per-token balance; the lock record is cleared.
        state.current_epoch = 11;
        gov_resolve(&mut state, &config, &voter_a, 2, proposal_id, token_id).expect("resolve");
        gov_reclaim(&mut state, &config, &voter_a, 3, proposal_id, token_id).expect("reclaim");
        assert_eq!(token_balance(&state, token_id, voter_a.address()), 600);
        assert_eq!(escrow_balance(&state, token_id, proposal_id), 0);
        assert!(!state
            .governance_votes
            .contains_key(&(proposal_id, voter_a.address())));
        assert!(state.token_supply_report(token_id).unwrap().balanced);

        // A second reclaim finds nothing locked.
        let err = gov_reclaim(&mut state, &config, &voter_a, 4, proposal_id, token_id).unwrap_err();
        assert!(matches!(err, ChainError::GovernanceNothingToReclaim));
    }

    #[test]
    fn frozen_or_paused_weight_token_blocks_the_vote_lock() {
        let (config, mut state, creator, voter_a, voter_b, _r, token_id, instance_id) = gov_setup();
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open");
        // Freeze voter_a: the vote lock (a transfer to escrow) is blocked exactly as
        // TransferToken would be.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            4,
            Operation::FreezeTokenAccount {
                token_id,
                account: voter_a.address(),
            },
        )
        .expect("freeze");
        let err = gov_vote(
            &mut state,
            &config,
            &voter_a,
            1,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(100),
            token_id,
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenAccountFrozen));

        // Pause the token: any voter's lock is blocked.
        mandate_exec(
            &mut state,
            &config,
            &creator,
            5,
            Operation::SetTokenPaused {
                token_id,
                paused: true,
            },
        )
        .expect("pause");
        let err = gov_vote(
            &mut state,
            &config,
            &voter_b,
            0,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(100),
            token_id,
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::TokenPaused));
        // No lock was taken on either rejected vote.
        assert_eq!(escrow_balance(&state, token_id, proposal_id), 0);
    }

    #[test]
    fn full_lifecycle_keeps_both_native_and_token_supply_balanced() {
        let (config, mut state, _creator, voter_a, voter_b, recipient, token_id, instance_id) =
            gov_setup();

        let assert_balanced = |state: &ChainState, label: &str| {
            assert!(
                state.supply_invariant_report().unwrap().balanced,
                "native supply must balance after {label}"
            );
            assert!(
                state.token_supply_report(token_id).unwrap().balanced,
                "token supply must balance after {label}"
            );
        };
        assert_balanced(&state, "create");

        gov_fund(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            Amount::from_webc(4),
        )
        .expect("fund");
        assert_balanced(&state, "fund");

        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            1,
            instance_id,
            GovernanceAction::TreasuryTransfer {
                recipient: recipient.address(),
                amount: Amount::from_webc(4),
            },
            token_id,
        )
        .expect("open");
        assert_balanced(&state, "open");

        // Both voters vote (1000 participation, 600 yes / 400 abstain -> 100% of the
        // decisive vote, quorum met).
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            2,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote a");
        gov_vote(
            &mut state,
            &config,
            &voter_b,
            0,
            proposal_id,
            VoteChoice::Abstain,
            Amount::from_units(400),
            token_id,
        )
        .expect("vote b");
        assert_balanced(&state, "vote");

        state.current_epoch = 11;
        gov_resolve(&mut state, &config, &voter_a, 3, proposal_id, token_id).expect("resolve");
        assert_eq!(
            state.governance_proposals.get(&proposal_id).unwrap().status,
            GovProposalStatus::Passed
        );
        assert_balanced(&state, "resolve");

        state.current_epoch = 13;
        gov_execute(
            &mut state,
            &config,
            &voter_a,
            4,
            proposal_id,
            Some((instance_id, recipient.address())),
        )
        .expect("execute");
        assert_balanced(&state, "execute");

        // Both voters reclaim their full locked weight.
        gov_reclaim(&mut state, &config, &voter_a, 5, proposal_id, token_id).expect("reclaim a");
        gov_reclaim(&mut state, &config, &voter_b, 1, proposal_id, token_id).expect("reclaim b");
        assert_balanced(&state, "reclaim");
        assert_eq!(token_balance(&state, token_id, voter_a.address()), 600);
        assert_eq!(token_balance(&state, token_id, voter_b.address()), 400);
        assert_eq!(escrow_balance(&state, token_id, proposal_id), 0);
    }

    #[test]
    fn votes_serialize_on_shared_proposal_and_batch_across_proposals() {
        let (config, mut state, _creator, voter_a, voter_b, _r, token_id, instance_id) =
            gov_setup();
        let p1 = gov_open(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open p1");
        let p2 = gov_open(
            &mut state,
            &config,
            &voter_a,
            1,
            instance_id,
            GovernanceAction::Signaling,
            token_id,
        )
        .expect("open p2");

        // Two DIFFERENT voters on the SAME proposal both write the proposal tally
        // record (and the shared escrow balance), so they must serialize.
        let a_on_p1 = Transaction::for_cast_vote(
            &voter_a,
            2,
            p1,
            VoteChoice::Yes,
            Amount::from_units(100),
            token_id,
            gov_fee(),
        )
        .expect("a votes p1");
        let b_on_p1 = Transaction::for_cast_vote(
            &voter_b,
            0,
            p1,
            VoteChoice::No,
            Amount::from_units(100),
            token_id,
            gov_fee(),
        )
        .expect("b votes p1");
        let batches = crate::parallel_batches(&[a_on_p1, b_on_p1]);
        assert_eq!(
            batches.len(),
            2,
            "votes on the same proposal serialize on the proposal tally record"
        );

        // The SAME two voters on DIFFERENT proposals share no writable key (distinct
        // proposal records, vote records, escrows, and voter balances; the weight
        // token record is a shared READ only), so they batch.
        let a_on_p1 = Transaction::for_cast_vote(
            &voter_a,
            2,
            p1,
            VoteChoice::Yes,
            Amount::from_units(100),
            token_id,
            gov_fee(),
        )
        .expect("a votes p1");
        let b_on_p2 = Transaction::for_cast_vote(
            &voter_b,
            0,
            p2,
            VoteChoice::Yes,
            Amount::from_units(100),
            token_id,
            gov_fee(),
        )
        .expect("b votes p2");
        let batches = crate::parallel_batches(&[a_on_p1, b_on_p2]);
        assert_eq!(
            batches.len(),
            1,
            "votes on different proposals by different voters parallelize"
        );
    }

    #[test]
    fn expired_after_execution_window_blocks_the_payout() {
        let (config, mut state, _creator, voter_a, _b, recipient, token_id, instance_id) =
            gov_setup();
        gov_fund(
            &mut state,
            &config,
            &voter_a,
            0,
            instance_id,
            Amount::from_webc(6),
        )
        .expect("fund");
        let proposal_id = gov_open(
            &mut state,
            &config,
            &voter_a,
            1,
            instance_id,
            GovernanceAction::TreasuryTransfer {
                recipient: recipient.address(),
                amount: Amount::from_webc(6),
            },
            token_id,
        )
        .expect("open");
        gov_vote(
            &mut state,
            &config,
            &voter_a,
            2,
            proposal_id,
            VoteChoice::Yes,
            Amount::from_units(600),
            token_id,
        )
        .expect("vote");
        state.current_epoch = 11;
        gov_resolve(&mut state, &config, &voter_a, 3, proposal_id, token_id).expect("resolve");
        let recipient_before = balance(&state, recipient.address());
        // eta = 13; execution window is [13, 13 + voting_period(10)) = [13, 23).
        // At epoch 23 the window has lapsed: execute marks Expired, pays nothing.
        state.current_epoch = 23;
        gov_execute(
            &mut state,
            &config,
            &voter_a,
            4,
            proposal_id,
            Some((instance_id, recipient.address())),
        )
        .expect("execute (expires)");
        assert_eq!(
            state.governance_proposals.get(&proposal_id).unwrap().status,
            GovProposalStatus::Expired
        );
        // No payout occurred; the treasury is intact and supply balances.
        assert_eq!(balance(&state, recipient.address()), recipient_before);
        assert_eq!(state.governance_treasury, Amount::from_webc(6));
        assert!(state.supply_invariant_report().unwrap().balanced);
        // A voter can still reclaim after expiry (Expired is a resolved state).
        gov_reclaim(&mut state, &config, &voter_a, 5, proposal_id, token_id).expect("reclaim");
        assert_eq!(token_balance(&state, token_id, voter_a.address()), 600);
    }
}
