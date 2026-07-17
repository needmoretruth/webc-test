//! Core WEBC protocol logic.
//!
//! This crate deliberately keeps the prototype small and auditable. Networking,
//! durable storage, and production BFT consensus should live in separate crates
//! once the deterministic state transition rules are stable.

pub mod account;
pub mod amount;
pub mod authorization;
pub mod authorization_policy;
pub mod block;
pub mod block_builder;
pub mod bridge;
pub mod canonical;
pub mod consensus;
pub mod contract;
pub mod dex;
pub mod fees;
pub mod genesis;
pub mod grants;
pub mod hex_bytes;
pub mod inflation;
pub mod mandate;
pub mod namespace;
pub mod object;
pub mod oracle;
pub mod protocol;
pub mod round;
pub mod scheduler;
pub mod service_registry;
pub mod session_key;
pub mod slashing;
pub mod sponsorship;
pub mod staking;
pub mod state;
pub mod state_key;
pub mod transaction;
pub mod unbonding;

pub use account::Account;
pub use amount::{Amount, GENESIS_TOTAL_SUPPLY, WEBC_DECIMALS, WEBC_UNIT};
pub use authorization::AuthorizationLane;
pub use authorization_policy::{
    active_key_rotation_message, post_quantum_root_rotation_message, AccountAuthorizationPolicy,
    AccountAuthorizationPolicyV1, AuthorizationPolicyRevision, PostQuantumRoot,
    PostQuantumRootReveal, PostQuantumScheme, ACTIVE_KEY_ROTATION_DOMAIN,
    INITIAL_AUTHORIZATION_POLICY_REVISION, LEGACY_AUTHORIZATION_POLICY_REVISION,
    MAX_AUTHORIZATION_POLICY_REVISION, MAX_POST_QUANTUM_PUBLIC_KEY_BYTES,
    MAX_POST_QUANTUM_SIGNATURE_BYTES, POST_QUANTUM_ROOT_ROTATION_DOMAIN,
};
pub use block::{Block, BlockHeader};
pub use block_builder::{
    apply_block, build_block, evidence_root, receipt_root, transaction_root, BlockBuildInput,
    MAX_BLOCK_SLASHING_EVIDENCE,
};
pub use bridge::{
    AssetId, BridgeConfig, BridgeEvent, BridgeMessage, ExternalChain, MAX_BRIDGE_RECIPIENT_BYTES,
};
pub use consensus::{
    detect_double_votes, DoubleVoteEvidence, FinalityCertificate, Proposal, SignedProposal,
    SignedVote, ValidatorPower, ValidatorSet, Vote, VoteType, CONSENSUS_PROPOSAL_DOMAIN,
    CONSENSUS_VOTE_DOMAIN, LEADER_SCHEDULE_DOMAIN,
};
pub use contract::{
    builtin_contract, kv_command, BuiltinContract, Contract, ContractContext, ContractError,
    ContractManifest, ContractRuntimeConfig, ContractStateValue, GasMeter, KeyValueContract,
    CONTRACT_ABI_VERSION, CONTRACT_GAS_SCHEDULE_VERSION, CONTRACT_LEAF_DOMAIN,
    CONTRACT_STATE_LEAF_DOMAIN, MAX_CONTRACT_FOOTPRINT_KEYS, MAX_CONTRACT_INPUT_BYTES,
    MAX_CONTRACT_STATE_VALUE_BYTES,
};
pub use dex::{
    prorata_fills, uniform_clearing_price, DexConfig, Order, OrderId, OrderSide, Price,
    TradingPair, DEX_ORDER_LEAF_DOMAIN,
};
pub use fees::{
    next_base_fee, next_localized_base_fee, split_fee, FeeBreakdown, FeePolicy, NamespaceFeeState,
    StoragePricing, StorageRefund, NAMESPACE_FEE_LEAF_DOMAIN,
};
pub use genesis::{GenesisAccount, GenesisConfig, GenesisValidator};
pub use grants::StakeGrant;
pub use inflation::{BootstrapIssuance, InflationSchedule};
pub use mandate::{
    Mandate, MandateConfig, MandateCounterparty, MandateCounterpartyPolicy, MandateId,
    MANDATE_LEAF_DOMAIN,
};
pub use namespace::{namespace_state_key_hash, NamespaceRecord, NAMESPACE_LEAF_DOMAIN};
pub use object::{ObjectId, ObjectOwner, ObjectVersion, StateObject, MAX_OBJECT_DATA_BYTES};
pub use oracle::{
    accuracy_weight, median, Feed, FeedId, FeedValue, OracleConfig, OracleReporter,
    ORACLE_ACCURACY_SCALE, ORACLE_FEED_LEAF_DOMAIN, ORACLE_REPORTER_LEAF_DOMAIN,
};
pub use protocol::{
    AuthorizationLaneId, BaseUnits, BlockHeight, ChainId, ChainIdError, Epoch, Nonce,
    ProtocolVersion, ValidatorId, CURRENT_PROTOCOL_VERSION,
};
pub use round::{
    ConsensusAction, ConsensusEvent, ConsensusMachine, ConsensusMessage, ConsensusWalRecord, Step,
    TimeoutKind, ValidatorIdentity, MAX_FUTURE_ROUNDS, MAX_PAST_ROUNDS,
};
pub use scheduler::parallel_batches;
pub use service_registry::{
    ServiceEntry, ServiceId, ServicePaymentFlags, ServicePrice, ServiceStatus,
    INITIAL_SERVICE_REVISION, MAX_SERVICE_CATEGORIES, MAX_SERVICE_ENDPOINT_BYTES,
    MAX_SERVICE_PRICE_UNIT_BYTES, MAX_SERVICE_PRICING_ENTRIES, MAX_SERVICE_TITLE_BYTES,
    SERVICE_REGISTRY_LEAF_DOMAIN,
};
pub use session_key::{
    session_key_authorization_message, SessionAllowedOperations, SessionKey,
    SessionKeyAuthorizationAction, SessionKeyConfig, SessionKeyConstraints, SessionKeyId,
    SESSION_KEY_AUTHORIZATION_DOMAIN,
};
pub use slashing::{InactivityLeakConfig, SlashingEvidence, SlashingOutcome, SlashingPolicy};
pub use sponsorship::{
    sponsor_state_key_hash, AppSponsor, SponsorUserWindow, SponsorshipConfig, SPONSOR_LEAF_DOMAIN,
};
pub use staking::{
    Delegation, StakingConfig, Validator, ValidatorStatus, SEVEN_DAY_TARGET_AT_ONE_MINUTE_EPOCHS,
};
pub use state::{
    AccountStateProof, ChainConfig, ChainState, Event, OrderCloseReason, Receipt,
    SupplyInvariantReport,
};
pub use state_key::{ProtocolStateKey, StateKey, StateKeyKind, MAX_TRANSACTION_STATE_KEYS};
pub use transaction::{AccessList, FeeBid, Operation, Transaction};
pub use unbonding::{
    CoolingTranche, UnbondingKind, UnbondingQueue, UnbondingRequest, UnbondingRequestId,
    UnbondingSlashOutcome, UnbondingStatus, UnbondingTransition,
};

/// Stable cross-language domain tag embedded in every signing payload.
///
/// Both Rust and TypeScript must use this exact string. Bumping it invalidates
/// all previously signed transactions, so change it only when intentionally
/// taking a signing-format breaking change.
pub const SIGNING_DOMAIN: &str = "WEBC_SIGNED_TRANSACTION_V4";

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("unsupported protocol configuration version: {actual:?}")]
    UnsupportedProtocolVersion { actual: ProtocolVersion },
    #[error("crypto error: {0}")]
    Crypto(#[from] webc_crypto::CryptoError),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("canonical protocol JSON cannot contain floating-point numbers")]
    NonIntegerCanonicalNumber,
    #[error("canonical protocol JSON integer is outside the JS safe range (±(2^53-1))")]
    CanonicalIntegerOutOfSafeRange,
    #[error("account not found: {0}")]
    AccountNotFound(webc_crypto::Address),
    #[error("nonce mismatch for {address}: expected {expected}, got {actual}")]
    NonceMismatch {
        address: webc_crypto::Address,
        expected: u64,
        actual: u64,
    },
    #[error("insufficient balance for {address}: needed {needed}, available {available}")]
    InsufficientBalance {
        address: webc_crypto::Address,
        needed: Amount,
        available: Amount,
    },
    #[error("transaction fee bid is below current base fee")]
    FeeTooLow,
    #[error("fee policy is invalid for deterministic base-fee adjustment")]
    InvalidFeePolicy,
    #[error("gas limit is lower than required execution units")]
    GasLimitTooLow,
    #[error("transaction is missing signature")]
    MissingSignature,
    #[error("public key does not match transaction sender address")]
    SenderPublicKeyMismatch,
    #[error(
        "transaction authorization policy revision mismatch: expected {expected}, got {actual}"
    )]
    AuthorizationPolicyRevisionMismatch { expected: u64, actual: u64 },
    #[error("transaction public key is not active in the account authorization policy")]
    AuthorizationKeyMismatch,
    #[error("account authorization policy is invalid")]
    InvalidAuthorizationPolicy,
    #[error("authorization policy revision is outside the exact wire range")]
    InvalidAuthorizationPolicyRevision,
    #[error("post-quantum root commitment is invalid")]
    InvalidPostQuantumRoot,
    #[error("account authorization policy is already installed")]
    AuthorizationPolicyAlreadyExists,
    #[error("account authorization policy installation must use the default lane")]
    AuthorizationPolicyRequiresDefaultLane,
    #[error("validator already exists: {0}")]
    ValidatorAlreadyExists(webc_crypto::Address),
    #[error("duplicate genesis account: {0}")]
    DuplicateGenesisAccount(webc_crypto::Address),
    #[error("genesis allocation sums to {actual} but the chain config pins the total supply at {expected}")]
    GenesisSupplyMismatch { expected: Amount, actual: Amount },
    #[error("validator not found: {0}")]
    ValidatorNotFound(webc_crypto::Address),
    #[error("validator is not active: {0}")]
    ValidatorNotActive(webc_crypto::Address),
    #[error("stake amount is below protocol minimum")]
    StakeTooSmall,
    #[error("validator commission is above protocol maximum")]
    CommissionTooHigh,
    #[error("bootstrap validators are disabled by this chain config")]
    BootstrapDisabled,
    #[error("delegation not found")]
    DelegationNotFound,
    #[error("delegation amount is too small")]
    DelegationTooSmall,
    #[error("delegation would exceed 80% of the validator pool")]
    DelegationRatioExceeded,
    #[error("slashing evidence is invalid or non-objective")]
    InvalidSlashingEvidence,
    #[error("slashing evidence was already processed")]
    SlashingReplay,
    #[error("sender is not authorized to submit incoming bridge messages")]
    UnauthorizedBridgeRelayer,
    #[error("bridge message was already processed")]
    BridgeReplay,
    #[error("bridge message destination is not WEBC")]
    BridgeDestinationMismatch,
    #[error("bridge recipient is not a valid WEBC address byte array")]
    InvalidBridgeRecipient,
    #[error("bridge amount must be greater than zero")]
    BridgeAmountZero,
    #[error("asset and bridge operation do not form a supported direction")]
    InvalidBridgeAssetFlow,
    #[error("bridge message source does not match the asset origin")]
    BridgeSourceMismatch,
    #[error("native bridge escrow is insufficient: needed {needed}, available {available}")]
    InsufficientBridgeEscrow { needed: Amount, available: Amount },
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("inflation schedule parameters are invalid")]
    InvalidInflationSchedule,
    #[error("inactivity-leak configuration is invalid")]
    InvalidInactivityLeakConfig,
    #[error("stake grant parameters are invalid")]
    InvalidStakeGrant,
    #[error("block chain ID does not match the active protocol configuration")]
    BlockChainIdMismatch,
    #[error("transaction chain ID does not match the active protocol configuration")]
    TransactionChainIdMismatch,
    #[error("block execution units exceed the configured maximum of {maximum}")]
    BlockUnitsExceeded { maximum: u64 },
    #[error(
        "application namespace {namespace} exceeds its fair block-capacity share \
         of {maximum} execution units"
    )]
    NamespaceBlockShareExceeded {
        namespace: webc_crypto::Hash256,
        maximum: u64,
    },
    #[error(
        "serialized block size {actual} bytes exceeds the configured maximum of {maximum} bytes"
    )]
    BlockBytesExceeded { actual: u64, maximum: u64 },
    #[error("block carries {actual} slashing evidence items, above the maximum of {maximum}")]
    TooManyBlockEvidence { actual: usize, maximum: usize },
    #[error("supply invariant does not reconcile")]
    SupplyInvariantViolation,
    #[error(
        "block timestamp {timestamp} is not strictly greater than the parent timestamp {parent}"
    )]
    NonMonotonicBlockTimestamp { timestamp: u64, parent: u64 },
    #[error("unsupported state-key version: {actual:?}")]
    UnsupportedStateKeyVersion { actual: ProtocolVersion },
    #[error("transaction access list contains duplicates or read/write overlap")]
    InvalidAccessList,
    #[error("transaction declares {actual} state keys, above the maximum of {maximum}")]
    TooManyStateKeys { actual: usize, maximum: usize },
    #[error("transaction read undeclared state: {key:?}")]
    UndeclaredStateRead { key: StateKey },
    #[error("transaction wrote undeclared or read-only state: {key:?}")]
    UndeclaredStateWrite { key: StateKey },
    #[error("transaction declared state it did not access")]
    UnusedDeclaredStateAccess,
    #[error("unbonding amount must be greater than zero")]
    UnbondingAmountZero,
    #[error("unbonding request was not found")]
    UnbondingRequestNotFound,
    #[error("unbonding request is owned by another account")]
    UnbondingOwnerMismatch,
    #[error("unbonding request has no matured principal to claim")]
    UnbondingNotWithdrawable,
    #[error("operator cannot fully exit while delegated stake remains")]
    OperatorExitHasDelegations,
    #[error("partial operator exit would deactivate the validator pool")]
    OperatorExitWouldDeactivatePool,
    #[error("the default authorization lane cannot be opened as a prepaid lane")]
    DefaultAuthorizationLaneReserved,
    #[error("authorization lane already exists")]
    AuthorizationLaneExists,
    #[error("authorization lane was not found")]
    AuthorizationLaneNotFound,
    #[error("authorization lane management must use the default lane")]
    LaneManagementRequiresDefault,
    #[error(
        "authorization lane fee balance is insufficient: needed {needed}, available {available}"
    )]
    InsufficientLaneFeeBalance { needed: Amount, available: Amount },
    #[error("authorization lane fee deposit must be greater than zero")]
    AuthorizationLaneDepositZero,
    #[error("storage pricing refund basis points exceed 10000")]
    InvalidStoragePricing,
    #[error("sponsorship configuration is invalid (day-window must be non-zero)")]
    InvalidSponsorshipConfig,
    #[error("application sponsor already exists for this namespace")]
    AppSponsorAlreadyExists,
    #[error("application sponsor was not found for this namespace")]
    AppSponsorNotFound,
    #[error("only the sponsor owner may fund or withdraw this application sponsor")]
    AppSponsorNotOwner,
    #[error("application sponsor daily budget cap exceeds the protocol maximum")]
    AppSponsorDailyCapTooHigh,
    #[error("application sponsor budget is insufficient for this withdrawal: needed {needed}, available {available}")]
    AppSponsorBudgetInsufficient { needed: Amount, available: Amount },
    #[error("fee sponsorship must use the default authorization lane")]
    SponsorshipRequiresDefaultLane,
    #[error(
        "oracle configuration is invalid (settlement cadence and liveness window must be non-zero)"
    )]
    InvalidOracleConfig,
    #[error("oracle feed already exists for this feed id")]
    OracleFeedAlreadyExists,
    #[error("oracle feed was not found for this feed id")]
    OracleFeedNotFound,
    #[error("reporter is already registered on this oracle feed")]
    OracleReporterAlreadyRegistered,
    #[error("reporter is not registered on this oracle feed")]
    OracleReporterNotFound,
    #[error("this oracle operation must use the default authorization lane")]
    OracleRequiresDefaultLane,
    #[error("oracle read-fee payment must be greater than zero")]
    OracleReadAmountZero,
    #[error("DEX configuration is invalid (per-fill fee basis points exceed 10000)")]
    InvalidDexConfig,
    #[error("DEX trading pair is invalid (base and quote must differ)")]
    InvalidTradingPair,
    #[error("a DEX order already exists for this order id")]
    DexOrderAlreadyExists,
    #[error("no DEX order exists for this order id")]
    DexOrderNotFound,
    #[error("only the order owner may cancel this DEX order")]
    DexOrderNotOwner,
    #[error("this DEX operation must use the default authorization lane")]
    DexRequiresDefaultLane,
    #[error("DEX order amount is zero or below the configured minimum")]
    DexOrderAmountTooSmall,
    #[error("DEX order limit price must be greater than zero")]
    DexOrderPriceZero,
    #[error("DEX order deadline height is before the current block height")]
    DexOrderDeadlineInPast,
    #[error("application namespace is already registered")]
    NamespaceAlreadyRegistered,
    #[error("application namespace is not registered")]
    NamespaceNotFound,
    #[error("only the current namespace owner may transfer this namespace")]
    NamespaceNotOwner,
    #[error("mandate configuration is invalid (rate-limit day-window must be non-zero)")]
    InvalidMandateConfig,
    #[error("mandate grant parameters are invalid (budget, per-tx cap, or allowlist)")]
    InvalidMandate,
    #[error("a mandate already exists for this principal, agent key, and grant nonce")]
    MandateAlreadyExists,
    #[error("no mandate exists for this mandate id")]
    MandateNotFound,
    #[error("only the mandate principal may top up or revoke this mandate")]
    MandateNotOwner,
    #[error("this mandate management operation must use the default authorization lane")]
    MandateRequiresDefaultLane,
    #[error("mandate spend was not signed by the mandate's agent key")]
    MandateAgentKeyMismatch,
    #[error("mandate has been revoked and rejects all spends")]
    MandateRevoked,
    #[error("mandate has expired and rejects all spends")]
    MandateExpired,
    #[error("mandate spend must move a non-zero principal amount")]
    MandateZeroAmount,
    #[error("mandate spend exceeds the per-transaction maximum")]
    MandatePerTxExceeded,
    #[error("mandate spend exceeds the remaining escrowed budget")]
    MandateBudgetExceeded,
    #[error("mandate spend recipient is not permitted by the counterparty policy")]
    MandateCounterpartyNotAllowed,
    #[error("mandate spend exceeds the per-day rate limit")]
    MandateRateLimited,
    #[error("a service is already registered for this namespace, owner, and create nonce")]
    ServiceAlreadyExists,
    #[error("no service is registered for this service id")]
    ServiceNotFound,
    #[error("only the service owner may update or set the status of this service")]
    ServiceNotOwner,
    #[error("the service is not active and cannot be paid")]
    ServiceNotActive,
    #[error(
        "service entry is invalid (empty required field, over-length field, or over-count \
         categories/pricing)"
    )]
    InvalidServiceEntry,
    #[error("a contract is already registered for this code id")]
    ContractAlreadyExists,
    #[error("no contract is registered for this code id")]
    ContractNotFound,
    #[error("contract manifest is invalid (footprint, versions, or owner)")]
    InvalidContractManifest,
    #[error("unsupported contract ABI/manifest version: {actual}")]
    UnsupportedContractAbiVersion { actual: u16 },
    #[error("contract invocation namespace does not match the registered manifest")]
    ContractNamespaceMismatch,
    #[error("contract invocation declared footprint does not match the registered manifest")]
    ContractFootprintMismatch,
    #[error("contract invocation input has {actual} bytes, above the maximum of {maximum}")]
    ContractInputTooLarge { actual: usize, maximum: usize },
    #[error("contract runtime operation must use the default authorization lane")]
    ContractRequiresDefaultLane,
    #[error("contract call exceeded its gas limit")]
    ContractOutOfGas,
    #[error("contract touched an undeclared state key")]
    ContractUndeclaredKey,
    #[error("contract state value has {actual} bytes, above the maximum of {maximum}")]
    ContractStateValueTooLarge { actual: usize, maximum: usize },
    #[error("contract input is malformed")]
    ContractInvalidInput,
    #[error("object already exists")]
    ObjectAlreadyExists,
    #[error("object was not found")]
    ObjectNotFound,
    #[error("object namespace does not match the signed operation")]
    ObjectNamespaceMismatch,
    #[error("object is not owned by the transaction sender")]
    ObjectOwnerMismatch,
    #[error("shared-object mutation is not enabled in the Phase 1 native path")]
    SharedObjectMutationUnsupported,
    #[error("object version mismatch: expected {expected}, actual {actual}")]
    ObjectVersionMismatch { expected: u64, actual: u64 },
    #[error("object data contains {actual} bytes, above the maximum of {maximum}")]
    ObjectDataTooLarge { actual: usize, maximum: usize },
    #[error("post-quantum root reveal does not match the committed account root")]
    InvalidPostQuantumRootReveal,
    #[error("session key was not found")]
    SessionKeyNotFound,
    #[error("session key already exists")]
    SessionKeyAlreadyExists,
    #[error("session key has expired")]
    SessionKeyExpired,
    #[error("account is at its maximum number of session keys")]
    SessionKeyLimitExceeded,
    #[error("requested session-key lifetime exceeds the configured maximum")]
    SessionKeyLifetimeTooLong,
    #[error("account has no installed policy able to own session keys")]
    SessionKeyRequiresInstalledPolicy,
    #[error("session-key management must use the default lane")]
    SessionKeyManagementRequiresDefaultLane,
    #[error("session-key transaction used a lane other than its bound lane")]
    SessionKeyLaneMismatch,
    #[error("session key is not permitted to authorize this operation")]
    SessionKeyOperationNotPermitted,
    #[error("session-key transaction exceeds the per-use amount limit")]
    SessionKeyAmountExceeded,
    #[error("session-key transaction exceeds the cumulative amount budget")]
    SessionKeyBudgetExceeded,
    #[error("session-key transaction exceeds the per-use fee limit")]
    SessionKeyFeeExceeded,
    #[error("session-key transaction exceeds the cumulative fee budget")]
    SessionKeyFeeBudgetExceeded,
    #[error("session-key constraints are invalid")]
    InvalidSessionKeyConstraints,
    #[error("active-key rotation must use the default lane")]
    ActiveKeyRotationRequiresDefaultLane,
    #[error("active-key rotation requires an installed policy with a post-quantum root")]
    ActiveKeyRotationRequiresInstalledPolicy,
    #[error("active-key rotation must change the active transaction key")]
    ActiveKeyRotationToSameKey,
    #[error("post-quantum root rotation must use the default lane")]
    PostQuantumRootRotationRequiresDefaultLane,
    #[error("post-quantum root rotation requires an installed policy with a post-quantum root")]
    PostQuantumRootRotationRequiresInstalledPolicy,
    #[error("post-quantum root rotation must change the committed recovery root")]
    PostQuantumRootRotationToSameRoot,
    #[error(
        "consensus message chain ID or protocol version does not match the local configuration"
    )]
    ConsensusConfigMismatch,
    #[error("consensus message does not match the expected height or round")]
    ConsensusHeightRoundMismatch,
    #[error("consensus proposal was not signed by the scheduled leader for this height and round")]
    ConsensusProposalNotFromLeader,
    #[error(
        "consensus re-proposal carries an invalid proof-of-lock (missing, mismatched, \
         or sub-quorum prevote set for the cited valid_round)"
    )]
    ConsensusProofOfLockInvalid,
    #[error("consensus proposal block hash does not match its carried block")]
    ConsensusProposalBlockMismatch,
    #[error("consensus message came from a validator absent from the height's snapshot")]
    ConsensusValidatorNotInSet,
    #[error("consensus message signature is invalid for the registered consensus key")]
    ConsensusSignatureInvalid,
    #[error("finality certificate does not carry strictly more than two-thirds precommit power")]
    FinalityQuorumNotReached,
    #[error("imported block does not match local re-execution of its transactions")]
    ImportedBlockMismatch,
    #[error(
        "consensus write-ahead journal is inconsistent with this validator height; \
         refusing to vote (a journal that cannot be trusted means the node no longer \
         knows what it already signed)"
    )]
    ConsensusWalMismatch,
}

impl From<bincode::Error> for ChainError {
    fn from(error: bincode::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

impl From<serde_json::Error> for ChainError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}
