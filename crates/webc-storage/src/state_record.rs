//! Versioned at-rest chain-state records and the one-way schema-1 adapter.
//!
//! Purpose: keep database layout compatibility outside the consensus state
//! machine. Schema 2 wraps the current [`ChainState`] in an explicit magic and
//! record version. Schema 1 is represented by an exact frozen field-order type
//! matching the last `main` layout before V5 sponsor-grant state was added.
//!
//! Responsibilities: bounded encode/decode, strict schema-2 envelope checks,
//! and deterministic conversion of protocol-1 snapshots to an empty V5 grant
//! book. Non-responsibilities: database transactions, chain-tip validation,
//! state execution, or backward migration from schema 2.
//!
//! Data flow: [`decode_schema_v1`] consumes the old direct-bincode record once;
//! [`ChainStore`](crate::ChainStore) atomically rewrites it with [`encode_schema_v2`]
//! and advances the store schema marker. Every later read uses only
//! [`decode_schema_v2`]. Security boundary: the shared record codec checks the
//! outer byte ceiling and rejects trailing bytes before conversion; schema 2
//! additionally rejects wrong magic/version values and schema 1 rejects a
//! protocol-2 state that could not have been represented by its frozen layout.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use webc_chain::{
    Account, AccountAuthorizationPolicy, Amount, AppSponsor, AssetId, AuthorizationLane,
    AuthorizationLaneId, ChainId, ChainState, ContractManifest, ContractStateValue, Delegation,
    ExternalChain, Feed, FeedId, GovernanceInstance, GovernanceInstanceId, GovernanceProposal,
    Mandate, MandateId, NamespaceFeeState, NamespaceRecord, NftCollection, NftCollectionId, NftId,
    NftItem, ObjectId, OracleReporter, Order, OrderId, ProposalId, ProtocolVersion, ServiceEntry,
    ServiceId, SessionKey, SessionKeyId, SponsorGrantBookV1, StateObject, TokenId, TokenRecord,
    UnbondingQueue, Validator, VoteRecord, WasmBytecode, WasmContractManifest,
    CURRENT_PROTOCOL_VERSION,
};
use webc_crypto::{Address, Hash256};

use crate::error::StorageError;
use crate::record_codec::{decode, encode, StoredRecordKind};

/// Fixed marker preventing a schema-2 snapshot from being confused with a
/// direct schema-1 `ChainState` bincode stream.
const STATE_SNAPSHOT_V2_MAGIC: [u8; 8] = *b"WEBCSTV2";

/// Version inside the state record itself, independent from the table layout.
const STATE_SNAPSHOT_RECORD_VERSION: u16 = 2;

/// Explicit schema-2 state record.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateSnapshotRecordV2 {
    /// Fixed format marker checked before the state is accepted.
    magic: [u8; 8],
    /// Exactly [`STATE_SNAPSHOT_RECORD_VERSION`].
    version: u16,
    /// Complete current deterministic chain state.
    state: ChainState,
}

/// Borrowed encoder view avoids cloning a potentially 256 MiB state snapshot.
#[derive(Serialize)]
struct StateSnapshotRecordV2Ref<'a> {
    magic: [u8; 8],
    version: u16,
    state: &'a ChainState,
}

/// Encodes one current state under the explicit schema-2 envelope.
pub(crate) fn encode_schema_v2(state: &ChainState) -> Result<Vec<u8>, StorageError> {
    encode(
        StoredRecordKind::StateSnapshot,
        &StateSnapshotRecordV2Ref {
            magic: STATE_SNAPSHOT_V2_MAGIC,
            version: STATE_SNAPSHOT_RECORD_VERSION,
            state,
        },
    )
}

/// Decodes one schema-2 state and rejects cross-version or unwrapped bytes.
pub(crate) fn decode_schema_v2(bytes: &[u8]) -> Result<ChainState, StorageError> {
    let record: StateSnapshotRecordV2 = decode(StoredRecordKind::StateSnapshot, bytes)?;
    if record.magic != STATE_SNAPSHOT_V2_MAGIC || record.version != STATE_SNAPSHOT_RECORD_VERSION {
        return Err(StorageError::Corruption(
            "state snapshot has the wrong schema-2 magic or record version".into(),
        ));
    }
    Ok(record.state)
}

/// Exact direct-bincode field order of the final schema-1 `ChainState`.
///
/// Do not reorder, add defaults, or reuse this type for new writes. Its only
/// purpose is decoding the old protocol-1 snapshot during the one-way migration.
#[derive(Clone, Serialize, Deserialize)]
struct StateSnapshotSchemaV1 {
    protocol_version: ProtocolVersion,
    chain_id: ChainId,
    accounts: BTreeMap<Address, Account>,
    authorization_policies: BTreeMap<Address, AccountAuthorizationPolicy>,
    authorization_lanes: BTreeMap<(Address, AuthorizationLaneId), AuthorizationLane>,
    session_keys: BTreeMap<(Address, SessionKeyId), SessionKey>,
    objects: BTreeMap<ObjectId, StateObject>,
    validators: BTreeMap<Address, Validator>,
    delegations: BTreeMap<(Address, Address), Delegation>,
    unbonding: UnbondingQueue,
    asset_balances: BTreeMap<(AssetId, Address), Amount>,
    native_bridge_escrow: BTreeMap<ExternalChain, Amount>,
    processed_bridge_messages: BTreeSet<Hash256>,
    processed_slashing_evidence: BTreeSet<Hash256>,
    burned_fees: Amount,
    slashed_units: Amount,
    storage_deposits: Amount,
    sponsors: BTreeMap<Hash256, AppSponsor>,
    sponsor_budgets: Amount,
    namespaces: BTreeMap<Hash256, NamespaceRecord>,
    oracle_feeds: BTreeMap<FeedId, Feed>,
    oracle_reporters: BTreeMap<(FeedId, Address), OracleReporter>,
    oracle_bonds: Amount,
    oracle_revenue: Amount,
    dex_orders: BTreeMap<OrderId, Order>,
    dex_escrow: Amount,
    mandates: BTreeMap<MandateId, Mandate>,
    mandate_escrow: Amount,
    services: BTreeMap<ServiceId, ServiceEntry>,
    tokens: BTreeMap<TokenId, TokenRecord>,
    token_balances: BTreeMap<(TokenId, Address), Amount>,
    frozen_token_accounts: BTreeSet<(TokenId, Address)>,
    token_deposits: Amount,
    nft_collections: BTreeMap<NftCollectionId, NftCollection>,
    nft_items: BTreeMap<NftId, NftItem>,
    nft_deposits: Amount,
    governance_instances: BTreeMap<GovernanceInstanceId, GovernanceInstance>,
    governance_proposals: BTreeMap<ProposalId, GovernanceProposal>,
    governance_votes: BTreeMap<(ProposalId, Address), VoteRecord>,
    governance_deposits: Amount,
    governance_treasury: Amount,
    contracts: BTreeMap<Hash256, ContractManifest>,
    contract_state: BTreeMap<(Hash256, Hash256), ContractStateValue>,
    wasm_contracts: BTreeMap<Hash256, WasmContractManifest>,
    wasm_code: BTreeMap<Hash256, WasmBytecode>,
    namespace_fees: BTreeMap<Hash256, NamespaceFeeState>,
    validator_fee_pool: Amount,
    minted_supply: Amount,
    inflation_year_start_supply: Amount,
    current_base_fee_per_unit: u64,
    current_epoch: u64,
    current_height: u64,
    bridge_nonce: u64,
    last_block_timestamp_ms: u64,
}

impl From<StateSnapshotSchemaV1> for ChainState {
    fn from(legacy: StateSnapshotSchemaV1) -> Self {
        Self {
            protocol_version: legacy.protocol_version,
            chain_id: legacy.chain_id,
            accounts: legacy.accounts,
            authorization_policies: legacy.authorization_policies,
            authorization_lanes: legacy.authorization_lanes,
            session_keys: legacy.session_keys,
            sponsor_grants: SponsorGrantBookV1::default(),
            objects: legacy.objects,
            validators: legacy.validators,
            delegations: legacy.delegations,
            unbonding: legacy.unbonding,
            asset_balances: legacy.asset_balances,
            native_bridge_escrow: legacy.native_bridge_escrow,
            processed_bridge_messages: legacy.processed_bridge_messages,
            processed_slashing_evidence: legacy.processed_slashing_evidence,
            burned_fees: legacy.burned_fees,
            slashed_units: legacy.slashed_units,
            storage_deposits: legacy.storage_deposits,
            sponsors: legacy.sponsors,
            sponsor_budgets: legacy.sponsor_budgets,
            namespaces: legacy.namespaces,
            oracle_feeds: legacy.oracle_feeds,
            oracle_reporters: legacy.oracle_reporters,
            oracle_bonds: legacy.oracle_bonds,
            oracle_revenue: legacy.oracle_revenue,
            dex_orders: legacy.dex_orders,
            dex_escrow: legacy.dex_escrow,
            mandates: legacy.mandates,
            mandate_escrow: legacy.mandate_escrow,
            services: legacy.services,
            tokens: legacy.tokens,
            token_balances: legacy.token_balances,
            frozen_token_accounts: legacy.frozen_token_accounts,
            token_deposits: legacy.token_deposits,
            nft_collections: legacy.nft_collections,
            nft_items: legacy.nft_items,
            nft_deposits: legacy.nft_deposits,
            governance_instances: legacy.governance_instances,
            governance_proposals: legacy.governance_proposals,
            governance_votes: legacy.governance_votes,
            governance_deposits: legacy.governance_deposits,
            governance_treasury: legacy.governance_treasury,
            contracts: legacy.contracts,
            contract_state: legacy.contract_state,
            wasm_contracts: legacy.wasm_contracts,
            wasm_code: legacy.wasm_code,
            namespace_fees: legacy.namespace_fees,
            validator_fee_pool: legacy.validator_fee_pool,
            minted_supply: legacy.minted_supply,
            inflation_year_start_supply: legacy.inflation_year_start_supply,
            current_base_fee_per_unit: legacy.current_base_fee_per_unit,
            current_epoch: legacy.current_epoch,
            current_height: legacy.current_height,
            bridge_nonce: legacy.bridge_nonce,
            last_block_timestamp_ms: legacy.last_block_timestamp_ms,
        }
    }
}

/// Decodes the frozen schema-1 layout for one-way migration.
pub(crate) fn decode_schema_v1(bytes: &[u8]) -> Result<ChainState, StorageError> {
    let legacy: StateSnapshotSchemaV1 = decode(StoredRecordKind::StateSnapshot, bytes)?;
    if legacy.protocol_version != CURRENT_PROTOCOL_VERSION {
        return Err(StorageError::Corruption(
            "schema-1 state snapshot unexpectedly selects a non-legacy protocol".into(),
        ));
    }
    Ok(legacy.into())
}

#[cfg(test)]
pub(crate) fn encode_schema_v1_fixture(state: &ChainState) -> Result<Vec<u8>, StorageError> {
    if state.protocol_version != CURRENT_PROTOCOL_VERSION || !state.sponsor_grants.is_empty() {
        return Err(StorageError::Serialization(
            "schema-1 fixtures support only protocol 1 with no V5 grant state".into(),
        ));
    }
    let legacy = StateSnapshotSchemaV1 {
        protocol_version: state.protocol_version,
        chain_id: state.chain_id.clone(),
        accounts: state.accounts.clone(),
        authorization_policies: state.authorization_policies.clone(),
        authorization_lanes: state.authorization_lanes.clone(),
        session_keys: state.session_keys.clone(),
        objects: state.objects.clone(),
        validators: state.validators.clone(),
        delegations: state.delegations.clone(),
        unbonding: state.unbonding.clone(),
        asset_balances: state.asset_balances.clone(),
        native_bridge_escrow: state.native_bridge_escrow.clone(),
        processed_bridge_messages: state.processed_bridge_messages.clone(),
        processed_slashing_evidence: state.processed_slashing_evidence.clone(),
        burned_fees: state.burned_fees,
        slashed_units: state.slashed_units,
        storage_deposits: state.storage_deposits,
        sponsors: state.sponsors.clone(),
        sponsor_budgets: state.sponsor_budgets,
        namespaces: state.namespaces.clone(),
        oracle_feeds: state.oracle_feeds.clone(),
        oracle_reporters: state.oracle_reporters.clone(),
        oracle_bonds: state.oracle_bonds,
        oracle_revenue: state.oracle_revenue,
        dex_orders: state.dex_orders.clone(),
        dex_escrow: state.dex_escrow,
        mandates: state.mandates.clone(),
        mandate_escrow: state.mandate_escrow,
        services: state.services.clone(),
        tokens: state.tokens.clone(),
        token_balances: state.token_balances.clone(),
        frozen_token_accounts: state.frozen_token_accounts.clone(),
        token_deposits: state.token_deposits,
        nft_collections: state.nft_collections.clone(),
        nft_items: state.nft_items.clone(),
        nft_deposits: state.nft_deposits,
        governance_instances: state.governance_instances.clone(),
        governance_proposals: state.governance_proposals.clone(),
        governance_votes: state.governance_votes.clone(),
        governance_deposits: state.governance_deposits,
        governance_treasury: state.governance_treasury,
        contracts: state.contracts.clone(),
        contract_state: state.contract_state.clone(),
        wasm_contracts: state.wasm_contracts.clone(),
        wasm_code: state.wasm_code.clone(),
        namespace_fees: state.namespace_fees.clone(),
        validator_fee_pool: state.validator_fee_pool,
        minted_supply: state.minted_supply,
        inflation_year_start_supply: state.inflation_year_start_supply,
        current_base_fee_per_unit: state.current_base_fee_per_unit,
        current_epoch: state.current_epoch,
        current_height: state.current_height,
        bridge_nonce: state.bridge_nonce,
        last_block_timestamp_ms: state.last_block_timestamp_ms,
    };
    encode(StoredRecordKind::StateSnapshot, &legacy)
}
