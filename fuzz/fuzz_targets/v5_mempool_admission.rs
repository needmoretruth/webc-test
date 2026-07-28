//! Fuzz protocol-2 mempool admission against a fixed funded state.
//!
//! Purpose: drive hostile V5 JSON through the exact validation, nonce, validity,
//! fee-reserve, replacement, and capacity policy used by the node. This target
//! owns no persistence or consensus behavior. Security boundary: arbitrary bytes
//! must be rejected or classified without panic, unbounded allocation, mutation
//! of the supplied chain state, or mutation before a durable plan is committed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use webc_chain::{
    Account, Amount, ChainConfig, ChainState, TransactionV5, TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::Keypair;
use webc_node::{V5Mempool, V5MempoolConfig};
use webc_storage::LocalTimestampMs;

/// Fixed protocol-2 state/configuration reused without mutation by every case.
fn fixture() -> &'static (ChainConfig, ChainState) {
    static FIXTURE: OnceLock<(ChainConfig, ChainState)> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let sender = Keypair::from_seed([1; 32]);
        let config = ChainConfig {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            ..ChainConfig::default()
        };
        let mut state = ChainState {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: config.chain_id.clone(),
            current_base_fee_per_unit: 1,
            ..ChainState::default()
        };
        state.accounts.insert(
            sender.address(),
            Account::with_balance(Amount::from_webc(1_000)),
        );
        (config, state)
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(transaction) = TransactionV5::decode_json(data) else {
        return;
    };
    let (config, state) = fixture();
    let state_before = state.clone();
    let mempool = V5Mempool::new(V5MempoolConfig::default()).expect("fixed fuzz policy is valid");
    let plan = mempool.plan_admission(
        transaction,
        state,
        config,
        webc_chain::BlockHeight::new(1),
        LocalTimestampMs::new(1_700_000_000_000),
    );
    assert_eq!(
        state, &state_before,
        "admission must not mutate chain state"
    );
    assert!(
        mempool.is_empty(),
        "planning must remain disk-before-memory"
    );
    let _classification = plan;
});
