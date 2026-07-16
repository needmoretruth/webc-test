//! Fuzz mempool admission against a fixed genesis state.
//!
//! `Mempool::insert` runs the full admission gauntlet (signature, chain id,
//! nonce bounds, fee floor, affordability) on a peer-supplied transaction. It
//! must classify every input as accepted/replaced/rejected without panicking,
//! over-allocating, or hanging. This target decodes arbitrary bytes as a
//! `Transaction` and inserts it into a fresh mempool over a deterministic
//! genesis; a panic is a bug.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use webc_chain::{
    Amount, ChainConfig, ChainState, GenesisAccount, GenesisConfig, GenesisValidator, Transaction,
};
use webc_crypto::Keypair;
use webc_node::{Mempool, MempoolConfig};

/// A fixed genesis with one funded account and one active validator, built once.
fn genesis() -> &'static (ChainConfig, ChainState) {
    static GENESIS: OnceLock<(ChainConfig, ChainState)> = OnceLock::new();
    GENESIS.get_or_init(|| {
        let funded = Keypair::from_seed([1u8; 32]);
        let validator = Keypair::from_seed([2u8; 32]);
        let config = ChainConfig::default();
        let genesis = GenesisConfig {
            chain: config.clone(),
            accounts: vec![
                GenesisAccount {
                    address: funded.address(),
                    balance: Amount::from_webc(1_000),
                },
                GenesisAccount {
                    address: validator.address(),
                    balance: Amount::from_webc(1_000),
                },
            ],
            validators: vec![GenesisValidator {
                operator: validator.address(),
                consensus_key: validator.public_key(),
                self_stake: Amount::from_webc(200),
                commission_bps: 500,
                bootstrap: false,
            }],
        };
        let state = ChainState::from_genesis(&genesis).expect("valid fuzz genesis");
        (config, state)
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(tx) = bincode::deserialize::<Transaction>(data) else {
        return;
    };
    let (config, state) = genesis();
    let mut mempool = Mempool::new(MempoolConfig::default());
    // Fixed timestamp: admission must be deterministic and clock-free from the
    // caller's supplied `now_ms`. Any Ok/Err classification is fine; a panic is not.
    let _ = mempool.insert(tx, state, config, 1_700_000_000_000);
});
