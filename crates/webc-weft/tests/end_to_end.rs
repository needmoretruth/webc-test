//! Flagship end-to-end proof: **Weft source → WASM → engine → chain state**.
//!
//! Each test compiles a `.weft` source with the real `webc_weft::compile`, then
//! registers and invokes the emitted module through the *actual* chain operation
//! path (`RegisterWasmContract` / `InvokeWasmContract`) on a genuine `ChainState`,
//! and asserts committed state — exactly as the audited hand-written WAT fixtures
//! are exercised in `webc-chain`. Green here means a Weft-authored contract is
//! behaviorally indistinguishable from the known-good hand-written module, running
//! under the same deterministic engine, gas metering, and declared-access
//! discipline.
//!
//! The state key asserted comes from the compiler's own `footprint` (not a
//! hand-pinned constant), so the guest's baked data-segment key, the manifest
//! footprint, and the leaf the test reads are identical by construction.

use webc_chain::{
    wasm_vm_limits, Amount, ChainConfig, ChainState, ContractStateValue, FeeBid, GenesisAccount,
    GenesisConfig, Operation, Transaction, WasmBytecode, WasmContractManifest,
};
use webc_crypto::{Hash256, Keypair};

/// A minimal single-account chain to run contracts against, via public API only.
fn fixture() -> (ChainConfig, ChainState, Keypair) {
    let config = ChainConfig::default();
    let alice = Keypair::from_seed([1u8; 32]);
    let genesis = GenesisConfig {
        chain: config.clone(),
        accounts: vec![GenesisAccount {
            address: alice.address(),
            balance: Amount::from_webc(1_000),
        }],
        validators: Vec::new(),
    };
    let state = ChainState::from_genesis(&genesis).expect("genesis builds");
    (config, state, alice)
}

/// Registers a compiled Weft artifact as a real WASM contract.
fn register(
    state: &mut ChainState,
    config: &ChainConfig,
    signer: &Keypair,
    manifest: &WasmContractManifest,
    wasm: Vec<u8>,
) {
    let tx = Transaction::for_operation(
        signer,
        0,
        Operation::RegisterWasmContract {
            manifest: manifest.clone(),
            code: WasmBytecode(wasm),
        },
        FeeBid {
            gas_limit: 500_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        },
    )
    .expect("register tx signs");
    state
        .execute_transaction(&tx, config)
        .expect("register succeeds");
}

/// Builds a signed invocation of a compiled Weft contract.
fn invoke(
    signer: &Keypair,
    nonce: u64,
    manifest: &WasmContractManifest,
    input: Vec<u8>,
) -> Transaction {
    Transaction::for_operation(
        signer,
        nonce,
        Operation::InvokeWasmContract {
            code_id: manifest.code_id,
            namespace: manifest.namespace,
            declared_keys: manifest.footprint.clone(),
            input,
        },
        FeeBid {
            gas_limit: 10_000_000,
            max_fee_per_unit: 1,
            priority_fee_per_unit: 0,
        },
    )
    .expect("invoke tx signs")
}

#[test]
fn weft_counter_runs_on_chain_and_accumulates() {
    // 1. COMPILE the flagship source through the whole front end.
    let out =
        webc_weft::compile(include_str!("examples/counter.weft")).expect("counter.weft compiles");

    // 2. The chain's own engine gate accepts the emitted bytes (no forbidden
    //    feature, no foreign import) — the same check registration runs.
    webc_vm::validate_module(&out.wasm, &wasm_vm_limits()).expect("engine accepts the module");

    // 3. REGISTER as a real WASM contract.
    let (config, mut state, alice) = fixture();
    let code = WasmBytecode(out.wasm.clone());
    let (code_id, namespace) = (Hash256([0xc7; 32]), Hash256([0x33; 32]));
    let manifest = WasmContractManifest::new(
        code_id,
        namespace,
        code.code_hash(),
        out.footprint.iter().copied(),
        alice.address(),
    );
    register(&mut state, &config, &alice, &manifest, out.wasm.clone());

    // 4. INVOKE three times; the persistent LE u64 counter must climb 1 -> 2 -> 3.
    let key = out.footprint[0]; // == keys::state_key("counter", "count")
    for (nonce, expected) in [(1u64, 1u64), (2, 2), (3, 3)] {
        let tx = invoke(&alice, nonce, &manifest, Vec::new());
        state
            .execute_transaction(&tx, &config)
            .expect("invoke succeeds");
        assert_eq!(
            state.contract_state.get(&(namespace, key)),
            Some(&ContractStateValue(expected.to_le_bytes().to_vec())),
            "the Weft-compiled counter persisted across transactions"
        );
    }
    assert!(state.supply_invariant_report().unwrap().balanced);
}

#[test]
fn weft_echo_round_trips_input_on_chain() {
    let out = webc_weft::compile(include_str!("examples/echo.weft")).expect("echo.weft compiles");
    webc_vm::validate_module(&out.wasm, &wasm_vm_limits()).expect("engine accepts the module");

    let (config, mut state, alice) = fixture();
    let code = WasmBytecode(out.wasm.clone());
    let (code_id, namespace) = (Hash256([0xe0; 32]), Hash256([0x44; 32]));
    let manifest = WasmContractManifest::new(
        code_id,
        namespace,
        code.code_hash(),
        out.footprint.iter().copied(),
        alice.address(),
    );
    register(&mut state, &config, &alice, &manifest, out.wasm.clone());

    let key = out.footprint[0];
    let tx = invoke(&alice, 1, &manifest, b"hello weft".to_vec());
    state
        .execute_transaction(&tx, &config)
        .expect("invoke echo succeeds");
    assert_eq!(
        state.contract_state.get(&(namespace, key)),
        Some(&ContractStateValue(b"hello weft".to_vec())),
        "the Weft-compiled echo stored its input verbatim"
    );
}

#[test]
fn weft_manifest_footprint_matches_on_chain_declared_access() {
    // The compiler-derived footprint and the manifest's resolved effect keys must
    // agree with what the chain enforces, or an invocation would be denied.
    let out = webc_weft::compile(include_str!("examples/counter.weft")).unwrap();
    assert_eq!(out.manifest.footprint, out.footprint);
    assert_eq!(out.manifest.component, "counter");
    assert_eq!(out.manifest.entrypoints.len(), 1);
    let entry = &out.manifest.entrypoints[0];
    assert_eq!(entry.name, "bump");
    assert_eq!(entry.returns.as_deref(), Some("u64"));
    assert_eq!(entry.effects.writes, out.footprint);
}
