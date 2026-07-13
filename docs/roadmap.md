# WEBC roadmap

The authoritative detailed roadmap is [`development-plan.md`](development-plan.md). This file is a short map only, so two competing plans do not develop.

## Order of work

1. Freeze specifications, toolchain, tests, and protocol configuration.
2. Repair the current single-node state machine and economic accounting.
3. Make Rust and browser transaction formats exactly compatible.
4. Add durable storage, node APIs, and restart-safe operation.
5. Build networking and stake-based BFT consensus.
6. Implement correct staking, delegation, rewards, unbonding, and slashing.
7. Add enforced access lists, parallel execution, app isolation, and localized fees.
8. Benchmark restricted WASM/Rust, Move VM, and EVM compatibility before choosing the public contract runtime.
9. Add compact browser proofs and versioned post-quantum authorization.
10. Complete the browser wallet, SDK, widget, and site-agent protocol.
11. Add native tokens, NFTs, application rules, and optional token governance.
12. Build mock bidirectional Ethereum/Solana bridges.
13. Run a publicly announced incentivized testnet and publish distribution rules.
14. Launch only after audits, long-running tests, recovery drills, and public review.
15. Enable real bridge funds only after separate bridge audits and safety approval.

## Immediate milestone

Phase 0 and Phase 1 are complete. Implement Phase 2 wallet derivation, encrypted
storage, origin isolation, authorization policy, recovery, and post-quantum
prototype gates. Do not build RPC, networking, ZK, or real bridges before the
wallet security foundation passes its acceptance tests.
