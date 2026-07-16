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
8. Build the contract runtime on the chosen Rust->WASM foundation, then the WEBC high-level authoring language (lowering to the audited Rust framework), its anti-complexity tooling, AI-readable component catalog, and the native staked oracle.
9. Add compact browser proofs and versioned post-quantum authorization.
10. Complete the browser wallet, SDK, widget, and site-agent protocol.
11. Add native tokens, NFTs, application rules, and optional token governance.
12. Build mock bidirectional Ethereum/Solana bridges.
13. Run a publicly announced incentivized testnet and publish distribution rules.
14. Launch only after audits, long-running tests, recovery drills, and public review.
15. Enable real bridge funds only after separate bridge audits and safety approval.

## Immediate milestone

Phases 0-3 are complete (single-node state machine, wallet/security foundation,
durable node + storage + developer APIs). **Phase 4 (networking and signed BFT
consensus) is active but not complete or safe:** the happy-path mechanism exists
and converges in loopback tests, but a 2026-07-16 review reported HIGH-severity
consensus safety/liveness/DoS gaps that must be fixed first. This file is a map
only and does not restate detailed status; see `continuation-guide.md` for the
verified checkpoint and `docs/review/2026-07-16-plan-review.md` §6 for the
prioritized worklist.

The AI-era product direction (a WEBC high-level contract language that lowers to
the audited Rust/WASM layer, a native staked oracle, capped fee sponsorship,
anti-complexity contract tooling, and prioritized Ethereum/Solana bridges) is
recorded in `decision-record.md` and slotted into the phases above; it is built
after consensus is stable.
