# WEBC roadmap

The authoritative detailed roadmap is [`development-plan.md`](development-plan.md).
This file is a short map only, so two competing plans do not develop. Product
scope comes from `WEBC-DEFINITION.md` (§16 lists what is decided vs delegated).

## Order of work

1. Freeze specifications, toolchain, tests, and protocol configuration.
2. Repair the single-node state machine and economic accounting.
3. Make Rust and browser transaction formats exactly compatible.
4. Add durable storage, node APIs, and restart-safe operation.
5. Build networking and stake-based BFT consensus (rotating committee;
   aggregated votes §15.19; no per-vote fees §15.28).
6. Implement correct staking, delegation, rewards, unbonding, and slashing.
6.5. Freeze the consensus + crypto + economics core and pass an earlier
   independent security review (Phase 5.5 gate; owner-confirmed 2026-07-16).
7. Add enforced access lists, parallel execution, app isolation, localized
   fees, and storage deposit + deletion rebate pricing (§15.22).
8. Build the contract runtime on the Rust→WASM foundation with the interim
   Rust-eDSL authoring path over a frozen ABI/front-end seam (Phase 7a), plus
   the native oracle with its decided economics (§15.17/15.21); **Weft** — the
   decided authoring language (§15.41/15.43/15.44) — comes later as a front
   end over that same seam (Phase 7b).
9. Build the native DEX: canonical shared pools, storefront modes, trust
   registry, and mandatory per-block uniform-price batch settlement with
   chain-native retry (§15.13/15.18/15.37).
10. Build agent commerce: mandate objects, the on-chain service registry, and
    HTTP-402-style flows (§15.5/15.32).
11. Add compact browser proofs and versioned post-quantum authorization; zk
    stays off the consensus path (§15.25).
12. Prototype the fast path for single-owner operations (~0.4–0.8s target,
    launch scope — §15.40/15.42) and run the speed-roadmap benchmarks; public
    claims stay at ~2s / 6–8s until benchmarks pass.
13. Complete the browser wallet, SDK, widget, site-agent protocol, and the
    flagship applications (payment widget, HTML-game kit, DEX storefront,
    AI-agent marketplace — §15.36).
14. Add native tokens, NFTs, application rules, and optional token governance.
15. Build mock bidirectional Ethereum/Solana bridges with the one-action
    cross-chain UX direction (§15.36).
16. Ship the validator operations stack: official tuned container image,
    spec floor/recommended split, bandwidth budgets (§15.19/15.23/15.26).
17. Run the publicly announced incentivized testnet: contributor program
    (25%), validator-bootstrap grants (5% ceiling), and publish the full
    distribution mechanics (§15.33/15.38) before it starts.
18. Launch only after audits, long-running tests, recovery drills, and public
    review; storage blob layer (§15.27) and zk state compression (§15.25)
    remain phase-2 additions.
19. Enable real bridge funds only after separate bridge audits and safety
    approval.

## Immediate milestone

Phases 0–3 are complete (single-node state machine, wallet/security
foundation, durable node + storage + developer APIs). **Phase 4 (networking
and signed BFT consensus) is active but not complete or safe:** a 2026-07-16
review reported HIGH-severity consensus safety/liveness/DoS gaps that must be
fixed first. This file is a map only; see `continuation-guide.md` for the
verified checkpoint and `docs/review/2026-07-16-plan-review.md` §6 for the
prioritized worklist.
