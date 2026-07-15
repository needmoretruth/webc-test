# WEBC documentation map

This page keeps future development sessions from guessing which document controls a decision.

## Authority order

1. `AGENTS.md` — mandatory working, security, communication, and quality rules
2. `decision-record.md` — confirmed user decisions and unresolved technical gates
3. `development-plan.md` — implementation order and completion checks
4. `implementation-status.md` — what the current code actually implements
5. `whitepaper.md` — complete design explanation

If documents disagree, the higher item in this list wins. Fix the lower document in the same change.

## Topic documents

- `definition.md` — short product definition
- `architecture.md` — chain, execution, consensus, proofs, and module boundaries
- `tokenomics.md` — supply, inflation, fees, staking, and distribution
- `bridge.md` — bidirectional Ethereum/Solana bridge design
- `security.md` — threats, invariants, wallet, consensus, proof, and bridge security
- `roadmap.md` — short phase overview; details live in `development-plan.md`
- `continuation-guide.md` — exact starting point for the next development session
- `ai-handoff.md` — prevents stale conversation summaries from becoming decisions
- `session-keys-implementation-plan.md` — constrained on-chain session-key design and staged build order (Phase 2 gate)
- `session-keys-next-steps.md` — durable resume plan; the ML-DSA signature gate, primary-key recovery/rotation, recovery-root rotation, epoch-boundary pruning, the browser/SDK surface, and durable encrypted permission storage + automatic lane setup are done — only reference-machine benchmarks remain before Phase 3

## Editing rule

- A confirmed product/economic change first updates `decision-record.md`, but only after user approval.
- An implementation change updates code, tests, and `implementation-status.md` together.
- A changed phase or completion check updates `development-plan.md`.
- Supporting documents may explain a decision but must not create a competing decision.

## Technical decision records

Implementation-only architecture choices are recorded under [`adr/`](adr/README.md).
They cannot override confirmed product or economic policy in
`decision-record.md`.

## Current next action

Phase 0 and Phase 1 are complete, and Phase 2 is active. The versioned
authorization + constrained session-key gate is **complete** (ML-DSA-65
root-signature gate, session keys with budgets/lane/expiry+pruning, active-key and
recovery-root rotation, the browser/SDK surface, and an indicative benchmark).
Durable encrypted per-origin wallet permission storage and automatic
authorization-lane setup are **complete** too — the last outstanding Phase 2
wallet-wire/secret-isolation gate. The only session-key remainder is
reference-machine benchmark numbers. Use `continuation-guide.md` for the verified
checkpoint and exact next task, and do not restart completed amount, inflation,
genesis, block-atomicity, staking-ratio, access-enforcement, session-key, or
wallet-permission-storage work. The next milestone is **Phase 3**: a local
restartable node with storage traits, crash-safe commits, and HTTP/WebSocket
developer APIs.

This project runs in an ephemeral cloud container: the GitHub repo is the source
of truth, so commit and push every step. `target/`, `node_modules/`, and `dist/`
are git-ignored but regenerable from the committed lock files and toolchain pins.
