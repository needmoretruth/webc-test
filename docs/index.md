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

## Review artifacts (`docs/review/`)

Durable outputs of review sessions. Not authority (the decision record and code
win), but a session must read them at start so it does not re-derive the map or
re-discover a known finding.

- `review/codebase-map.md` — where every crate/module/file lives and what it owns
- `review/2026-07-16-plan-review.md` — the critical plan review: what is sound,
  decision provenance, the security checklist, architectural gaps, the open owner
  decisions, and the prioritized P0/P1/P2 worklist
- `review/findings.md` — reported code-level findings (severity, location, fix
  direction); reproduce each before fixing

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

Phases 0-3 are complete and **Phase 4 (networking and signed BFT consensus) is
active but not complete or safe.** This page does not restate the phase status
(it rots — see `AGENTS.md` pitfall 8). `continuation-guide.md` and
`implementation-status.md` are the live owners of "what is done / what is next,"
and `docs/review/2026-07-16-plan-review.md` §6 holds the prioritized worklist
(chiefly the reported HIGH-severity consensus findings in
`docs/review/findings.md`). Do not restart completed amount, inflation, genesis,
block-atomicity, staking-ratio, access-enforcement, session-key,
wallet-permission-storage, storage, node, or networking work.

The AI-era product direction is now recorded in `decision-record.md`: a WEBC
high-level contract language that lowers to the audited Rust/WASM layer, a native
staked oracle, capped fee sponsorship, anti-complexity contract tooling, an
AI-readable component catalog, and prioritized Ethereum/Solana bridges. These are
built after consensus is stable; `development-plan.md` phases 6-14 carry them.

This project runs in an ephemeral cloud container: the GitHub repo is the source
of truth, so commit and push every step. `target/`, `node_modules/`, and `dist/`
are git-ignored but regenerable from the committed lock files and toolchain pins.
