# WEBC documentation map

This page keeps future development sessions from guessing which document
controls a decision.

## Authority order

1. [`../WEBC-DEFINITION.md`](../WEBC-DEFINITION.md) — the single source of
   truth for **product, economic, experience, and functional design**
   (read §16 first; §15 wins over older sections). **Read-only**: report
   contradictions to the owner; never edit it.
2. `AGENTS.md` — mandatory working, security, communication, and quality rules.
3. `decision-record.md` — security-adjacent decisions and implementation
   gates (the definition's declared scope excludes security; this file owns
   it). Defers to the definition for everything the definition covers.
4. `development-plan.md` — implementation order and completion checks.
5. `implementation-status.md` — what the current code actually implements.
6. `whitepaper.md` — complete design explanation.

If documents disagree, the higher item wins. Fix the lower document in the
same change. Security documents (`security.md`, ADRs) are the authority for
security content specifically — the definition deliberately does not cover it.

## Definition-alignment artifacts (2026-07-17)

- `definition-gap-analysis.md` — the audit of every doc-vs-definition
  divergence that drove the 2026-07-17 documentation overhaul.
- `code-reconciliation-worklist.md` — prioritized code-vs-definition
  divergences (records only; changes no code).

## System plans (each cites its deciding definition sections)

- `distribution-program.md` — the decided 25/5/30/15/15/10 allocation and
  channel mechanics (§15.33/15.38)
- `dex-batch-settlement.md` — canonical pools, mandatory per-block
  uniform-price batches, chain-native retry, MEV policy (§15.13/15.18/15.37)
- `oracle-economics.md` — bonded accuracy-weighted reporters, pull-based
  updates, read fees, seeding (§15.17/15.21)
- `weft-language-plan.md` — the decided Weft language design and spec plan
  (§15.41/15.43/15.44)
- `speed-roadmap.md` — two-track speed strategy, fast path, claim policy,
  benchmark gates (§15.40/15.42)
- `validator-operations.md` — middle-path economics, container image,
  frugality, bootstrap operations (§15.23/15.26/15.28)
- `agent-commerce.md` — mandate objects, service registry, HTTP-402 flows
  (§15.5/15.32)

## Topic documents

- `definition.md` — one-page summary pointing into `WEBC-DEFINITION.md`
- `architecture.md` — chain, execution, consensus, proofs, module boundaries
- `tokenomics.md` — supply, issuance, distribution, fees, staking
- `bridge.md` — bidirectional Ethereum/Solana bridge design + cross-chain UX
- `security.md` — threats, invariants, wallet, consensus, proof, bridge security
- `roadmap.md` — short phase overview; details live in `development-plan.md`
- `continuation-guide.md` — exact starting point for the next development session
- `ai-handoff.md` — prevents stale conversation summaries from becoming decisions
- `session-keys-implementation-plan.md` / `session-keys-next-steps.md` —
  completed session-key gate records (historical; do not redo)

## Goal-scoped task plans

These are active only when an explicit goal names them. They do not replace the
global next action in `continuation-guide.md`.

- `transaction-system-plan.md` — end-to-end transaction completion on its
  dedicated branch, with optional parallel work areas, proof/light-client
  boundaries, acceptance gates, and a branch-local recovery/decision log

## Review artifacts (`docs/review/`)

Durable outputs of review sessions. Not authority (the definition, decision
record, and code win), but a session must read them at start so it does not
re-derive the map or re-discover a known finding.

- `review/codebase-map.md` — where every crate/module/file lives
- `review/2026-07-16-plan-review.md` — the critical plan review and
  prioritized P0/P1/P2 worklist
- `review/findings.md` — reported code-level findings; reproduce each before
  fixing

## Editing rule

- Product/economic/experience/functional decisions change only through the
  owner's review process in `WEBC-DEFINITION.md` — never by editing repo docs
  first. Repo docs then realign, citing the deciding section.
- A security-adjacent decision updates `decision-record.md`, only with owner
  approval.
- An implementation change updates code, tests, and
  `implementation-status.md` together.
- A changed phase or completion check updates `development-plan.md`.
- Supporting documents may explain a decision but must not create a competing
  decision.

## Technical decision records

Implementation-only architecture choices are recorded under
[`adr/`](adr/README.md). They cannot override the definition or the decision
record.

## Current next action

This page does not restate phase or completion status because a second copy
rots. Read `continuation-guide.md` for the exact next task and
`implementation-status.md` for demonstrated code reality. A separately assigned
goal document is not the global next action unless the continuation guide says
so.

This project runs in an ephemeral cloud container: the GitHub repo is the
source of truth, so commit and push every step. `target/`, `node_modules/`,
and `dist/` are git-ignored but regenerable from the committed lock files and
toolchain pins.
