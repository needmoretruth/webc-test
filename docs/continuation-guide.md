# WEBC continuation guide

Last updated: 2026-07-17 (after the definition-alignment documentation
overhaul). This file is the live pointer to the **exact next task**. Detailed
"what the code implements" facts live in `implementation-status.md`; do not
duplicate them here.

## Read first

1. `AGENTS.md`
2. `WEBC-DEFINITION.md` §16 (repository root) — product/economic/experience/
   functional source of truth; §15 wins over older sections; **read-only**
3. `docs/decision-record.md` — security-adjacent decisions and gates
4. `docs/development-plan.md` — the 19-phase plan (2026-07-17 revision)
5. `docs/implementation-status.md` — what the code actually does
6. `docs/review/findings.md` — known code findings (read BEFORE touching
   consensus, networking, mempool, or faucet)
7. `docs/index.md` and the topic/system document the task needs

Then inspect `git status --short --branch` and `git log -5 --oneline`.
Preserve all existing changes, determine the first incomplete item below, and
continue it **autonomously** without asking the user to restate recorded
decisions or safety rules (AGENTS.md start protocol). "continue" / "이어서"
always means exactly that.

## What is already decided

Do not reopen or re-derive:

- Every product, economic, experience, and functional design decision is in
  `WEBC-DEFINITION.md` (§16 lists decided vs delegated). Highlights: the
  25/5/30/15/15/10 distribution (§15.38); two-track speed targets with
  conservative public claims (§15.42); mandatory per-block batch settlement
  DEX (§15.37); oracle economics (§15.17/15.21); the Weft language design
  (§15.41/15.43/15.44); storage deposit/rebate (§15.22); middle-path
  validator economics with no per-vote fees (§15.23/15.28); agent mandates
  (§15.32).
- Security-adjacent decisions and the Phase 5.5 review gate:
  `docs/decision-record.md`.
- The delegated designs are already written as system plans (see
  `docs/index.md`): distribution-program, dex-batch-settlement,
  oracle-economics, weft-language-plan, speed-roadmap, validator-operations,
  agent-commerce. Plan within them.
- 2026-07-17: all repository docs were realigned to the definition
  (`docs/definition-gap-analysis.md` records the audit;
  `docs/code-reconciliation-worklist.md` records code-vs-definition
  divergences, prioritized, code untouched).

Speak simple Korean to the user, address them as 관리자 with 존댓말, and
explain unavoidable technical terms plainly.

## Current verified checkpoint

**Code (unchanged by the 2026-07-17 doc overhaul — no code was modified):**

- Phases 0, 1, 2, 3 are complete. Do not redo: 12-decimal u128 amounts and
  the inflation curve; staking activation rules and the ADR-0008 exit
  lifecycle; atomic block execution; declared-access enforcement; signed
  slashing evidence; the session-key gate (versioned authorization, ML-DSA
  root, constrained session keys, recovery/rotation, browser SDK parity);
  encrypted wallet permission storage and automatic lane setup; the
  redb-backed restartable node, mempool, HTTP/WS APIs, faucet, node client,
  and demo site. Details: `implementation-status.md`,
  `session-keys-implementation-plan.md`, `session-keys-next-steps.md`.
- **Phase 4 is active and NOT safe.** Done: A-1 networking plumbing
  (`webc-net`), the A-2 consensus core (validator-set snapshots with
  consensus keys, `SignedProposal`, self-verifying `FinalityCertificate`),
  the A-3 multi-round Tendermint `ConsensusMachine` with locking and safe
  round changes, `Node::import_block`, the async `ConsensusDriver` over real
  TCP with a mempool, certificate-verified state sync, and
  equivocation-to-slash wired end to end (commit `a6197ac`) — all proven by
  deterministic/loopback tests (three validators converge; a gossiped
  transfer finalizes everywhere; a late node catches up via sync).
- Last verified gates (2026-07-15, cloud Linux): `cargo fmt --check`, strict
  clippy, 192 Rust tests, rustdoc, `webc-node demo`, node smoke test with
  kill/restart recovery; TypeScript SDK 69/69, widget 3/3, link check.
  (Re-run the gates at session start; this note is history, not proof.)
  Windows GNU host note: use `cargo +1.96.0-x86_64-pc-windows-gnu`.
- Reference-machine benchmark numbers are still owed before any performance
  claim (a cloud container cannot produce them honestly).

**Documentation (2026-07-17):** fully realigned to `WEBC-DEFINITION.md`;
seven system plans added; development plan rebuilt (phases 0–7 numbering
preserved, 8–19 new); AGENTS.md facts updated. Committed and pushed through
`3a327c3`.

## Exact next work

**Resume Phase 4 consensus hardening — the P0 findings, in this order.**
For each: reproduce with a failing test FIRST, then fix, then mark the
finding resolved in `docs/review/findings.md` with the commit hash
(AGENTS.md pitfall 7).

1. ~~**C4 — durable WAL of own votes/locks before broadcasting.**~~ **DONE
   (commit `90c28ac`).** The driver journals every own signed message durably
   before broadcast (`Table::ConsensusWal`) and replays the journal on
   restart (`ConsensusMachine::restore`); reproduced first by
   `webc-node/tests/consensus_restart.rs`.
2. ~~**C1 — validate a proposed block before prevote/lock/finalize.**~~
   **DONE (commit `45f7396`).** The driver dry-runs `apply_block` (after the
   cheap authenticity gate and a chain-position pin) before any proposal
   reaches the machine; reproduced first by
   `webc-node/tests/consensus_byzantine_proposal.rs`.
3. ~~**C2 — no silent halt on failed finalized-block import.**~~ **DONE
   (commit `5ca197d`).** `run()` returns a typed `DriverExit`; transient
   storage I/O retries with backoff; a certified-but-unimportable block is a
   surfaced consensus emergency; tests in
   `webc-node/tests/consensus_import_failure.rs`.
4. ~~**C3 — bound per-height consensus memory.**~~ **DONE (commit
   `bc3869b`).** Sliding round window (`MAX_FUTURE_ROUNDS`/`MAX_PAST_ROUNDS`
   = 32) at machine ingestion + eviction on round change + the same horizon
   in the driver before block re-execution.
5. C5/C6 (proof-of-lock with re-proposals, round-scaled timeouts), C7
   (state-sync replies gated on a verified higher-height certificate), and
   the CI gates (`cargo-deny` + fuzz targets — plan review §3.5–3.6).
   ← **NEXT**

Full context: `docs/review/findings.md` (C1–C8) and
`docs/review/2026-07-16-plan-review.md` §6. The session decides autonomously
within this list and the development plan; do not stop to ask permission
between items (AGENTS.md). Do not jump ahead to Phase 5+ features, the
contract runtime, Weft, the DEX, the oracle, ZK, or bridges before their
phase gates.

After Phase 4's P0/P1 items are done, the path is: Phase 5 economics (bring
the owner the slashing-severity numbers and the §15.2 bootstrap-issuance
decision with threat models at the freeze — not before), then the Phase 5.5
core freeze + independent security review, then Phase 6+ per
`development-plan.md`.

## Working rules

- Preserve user changes in a dirty worktree.
- Never delete broad directories, unrelated user data, or system data; never
  run broad cleanup or `git reset --hard`. Delete only a verified exact
  development-generated path inside its intended scope.
- Perform only repository development and necessary development-tool actions.
- Install required reputable development tools automatically when safe,
  prefer project/user scope, pin versions, verify origin and integrity.
- Security and correctness outrank speed and feature count.
- Keep protocol code deterministic and Rust-first; typed errors, checked
  arithmetic, deterministic ordering, canonical encoding; no panics on
  hostile input; `unsafe` forbidden in protocol crates.
- Wrapper types for amounts, heights, epochs, nonces, chain IDs, asset IDs.
- Module comments, invariants, and security reasons per
  `code-documentation-template.md`; update comments with behavior.
- Add tests before or with each protocol repair; run the relevant gates
  before pushing (AGENTS.md "Validation expectations").
- Update `implementation-status.md` and this guide after material work;
  commit and push every coherent, tested step (ephemeral environment — the
  repository is the only durable memory).
- Record a user-approved security-adjacent decision in
  `docs/decision-record.md`; product/economic decisions change only through
  the owner's `WEBC-DEFINITION.md` process.
- Never treat the trusted-relayer bridge as production-ready; never claim
  TPS, finality, ZK, or quantum safety without measurements (§15.42 claim
  policy).

## Questions to postpone

Technical constants (epoch length, committee size, fee constants, block
limits, oracle parameters, DEX curve family) are decided by benchmarks and
testnet evidence, not by asking the user. Ask the owner only at the recorded
decision points: slashing severity and the §15.2 bootstrap issuance at the
Phase 5 freeze; any hardware-floor trade-off the §15.42 targets force;
production bridge trust model; emergency governance powers; renaming Weft
before public branding.
