# WEBC continuation guide

Last updated: 2026-07-17 (findings-backlog session: consensus C1–C7 done;
active goal is now clearing the rest of the `docs/review/findings.md` backlog —
see "THE ACTIVE GOAL" below). This file is the live pointer to the **exact next
task**. Detailed "what the code implements" facts live in
`implementation-status.md`; do not duplicate them here.

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
5. ~~**C6 — round-scaled timeouts.**~~ **DONE (commit `90ae433`).**
   ~~**C7 — directed + certificate-gated state sync.**~~ **DONE (commit
   `0813e7c`).** ~~**CI gates — `cargo-deny` + fuzz targets.**~~ **DONE (commit
   `91760e2`:** `deny.toml` + cargo-deny job, `pnpm audit --prod` job, and a
   `fuzz/` crate with four libFuzzer targets run by a `fuzz-smoke` CI job).
6. ~~**C5 — carry proof-of-lock with re-proposals.**~~ **DONE (commit
   `3b2b460`).** `SignedProposal` carries a `proof_of_lock` prevote set; a node
   that missed round `vr` now follows a re-proposal via its attached 2f+1
   prevotes (wire bumped to `NET_PROTOCOL_VERSION = 2`, Rust-only format).

**All consensus review findings C1–C7 are now resolved**, plus the CI
supply-chain (`cargo-deny`), JS advisory (`pnpm audit --prod`), and fuzz gates.

### THE ACTIVE GOAL (owner-set 2026-07-17): clear the whole findings backlog

Drive **every remaining open finding in `docs/review/findings.md` to resolved**
— reproduce with a failing test FIRST, fix, keep the test, mark it resolved in
`findings.md` with the commit hash (AGENTS.md pitfall 7). This is exactly what
the Phase 5.5 core-freeze review gate requires ("resolve every open blocking
finding first"). Run to completion autonomously; do NOT stop mid-way for status
reports (AGENTS.md "Deciding for yourself"). Report to the owner only at true
completion or a hard blocker.

**Remaining backlog (ordered; each = repro-test-first → fix → gate → commit →
push; keep `main` green):**

- **Network DoS — webc-net (HIGH):** N1 handshake timeout, N2 bound inbound
  connections (Semaphore + per-IP cap), N3 cap peer table, N5 backoff reset,
  N6 bincode `.with_limit()`.
- **Node/faucet DoS — webc-node (HIGH/MED):** H1 faucet global rate-limit +
  prune `last_drip`, H2 mempool fee-priority eviction + call `prune_expired` on
  the seal tick, H3 cap WS subscriptions, H4 generic 5xx to client.
- **Correctness — webc-chain / webc-storage (MED):** G1 pin genesis total
  supply, T1 `deny_unknown_fields` on `Operation`, B1 bounded bridge-recipient
  hex, ST1 persist+validate `ChainId` in `ChainStore::open`, U1 `slash_locked`
  slashable-window.
- **Latent (HIGH latent / MED):** SC1 scheduler serializable order, SC2
  version-independent conflict keys, E2 block-timestamp validation, F1 epoch
  reward remainder supply-conservation, E1 wire epoch advancement
  deterministically into `apply_block`.
- **Cross-language (MED):** X1/X2 SDK bridge/object hex lowercase validation.
- **Docs/design:** C8 quorum-arithmetic property test + doc; plan-review §6
  P1/P2 ADRs (node key management; committee sampling; historical-state /
  archival; epoch/validator-set transition + weak-subjectivity; off-chain
  contract-compilation invariant); doc hygiene (line-number → section refs).

**Deferred, NOT in this backlog (do not start):** reference-machine
finality-timing number (needs real hardware — a cloud container cannot produce
it honestly); the optional multi-node-over-TCP Byzantine integration test (the
machine-level property is already tested — do only if time permits).

### Working method: sequential on main (worktree-isolation caveat)

Working method is in AGENTS.md ("Parallel subagents and durable work"). **CAVEAT
discovered 2026-07-17: in this environment the Agent tool's `isolation: worktree`
did NOT create a separate git worktree** — two launched agents collided on the
shared main worktree (one switched the main branch, so a docs commit landed on a
stray branch and had to be folded back). They were stopped. `claude/net-hardening`
was never created; `claude/sdk-hex-parity` held only that docs commit and is now
in `main` and deleted. **No finding work survived — N1–N6 and X1/X2 are still
fully TODO in the backlog above.**

Before relying on any parallel worktree agent, VERIFY `git worktree list` shows a
NEW worktree for it; if it does not, STOP and run the tracks sequentially on
`main`. Default plan on resume: do the whole backlog SEQUENTIALLY on `main`
(4 cores make parallel cargo builds thrash anyway), reproduce-test-first → fix →
gate → commit+push each finding. The webc-chain/webc-node/webc-storage findings
are coupled (shared error enums, `apply_block`/`ChainStore::open` signature
ripple) so they must be sequential regardless. The SDK track (X1/X2, pnpm — no
Rust build contention) is the only safe parallel candidate, and only if isolation
is verified to work.

### Decisions locked this session (do not re-litigate)

- **Devnet initializes 10,000,000 WEBC** (same as mainnet), one valueless faucet
  account; real distribution buckets are Phase 5. Change devnet `main.rs` genesis
  faucet balance 1M → 10M.
- **G1 mechanism:** add `pub const GENESIS_TOTAL_SUPPLY = Amount::from_webc(
  10_000_000)` (make `Amount::from_webc` a `const fn` via a lossless u64→u128
  widening cast), add `#[serde(default)] expected_total_supply: Option<Amount>`
  to `GenesisConfig`, and have `from_genesis` reject `minted_supply != Some(v)`.
  Production genesis (devnet/mainnet) sets `Some(GENESIS_TOTAL_SUPPLY)`; in-crate
  test fixtures pass `None` (trusted inputs). This requires adding the field to
  every `GenesisConfig` literal (webc-chain block_builder.rs/state.rs tests +
  webc-node src/tests) — mechanical.

Full context: `docs/review/findings.md` (per-finding detail + recommended fixes)
and `docs/review/2026-07-16-plan-review.md` §6. Do not jump ahead to Phase 5+
features, the contract runtime, Weft, the DEX, the oracle, ZK, or bridges before
their phase gates.

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
