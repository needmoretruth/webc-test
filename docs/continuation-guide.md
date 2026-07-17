# WEBC continuation guide

Last updated: 2026-07-17 (findings-backlog session COMPLETE: every open finding
in `docs/review/findings.md` is resolved — see "FINDINGS BACKLOG CLEARED" below;
next is Phase 5 economics, which opens with owner-owned decisions). This file is
the live pointer to the **exact next task**. Detailed "what the code implements"
facts live in `implementation-status.md`; do not duplicate them here.

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

### FINDINGS BACKLOG CLEARED (2026-07-17)

**Every open finding in `docs/review/findings.md` is resolved** — reproduced with
a failing test first, fixed, tested, and marked resolved there with its commit
hash (AGENTS.md pitfall 7). This satisfies the Phase 5.5 core-freeze gate's
"resolve every open blocking finding first." The working branch
(`claude/agent-md-review-6a392q`) is green on the full workspace gate (fmt,
clippy `-D warnings`, `cargo test --workspace`, rustdoc, `webc-node demo`, SDK
`pnpm check`); `main` holds the same tree up to the H2 hardening follow-up.

What landed this session (per-finding detail + commit hashes in `findings.md`):

- **Consensus C1–C8** (C1–C7 P0/P1 plus C8 quorum-arithmetic property test).
- **Network DoS N1–N6:** handshake timeout, bounded inbound + per-IP cap,
  peer-table cap, per-peer rate limit, authenticated-only backoff reset, bincode
  decode limit.
- **Node DoS H1–H4:** faucet global rate-limit + pruned drip map, mempool
  fee-priority eviction + seal-tick `prune_expired`, WS-subscription cap, generic
  5xx (detail logged server-side).
- **Chain correctness:** G1 genesis total-supply pin (devnet = mainnet = 10M),
  T1 strict `Operation` decode, B1 bounded bridge hex, U1/U2 slashable-window +
  settled-request pruning, F1 epoch-reward supply conservation, F2 non-zero
  inflation floor, SC1/SC2 serializable + version-independent scheduling, E1
  height-derived epoch advancement in `apply_block`, E2 timestamp monotonicity +
  drift, E3 Merkle proof-length bound, E6 `verify_strict` signatures, E8
  state-root completeness guard, X3 canonical JS-safe integer bound.
- **Storage ST1:** chain-id bound + verified at `ChainStore::open`.
- **SDK:** X1/X2/X4 cross-language hex/amount validation; S1–S7 wallet hardening
  (double-click guard, popup parsing bounds, per-origin replay bound + idempotent
  retries, reconnect spend-cap, streamed byte cap, S3 KDF purpose separation).
- **Dependencies D3:** tokio-tungstenite aligned; remaining transitive skew
  documented in `deny.toml`.
- **Design ADRs (plan-review §6):** ADR-0009 node key management, ADR-0010
  committee sampling, ADR-0011 historical state + weak-subjectivity;
  contract-compile invariant in ADR-0006. E4/E5 direction recorded there; E7
  phase-gated (no VM).

### Adversarial re-verification pass (2026-07-17)

After the backlog was cleared, an adversarial verification pass (parallel
subagents, each told to *refute* a fix by reading the code, not just confirm its
tests) re-checked the highest-risk fixes. It surfaced **one additional real
defect** in the H2 mempool eviction, now fixed (commit `370f231`): the eviction
rule ranked purely by effective fee and was *runnability-blind*, so a gapped-nonce
bid (never sealable — `select_block` skips gaps, so it never pays) could evict an
honest *runnable* transaction for free — the exact "free churn" the guard claimed
to prevent. Eviction now ranks by `(is_runnable, effective_fee)`; a non-runnable
bid can no longer displace a runnable entry. All other high-risk fixes
(F1, E1, E2, SC1/SC2, U1, G1, E6, S4/S7, ST1, H1, C8) were independently confirmed
SOUND. Lesson for future sessions: after tests pass, run an adversarial pass that
tries to *break* each fix — a green test suite proves the tested cases, not the
absence of the vector.

### Branch note

Work now lives on the designated branch **`claude/agent-md-review-6a392q`** (the
earlier findings-backlog commits were on `main`; the designated branch was
fast-forwarded to include all of them and is the branch to keep developing on).
`main` and the designated branch are in sync.

### Exact next work

**Phase 5 economics is UNBLOCKED (owner direction taken 2026-07-17).** Recorded
in `docs/decision-record.md` (§ "Consensus and slashing" → the 2026-07-17
subsections):

- **Slashing severity = DIRECTION only; exact numbers DEFERRED.** The owner
  directed keeping severity in a **flexible config** with provisional defaults
  and finalizing the numbers later by referencing Ethereum/Solana/Sui/Polkadot/
  Cardano (design → **ADR-0012**). Direction: severe = large whole-pool slash +
  Tombstone; correlated ramp for coordinated attacks; **liveness handled by an
  Ethereum-style inactivity leak** so a >1/3-offline event does NOT permanently
  halt the (Tendermint-style) chain — offline stake is drained until the online
  set regains >2/3. Burn (not redistribute) is fixed. **Do NOT hardcode final
  magnitudes**; keep everything parameterized until the owner confirms.
- **Bootstrap issuance = DECIDED: stake-keyed with a supply-% cap + published
  sunset criteria** (base 10%→1% schedule unchanged, resumes on bootstrap exit).
  This one is not deferred.

The slashing EXECUTION mechanism (evidence→slash→burn→tombstone, replay-guarded)
is already built and test-covered; the current 80/90/100% defaults are
**un-approved placeholders** to keep as flexible provisional values (do not
present as final). Remaining Phase 5 work: (1) **ADR-0012** — inactivity-leak +
slashing-posture design comparing the 5 reference chains, with the tunable
parameters and the owner-decision points flagged; (2) **inactivity-leak
scaffolding** — config struct + participation/finality-gap tracking (design-
independent parts), consensus recovery-mode gated on the ADR being confirmed;
(3) **bootstrap issuance** (decided; stake-keyed capped budget + sunset); then
the lighter tasks — compounding, public validator perf/reward/slash endpoints,
faucet devnet staking UX, stake-locked-grant / vest-by-operation primitives
(Phase 16). After Phase 5 comes the **Phase 5.5 core freeze + independent
security review**, whose per-finding prerequisite this session satisfied.

### Phase 5 progress (2026-07-17)

Landed this session (each reproduce/test → gate → commit → push; full workspace
gate green incl. SDK):

- **Task 10 — public validator/supply endpoints:** `GET /v1/validators`,
  `/v1/validators/{addr}`, `/v1/supply`; SDK node-client `getValidators/
  getValidator/getSupply`.
- **Task 12 — bootstrap issuance (decided):** opt-in `ChainConfig.bootstrap_issuance`;
  stake-keyed budget capped by the base per-period budget; sunset epoch; supply
  conserved.
- **Task 6b — compounding:** `CompoundValidatorRewards` / `CompoundDelegatorRewards`
  restake accrued rewards in place (supply-neutral, ratio-guarded).
- **Task 11 — faucet-funded staking UX:** `stake-register/-delegate/-undelegate/
  -claim` + `faucet-stake` CLI subcommands over the in-process service.
- **Task 13 — grant/vest primitive:** `grants::StakeGrant` (stake-locked,
  vest-by-credited-epoch, forfeit-reverts); Phase 16 accounting integration
  deferred.
- **ADR-0012 + flexible scaffolding:** the Ethereum/Solana/Sui/Polkadot/Cardano
  comparison and the inactivity-leak + correlation-scaled slashing design;
  `InactivityLeakConfig` (opt-in, disabled) with tested per-epoch leak math;
  `SlashingPolicy` marked provisional.

### Phase 6 progress (2026-07-17)

Started Phase 6 (parallel execution / localized fees / storage deposits). The
scheduler (deterministic parallel batches + serializable order, SC1/SC2), the
end-to-end signed access-list declarations, and namespace-keyed object state
were already implemented. Landed this session:

- **Storage deposit + deletion rebate (§15.22) — DONE, wired:** `StoragePricing`
  config; `CreateObject` locks a byte-proportional deposit, `MutateObject`
  adjusts on resize, new `Operation::DeleteObject` refunds `refund_bps` and burns
  the remainder; `storage_deposits` supply bucket reconciles the invariant;
  per-object `StateObject.deposit`. **State-commitment domain bumped V7→V8** and
  the object leaf V1→V2 (committed shapes changed). Full workspace gate green.
- **ADR-0013 hot/cold tiering boundary** — the archive-node interface + proof /
  restore-on-demand design (builds on ADR-0011).
- **Fixed the long-standing `consensus_import_failure` flake** (a harness
  broadcast/peer-registration race — now waits for both connection directions;
  8/8 green where it was ~2/3).

**zstd compression (§15.19/15.24) — DONE (both tiers).** Storage-layer (webc-storage,
transparent redb value compression) and wire-frame (webc-net envelope, same tag
convention, 4 MiB streamed decompression cap as a zip-bomb defense since wire
frames are attacker-controlled, `NET_PROTOCOL_VERSION` 2→3). Both cargo-deny clean.

**Phase 6 remaining:** sponsor/paymaster accounts (§15.35, per-user/app/op/day
caps) — IN PROGRESS (subagent); then localized base/priority pricing + network-wide
minimum + per-resource congestion measurement + fair block packing; varint amount
encoding (§15.14, a wire-version bump); an application namespace registry; sharded
examples. The **TPS benchmarks** (100/500/1000/2000 gates) need real reference
hardware, not a cloud container (a known deferred non-finding) — implement the
features here; the published-claim benchmarks run on real machines later.

**Deferred within Phase 5 (owner-gated / consensus-safety, tracked in ADR-0012):**
the slashing severity numbers, correlated-slashing behavior, the downtime→jail
path, and the inactivity-leak consensus wiring (recovery mode) all await the
owner confirming ADR-0012's recovery family + constants. Other severe evidence
types (invalid-transition, fraudulent-bridge) need their objective artifacts,
which are later-phase (runtime / bridge). Tasks 1–7 (ratio/minimums/queues/
snapshots/commission/rewards/inflation) were already implemented and test-covered.

**Owner-owned items still deferred** (do not decide alone; full list in AGENTS.md
"User decisions still required later"): the Phase-5 economics numbers above; the
production-bridge trust/proof model; the weak-subjectivity trust-anchor source
(ADR-0011); mainnet governance emergency powers; renaming Weft.

**Deferred non-findings (not blockers):** the reference-machine finality-timing
benchmark (needs real hardware, not a cloud container) and the optional
multi-node-over-TCP Byzantine integration test (the machine-level property is
already tested).

### Parallel-subagent note (for future sessions)

This session ran the `webc-net` and `sdk/webc-js` tracks as parallel background
subagents in **manually-created git worktrees** (`git worktree add ...`, verified
with `git worktree list` before trusting them — the Agent tool's
`isolation: worktree` flag did NOT create a real worktree in this environment).
Each subagent committed and pushed its own branch; the orchestrator merged both
into `main` after the full gate, then finished the few items each subagent did
not reach (N5; S3/S4/S7) on `main`. The coupled
`webc-chain`/`webc-node`/`webc-storage` core was done sequentially on `main` by
the orchestrator (shared error enums and `apply_block`/`ChainStore::open`
signature ripples make it inherently sequential). Repeat that pattern: create the
worktrees yourself and verify isolation, keep disjoint file sets per track, and
integrate on `main`.

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
