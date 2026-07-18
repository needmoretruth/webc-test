# WEBC continuation guide

Last updated: 2026-07-18 (Phases 5–13 done on `main`; owner direction is
"practical L1 완성" plus, now owner-approved, an **earliest-skeleton Weft**
front end for future flexibility.
**START AT the "SESSION HANDOFF" block in the "Exact next work" section below** —
it has the live state: the WASM contract runtime is now **wired end-to-end**
(`webc-vm` engine bridged into `webc-chain`; commit `4ca3483`), and the current
in-flight item is the **Weft skeleton compiler** (`webc-weft`: front end →
WAT/WASM over the host ABI). The Codex decision and swappable-engine design still
apply.) Separately assigned feature goals use their own branches and do not
replace this pointer until merged.
This file is the live pointer to the **exact next task**. Detailed "what the code
implements" facts live in `implementation-status.md`; do not duplicate them
here.

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

**Phases 5–13 are DONE and integrated into `main`** (economics, localized fees /
sponsorship / namespaces / compression, interim contract runtime + oracle, DEX,
agent mandate + service registry, tokens, NFTs, application governance), together
with the TypeScript SDK for all 38 native operations, the HTTP-402 agent-payment
flow, node read + query endpoints, and a proptest invariant-stress suite. Each
feature was adversarially reviewed (fixing real bugs M1 and T1) and gated. The
detailed per-phase record is deeper in this file; the current status and the
owner-gated remainder are in the **"Boundary reached — app-facing surface
complete; remainder is owner-gated"** section below.

### SESSION HANDOFF (2026-07-17, updated before a context compaction)

**Owner-set direction: "practical L1 완성" (feature-complete WEBC).** Complete all
DECIDED, non-owner-gated implementation so only refinement + owner decisions +
audit remain. **Weft language is EXCLUDED** (later separate project). Work on
`main` (owner directed). `implementation-status.md` is STALE (predates Phase
5–13) — trust THIS guide + the code, not that file.

**Landed on `main` since Phase 13 (this session):** node read + discovery/list
endpoints; the full SDK high-level client layer (Agent-commerce / Governance /
Token / Nft clients); and the **`webc-proof` crate** (transparent indexed Merkle
proofs — the **Phase 10** foundation), adopted from the paused
`codex/transaction-system` branch (commit `b21a525`).

**Codex decision (owner-delegated):** `codex/transaction-system` is PAUSED and
self-declared incomplete. Adopted ONLY its clean, complete `webc-proof` crate.
Its centerpiece **V5 transaction wire** was SKIPPED — it is an unintegrated
parallel foundation (2000+ lines) that would need real completion (not a light
fix) + conflicts (fees.rs, an ADR-0012 number collision). Owner MAY later ask to
complete V5 as a formal task; do not merge it wholesale.

**DONE — Phase 7b: real WASM contract runtime, wired end-to-end.** Owner-endorsed
principle held throughout: **SWAPPABLE / MODULAR ENGINE.** `webc-vm` (deterministic
`wasmi` 0.31 interpreter + fuel metering) sits behind its crate boundary; the gas
model and contract ABI are engine-independent, so `wasmtime` (JIT) can replace it
later without touching the chain. Production engine choice stays owner-deferred.
(Perf note: an interpreter does NOT raise user fees — fees are protocol
gas-metering, independent of node exec speed.)
- **`webc-vm` engine — DONE and MERGED (`2742201`).** Deterministic interpreter +
  host ABI (module `webc`: `webc_input_len/webc_input_read/webc_get/webc_set/
  webc_epoch/webc_output`; guest exports `memory` + `webc_call`), `VmHost` trait
  (`get/set/epoch/charge_gas`), `validate_module` (fail-closed on floats/SIMD/
  threads/bulk-memory/reference-types/foreign-imports/oversized), `VmLimits`, 22
  tests.
- **Chain wiring — DONE and MERGED (`4ca3483`).** `crates/webc-chain/src/
  wasm_contract.rs`: a thin adapter — `ContractVmHost` maps `VmHost` 1:1 onto
  `ContractContext`+`GasMeter`; `WasmContract` implements the existing `Contract`
  trait via `webc_vm::execute`; `WasmContractManifest` + content-hashed
  `WasmBytecode`; `wasm_vm_limits()` routes STATE gas through `ContractContext`
  (single meter, no double count) and compute/io through the engine. Operations
  `RegisterWasmContract` (upload+validate bytecode) / `InvokeWasmContract` are
  additive (transaction.rs required_units + access list). `state.rs`: `wasm_contracts`
  + `wasm_code` maps committed by two new state-root sub-roots (commitment domain
  **V19 → V20**); a shared `run_contract_call` core both native + wasm invoke paths
  go through; `WasmContract{Registered,Invoked}` events; a `code_id` is unique
  across BOTH contract paths (shared `StateKey::module`). Typed, text-free wasm
  error variants keep receipt errors byte-identical across nodes. Real end-to-end
  WAT tests (store/echo + a stateful counter exercising `webc_get`): register+invoke,
  state commit, determinism, over-gas atomic rollback, undeclared-key fail-closed,
  invalid-module + code-hash rejection, state-root commitment across restart. **Full
  workspace test suite green** (V19→V20 bump broke nothing).
- Adversarial multi-dimension review of the wiring was run via a workflow
  (determinism / gas / footprint / rollback / additive-safety / bytecode-validation);
  resolve any confirmed findings before treating 7b as closed.

**CURRENT IN-FLIGHT — Weft skeleton (owner-approved earliest version).** Owner:
"weft을 아주 극초기버전이라도… 틀이라도… 나중에 유연성 좋게" — build even a
skeleton Weft, for future flexibility. Weft is a **DECIDED** language
(`docs/weft-language-plan.md`, `architecture.md`, ADR-0014): a front end that
compiles **off-chain to deterministic WASM** targeting the frozen host ABI — never
a second VM. The skeleton = a new `webc-weft` crate with a REAL (tiny) pipeline
lexer→parser→AST→sema→WAT codegen over the host ABI, emitting the machine-readable
interface manifest, with the flagship proof being a `.weft` counter that compiles
and **runs as a real on-chain contract** (register+invoke on `webc-chain`, state
accumulates). Skeleton codegen emits WAT and assembles via the `wat` crate; the
production backend (lowering via the audited Rust framework) is a documented
extension point. Being built with workflows (design synthesis + adversarial review)
per owner direction.

**Remaining practical-L1 roadmap after the WASM runtime (value order, all
additive so Codex-safe):** distribution program (airdrop claim / expiring
fee-credits / stake-locked vesting) · bridge prototype (provisional trust) ·
validator operations stack (keystore per ADR-0009 / monitoring `/metrics` /
Dockerfile) · DEX delegated mechanics (AMM / multi-hop) · flagship demo apps.
Optional: complete Codex's V5 transaction system as a formal task.

**Owner-deferred — do NOT decide autonomously:** slashing severity numbers +
inactivity-leak params (ADR-0012), WASM production engine + manifest trust
(ADR-0014), production bridge trust model, PQ transaction policy, mainnet
governance emergency powers, fast-path hardware trade-offs. **External:**
real-hardware benchmarks, independent security audit (Phase 5.5), testnet/mainnet
launch. Weak-subjectivity anchor (ADR-0011) is already owner-confirmed.

NOTE ON THE EPHEMERAL ENVIRONMENT: the container is reclaimed on idle, which
SILENTLY kills in-flight background subagents (no completion notification) and
may drop an un-pushed worktree. Mitigations that WORK: keep the main session
active with real foreground work while a subagent runs (this reliably keeps the
container alive); make subagents commit+push after their first unit and often;
set a `send_later` self-check-in to recover if the container reclaims; salvage
uncommitted work from the (often-persistent) worktree — that is how
AgentCommerceClient was recovered. If a subagent runs long with no completion,
check for a restart (worktree/branch gone, fresh process start-times) rather than
waiting indefinitely.

## Completed Phase 4 findings checkpoint (historical)

The following Phase 4 hardening work is complete; do not resume it as the next
task.

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

The Phase 5–13 work (economics, localized fees, sponsorship, namespaces, oracle,
interim contract runtime, DEX, agent mandate + service registry, tokens, NFTs,
application governance) was developed on **`claude/agent-md-review-6a392q`** and
**integrated into `main`** on 2026-07-17. A separately assigned **transaction-system**
goal develops independently on its own `codex/transaction-system` branch and is
**not** merged here (per the branch-isolation workflow in `AGENTS.md`); the three
Codex commits already on `main` (repo restore + workflow docs) are preserved by
this integration. Further work continues on `main`.

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

**Fee sponsorship / paymaster (§15.35) — DONE, wired.** Registered apps pre-fund a
budget that pays users' fees within hard deterministic caps (ops per user/app/day,
per-op fee, per-app daily budget; "day" = epoch window). New `sponsorship` module
(`RegisterAppSponsor`/`FundAppSponsor`/`WithdrawAppSponsor`, `AppSponsor`,
`SponsorshipConfig`); opt-in `Transaction.sponsor: Option<Hash256>` (fail-open to
self-pay when over-cap/ineligible/unregistered; Transfer-only). `sponsor_budgets`
supply bucket; **state-commitment domain V8→V9**; non-sponsored txs stay
byte-identical (manual `Transaction` Serialize keeps `sponsor` out of the JSON wire
when absent). **TS SDK support DONE** too — `signTransaction` gains an optional
`sponsor`, byte-parity verified against the frozen `WEBC_SIGNED_TRANSACTION_V4`
vector for both the absent (identical) and present cases. §15.35 is complete
end-to-end (Rust + SDK).

**Application namespace registry — DONE.** `RegisterNamespace`/`TransferNamespace`
claim/transfer an app namespace to an owner (`namespaces` map, `namespace` module);
object ops stay UNGATED (open namespaces; gating is a deferred later-phase policy);
supply unaffected; state-commitment domain V9→V10.

**Sharded examples — DONE.** `crates/webc-chain/tests/sharded_parallel_execution.rs`
(8 tests) demonstrates namespace/account isolation at the scheduler for
tokens/games/swaps/site-sessions (disjoint ⇒ one parallel batch + order-independent
execution; shared resource ⇒ serialized). Swaps and shared-session contention are
asserted at the scheduler level only (no native DEX / cross-owner object write yet
— later phases).

**Localized (per-namespace) fee pricing + fair block packing — DONE, wired
(§8/§7).** Object operations are priced by their namespace's own EIP-1559 base
fee, adjusted each block from only that namespace's usage vs a per-namespace
target (`FeePolicy::per_namespace_target_units`), so one app's congestion never
raises another's price; account-scoped ops keep the global base fee. Every
localized fee is floored at the network-wide `min_base_fee_per_unit`, and a
namespace back at the floor sheds its committed record (bounded `namespace_fees`
map). Fair packing caps a single namespace at
`FeePolicy::namespace_block_share_bps` of `max_block_units` — a hard
`build_block`/`apply_block` validity rule plus mempool `select_block` shaping, so
one hot app cannot monopolize a block. New config knobs are serde-defaulted
testnet placeholders (§15.35). **State-commitment domain V10→V11** (added
`namespace_fee_root`); the map locks no native units so the supply invariant is
unchanged; new `NamespaceBlockShareExceeded` error. Acceptance tests: A's
congestion not raising B's price, the floor, fair packing admitting other
namespaces, unaffected account transfers, supply reconciliation, bincode
crash-restart of the fee state with a stable root, and cross-run determinism.
Full workspace gate green (fmt/clippy -D warnings/test/doc/demo).

**Varint amount encoding (§15.14) — DONE.** The binary bincode paths (wire +
storage-at-rest) switched to `with_varint_encoding()`, so `Amount` (and every
binary integer) is compact; `Amount`'s serde is untouched and the canonical-JSON
decimal-string path is byte-identical, so `state_root`, signing (`SIGNING_DOMAIN`),
and the SDK are unchanged (SDK gate green unchanged). **`NET_PROTOCOL_VERSION`
3→4** (a v3 frame is refused before body decode); N6 frame-size protection
preserved; storage-at-rest layout changed (ephemeral prototype, no migration).

### Phase 6 — major code items COMPLETE (2026-07-17)

All Phase 6 code-completable tasks are done and pushed, full workspace + SDK gate
green: storage deposit + deletion rebate (§15.22); zstd compression at rest and on
the wire (§15.24); fee sponsorship / paymaster (§15.35, Rust + SDK); application
namespace registry; sharded parallel-execution examples; localized per-namespace
fee pricing + fair block packing; varint amount encoding (§15.14). The scheduler /
declared-access / parallel-batch foundation (SC1/SC2) was already in place. The
state-commitment domain moved V7→V11 across these (each bump E8-guarded, supply
invariant preserved). ADR-0013 records the hot/cold tiering boundary
(implementation may lag). **Two items remain non-blocking:** (1) multi-dimensional
per-resource congestion metering (today one execution-unit scalar per namespace —
a refinement; the acceptance criteria "one app's congestion doesn't raise
another's price" and "fair capacity bounds saturation" are already met); (2) the
TPS benchmarks (100/500/1000/2000 gates) need real reference hardware, not a cloud
container (a known deferred non-finding).

### Phase 7 progress

**Native oracle — DONE.** New `oracle` module: `CreateFeed`/`RegisterReporter`/
`DeregisterReporter`/`SubmitReport`/`PayFeedRead`; integer median (lower-mid
tie-break) over reporters' latest values; read-fee revenue settled every
`settlement_epochs`, split accuracy- (inverse-distance) and liveness-weighted with
the F1 dust-carry (supply-neutral). Locked `oracle_bonds` + `oracle_revenue`
buckets in the supply invariant; feeds/reporters committed via new sub-roots;
state-commitment domain **V11→V12**. Reporter slashing deferred (ADR-0012 owner
decision) — outliers simply earn zero revenue. Deferred oracle refinements (later
`oracle-economics.md` steps): first-party publisher class, cold-start seeding, app
subscriptions, once-per-block pull gating, freshness-gating the displayed aggregate.

**Contract runtime (Phase 7a) — design landed; interim framework IN PROGRESS.**
**ADR-0014** (docs/adr/0014-contract-runtime.md) records the design: ship the
interim native/Rust-authored path first (a contract is a Rust handler behind the
same declared-access + gas discipline as native ops, with an on-chain manifest),
then restricted WASM as the general engine, with the Weft machine manifest (§15.41)
as the ABI sidecar; the (c)→(a) migration is state-free via the versioned ABI.
Owner-owned decisions flagged in the ADR (do not decide alone): the final engine
(restricted WASM vs bespoke bytecode) and the manifest trust/verification model.
The **interim framework is DONE** — `contract` module, `ContractManifest` registry,
`RegisterContract`/`InvokeContract` ops, a `Contract` trait routing all state access
through `StateAccessRecorder` against the manifest's declared `StateKey::application`
footprint (declared-access enforced + parallel-schedulable), deterministic gas
metering (admission + metered execution) with atomic over-gas rollback, and a
`KeyValueContract` example; registration fee burned (supply-neutral);
state-commitment domain V12→V13. NO WASM / untrusted-code loading (deferred).

**Phase 7a WASM engine — OWNER-GATED, do NOT build yet.** ADR-0014 explicitly
defers the final engine choice (restricted WASM vs bespoke bytecode) and the
manifest trust/verification model to the owner at the ADR-0006 evidence gate. The
interim ABI is versioned so the (c)→(a) migration is state-free once the owner
decides. **Phase 7b (Weft language)** is a separate large project whose name is
owner-renamable (owner-deferred) — not autonomous work here.

### Phase 8 — native DEX batch settlement (§15.37) — CORE DONE

Mandatory per-block **uniform-price batch settlement** (MEV-resistant) is
implemented (`dex` module): `SubmitOrder`/`CancelOrder`, orders lock input into a
`dex_escrow` bucket, `settle_dex_batch` runs in `build_block`/`apply_block` at one
deterministic clearing price per pair (two-pointer crossing, integer-midpoint
tie-rule so no fill breaches its limit), long side rationed dust-free by
cumulative-rounding pro-rata; chain-native retry until `deadline_height`/cancel;
`fill_or_cancel`. New `current_height` scalar; state-commitment domain V13→V14;
supply invariant reconciles; build==import deterministic. **Deferred delegated
mechanics** (§15.13/15.18/15.37): AMM/shared-pool curve pricing, multi-hop
routing, finer tick sizes, complex slippage — later refinements.

### Phase 9 — agent commerce (§15.5/§15.32)

**Mandate — DONE (9a).** The spec (`agent-commerce.md` §2) is explicit that a
mandate is a SEPARATE primitive from session keys: session keys authorize the
owner's own device flows; a mandate authorizes a DISTINCT agent identity with its
own key and audit trail. Implemented as `mandate.rs`: a PRE-FUNDED, instantly-
revocable on-chain mandate (`GrantMandate`/`TopUpMandate`/`SpendUnderMandate`/
`RevokeMandate`) enforcing budget + per-tx max + expiry + daily rate-limit +
counterparty policy (Open | Allowlist of recipients/category tags), no
re-delegation, agent-key-signed spends, full audit trail. New `mandate_escrow`
supply bucket (grant locks, spend draws, revoke/expire-reclaim returns the
remainder); state-commitment domain V14→V15; adversarial coverage of every
rejection path + supply-balanced assertions. Merged 69a4840.

**Service registry — DONE (9b).** A bounded, namespace-scoped, fee-priced
native registry (`service_registry.rs`, §15.5b/§3 of `agent-commerce.md`) where
services publish machine-readable categories/prices/interfaces for agent
discovery — built like the oracle-feed / namespace registries, only the current
revision in committed state (monotonic `revision`; history is archival). Closes
the mandate category-allowlist loop with a service-scoped spend
(`SpendUnderMandateToService`) that resolves `Category` tags against a service's
registered categories. Domain V15→V16. Merged 161522d.

**M1 fee-cap fix (post-9b adversarial review) — DONE.** A read-only adversarial
review of the merged mandate found the per-tx cap bounded only the principal
`amount`, not `amount + fee`; since the agent-chosen fee is drawn from the same
escrow, one high-fee spend could drain the whole budget past `per_tx_max` /
`rate_limit_per_day` (value extraction, supply stayed conserved). Both spend arms
now reject `amount + total_fee > per_tx_max` and zero-amount spends; reproduced
first (`fee_bid_cannot_inflate_a_spend_past_per_tx_max`). Validation-only, no
domain bump. Recorded as finding M1 in `docs/review/findings.md`. Commit 13c7b9e.

**Phase 9 native core is COMPLETE.** The tail (SDK agent toolkit, HTTP-402
challenge/verify middleware, docs-as-data registry snapshot, flagship
marketplace demo) is SDK/integration/external, matching the deliberately partial
wallet-focused SDK (it covers Transfer/Stake/Delegate/InstallSessionKey only —
oracle/DEX/contract/namespace/sponsor/mandate/service all await the consolidated
SDK/platform phase, development-plan Phase 12). Those are not per-feature work.

**Follow-ups (later, mostly non-consensus):** HTTP-402 payment flow (§4) and the
SDK agent toolkit (mandate management UI, agent discover→validate→pay→retry
client, service challenge/verify middleware) are SDK/integration-level. The
docs-as-data registry snapshot and the flagship agent-marketplace showcase ride
on the primitives above.

### Phase 13 — native tokens / NFTs / app governance

**Fungible tokens — DONE (13a).** A SELF-CONTAINED native token space
(`token.rs`), deliberately separate from the bridge `AssetId`/`asset_balances`
to avoid entangling with the production-bridge trust model and the SDK codec:
own `TokenId` (namespace/creator/nonce-derived), own zero-pruned
`token_balances`, own `frozen_token_accounts`. Ops CreateToken / MintToken /
BurnToken / TransferToken / SetTokenPaused / FreezeTokenAccount / ThawTokenAccount
/ SetTokenAuthority. Authorities are `Option<Address>` — renounce (`Some→None`) is
PERMANENT. TWO invariants both enforced+tested: native WEBC supply stays balanced
(non-refundable creation deposit locked into a new `token_deposits` bucket; mint/
burn never touch WEBC) and per-token `sum(balances)==issued_supply`. Transfers
write only the two `(token,addr)` balance keys — no global mint bottleneck. Domain
V16→V17. Merged 4cc47ca. **Post-merge adversarial review** confirmed supply/
authority/native-WEBC/arithmetic/determinism clean and found one latent defect
(**T1**): `TransferToken` read freeze state without declaring the `TokenFreeze`
keys, so under the (not-yet-wired) parallel executor a transfer could share a
batch with a concurrent freeze and race. Fixed by declaring both parties' freeze
markers as reads on the transfer path (+ scheduler regression test
`token_transfer_serializes_against_a_freeze_of_either_party`). Finding 2 (a token's
own freeze authority can freeze many accounts) is within that token's trust model
and cost-bounded — informational, no change.

**NFTs — DONE (13b).** Native NFT collections (`nft.rs`) with single-owner items
keyed by `(collection_id, serial)`: CreateNftCollection / MintNft / TransferNft /
BurnNft plus per-collection pause, per-item freeze/thaw, and permanent authority
transfer/renounce. Monotonic `next_serial` (burned serials never reminted),
optional `max_supply`, recorded-but-unenforced `royalty_bps`. Two invariants both
enforced+tested: native WEBC supply balanced (deposit locked into a new
`nft_deposits` bucket) and `minted_count - burned_count == live items`. Transfers
write only the one item key; MintNft serializes on the collection record (serial
is chain-assigned). Domain V17→V18. Merged 200c4fa. **Post-merge adversarial
review returned CLEAN** — the subagent had applied the token-T1 lesson
(declared==actual access verified end-to-end, mint/op races checked via
`parallel_batches`); only a stale pause doc comment was corrected. Two invariants,
authority renounce permanence, freeze/pause gating, and supply neutrality all
verified.

**Application governance — DONE (13c).** Token-weighted, LOCK-TO-VOTE governance
(`governance.rs`): an instance is bound to a `weight_token` and holds a native-WEBC
`treasury`. Ops CreateGovernanceInstance / FundGovernanceTreasury / OpenProposal /
CastVote / ResolveProposal / ExecuteProposal / ReclaimVote. Voting LOCKS weight
tokens by moving them to a synthetic per-proposal escrow **within** `token_balances`
— this satisfies the "prevent double-voting / after-snapshot manipulation"
acceptance criterion WITHOUT historical state and keeps `sum(token_balances)==
issued_supply` intact automatically. Integer quorum/approval (`u128 checked_mul`,
no float); timelock + Compound-style execution/expiry window; `TreasuryTransfer`
pays once, re-checking the live treasury. Two supply buckets (`governance_deposits`,
`governance_treasury`); domain V18→V19. Delegation DEFERRED (does not compose
cleanly with lock-to-vote; documented). Merged into main f5a4ad8. **Post-merge
adversarial review returned CLEAN** — native-supply conservation, no treasury
double-spend/overspend/timelock-bypass, per-token invariant, declared==actual
access (no T1-style bug, verified line-by-line + scheduler serialization), integer
math, and determinism all confirmed; two by-design informational notes only (live
quorum denominator = mint-authority grief, documented; ReclaimVote intentionally
skips pause/freeze to avoid stranding a voter's escrow).

**Phase 13 (tokens, NFTs, governance) is COMPLETE and integrated into `main`.**
The deferred cross-phase tail — SDK agent/token/governance toolkits, HTTP-402
flows, Phase 10 succinct proofs / PQ, Phase 11 fast-path + real-hardware
benchmarks, Phase 12 web platform, Phase 14/18 bridges, Phase 16 testnet, Phase
17 mainnet gates — remains owner-gated (trust anchors, slashing numbers, bridge
trust model, mainnet governance) or needs external resources (benchmarks, audits,
live bridges). Surface those to the owner rather than deciding alone. A separate
**transaction-system** goal runs independently on `codex/transaction-system`.

### SDK native-operation coverage — DONE (Phase 12 sliver)

The TypeScript SDK (`sdk/webc-js`) now exposes **all 38 new native operations**
(tokens, NFTs, governance, mandate, service registry, oracle, DEX) plus 13 new
state-key kinds, with cross-language canonical-JSON parity tests pinned against
the Rust wire vectors. `defaultAccessList` replicates every Rust access-list arm
in exact insertion order (including TransferToken's both-parties `TokenFreeze`
reads); the six state-derived ops (governance vote/resolve/execute/reclaim/open,
mandate→service spend) expose `accessListFor*` helpers mirroring the Rust `for_*`
constructors and `signTransaction` refuses to auto-derive them. Merged into main
e51e7de. A follow-up (75519c6) added the Rust `dex_operations_have_stable_wire_vectors`
test so DEX — previously the one family with no Rust vector — now has real
Rust↔TS byte parity.

### HTTP-402 agent-payment flow — DONE (Phase 9 §4, agent-commerce flagship)

An SDK helper (`sdk/webc-js/src/http402.ts`, merged e8e8463): an agent validates a
`402` challenge against the on-chain registry entry (price + pay-to must match,
defeating a compromised endpoint), pays via `SpendUnderMandateToService` under its
mandate, and retries with a verifiable payment reference. 29 tests covering every
failure mode.

### Node read-APIs — DONE (merged 0c0cb7f)

Additive GET-only endpoints so apps and the SDK can QUERY the Phase 9/13 state:
`/v1/tokens/{id}(+/balances/{addr},/supply)`, `/v1/nft/collections/{id}(+/items/
{serial})`, `/v1/services/{id}` (closes the 402 registry-fetch loop),
`/v1/governance/instances/{id}`, `/v1/governance/proposals/{id}`, `/v1/mandates/
{id}`. Nine `NodeService` read accessors; unknown id → 404, known-token/no-holder
→ 200 zero.

### Automated invariant evidence — DONE (merged 4223daa)

`crates/webc-chain/tests/native_ops_invariants.rs`: a proptest driving random
seeded sequences of all fund-moving ops (tokens/NFT/mandate/governance/DEX, with
epoch advancement) through `execute_transaction`, re-asserting the native supply
invariant, per-token and per-collection supply invariants, and fail-closed
rollback after EVERY applied or rejected step. No violation found; non-vacuous.

### Boundary reached — app-facing surface complete; remainder is owner-gated

The decided, autonomous app-layer arc is DONE end-to-end on `main`: construct any
native op (SDK, 38 ops), submit it (`POST /v1/transactions`), query the resulting
state (node read-APIs), and run the agent-commerce 402 flow — with adversarial
review + proptest evidence behind the fund-moving code. **Remaining work needs the
owner or external resources** and must NOT be decided autonomously: ADR-0012
slashing severity numbers + inactivity-leak consensus wiring; ADR-0011 weak-
subjectivity trust anchor; ADR-0014 WASM engine + manifest trust; the production-
bridge trust model (Phase 14/18); mainnet governance emergency powers; the Weft
rename; founder compensation (§15.4); Phase 10 succinct-proof/PQ backend choice;
Phase 11 fast-path DAG-BFT adoption + real-hardware benchmarks; Phase 16 testnet /
Phase 17 mainnet launch gates; and an independent security audit before any real
funds. Optional low-value autonomous polish that could still be picked up: SDK
node-client read-method parsers + high-level client wrappers, node list/pagination
endpoints, and the DEX delegated mechanics (AMM/multi-hop, a design-within-scope
refinement). A separate transaction-system goal runs on `codex/transaction-system`.

### Original Phase 13 rationale — native tokens / NFTs / app governance

Chosen next because it is the cleanest FULLY-AUTONOMOUS native block: spec-decided
(§15, development-plan Phase 13), builds directly on the existing multi-asset
`asset_balances`, the storage-deposit system (§15.22, deposit-based spam pricing),
and the established native-registry / sub-root / domain-bump patterns, with NO
owner-gated dependency. Skipping ahead of Phases 10-12 is deliberate: **Phase 10**
(succinct proofs / PQ) needs the owner-gated archival trust anchor (ADR-0011) and
external proof-backend/benchmark choices; **Phase 11** (fast path) is deep
consensus work needing reference-hardware benchmarks + an adopt-by-ADR DAG-BFT
decision + committee-sampling ADR; **Phase 12** is the consolidated SDK/platform
phase. Their autonomous slivers (e.g. object inclusion proofs vs the current root)
can be picked up later. Phase 13 core to build: native token/NFT registry +
metadata commitments; mint/burn/freeze/pause/authority-transfer/revocation;
transfer-policy hooks without a global mint bottleneck; deposit-based creation
fees. App-governance instances (snapshots/quorum/timelocks/delegation) follow as a
second unit. Build with worktree subagents, frequent commit+push, gate+merge each,
and keep the supply invariant + a domain bump + E8 coverage for any new committed
map/scalar. **Owner-gated (do NOT decide alone):** ADR-0012 slashing numbers +
inactivity-leak wiring, WASM engine + manifest trust (ADR-0014), Weft rename,
bridge trust model (Phase 14/18), weak-subjectivity anchor (ADR-0011), mainnet
governance emergency powers, founder comp (§15.4). Later phases (14 bridges, 16-19
testnet/mainnet/production) are increasingly owner-gated or need external
resources — surface to the owner rather than deciding alone.

### Original Phase 7 plan summary — contract runtime, native oracle, then Weft

Per `development-plan.md` Phase 7 (sequencing owner-confirmed): **7a** a sandboxed
contract runtime with declared-access enforcement + interim Rust authoring ships
first; the **native oracle** (feed registry + bonded reporters + median
aggregation, §15.17/15.21 economics — see `oracle-economics.md`); then **7b** the
Weft language + tooling (later, separate project — `weft-language-plan.md`; the
design is decided, do not re-litigate; the name is owner-renamable). This is a
large phase — decompose it, keep using worktree subagents with frequent
commit+push, gate + merge each. Owner-deferred items unchanged (ADR-0012 slashing
numbers + inactivity-leak wiring; production-bridge trust model; weak-subjectivity
anchor; governance emergency powers; Weft rename; founder comp §15.4).

**Note on commit signing:** this environment's ssh signing key
(`/home/claude/.ssh/commit_signing_key.pub`) is a 0-byte placeholder, so no commit
can be signed — every branch commit is correctly authored `Claude
<noreply@anthropic.com>` but shows "Unverified" on GitHub. Unavoidable here; not a
code issue. The stop-hook's rebase remedy cannot add signatures without a real key. The **TPS benchmarks** (100/500/1000/2000 gates) need real reference
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
production-bridge trust/proof model; mainnet governance emergency powers;
renaming Weft. The weak-subjectivity checkpoint-source direction is no longer
deferred; it is recorded in `decision-record.md` and ADR-0011 as explicitly
reviewable.

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

Full historical context: `docs/review/findings.md` (per-finding detail + fixes)
and `docs/review/2026-07-16-plan-review.md` §6. The owner-selected transaction
objective is the current bounded work. Do not use it to jump into the contract
runtime, Weft, DEX, oracle, bridges, or the real ZK/STARK backend before their
gates.

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
