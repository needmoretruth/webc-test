# WEBC transaction-system completion plan

Status: owner-selected implementation objective (2026-07-17). This is the task
specification, not a completion claim. Branch-local recovery state lives in the
goal progress section below. Global code reality and continuation documents are
reconciled only when the completed branch is integrated.

This plan is activated only by an explicit transaction-system goal. It is not
the global `main` continuation pointer and must not redirect unrelated agents.

## Goal branch and durability

- The dedicated integration branch is `codex/transaction-system`. Create it
  from the latest `origin/main`, or resume it if it already exists. Do not do
  transaction development directly on `main`.
- Push the branch immediately after creation, then commit and push every
  coherent tested step to it. Before a long integration/test pass or likely
  context/session limit, push the latest recoverable checkpoint. Local-only work
  is not durable.
- Use subagents only when parallel work is genuinely useful. The root chooses
  the number, timing, and split from current dependencies; no fixed count is a
  completion requirement. Every code-changing subagent gets a real worktree and
  its own branch based on the transaction integration branch, and pushes each
  coherent tested step. Root integrates subagent work only into
  `codex/transaction-system` while the goal is in progress.
- Do not rewrite, force-push, or delete history. Do not change the global
  `continuation-guide.md` or `implementation-status.md` merely to report
  branch-local progress; use this plan's decision/progress log and commits. The
  live global documents are reconciled only during the final main integration.
- When all allowed completion gates pass, fetch the latest `main`, merge it into
  `codex/transaction-system`, resolve/test there, push the tested branch, then
  integrate it into the latest `main` without force. If `main` moves meanwhile,
  fetch, merge, retest, and retry instead of overwriting concurrent work.

## Outcome in plain language

A transaction must have one understandable and verifiable life:

1. a wallet creates and signs it;
2. a node rejects it precisely or queues it safely;
3. validators include and execute it deterministically;
4. its success/failure, fee, and events are recorded durably;
5. users can query its status after restart;
6. a browser/light node can prove inclusion and finality without trusting the
   RPC server that returned the answer;
7. after the Phase 5.5 core-review gate, a real replaceable STARK backend may
   also prove correct execution without replaying the full block.

“Complete” means that whole path passes adversarial end-to-end tests. Current
native operations use it first. Future contract calls enter through the same
versioned boundary; this task does not invent Weft or a VM ahead of their gate.

## Existing code to preserve and reuse

Do not replace or duplicate these working foundations:

- signed chain-bound `Transaction`: protocol version, authorization policy,
  lanes, per-lane nonce, access list, fee bid, and Rust/TypeScript fixtures;
- deterministic native operations and whole-block atomic execution;
- bounded mempool: nonce ordering, local expiry, fee priority, and fee-bumped
  replacement;
- block `tx_root`/`receipt_root`, receipts, finality certificates, bounded Merkle
  verification, and account-state proof;
- redb storage, HTTP/WebSocket APIs, gossip, and TypeScript SDK;
- ADR-0005's replaceable proof seam and ADR-0011's historical/checkpoint plan;
- existing crypto, canonical encoding, state-key, fee, authorization, storage,
  network, and dependency-audit modules.

Start with a code audit. Extend the module that already owns a responsibility;
create a focused module only when no correct home exists.

## Reviewable working design

Everything below is a delegated engineering direction, not permanent owner
policy. An implementer may replace a choice when tests, audits, measurements, or
maintenance evidence support it. The replacing commit must preserve history and
record why, alternatives, compatibility, migration, and proof.

### Signed transaction and actions

- Preserve domain separation, chain ID, protocol version, authorization policy,
  lane, nonce, declared access, fee limits, and signatures in signed bytes.
- Audit the current format before changing it. Any signed/consensus byte change
  gets a new explicit version and frozen cross-language vectors; old bytes are
  never silently reinterpreted.
- Add a bounded ordered action list only through a versioned format. Its actions
  are atomic: all application-state changes succeed or all roll back. Validate
  action count, bytes, declared access, and unit limits before allocation/work.
- Future contract calls are action variants behind the contract-runtime seam.

### Admission, replacement, cancellation, and expiry

- Malformed, unauthorized, wrong-chain, stale, or plainly unaffordable
  transactions are rejected before inclusion: no nonce consumed, no fee.
- Consensus expiry is signed and expressed in block height/epoch, never a node's
  wall clock. Mempool time-to-live remains only a local resource bound.
- Replacement keeps `(sender, lane, nonce)` and requires a measured fee bump.
  Cancellation is a signed no-effect replacement for the same identity; it
  cannot undo a finalized result.
- Queue, decoding, proof, future-nonce, and resource limits fail closed.

### Failed execution and fees

- An included execution failure rolls back that transaction's application
  changes, consumes its nonce, charges deterministically measured work, and
  creates a committed failed receipt. It must not abort or partially commit
  unrelated valid transactions.
- Fee accounting preserves the confirmed base-fee split: 50% burned and 50%
  rewards. Caps, used units, payer, burn, reward, priority fee, and refund are
  explicit and checked with integer arithmetic.
- Sponsored fees use separate signed payer authorization with amount, action,
  sender/site, lifetime, and replay caps. Paying a fee grants no authority over
  the payer's unrelated state.

### Receipt and visible status

- Replace consensus-critical free-form failure text with a versioned typed code.
  Human text is derived at API/SDK edges and is not protocol meaning.
- A receipt commits the transaction hash, block position, schema version,
  success/typed failure, units, full fee breakdown, payer, and ordered events.
- Status distinguishes unknown, queued, replaced, expired/dropped,
  included-success, included-failure, finalized-success, and finalized-failure.
  APIs identify local observations versus durable consensus facts.
- Finalized indexes and required pending records survive clean/crash restart.
  Re-submitting the same transaction hash is idempotent.

### Finality proof and ZK boundary

- A finalized transaction proof contains the header, finality certificate,
  transaction/receipt positions and bounded Merkle paths, plus validator-set
  transitions needed from the starting checkpoint.
- Rust is the reference verifier; TypeScript verifies identical canonical bytes
  and fixtures. Any changed transaction, receipt, path, header, certificate,
  chain, or validator transition must fail.
- Merkle paths prove inclusion and validator certificates prove finality. They
  remain the transparent fallback after ZK exists.
- The execution-proof interface is versioned and replaceable. A real STARK may
  bind chain/protocol, previous and next state roots, block, transaction root,
  and receipt root. Finality signatures remain outside unless later evidence
  supports aggregation.
- A hash wrapper or mock is never called ZK. ZK is complete only with a real
  prover/verifier, negative vectors, and target-browser benchmarks. Backend work
  waits for the Phase 5.5 independent core review; interface and transparent
  proof work may land first.

## Replaceable first-bookmark design

A light node's first known-good checkpoint is its “first bookmark.” From there,
it verifies certificates and validator-set changes itself. The owner approved
multi-source comparison as a provisional direction, not an immutable solution.

Implement three separate boundaries:

1. `Checkpoint`: canonical, versioned data plus chain/age/size validation.
2. `CheckpointSource`: interchangeable retrieval adapters, such as official
   release, independent service/node, or explicit operator input.
3. `CheckpointTrustPolicy`: interchangeable acceptance logic over validated
   candidates. The initial multi-source policy stops on disagreement.

Consensus, execution, and proof verification consume only an accepted
`Checkpoint`. They never depend on URLs, publisher brands, source count, or one
specific policy. The implementation session autonomously chooses exact source
authentication/count/threshold after a threat-model review and records it; a
later audit can replace it without rewriting the transaction or consensus core.

## Candidate work areas and optional parallelism

The following areas describe ownership and dependencies; they do not force three
agents or simultaneous execution. Root decides whether to delegate none, one,
or several areas. If it delegates, it first freezes the smallest shared
interfaces, gives agents disjoint primary files, verifies every worktree with
`git worktree list`, and keeps coupled changes sequential when that is safer.
Root owns shared types, branch integration, the plan's progress/decision log,
and full gates. Global status documents and `main` are updated only during final
integration.

### Area A — transaction protocol and execution

Primary ownership: `crates/webc-chain` and required canonical fixtures.

- versioned action/envelope model, signed expiry, cancellation, payer
  authorization, and hard bounds;
- failed-execution/nonce/fee/refund semantics and typed receipts;
- Merkle leaf definitions and Rust/TypeScript canonical vectors;
- property/adversarial tests for rollback, supply, replay, access, fees, action
  ordering, and hostile decoding.

### Area B — node lifecycle, storage, and APIs

Primary ownership: `crates/webc-node` and `crates/webc-storage`.

- restart-safe pending/finalized lifecycle and transaction/receipt indexes;
- admission, replacement, cancellation, expiry, eviction, duplicates, gossip,
  and status transitions;
- bounded status/receipt/proof HTTP and WebSocket APIs with typed errors;
- crash recovery, idempotency, multi-node, rate-limit, and index tests.

### Area C — finalized proofs and light client

Primary ownership: a focused proof/light-client crate and `sdk/webc-js`.

- finalized transaction-proof schema and verification from a checkpoint;
- modular checkpoint/source/trust-policy interfaces, multi-source mismatch stop,
  explicit operator input, and validator-set transition verification;
- Rust/TypeScript parity fixtures, browser verifier/SDK, and tamper tests;
- after Phase 5.5, select a maintained Apache-2.0-compatible STARK library from
  security, maintenance, license, and browser benchmarks and implement the real
  backend behind ADR-0005.

## Integration sequence

1. Create/resume and push `codex/transaction-system` from current `origin/main`.
2. Freeze shared domains, types, errors, API shapes, compatibility/migration,
   and file ownership in one root commit; push it.
3. Work through A/B/C in the dependency order root judges safest. Delegate
   independent portions when useful; keep tightly coupled portions sequential.
   Every active branch pushes recoverable milestones frequently.
4. Integrate completed work into the transaction branch in dependency order,
   resolve interface drift there, test, and push each coherent integration.
5. Run Rust, TypeScript, docs, dependency, fuzz-smoke, restart, and multi-node
   gates; fix and push focused integration commits on the transaction branch.
6. Fetch and merge the latest `origin/main` into the transaction branch, run the
   full gates again, then reconcile `implementation-status.md` and
   `continuation-guide.md` with both lines of work.
7. Push the tested transaction branch, integrate it into the still-latest
   `main` without force/history rewriting, and verify local/remote equality.
8. After Phase 5.5, complete the real STARK backend and gates. Until then state
   truthfully: transparent proof complete; ZK backend deferred.

## Completion gates

Do not call the system complete until tests prove:

- wallet → RPC → mempool → gossip → proposal → execution → finality → durable
  query across at least three validators and restart;
- malformed/wrong-chain/expired/stale/future-flood/underfunded/underpriced/
  unauthorized-sponsor/access attacks have exact state, nonce, and fee results;
- replacement/cancellation cannot replay or undo finality;
- included failure rolls back only its actions, charges bounded measured work,
  consumes the correct nonce, and leaves unrelated transactions valid;
- all fee paths conserve supply and preserve the 50/50 base-fee split;
- indexes remain consistent after crash/restart and duplicate submissions;
- valid transaction/receipt/finality proofs verify in Rust/browser, while every
  tamper and oversized proof fails safely;
- the initial checkpoint policy accepts agreement, stops on disagreement or
  invalid/stale/wrong-chain input, and labels explicit operator trust;
- after Phase 5.5, a real STARK proof verifies, altered public inputs fail, and
  proof delay/failure falls back transparently without blocking consensus;
- canonical cross-language vectors, fuzz targets, `cargo-deny`, production JS
  audit, format, strict lint, rustdoc, and full tests are green.

## Mandatory maintainability and reuse rules

Every agent fully reads `AGENTS.md` and all required linked documents before
code, then this plan and track-specific files.

- Follow `code-documentation-template.md`: module ownership,
  non-responsibilities, flow, invariants, limits, rollback, and security reason.
- Use focused modules, one-directional dependencies, typed boundaries, checked
  arithmetic, deterministic ordering, and no panic on hostile input.
- Search first. Reuse existing Merkle, canonical, crypto, storage, network,
  authorization, fee, and error modules instead of cloning logic.
- Study established Layer-1 implementations such as Sui and Solana when they
  solve an analogous transaction, fee, storage, proof, or node problem. Use
  their official source/specification as design evidence, not as an instruction
  to copy architecture blindly. Record the relevant reference and the WEBC
  differences in the repository.
- Prefer maintained reviewed dependencies for commodity machinery. Permit only
  the Apache-2.0-compatible licenses in `AGENTS.md`; verify SPDX/maintenance,
  commit lockfiles, and pass `cargo-deny`/JS audit. Never invent crypto or proof
  primitives.
- Put dependencies behind narrow replaceable interfaces at protocol boundaries.
- Add negative tests with behavior, preserve frozen vectors, and never weaken a
  test to make code pass.
- Commit and push every coherent tested step. Security-relevant commit bodies
  state what/why, alternatives, compatibility/migration, and proof.
- Architecture choice → ADR or decision log below; code reality →
  `implementation-status.md`; next action → `continuation-guide.md`.

## Technical decision log

For each cross-module choice append:

```text
YYYY-MM-DD — choice
Changed: concrete interface/behavior.
Why: invariant, attack, measurement, evidence, or maintenance reason.
Reused: internal module or dependency and license; or why none fit.
Rejected: serious alternatives and why.
Compatibility: wire/state/API migration and rollback.
Proof: tests, vectors, benchmark/audit, commit hash.
Review status: provisional, accepted after review, or superseded by entry/ADR.
```

Never erase the earlier reason. Supersede it with a new entry.
The durable entry belongs in this file or a numbered ADR, with supporting detail
in the commit when useful. A chat explanation alone does not satisfy this rule.

### 2026-07-17 — modular checkpoint trust policy

Changed: checkpoint data/validation, candidate sources, and acceptance policy are
separate versioned interfaces; initial direction compares independent sources
and stops on disagreement, with explicit operator input supported.

Why: one official server is a trust/availability bottleneck, but multi-source
comparison may also have weaknesses. Separation lets a later review adopt a
better model without changing consensus or transaction-proof verification.

Reused: existing finality certificates, validator snapshots, Merkle roots, and
ADR-0005/0011 proof seams. No new crypto primitive.

Rejected: hardwiring an official-only source; embedding URLs/thresholds inside
consensus; pretending the first bookmark needs no trust.

Compatibility: not implemented. Exact schema, authentication, count, and policy
will be versioned and recorded when chosen.

Proof: owner approved the provisional direction and replaceability requirement
on 2026-07-17; implementation tests/commits remain pending.

Review status: provisional and explicitly replaceable after later review.

### 2026-07-17 — shared transaction lifecycle and proof interfaces

Changed: [ADR-0012](adr/0012-transaction-lifecycle-and-finalized-proofs.md)
freezes protocol-version-2 transaction/action/cancellation/sponsor shapes,
typed validation/execution/block errors, two-level rollback, base/priority fee
accounting, receipt/event/leaf formats, a single node runtime, durable lifecycle
indexes, V2 APIs, indexed proofs, authority transitions, checkpoint policy, hard
hostile-input bounds, compatibility, and module ownership.

Why: independent audits of `webc-chain`, `webc-node`/`webc-storage`, and the
proof boundary found that the V1 pieces do not share one failure, finality, or
restart model. Freezing the boundary first prevents Rust, storage, networking,
and TypeScript from encoding different meanings and prevents a chargeable user
failure from aborting unrelated block work.

Reused: existing canonical JSON, typed protocol integers, native operations,
access recorder, fees/base-fee state, Merkle hashing, finality certificates,
validator snapshots, `KvStore`, redb (`MIT OR Apache-2.0`), bounded network
codec, axum/tokio, and browser canonical encoder. Sui and Agave official source
were reviewed at the revisions and Apache-2.0 license links pinned in ADR-0012;
no source was copied and no dependency was added.

Rejected: optional fields added to V4, free failed work, partial action commits,
one error enum for validation and execution, independent HTTP/consensus nodes,
precomputed proof paths, one privileged checkpoint server, and an early STARK
backend.

Compatibility: V4/header-V3 vectors stay immutable; V5/header-V4 activate only
with protocol version 2 and a coordinated devnet reset. Schema-2 migration
backfills finalized legacy indexes, marks pending V4 entries unsupported, and
never serves a V3 block as a V4 finalized proof. New transaction lifecycle
routes use `/v2`.

Proof: the pre-change Rust full gate passed from a clean target directory on
2026-07-17; exact `pnpm` 11.7.0 `pnpm check` passed 81 `webc-js` tests, 3 widget
tests, TypeScript checks, and documentation links. Implementation vectors,
adversarial tests, and commits remain pending after this interface-freeze
commit.

Review status: accepted implementation direction; subject to adversarial tests
and independent external review before production use.

## Goal progress checkpoint

Implementation checkpoint on 2026-07-18: the isolated branch contains code
through `ee25016`; the paused-goal record below is a later docs-only handoff.
ADR-0012 and `4d54170` freeze the shared interfaces. `d25eb57` adds the
versioned `FeeSummaryV1` accounting boundary without changing V4 execution.
`ee09e61` routes every schema-1 `ChainStore` record through a bounded,
trailing-rejecting codec while preserving its legacy bytes. `b405e6b` adds the
pure `webc-proof` crate and bounded `IndexedMerkleProofV1`; `528ef4d` integrates
the Rust/browser V5 multi-action, cancellation, transaction-ID, exact-decimal,
and scoped-sponsor wire foundation without activating protocol version 2.

The integrated gate passed: `webc-storage` 32 tests, `webc-proof` 10 tests, V5
7 tests, strict clippy for the changed protocol/proof crates, Rust formatting,
and exact pnpm 11.7.0 `pnpm check` (81 SDK and 3 widget tests plus builds and
documentation links). Remaining limitations are material: the frozen
cross-language V5 vector, typed receipt/event roots, two-level V5 execution and
fee/nonce rollback semantics, lifecycle schema 2/migration, mempool/runtime/API
integration, finalized checkpoint proofs and browser verifier, fuzz/dependency
gates, restart/three-validator acceptance, and the final full workspace/main
integration gates are not yet implemented. The real STARK backend remains
correctly deferred until the Phase 5.5 gate. Exact next item: add and freeze the
Rust/TypeScript V5 canonical/signature/ID fixture, then implement typed receipts
and the two-level V5 execution overlay before any node lifecycle consumer.

While the goal runs, update this branch-local section after each integrated
milestone with the last pushed commit, passed tests, remaining limitation, and
exact next item. This is the recovery pointer if a usage/session limit ends the
agent. Do not change the global continuation/status documents until final main
integration.

### Paused-goal handoff (2026-07-18)

The owner asked to stop implementation and leave a durable continuation point.
Before this handoff edit, `codex/transaction-system` was clean and local `HEAD`,
the local tracking ref, and `refs/heads/codex/transaction-system` on `origin`
were all verified equal at `ee2501603ec2736eb193854e1be6d6d8f8da345c`. The
goal is **not complete** and must not be merged to `main` from this checkpoint.

What is durable on the goal branch:

- `4d54170`: ADR-0012 shared lifecycle/proof interface freeze;
- `d25eb57`: checked `FeeSummaryV1` base/priority/reserve/refund accounting;
- `ee09e61`: bounded schema-1 storage codec integration;
- `b405e6b`: pure indexed transparent Merkle proof integration;
- `528ef4d`: V5 Rust/browser wire, action/cancel, ID, exact-decimal, and
  sponsor foundation integration;
- `ee25016`: tested-foundation checkpoint and honest remaining-scope record.

The last integrated focused gate, run from the goal worktree, passed:

```text
cargo +1.96.0-x86_64-pc-windows-gnu fmt --check
cargo +1.96.0-x86_64-pc-windows-gnu test -p webc-proof          # 10 passed
cargo +1.96.0-x86_64-pc-windows-gnu test -p webc-chain transaction_v5::tests
                                                               # 7 passed
cargo +1.96.0-x86_64-pc-windows-gnu clippy -p webc-proof -p webc-chain \
  --all-targets -- -D warnings
pnpm check                                                     # 81 SDK + 3 widget
```

The bounded storage integration was separately rechecked on the goal branch
with `cargo test -p webc-storage` (32 passed) and strict crate clippy. These are
focused milestone gates, not evidence for the still-required final full
workspace, restart, three-validator, dependency, or fuzz gates.

Important boundaries a continuation must not mistake for completion:

- `CURRENT_PROTOCOL_VERSION` remains 1 and V4 execution/fixtures are unchanged;
- `sdk/webc-js/src/transaction-v5.ts` builds and is exported, but has no dedicated
  behavior test or frozen Rust/TypeScript V5 signing/ID fixture yet;
- `webc-proof` currently owns only `IndexedMerkleProofV1`; checkpoint,
  authority-transition, finalized-transaction proof, and browser parity remain;
- `ChainStore` still uses schema 1 apart from the bounded codec; lifecycle
  schema 2, migration, pending/finalized indexes, and atomic lifecycle batches
  remain;
- V5 validation/preparation, typed receipts/events, two-level execution,
  mempool/runtime/V2 API activation, and all end-to-end acceptance tests remain;
- no STARK dependency, prover, or verifier has been started, as required before
  Phase 5.5.

Exact continuation sequence:

1. Start from the current clean `origin/codex/transaction-system` (its last code
   checkpoint is `ee25016` followed by this docs-only handoff), then re-run
   `git status`, `git log`, and the required-document protocol. Do not continue
   directly on the three old agent branches: their tips (`bc1e75f`, `a5cd93b`,
   `e3e417d`) are already merged. Fast-forward an old worktree to the goal branch
   and create a new `codex/tx-*` branch, or create a fresh verified
   worktree/branch from `origin/codex/transaction-system`.
2. Add one immutable V5 vector to the inline Rust transaction tests and a new
   TypeScript V5 test. Freeze canonical signing bytes, signature, complete JSON,
   transaction ID, action digest, and sponsored-use bindings; keep every V4
   vector byte unchanged. Commit, test, and push this independently.
3. Add focused V1 receipt/event/index wrapper and leaf-hashing modules in
   `webc-chain`, including fee reconciliation, position/ID binding, failed-event
   prohibition, equal transaction/receipt counts, and Rust/TypeScript vectors.
4. Refactor the existing native-operation transition behind one reusable
   action executor, then add `ValidatedTransaction`, `PreparedTransaction`, and
   the parent fee/nonce/sponsor plus child action/event overlay. Preserve V4
   behavior until protocol-2 activation and test success, chargeable failure,
   rollback, cancel, sponsor replay/budget/revocation, access-prefix, fee, nonce,
   supply, and a failed transaction followed by an unrelated success.
5. Only after those chain interfaces are stable, implement storage schema 2 and
   its resumable migration, then V5 mempool/lifecycle/runtime/V2 HTTP/WebSocket
   consumers. In parallel where file ownership is disjoint, implement the V4
   header/authority/checkpoint/finalized-proof chain and browser verifier.
6. Update this checkpoint after every merged milestone. Update global
   `implementation-status.md` and `continuation-guide.md` only during the final
   main integration, exactly as the goal-branch rule above requires.

No owner decision is pending for these steps. Technical choices remain delegated
and must be recorded in this decision log or a superseding ADR rather than chat.

## Partial blockers and owner-reserved decisions

A policy conflict or missing owner decision does not stop the whole goal by
default. Isolate and document the blocked part, choose a reversible interface or
safe disabled default where allowed, and continue every independent task,
test, refactor, proof, or integration step that still makes meaningful progress.
Stop only when all remaining goal work truly depends on the same unresolved
owner decision or external condition, safe alternatives are exhausted, and no
additional in-scope development can be completed. Report the exact dependency
and completed surrounding work at that point.

## User decisions for this objective

None remain. The checkpoint source direction was the only owner-owned trust
choice for this transaction/light-client objective, and it is approved as a
reviewable direction. Agents autonomously choose libraries, modules, formats,
limits, algorithms, tests, and tuning, then record what and why. If work reaches
monetary policy, production-bridge trust, governance/emergency power, or another
owner-reserved boundary, follow the partial-blocker rule above: isolate it and
continue everything independent before considering a stop.

## Goal prompt for a fresh session

> 목표: `docs/transaction-system-plan.md`의 WEBC 트랜잭션 시스템을 완료한다.
>
> 시작 전에 `AGENTS.md`와 필수 연결 문서, Git 상태, 위 계획서를 모두
> 읽는다. 개발은 `codex/transaction-system`에서만 하고, 필요할 때만
> 서브에이전트와 실제 worktree를 사용한다. 기존 WEBC 모듈과 유지보수되는
> Apache-2.0 호환 오픈소스를 우선하며 Sui·Solana의 공식 구현도 비교
> 자료로 활용한다. 코드는 모듈형·버전형·교체 가능하게 만들고 필수 주석,
> 적대적 테스트, 계획서의 완료 조건을 지킨다.
>
> 기술 선택의 이유·대안·호환성·근거는 채팅이 아니라 계획서의 결정 기록
> 또는 ADR에 남긴다. 사용량이나 세션이 끝나도 잃지 않도록 복구 가능한
> 단계마다 작업 브랜치에 커밋하고 즉시 푸시한다. 일부 정책 문제가
> 생겨도 독립적인 작업을 계속하고, 모든 남은 작업이 같은 문제에 막혀
> 더 진행할 수 없을 때만 멈춘다. Phase 5.5 전에는 실제 STARK 백엔드를
> 시작하지 않는다. 완료 후 최신 `main`을 작업 브랜치에 병합해 전체
> 검증하고, 강제 푸시나 기록 재작성 없이 최신 `main`에 통합한다.
