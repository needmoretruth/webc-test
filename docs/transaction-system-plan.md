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

Changed: [ADR-0016](adr/0016-transaction-lifecycle-and-finalized-proofs.md)
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
were reviewed at the revisions and Apache-2.0 license links pinned in ADR-0016;
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

### 2026-07-18 — frozen V5 cross-language vectors and default-lane parity fix

Changed: added immutable Rust inline vectors
(`sender_paid_transfer_has_frozen_cross_language_v5_vector`,
`scoped_sponsor_has_frozen_cross_language_v5_vector`) and a new TypeScript test
(`sdk/webc-js/src/transaction-v5.test.ts`) that freeze the canonical sender and
sponsor signing bytes, the deterministic Ed25519 signatures, the complete signed
JSON, the transaction ID, the action-program digest, the fee-bid digest, the
sponsor-grant digest, and the sponsor-use digest for a sender-paid transfer and a
scoped-sponsor transfer. Rust is the reference generator; TypeScript reproduces
every byte and verifies the exact Rust signatures. Also fixed a TypeScript-only
V5 validation divergence: `validateAuthorization` rejected the all-zero DEFAULT
authorization lane that Rust (`AuthorizationLaneId::DEFAULT = Hash256::ZERO`) and
V4 both accept.

Why: without a frozen cross-language fixture the Rust node and the browser SDK
could silently diverge on the signed wire, so a transaction would verify in one
language and fail in the other. The default-lane divergence would have made the
browser SDK reject the most common (default-lane) transaction; freezing the
vector is what exposed it. The transaction ID is a domain-separated hash over the
complete JSON and the signature covers the canonical signing bytes, so freezing
those two values cryptographically freezes the whole wire.

Reused: existing `webc_chain::transaction_v5`, `webc-crypto` Ed25519
(deterministic per RFC 8032), the shared canonical JSON encoder, and the browser
`canonical`/`transaction-v5` modules. No new dependency or crypto primitive.

Rejected: choosing a non-default authorization lane for the fixture to dodge the
TypeScript bug (would hide a real parity defect); freezing only a hash instead of
the human-readable canonical JSON (less debuggable); re-signing in TypeScript
(the V4 pattern verifies the Rust signature instead, which also proves byte
parity).

Compatibility: additive and test-only in Rust; no protocol-version bump.
`CURRENT_PROTOCOL_VERSION` stays 1 and every V4 vector is byte-unchanged. The
TypeScript change only widens acceptance to match Rust; it rejects nothing Rust
accepts.

Proof: `cargo fmt --check`, `cargo clippy -p webc-chain --all-targets -- -D
warnings`, `cargo test -p webc-chain` (185 passed), and `pnpm check` (84 webc-js
+ 3 webc-widget tests, builds, and documentation links) all passed on 2026-07-18.

Review status: accepted implementation direction; the frozen vectors are
consensus-critical and immutable without a coordinated protocol-version bump.

Known follow-up (same class, not yet exercised): TypeScript `validateSponsorGrant`
still requires a non-zero `payer_lane`, while Rust imposes no such bound and a
sponsor paying from its own default lane is legitimate. No current caller
exercises a zero payer lane, so this is recorded here to be fixed with a test
when the sponsor lifecycle lands rather than changed without coverage now.

### 2026-07-19 —position-bound V1 receipts and transaction roots

Changed: added Rust and browser V1 receipt/event/index types, exact fee-summary
reconciliation, ordered event checks, domain-separated receipt/event/transaction
leaves, shared Merkle roots, and one-to-one binding to the signed V5 sender,
fee payer/lane, fee bid, action count, transaction identity, height, and index.

Why: a receipt root is only evidence of execution when every leaf is tied to
the exact signed transaction and ordered block slot. Local receipt validation
alone would allow a structurally valid result to be paired with another sender,
sponsor, fee bid, or action program.

Reused: `FeeSummaryV1`, `TransactionV5`/browser V5 wire validation, canonical
JSON, address/hex codecs, and `webc_crypto::merkle_root`/`WEBC_MERKLE_V1`. No
dependency or cryptographic primitive was added.

Rejected: hashing transaction IDs without positions (does not commit the block
slot); trusting derived fee fields (permits tampered charge/refund splits);
publishing partial events on failure (breaks action-overlay rollback); and a
browser-only Merkle convention (would make node roots unverifiable by clients).

Compatibility: additive while protocol version 2 remains inactive. V4 receipt
and header bytes are unchanged. The browser rejects unsafe numeric values inside
legacy native event bodies because JavaScript cannot reproduce such Rust JSON
exactly; future event schemas should replace remaining raw `u64` fields with
decimal-string wrappers.

Proof: frozen sender-paid canonical receipt, event digest, receipt digest,
receipt leaf, and transaction leaf match in Rust and TypeScript. Rust receipt
tests (6), strict `webc-chain` clippy, full `webc-chain` tests (191), and exact
pnpm 11.7.0 `pnpm check` (89 SDK + 3 widget tests, builds, and documentation
links) pass.

Review status: accepted implementation direction; frozen values require a
coordinated receipt-schema change to modify.

## Goal progress checkpoint

Implementation checkpoint on 2026-07-18: the isolated branch contains code
through `ee25016`; the paused-goal record below is a later docs-only handoff.
ADR-0016 and `4d54170` freeze the shared interfaces. `d25eb57` adds the
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

- `4d54170`: ADR-0016 shared lifecycle/proof interface freeze;
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

### Resumed milestone (2026-07-18): frozen V5 cross-language vectors

The owner resumed the goal on the same `codex/transaction-system` branch.
Completed continuation step 2: the immutable Rust/TypeScript V5 canonical
signing-bytes, deterministic signature, complete JSON, transaction ID,
action-program digest, fee-bid digest, and scoped-sponsor grant/use vectors are
frozen and pass in both languages, and the browser SDK's default-lane parity bug
is fixed (see the 2026-07-18 decision-log entry above). The focused gate passed:
`cargo fmt --check`, `cargo clippy -p webc-chain --all-targets -- -D warnings`,
`cargo test -p webc-chain` (185 passed), and `pnpm check` (84 webc-js + 3
webc-widget tests, builds, and documentation links).

Still not implemented and still material: the typed receipt/event/index wrapper
and leaf-hashing modules; the reusable action executor and the two-level
(parent fee/nonce/sponsor plus child action/event) V5 execution overlay with
success, chargeable-failure, rollback, cancel, and sponsor replay/budget/
revocation coverage; storage schema 2 and its resumable migration; the V5
mempool/runtime/V2 HTTP/WebSocket consumers; finalized checkpoint proofs and the
browser verifier; and the restart, three-validator, fuzz, dependency, and full
workspace/main integration gates. The real STARK backend remains correctly
deferred until Phase 5.5.

Exact next item: add the focused V1 receipt/event/index wrapper and leaf-hashing
modules in `webc-chain` (continuation step 3) — fee reconciliation, position/ID
binding, the failed-event prohibition, equal transaction/receipt counts, and
frozen Rust/TypeScript vectors — before any node lifecycle consumer.

### Resumed milestone (2026-07-19): typed V1 receipts and ordered roots

Completed continuation step 3 in Rust and TypeScript: strict receipt/event/index
wrappers, fee reconciliation, sender/payer/signed-bid/action/position/identity
binding, domain-separated leaves, ordered roots, and the frozen sender-paid
cross-language vector. The gate passed 6 focused Rust receipt tests, strict
`webc-chain` clippy, all 191 `webc-chain` tests, and exact pnpm 11.7.0
`pnpm check` (89 SDK + 3 widget tests, builds, and documentation links).

Still material: the reusable action executor and two-level execution overlay;
storage schema 2 and migration; lifecycle/mempool/runtime/V2 API consumers;
finalized checkpoint proofs and browser verifier; restart, multi-validator,
fuzz, dependency, full workspace, and final-main integration gates.

Exact next item: continuation step 4 —refactor the existing native transition
behind one reusable action executor, then implement the parent fee/nonce/sponsor
and child action/event overlay with atomic success, chargeable failure,
rollback, cancellation, and sponsor lifecycle coverage.

### Partial step 4 checkpoint (2026-07-19): V5 overlays and object actions

Continuation step 4 is materially advanced but is not complete. The branch now
has stateless `ValidatedTransactionV1`, pure snapshot-bound
`PreparedTransactionV1`, durable sponsor grant replay/budget/revocation state,
sender/sponsor/session fee authority, and a two-level executor. The parent
overlay commits nonce, actual fee, sponsor use, and session fee spend after an
included action failure; the child overlay commits ordered action state/events
only on success. Tests cover cancellation, default and non-default fee lanes,
sponsored failure, session principal-versus-fee budgets, unused failure suffixes,
and a failed transaction followed by an unrelated success.

Commit `8b29cea` extends the reusable native action boundary beyond transfers:
V4 and V5 now share the exact object create, mutate, and ownership-transfer
transitions. Ordered object actions commit typed events on success, while an
object version failure produces the stable chargeable receipt code and discards
all child object state and events. The focused gate passed all 16 execution V1
tests, strict all-target `webc-chain` clippy, formatting, and all 209
`webc-chain` tests.

Commits `2d60cc3`, `436baae`, `1f2e6a0`, and `84ef04e` extend that checkpoint.
V5 now shares V4 transitions for fee-lane open/fund, validator/delegator reward
claims, matured unbonding claims, and first authorization-policy installation.
Statically invalid lane selection, zero deposits, oversized object data, and an
invalid recovery root fail before signing or charging. Multi-action tests prove
that insufficient lane funding, a missing delegation, a duplicate matured
claim, and a duplicate policy install discard every prior child change and
event while preserving only parent fee/nonce accounting. The latest focused
gate passed 24 execution tests, strict all-target `webc-chain` clippy,
formatting, and all 218 `webc-chain` tests.

This does not activate protocol 2. Existing V4 execution remains the node path.
V5 currently supports transfers, owned-object operations, fee-lane management,
reward and matured-principal claims, authorization-policy installation, and
sponsor-grant revocation. It still rejects the remaining configuration-dependent
staking mutations, session/policy rotations, slashing, and bridge operations
before touching state. Step 4 therefore remains open until those V4 transitions
are extracted with their full chain-config, authorization, exact-access,
failure-classification, and rollback semantics.

Exact next item: add immutable chain configuration and the remaining signed
envelope fields to the shared execution context, then integrate validator
registration/delegation/undelegation/operator-exit as one staking group. Keep
statically invalid actions in the free validation or preparation layer; only
state preconditions that can change after admission may become chargeable
receipt failures. After every native variant is covered and the full step-4
gate passes, move to storage schema 2 and its resumable migration.

### Adversarial sponsorship checkpoint (2026-07-22)

Commit `2ba13f4` closes the signed pre-use revocation lifecycle without
activating protocol 2. A signed grant can be revoked before its first fee use;
the durable record authenticates its inclusive expiry; the state commitment
binds the complete grant book; and a derived, canonically ordered expiry index
can prune at most 256 expired records per protocol-2 block after activation. The
protocol-1 block path never calls this cleanup. The old per-expiry admission cap
was removed because it created a hidden global conflict and allowed one sender
to squat an expiry bucket. Instead, every sponsored transaction and every
signed revocation action reserves 100,000 deterministic bookkeeping units.
With the current 2,000,000-unit default block limit this admits at most 20 new
records per block, while the 4,096-block signed-revocation lookahead bounds the
default live set at approximately 163,840 records.

The same commit preflights every sparse grant-book write before any base state
mutation, replaces expired identities without prepare/execute divergence, and
keeps Rust and TypeScript sender-first validation, signer ordering, identity
conflict detection, and unit accounting aligned. Commit `8b92a75` freezes the
adversarial boundaries: exact duplicate revocations remain valid and are
verified once, cross-source fee/action identity conflicts fail closed, failed
child actions discard revocations while the outer fee grant still advances,
and sponsored cancellation charges the exact static units. The focused gate
passed formatting, strict all-target `webc-chain` clippy, all 240
`webc-chain` tests, Rust documentation, and `pnpm check` (95 SDK and 3 widget
tests plus builds and documentation links).

Protocol 2 remains inactive. Activation is gated on both of the following:

1. enforce a fail-closed relationship between the configured block-unit policy
   and pruning capacity (recommended invariant: pruning capacity is at least
   four times the maximum per-block materialization count; the current defaults
   provide 12.8 times headroom); and
2. run a release-build benchmark at 163,840 live grant records covering state
   cloning, state-root computation, block execution latency, and peak resident
   memory. Do not raise the lookahead or block-unit limit without repeating it.

Exact next item: replace V5 matured-unbonding claims' full global
`UnbondingQueue` capture and child clone with a request-scoped delta journal.
The journal must preserve the existing global conflict key and state-root
semantics, validate all dirty entries before any base mutation, apply only after
validation succeeds, and prove bounded overlay size for successful and missing
request IDs against a large unrelated queue.

### Request-scoped unbonding checkpoint (2026-07-22)

Commit `6865eb2` completes that exact item. V5 execution no longer copies the
global `UnbondingQueue` into its sparse parent and child states. It captures only
the fixed-size owner, validator, kind, request ID, withdrawable, and claimed
fields for the at-most-32 signed action IDs. Ordered duplicate claims share one
virtual record, successful execution validates every dirty snapshot before any
sponsor/account mutation, and final commit clones and replaces only the claimed
requests so unrelated queued/cooling topology is preserved. Chargeable action
failure selects the unchanged parent journal. V4 continues to use the direct
queue transition.

The logical `StateKey::unbonding_queue(validator)` and its
`GlobalUnbondingQueue` scheduler conflict are unchanged; only the physical copy
strategy changed. Tests prove direct-transition and state-root parity, stale
multi-request validation before mutation, duplicate/missing/wrong-owner/
wrong-validator/zero/overflow/corrupt-ID behavior, later-action rollback, and
both successful and missing claims against 1,025 live requests. In those large
queue tests the sparse `ChainState` contains zero queue requests and the journal
contains exactly one entry. An independent final diff review reported no
actionable finding. The focused gate passed formatting, strict all-target
`webc-chain` clippy, all 246 `webc-chain` tests, and Rust documentation.

Exact next item: resume the still-open step-4 native transition set. Introduce
an explicit immutable `ChainConfig` execution context with no production
default fallback, then extract and integrate validator registration,
delegation, undelegation, and operator unstaking as one reviewed staking group.
Request-creating staking actions must use a bounded queue delta rather than
reintroducing a global queue clone. Preserve V4 behavior and classify only
state preconditions that can change after admission as chargeable failures.

### Latest-main integration checkpoint (2026-07-22)

The transaction branch now integrates `origin/main` at `ef1fb9d8913d`, including
the V20 state commitment, the complete current native operation set, localized
fees, storage deposits, native token/NFT/governance/DEX/oracle/agent systems,
the WASM runtime, Weft, and the latest bounded/compressed storage stack. Conflict
resolution preserves protocol 1 byte-for-byte instead of silently activating
transaction-V5 state:

- an empty protocol-1 state is pinned to the V20 root
  `ddb1a0d463e7ef12b73b2408c344e9b7799570b16f06b7cb7f83727c9644127f`;
- protocol 1 rejects any non-empty V5 grant book before block commitment and
  does not run V5 grant pruning;
- V5 preparation requires a protocol-2 `ChainState`; protocol 2 uses the V21
  commitment and authenticates the grant subtree;
- the original protocol-1 state-key fixture remains
  `86b42dee5ac735a7435d64b12b3f6f958e90c03ac03173ef6f98ec88169c9e20`,
  while the additive sponsor key has its own Rust/TypeScript fixture;
- all main `Event` variants keep their existing binary discriminants and the V5
  sponsor-revocation event is appended last;
- schema-1 at-rest records use main's variable-length integer format through the
  transaction branch's kind-specific bounded decoder, with trailing bytes and
  hostile length prefixes rejected before unbounded work; and
- the transaction lifecycle ADR is renumbered from the colliding ADR-0012 to
  ADR-0016; main's ADR-0012 through ADR-0015 remain unchanged.

Main added refundable storage-deposit economics after the old V5 object helper
was written. Reusing that helper would let protocol 2 create or resize objects
without locking the required deposit. `CreateObject` and `MutateObject` are
therefore explicitly rejected at structural validation until V5 receives an
immutable `ChainConfig`/storage-pricing snapshot and its sparse overlay commits
the exact `storage_deposits` delta. `TransferObject` remains enabled because it
preserves the existing deposit unchanged. New main state-key families are also
explicitly rejected by the sparse overlay until their state adapters exist; no
wildcard match can accidentally enable them.

Integration verification passed: `cargo fmt --check`, workspace Clippy with
warnings denied, the complete Rust workspace test suite, workspace rustdoc with
warnings denied, `pnpm check`, and the deterministic node demo all succeed. The
focused coverage includes all 501 `webc-chain` unit tests, the native
supply-invariant integration test, eight parallel-execution integration tests,
48 `webc-storage` tests, 257 JavaScript SDK tests, and three widget tests. The
rustdoc gate also caught and fixed invalid intra-doc links in the newly imported
Weft skeleton before this integration commit was accepted.

Exact next item after the integration commit: inject the immutable chain config
into V5 preparation/execution, upgrade the shared object create/mutate
transitions to main's deposit debit/refund semantics, add signed account access
and an additive `storage_deposits` sparse delta, then restore ordered object
success/failure/restart/property coverage. After that, resume the remaining
step-4 native operation groups against the now-current main types.

### V5 refundable object-deposit checkpoint (2026-07-22)

The post-integration object blocker is resolved without a protocol-1 behavior
fork. V4 and V5 now call the same focused create, mutate, transfer, and delete
transitions. V5 preparation and execution both require an explicit immutable
`ChainConfig`; preparation fails closed unless the config, state, and signed
transaction identify the same chain and protocol. The storage-pricing value is
part of the preparation snapshot, so a changed price rejects execution before
fee, nonce, object, or account mutation. Invalid refund basis points are rejected
both at genesis construction and V5 preparation.

Create/grow moves native units from the current owner's main account into the
object's recorded deposit and the aggregate `storage_deposits` bucket. Shrink
returns the exact difference. Delete uses the recorded deposit, returns the
configured share to the current owner, and burns the remainder. The sparse V5
overlay captures the aggregate bucket and commits a full-`u128` directional
increase/decrease delta. All scalar merges are checked before any base record is
changed. No global storage conflict key was added: the object key owns the delta,
the account key protects liquid funding, and independent object deltas remain
commutative and parallelizable.

Adversarial coverage proves create→grow→shrink→delete balance and event
semantics, restart/state-root stability, insufficient-deposit charging with no
partial object, later-action rollback of all child deposits/events, cross-chain
API misuse rejection, immutable-price stale rejection, independent mixed-sign
overlay merge order, and stale-decrease failure before any account commit. The
shared randomized native-operation invariant now also requires
`storage_deposits == sum(live object.deposit)`, which catches bucket/leaf drift
that aggregate supply reconciliation alone could miss. The focused gate passes
strict all-target `webc-chain` Clippy, all 511 unit tests, the randomized native
supply test, and all eight sharded-parallel tests. The complete workspace gate
also passes formatting, warnings-denied all-target Clippy, every Rust test,
warnings-denied rustdoc, and the deterministic node demo.

Exact next item: extract and integrate validator registration, delegation,
undelegation, and operator unstaking as one reviewed V5 staking group. Preserve
the current V4 `ChainConfig` semantics and exact access lists. Request-creating
actions must use a bounded additive/request journal rather than cloning the
global `UnbondingQueue`; stable state races are chargeable receipt failures,
while arithmetic, configuration, and access violations remain block errors.

### Bounded staking-request journal checkpoint (2026-07-22)

The queue and transition foundation for the V5 staking group is complete. A
new request journal captures only the queued totals named by at most 32 signed
actions plus the monotonic request cursor; it never clones unrelated requests or
the global FIFO. Ordered actions see earlier staged exits, IDs remain identical
to direct queue execution, and commit validates every consulted total, cursor,
destination ID, and reconstructed staged total before changing any base record.
Successful appends preserve direct-queue serialization and state-root semantics;
stale totals/cursors, capacity misuse, and full-range arithmetic failures leave
both journal and base byte-for-byte unchanged. Coverage includes 1,025 unrelated
requests, mixed operator/delegation appends, restart equivalence, and the 32-action
bound.

V4 registration, delegation, undelegation, and operator-exit logic now call four
focused shared transitions. This also fixes a pre-existing exact-access bug:
registration and delegation paid from a non-default authorization lane declared
the sender's main account but failed to record that write, so successful state
changes were rejected as unused access. The regression test proves both actions
now consume the main account while fee and nonce remain isolated in their lanes.
The V5 sparse overlay already carries and atomically preflights the new request
journal alongside the request-scoped claim journal. The focused gate passes
formatting, strict all-target `webc-chain` Clippy, all 516 unit tests, the native
supply-invariant test, all eight sharded-parallel tests, and Rust documentation.

Legacy native staking operations deliberately remain unsupported in V5 at this
checkpoint. `docs/decision-record.md` requires post-quantum-root authorization
for staking control, but the protocol-1 `Operation` variants carry no such proof;
enabling them unchanged would reproduce a known policy violation in the new
transaction system.

Exact next item: add a versioned V5 staking-control action format carrying a
bounded post-quantum root reveal and a domain-separated authorization message
bound to chain, owner, policy revision, default lane, transaction nonce, action
index, and exact staking payload. Validate immutable staking configuration and
snapshot it across preparation/execution, update the frozen Rust/TypeScript wire
fixtures, then integrate the four shared transitions with chargeable state-race
failures and full rollback/restart/supply coverage. Do not enable the legacy
native staking variants as a shortcut.

### Post-quantum staking authorization format checkpoint (2026-07-22)

The recovery-signer boundary for staking control is frozen before execution is
enabled. Rust and TypeScript now share a narrow `StakingActionV1` payload with no
legacy bootstrap flag and construct byte-identical canonical authorization
messages. The message binds protocol version 2, chain, owner, exact policy
revision, default lane, transaction nonce, a bounded zero-based action-program
index, and the complete staking payload under
`WEBC_STAKING_CONTROL_AUTHORIZATION_V1`. A fixed Rust/TypeScript JSON and SHA-256
vector prevents silent signer drift. Both implementations reject non-default
lanes, out-of-range indices, zero amounts, and commission above 10,000 before a
recovery signer is invoked. The SDK also now mirrors the already-active Rust V5
object-delete operation in its operation type, namespace matching, validation,
and 20,000-unit pricing.

This checkpoint does not yet add `StakingControl` to the executable action
envelope, so no new staking path is admitted from this format-only change.

The same review found and closed a P0 sponsorship-policy gap before staking
activation: V5 had accepted any exactly digested action program, whereas the
confirmed launch rule permits sponsorship only for a simple native transfer.
Rust and TypeScript now share a fail-closed predicate requiring exactly one
`Native(Transfer)` action. Sponsor-use builders and hostile-wire validation
reject cancellations, multi-action programs, objects, policy/staking controls,
and grant management before state lookup or fee/nonce mutation. Regression
coverage proves a sponsored cancellation leaves chain state byte-for-byte
unchanged while a single sponsored transfer, including its chargeable failure
path, still advances the bounded grant accounting correctly.

Exact next item: add the full action plus bounded root reveal to Rust and
TypeScript together, reject sponsorship and non-default lanes structurally,
verify the current installed root during free preparation, snapshot validated
staking configuration, and connect the four shared transitions with atomic
rollback, restart, and supply-invariant tests. The legacy native staking forms
must remain unsupported.

### Root-authorized V5 staking execution checkpoint (2026-07-27)

The dedicated `StakingControl` envelope is now active end to end without
activating any legacy Ed25519-only staking operation. Rust and TypeScript share
the strict action/reveal shape, 100,000-unit ML-DSA verification price plus the
underlying transition price, default-lane restriction, exact-transfer-only
sponsorship exclusion, bounded reveal fields, and frozen canonical action JSON
and SHA-256 vector. The active account key must still sign the outer transaction;
session keys and accounts without an installed policy fail during free
preparation.

Preparation validates the immutable staking configuration, checks current
policy revision and nonce, then verifies every root signature over the exact
chain, owner, revision, default lane, nonce, action index, and payload. It
snapshots the complete staking configuration and current root. Execution checks
both snapshots before any reservation or nonce mutation and re-prepares against
the current logical state. Invalid/misbound root signatures and below-threshold
static payloads are free preparation failures; a policy-root rotation or valid
configuration change after preparation is a stale-preparation block error.

Registration, delegation, undelegation, and operator unstaking call the same
focused transitions as V4. Request creation remains in the bounded additive
journal rather than cloning the global queue. Stable user-state races are
chargeable receipt preconditions, while configuration, arithmetic, access, and
journal invariant failures remain block errors. Coverage proves all four success
paths, current-root/message binding, missing-policy and session-key rejection,
configuration/root races, multi-action child rollback with parent fee/nonce
commit, restart/state-root equality, and native supply reconciliation. The
focused gate passes strict all-target Clippy, 522 chain unit tests, the randomized
native supply invariant, eight parallel-execution tests, and the SDK/widget gate.

Exact next item: replace the schema-1 at-rest transaction state with an explicit
schema-2 record and bounded migration before V5 reaches the node/mempool API.
`sponsor_grants` was added to the middle of the bincode `ChainState` layout, so a
defaulted field alone is not a safe compatibility argument. The migration must
preserve protocol-1 records byte-for-byte, persist protocol-2 grant state, reject
hostile/trailing data before unbounded work, and prove crash/restart behavior.
Then integrate V5 lifecycle records into the mempool/runtime/API and resume the
finalized proof/browser-verifier track.

### Atomic storage schema-2 checkpoint (2026-07-27)

The at-rest ambiguity is closed before V5 reaches the node. `ChainStore` now
stamps schema 2 and stores each current `ChainState` inside an explicit
`WEBCSTV2`/record-version-2 envelope. Encoding borrows the state instead of
cloning a potentially large snapshot. Every read still passes through the
kind-specific 256 MiB outer bound, active bincode limit, strict trailing-byte
rejection, and the physical zstd codec.

Opening schema 1 performs one bounded, one-way migration. The compatibility
type exactly matches the 54 field names, types, and order in the final
`origin/main` schema-1 `ChainState`; a frozen old-record hash catches drift. Only
protocol 1 is accepted through that adapter, and its V5 grant book is created
empty. The old state is decoded, its chain and tip root are verified, the old
buffer is released, and the schema-2 state plus schema marker are committed in
one redb/KV transaction. Because schema 1 retained only the latest snapshot,
migration work is constant with chain age and needs no partial-progress cursor.
Any malformed/trailing/oversized record, wrong chain/root, encode failure, or
database failure leaves the schema-1 marker and bytes untouched for a safe
retry.

Tests prove memory and redb migration, unchanged protocol-1 state root, frozen
legacy bytes, failure atomicity across reopen, rejection of unwrapped/wrong-magic
schema-2 records, and persistence of a real non-empty protocol-2 sponsor-grant
book across restart with a stable V21 root. Strict storage Clippy and all 53
storage tests pass.

Exact next item: add the protocol-2 pending/finalized transaction lifecycle
records and atomic indexes, then integrate V5 admission/replacement/expiry into
the mempool and node runtime with versioned HTTP/WebSocket APIs. The V4 paths
must remain byte-compatible and active under protocol 1 while protocol 2 is
explicitly configured in tests/devnet fixtures.

### Durable pending-lifecycle checkpoint (2026-07-27)

The first storage-lifecycle slice is implemented without coupling storage to
mempool policy. Schema 2 reserves distinct physical tables for the pending slot
index, pending V5 bytes, lifecycle projection, finalized position index, and
finalized receipt index. Stable table tags 0 through 6 remain unchanged.

`webc-storage::lifecycle` now owns versioned records for the exact
`(sender, authorization lane, nonce)` slot, complete signed V5 transaction,
canonical transaction ID, local admission timestamp, local observation,
separate consensus fact, and durable monotonically increasing sequence. JSON
exposes timestamp/sequence `u64` values as strict decimal strings. Pending
record reads repeat the bounded V5 signature/ID/slot checks and cross-check the
table key and slot index; a record for another chain is rejected before writing.

Admission commits the transaction, slot index, new lifecycle, optional replaced
lifecycle/deletion, and sequence marker in one `KvStore` batch. Duplicate IDs
are idempotent. Expiry/drop removal deletes both pending indexes while retaining
the lifecycle. A merely proposed `Included` observation deliberately retains the
pending bytes because the candidate may fail to finalize. Redb reopen proves the
transaction bytes, slot, lifecycle, and sequence survive restart. An injected
commit failure proves no partial index or sequence becomes visible. Strict
storage Clippy and all 62 storage tests pass.

Exact next item: add the finalized position/receipt record codecs and stage their
indexes, pending deletion, authoritative consensus fact, and sequence allocation
inside the same atomic batch as the finalized protocol-2 block/state/certificate/
tip commit. Do not model protocol 2 through the frozen protocol-1 `Block`
(V3 header plus V4 transactions);
introduce the explicit V4-header/V5-block storage boundary needed to keep legacy
protocol-1 blocks readable without reinterpretation.

The prerequisite block boundary is now frozen: `webc-chain::BlockHeaderV4`
uses `WEBC_BLOCK_HEADER_V4`, exact decimal-string wide integers, and separate
current/next finality-authority commitments, while `BlockV4` owns bounded V5
transactions, V1 receipts, and objective evidence. Validation checks collection
and 4 MiB byte caps, every sender/sponsor signature and signed height window,
transaction/receipt positional binding, duplicate IDs, and the three shared
roots. The old `Block` and `WEBC_BLOCK_HEADER_V3` are untouched. Rust and
TypeScript freeze the V4 header hash as
`9855e491949296206f38c03e12a5f4aa82ca332170d1e42bb9dc1dfab5bb9949`.

Exact next item remains the atomic finalized storage batch, now using this
explicit `BlockV4` boundary rather than extending or reinterpreting the legacy
container.

The V4 authority commitment is also concrete rather than caller-supplied opaque
data. `FinalityAuthoritySetV1` binds protocol, chain, decimal-string epoch,
strictly sorted validator IDs, distinct Ed25519 consensus keys, non-zero voting
power, and its checked exact total under `WEBC_FINALITY_AUTHORITY_SET_V1`.
Hostile JSON is bounded to 8 MiB and 16,384 entries before retention. It converts
only after validation to the existing `ValidatorSet` certificate verifier. Rust
and TypeScript freeze commitment
`4361528bc72a2ea4e098119168f5eec6c5087d2958d48c2bccd26d0de2651899`.
This closes the prerequisite for checking a V4 header's current authority root
before accepting its finality certificate in the atomic storage batch.

### Atomic finalized-lifecycle checkpoint (2026-07-27)

Commit `db55f65` completes the protocol-2 storage finalization unit. One backend
transaction now persists the validated V4 block and hash index, latest schema-2
state, immutable current/next authority sets, mandatory exact-block finality
certificate, consensus-WAL deletion, pending-slot/transaction deletions,
finalized transaction-position and complete V1 receipt indexes, authoritative
consensus lifecycle facts, lifecycle sequence, and new tip. The frozen
protocol-1 `Block` path now rejects protocol 2 rather than reinterpreting it.

The failure coverage is adversarial rather than happy-path only: a redb reopen
restores the block, state, certificate, authority set, transaction, receipt,
position, lifecycle, and sequence; a certified older transaction displaces a
conflicting local replacement without letting the local observation override
finality; invalid certificate and authority commitments leave the pending state
unchanged; an injected backend failure exposes none of the staged block/tip/
index writes; an epoch's authority set cannot be rewritten; and one block cannot
finalize two transaction IDs for the same `(sender, lane, nonce)` slot. Strict
storage Clippy, all 67 storage tests, focused restart/rollback tests, Rust
formatting, and storage documentation generation pass.

Exact next item: integrate the durable V5 records with a protocol-2 mempool and
the single `NodeRuntime` actor/handle boundary from ADR-0016. Admission must
prepare/validate against one state view, durably commit before acknowledging or
gossiping, rebuild bounded in-memory indexes after restart, apply deterministic
replacement/expiry/eviction policy, and keep the protocol-1 runtime behavior
unchanged. Then expose the resulting lifecycle through the bounded V2 HTTP and
WebSocket APIs before starting finalized checkpoint/proof/browser verification.

The first half of that item is durable in commit `ec8e84f`.
`webc-node::V5Mempool` is a separate protocol-2 policy boundary, leaving the
frozen V4 pool unchanged. Pure admission plans enforce the 64 MiB canonical-byte
budget, 8,192 global count, 64 per sender/lane, future nonce/start bounds, and
10% replacement bump before constructing a pending record. Immediately runnable
transactions pass full state preparation; bounded future nonces are parked and
cannot evict a runnable transaction regardless of their nominal bid. Capacity
eviction is deterministic, exact duplicates are idempotent, expiry plans no
memory mutation before durable deletion, and restart reconstruction checks
signatures, IDs, slots, record version, duplicates, bytes, and every cap. Strict
node Clippy, all 66 node-library tests, 21 node integration/binary tests, Rust
formatting, and node documentation generation pass.

Exact next item is the persist-before-memory runtime half: extend one storage
batch to support capacity eviction plus insertion, then add the bounded
`NodeRuntime` actor and cloneable `NodeHandle`. The actor must recover durable
records, revalidate or durably drop them before re-gossip, commit admission/
replacement/eviction before applying the corresponding `V5Mempool` plan, and
prove queue backpressure plus database-failure rollback.

### Protocol-2 single-owner runtime checkpoint (2026-07-27)

Commits `8053d80` and `4acaaf8` complete that runtime half. A protocol-2
`NodeRuntime` now exclusively owns `Node` plus `V5Mempool` behind a bounded
Tokio mailbox and cloneable `NodeHandle`. Submission plans against one committed
state view, writes queued/replaced/capacity-evicted lifecycle and pending records
first, and only then applies the infallible memory plan. Exact duplicates are
durably idempotent, a full mailbox returns typed backpressure immediately, and a
failed backend commit leaves the in-memory pool unchanged and accepts a later
retry. Expiry follows the same disk-before-memory order.

Restart scans at most the storage cap, deterministically revalidates records in
transaction-ID order, retains the original admission timestamp, durably expires
TTL-old records, records state/policy rejection as `RevalidationFailed`, and
applies the current count/byte policy without re-gossiping a rejected record.
Tightening capacity keeps the runnability-aware eviction rule. Protocol-2 genesis
uses a separate constructor but shares the existing allocation, staking,
configuration, supply-pin, and supply-invariant implementation; legacy V3 block
methods now fail closed rather than writing their format into a protocol-2 store.

The runtime tests cover durable/idempotent submission and lifecycle query,
atomic replacement, durable runnable-over-parked eviction, injected storage
failure with unchanged memory and successful retry, real redb close/reopen and
durable TTL cleanup, and mailbox saturation. Strict Clippy passed for the touched
chain/storage/node crates. All 530 chain unit tests plus invariant/sharded tests,
all 73 node-library tests plus 21 binary/integration tests, and Rustdoc generation
for chain/storage/node passed.

Exact next item: expose this one runtime owner through bounded `/v2/transactions`
submission and lifecycle/receipt query routes plus a replayable protocol-2
WebSocket lifecycle stream. The API must decode with existing V5 hostile-input
bounds, preserve typed public errors without leaking storage details, reserve
request slots before large bodies, and never hold a second `Node`/mempool copy.
Then wire gossip/proposal/finalization callbacks through the same handle before
starting finalized checkpoint/proof/browser verification.

### V2 transport, gossip, and certified V4 runtime checkpoint (2026-07-27)

Commits `5cf0e35`, `a2ea41e`, and `3c058f4` expose the single actor-owned V5
lifecycle without creating a second node or mempool. The bounded V2 surface now
supports durable submission, lifecycle and finalized-receipt queries, and an
explicit-ID WebSocket stream with actor-consistent snapshots, monotonic durable
sequences, lag/resnapshot signaling, message/connection/subscription limits,
pre-body submission slots, redacted correlated errors, and a bounded socket-IP
token bucket that ignores spoofable forwarding headers. Successful durable
admission is gossiped as a versioned authenticated network message; a real
two-node HTTP-to-TCP-to-remote-runtime test passes. Legacy consumers ignore V5
without reinterpreting it.

Commits `09aaee5`, `97afba3`, and `8714660` close the next execution/finality
unit. One protocol-2 block transition now validates metadata and authority
domains, applies objective evidence before user work, prunes expired grant state,
executes ordered V5 transactions into position-bound V1 receipts, treats a
chargeable action failure as an includable receipt, finishes fee/epoch state,
checks supply conservation, derives the successor authority snapshot from
post-state, and constructs every V4 root on a whole-block overlay. Import uses
the same transition and adopts nothing unless the reconstructed block matches
exactly. Tests cover later-invalid rollback, tampered roots, duplicate IDs,
non-contiguous height, stale time, outsider proposer, byte limits, epoch
transition, failed-then-successful execution, and producer/importer equality.

`V5Mempool` now selects deterministic, gap-free sender/lane runs by effective
fee while simulating preparation and ordered execution on a private state clone.
This lets a chargeable failure consume its nonce so the next transaction remains
eligible, but a stale head cannot poison unrelated lanes. `NodeRuntime` builds
these candidates and atomically commits a mandatory certificate, block,
post-state, current/next authority sets, receipt/index/lifecycle records, pending
deletions, WAL cleanup, and tip before changing live state or pending memory. An
injected storage failure leaves height and memory untouched and the identical
certificate retries successfully; an externally finalized transaction removes a
different local occupant of the same slot only after disk commit. Strict
chain/node Clippy passes, all 535 chain tests plus supply/parallel integration
tests pass, and all 79 node-library, 9 binary, and 18 node integration tests pass.

This is not yet an end-to-end consensus claim. The active consensus proposal,
vote driver, and state-sync messages still carry the frozen legacy `Block`, so
they cannot transport or certify `BlockV4`; production `webc-node run` also does
not yet start the protocol-2 actor/API/gossip/finality stack. Protocol-2 action
programs currently use the one global V1 receipt base rate; localized
multi-namespace pricing needs an explicit versioned rule and must not be inferred
inside the current receipt. Finalized proof assembly and the browser verifier are
also still absent.

Exact next item: add distinct versioned protocol-2 proposal/state-sync network
messages carrying `BlockV4` plus the derived next authority set, and a V4
consensus driver that uses the existing pure BFT machine/WAL but routes candidate
build, proposal validity replay, and certified finalization exclusively through
`NodeHandle`. Reproduce malformed/oversized proposal bounds before allocation,
wrong authority commitments, invalid proposer/certificate, restart WAL replay,
storage retry, and a three-validator HTTP-to-gossip-to-consensus-to-finalized-
receipt flow before wiring the public run command. Never reinterpret the legacy
proposal bytes.

### Protocol-2 consensus and public-runtime checkpoint (2026-07-27)

Commits `454fe06`, `88fd46d`, `7f881cc`, `9aae82f`, `89609a2`, `afbcb66`,
and `3f34ef2` close the distinct protocol-2 consensus path without changing the
legacy wire format. Authenticated V4 proposals bind the chain, epoch, round,
scheduled proposer, current authority commitment, complete block, and derived
next authority set. Hostile outer and binary collection lengths are bounded
before allocation. V5 network frames carry separate V4 proposal and state-sync
variants, while the shared pure BFT state machine uses the protocol-2 signing
domain and preserves a locked value across reproposal. Every locally signed
proposal, prevote, and precommit is persisted in the existing bounded WAL before
broadcast; restart restores the lock and refuses to sign a conflicting value.

`NodeRuntime` remains the only state/mempool owner. Its actor commands build a
candidate, replay proposal validity against committed state, and atomically
finalize a certified V4 block. Commit `bd2dcf8` adds the asynchronous driver over
only `NodeHandle` plus authenticated gossip: it verifies peer identity and
signatures before replay accounting, deduplicates bounded rounds, synchronizes
certified missing blocks, and retries transient finalization failures. A real
three-validator TCP test submits V5 over HTTP, propagates it through V5 gossip,
runs V4 proposal/vote consensus, and observes the finalized V1 receipt.

Commit `3be828f` red-teams recovery rather than only the happy path. A real redb
restart in the middle of a height proves that the validator never emits a
conflicting signed message. Injected transient finalization I/O is retried and
survives; persistent I/O exits with a typed error after the bounded retry budget.
Commit `30d14a2` makes network rate limiting charge expanded work in 16 KiB
units using the greater encoded or declared-decoded frame size before hashing,
decompression, decoding, or reflooding. Locally compressed zstd frames declare
their content size, and an attacker hiding it is charged the full 8 MiB budget.

Commit `cb54931` exposes this stack through `webc-node run
--protocol2-genesis <path>` while leaving the no-flag legacy command unchanged.
The public process loads and validates the bounded protocol-2 genesis, starts one
redb actor, authenticated network, V4 driver, V2 transaction API, lifecycle
WebSocket, and `/v2/health`, and shuts the stack down cleanly. A distinct
consensus signing key is supported but may enter only through a bounded keystore
file. Secret bytes are retained in a zeroizing container and are never accepted
through argv, environment variables, `Debug`, serialization, or logs. Unix
permissions are checked on the same opened handle; Windows ACL hardening remains
an explicit operator responsibility.

The public assembly test starts the actual database, actor, P2P network, driver,
and HTTP server. Node library/CLI/integration suites, strict Clippy, Rustdoc, V1
network convergence/resilience, and the focused restart and retry suites pass.
Commit `d31423f` additionally upgrades the deterministic interpreter to stable
`wasmi` 0.46 (MIT OR Apache-2.0), removes the unmaintained transitive `paste`
crate (`RUSTSEC-2024-0436`), and keeps a protocol-owned invocation fuel floor so
engine optimization cannot silently make tiny-budget calls free. All VM tests,
549 chain unit tests plus invariant/parallel integration tests, and
`cargo deny check advisories licenses bans sources` pass.

This checkpoint completes the planned V4 driver and public assembly, not the
transaction system as a whole. A late-joining validator still needs a dedicated
V4 state-sync integration test. The public API returns a finalized receipt but
does not yet assemble a transaction/receipt inclusion proof or a signed
authority checkpoint, so a browser must still trust the queried node. Localized
multi-namespace receipt pricing remains a separately versioned follow-up, and
Windows validator-key ACLs require deployment enforcement.

The finalized-proof path is now implemented through commit `0acc5c9`.
`webc-proof` reuses the indexed Merkle implementation for bounded V1 authority
checkpoints and transitions (`725922c`) and complete transaction/receipt proofs
(`2e32845`). The node assembles and self-verifies those proofs only from durable
blocks, certificates, receipt indexes, and authority snapshots (`2474dd7`), then
serves them through a concurrency- and size-bounded V2 route (`b2f733e`). A
checkpoint remains explicitly untrusted until configured source identities
reach exact quorum agreement or an operator deliberately selects visibly
labelled explicit trust (`3f2860a`). The browser SDK mirrors every signature,
quorum, transition, indexed Merkle, V5 identity, validity, and receipt/fee rule;
Rust generates the exact shared JSON fixture consumed by TypeScript, and the SDK
fetches the V2 envelope without silently trusting its checkpoint (`0acc5c9`).

The focused gates passed 25 Rust proof tests, strict all-target proof Clippy,
Rustdoc, both SDK package builds, 273 browser SDK tests, 3 widget tests, package
entry validation, and documentation-link validation. Tampered transactions,
fees, positions, siblings, roots, certificate signatures, missing/skipped
transitions, excessive collections, stale/wrong-chain candidates, configured
source disagreement/invalidity, and JavaScript mutation during asynchronous
verification all fail closed.

Exact next item: red-team the assembled node path across a real epoch boundary
(checkpoint below the target) and at maximum practical block size. Add a
repeatable proof-assembly benchmark and bounded-memory/resource-abuse tests; if
measurement shows actor starvation, split durable proof-material loading from
CPU-heavy hashing and signature verification so consensus traffic is not held
behind proof requests. Then run the full workspace/security gates, reconcile
the branch with the latest `main`, and update the global status documents only
when the branch is ready for integration.

### Step 3 implementation brief (2026-07-18 pre-implementation handoff; completed 2026-07-19)

Step 3 was scoped and researched but not started (working tree clean at
`d48f930`). This brief captures the ADR-0016 spec and the exact current-code
reuse map so the next session implements it directly without re-exploring. Do not
duplicate any listed foundation; extend/reuse it.

Target: new `crates/webc-chain/src/receipt_v1.rs`, registered in `lib.rs`
(`pub mod receipt_v1;` plus focused `pub use` re-exports). Mirror afterwards in a
new `sdk/webc-js/src/receipt-v1.ts` (+ `receipt-v1.test.ts`). Receipts are not
signed, so no keypair is needed to harvest vectors.

Reuse (with file:line) — do not re-implement:
- Fee accounting: `crate::fees::{FeeSummaryV1, calculate_fee_summary_v1,
  FeePayerV1, GasUnits, FeeRate}` (`fees.rs:87-242`). The receipt carries
  `FeeSummaryV1` (already documented "committed by a V1 receipt"), NOT the legacy
  `FeeBreakdown`. `FeeSummaryV1::validate()` IS the required fee reconciliation.
  `GasUnits`/`FeeRate` serialize as decimal strings; `FeePayerV1 { address, lane }`
  is the payer/lane single source of truth.
- Event body: reuse the existing flat `crate::state::Event` enum
  (`state.rs:87-231`), which nests `bridge::BridgeEvent` (`bridge.rs:160-190`).
- Identity/wire: `crate::transaction_v5::{TransactionId, TransactionV5}`
  (`transaction_v5.rs:124-139`, `818-830`). Copy its digest style verbatim:
  `canonical_bytes`/`canonical_hash` + a `#[derive(Serialize)] struct Payload {
  domain: &'static str, ... }` wrapper (`transaction_v5.rs:940-947`).
- Merkle: `webc_crypto::merkle_root` (`crates/webc-crypto/src/merkle.rs:64`;
  internal node domain `WEBC_MERKLE_V1`; empty tree -> `Hash256::ZERO`; odd layer
  duplicates the last node). Position/inclusion proofs reuse
  `webc_proof::{build_indexed_merkle_proof, verify_indexed_merkle_proof,
  IndexedMerkleProofV1, MerkleLeafIndex, MerkleLeafCount}`
  (`crates/webc-proof/src/indexed_merkle.rs`). Do not write a new tree.
- V4 precedent to diverge from deliberately: V4 tx/receipt leaves are UNDOMAINED
  `digest(canonical_json)` (`block_builder.rs:212-243`). V5 leaves ARE
  domain-separated (ADR-0016 §"Frozen domains"); document the asymmetry.

Types to add (ADR-0016 §Receipt/event/block, §Frozen domains):
- Consts: `RECEIPT_V1: u16 = 1`, `EVENT_V1: u16 = 1`; domains `WEBC_RECEIPT_V1`,
  `WEBC_RECEIPT_LEAF_V1`, `WEBC_EVENT_V1`, `WEBC_TRANSACTION_LEAF_V1`.
- Bounded index wrappers `ActionIndex(u32)`, `EventIndex(u32)`,
  `TransactionIndex(u32)` — JSON numbers (`#[serde(transparent)]`), per ADR
  "bounded action/event indexes remain JSON numbers".
- `BlockPositionV1 { height: BlockHeight (decimal-string serde — copy V5's
  `block_height_decimal`), transaction_index: TransactionIndex }`.
- `ExecutionFailureCodeV1` = `InsufficientBalance | ObjectNotFound |
  ObjectOwnerMismatch | ObjectVersionMismatch | Precondition` (chargeable
  post-admission failures; Step 4 maps concrete native failures to these; adding
  a code is a version bump, acceptable while protocol v2 is inactive).
- `ReceiptStatusV1` = `Succeeded | Failed { code: ExecutionFailureCodeV1,
  failed_action_index: Option<ActionIndex> }`.
- `EventV1 { version, transaction_id, action_index, event_index, body: Event }`.
- `ReceiptV1 { version, position: BlockPositionV1, transaction_id, sender:
  Address, status: ReceiptStatusV1, fee_summary: FeeSummaryV1, events:
  Vec<EventV1> }`.
- `ReceiptError` typed enum; every check fails closed, no panics on hostile input.

Functions:
- `ReceiptV1::validate()`: version == RECEIPT_V1; `fee_summary.validate()`;
  Failed => `events` empty (failed-event prohibition); each event
  `version == EVENT_V1` and `transaction_id == receipt.transaction_id`.
- `ReceiptV1::digest()` under `WEBC_RECEIPT_V1` (content identity, for the later
  `FinalizedReceiptIndex`); `ReceiptV1::leaf()` under `WEBC_RECEIPT_LEAF_V1` (over
  the complete receipt). `EventV1::digest()` under `WEBC_EVENT_V1`.
- `transaction_leaf_v1(position, transaction_id)` under `WEBC_TRANSACTION_LEAF_V1`
  — commits `(position, transaction_id)`, not the full transaction (the ID already
  commits it).
- `receipt_root_v1(&[ReceiptV1])` and `transaction_root_v1(height,
  &[TransactionV5])` build domained leaves then call `merkle_root`.
- `verify_transaction_receipt_binding(height, &[TransactionV5], &[ReceiptV1])`:
  equal counts; for each i `position == (height, i)` and `transaction_id ==
  txs[i].transaction_id()`; no duplicate transaction IDs; `receipt.validate()`.

Serialization: heights/amounts/gas/rates/nonces -> canonical decimal strings;
bounded indexes/versions -> JSON numbers. Harvest frozen vectors with a temporary
Rust dump test (same technique as the Step 2 commit `d48f930`), then bake them in:
a Succeeded receipt and a Failed receipt (canonical JSON + digest + leaf), the
`transaction_leaf_v1` for the sender-paid fixture (`transaction_id`
`c268d7d3...b143f50f`) at a fixed position, and a two-leaf `receipt_root_v1` +
`transaction_root_v1` whose binding check passes.

Step 3b (next commit): mirror in `sdk/webc-js` (`receipt-v1.ts` +
`receipt-v1.test.ts`) reproducing every digest/leaf/root byte-for-byte, reusing
the existing SDK `Event`/`FeeSummaryV1` JSON shapes. Gate each commit with
`cargo fmt --check`, `cargo clippy -p webc-chain --all-targets -- -D warnings`,
`cargo test -p webc-chain`, and `pnpm check`, then push to
`codex/transaction-system`.

After step 3: continuation step 4 (reusable action executor + two-level
parent-fee/nonce/sponsor and child-action/event execution overlay with success,
chargeable-failure, rollback, cancel, and sponsor replay/budget/revocation
coverage), then step 5 (storage schema 2 + migration and V5 mempool/runtime/V2
APIs; in parallel where files are disjoint, the V4 header/authority/checkpoint/
finalized-proof chain and browser verifier), then step 6 (fetch/merge latest
`main`, full gates, reconcile the global `implementation-status.md` and
`continuation-guide.md`, and integrate without force).

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
