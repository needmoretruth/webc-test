# WEBC transaction-system completion plan

Status: owner-selected implementation objective (2026-07-17). This is the task
specification, not a completion claim. Code reality lives in
`implementation-status.md`; the resume pointer lives in
`continuation-guide.md`.

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

## Three simultaneous subagent tracks

The root agent first makes a small shared-interface/ownership commit, creates
three real Git worktrees, verifies them with `git worktree list`, and starts all
three subagents together. Each owns disjoint primary files, commits tested steps
on its own branch, and pushes. Root owns shared types, integration, status docs,
full gates, and final merges to `main`.

### Track A — transaction protocol and execution

Primary ownership: `crates/webc-chain` and required canonical fixtures.

- versioned action/envelope model, signed expiry, cancellation, payer
  authorization, and hard bounds;
- failed-execution/nonce/fee/refund semantics and typed receipts;
- Merkle leaf definitions and Rust/TypeScript canonical vectors;
- property/adversarial tests for rollback, supply, replay, access, fees, action
  ordering, and hostile decoding.

### Track B — node lifecycle, storage, and APIs

Primary ownership: `crates/webc-node` and `crates/webc-storage`.

- restart-safe pending/finalized lifecycle and transaction/receipt indexes;
- admission, replacement, cancellation, expiry, eviction, duplicates, gossip,
  and status transitions;
- bounded status/receipt/proof HTTP and WebSocket APIs with typed errors;
- crash recovery, idempotency, multi-node, rate-limit, and index tests.

### Track C — finalized proofs and light client

Primary ownership: a focused proof/light-client crate and `sdk/webc-js`.

- finalized transaction-proof schema and verification from a checkpoint;
- modular checkpoint/source/trust-policy interfaces, multi-source mismatch stop,
  explicit operator input, and validator-set transition verification;
- Rust/TypeScript parity fixtures, browser verifier/SDK, and tamper tests;
- after Phase 5.5, select a maintained Apache-2.0-compatible STARK library from
  security, maintenance, license, and browser benchmarks and implement the real
  backend behind ADR-0005.

## Integration sequence

1. Freeze shared domains, types, errors, API shapes, compatibility/migration,
   and file ownership in one root commit.
2. Run A/B/C concurrently in verified worktrees.
3. Integrate A, rebase B/C onto the stable protocol surface, then integrate B
   and the transparent-proof portion of C.
4. Run Rust, TypeScript, docs, dependency, fuzz-smoke, restart, and multi-node
   gates; fix integration defects with focused commits on `main`.
5. Update `implementation-status.md` only with demonstrated facts and point
   `continuation-guide.md` to the first incomplete acceptance item.
6. After Phase 5.5, complete the real STARK backend and gates. Until then state
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

## User decisions for this objective

None remain. The checkpoint source direction was the only owner-owned trust
choice for this transaction/light-client objective, and it is approved as a
reviewable direction. Agents autonomously choose libraries, modules, formats,
limits, algorithms, tests, and tuning, then record what and why. Stop only if
implementation reaches a real conflict with monetary policy, production-bridge
trust, governance/emergency power, or another item reserved by `AGENTS.md`.

## Goal prompt for a fresh session

> Continue the owner-selected WEBC transaction-system completion goal. First
> follow the full startup protocol in `AGENTS.md`: read it completely and then
> every required linked authority/status/review document, inspect Git status and
> history, and read `docs/transaction-system-plan.md`. Treat repository docs and
> Git as authoritative, not chat memory. Work on `main` and preserve history.
> Make the small shared-interface/ownership commit, then create and verify three
> real worktrees and start three subagents simultaneously for Track A
> (transaction protocol/execution), Track B (node/storage/API lifecycle), and
> Track C (finalized proofs/light client). Enforce disjoint primary file
> ownership; root integrates and owns shared interfaces/docs/gates. Proceed
> autonomously without asking routine technical questions. Reuse existing
> modules and maintained Apache-2.0-compatible dependencies; do not reinvent
> crypto, proof, storage, networking, or encoding. Keep code modular, versioned,
> replaceable, documented, and adversarially tested. Every technical choice is
> reviewable: record what changed, why, alternatives, compatibility/migration,
> reused module/dependency/license, evidence, and commit. Commit and push every
> coherent tested step. Respect the Phase 5.5 gate: transparent finalized proofs
> may be completed now, but a real STARK backend starts only after the independent
> core review. Keep `implementation-status.md` truthful and
> `continuation-guide.md` pointed at the first incomplete acceptance gate. Do not
> stop until the allowed transaction-system work is integrated, fully tested,
> documented, committed, and pushed, or a genuinely owner-reserved decision or
> hard external blocker is reached.
