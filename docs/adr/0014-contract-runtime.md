# ADR-0014: contract runtime — sandbox, determinism, gas, and the manifest seam

Status: **proposed** — records the design direction for the Phase 7a contract
runtime (the sandboxed execution engine plus the interim Rust-authored path that
ships first) and the two owner-owned decisions it deliberately does not settle.
Not yet implemented; the chain today exposes native operations only. This ADR
fixes the *design*; [ADR-0006](0006-contract-runtime-gate.md) still owns the
*selection process* and the off-chain-compile invariant, and this ADR does not
supersede it.

## Context

WEBC already executes a fixed catalogue of native operations
(`Operation` in `transaction.rs`) with three properties that Phase 7 must not
lose when arbitrary application logic becomes deployable:

- **Declared access, enforced.** Every transaction carries a signed `AccessList`
  of exact read-only / read-write `StateKey`s. The scheduler
  (`parallel_batches`) groups transactions whose declared access is disjoint —
  keyed on the version-independent `StateKeyKind` — into order-preserving,
  serializable parallel batches. At execution `StateAccessRecorder` fails closed
  on any access the transaction did not declare (`UndeclaredStateRead` /
  `UndeclaredStateWrite`) and on any declared key it did not use
  (`UnusedDeclaredStateAccess`), so a forged or padded list cannot manufacture
  false conflicts or hide a real one.
- **Deterministic gas.** `Operation::required_units()` prices each op in
  execution units; `FeeBid` bounds the units (`gas_limit`) and the price
  (`max_fee_per_unit` / `priority_fee_per_unit`), and object operations are
  priced by their namespace-localized base fee (`fee_namespace()`). Amounts are
  u128 base units; the canonical encoder rejects floats.
- **Atomic execution.** A transaction that violates any check rolls back whole;
  no partial state persists.

The Phase 7a task (`development-plan.md`; `weft-language-plan.md`;
§15.41/15.43/15.44) is to run **application logic authored off-chain** while
preserving exactly those properties, and to do so behind a **versioned, swappable
seam** so the authoring front end (interim Rust eDSL first, Weft later) and the
execution engine can each change without a protocol rewrite. The chain must keep
running the *same* determinism/parallelism/gas discipline it enforces for native
ops, now for third-party code — and it must never compile source in a state
transition (the [ADR-0006](0006-contract-runtime-gate.md) off-chain-compile
gate). The unified state-key schema already reserves the hooks:
`StateKeyKind::Application { namespace, key_hash }` for contract state and
`StateKeyKind::Module { module_id }` for a contract's code/manifest record.

## Decision (direction)

### 1. Execution model and sandbox

Three realistic options for a determinism-first chain that must also run on a
mid-range validator floor (§15.23) — a lightweight-device *verification* promise,
not a data-center *execution* one:

- **(a) A restricted WASM engine** (e.g. `wasmi` or `wasmtime`, both permissively
  licensed — `MIT OR Apache-2.0` / `Apache-2.0 WITH LLVM-exception`, compatible
  with our Apache-2.0 per the reuse rule) configured for determinism: fuel
  metering, no floats, no threads, no SIMD nondeterminism, bounded linear memory,
  and only the host functions the runtime exports. WASM is already the committed
  artifact format (§9, §15.44 "the WASM question answered"); its engines are
  mature, audited, widely deployed, and reusable rather than hand-built.
- **(b) A purpose-built bytecode interpreter** fed by Weft's compiler-emitted
  machine manifest. Maximum control over metering and validation, but it is
  exactly the *commodity execution machinery a reputable dependency already
  provides* — building and auditing a bespoke VM cuts against the
  reuse-over-reinvention rule and duplicates solved work, for a determinism
  guarantee a configured WASM engine already gives.
- **(c) The interim native / Rust-authored module path.** A contract is a
  Rust-defined handler (an embedded-DSL/SDK over the audited framework, compiled
  off-chain to WASM for deployment, but registered and executed behind the *same*
  declared-access + gas discipline as native ops). No third-party bytecode
  executes yet; the trust surface is the audited framework only.

**Recommended direction.** Ship **(c) first**, and treat **(a) restricted WASM**
as the working assumption for the general engine — *not* a bespoke bytecode (b).
Reasons: (c) lets the seam, the ABI, the manifest schema, the state-access
extension, the gas model, and the whole reference-application corpus be built,
benchmarked, and frozen against native Rust the node already trusts, before any
untrusted bytecode is admitted — the safest possible sequencing, and the one the
plan mandates ("interim Rust authoring ships first"). (a) is favoured over (b)
because WASM is already the deployment artifact, its engines are reusable and
audited, and a bespoke interpreter would be new consensus-critical surface built
to re-solve determinism that engine configuration already solves. **The machine
manifest is retained regardless** — but as the ABI/metadata sidecar that
*describes* the artifact (option b's genuinely valuable idea), not as a second
execution engine.

**(c) → (a) with no breaking migration.** The seam — not the engine — is the
stable boundary. It is the versioned **contract ABI**: an entrypoint receives a
bounded host context that exposes only its declared state keys and the
block-provided environment (height/epoch, never a clock or RNG), consumes units
from the same `FeeBid` budget, and returns typed events/errors plus linear-asset
moves. The interim Rust handler and a future WASM module implement the *same*
ABI. Because a contract's on-chain identity is the hash of its artifact + manifest
([ADR-0006](0006-contract-runtime-gate.md)) and its state lives under
`StateKey::application(namespace, …)` keyed by the manifest — independent of how
the code runs — swapping the engine under the seam changes *how* a call executes,
never *what* it means, and needs **no state migration**. The Phase 7 acceptance
condition already requires each reference app to "pass on the interim Rust path
(7a) and later compile from Weft to the same behavior (7b)"; the same equality is
the migration test for (c) → (a).

### 2. Determinism guarantees

- **No wall-clock, RNG, or float in contract execution.** Block time and epoch
  are injected as inputs, exactly as the consensus machine already treats time
  ("time enters consensus only as an event fed in by a driver, never read by the
  machine"). No ambient randomness — VRF/oracle components only. This holds on
  every path.
- **Floats statically excluded, two ways.** Weft has no float type and the
  interim Rust eDSL forbids `f32`/`f64` in the contract surface; the canonical
  encoder already rejects floats in any consensus value. On the WASM path the
  engine is additionally configured to **reject float opcodes at module
  validation** (load time), so float nondeterminism (NaN bit-patterns, rounding)
  cannot arise because floats cannot be represented. Threads, non-deterministic
  SIMD, and unbounded `memory.grow` are rejected the same way; the only imports a
  module may name are the runtime's declared-access host functions.
- **Bounded memory and stack.** A per-call linear-memory cap, a call-depth cap,
  and the per-call gas cap bound resource use; loops over unbounded data must
  declare their bounds (a Weft compile rule), so worst-case cost is knowable.
- **Reproducible across machines and thread counts.** A contract call declares
  its full access set up front (§3), so `parallel_batches` never schedules two
  conflicting calls into the same batch, and non-conflicting calls produce the
  same result in any order on any worker. Contract state is ordinary `StateKey`
  records committed by the existing per-subtree state roots, so those roots and
  the block hash are identical regardless of thread count or machine — the same
  determinism the native path already proves.

### 3. Gas metering

- **One unit currency, integrated with the existing model.** A contract call is
  priced in the same execution units as native ops and settled through the same
  `FeeBid` / base-fee path (`effective_fee_per_unit(base_fee_per_unit)`), at the
  operation's namespace-localized base fee (`fee_namespace()`). Native ops charge
  a fixed `required_units()`; a contract call charges a base admission cost plus
  **metered** consumption — WASM engine fuel on path (a), or per-host-call fixed
  costs (state read/write, asset move, event emit) on the interim path (c) —
  always hard-bounded above by the sender's authorized `gas_limit`.
- **Ahead-of-time boundable.** The manifest declares each entrypoint's
  worst-case shape (bounded loops, bounded allocations) so a static upper bound on
  units is computable before execution, for fee estimation and for admission; the
  runtime still meters and hard-stops at `gas_limit`. The cost constants are
  benchmark-decided implementation values (like today's placeholder
  `required_units`), not owner policy.
- **Declared access extends the existing `AccessList`.** A contract-call
  transaction still carries exact `read_only` / `read_write` `StateKey`s — now
  including the `StateKey::application(namespace, …)` keys the entrypoint will
  touch, derived directly from its `reads` / `writes` effect clauses in the
  manifest (the source-level mirror of §8's declared sets). `StateAccessRecorder`
  enforces at runtime that the contract reads/writes nothing undeclared and uses
  everything declared, so contracts stay **parallel-schedulable by the unchanged
  `parallel_batches`** and **cannot touch undeclared state**.
- **Fail-closed on over-gas or access violation.** Exhausting `gas_limit` or
  touching an undeclared key aborts the call and rolls the whole transaction back
  atomically — identical to a native op that diverges from its signed list. No
  partial contract state survives; the fee model settles exactly as it does for a
  failed native operation.

### 4. State and isolation

- **Contracts live under application namespaces.** Contract state is a set of
  `StateKey::application(namespace, key_hash)` records under the contract's
  registered namespace, with `key_hash` domain-separating records inside the
  namespace exactly as objects, sponsor records, and registry records already do;
  the reserved `StateKeyKind::Module { module_id }` holds the contract's
  code/manifest commitment. Namespace ownership uses the existing registry
  (`RegisterNamespace` / `TransferNamespace`), so independent applications
  schedule and price independently (§8 isolation) with no new state space.
- **Storage rides the §15.22 storage deposit.** A contract write that grows state
  locks a byte-proportional deposit from the funding account, mostly refunded on
  delete — the same occupancy pricing and settlement the object operations
  already implement (e.g. `DeleteObject`). No new storage economics.
- **No ambient authority — capability / declared-access only.** A contract can
  touch only the state keys it declared and can move only the linear assets
  passed into it (`Amount<T>` that must be deposited, returned, or explicitly
  burned — the compiler rejects code that loses money). There is no global
  mutable token object and no cross-namespace reach without a declared key: the
  §8 declared-access model *is* the contract sandbox's authority model.

### 5. The machine manifest (§15.41)

- **What the compiler emits.** A machine-readable interface manifest — the ABI:
  entrypoints with their `reads` / `writes` effect clauses, types, typed events
  and errors, structured doc-comment payloads, the pinned language edition and
  compiler-version hash, and the artifact hash. The interim Rust eDSL emits the
  *same* manifest schema, so the seam is authoring- and engine-independent, and
  the component catalog and agent service registry (`agent-commerce.md`) consume
  the same schema family.
- **How the chain verifies and loads it.** At deploy the chain commits to
  `hash(artifact)` and `hash(manifest)` and stores them under the contract's
  `Module` key. It **validates** — it does not compile: the manifest must be
  well-formed and its declared effect-keys must fall within the contract's own
  namespace; the artifact must pass the engine's static rules (no floats, no
  disallowed imports, bounded memory) at load. Execution then binds each call's
  signed `AccessList` to the manifest's effect clauses, so an entrypoint cannot
  declare less than it touches.
- **The off-chain-compile gate holds ([ADR-0006](0006-contract-runtime-gate.md)).**
  The chain runs a *verified manifest + artifact*; it never compiles source,
  reads a filesystem, or fetches a toolchain inside a state transition. A verifier
  reproduces a deployment by rebuilding the published source with the pinned
  toolchain off chain and checking the artifact hash matches the on-chain
  commitment — the same commit-hash-on-chain / content-off-chain rule the project
  uses for object payloads and agent receipts.

## The owner-owned decisions

Two decisions here are of the same class as the [ADR-0011](0011-historical-state-and-weak-subjectivity.md)
trust anchor and the production-bridge trust model, and are deferred to the owner
at the Phase 7 freeze — this ADR recommends but does not bind them:

- **The final engine choice — restricted WASM vs a bespoke bytecode interpreter.**
  This ADR recommends restricted WASM (§1) and gives its reasons, but the binding
  selection is the [ADR-0006](0006-contract-runtime-gate.md) evidence gate: the
  engine is chosen against the published benchmark scorecard and the security
  gates (deterministic resource limits, enforced state access, sandboxing,
  stable TS clients, versioned ABI), not by preference. Until then the runtime is
  the interim native path (c), whose only trust surface is the audited framework.
- **The trust / verification model for loaded manifests and artifacts.** How much
  the chain trusts a deployed artifact beyond its hash commitment and static
  validation: whether deployment is fully permissionless on reproducible-build
  hash + static checks, or whether privileged capabilities require an additional
  attestation / audit / allowlist gate, and what fuzz/validation an artifact must
  clear before it may execute. This is a security-trust decision for the owner at
  the phase freeze, not an implementation constant.

The gas cost constants, memory/stack/gas caps, and the exact manifest schema
fields are benchmark- and spec-decided implementation values (per ADR-0006 and
the plan), not owner-owned — they are tuned against the reference corpus before
the ABI is frozen.

## Consequences

- Application logic gains the *same* determinism, serializable parallelism, gas,
  and atomic-rollback guarantees the native path already proves — because the
  contract call reuses the `AccessList`, `parallel_batches`, `StateAccessRecorder`,
  `FeeBid`, per-subtree state-root, and §15.22 storage machinery unchanged, rather
  than introducing a parallel mechanism that could drift from it.
- Shipping the interim native path (c) first lets the seam and the whole
  contract surface be exercised and frozen with no untrusted bytecode in the
  trust surface; admitting a general engine later is a change *under* the seam,
  with the reference-app behavioral-equality test as its acceptance gate and no
  state migration.
- Recommending WASM over a bespoke VM keeps consensus-critical surface small and
  reuses audited, permissively-licensed engines, consistent with the
  reuse-over-reinvention and license rules — while leaving the binding engine
  selection to the ADR-0006 evidence gate, so this ADR does not pre-empt the
  owner's decision.
- No protocol version bump is required to *record* this design; the versioned ABI
  and manifest are introduced when the runtime lands, and the reserved
  `Application` / `Module` state-key kinds mean the state schema already
  accommodates contract state without a new key space.
