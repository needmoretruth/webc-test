# ADR-0015: Weft authoring front end — earliest skeleton

Status: **accepted (skeleton)** — records the scope and structure of the first
walking skeleton of the Weft compiler (`crates/webc-weft`), built after the WASM
contract runtime it targets. It does not re-decide the language (that is
[weft-language-plan.md](../weft-language-plan.md) and §15.41/15.43/15.44); it
records how the *earliest* front end is built so future growth is additive.
[ADR-0014](0014-contract-runtime.md) owns the runtime/ABI seam; ADR-0006 owns the
off-chain-compile invariant. Neither is superseded.

## Context

Weft is WEBC's **decided** application language: a brace-style, TypeScript-familiar
surface with Rust-grade semantics that compiles **off-chain to deterministic
WebAssembly**. The permanent invariants (ADR-0006, ADR-0014, `architecture.md`):
the chain runs only WASM; Weft is a *front end* over the frozen contract ABI,
never a second VM and never an on-chain compiler; deployed WASM runs forever;
breaking changes ship as editions; builds are reproducible.

Two things made an early skeleton worthwhile now, and the owner approved building
one "even in its earliest form, even just a frame — for good flexibility later":

1. The **compile target now exists.** Phase 7b landed the deterministic `webc-vm`
   engine and wired it into `webc-chain` (`RegisterWasmContract` /
   `InvokeWasmContract`, the `WasmContract` adapter, the host ABI). A Weft-emitted
   module can be registered and invoked exactly like a hand-written one.
2. Standing up the front-end **shape** early — the stage boundaries, the stable IR
   hand-off, the manifest schema, the extension seams — is what lets the full
   language grow additively instead of through a redesign.

## Decision

Build `webc-weft` as a **real but minimal** compiler: a genuine
lex → parse → sema → IR → codegen → wasm pipeline (not a fixed-output stub),
scoped to an "edition-1 counter subset" that provably compiles and runs on-chain,
and structured so every deferred construct has a named seam.

### Pipeline (each stage a pure `Result<_, WeftError>`, fail-closed, no panics)

| Stage | File | Responsibility |
|---|---|---|
| lex | `lexer.rs`, `token.rs` | byte scan; keywords, `///` docs, `->`; **rejects float literals** so no `f64` can reach codegen |
| parse | `parser.rs`, `ast.rs` | recursive descent, one fn per production; `component/state/event/entry` with `reads`/`writes` effect clauses, `let`/assign/`emit`/`return`, `+ - *` precedence |
| sema | `sema.rs` | resolves fields to keys+slots; type- and effect-checks; a **no-op linear/money-safety pass** as the `Amount<T>` seam |
| IR | `ir.rs` | the **stable backend hand-off**; `Module::footprint()` yields the sorted, deduped state keys the chain's `WasmContractManifest` requires |
| codegen | `codegen.rs` | a `Backend` trait (WAT today) lowering IR to WAT over the host ABI, then assembling via `wat`; layout + ordering match the audited fixtures; only i32/i64 + active data, so `validate_module` accepts by construction |
| manifest | `manifest.rs` | the `weft.interface/v1` machine-readable interface (entrypoints, state, events, resolved effect keys, footprint) for the catalog/agents |
| keys | `keys.rs` | one derivation `state_key(component, field)` feeding **both** the baked data segment and the manifest footprint — a correctness invariant, not a convenience |

The public API is `compile(&str) -> Result<Compiled, WeftError>`, where `Compiled`
carries `{ wasm, wat, manifest, footprint, abi_version }`. A single-binary CLI
(`weft check|build|wat`) is the toolchain skeleton.

### Edition-1 scope (deliberately small)

- Types `u64` (8-byte little-endian in linear memory; wrapping arithmetic) and
  `bytes` (the store-and-echo shape).
- Exactly one entry per component, compiled as `webc_call`.
- Statements `let` / assign / `emit` / `return` (return must be last); expressions
  are integer literals, `input`, names, and `+ - *`.
- `event`/`emit` parse, type-check, and populate the manifest; their **codegen is a
  no-op** (the host has no event sink yet).

### What is proven

`compile` runs end-to-end: a `.weft` counter is compiled, its bytes pass the
chain's own `validate_module` gate, and it is **registered and invoked on a real
`ChainState`**, where the persistent counter climbs 1 → 2 → 3 across transactions
— behaviorally indistinguishable from the audited hand-written WAT fixture, under
the same engine, gas metering, and declared-access enforcement. An `echo`
component round-trips input; the emitted manifest footprint equals the on-chain
declared access.

## Extension points (the flexibility this skeleton is for)

Every deferred construct has a named seam already wired into the pipeline:

- **More types / expressions / control flow** — `Ty`, `Stmt`, `Expr` are
  `#[non_exhaustive]`; the parser's expression layer is a precedence chain; codegen
  dispatches per variant. New variants only.
- **Linear `Amount<T>`** — `sema`'s no-op linear pass is already in the pipeline;
  turning on the deposited/returned/burned theorem is confined to that function.
- **Events** — already parsed, type-checked, and manifested; only the codegen arm
  changes when a host event sink lands. The manifest schema is unchanged.
- **Generics / interfaces** — a monomorphization pass slots between type-check and
  IR lowering, producing the same `Module` the backend already consumes.
- **Editions + stable ABI** — `edition`/`abi_version` are explicit; layout and
  lowering are edition-scoped, so a new edition is additive and old ones keep
  compiling. `weft migrate` operates on the AST.
- **Production backend** — `trait Backend { emit(&ir::Module) }` has one impl
  (`WatBackend`). A `RustFrameworkBackend` (the decided "Weft → audited Rust
  framework → WASM" path) slots in behind the same trait consuming the identical
  IR; the whole front end is reused, and the WAT path becomes the reference oracle.
- **Diagnostics / LSP / fmt** — today one fail-fast `WeftError`; a collecting
  driver and a machine-readable `fix` field slot in without changing stage
  signatures; `weft fmt` is a pure AST→text pass reusing lex/parse.

## Consequences

- WEBC now has a language front end that emits real, on-chain-runnable contracts —
  the Phase 7b "authoring" half, at skeleton maturity.
- The permanent invariants are honored: compilation is off-chain and deterministic;
  the chain runs only WASM; editions and reproducible-build provenance are explicit
  fields; there is no second VM.
- Two honest, documented simplifications, each a live seam rather than a silent
  divergence: codegen emits WAT (assembled via `wat`) instead of lowering through
  the audited Rust framework; and the linear/type systems are minimal. No code path
  emits `Amount` operations or relies on events, so nothing depends on the stubs.
- Not in scope (future work, not regressions): the full type system and linearity,
  multi-entry dispatch, control flow, the Rust-framework backend, `weft fmt/test`
  and the LSP, the normative examples corpus, and the AI-authoring acceptance
  evaluation (weft-language-plan §3).
```
