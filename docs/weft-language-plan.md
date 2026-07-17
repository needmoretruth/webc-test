# Weft language plan

Sources: `WEBC-DEFINITION.md` §9, §15.41, §15.43, §15.44. Status: the design
is **decided**; the full grammar specification is implementation work within
those decisions. The language is **not-yet-built**; the runtime seam it
mounts on is planned in development-plan Phase 7a.

## 1. What is decided (§15.41, §15.43, §15.44)

### Identity
- **Working name "Weft"** (the thread woven across a web); file extension
  `.weft`; owner may rename at any time — the name is the only cosmetic item.
  Due diligence before public branding: trademark/domain search; fallback
  branding "Weftlang" with `.weft` unchanged (§15.43).
- A **domain language for WEBC applications**, not general-purpose (§15.44):
  websites and off-chain apps use the TypeScript SDK; focused DSLs win their
  domain.
- A **front end** that lowers to the audited Rust framework and compiles to
  deterministic WASM off-chain — never a second engine or VM (§9).

### Surface and semantics
- Brace-style syntax familiar to the TypeScript/JavaScript mainstream — the
  largest shared corpus for human developers and AI models — with Rust-grade
  semantics underneath.
- **Type system:** primitives (`bool`, `u8`–`u128`, `bytes`, `text`),
  structs, tagged enums with exhaustive `match`, `Option`/`Result`, limited
  monomorphized generics, interfaces for component contracts; no inheritance,
  no reflection, **no floats**.
- **Money and assets are special:** `Amount<T>` parameterized by asset type
  (adding TOKEN_A to TOKEN_B is a compile error); decimal literals compile to
  exact u128 base units (`1.5 WEBC`); asset values are **linear** — they
  cannot be duplicated or silently dropped, only moved/deposited/returned/
  explicitly burned; the compiler rejects code that loses money.
- **Predictability:** immutable by default; no null (Option) and no
  exceptions (Result); loops over unbounded data must declare bounds; no
  macros or metaprogramming; no wall clock (block time/epoch provided); no
  ambient randomness (VRF/oracle components only).
- **Entrypoints declare effects:** `reads`/`writes` clauses compiler-checked —
  the source-level mirror of §8's declared access sets.
- **Events and errors are typed enums**, emitted into the manifest.

### AI-native mechanics
- One canonical formatter (`weft fmt`, gofmt-style single valid formatting).
- Compiler-emitted **machine-readable interface manifest** (entrypoints,
  types, events, errors) consumed by the component catalog and by agents.
- **Structured doc-comments** (params / effects / failure modes)
  compiler-enforced at build.
- **Error-driven convergence:** diagnostics carry machine-parseable fix
  suggestions; `weft check` fast enough to run on every edit.
- **One-file components:** a component is fully defined in one file with
  explicit imports — no hidden state or cross-file magic — sized for a
  model's working context.
- **Small, regular grammar:** few keywords, no syntactic synonyms, one way to
  express each construct.
- **Docs-as-data:** every construct and catalog component ships a
  machine-readable spec entry plus canonical examples; the bundle publishes
  in an LLM-ingestible flat format; the examples corpus is normative,
  guaranteed-compiling, tested in CI.
- **Framework quality bar:** catalog building blocks (tokens, escrow,
  memberships, swaps, mandates…) behind small uniform interfaces with the
  same naming conventions — "read one component, understood them all."

### Never-break architecture (§15.43)
1. Deployed apps cannot be broken by language changes, by construction: the
   chain runs WASM artifacts, never Weft source.
2. **Editions** (Rust's model): breaking changes ship only as a new edition;
   contracts pin their edition; old editions compile indefinitely;
   `weft migrate` moves source forward mechanically.
3. **Stable ABI at the WASM boundary:** contracts interoperate through the
   versioned manifest/ABI across editions.
4. **Reproducible builds:** compiler version hash recorded at deploy; anyone
   can rebuild and verify the on-chain artifact.
5. **Stdlib stability:** long deprecation windows; never removal within an
   edition.

### Toolchain (single binary)
`weft fmt` · `weft check` · `weft test` (unit + property + local chain
simulation) · `weft build` (WASM + manifest) · LSP server. The toolchain may
additionally emit native builds for local testing so development never
depends on a chain node (§15.44).

### Illustrative shape (non-normative, §15.43)

```
component tip_jar v1 {
  state balances: Map<Address, Amount<WEBC>>

  entry tip(from: signer, to: Address, amount: Amount<WEBC>)
    reads balances[to] writes balances[to]
  {
    let coin = withdraw(from, amount)?   // linear: must be deposited or returned
    deposit(to, coin)
    emit Tipped { from: from.address, to, amount }
  }
}
```

## 2. Sequencing — decided (§9, decision-record Phase 7a/7b)

- **Phase 7a (first):** contracts authored in Rust via an embedded-DSL/SDK
  over the audited framework, compiled off-chain to WASM. Freeze the contract
  **ABI** and the "authoring front-end → lowering → audited Rust framework →
  WASM" **seam** as a versioned, swappable boundary.
- **Phase 7b (later, separately resourced):** Weft mounts as one more front
  end over the *same* seam — parser + lowering only; the Rust/LLVM toolchain
  does codegen. Never a runtime or framework rewrite.
- Permanent invariant: the chain accepts only deterministic WASM + metadata;
  no compiler ever runs on-chain (`architecture.md`).

## 3. Specification work plan — designed here (delegated)

1. **Grammar spec:** EBNF + reserved-word list + the one-way-per-construct
   rule audit; written spec-first, iterated against the examples corpus.
2. **Type/linearity spec:** typing rules for `Amount<T>`, linear-value flow
   (every value deposited/returned/burned on every path — the money-safety
   theorem the compiler enforces), effect-clause checking against framework
   access keys.
3. **Manifest/ABI spec:** the machine manifest schema (entrypoints, types,
   events, errors, effects, doc-comment payloads), versioned with the
   Phase 7a ABI; the component catalog and the agent service registry
   (`agent-commerce.md`) consume the same schema family.
4. **Examples corpus:** the normative, CI-compiled example set — begun from
   the development-plan reference applications (token, NFT, canonical-pool
   swap intent, commit-reveal game, conditional payment, sponsored
   membership, mandate-gated service).
5. **Lowering spec:** Weft constructs → framework calls mapping; determinism
   audit (no construct may lower to anything nondeterministic).
6. **Toolchain milestones:** `weft check` (parse+type+effects) → `weft fmt` →
   `weft build` via Rust lowering → `weft test` with local simulation → LSP.
7. **Editions policy document** + `weft migrate` skeleton from edition 1.

Acceptance for the language phase (extends development-plan Phase 7b):
- the reference corpus compiles, passes tests, and byte-matches reproducible
  builds;
- an AI-authoring evaluation: a model given only the docs-as-data bundle
  writes each reference app to green within a bounded number of
  check-fix iterations — measured, published (the §6 thesis made testable);
- the linter/pre-deploy review rejects the anti-pattern fixtures;
- manifest output validates against the catalog schema.

## 4. Open items

- Full grammar details (within the decided commitments).
- The framework's component naming conventions (uniform-interface audit).
- Trademark/domain check before public branding (§15.43).
- Owner may rename "Weft" at any time.
