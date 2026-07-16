# WEBC agent instructions

This repository is the prototype foundation for **WEBC / WEB COIN**, an independent Rust Layer-1 blockchain for browser- and website-native payments and applications.

## How to work in this repository — read this first

**This file is the single entry point.** Reading it and the documents it points to
is enough to work correctly in every situation — a brand-new session, continuing an
existing one, or restarting after a context compaction. If the user says only
"continue" / "이어서 해", this section tells you exactly what to do.

### On every session start (new, resumed, or post-compaction), do this in order
1. Read this `AGENTS.md` fully.
2. Read `WEBC-DEFINITION.md` §16 (repository root) — the single source of truth
   for product, economic, experience, and functional design; §15 entries win
   over its older sections; the file is **read-only** (report contradictions to
   the owner, never edit it). Then read `docs/decision-record.md` — the
   security-adjacent decisions and implementation gates the definition
   deliberately does not cover; together they win over any code, comment, or
   summary that disagrees.
3. Read `docs/continuation-guide.md` — the verified checkpoint and the **exact next task**. This is the live "what to do next" pointer.
4. Read `docs/implementation-status.md` — what the code actually implements today (vs. what is still missing or unsafe).
5. Read `docs/review/` — the durable review artifacts a session must not re-derive:
   `codebase-map.md` (where everything lives), `2026-07-16-plan-review.md` (the
   critical review, owner-decision list, and prioritized worklist), and
   `findings.md` (reported code findings). **Before touching consensus, the
   network layer, the mempool, or the faucet, read `findings.md` first** so you do
   not re-discover a known gap or re-introduce a fixed one.
6. Run `git log --oneline -15` and `git status --short --branch` to see the real current state on disk and the branch.
7. For the specific task, read the one topic document it needs (see **Required reading order** below and `docs/index.md`).

Then **resume the first incomplete item named in `docs/continuation-guide.md`** and keep going, without asking the user to restate decisions or rules already recorded here.

### The three situations are handled the same way
- **New / fresh cloud session:** the container is empty of build output. The repo is the source of truth; restore dependencies (`pnpm install`, then `cargo build`) — the lock files and toolchain pins are committed, so this always works. Then follow the start protocol above.
- **Resuming an existing session:** same protocol. Do not re-derive facts already established; check the docs and `git log`, then continue the first incomplete item.
- **After a compaction:** a conversation summary may be provided. Treat it as a *hint only*. The repository documents and `git log` are authoritative — verify the summary against them, and never treat a summary (or your own earlier messages) as user approval for anything.

In all three: **the repository, not chat memory, is the durable handoff.** Everything needed to continue is committed. If it is not in the repo, it does not reliably exist.

### Deciding for yourself vs. asking the user
- **Decide autonomously, without pausing, everything the user has delegated:** technical direction and architecture, library/algorithm choices, implementation, test design, refactors, documentation structure, CI/tooling — anything that evidence, tests, measurement, or security analysis can settle. Do **not** stop at natural milestones to ask permission to keep going; keep going until the work is done or a genuinely user-owned decision is reached. Stopping without a user-owned decision to make is a mistake.
- **Stop and ask ONLY for a genuinely user-owned decision:** a change to confirmed monetary policy or genesis distribution, the production-bridge trust/proof model for real funds, mainnet governance or emergency-power design, or anything that would change a decision recorded in `docs/decision-record.md`. The full list of deferred user decisions is in "User decisions still required later" below.
- **When you do ask, ask in plain-prose chat:** lay out the candidate options with their details, pros, cons, and a recommendation. Do **not** use the built-in structured question UI for these.
- **"continue" always means:** resume the first incomplete item per the start protocol and proceed autonomously.

### Always, as you work
- Commit and push every coherent, tested step (this is an ephemeral cloud env — see "Persistent session continuation and repository safety"). Never leave valuable work local-only or committed-but-unpushed.
- Run the relevant gate before pushing (see "Validation expectations").
- Keep `docs/continuation-guide.md` and `docs/implementation-status.md` accurate as facts change, and persist any new standing user instruction into this `AGENTS.md`, so this protocol keeps working for the next session.
- Speak simple Korean to the user, address them as 관리자 with 존댓말, and explain any unavoidable technical term plainly (see "Communication with the user").

## Required reading order

Before changing protocol code, read:

1. `AGENTS.md`
2. `WEBC-DEFINITION.md` (§16 first — product/economic/functional source of truth, read-only)
3. `docs/decision-record.md` (security-adjacent decisions and gates)
4. `docs/development-plan.md`
5. `docs/whitepaper.md`
6. `docs/implementation-status.md`
7. `docs/index.md`
8. the specific supporting document for the task:
   - `docs/architecture.md`
   - `docs/tokenomics.md`
   - `docs/bridge.md`
   - `docs/security.md`
   - the system plans (`docs/distribution-program.md`, `docs/dex-batch-settlement.md`,
     `docs/oracle-economics.md`, `docs/weft-language-plan.md`, `docs/speed-roadmap.md`,
     `docs/validator-operations.md`, `docs/agent-commerce.md`)

`WEBC-DEFINITION.md` is authoritative for product/economic/experience/functional
design; `docs/decision-record.md` is authoritative for security-adjacent
decisions, when older documentation or the current prototype conflicts.

## Project identity

- Project: `WEBC`
- Coin: `WEB COIN`
- Ticker: `WEBC`
- Independent custom Layer 1, not merely a token on another chain
- Rust is the core protocol/node language
- TypeScript is the primary website SDK language
- Global audience

## Confirmed protocol/product decisions

The complete decided set lives in `WEBC-DEFINITION.md` (§16 summary; §15
detail). Key facts for quick orientation — the definition wins if this list
ever drifts:

- Genesis supply: `10,000,000 WEBC`; native precision: 12 decimals; amounts
  u128 with 256-bit multiply intermediates and variable-length encoding
  (§15.14)
- Inflation: 10% initial, ×0.8 each year, 1% floor (§7)
- Genesis distribution (decided, §15.33/15.38): 25% contributors / 5%
  validator-bootstrap ceiling / 30% usage subsidies / 15% airdrop in three
  waves / 15% ecosystem fund as non-transferable fee credits / 10% strategic
  reserve; no founder/investor/private-sale allocation; the founder is paid
  under the same published contribution rules, disclosed (§15.16)
- Consensus: permissionless stake-based BFT with a rotating stake-weighted
  committee; PoH not used; votes are permissioned aggregated messages with
  **no per-vote fees** (§8, §15.23, §15.28)
- Speed (§15.42): conservative public claim ~2s blocks / 6–8s finality until
  benchmarks; decided engineering targets: fast path ~0.4–0.8s for
  single-owner operations (launch scope), consensus ~1s blocks / ~1–2s
  finality (≤4s degraded), Mysticeti-class DAG-BFT reference
- Validator pool activation: 100 WEBC total / operator ≥20 WEBC and ≥20% of
  pool / delegation ≤80% / minimum delegation 1 WEBC; unstaking ~7 min
  devnet, ~7 days mainnet; devnet uses a valueless faucet (§7)
- Base fees: 50% burned, 50% rewards; dynamic localized pricing; capped
  sponsorship (launch values are measurement placeholders — §15.35); storage
  is deposit + deletion rebate with hot/cold tiering (§15.22)
- Parallel execution is a core requirement; hybrid account/object state
  (§8, §15.30); enforced declared read/write access; per-app namespaces
- Native DEX: canonical shared pools, disclosed frontend fees, **mandatory
  per-block uniform-price batch settlement** with chain-native retry; MEV is
  not monetized (§15.13, §15.18, §15.37)
- Native oracle: consumers pay, accuracy-weighted bonded reporters,
  pull-based once-per-block updates, free display-only reads (§15.17, §15.21)
- Agent commerce: revocable mandate objects (no re-delegation, instant
  revocation), on-chain service registry, HTTP-402-style flows (§15.5, §15.32)
- Authoring: deterministic WASM + Rust first; **Weft** (working name) is the
  decided high-level language — TS-familiar surface, Rust semantics, linear
  assets, never-break editions (§15.41, §15.43, §15.44)
- Browser wallet secrets stay isolated from host-site JavaScript
- ZK: succinct light-client verification yes; never on the consensus critical
  path; state compression phase-2 optional (§15.25)
- Post-quantum-ready versioned wallet/account authorization from genesis
- Bidirectional Ethereum/Solana bridges and wrapped WEBC are required
- Real bridge funds remain disabled until separately designed, audited,
  limited, monitored, and approved

## Things agents must not assume are already implemented

The existing prototype still uses old assumptions. Do not treat passing legacy tests as proof of the new design.

Known mismatches include:

- objective evidence exists only for double votes; other slashing classes remain disabled;
- consensus-detected equivocation IS wired to an applied slash (commit `a6197ac`); the crash-restart self-equivocation hazard (review finding C4) is fixed by the durable vote/lock WAL (commit `90c28ac`) — the driver journals every own signed message before broadcast and replays the journal on restart;
- the finality "committee" is the whole validator set — the confirmed rotating stake-weighted sub-committee is unbuilt;
- `ChainStore` keeps latest-only state — no historical state for proofs/sync yet;
- localized congestion fee markets are incomplete;
- trusted-relayer bridge logic that is only a mock/prototype.

Read `docs/implementation-status.md` for the audit summary and
`docs/review/findings.md` for reported code-level gaps (including HIGH-severity
consensus/network items a review flagged but has not yet reproduced).

## Development principles

1. Security and correctness outrank speed, feature count, and delivery convenience.
2. Keep code modular, deterministic, readable, and testable.
3. Explain protocol invariants, non-obvious choices, and security reasons in comments.
4. Keep modules focused and dependencies one-directional; avoid oversized files, hidden coupling, and hidden global state.
5. Prefer stable public interfaces and replaceable versioned boundaries so one subsystem can change without rewriting unrelated code.
6. Prefer small auditable rules over clever abstractions.
7. Do not read wall-clock time, network state, files, or randomness inside deterministic state transitions.
8. Treat full-block execution as atomic.
9. Validate actual state access against declared read/write lists.
10. Use checked arithmetic for supply, balances, rewards, fees, and stake.
11. Preserve a replaceable/versioned boundary for cryptography, proofs, contract runtime, storage, networking, and bridges.
12. Use established audited cryptographic libraries; do not invent primitives.
13. Do not claim TPS without reproducible sustained benchmarks.
14. Do not claim post-quantum security unless every relevant layer is covered.
15. Do not claim mainnet or bridge readiness without independent audits and adversarial public testing.
16. Update `docs/implementation-status.md` after each material implementation milestone.
17. Record any changed product decision in `docs/decision-record.md` only with the user's approval.
18. **Reuse over reinvention** (see the dedicated section below): prefer an existing, maintained, license-compatible crate/module over hand-writing equivalent machinery.

## Common implementer pitfalls — read before writing code

Two different models (Claude Opus 4.8 and GPT-5.6 Sol) take turns implementing
this project. These are the mistakes that break a crypto chain and that a
confident model is most likely to make. Treat each as a hard rule, not advice.

1. **Never call something "complete" without running its acceptance test.** A
   passing unit test on the happy path is not completion. A phase item is done
   only when the `development-plan.md` acceptance condition for it is demonstrated
   by a repeatable test, and `docs/implementation-status.md` says exactly what is
   and is not covered. Overstating status is a security defect here: it hides
   unbuilt safety mechanisms. (Live example: consensus was described as
   essentially complete, but a review found HIGH-severity safety/liveness/DoS gaps
   — see `docs/review/findings.md`. Do not repeat that.)
2. **Never weaken a check, edit a committed test vector, or relax an assertion to
   make a test pass.** If a cross-language fixture or a consensus vector fails,
   the code is wrong until proven otherwise — never the frozen bytes. Changing a
   vector requires a written reason and, if it is a wire/consensus format, a
   version bump.
3. **Never introduce nondeterminism into a state transition.** No `HashMap`/
   `HashSet` iteration in any hashed/consensus path (use `BTreeMap`/`BTreeSet` —
   the state maps already do), no wall-clock (`SystemTime`, `Instant`), no
   `Instant::now`, no thread timing, no `f64`/`f32` in canonical/consensus values
   (the canonical encoder rejects floats — keep it that way), no RNG inside
   `apply`/`build_block`/verification. Time enters consensus only as an event fed
   in by a driver, never read by the machine.
4. **Validate hostile input before allocating or looping on it.** Every network
   frame, wallet request, and stored record is hostile. Check length/bounds/magic/
   version before decoding, before `Vec::with_capacity`, before recursion. An
   attacker-controlled length prefix or round number must never size an
   allocation or an unbounded map (see findings C3, N6).
5. **Never put a secret in argv, an env var that leaks, a log line, `Debug`, or
   `Serialize`.** Validator/consensus/wallet key material loads from a permissioned
   keystore file, never a command-line flag (visible in `ps`). Secret types stay
   non-`Debug`/`Serialize`/`Clone` (the code already does this — preserve it).
6. **`unwrap`/`expect`/panic are forbidden on any path reachable by untrusted
   input or consensus.** Return a typed `Result`. `unwrap` is allowed only in
   `#[cfg(test)]`.
7. **Reproduce before you fix a review finding.** For any item in
   `docs/review/findings.md`, write a failing test that demonstrates it first, then
   fix, then keep the test. A static-review finding can be a false positive — do
   not "fix" phantom bugs, and do not trust one without a repro.
8. **Do not duplicate live status into multiple documents.** Phase/checkpoint
   facts live ONLY in `docs/continuation-guide.md` and
   `docs/implementation-status.md`. Do not copy them into `AGENTS.md`,
   `ai-handoff.md`, or a new summary file — duplicated status rots into
   contradictory sources. Update the two owners; point everything else at them.
9. **Stay inside the phase gate.** Do not jump ahead to the contract runtime, the
   WEBC language, ZK, or real-fund bridges before their phase and its acceptance
   gate. Building ahead of the gate creates unaudited surface that looks done.
10. **Commit and push after every coherent, tested step.** This is an ephemeral
    cloud container; unpushed work is lost work. Never end a turn with valuable
    uncommitted or committed-but-unpushed changes.

## Conventions for alternating implementers

So two models produce one consistent codebase:

- **Commit messages:** `type(scope): summary` (e.g. `feat(consensus): …`,
  `fix(node): …`, `docs(review): …`, `test(mempool): …`). Explain *why* in the
  body when the change is non-obvious or security-relevant. Record the reason when
  deleting or reversing prior work.
- **Wire/consensus formats are versioned and domain-separated.** New signed or
  hashed payloads get a `WEBC_*_V<n>` domain constant; changing an existing format
  bumps its version and updates the shared Rust/TypeScript fixture in the same
  commit.
- **Every new source file opens with the module comment from
  `docs/code-documentation-template.md`** (purpose, responsibilities,
  non-responsibilities, data flow, security boundary).
- **New wrapper types over raw integers/bytes** for any value that must not be
  mixed (`Amount`, `BlockHeight`, `Epoch`, `Nonce`, `ChainId`, `AssetId`,
  `ValidatorId`, `PeerId`, …). Do not pass bare `u64`/`u128`/`[u8; N]` across
  module boundaries for such values.
- **One decision, one home:** product/economic changes → `docs/decision-record.md`
  (owner-approved only); implementation-architecture choices → a numbered ADR
  under `docs/adr/`; status → the two status docs above.
- **When you finish an item,** update `docs/continuation-guide.md` and
  `docs/implementation-status.md`, and, if you resolved a `findings.md` item, mark
  it resolved there with the commit hash. Leave the next session an unambiguous
  "exact next task."

## Reuse over reinvention — standing rule

This is a standing user instruction, not a one-off. It applies in every current and
future session.

- **Default to reuse.** Before writing non-trivial machinery (a database/WAL, an HTTP
  or WebSocket server, an async runtime, serialization, hashing, an RNG, a rate
  limiter, a parser, a data structure, etc.), look for a mature, maintained,
  well-reviewed crate or existing internal module and use it. Do **not** re-implement
  what a reputable dependency already does well.
- **Why this rule exists:** (1) it prevents spaghetti code — bespoke reimplementations
  accrete edge cases and become unmaintainable; (2) it prevents wasted tokens and
  effort — re-deriving solved problems burns budget for no gain. Reuse keeps the
  codebase small, auditable, and cheap to evolve.
- **License constraint — never contaminate our Apache-2.0.** WEBC is licensed
  Apache-2.0. Only add dependencies under Apache-2.0-compatible permissive licenses
  (Apache-2.0, MIT, BSD-2/3-Clause, ISC, Zlib, Unlicense, or dual `MIT OR Apache-2.0`).
  **Never** add a copyleft or source-available dependency that would relicense or
  restrict our code: no GPL, LGPL, AGPL, MPL-as-a-forced-copyleft, SSPL, BUSL, or
  "commons clause" crates in shipped code. Verify the SPDX license field (crates.io /
  the crate's `Cargo.toml` / its LICENSE files) **before** adding it, and record the
  license in the commit message or code comment when it is security-critical.
- **Where writing it ourselves IS correct — the rule never blocks building WEBC's own
  value.** Reuse the commodity plumbing; build the parts that are ours. Specifically:
  (a) **WEBC-unique / one-of-a-kind protocol logic** — the actual product: the state
  transition rules, versioned post-quantum authorization, constrained session keys,
  the economic/staking/slashing rules, parallel state-access model, bridge protocol,
  and anything novel to WEBC that no dependency implements. These are the reason the
  project exists; write and own them. (b) the thin *seam/adapter* that lets a
  commodity dependency be swapped later (the storage `KvStore` trait, the
  `webc-crypto` boundary) — deliberate decoupling the plan requires, not reinvention.
  (c) consensus-critical canonical encoding / domain-separated signing payloads that
  must be byte-identical across Rust and TypeScript and cannot depend on a library's
  internal format. (d) cases where every candidate dependency is unmaintained,
  incompatible-licensed, or pulls in unacceptable risk — record why in a comment.
- **The test to apply:** is this *commodity plumbing* someone already solved well (a
  DB, a web server, an async runtime, a codec, a hash) → reuse it; or is it *WEBC's own
  protocol/economic logic or the glue binding a dependency in* → write and own it. When
  unsure, prefer reuse for infrastructure and ownership for protocol semantics.
- **Still apply the security rules to dependencies:** pin versions, prefer maintained
  and widely-used crates, and keep security-critical ones behind a replaceable
  boundary. Reuse does not mean trust blindly.

## Security-first implementation rules

- Treat every parser, network message, wallet request, contract call, proof, signature, database record, and bridge message as hostile input.
- Never invent cryptography or silently weaken a check to make a test pass.
- Use maintained, reviewed libraries and pin/review security-critical dependencies.
- Keep private keys, seeds, passwords, decrypted wallet data, and sensitive request contents out of logs and error reports.
- Use explicit domain separation, versioning, replay protection, size limits, time/resource limits, and fail-closed behavior.
- Add unit, integration, property, fuzz, malformed-input, restart, and adversarial tests in proportion to risk.
- Avoid Rust `unsafe` unless there is no practical safe alternative; document the invariant and require focused review and tests.
- Do not hide uncertainty. If a security assumption is unproven, record it and keep the affected real-fund feature disabled.
- A feature is not complete merely because its happy path works. Failure, rollback, restart, duplicate, race, abuse, and recovery paths must be tested.

## Maintainability and comments

- Organize code by responsibility with small public interfaces and clear ownership of data.
- Keep consensus logic separate from networking, storage, CLI/UI, and bridge adapters.
- Comments should explain why a rule exists, what must always remain true, and what attacks it prevents; do not narrate obvious syntax.
- Each protocol module needs module-level documentation, invariants, error behavior, and tests near the code.
- Prefer generated/shared schemas and cross-language fixtures over manually duplicated Rust/TypeScript formats.
- Remove or clearly quarantine obsolete experiments so future agents cannot mistake them for active protocol behavior.

### Required documentation inside code

- Every source file starts with a module comment explaining its purpose, responsibilities, non-responsibilities, main data flow, and security boundary.
- Every public type, non-obvious field, constant, trait, function, method, error, and protocol message has a Rust doc comment (`///`) or TypeScript documentation comment.
- Public function documentation explains inputs, outputs, state changes, authorization, failure cases, units, limits, and whether the operation is consensus-critical.
- Consensus-critical structs document their invariants next to their definitions, and the code that enforces each invariant must be easy to locate.
- Complex internal logic explains the reason for its ordering, rollback behavior, and attack defenses.
- Amounts, heights, epochs, time values, byte sizes, fee units, percentages, and network identifiers always state their units and allowed ranges.
- Prefer executable examples or documentation tests so examples cannot silently become stale.
- Update or remove comments in the same change as the behavior they describe.
- Do not add comments that merely translate obvious syntax. Noisy comments can hide important security rules.

## Rust safety rules

- Use Rust's type system to make invalid states hard to represent.
- Create distinct wrapper types for values that must never be mixed, including `Amount`, `BaseUnits`, `BlockHeight`, `Epoch`, `Nonce`, `ChainId`, `AssetId`, and `ValidatorId`.
- Use enums for protocol states and handle every state explicitly.
- Return typed `Result` errors. Untrusted input, network data, wallet requests, storage data, and consensus paths must never rely on `unwrap`, `expect`, or ordinary panics.
- Use checked arithmetic and explicit conversions. Never use unchecked `as` conversions for consensus amounts, lengths, heights, fees, rewards, or stake.
- Prefer immutable data and explicit ownership. Avoid shared mutable state; if concurrency requires it, keep synchronization small and document lock ordering or use message passing.
- Consensus output must not depend on hash-map iteration order, thread timing, local clock, locale, or platform behavior. Use deterministic ordering and canonical encoding.
- Forbid `unsafe` in protocol crates by default. An exception requires a written safety argument, an isolated module, focused tests, and explicit review.
- Strict formatting and linting run in CI; unexplained new warnings fail security-critical crates.
- Validate lengths and bounds before allocation, decoding, recursion, or loops so hostile input cannot exhaust memory or CPU.
- Keep secrets in purpose-built types where possible, minimize copies, erase them where supported, and do not casually derive `Debug` or serialization for raw secrets.
- Prefer compiler guarantees, then runtime checks, then clear errors. A comment never replaces a check that code or the compiler can enforce.

## Definition of done for a code change

A change is done only when ALL of these hold — not when the feature's happy path
runs:

- Module, function, and type documentation describes the final behavior.
- Relevant unit, integration, property, malformed-input, adversarial, and regression tests pass — including the failure, rollback, restart, duplicate, race, and abuse paths, not only success.
- The specific `development-plan.md` acceptance condition for the item is demonstrated by a repeatable test (see pitfall 1).
- The full gate passes locally with no unexplained warnings (see **Validation expectations** for the exact commands): `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, `cargo doc --workspace --no-deps`, `cargo run -p webc-node -- demo`; and for SDK/wire changes `pnpm install --frozen-lockfile && pnpm check`.
- Consensus/wire changes include deterministic test vectors and cross-language byte fixtures when TypeScript shares the format, updated in the same commit, with a version bump if the format changed.
- Security assumptions and remaining limitations are recorded in code and the relevant document.
- `docs/implementation-status.md` and `docs/continuation-guide.md` accurately state what is implemented and what remains missing, and any resolved `docs/review/findings.md` item is marked resolved with its commit hash.
- The change is committed and pushed to the designated branch.

## Communication with the user

- Speak in simple Korean unless the user requests another language. Address the user as 관리자 (administrator) and use 존댓말 (polite form).
- Do not flatter or praise the user. State the truth plainly and objectively, even when it is unwelcome. Ground statements in the repository documents and code; avoid speculation, and when something is uncertain or not recorded, say so instead of guessing. Keeping the explanation easy to understand still matters.
- Lead with the outcome. Explain every unavoidable technical term immediately in ordinary words.
- Never make a user-owned product or economic decision silently. Present choices, practical advantages, disadvantages, and a recommendation, then wait for confirmation.
- When a question is genuinely the user's to answer, ask it in plain prose in the
  chat: lay out the candidate options with their details, pros, and cons in
  easy-to-understand language, and give a recommendation. Do not use the built-in
  structured question UI for this; write the question and choices out as text.
- Decide everything the user has delegated — technical direction, architecture,
  library, and implementation choices that evidence or tests can settle — yourself,
  autonomously, without pausing. Only stop for a genuinely user-owned decision.
- Do not push implementation-only constants onto the user when tests, measurements, or security analysis can decide them.
- Clearly label what is confirmed, recommended, experimental, unimplemented, or unsafe for real funds.

## Persistent session continuation and repository safety

These rules are standing user instructions. They apply in every current and future
session, including when the user says only “read `AGENTS.md` and continue.”

- **This project always runs in an ephemeral cloud environment.** The container is
  reclaimed after the session, so anything left only on local disk is lost. The
  GitHub repository is the single source of truth: push every coherent change to
  the designated branch, mid-work and again before ending. Never end a turn with
  committed-but-unpushed work or with valuable uncommitted work.
- **Commit and push frequently**, not only at the end — after each coherent, tested
  step. A container reclaim mid-session must never be able to lose more than the
  last small step.
- **`.gitignore` excludes only truly regenerable or secret junk** — build artifacts
  (`/target`, `**/dist`), installed dependencies (`**/node_modules`, `.pnpm-store`),
  caches/logs, and secrets (`.env`). Everything else — all source, configs, docs,
  fixtures, lock files, toolchain pins, and any folder future work depends on — is
  committed. The regenerable folders are safe to ignore ONLY because the lock files
  (`Cargo.lock`, `pnpm-lock.yaml`), `rust-toolchain.toml`, and `.node-version` are
  committed and deterministically restore them. Never ignore a folder that cannot
  be regenerated from committed inputs; if in doubt, commit it (this is a private
  repo). Do NOT commit `node_modules`/`target`/`dist` themselves — they are huge and
  platform-specific; keep them restorable instead.
- A fresh cloud session must be able to restore a working environment from the repo
  alone. Keep dependency restoration reliable (lock files committed; a SessionStart
  hook or setup script may run `pnpm install` and `cargo fetch`/build). A
  devcontainer/Dockerfile is optional — add one only if it is genuinely needed for
  environment reproducibility, not by default.
- Treat repository files, not chat memory, as the durable handoff. Never claim that
  unrecorded conversation context can be restored perfectly.
- At the start of a continuation session, read the required documents in order,
  then inspect `git status --short --branch`, `git log -5 --oneline`,
  `docs/implementation-status.md`, and `docs/continuation-guide.md`. Resume the
  first incomplete item in the active phase without asking the user to repeat
  decisions or standing instructions already recorded here.
- Preserve every user file and pre-existing worktree change. Never delete all files,
  broad directory trees, unrelated files, user data, or system data. Never run
  broad cleanup, disk-reset, operating-system-reset, `git reset --hard`, or
  history-rewriting commands unless the user explicitly requests the exact action
  after its impact is explained.
- Delete only a specific temporary or generated path created by the development
  workflow, and only after resolving and checking that the path is inside the
  intended repository or tool cache. Prefer non-destructive cleanup.
- Perform only actions needed to develop, test, document, or safely maintain this
  repository. Do not make unrelated system changes.
- Install a required development tool without interrupting the user when it is from
  an official or reputable source, scoped to the user or project where practical,
  and its purpose and version can be verified. Pin versions and verify checksums or
  signatures where available. Do not install unrelated software or weaken system
  security settings.
- After each coherent change passes its relevant tests, update
  `docs/implementation-status.md` and `docs/continuation-guide.md` when their facts
  changed, then create a focused descriptive commit. Do not bundle unrelated work
  or leave verified changes uncommitted without recording the exact blocker.
- Before committing, inspect the diff, run `git diff --check`, and run the relevant
  formatting, lint, test, documentation, and demo gates. Do not amend or rewrite
  existing commits unless the user explicitly asks.
- Before ending a development session, make the worktree and handoff unambiguous:
  record the active phase, completed work, passed tests, remaining limitations, and
  exact next task in `docs/implementation-status.md` and
  `docs/continuation-guide.md`. Immediately persist any new standing user
  instruction in `AGENTS.md` so a fresh session inherits it.

## Consensus and slashing rules

- Slashing requires objective signed evidence.
- Severe evidence includes conflicting signed votes/blocks, objectively invalid signed transitions, and fraudulent signed bridge messages.
- Downtime/late participation receives lost rewards and softer penalties.
- Coordinated provable attacks may receive correlated penalties.
- Never implement subjective accusation-based slashing.
- A label such as “51% attack” is not evidence by itself.
- No zero-collateral block-producing validator path belongs in the new protocol.
- A validator pool activates only at 100 WEBC or more total active stake.
- At activation the operator supplies at least 20 WEBC, and at all times at least 20% of the pool's active stake.
- Each delegator must delegate at least 1 WEBC per active delegation position.

## Parallelism and application isolation

- Use a unified versioned state-key model for accounts, balances, objects, applications, and protocol state.
- Transactions must declare exact read-only and writable keys.
- Runtime undeclared access fails and rolls back.
- Independent application namespaces should schedule and price independently.
- Do not create one writable global token object for ordinary transfers.
- Shared hot state must be sharded/bucketed where semantics allow.
- Support independent wallet authorization/nonce lanes for concurrent multi-site use.
- Keep a bounded network-wide floor/fair-capacity policy for global bandwidth attacks.

## Smart contracts and external web actions

- Rust native modules implement security-critical core operations first.
- The public contract VM/language is a technical gate, not decided by preference.
- Benchmark restricted WASM/Rust, Move VM, and EVM/Solidity as described in `docs/development-plan.md`.
- Contracts never directly access the web, local files, wall-clock time, or device randomness.
- Browser/server agents perform file transfer, button actions, webhooks, APIs, and headless work based on on-chain events and signed receipts.
- File content normally stays off-chain; commit hashes and permissions on-chain.

## Wallet and post-quantum rules

- Use versioned authorization policies rather than binding an address forever to one signature algorithm.
- Every standard wallet includes a post-quantum root/recovery path from creation.
- ML-DSA is an initial candidate, not an unaudited guarantee.
- Benchmark strict post-quantum transactions, limited session keys, and proof aggregation.
- Host websites must not receive seeds/private keys.
- Signing UI must show origin, action, recipient, amount, asset, and maximum fee.
- Use standard mnemonic/derivation/keystore practices and audited libraries.

## Bridge rules

- Required directions:
  - native WEBC lock -> wrapped WEBC mint on Ethereum/Solana;
  - wrapped WEBC burn -> native WEBC release;
  - supported external asset lock -> WEBC representation mint;
  - WEBC representation burn -> origin asset release.
- Ethereum bridge contracts are Solidity; Solana bridge programs are Rust.
- Every message includes source/destination domains, nonce, asset identity, amount, recipient, source transaction, and replay protection.
- Generic token support does not mean every malicious/non-standard token is safe.
- Use mock assets until the production bridge passes separate audits and approval.

## Validation expectations

As tooling becomes available, run the relevant subset and report anything unavailable:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo run -p webc-node -- demo
```

For TypeScript packages, run package build/tests after every SDK or wire change.

## Immediate next work

Follow `docs/development-plan.md` for the phase order, and read
`docs/continuation-guide.md` for the verified checkpoint and the **exact next
task** — that file and `docs/implementation-status.md` are the single live owners
of "what is done / what is next." This section deliberately does NOT restate the
phase status, because a second copy rots into a contradiction (see pitfall 8).

The 2026-07-17 documentation overhaul realigned every document to
`WEBC-DEFINITION.md` and rebuilt the development plan (19 phases; 0–7 keep
their historical numbers). The **Phase 4 consensus review findings C1–C7 are
now all resolved** (see `docs/review/findings.md` for the per-finding commit
hashes), along with the `cargo-deny` supply-chain gate, the `pnpm audit`
JS-advisory gate, and the `cargo-fuzz` targets. The next session **resumes
implementation work autonomously** from `docs/continuation-guide.md` "Exact
next work" — the remaining Phase 4 items are a reference-machine finality
benchmark (needs real hardware) and an optional multi-node-over-TCP Byzantine
integration test, after which Phase 4 is done and Phase 5 economics begins.
Reproduce each finding with a failing test before fixing it. The session
chooses and sequences work within the plan on its own; it does not stop to ask
permission between items. Do not skip ahead to the contract runtime, Weft, the
DEX, the oracle, ZK, or real-fund bridges before their own phase gates.

## User decisions still required later

Do not ask prematurely. Ask only when the relevant phase is ready to freeze:

- production bridge trust/proof model for real funds;
- any change to the decided genesis distribution (definition §15.38) or
  monetary policy;
- any mainnet governance emergency-power design;
- **slashing severity percentages and the downtime-penalty schedule** — economic
  policy of the same class as inflation; bring numbers with a threat model at the
  Phase 5 economics freeze, not before;
- the **§15.2 bootstrap-phase issuance** proposal (issuance keyed to staked
  amount during bootstrap) — decide at the Phase 5 economics freeze;
- any **hardware-floor trade-off** the §15.42 speed targets turn out to
  require (the definition forbids buying speed by silently raising the floor);
- renaming **Weft** before public branding (trademark/domain search first —
  §15.43).

Already decided — do not re-ask: the distribution allocation and channel
rules (§15.33/15.38), the contract-language sequencing (interim Rust-eDSL
first, Weft later over the same seam — Phase 7a/7b), the Weft design
commitments (§15.41/15.43/15.44), batch-settlement semantics (§15.37), and
the MEV revenue policy (§15.37).

See `docs/review/2026-07-16-plan-review.md` §5 for the framing of the open owner
decisions. Technical gates such as epoch duration, committee size, fee constants,
VM, proof backend, and block limits should be decided with specifications,
benchmarks, threat models, and tests rather than pushed to the user without
evidence.
