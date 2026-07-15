# WEBC agent instructions

This repository is the prototype foundation for **WEBC / WEB COIN**, an independent Rust Layer-1 blockchain for browser- and website-native payments and applications.

## How to work in this repository — read this first

**This file is the single entry point.** Reading it and the documents it points to
is enough to work correctly in every situation — a brand-new session, continuing an
existing one, or restarting after a context compaction. If the user says only
"continue" / "이어서 해", this section tells you exactly what to do.

### On every session start (new, resumed, or post-compaction), do this in order
1. Read this `AGENTS.md` fully.
2. Read `docs/decision-record.md` — confirmed user decisions; it wins over any code, comment, or summary that disagrees.
3. Read `docs/continuation-guide.md` — the verified checkpoint and the **exact next task**. This is the live "what to do next" pointer.
4. Read `docs/implementation-status.md` — what the code actually implements today (vs. what is still missing or unsafe).
5. Run `git log --oneline -15` and `git status --short --branch` to see the real current state on disk and the branch.
6. For the specific task, read the one topic document it needs (see **Required reading order** below and `docs/index.md`).

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
2. `docs/decision-record.md`
3. `docs/development-plan.md`
4. `docs/whitepaper.md`
5. `docs/implementation-status.md`
6. `docs/index.md`
7. the specific supporting document for the task:
   - `docs/architecture.md`
   - `docs/tokenomics.md`
   - `docs/bridge.md`
   - `docs/security.md`

`docs/decision-record.md` is authoritative when older documentation or the current prototype conflicts with confirmed product decisions.

## Project identity

- Project: `WEBC`
- Coin: `WEB COIN`
- Ticker: `WEBC`
- Independent custom Layer 1, not merely a token on another chain
- Rust is the core protocol/node language
- TypeScript is the primary website SDK language
- Global audience

## Confirmed protocol/product decisions

- Genesis supply: `10,000,000 WEBC`
- Native precision: 12 decimals
- Initial inflation: 10% annually
- Inflation-rate decay: multiply the rate by 0.8 each year
- Long-term inflation floor: 1%
- Genesis distribution intent:
  - 30% public devnet/testnet contributors after a formally announced start;
  - 70% broad global public distribution;
  - no fixed developer/founder/foundation/investor/private-sale allocation.
- Consensus: permissionless delegated Proof of Stake with BFT-style finality
- PoH: not part of the WEBC protocol
- Block target: 2 seconds
- Normal finality target: 6-8 seconds
- Validator pool activation minimum: 100 WEBC total active stake
- Validator operator minimum at activation: 20 WEBC
- Validator operator self-stake: at least 20% of pool stake
- Delegated stake: at most 80% of pool stake
- Minimum individual delegation: 1 WEBC
- Validator stake is required on devnet and mainnet; devnet uses a valueless faucet
- Unstaking target: about 7 minutes devnet, about 7 days mainnet
- Base fees: 50% burned, 50% validator/delegator rewards
- Dynamic localized congestion pricing and sponsored fees
- Parallel execution is a core requirement
- Hybrid state: account-style fungible balances plus object-style application/NFT state
- Every transaction declares enforced read/write state access
- Website/application namespaces must avoid unrelated cross-site state and fee contention
- Browser wallet secrets stay isolated from host-site JavaScript
- ZK/light-client direction is inspired by Mina
- Post-quantum-ready versioned wallet/account authorization is required from genesis
- Bidirectional Ethereum/Solana bridges and wrapped WEBC are required
- Real bridge funds remain disabled until separately designed, audited, limited, monitored, and approved

## Things agents must not assume are already implemented

The existing prototype still uses old assumptions. Do not treat passing legacy tests as proof of the new design.

Known mismatches include:

- objective evidence exists only for double votes; other slashing classes remain disabled;
- localized congestion fee markets are incomplete;
- trusted-relayer bridge logic that is only a mock/prototype.

Read `docs/implementation-status.md` for the audit summary.

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

- Module, function, and type documentation describes the final behavior.
- Relevant unit, integration, property, malformed-input, adversarial, and regression tests pass.
- Formatting, strict linting, and documentation generation pass without unexplained warnings.
- Consensus changes include deterministic test vectors and cross-language byte fixtures when TypeScript shares the format.
- Security assumptions and remaining limitations are recorded in code and the relevant document.
- `docs/implementation-status.md` accurately states what is implemented and what remains missing.

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

Follow `docs/development-plan.md`.

Phase 0 and Phase 1 are complete, and Phase 2 is active. The exact verified checkpoint and next
unfinished task are maintained in `docs/continuation-guide.md` and
`docs/implementation-status.md`. Continue from there; do not restart completed work.

The versioned on-chain account authorization gate is now **implemented**: policy
+ post-quantum root field, a real ML-DSA-65 root-**signature** gate on session-key
install/revoke, constrained session keys (budgets, lane binding, epoch expiry with
epoch-boundary pruning), primary active-key recovery/rotation, recovery-root
rotation, the browser/SDK operation + subkey surface with cross-language fixtures,
and an indicative `webc-node bench`. The only remaining session-key item is
reference-machine benchmark numbers (this cloud container is not a reference
machine). See `docs/session-keys-next-steps.md`.

Durable encrypted per-origin wallet **permission storage** and **automatic
authorization-lane setup** are now implemented too (`sdk/webc-js/src/permission-store.ts`
and the `persistence`/`restoredGrants` wiring in `wallet-service.ts`), which was
the last outstanding Phase 2 wallet-wire/secret-isolation gate. With the
session-key gate, Phase 2's acceptance conditions are met except reference-machine
benchmarks.

**Phase 3 is largely complete on the Rust node side** (`crates/webc-storage` +
`crates/webc-node`): the `KvStore` storage seam with an in-memory backend and a
durable crash-safe `RedbKvStore` (redb, reused not hand-rolled), a typed
`ChainStore` with atomic per-block commits and startup consistency checks, a
restartable single-proposer `Node`, a validating fee-priority `Mempool`, a
transport-independent `NodeService`, an axum/tokio HTTP+WebSocket API under `/v1`
with a devnet faucet, and a `webc-node run` command (redb-backed, auto-sealing,
restart-recovery smoke-tested). Rust gate: 176 tests.

The browser side is done too: `sdk/webc-js/src/node-client.ts` (`WebcNodeClient`,
a typed HTTP/WS client for `/v1`) and `sdk/webc-js/demo/index.html` (a static
reference site: create wallet → faucet → proof → signed transfer → live finality
over WebSocket). Verified end to end against a running node.

**Phase 3 is complete. Phase 4 (networking + signed BFT consensus) is in
progress**, split into three stages: A-1 networking plumbing, A-2 signed BFT
consensus core, A-3 robustness.

**Phase 4 A-1 is complete**: a new `crates/webc-net` crate (the swappable
transport seam) with the WEBC gossip wire format, mutual challenge/response peer
authentication over Ed25519 identity keys, and authenticated TCP flood gossip
behind a `NetworkHandle` (reusing tokio + tokio-util framing, owning the protocol
pieces), plus node glue (`admit_network_transaction`, `AppState::with_network`,
`run_gossip_pump`, and `webc-node run --p2p-listen/--peer`). A transaction
submitted to one node reaches every peer's mempool. Rust gate: 192 tests.

**The next step is Phase 4 A-2 (signed BFT consensus core)** in
`docs/development-plan.md`: extend `NetMessage` with proposals/votes/certs, a
deterministic leader schedule over a persisted stake snapshot (activating the
already-wired `Table::ValidatorSets` writer), and signed prevote/precommit
producing a finality certificate. Do not skip to contract runtime, ZK, or real
bridges before their own gates. The only broad open item across phases is
reference-machine benchmark numbers (this cloud container cannot produce them
honestly). See `docs/continuation-guide.md` for the exact next step.

## User decisions still required later

Do not ask prematurely. Ask only when the relevant phase is ready to freeze:

- final public distribution/anti-duplicate-account specification;
- production bridge trust/proof model for real funds;
- any change to confirmed genesis distribution or monetary policy;
- any mainnet governance emergency-power design.

Technical gates such as epoch duration, committee size, fee constants, VM, proof backend, and block limits should be decided with specifications, benchmarks, threat models, and tests rather than pushed to the user without evidence.
