# WEBC continuation guide

## Read first

1. `AGENTS.md`
2. `docs/decision-record.md`
3. `docs/development-plan.md`
4. `docs/whitepaper.md`
5. `docs/implementation-status.md`
6. `docs/index.md`
7. the supporting architecture, economics, bridge, or security document needed
   by the current task

The decision record wins when old code, tests, comments, or documents disagree.

Then inspect `git status --short --branch` and `git log -5 --oneline`. Preserve
all existing changes, determine the first incomplete item below, and continue it
without asking the user to restate recorded decisions or safety rules.

## What the user has already decided

Do not reopen confirmed product choices without new evidence. Important examples are the independent L1, Rust core, 10 million genesis supply, 12 decimals, 10% inflation with yearly 20% relative decline to a 1% floor, 100 WEBC validator-pool activation, 20 WEBC operator minimum at activation, continuous 20% operator self-stake, 1 WEBC minimum delegation, no PoH, 2-second blocks, parallel app isolation, hybrid account/object state, browser wallet isolation, post-quantum-ready authorization, and bidirectional Ethereum/Solana bridges.

Use simple Korean when speaking to the user. Explain unavoidable technical terms immediately.

## Current verified checkpoint

Phase 0 and Phase 1 are complete, and Phase 2 is active. Always use `git log` to discover the
current branch tip; the checkpoint list below names implementation history, not
an instruction to reset or return to an older commit.

Completed Phase 1 work, in implementation order:

1. `c56d466` introduced 12-decimal native amounts and the confirmed annual
   inflation curve.
2. `eb48737` made local block construction atomic and enforced configured unit
   and canonical-byte limits.
3. `a7b01ea` removed synthetic bootstrap voting power and enforced validator-pool
   activation, operator stake, delegation ratio, and minimum-delegation rules.
4. `f2dba9d` made genesis debit operator stake, reject duplicate accounts, and
   reconcile gross native supply with an explicit invariant report.
5. The versioned-state milestone introduced exact logical keys, runtime access
   recording, fail-closed declaration checks, namespace scheduling tests, and a
   shared Rust/TypeScript canonical transfer fixture. Its commit follows the
   documentation handoff commit `7830145` in `git log`.
6. The signed-evidence milestone replaced label-only slashing with two
   domain-separated signed consensus votes, registered-key verification,
   order-independent replay protection, adversarial tests, and a shared vote
   fixture. Locate its commit immediately after `baddaba` in `git log`.
7. The slash-accounting milestone atomically reconciled operator stake,
   delegator positions/accounts, validator aggregates, a state-root-committed
   slashed-unit bucket, and the supply report. Locate it after `9e76c0c`.

The current code remains prototype-only and unsafe for real funds.

This project runs in an ephemeral cloud container; the GitHub repository is the
single source of truth. Always push to the designated branch mid-work and before
ending, and never leave valuable work only on local disk. `target/`,
`node_modules/`, and `dist/` are intentionally git-ignored but fully regenerable
because `Cargo.lock`, `pnpm-lock.yaml`, `rust-toolchain.toml`, and `.node-version`
are committed (`cargo build`, `pnpm install`).

Latest verified gate: the Rust side (2026-07-15 prior run, this cloud
environment) passed `cargo fmt --check`, strict workspace Clippy (`-D warnings`),
133 Rust tests (120 `webc-chain` + 13 `webc-crypto`), rustdoc with warnings
denied, and `webc-node demo`; the permission-storage pass changed no Rust files,
so that gate is unaffected. The TypeScript SDK (2026-07-15, Node 22) builds and
passes 55/55 tests, the widget suite 3/3, plus the package-entry and
Markdown-link checks. The previously reported single SDK failure was a real
host-client schema bug (missing `authorization_policy_revision`), now fixed — not
a Node 22 WebCrypto gap; the suite is green on Node 22. Historical note: on a
Windows GNU host use `cargo +1.96.0-x86_64-pc-windows-gnu` (the MSVC target lacks
`link.exe`); the cloud Linux toolchain needs no override.

## Exact next work

The versioned on-chain authorization + constrained session-key gate is
**complete**. Do not redo any of it. What shipped (see
`docs/session-keys-implementation-plan.md`, `docs/session-keys-next-steps.md`, and
the Phase 2 section of `docs/implementation-status.md`):

- Versioned account authorization policy with a post-quantum recovery-root field.
- A real ML-DSA-65 root-**signature** gate (pinned `fips204` behind the
  replaceable `webc-crypto::mldsa` boundary) on session-key install/revoke, over
  `session_key_authorization_message` (`WEBC_SESSION_KEY_AUTHORIZATION_V1`, binding
  chain id, owner, policy revision, nonce, and action).
- Constrained session keys: per-use and cumulative amount and fee budgets, lane
  binding, epoch expiry with a deterministic epoch-boundary pruning sweep, and
  rotation invalidation.
- Primary active-key recovery/rotation (`RotateActiveTransactionKey`, recovery via
  a new-key-signed envelope + root signature) and recovery-root rotation
  (`RotatePostQuantumRoot`, current-root signature + active-key envelope). Both
  halves of the policy can be recovered independently; both had a clean isolated
  adversarial review.
- Browser/SDK surface: operation constructors, access lists, `deriveSessionKeyIdHex`,
  session-subkey generation, and epoch-based expiry display, with cross-language
  byte-parity fixtures.
- `webc-node bench` for an indicative (non-reference) ML-DSA-65 vs Ed25519 timing.

The single remaining session-key item: **reference-machine benchmark numbers**
(session-key vs Ed25519 transfer end to end, and ML-DSA verify/sign vs Ed25519),
which this cloud container cannot produce honestly. Publish reference numbers
before any performance claim.

Persistent encrypted wallet **permission storage** and **automatic
authorization-lane setup** are now **complete** in the SDK (the last outstanding
Phase 2 wallet-wire/secret-isolation gate). Do not redo them. What shipped:

- `sdk/webc-js/src/permission-store.ts`: an authenticated encrypted-at-rest store
  (v1) for per-origin grants (lane, scopes, limits, cumulative `spent_amount`),
  AES-256-GCM under an Argon2id key through the shared `argon2.ts` gate, bound to
  the wallet identity as AES-GCM additional data, with a strict bounded schema
  and a key-caching `openPermissionStore` port so per-spend saves need no
  repeated KDF.
- `TrustedWalletService` (`sdk/webc-js/src/wallet-service.ts`) gains optional
  `persistence` and `restoredGrants`: it restores dormant grants (lane + spend
  survive a restart; reconnect required before signing), persists after every
  connect/spend/revoke inside its serial queue, carries cumulative spend across
  reconnects (only revoke clears a grant), and rolls back on any durable-write
  failure so state never disagrees in the under-count direction.
- Fixed a real host-client schema bug found here: the connection and
  signed-transaction result parsers omitted `authorization_policy_revision`,
  which had failed the end-to-end exchange on every Node version (not a Node 22
  issue). SDK suite is now 55/55.

With this, Phase 2's acceptance conditions are met except reference-machine
benchmarks. The next milestone is **Phase 3** in `docs/development-plan.md`: a
local restartable node with storage traits, crash-safe transactional commits and
startup recovery, and HTTP/WebSocket developer APIs (health, account/object
queries, proofs, blocks, tx submission, subscriptions, fees, devnet faucet).
Define storage traits before choosing a database backend. Public contract VM, ZK
expansion, and real-fund bridge work stay disabled until their later gates.

## Working rules

- Preserve user changes in a dirty worktree.
- Never delete all files, broad directories, unrelated user data, or system data;
  never run broad cleanup or `git reset --hard`. Delete only a verified exact
  development-generated path inside its intended scope.
- Perform only repository development and necessary development-tool actions.
- Install required reputable development tools automatically when safe, prefer
  project/user scope, pin their versions, and verify their origin and integrity.
- Treat security and correctness as more important than speed or feature count.
- Keep protocol code deterministic and Rust-first.
- Keep modules focused, interfaces small, dependencies clear, and obsolete experiments quarantined.
- Add comments for reasons, invariants, security assumptions, and attack prevention rather than obvious syntax.
- Start every source file with its purpose, boundaries, data flow, and important security rules; document every public interface and its failure behavior.
- Use Rust wrapper types so amounts, block heights, epochs, nonces, chain IDs, and asset IDs cannot be mixed accidentally.
- Use typed errors, checked arithmetic, deterministic ordering, and canonical encoding; do not panic on hostile input.
- Forbid `unsafe` in protocol crates unless an isolated, reviewed exception includes a written safety argument and focused tests.
- Treat all external input as hostile and keep secrets out of logs.
- Use checked integer arithmetic.
- Add tests before or with each protocol repair.
- Update `docs/implementation-status.md` after material work.
- Commit each coherent, tested change promptly with a focused descriptive message.
- Before ending, record passed gates, remaining limitations, and the exact next
  task here so a fresh session can continue without relying on chat history.
- Record a user-approved product change in `docs/decision-record.md`.
- Never treat the existing trusted-relayer bridge as production-ready.
- Never claim TPS, finality, ZK, or quantum safety without measurements and complete coverage.

## Questions to postpone

The user does not need to choose technical constants now. Use benchmarks and public testnet evidence for epoch length, committee size, fee constants, block limits, and VM choice. Ask the user later only for decisions that truly change policy, especially final distribution rules, production bridge trust, or emergency governance powers.
