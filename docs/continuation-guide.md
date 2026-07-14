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

The 2026-07-13 continuation gate passed with the pinned GNU Rust toolchain:
`cargo fmt --check`, strict workspace Clippy, 77 Rust unit tests, Rust
documentation with warnings denied, and `webc-node demo`. Node.js 24.18.0 and
pnpm 11.7.0 passed both TypeScript builds, all 40 TypeScript tests, the emitted
ESM package-entry smoke test, and the local Markdown-link check. On this Windows host, explicitly use
`cargo +1.96.0-x86_64-pc-windows-gnu`; the default MSVC target has no installed
`link.exe` and is not the verified repository toolchain.

## Exact next work

Resume with the first incomplete item in this order:

1. Add versioned account authorization policies and the post-quantum root field,
   then benchmark the ML-DSA candidate before enabling any claim.
2. Add recovery, rotation, revocation, and constrained session-key state/tests.
   The constrained session-key design, data model, integration points, security
   invariants, test matrix, and staged build order are specified in
   `docs/session-keys-implementation-plan.md`; implement it in the staged order
   given there (§13), committing and testing each step before the next.

Do not start RPC, networking, a public VM, ZK, or a real bridge before the Phase
2 wallet wire and secret-isolation gates pass.

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
