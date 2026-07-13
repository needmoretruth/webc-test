# WEBC AI handoff

This file intentionally contains no separate conversation summary. Separate summaries become stale and can silently restore rejected decisions.

Use these sources in order:

1. `AGENTS.md` for repository rules and immediate scope;
2. `docs/decision-record.md` for confirmed user decisions;
3. `docs/development-plan.md` for exact phase order and acceptance gates;
4. `docs/whitepaper.md` for the full design;
5. `docs/implementation-status.md` for what the current code really does;
6. `docs/index.md` and the topic document for architecture, economics, bridges,
   or security;
7. `docs/continuation-guide.md` for the verified checkpoint and exact next task.

The current code is a reusable prototype, not the confirmed protocol. In particular, do not revive 9 decimals, six-month halving, zero-collateral validators, PoH, global fee contention, or a trusted-relayer production bridge.

When talking to the user, avoid unexplained technical language. When implementing, distinguish clearly among:

- confirmed product decisions;
- technical choices that require benchmarks;
- features present only in the legacy prototype;
- features planned but not implemented;
- features unsafe for real funds.

Current phase and checkpoint facts intentionally live only in
`docs/implementation-status.md` and `docs/continuation-guide.md`; use `git status`
and `git log` to confirm them. Do not copy a phase summary into this file because
it would become another stale source of truth.

Standing user instructions also survive through `AGENTS.md`: never broadly delete
files or user/system data, perform only development-related actions, install safe
required development tools when needed, preserve existing changes, test each
coherent change, and commit it promptly. If the user says only “read `AGENTS.md`
and continue,” resume from the first recorded incomplete task without asking them
to reconstruct the previous session.
