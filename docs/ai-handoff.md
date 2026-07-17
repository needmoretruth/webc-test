# WEBC AI handoff

This file intentionally contains no separate conversation summary. Separate summaries become stale and can silently restore rejected decisions.

Use these sources in order:

1. `WEBC-DEFINITION.md` (repository root) for every product, economic,
   experience, and functional design decision — read §16 first; §15 wins over
   older sections; the file is read-only;
2. `AGENTS.md` for repository rules and immediate scope;
3. `docs/decision-record.md` for security-adjacent decisions and
   implementation gates (it defers to the definition for product decisions);
4. `docs/development-plan.md` for exact phase order and acceptance gates;
5. `docs/whitepaper.md` for the full design;
6. `docs/implementation-status.md` for what the current code really does;
7. `docs/index.md` and the topic document for architecture, economics, bridges,
   or security;
8. `docs/continuation-guide.md` for the verified checkpoint and exact next task.

The current code is a reusable prototype, not the confirmed protocol. In
particular, do not revive 9 decimals, six-month halving, zero-collateral
validators, PoH, global fee contention, or a trusted-relayer production
bridge. Also do not revive superseded documentation claims: the 30/70
distribution split (superseded by the 25/5/30/15/15/10 allocation,
definition §15.38) or 6–8s finality as the *only* speed framing (the decided
engineering targets are two-track — definition §15.42 — while 2s/6–8s remains
the conservative public claim until benchmarks).

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
