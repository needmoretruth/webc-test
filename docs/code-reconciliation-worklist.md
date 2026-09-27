# Code reconciliation worklist

Date: 2026-07-17. Scope rule: this document only *records* where the current
code diverges from `WEBC-DEFINITION.md`; it changes no code. Each item names
the definition source, the code reality (verified this session unless marked
"per status docs"), the phase where the fix belongs, and a priority:

- **P0** — blocks correctness/safety of what already runs, or gets much more
  expensive if formats freeze first;
- **P1** — required for launch scope; build at its phase;
- **P2** — decided but deferrable (phase-2 or benchmark-gated).

The Phase 4 consensus-safety findings (C1–C8) are tracked in
`docs/review/findings.md`, not duplicated here.

## P0 — do before formats freeze or the next network run

1. **Variable-length amount encoding at rest and on the wire** (§15.14,
   §15.19). Code: `Amount(pub u128)` / `BaseUnits(u128)` exist (u128 is
   done), but wire/storage use fixed-int bincode — amounts serialize as
   fixed 16 bytes; no varint layer exists anywhere (grep-verified). This is
   a wire/storage format change → version bump + cross-language fixtures;
   every format frozen before it lands makes it costlier. Phase 6 at the
   latest; ideally with the next planned wire-version bump.
2. **256-bit intermediates for multiply/divide amount paths** (§15.14).
   Code: no widening-multiply helper exists; current arithmetic is checked
   u128 add/sub (fees.rs `half_split` etc.). Low risk today (no AMM math in
   the tree), but the helper + convention must exist **before** Phase 8 pool
   math is written, or overflow bugs get designed in. Land the shared
   `webc-chain` widening-math utility with property tests by Phase 7a.
   **Done (2026-09-26, `441bc22`):** `Amount::checked_mul_ratio` computes the
   exact floor over a 256-bit intermediate, with oracle and sweep tests.
3. **Committee sampling + aggregated votes are unbuilt while the validator
   set is uncapped** (§8, §15.19, §15.28). Code: the finality certificate
   requires >2/3 of the *whole* validator-set snapshot and carries
   per-validator signatures (O(N) votes, O(N²) gossip). Already flagged in
   `architecture.md`; repeated here because §15.19 makes vote aggregation a
   decided requirement, not an optimization. Needs its own ADR (selection
   algorithm + honest-super-majority argument + aggregation scheme);
   finality path should become committee-parameterized now so the change is
   not a rewrite. Phase 4/11.

## P1 — launch-scope systems with no code yet

4. **Fast path for single-owner operations** (§15.40, §15.42 — launch
   scope). Code: nothing exists; all operations flow through consensus.
   Phase 11; protocol design scoped in `speed-roadmap.md`. The declared
   access-set machinery (exists) is the eligibility substrate — keep it
   exact.
5. **DEX batch settlement** (§15.13, §15.18, §15.37). Code: no pool, intent,
   registry, or batch-clearing code exists. Phase 8
   (`dex-batch-settlement.md`). Watch item: nothing in the mempool/block
   builder may ever offer per-transaction swap execution against a shared
   pool — the mandatory-batch rule forbids a bypass lane by construction.
6. **Oracle module with economics** (§15.17, §15.21). Code: none. Phase 7a
   (`oracle-economics.md`).
7. **Agent mandates + service registry** (§15.5, §15.32). Code: none (the
   session-key system is a different primitive — own-device flows, not
   distinct agent identities). Phase 9 (`agent-commerce.md`).
8. **Storage deposit + deletion rebate** (§15.22). Code: fees are split
   50/50 burn/reward (`fees.rs`, matches §7) but storage is charged as flat
   growth cost with no deposit locking or delete refund; no occupancy
   accounting exists. Phase 6; must enter the supply invariant report.
9. **zstd compression (wire + storage) and compact-block relay** (§15.19,
   §15.24, §15.29 — "on by default" is decided). Code: no compression
   anywhere (grep-verified); gossip floods full transaction bodies; blocks
   carry full bodies. Phase 11 frugality set (wire), storage layer can adopt
   zstd earlier behind the `KvStore` seam.
10. **Distribution machinery** (§15.33, §15.38): stake-locked grant records,
    vest-by-operation unlocks, non-transferable expiring fee credits,
    airdrop claim verification (external-wallet signature proofs, per-wave
    Merkle snapshots), usage-subsidy underwriting hooks in the sponsorship
    path. Code: none. Primitives in Phase 5, program machinery by Phase 16
    (`distribution-program.md`).
11. **Sponsorship/paymaster protocol caps** (§7, §15.35). Code: wallet-side
    per-origin grants/limits exist (Phase 2 SDK), but there is no on-chain
    sponsor account or protocol-enforced per-user/app/operation/day caps.
    Phase 6.

## P2 — decided, deferrable

12. **Mysticeti-class DAG-BFT consensus** (§15.40 track 2). Code: the
    consensus is a Tendermint-style single-height multi-round machine
    (`webc-chain::round`) — sound as the conservative baseline. Migration is
    ADR + like-for-like benchmark on reference hardware (Phase 11); do not
    rewrite by default. The ~1s block / 1–2s finality targets are claims
    only after benchmarks.
13. **Block-interval parameter** (§15.42): node auto-seal and devnet cadence
    are 2s; the ~1s target is benchmark-gated (Phase 11). Keep the interval
    a config parameter (it is), never a hardcoded constant in consensus
    logic.
14. **Hot/cold storage tiering + archive interface** (§15.22): `ChainStore`
    keeps latest-only state (also blocks proofs — see the architecture gap).
    ADR in Phase 6, implementation by Phase 10 (proofs need historical
    state anyway).
15. **Walrus-style blob layer** (§15.27): none; Phase 19.
16. **zk state compression** (§15.25, §15.29): none; Phase 19, only if
    mass-tiny-object applications emerge.
17. **Official validator container image + keystore provisioning**
    (§15.26): none; devnet uses per-process/hardcoded devnet keys (also a
    security-doc finding). Phase 15.
18. **Fee-credit spending path** (§15.12): fee payment knows nothing of
    non-transferable credits; needed by Phase 16 with the ecosystem fund.
19. **TypeScript SDK parity for the above**: amounts already flow as
    BigInt-compatible strings (per status docs); every new wire format
    (varint amounts, intents, mandates, certificates) needs cross-language
    fixtures in the same commit, per AGENTS.md conventions.

## Explicit non-items

- **u128 amounts** — already implemented (`webc-chain/src/amount.rs`,
  `protocol.rs`); the widening half of §15.14 landed in `441bc22` (item 2).
- **50/50 fee split, inflation curve, staking rules (100/20/80/1),
  ADR-0008 exit lifecycle, declared access enforcement, hybrid
  account/object state, session keys, PQ recovery root** — code matches the
  definition; no reconciliation needed.
- **PoH** — already absent, matching §8.
- Consensus C1–C8 safety findings — owned by `docs/review/findings.md`.
