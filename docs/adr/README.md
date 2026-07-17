# WEBC architecture decision records

These records contain technical implementation decisions. Confirmed product or
economic policy remains authoritative only in `docs/decision-record.md` and is
never changed by an ADR.

An ADR is replaced by a new numbered ADR rather than silently rewritten after
code depends on it. Every replacement states compatibility and migration rules.

- [ADR-0001: versioned state](0001-versioned-state.md)
- [ADR-0002: signed BFT consensus](0002-signed-bft-consensus.md)
- [ADR-0003: fee accounting](0003-fee-accounting.md)
- [ADR-0004: wallet authorization](0004-wallet-authorization.md)
- [ADR-0005: replaceable proofs](0005-replaceable-proofs.md)
- [ADR-0006: contract runtime gate](0006-contract-runtime-gate.md)
- [ADR-0007: bridge safety boundary](0007-bridge-safety-boundary.md)
- [ADR-0008: stake lifecycle and exit queue](0008-stake-lifecycle-and-exit-queue.md)
- [ADR-0009: node and validator key management](0009-node-key-management.md)
- [ADR-0010: committee sampling](0010-committee-sampling.md)
- [ADR-0011: historical state, archival, and weak-subjectivity sync](0011-historical-state-and-weak-subjectivity.md)
- [ADR-0012: inactivity leak and slashing posture](0012-inactivity-leak-and-slashing.md)
- [ADR-0013: hot/cold storage tiering boundary](0013-hot-cold-storage-tiering.md)
- [ADR-0014: contract runtime](0014-contract-runtime.md)

## Planned ADRs (from the 2026-07-16 plan review)

Status of each recommended ADR from the review (details in
`docs/review/2026-07-16-plan-review.md` §4/§6):

- **Consensus block-validity + safe driver** (C1/C2/C4), **bounded consensus
  message admission** (C3), and the **equivocation-to-slash evidence pipeline** —
  IMPLEMENTED. Rather than a separate ADR, each is recorded per-finding in
  `docs/review/findings.md` with its reproducing test and commit hash (the
  `valid(v)` dry-run, typed `DriverExit`, sliding round window, durable
  vote/lock WAL, and header-committed evidence root). ADR-0002 remains the
  consensus overview.
- **Committee sampling** — [ADR-0010](0010-committee-sampling.md) (proposed;
  the finality path is already committee-parameterized).
- **Historical-state / archival strategy** and **epoch validator-set transition +
  weak-subjectivity checkpoint** — [ADR-0011](0011-historical-state-and-weak-subjectivity.md)
  (accepted, explicitly reviewable direction; multi-source comparison is
  separated from checkpoint verification so a later review can replace it).
- **Node key management** — [ADR-0009](0009-node-key-management.md) (accepted
  design; implementation gated to the validator-operations phase).
- **Off-chain contract-compilation invariant** — recorded in
  [ADR-0006](0006-contract-runtime-gate.md).
