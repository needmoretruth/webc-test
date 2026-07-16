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

## Planned ADRs (from the 2026-07-16 plan review)

These are recommended but not yet written. Author each as the corresponding work
is picked up; details and rationale are in `docs/review/2026-07-16-plan-review.md`
§4 and §6. Number them from ADR-0009 in the order they are written.

- **Consensus block-validity + safe driver** — the `valid(v)` predicate before
  prevote/lock/finalize, non-silent handling of failed finalized-block import, and
  a durable vote/lock WAL to prevent crash-restart self-equivocation (findings
  C1/C2/C4).
- **Bounded consensus message admission** — reject/park future-round messages and
  cap per-height round memory (finding C3).
- **Equivocation-to-slash evidence pipeline** — who submits evidence, whether an
  evidence root is committed by the header, dedup/expiry window, and interaction
  with the unbonding slashable window.
- **Committee sampling** — rotating stake-weighted sub-committee selection (VRF/
  sortition) with an honest-super-majority security argument, keeping the finality
  path committee-parameterized.
- **Historical-state / archival strategy** — state snapshots/deltas for proofs,
  sync, and the light client, decided before the proofs phase.
- **Epoch validator-set transition + weak-subjectivity checkpoint** — who signs the
  certificate for a set-changing block, and safe long-range sync assumptions.
- **Node key management** — validator/consensus key provisioning via a permissioned
  keystore file (never argv/env), zeroization where practical.
