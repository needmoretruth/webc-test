# ADR-0010: committee sampling

Status: proposed — records the design direction for the rotating-committee
phase. The current prototype's finality "committee" is the whole active
validator set; this ADR is not yet implemented and no code depends on it.

## Context

`WEBC-DEFINITION.md` commits to a **rotating stake-weighted sub-committee** for
finality (§8, §15.23/§15.28): permissionless stake-based BFT where a subset of
the active validator set runs each height's consensus, not the entire set. The
prototype today finalizes with the whole active set (`ValidatorSet::from_state`),
which is correct but does not scale: quorum certificates grow with the validator
count and every validator verifies every vote.

Two properties must hold simultaneously:

1. **Safety** — an adversary below the global Byzantine threshold must not be
   able to control ≥1/3 of any sampled committee's power (which would let it
   block finality) nor ≥2/3 (which would let it finalize conflicting blocks).
   Committee sampling trades an exact whole-set guarantee for a probabilistic
   one; the committee size must be chosen so the failure probability is
   negligible for the assumed stake distribution and adversary fraction.
2. **Determinism** — every honest node must derive the identical committee for a
   given height without communication, so the certificate a committee produces is
   verifiable by non-members. The prototype already has the deterministic
   ingredient: a domain-separated `WEBC_LEADER_SCHEDULE_V1` hash of `(height,
   round)` seeds the stake-weighted leader schedule with no wall-clock or RNG.

## Decision (direction)

- **Sampling function.** Derive the committee deterministically from a
  domain-separated seed bound to the epoch's validator-set snapshot and the
  height, stake-weighted so a validator's inclusion probability tracks its active
  stake. A verifiable random function (VRF) per validator, or a
  hash-of-snapshot-and-height sortition, are the two candidates; the choice is
  gated on a security analysis of grinding resistance (a leader must not be able
  to bias the seed by choosing block contents). Until that analysis exists this
  ADR does not pick one.
- **Snapshot binding.** The committee is sampled from the immutable per-epoch
  validator-set snapshot (already persisted per epoch by the node), so committee
  membership cannot shift mid-epoch with stake changes — the same reason the
  stake lifecycle uses epoch snapshots (ADR-0008).
- **Keep the finality path committee-parameterized.** The certificate
  verification, quorum arithmetic (`has_two_thirds_power`, finding C8), and
  equivocation checks already operate over "a validator set with power"; they
  must stay parameterized over *the committee for this height*, not hard-wired to
  the whole active set, so switching from whole-set to sampled committee is a
  change of which set is passed in, not a rewrite of the safety-critical code.

## Consequences

- Certificates and per-height verification cost become bounded by the committee
  size, not the validator count — the scalability the definition requires.
- Safety becomes probabilistic; the committee size is a technical gate decided by
  a threat model and the stake distribution, to be fixed with evidence at the
  rotating-committee phase (not pushed to the owner as a bare constant).
- The seed's grinding resistance is the load-bearing security argument and must
  be settled before implementation. Weak-subjectivity and set-transition
  interactions are covered by ADR-0011.
