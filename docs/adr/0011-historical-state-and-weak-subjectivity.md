# ADR-0011: historical state, archival, and weak-subjectivity sync

Status: proposed — records the design direction and the one owner-owned trust
decision for the state-proofs / long-range-sync phase. Not yet implemented; the
prototype keeps latest-only state and certificate-gated same-set sync.

## Context

Two gaps surfaced in the 2026-07-16 review (findings E4, and the P2 archival
item) that share one root: the prototype's `ChainStore` keeps **latest-only**
state, and state sync (finding C7) hands a late node a block plus a
`FinalityCertificate` that it verifies against **the current validator snapshot**.

- **Historical state (§4.2).** Light clients and inclusion/consistency proofs
  need historical state — snapshots or deltas at past heights — which latest-only
  storage cannot serve. This must be decided before the proofs phase so the
  storage layout is not migrated twice.
- **Weak subjectivity (§4.5, E4).** Validator sets are per-epoch snapshots and
  keys rotate. A brand-new node has no trusted anchor: it must trust whoever
  answers its first sync. Worse, a set-changing block's certificate is signed by
  the *outgoing* set, and validators whose stake has fully exited still hold their
  old keys — the classic long-range attack, where an adversary who acquires enough
  retired keys forges an alternate history from an old fork point.

## Decision (direction)

### Historical state / archival

- Keep the current atomic per-block commit and latest-state snapshot as the hot
  path. Add an **archival tier**: periodic full state snapshots plus per-block
  deltas, keyed by height, behind the existing `KvStore` seam so the hot path is
  unchanged and an operator chooses the retention depth (a full-archive node vs. a
  pruned node keeping only a weak-subjectivity window). State proofs and light
  clients read from the archival tier.
- Reuse the existing per-subtree Merkle roots (already in `state_root`) as the
  proof structure, so a historical proof is "the account/validator/… root at
  height H plus a Merkle path," verifiable by the same `verify_merkle_proof`
  (bounded by finding E3) the light client already uses.

### Epoch validator-set transition + weak-subjectivity checkpoint

- A **set-changing block is finalized by the outgoing (current-epoch) committee**,
  and its certificate binds the *new* validator-set commitment, so a verifier who
  trusts epoch N's set can authenticate the transition to epoch N+1 by one
  certificate — the standard chain-of-certificates that makes long-range sync
  safe forward from a trusted point.
- Long-range sync is therefore only safe **from a trusted anchor**: a
  weak-subjectivity checkpoint (a recent `(height, state_root, validator-set
  commitment)`) that a syncing node must obtain out of band, within a
  weak-subjectivity period shorter than the unbonding/slashable window (ADR-0008),
  so retired keys cannot forge history that a node would accept as newer than its
  checkpoint.

## The one owner-owned decision

**Where the trust anchor comes from** is a trust-model decision of the same class
as the production-bridge trust model, and is deferred to the owner at this
phase's freeze (per `docs/decision-record.md` and the AGENTS.md deferred-decision
list). Candidates to present with trade-offs: shipping a signed checkpoint in
release artifacts; a small governance/foundation multisig that publishes
checkpoints; or requiring the operator to supply a checkpoint from a source they
already trust. This ADR fixes the *mechanism* (certificate-chained set
transitions + a weak-subjectivity window shorter than unbonding); it does not
choose the anchor source.

## Consequences

- Storage grows for archival nodes; pruned nodes stay small but can only serve
  and trust history back to their weak-subjectivity window. Both are supported by
  making retention an operator choice behind the storage seam.
- No node accepts an alternate history older than its checkpoint, closing the
  long-range/retired-key forgery vector without a subjective fork choice.
- Eclipse resistance (finding E5) is complementary: the network-layer bounds
  already landed (N1–N6 — handshake timeout, inbound/peer caps, per-peer rate
  limit), and peer scoring / inbound diversity / anti-eclipse peer selection are
  tracked for the same phase, since a node that can be eclipsed can be fed a
  hostile "checkpoint" regardless of this ADR's mechanism.
