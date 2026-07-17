# ADR-0011: historical state, archival, and weak-subjectivity sync

Status: accepted direction (owner-approved source model 2026-07-17); technical
details and implementation remain pending and reviewable. The prototype keeps
latest-only state and certificate-gated same-set sync.

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

## Approved source direction and replaceable boundary

The owner approved the following provisional source direction on 2026-07-17,
while explicitly requiring that later review can replace it:

- an official release may provide a checkpoint, but it is optional and must not
  become the only trusted source;
- the client also obtains checkpoints from independently operated public nodes
  or services and compares the answers;
- an operator may explicitly supply a checkpoint from a source they trust;
- disagreement between sources stops startup and produces a visible warning
  instead of silently choosing one answer.

In plain language, the checkpoint is the recent known-good “first bookmark” a
new light node uses before it can verify later history itself.

The implementation must separate three responsibilities behind narrow,
versioned interfaces: (1) checkpoint data and its validation, (2) sources that
retrieve candidates, and (3) the policy that decides whether the candidates are
acceptable. Consensus and proof verification depend only on the validated
checkpoint, never on a particular URL, publisher, threshold, or governance
service. This permits a later audit to replace multi-source comparison with a
better policy without changing block execution or proof formats.

The approved direction removes the previously deferred owner choice. Exact
source count, publisher authentication, comparison threshold, schema, key
rotation, transport, and limits remain delegated technical work. Implementers
must record what they choose and why, including rejected alternatives, threat
model, compatibility/migration plan, and tests. No technical detail in this ADR
is immutable merely because it was implemented first.

## Consequences

- Storage grows for archival nodes; pruned nodes stay small but can only serve
  and trust history back to their weak-subjectivity window. Both are supported by
  making retention an operator choice behind the storage seam.
- No node accepts an alternate history older than its checkpoint, closing the
  long-range/retired-key forgery vector without a subjective fork choice.
- Comparing independent sources favors safety over automatic startup: a missing
  or disagreeing source may delay a new node, but cannot be ignored silently.
- The source and acceptance policy can evolve independently of the canonical
  checkpoint and certificate-verification code.
- Eclipse resistance (finding E5) is complementary: the network-layer bounds
  already landed (N1–N6 — handshake timeout, inbound/peer caps, per-peer rate
  limit), and peer scoring / inbound diversity / anti-eclipse peer selection are
  tracked for the same phase, since a node that can be eclipsed can be fed a
  hostile "checkpoint" regardless of this ADR's mechanism.
