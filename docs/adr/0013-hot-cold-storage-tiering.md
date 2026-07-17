# ADR-0013: hot/cold storage tiering boundary

Status: **proposed** — the Phase 6 plan calls for designing the hot/cold tiering
boundary (archive-node interface + proofs) as an ADR now, with implementation
allowed to lag (§15.22). This ADR fixes the *boundary* and the *interface*;
ADR-0011 already fixes the archival-sync and weak-subjectivity mechanics it
builds on.

## Context

WEBC prices storage as **occupancy** (ADR/§15.22 storage deposit + deletion
rebate): a byte-proportional deposit is locked on write and mostly refunded on
delete. For that to keep the *executing* state small and cheap, the node must be
able to keep only execution-relevant state in a fast **hot tier** and move
history and long-untouched data to a **cold/archive tier**, restoring on demand.
ADR-0011 established the archival tier (periodic full snapshots + per-block
deltas behind the `KvStore` seam) for historical-state proofs and long-range
sync. What is still unspecified — and what Phase 6 needs — is **where the hot/cold
line falls, how a node evicts across it, and the interface an archive node
exposes** so a pruned node can restore an item and prove it.

## Decision (direction)

### What is hot vs cold

- **Hot tier (every full node keeps):** the latest committed state needed to
  execute the next block — accounts, the active validator/delegation set and the
  current epoch snapshot, live objects, authorization lanes/policies/session
  keys, the protocol scalar counters, and the current per-subtree Merkle roots.
  This is exactly the state `state_root` commits, so the hot tier is
  self-verifying.
- **Cold tier (archive nodes keep; pruned nodes may drop):** historical block
  bodies and receipts, superseded state versions (prior object revisions, past
  epoch snapshots), and **long-untouched live objects** — objects not read or
  written for a configurable age/height window. A cold object is still *owned*
  and still *holds its storage deposit* (the deposit is released only on delete,
  not on tiering); it is merely not resident in the hot working set.

### Eviction and the boundary

- Eviction is **deterministic and local**: it never changes `state_root` or the
  logical state, only which tier physically holds a record. The boundary is a
  configured **cold threshold** — an object (or state version) whose
  last-touched height is more than `cold_after_heights` behind the tip is
  eligible to move to the cold tier. Operators choose the threshold (and whether
  to be a full-archive node or a pruned node keeping only a weak-subjectivity
  window, per ADR-0011); consensus does not depend on the choice.
- Because tiering is physical-only, two nodes with different retention still
  compute identical roots — the hot tier of each is the same committed state.

### Archive-node interface + proofs

- An archive node exposes **read-by-(key, height)** and **read-object-at-version**
  over the same `KvStore` seam, returning the value plus a **Merkle path against
  the per-subtree root at that height** — verifiable by the same
  `verify_merkle_proof` (bounded by finding E3) that light clients already use,
  since the subtree roots are the ones `state_root` commits. No new proof system
  is introduced.
- **Restore-on-demand:** when a transaction touches a cold object, the executing
  node fetches `(object, proof)` from an archive node, verifies the proof against
  the committed root for the object's last-touched height, promotes it back into
  the hot tier, and proceeds. A missing/invalid proof fails closed (the tx does
  not execute) rather than fabricating state.
- **Off-chain blobs** (files, media) are already hash-only on-chain by design
  (§9); tiering concerns only on-chain records, so bulky content never enters
  either tier as bytes.

## The owner-owned / careful items

Deferred to the implementation phase (config until then): the exact
`cold_after_heights` threshold and archival snapshot cadence; whether a cold
object can be *transacted against* only after a restore round-trip (the safe
default) or whether short read-only proofs can be inlined into a block for
one-shot access; and the proof-size bound for restore payloads (must compose with
the block-size and E3 proof-length limits). These are performance/DoS trade-offs
that want benchmarks (Phase 6) before fixing.

## Consequences

- Pruned nodes stay small and cheap to run (the hot tier is bounded by *live*
  occupancy, which the storage deposit already prices), while archive nodes serve
  and prove history — the same operator choice ADR-0011 makes for sync.
- Storage-deposit economics and tiering compose cleanly: the deposit bounds hot
  occupancy; tiering bounds the *physical* cost of the long tail without changing
  who owns what or what is committed.
- No consensus change: tiering is a storage-layer concern behind the `KvStore`
  seam, so it can land after the Phase 6 execution/fee work without a protocol
  version bump.
