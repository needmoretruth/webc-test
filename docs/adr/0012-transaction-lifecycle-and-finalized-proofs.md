# ADR-0012: versioned transaction lifecycle and finalized proofs

Status: accepted implementation direction for protocol version 2; external
security review remains required before a production network

## Context

The protocol-version-1 prototype has useful foundations: a canonical signed
transaction, declared state access, deterministic execution units, atomic
full-block construction, a fee market, Merkle roots, finality certificates,
`KvStore`, a bounded network frame, and browser canonical encoding. The
transaction-system audit on 2026-07-17 found that these pieces do not yet form
one safe end-to-end transaction lifecycle:

- a transaction contains one `Operation`, has no signed height range, sponsor,
  or cancellation form;
- execution commits nonce and fees only on success, and a chargeable operation
  failure currently aborts the whole candidate block;
- the fee split applies the 50/50 rule to priority fees even though the
  confirmed rule applies it to the base fee and gives the priority fee to the
  validator;
- receipts use a free-form error string and events have no transaction/action
  position;
- transaction and receipt roots do not use tree-specific, position-bound leaf
  domains, and the existing Merkle proof carries caller-supplied directions
  without a leaf index or count;
- the public `webc-node run` path and the `ConsensusDriver` own independent
  node/mempool state, while an auto-sealer can publish uncertified blocks as if
  they were finalized;
- pending transactions, lifecycle facts, transaction positions, and receipts
  are not durably indexed;
- no checkpoint-to-finalized-transaction proof verifies validator-set
  transitions, and no checkpoint acceptance policy is implemented.

Changing any one of these in isolation would create ambiguous bytes and status
semantics between Rust, the browser SDK, storage, networking, and proof code.
This ADR freezes the shared boundary before those areas are implemented.

## Decision

### One coordinated activation, never reinterpretation

The completed transaction system activates as protocol version 2. Its signed
transaction is `TransactionV5`, its block header is `BlockHeaderV4`, and its
receipt/event/proof schemas begin at version 1. Every signed, hashed, stored, or
served object has an explicit version or versioned enum.

The protocol-version-1 `WEBC_SIGNED_TRANSACTION_V4` and
`WEBC_BLOCK_HEADER_V3` vectors remain frozen regression fixtures. A V5 decoder
never accepts V4 bytes and no old field gains a new meaning. This repository is
still a devnet prototype, so version 2 uses a coordinated devnet reset at final
activation. Storage migration still handles a version-1 database safely:

- finalized V1 blocks remain readable and can be backfilled into legacy query
  indexes;
- V1 pending transactions become a typed `Dropped(UnsupportedProtocolVersion)`
  lifecycle observation because an expiry or sponsor scope cannot be inferred;
- a V3 header cannot be advertised as a V4 finalized-transaction proof because
  it lacks authority-set commitments;
- rollback before activation is the previous binary plus its V1 database, not
  a reinterpretation of data written by version 2.

### Frozen domains and identifiers

The following ASCII domains are independent even when two payloads currently
contain similar fields:

| Purpose | Domain |
| --- | --- |
| sender-signed transaction | `WEBC_SIGNED_TRANSACTION_V5` |
| transaction identifier | `WEBC_TRANSACTION_ID_V1` |
| ordered transaction leaf | `WEBC_TRANSACTION_LEAF_V1` |
| sponsor grant | `WEBC_SPONSOR_GRANT_V1` |
| sponsor use | `WEBC_SPONSOR_USE_V1` |
| receipt | `WEBC_RECEIPT_V1` |
| ordered receipt leaf | `WEBC_RECEIPT_LEAF_V1` |
| event | `WEBC_EVENT_V1` |
| block header | `WEBC_BLOCK_HEADER_V4` |
| finality authority set | `WEBC_FINALITY_AUTHORITY_SET_V1` |
| authority-set transition | `WEBC_AUTHORITY_SET_TRANSITION_V1` |
| weak-subjectivity checkpoint | `WEBC_CHECKPOINT_V1` |
| finalized transaction proof | `WEBC_FINALIZED_TRANSACTION_PROOF_V1` |
| future execution-proof envelope | `WEBC_EXECUTION_PROOF_ENVELOPE_V1` |

`TransactionId` is the SHA-256 digest of canonical JSON containing the
transaction-ID domain and the complete signed V5 transaction. A transaction
leaf commits `(position, transaction_id)` under its own domain. A receipt leaf
commits the complete V1 receipt under its own domain; the receipt itself contains
the same position and transaction ID. Duplicate transaction IDs in a block are
invalid even if their positions differ.

All values that can exceed JavaScript's exact integer range—amounts, heights,
epochs, nonces, gas units, fee rates, counts derived from `u64`, and cumulative
budgets—use canonical unsigned decimal strings in cross-language JSON. Small
closed discriminants and bounded action/event indexes remain JSON numbers. Rust
uses the existing `BlockHeight`, `Epoch`, and `Nonce` wrappers and adds focused
wrappers such as `TransactionId`, `ActionIndex`, `EventIndex`, and `GasUnits`
rather than passing raw integers or hashes across module boundaries.

### Transaction V5

The sender signature covers this logical payload and every nested field:

```text
TransactionV5 {
  protocol_version, chain_id,
  sender, sender_public_key,
  authorization { lane, policy_revision, nonce },
  validity { valid_from_height, valid_until_height },
  kind: Actions(ActionProgramV1) | Cancel(CancelV1),
  access_list,
  fee_bid,
  fee_payment: SenderLane | Sponsored(SponsorUseV1),
  sender_signature
}
```

`ActionProgramV1` is an ordered, non-empty list of `ActionV1`. `ActionV1`
initially wraps the existing native `Operation` variants without changing their
semantics. Results from one action are not dynamically referenced by another in
this phase; later contract calls can add a new versioned action/result model.
This keeps the first multi-action format deterministic and lets existing WEBC
operation logic be reused.

The signed height range is inclusive. Admission for proposed height `H` requires
`valid_from_height <= H <= valid_until_height`. The range cannot be reversed,
cannot span more than 4,096 blocks, and cannot start more than 128 blocks after
the node's next expected height. The future-start rule is mempool policy, while
the inclusive range and maximum span are consensus rules. Local wall-clock TTL
may evict a pending copy but never changes consensus validity.

`CancelV1` is a top-level kind with no action payload. It competes for the same
`(sender, lane, nonce)` slot under the ordinary replacement-fee rule. If
finalized, it consumes that nonce, charges its fixed measured units, and changes
no action state; therefore an older transaction for that slot cannot later
execute. Cancellation is not deletion of a finalized fact and cannot undo an
already finalized transaction.

### Scoped sponsorship

`SponsorGrantV1` is signed by the sponsor and contains:

- protocol version, chain ID, grant ID, sponsor payer, and payer lane;
- one sender plus optional site/application namespace hashes;
- an allowed `ActionScopeV1` digest;
- inclusive start/end heights;
- maximum fee per transaction, cumulative fee, and uses.

`SponsorUseV1` binds the grant digest and a strictly increasing grant-use nonce
to the exact transaction action digest and fee bid. The sender signs the whole
transaction containing the use. The sponsor signature authorizes the immutable
grant, not an unbounded arbitrary transaction. Consensus state keyed by grant ID
tracks the next use nonce, total charged fee, uses, and revocation. A sponsor can
revoke a grant with a sponsor-authorized native action; revocation affects later
uses and cannot rewrite a finalized receipt.

Sponsorship changes only the fee payer. The sender still authorizes every action
and consumes the sender's authorization-lane nonce. The payer lane reserves and
pays fees. The grant state is declared read/write access and is updated in the
fee/nonce overlay even when action execution fails. Grants are fail-closed on a
wrong chain, sender, scope, height, nonce, signature, revocation, use count, or
budget.

Alternatives rejected here are a relayer that appears as the sender, a sponsor
signature over only a transaction hash supplied by an untrusted service, and an
unbounded reusable allowance. They hide the actual authority or make replay and
budget enforcement dependent on off-chain state.

### Admission and error layers

The public protocol separates three outcomes:

1. `TransactionValidationErrorV1`: not includable, consumes no nonce or fee.
   Examples are malformed/oversized bytes, unknown version, wrong chain, bad
   signature, invalid height range, stale/future nonce, underpriced bid,
   insufficient fee reserve, invalid sponsor, or an access-list mismatch.
2. `ExecutionFailureCodeV1`: includable and chargeable after validation. The
   receipt records the stable code and optional failed action index. Examples
   are insufficient action balance, a missing object, ownership/version
   mismatch, or a native-operation precondition that can change between
   admission and ordered execution.
3. `BlockExecutionError`: a proposed block is invalid and no part commits.
   Examples are an undeclared actual state access, root/receipt mismatch,
   arithmetic overflow, impossible internal invariant, invalid evidence, or
   block resource overflow.

Free-form internal messages can be logged without secrets, but never become a
consensus receipt or stable API error. Rust validation returns a
`ValidatedTransaction`; height/base-fee/state preparation returns a
`PreparedTransaction`; execution returns an `ExecutedTransaction` whose status
is success or chargeable failure. A chargeable failure is data, not a Rust
`Err`, so a proposer cannot accidentally drop it or abort unrelated later
transactions.

The signed access list must equal the deterministic sorted union of authorization,
fee payer/sponsor, and every action's statically required access. Actual access
must always be a subset of that declaration. Successful execution must use the
full statically derived set. A failed action may leave later actions' declared
keys unused; that is not a block error. Any actual undeclared read/write remains
a block-invalidating invariant violation.

### Two-level execution overlay and fee rules

Execution uses a parent inclusion overlay and a child action overlay:

1. validation and preparation make no state change;
2. the parent reserves `gas_limit * max_fee_per_unit` from the selected payer,
   advances the sender nonce, and advances sponsor-use accounting when present;
3. actions execute in order in the child overlay, with attempted deterministic
   units accumulated through the successful actions and the failing action;
4. on success the child state/events commit into the parent; on chargeable
   failure the entire child state/events roll back;
5. the parent charges measured units, refunds unused reserve, and commits a
   typed receipt in either case;
6. only a `BlockExecutionError` discards the full-block overlay.

The gas limit must cover the statically bounded maximum units for the whole
action list, so out-of-gas caused by a deliberately insufficient limit is a
validation error. Versioned actions that later have data-dependent work must
meter each step and use a typed chargeable out-of-gas failure.

For `U` measured units, base rate `B`, maximum rate `M`, and requested priority
rate `P`:

```text
effective_priority = min(P, M - B)
base_amount         = U * B
priority_amount     = U * effective_priority
charged             = base_amount + priority_amount
burned              = floor(base_amount / 2)
validator_reward    = (base_amount - burned) + priority_amount
refund              = (gas_limit * M) - charged
```

Every operation is checked arithmetic. The odd base-fee unit goes to the
validator so burn plus reward exactly equals the charge. Priority fee is never
burned. This supersedes applying `split_fee(total)` to base plus priority, but
does not change the confirmed 50/50 base-fee policy.

### Receipt, event, and block commitments

`ReceiptV1` contains version, position `(height, transaction_index)`,
transaction ID, sender, fee payer and lane, status, `FeeSummaryV1`, and ordered
events. Status is `Succeeded` or
`Failed { code: ExecutionFailureCodeV1, failed_action_index }`.
`FeeSummaryV1` contains gas limit, measured units, base/priority rates and
amounts, reserved, charged, refund, burned, and validator reward. Its arithmetic
must reconcile independently.

`EventV1` contains version, transaction ID, action index, event index, and one
typed existing event body. Failed action programs publish no child events.
System-level events outside a user transaction remain a distinct versioned
block-event path rather than using a fake transaction ID.

`BlockHeaderV4` adds `finality_authority_set_root` and
`next_finality_authority_set_root`. The first commits the authority set whose
certificate authorizes this header. The second commits the set that authorizes
the next height. They are equal on an ordinary block. A set-changing block is
certified by the outgoing set and binds the incoming set, as required by
ADR-0011.

Transaction and receipt roots have equal leaf counts. Each receipt position and
transaction ID must match the transaction at that position. Root construction,
verification, and proof generation reuse one shared leaf-hashing function per
tree; node and SDK code must not duplicate the canonical bytes.

### Single node runtime and durable lifecycle

Production `webc-node run` starts one `NodeRuntime` actor that exclusively owns
the mutable `Node`, mempool, consensus driver, lifecycle store, and finalization
pipeline. HTTP, WebSocket, gossip, and tests use a cloneable `NodeHandle` facade
with bounded command queues and one-shot responses. No second `Node` or mempool
exists behind the HTTP service. The transaction-only auto-sealer remains an
explicit development/test utility and cannot label its blocks finalized.

The mempool is indexed both by transaction ID and by
`(sender, authorization lane, nonce)`. `InsertOutcome` is
`DuplicateKnown`, `Added`, `Replaced { old_id }`, or `Evicted { old_id }`.
Duplicate submission is idempotent. Replacement, including cancellation,
requires the existing 10% maximum-fee bump. Defaults add a 64 MiB total byte
cap, 8,192 transaction cap, 64 transactions per sender/lane, and the existing
future-nonce gap of 64. Global and per-sender limits are enforced before cloning
or durable insertion.

Storage schema 2 adds versioned records equivalent to:

- `PendingBySlot` and `PendingTransactions`;
- `TransactionLifecycle` with separate `local_observation` and
  `consensus_fact` fields;
- `FinalizedTransactionIndex` mapping ID to block position;
- `FinalizedReceiptIndex` mapping ID to the receipt record.

Admission order is validate/prepare, durable batch, infallible memory update,
then response/gossip. Finalization is one durable batch containing block, state,
certificate, tip, transaction/receipt indexes, pending deletions, and lifecycle
facts. A finalized consensus fact always wins presentation over a local
replacement, eviction, TTL drop, or expiry: a transaction dropped locally can
still finalize elsewhere. Pending records reload and are revalidated/re-gossiped
after restart. The V1-to-V2 migration is resumable and records a cursor while it
backfills finalized indexes; reopening any completed batch is idempotent.

Stored and network records are hostile. Record byte length, canonical version,
and collection counts are checked before bincode/JSON allocation. The existing
`KvStore`, `redb` (`MIT OR Apache-2.0`), bounded network codec, `axum`, and
`tokio` seams are reused; the lifecycle logic does not add a database, HTTP
server, or async runtime.

### Stable transaction APIs

New transaction lifecycle routes use `/v2` while unrelated V1 account/faucet
routes can coexist during migration:

- `POST /v2/transactions` returns the transaction ID and typed insert outcome;
- `GET /v2/transactions/{id}` returns `Unknown`, `Queued`, local
  `Replaced/Dropped/Expired/Included`, or authoritative `Finalized` status;
- `GET /v2/transactions/{id}/receipt` returns only a finalized V1 receipt;
- `GET /v2/transactions/{id}/proof` builds a bounded finalized proof on demand;
- `/v2/transactions/ws` streams monotonically sequenced lifecycle snapshots for
  explicitly subscribed transaction IDs.

Errors use a stable code, safe message, request correlation ID, and optional
bounded structured details. They never serialize internal errors or sensitive
request contents. HTTP bodies stay under the existing 1 MiB request limit; the
canonical V5 transaction itself is capped at 256 KiB. WebSocket subscriptions,
queued events, connections, and per-IP request rates are bounded. A slow
subscriber is disconnected with a resumable last-sequence marker rather than
growing memory.

### Indexed proofs and checkpoint trust

A new pure `webc-proof` crate owns proof schemas, validation order, limits,
checkpoint policy, and verification. It performs no HTTP, filesystem, database,
or consensus mutation. Retrieval adapters live in the node/SDK. It reuses
`webc-crypto` hashing and `webc-chain` headers/certificates instead of creating
new cryptography.

`IndexedMerkleProofV1` contains leaf, `leaf_index`, `leaf_count`, and siblings.
Direction is derived from the index at each level; the caller cannot provide
direction flags. Verification rejects an empty tree, index outside count,
impossible depth/count, too many siblings, wrong odd-leaf duplication, or any
unconsumed index/count bits. Single-leaf and odd-leaf trees have frozen vectors.
The existing directional proof remains only for legacy account-proof
compatibility until its own versioned migration.

`FinalityAuthoritySetV1` uses the current whole-set Ed25519 verifier behind an
enum boundary so a later committee/aggregate-signature implementation can add a
variant. Its commitment sorts by validator ID and binds protocol version, chain
ID, epoch, validator ID, consensus key, voting power, and checked total power.
Empty sets, duplicates, zero power, unsorted input, or an inconsistent total are
invalid.

`CheckpointV1` contains a V4 header, its finality certificate, and the authority
set matching `finality_authority_set_root`. Candidate validation checks schema,
chain, configured minimum height/epoch, byte/count bounds, header hash,
certificate, and authority commitment. Age is operator policy expressed as
minimum acceptable height/epoch; consensus verification never reads local wall
clock time.

`CheckpointSource` only retrieves a candidate with a configured, distinct
`SourceIdentity`. Network-discovered identities are not counted automatically.
`CheckpointTrustPolicy` receives validated candidates and returns an
`AcceptedCheckpoint` with a visible trust label. The initial policies are:

- `QuorumAgreementV1`: require at least two distinct configured sources and
  byte-identical checkpoint digests. Any valid disagreement or invalid candidate
  stops; unavailable sources never lower the threshold silently. An official
  source is ordinary and has no special protocol authority.
- `ExplicitOperatorTrustV1`: accept one explicitly supplied valid checkpoint and
  permanently label the result `ExplicitOperatorTrust` in status/output.

This comparison limits accidental or single-source equivocation but does not
prove sources are independent or defeat a fully colluding/eclipsing set. That
residual assumption stays visible and the policy boundary remains replaceable,
as required by ADR-0011.

`AuthoritySetTransitionV1` carries a transition V4 header, its outgoing-set
certificate, and incoming set. It verifies adjacent epoch/height rules, outgoing
root, incoming root, certificate, and the protocol's set-change boundary.
`FinalizedTransactionProofV1` contains target V4 header/certificate/authority
set, transaction and receipt at one position, their indexed paths, and only the
authority transitions needed from the separately supplied accepted checkpoint.
Verification proceeds in this fail-fast order:

1. total bytes, collection counts, indexes, and depths;
2. schema, protocol version, chain, checkpoint floor, and target position;
3. authority-set shape/commitments and transition adjacency;
4. transition and target certificates with duplicate-vote/count bounds;
5. transaction leaf/root;
6. receipt leaf/root and exact position/transaction-ID binding;
7. receipt fee reconciliation.

Absolute hostile-input caps are 16 MiB per finalized proof, 8 MiB per checkpoint,
64 transitions, 16,384 authority entries or certificate votes, and 64 Merkle
siblings. Chain configuration can impose lower limits. Bytes and top-level
length prefixes are checked before allocating or verifying signatures.

`ExecutionProofEnvelopeV1` is only a versioned future container for system ID,
public inputs, proof bytes, and verification limits. No real STARK prover,
verifier, dependency, or proof claim may be added before the Phase 5.5 gate and
its independent review. Transparent checkpoint/certificate/Merkle proof remains
the permanent fallback and never blocks consensus.

## Module and integration ownership

- `webc-chain` owns V5 data, validation/preparation/execution semantics, fee
  arithmetic, receipts/events, leaf hashing, V4 headers, and authority-set
  consensus data.
- `webc-storage` owns schema-2 records, migrations, atomic batches, and bounded
  decoding; it does not decide mempool or finality policy.
- `webc-node` owns the runtime actor, pending policy, gossip admission, lifecycle
  projection, HTTP/WebSocket adapters, and on-demand proof assembly.
- `webc-proof` owns pure checkpoint, transition, indexed Merkle, finalized-proof,
  and trust-policy validation.
- `webc-js` owns exact V5 construction/signing/parsing, V2 API/status types,
  browser proof verification, and the shared fixtures.

Shared Rust types land before dependent node/proof changes. Root construction
and verification use exported chain/proof helpers, never locally copied JSON.
The root transaction branch owns shared docs, workspace integration, and final
gates; isolated worktree branches own only their assigned primary modules until
integration.

## Reuse and external implementation evidence

No external source is copied into WEBC by this ADR. The implementations were
reviewed as design evidence at the pinned revisions below, and both repositories
declare Apache-2.0:

- Sui revision
  [`6effb4523834cf2536be21d8ebe577b0cc9e0160`](https://github.com/MystenLabs/sui/tree/6effb4523834cf2536be21d8ebe577b0cc9e0160):
  [`transaction.rs`](https://github.com/MystenLabs/sui/blob/6effb4523834cf2536be21d8ebe577b0cc9e0160/crates/sui-types/src/transaction.rs)
  informed ordered programmable transactions, explicit gas ownership, and
  sender/sponsor signing; [`messages_checkpoint.rs`](https://github.com/MystenLabs/sui/blob/6effb4523834cf2536be21d8ebe577b0cc9e0160/crates/sui-types/src/messages_checkpoint.rs)
  informed certified checkpoint and end-of-epoch authority transitions. Sui's
  object-gas model and Move results are not copied because WEBC uses hybrid
  account/object state, authorization lanes, native actions, and declared
  access. License evidence: [Sui `LICENSE`](https://github.com/MystenLabs/sui/blob/6effb4523834cf2536be21d8ebe577b0cc9e0160/LICENSE).
- Agave revision
  [`ad143fecabb9d67e98856710dd9cdd5cc6a5ad6b`](https://github.com/anza-xyz/agave/tree/ad143fecabb9d67e98856710dd9cdd5cc6a5ad6b):
  [`status_cache.rs`](https://github.com/anza-xyz/agave/blob/ad143fecabb9d67e98856710dd9cdd5cc6a5ad6b/runtime/src/status_cache.rs),
  [`transaction_status_service.rs`](https://github.com/anza-xyz/agave/blob/ad143fecabb9d67e98856710dd9cdd5cc6a5ad6b/rpc/src/transaction_status_service.rs),
  and [`blockstore.rs`](https://github.com/anza-xyz/agave/blob/ad143fecabb9d67e98856710dd9cdd5cc6a5ad6b/ledger/src/blockstore.rs)
  informed separate execution/status persistence and query indexes. WEBC does
  not copy Agave's fork/status-cache lifetime because WEBC exposes BFT-finalized
  facts and restart-safe pending records. License evidence: [Agave `LICENSE`](https://github.com/anza-xyz/agave/blob/ad143fecabb9d67e98856710dd9cdd5cc6a5ad6b/LICENSE).
- The official [Solana fee specification](https://solana.com/docs/core/fees/fee-structure)
  confirms the useful separation of a 50%-burned base fee from a
  validator-paid priority fee and charging execution failures. WEBC retains its
  own measured native-action units, dynamic base fee, refund, and BFT model.
- The official Sui documentation for [programmable transaction blocks](https://docs.sui.io/develop/transactions/ptbs/prog-txn-blocks)
  and [sponsored transactions](https://docs.sui.io/develop/transaction-payment/sponsor-txn)
  was checked against the source. WEBC uses a bounded grant with on-chain budget
  state rather than Sui gas objects.

Existing internal modules and already-approved dependencies are preferred. A
new dependency requires SPDX/license and maintenance review plus `cargo deny`;
none is required for the shared interface or transparent proof design.

## Alternatives rejected

- Preserve the V4 struct and add optional fields: old bytes could acquire new
  meaning, optional combinations create invalid states, and wallets cannot know
  which fields were authorized.
- Treat every execution error as block invalid: one state-dependent transaction
  can prevent unrelated valid work and users receive no finalized failure fact.
- Commit fees only on success: it makes failed work free and enables resource
  abuse. Commit partial action state on failure: it breaks transaction atomicity.
- Let actual access equal only the executed prefix: malicious or buggy code can
  hide undeclared future behavior. The signed static union plus subset-on-failure
  rule is auditable.
- Keep independent service/consensus nodes synchronized by locks: there are still
  two authorities and crash order is ambiguous. One actor gives one owner and
  one persistence order.
- Store precomputed Merkle paths: every append/reorg/migration invalidates many
  records. Store full finalized blocks plus indexes and derive bounded paths.
- Trust the node serving a proof, one branded checkpoint server, or a local
  latest height: none establishes a weak-subjectivity anchor.
- Start a STARK library while transparent proofs are incomplete: it expands the
  attack surface before the required gate and risks coupling consensus to proof
  latency.

## Required verification

Implementation is not complete merely because these types compile. Each phase
must add frozen Rust/TypeScript bytes and negative tests for its invariants. The
acceptance evidence includes:

- V4 fixtures unchanged and V5/domain/version cross-language vectors;
- property tests for multi-action rollback, nonce/fee parent commit, sponsor
  replay/budget/revocation, supply conservation, odd base fees, and access
  prefixes;
- blocks where a failed transaction is followed by a successful unrelated one;
- redb reopen, resumable migration, injected batch failure, and child-process
  crash points around admission/finalization;
- three-validator public HTTP-to-gossip-to-consensus-to-finalized-query tests
  across restart, duplicates, replacement, cancellation, and expiry;
- indexed Merkle odd/single/boundary vectors, certificate/authority/transition
  tampering, source disagreement/unavailability, wrong-chain/stale checkpoint,
  oversized proof, and Rust/browser parity;
- format, strict lint, full tests, rustdoc, demo, SDK, docs, `cargo deny`, audit,
  and fuzz-smoke gates from the transaction-system plan.

The transaction branch records the commit hashes and exact commands as each
portion lands. Production readiness still requires independent protocol,
storage, node, browser, and proof security review.
