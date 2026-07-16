# WEBC implementation status

Last documentation audit: 2026-07-13 (code facts) · 2026-07-17 (definition
alignment: all docs realigned to `WEBC-DEFINITION.md`; no code changed —
see `definition-gap-analysis.md` for the audit and
`code-reconciliation-worklist.md` for the prioritized code-vs-definition
divergences)

## Summary

The repository contains useful prototype pieces, but it does not yet implement the confirmed WEBC protocol. It must not be used with real funds or described as a working devnet.

The original audit was based on source inspection because Rust was unavailable
at that time. The Phase 0 section below records newer verification work; any
test result not repeated there remains historical evidence only.

The durable resume point is `docs/continuation-guide.md`. A fresh session must
also inspect `git status` and `git log` so documentation-only commits or preserved
user changes after the latest implementation checkpoint are not overlooked.

## Phase 0 baseline completed

The repository baseline has been repaired against the authoritative plan.
Completed and locally verified items are:

- recovered the damaged Git metadata without overwriting the working tree and
  retained a sibling backup of the original `.git` directory;
- pinned Rust `1.96.0`, Node.js `24.18.0`, and pnpm `11.7.0` in repository
  configuration;
- added workspace lint policy that forbids `unsafe` and denies compiler
  warnings in protocol crates;
- added Windows/Linux Rust CI plus TypeScript and local-document-link CI;
- restored the browser SDK public entry point and pnpm workspace/lock file;
- added initial TypeScript regression tests and passed both package builds,
  three tests, and the local Markdown-link check;
- added the source documentation template and technical ADRs for state,
  consensus, fees, wallet authorization, proofs, contracts, and bridges;
- added validated `ChainId`, `ProtocolVersion`, `BaseUnits`, `BlockHeight`,
  `Epoch`, `Nonce`, and `ValidatorId` types and committed protocol/chain identity
  into the in-memory state and block header.
- marked halving and bootstrap staking as legacy behavior and removed PoH from
  authoritative block data and hashing.

The Windows host uses the pinned Rust GNU toolchain with a checksum-verified
portable WinLibs GCC installation because MSVC Build Tools were unavailable.
The final Phase 0 gate passed `cargo fmt --check`, strict workspace Clippy,
the complete Rust workspace tests, Rust documentation with warnings denied, the
node demo, both TypeScript builds and tests, and the local Markdown-link check.
Legacy tests still exercise known-invalid prototype behavior; their success is
only a Phase 0 reproducibility result and does not satisfy Phase 1 invariants.

## Phase 1 completed

Completed and verified:

- native WEBC precision is now 12 decimals in Rust and TypeScript, with exact
  decimal-string vectors for one WEBC and the 10,000,000 WEBC genesis supply;
- the legacy halving schedule was replaced by the confirmed 10% initial annual
  rate, exact 0.8 yearly decay, and 1% floor;
- reward-period rounding uses cumulative integer budgets, so a complete year
  distributes exactly the annual issuance budget without floating point or
  wall-clock input;
- the inflation year-start supply is committed in deterministic chain state.
- block construction now executes in a whole-block overlay and commits only
  after every transaction, root, unit limit, and canonical byte limit succeeds;
- regression tests prove rollback after a late invalid transaction and after
  byte/unit limit failures.
- bootstrap registration now fails closed and consensus assigns no synthetic
  voting power to unstaked legacy records;
- validator pools remain pending until reaching 100 WEBC total stake with at
  least 20 WEBC operator stake, delegation is capped at four times operator
  stake, and individual delegations require at least 1 WEBC.
- genesis rejects duplicate accounts, debits operator stake from liquid
  allocations, and fails if its gross native supply does not reconcile;
- `SupplyInvariantReport` accounts for liquid, operator stake, delegation,
  pending rewards, fee rewards, and burned units without double-counting mirror indexes.
- versioned `StateKey` now distinguishes accounts, owner-scoped asset balances,
  validators, delegation positions, payer-scoped fee deltas, bridge/slashing
  replay markers, protocol fields, objects, modules, and application namespaces;
- native transaction execution records logical reads/writes and rejects missing,
  read-only writes, duplicates, overlap, unsupported versions, more than 256
  declared keys, and unused over-declarations before committing its overlay;
- scheduler conflicts now use the same versioned keys, with regression coverage
  proving unrelated application namespaces can share a batch;
- Rust and TypeScript share an executable canonical transfer fixture containing
  the versioned access list and snake-case fee wire fields.
- consensus votes now sign an explicit `WEBC_CONSENSUS_VOTE_V1` payload containing
  protocol version, chain ID, height, round, stage, block hash, and validator;
- double-vote slashing verifies both artifacts with the validator's registered
  consensus key and uses an order-independent replay identity;
- forged signatures, cross-chain reuse, same-block pairs, mismatched vote steps,
  and reversed duplicate submissions fail before any penalty, with a shared
  Rust/TypeScript canonical vote fixture;
- label-only invalid-block, bridge-fraud, downtime, and majority-attack evidence
  variants were removed from the accepted penalty path until objective signed
  verification is separately implemented.
- a verified slash now reduces the operator account, every affected delegation
  position, each delegator account mirror, and validator aggregates atomically;
- per-position basis-point rounding is deterministic and overflow-safe, and all
  removed units enter an explicit `slashed_units` bucket committed by the state
  root and included exactly once in supply reconciliation.

- native bridge escrow is isolated by external domain, committed by the state
  root, and reconciled exactly once in the supply report; wrong-domain and
  over-release paths roll back atomically. This remains a mock trusted-relayer
  flow and is not approval for real funds.

ADR-0008 now fixes the unbonding implementation boundary: epoch snapshots,
per-position lifecycle states, a deterministic FIFO churn queue, graceful pool
draining, a slashable cooldown window, and no Layer-1 instant-liquidity promise.
This is the accepted technical design and its single-node chain-state
integration is complete; durable restart integration remains a Phase 3 task.

Delegator exits now use the queue end to end: monotonic request IDs,
owner/validator binding, FIFO partial admission under a base-unit churn budget,
typed epoch cooldown/evidence boundaries, one-time matured claims, JSON restart
equivalence, account/delegation/validator updates, and state-root/supply
commitments. Exit requests do not change active voting stake until an epoch
boundary. Earned rewards survive full admission, and queued/cooling principal
remains slashable without double-counting destroyed units.
- operator self-stake uses the same typed queue without mixing it with delegation
  accounting; partial exits must preserve 100/20/80 activation rules, and a full
  operator exit is rejected while delegated stake remains.

## Latest full validation

On 2026-07-13, the pinned `1.96.0-x86_64-pc-windows-gnu` Rust toolchain passed
`cargo fmt --check`, strict workspace Clippy, 77 unit tests, documentation with
warnings denied, and the deterministic node demo. Node.js 24.18.0 with pnpm
11.7.0 passed both TypeScript builds, all 40 TypeScript tests, the emitted ESM
package-entry smoke test, and the
repository-local Markdown-link check.

The unqualified Windows Rust default targets MSVC and cannot link on this host
because MSVC Build Tools are not installed. This is not the verified project
path; use the pinned GNU toolchain and checksum-verified WinLibs compiler recorded
in Phase 0.

On 2026-07-14, after adding constrained session keys and the ML-DSA-65
root-signature gate, the pinned Rust `1.96.0` GNU toolchain (on Linux for this
session) passed `cargo fmt --check`, strict workspace Clippy, 115 unit tests (102
`webc-chain` + 13 `webc-crypto`), documentation with warnings denied, and the node
demo. Both TypeScript packages build. One pre-existing browser end-to-end test
(`wallet-service.test.ts`) fails only on this host's Node 22 because it requires
the verified Node 24 WebCrypto behaviour; it is unrelated to the session-key
change and fails identically without it. The cross-language state-key wire vector
passes on both Rust and TypeScript with its updated digest.

On 2026-07-15 (this cloud environment, Node 22), after adding durable encrypted
permission storage and automatic lane setup, both TypeScript packages build and
the SDK suite passes 69/69 with the widget suite at 3/3; the Markdown-link and
package-entry checks pass. The previously reported single failing
`wallet-service.test.ts` case was not a Node 22 issue: it was a real host-client
schema bug (the connection and signed-transaction result parsers omitted
`authorization_policy_revision`), now fixed, so the end-to-end exchange passes on
Node 22. No Rust files changed in this pass, so the Rust gate is unaffected from
the prior green run (133 tests).

On 2026-07-15 (this cloud environment), Phase 3 landed the local restartable node.
The pinned Rust `1.96.0` toolchain passed `cargo fmt --check`, strict workspace
Clippy (`-D warnings`), **176 tests (120 `webc-chain` + 13 `webc-crypto` + 20
`webc-storage` + 23 `webc-node`)**, rustdoc with warnings denied, and the node
demo. The `webc-node run` devnet node was smoke-tested end to end: `GET
/v1/health`, `POST /v1/faucet/{addr}` funding a fresh wallet to block height 1
with the no-value disclaimer, block/fee queries, and a kill/restart that recovered
height 1 from the persisted redb store.

## Phase 4: networking and signed consensus (in progress)

Phase 4 is split into three stages: **A-1 networking plumbing**, **A-2 signed BFT
consensus core**, **A-3 robustness**. The happy-path mechanism of all three exists
and converges in loopback tests, but **Phase 4 is NOT complete or safe**: A-1 and
A-2 landed, and A-3 covers received-block validation, the multi-round Tendermint
machine with locking and round changes, equivocation *detection*, the async
consensus driver with mempool-fed proposals, and certificate-verified state sync —
proven by loopback tests where three validator nodes finalize the same chain, a
gossiped transfer is finalized by all, and a late-joining node catches up purely
via sync.

**2026-07-16 plan-review correction:** a read-only review reported HIGH-severity
consensus safety/liveness/DoS gaps that must be reproduced and fixed before Phase
4 can be called done — see `docs/review/findings.md` C1–C8: no `valid(v)`
re-execution before prevote/lock/finalize (a Byzantine leader can certify an
unimportable block — C1), a silent node halt on failed import (C2), unbounded
attacker-chosen-round memory (C3), and no vote/lock WAL so a crash-restart
self-equivocates (C4).

Also corrected in the same review: two commits by the GPT implementer
(`a6197ac`, `75d054b`) landed 2026-07-15 without updating this file, so two items
this document previously listed as remaining are in fact DONE — **equivocation-to-
slash is wired** (header `evidence_root` + block `evidence` executed atomically in
`build_block`/`apply_block`, driver auto-includes machine-detected equivocation)
and a **Byzantine `less_than_one_third_..._cannot_finalize_conflicting_blocks`
test** exists. Because the slash loop is now live, C4 is no longer latent: an
honest restart can self-equivocate and be slashed, so the vote/lock WAL is urgent.
Genuinely remaining: a reference finality-timing number, C1–C4, and (optionally) a
multi-node-over-TCP Byzantine test. Full worklist:
`docs/review/2026-07-16-plan-review.md` §6.

### Phase 4 A-1: peer-to-peer networking plumbing — complete

A new crate, **`crates/webc-net`**, is the swappable transport seam between the
deterministic protocol core and the network. Following the reuse-over-reinvention
rule, it reuses mature MIT crates for commodity plumbing (tokio sockets,
tokio-util length-delimited framing) and owns only the WEBC-specific protocol
pieces. All pure crates (`webc-chain`, `webc-crypto`, `webc-storage`) stay fully
synchronous; async lives only in `webc-net` and `webc-node`.

- **`wire.rs`** — the gossip message set (`NetMessage`, carrying a `Transaction`
  in A-1; proposals/votes/certs are added in A-2) inside a self-describing
  envelope with a fixed magic and a wire-protocol version. Decoding rejects
  foreign magic, an unsupported version, oversize payloads, and trailing bytes
  before trusting a peer-controlled payload; fixed-int bincode (shared `codec.rs`)
  keeps the magic and version at stable offsets for a cheap pre-deserialize
  reject. `message_id` gives each frame a content identity for loop suppression.
- **`handshake.rs`** — mutual challenge/response peer authentication over Ed25519
  identity keys (reusing `webc-crypto`; only the signature primitive is reused).
  Each side sends a fresh random challenge and must return a signature over the
  *counterparty's* challenge, so a recorded handshake cannot be replayed to
  impersonate a peer. The handshake pins the chain id and wire version. `PeerId`
  names a node and is distinct from any account or consensus key. Channel
  encryption is deliberately deferred: gossiped data is public and every
  consensus-weighted message is independently signed, so authenticated plaintext
  framing is sufficient for devnet.
- **`transport.rs`** — authenticated TCP dial/listen behind a cloneable
  `NetworkHandle`, in an actor pattern where a single background worker owns the
  peer table (no shared-state locking). A static bootstrap-peer list is dialed
  with capped exponential-backoff reconnect; the symmetric handshake runs
  identically on both inbound and outbound sides and rejects self-peering and
  cross-chain peers. Gossip is best-effort flooding with a bounded FIFO
  seen-frame cache, so a message is delivered once and never loops; per-peer
  bounded queues drop frames for a slow peer rather than stalling the worker.

The node integrates the network in **`crates/webc-node`**:

- `NodeService::admit_network_transaction` — a tolerant admission path for
  gossiped transactions that classifies the outcome (`NetworkAdmission`) instead
  of erroring, since peers legitimately re-send known transactions.
- `AppState::with_network` + `AppState::submit_transaction` — a locally submitted
  transaction is validated and admitted first, then gossiped **only** if newly
  accepted, so a rejected or duplicate submission never floods the network.
  Standalone nodes (no network handle) behave exactly as before.
- `run_gossip_pump` — drains inbound gossip into the mempool. Because the
  transport already re-floods a newly-seen frame to a node's other peers, the
  pump only absorbs into the local mempool; it does not re-broadcast.
- `webc-node run --p2p-listen <addr> --peer <addr>...` — joins the gossip network
  with a fresh per-process network identity; without those flags the node runs
  standalone as before.

Verified: `cargo fmt --check`, strict workspace Clippy (`-D warnings`), rustdoc
with warnings denied, and **192 Rust tests** (120 `webc-chain` + 13
`webc-crypto` + 20 `webc-storage` + 15 `webc-net` + 23 `webc-node` + 1 gossip
integration test). The integration test propagates a transfer submitted to node A
into node B's mempool over real authenticated loopback TCP.

Deferred within A-1 (not required for its milestone): channel encryption, richer
peer discovery beyond a static bootstrap list, and peer scoring/rate-limiting on
repeated rejections. These are hardening or later-stage items.

### Phase 4 A-2: signed BFT consensus core — complete

The deterministic, clock-free consensus core is implemented and gate-verified.

- **`webc-chain::consensus`** — the `ValidatorSet` snapshot now carries every
  member's registered Ed25519 consensus key (`ValidatorPower.consensus_key`), so
  a finality certificate is self-verifiable against the snapshot alone (a
  light-client-friendly property: no full validator state needed to check
  finality). Added `SignedProposal` (domain `WEBC_CONSENSUS_PROPOSAL_V1`; the
  signature covers the block hash, and `verify_in_set` re-hashes the carried
  block, requires the signer to be the scheduled leader for `(height, round)`,
  and checks the signature against the snapshot key) and `FinalityCertificate`
  (aggregate precommits for one exact height/round/block, each verified against a
  distinct snapshot member, aggregate power strictly greater than two thirds),
  with a `build` convenience and an independent `verify` that rejects a foreign
  validator, a duplicated validator, or a precommit for another block.
- **`webc-chain::round`** — a pure `RoundState` state machine for one
  height/round driving propose -> prevote -> precommit -> commit. It reads no
  clock and performs no I/O: it returns `ConsensusAction`s (broadcast a message,
  or commit a block) for a driver to execute. It verifies every proposal and
  vote against the immutable snapshot before acting, counts each validator at
  most once per step (first vote wins, so a later equivocating vote cannot change
  the tally), and finalizes a block only when it holds that block and observes
  strictly over two-thirds precommit power. An observer (no validator identity)
  follows finality without ever broadcasting. Timeouts and round changes are
  deferred to A-3, so the engine is single-round: a stalled proposer stalls the
  height.
- **`webc-net::wire`** — `NetMessage` gained `Proposal`, `Vote`, and
  `Certificate` variants (large payloads boxed), each with a round-trip test.
- **`webc-node::node`** — `produce_block` populates the per-epoch
  `Table::ValidatorSets` snapshot at each epoch's first block; the writer path
  (wired but unpopulated since Phase 3) is now live. With no active validators in
  devnet genesis the snapshot is an empty (zero-power) set, which is correct
  until validators activate through staking.

Convergence is proven by a deterministic 3-validator test that drives the round
engines over an in-memory message bus and asserts all three finalize the
identical block and a certificate that independently verifies against the
snapshot. Verified: `cargo fmt --check`, strict workspace Clippy (`-D warnings`),
rustdoc with warnings denied, and the full workspace test suite (webc-chain 137,
webc-crypto 13, webc-net 18, webc-node 24, webc-storage 20, plus the gossip
integration test).

### Phase 4 A-3: robustness — deterministic core complete, integration remaining

The safety-critical, deterministic parts of A-3 are implemented and gate-verified.

- **Received-block validation** — `webc-chain::apply_block` re-executes a block
  another node produced (its own transactions and header metadata) and requires
  the locally recomputed header and receipts to equal the received ones; because
  the header commits every root and the block fee, any forged root, altered
  transaction set, or wrong fee is rejected, all on a clone so a rejected block
  leaves state untouched. `webc-node::Node::import_block` wraps it and commits
  through the store, which independently enforces height contiguity, parent
  linkage, and `state_root`. This is the receiving side of networked consensus and
  the basis for state sync. Tested: producer/follower import round-trip to the
  same state root, tampered-header rejection with untouched state, and gapped
  import rejection.
- **Multi-round consensus** — the A-2 single-round engine became a full
  single-height, multi-round `ConsensusMachine` following Tendermint
  (arXiv:1807.04938, Algorithm 1). A validator locks a value when it precommits
  and thereafter only prevotes that value or nil, so honest nodes never prevote
  two blocks and two blocks can never both reach a precommit quorum. Proposals
  carry a signed proof-of-lock `valid_round` for safe re-proposal (rule 28).
  Three timeouts (propose/prevote/precommit) are surfaced as `ScheduleTimeout`
  actions and fed back as `Timeout` events, so the machine reads no clock; `f+1`
  catch-up (rule 55) advances a lagging node. Nil votes use the reserved all-zero
  sentinel hash, so no vote wire format or cross-language fixture changed. Tested
  deterministically: happy-path multi-validator convergence; a round change when
  the round-0 proposer is silent (all responsive nodes finalize the same block at
  a later round with a verifying certificate); and the lock-safety property (a
  node locked on X never prevotes a conflicting Y after a round change).
- **Objective equivocation detection** — the machine emits
  `ConsensusAction::Equivocation` the first time a validator signs two conflicting
  votes in one round/step; both votes are already snapshot-verified, so the
  `DoubleVoteEvidence` plugs straight into the existing verified
  `SlashingEvidence::DoubleVote` path (whose application was already implemented in
  Phase 1). Tested against `SlashingEvidence::verify`.

- **Async consensus driver** — `webc-node::ConsensusDriver` (`consensus_driver.rs`)
  runs one `ConsensusMachine` per height over real `webc-net` TCP. It builds a
  candidate on `NeedProposalBlock` (`Node::build_candidate`, which builds without
  committing), arms real tokio timers on `ScheduleTimeout` (tagged by height so
  stale timers are ignored), routes gossiped Proposal/Vote into the machine,
  commits on `Commit` via `import_block` and advances to the next height. (It does
  not act on `ConsensusAction::Equivocation` yet — see the note at the end of this
  section.) A validator supplies its consensus-key seed; an observer (`None`)
  still follows
  and commits finalized blocks. A loopback integration test
  (`tests/consensus_convergence.rs`) has three validator nodes — active at genesis
  because their `self_stake` exceeds the activation threshold — finalize the same
  blocks at the same heights over the real authenticated transport, stable across
  repeated runs.

- **Mempool-fed proposals** — the driver carries a mempool: it admits gossiped
  transactions, proposes fee-priority nonce-ordered transactions under the block
  unit budget (`Mempool::select_block`), and prunes included/stale transactions
  after each commit. `CommitInfo.tx_count` lets an observer see a block carried
  transactions. Integration test: a transfer gossiped into the 3-node network is
  admitted by every mempool and included by a proposer in a block all three nodes
  finalize at the same height with agreeing tips.

- **Certificate-verified state sync** — a lagging or newly-joining node fetches
  finalized blocks with their certificates and imports them without replaying
  consensus. The finality certificate is persisted per height
  (`Table::Certificates`; `BlockCommit.certificate`; `ChainStore::certificate`;
  `Node::import_finalized_block` writes it, `Node::certified_block` reads it).
  `NetMessage` gained `BlockRequest` and `BlockResponse(CertifiedBlock)`. The
  driver runs live consensus and sync in one per-height loop: a node advances a
  height either by finalizing it live or by importing a peer's certified block —
  verifying the block-bound certificate against the current validator snapshot,
  then re-executing on import — and serves `BlockRequest`s from its store. A node
  that observes the network ahead requests the finalized block for its current
  height once, so a node missing votes advances by import instead of stalling.
  Integration test: three synchronized validators produce blocks, then a late
  observer joins and catches up to height 3 purely via state sync, its finalized
  tips matching the validators' at every height.

**Update (2026-07-16, reconciled with commits `a6197ac`/`75d054b` that this file
had not caught up to): consensus-detected equivocation IS now wired to an applied
slash.** `a6197ac` added an `evidence_root` to the block header, an `evidence:
Vec<SlashingEvidence>` block body, and `build_block`/`apply_block` execution of
`apply_block_slashing_evidence` (bounded by `MAX_BLOCK_SLASHING_EVIDENCE`, before
user txs, inside the atomic overlay); the driver auto-includes machine-detected
equivocation via `pending_evidence` + `build_candidate` +
`prune_pending_evidence`; there is a
`header_committed_evidence_slashes_and_imports_deterministically` test. `75d054b`
added the `less_than_one_third_byzantine_power_cannot_finalize_conflicting_blocks`
machine-level test. The `Operation::SubmitSlashingEvidence` transaction path also
still exists.

Because the slash loop is now live, review finding **C4 (no durable vote/lock WAL)
is an ACTIVE danger**: an honest validator that crashes and restarts mid-height can
self-equivocate and be slashed — fix the WAL before running this on a network (see
`docs/review/findings.md`). Genuinely remaining Phase 4 items: a reference-machine
finality-timing number (this cloud container cannot produce it honestly); the
CONFIRMED review findings C1–C4; and, optionally, a multi-node-over-TCP Byzantine
integration test (the machine-level property is now tested). Fork choice is covered
by the finality-certificate design (a node follows the certified chain and commits
only finalized blocks). The a6197ac evidence path is being independently verified
this session.

## Phase 3: local restartable node, storage, and developer APIs

**Complete.** A standing "reuse over reinvention" rule was added to `AGENTS.md`:
prefer mature, Apache-2.0-compatible crates for commodity plumbing; own WEBC's
protocol logic, the swappable seams, and cross-language canonical encoding.

The browser side landed alongside the Rust node: `sdk/webc-js/src/node-client.ts`
(`WebcNodeClient`) is a typed, defensively-validated HTTP/WebSocket client for the
`/v1` API, and `sdk/webc-js/demo/index.html` is a static reference site (create
wallet → faucet → account + Merkle proof → signed transfer → live finality over
the block-subscription WebSocket). The node applies a permissive devnet CORS
policy so the page can reach it. The full flow was verified end to end against a
running node: a `createWallet` + `signTransaction` transfer is accepted (browser
canonical signing matches Rust exactly) and the recipient is funded after the 2s
auto-seal. 12 client tests over an injected fetch and a fake WebSocket.

Completed and verified:

- **`crates/webc-storage`** — the storage abstraction, defined before choosing a
  database:
  - `KvStore`: an atomic, durable, ordered key/value contract (`WriteBatch`,
    `Table` namespaces). Corruption is a first-class reported outcome
    (`StorageError::Corruption`), never a panic, so a node fails closed on a
    damaged store.
  - `MemoryKvStore` (tests/ephemeral) and `RedbKvStore`, a durable crash-safe
    backend built on the redb embedded ACID database (MIT OR Apache-2.0) — reused
    behind the seam, not a hand-rolled WAL. One `commit` == one durable redb
    transaction.
  - `ChainStore`: typed block/latest-state/tip persistence with one atomic
    per-block commit (tip advances in the same batch as its block and state, so a
    crash never leaves them disagreeing) and startup schema + tip-consistency
    checks. Latest-only state retention for now; historical snapshots/deltas are a
    later step.
- **`crates/webc-node`** (now lib+bin):
  - `Node` — a restartable single-proposer runtime that recovers the latest
    committed state or initializes genesis, and produces blocks via the existing
    `build_block` against a clone, committing atomically so memory and disk never
    disagree; refuses to resume a store with a mismatched chain id.
  - `Mempool` — admission (signature, chain id, per-lane nonce not stale and
    bounded ahead, fee floor, best-effort affordability), replacement-by-fee, TTL
    expiry, obsolete-nonce removal, and fee-priority nonce-contiguous block
    selection under a unit budget. Reads no clock (caller supplies `now_ms`).
  - `NodeService` — a transport-independent core (health, fees, account + Merkle
    proof, object, block-by-height/hash, submit, seal) plus a **devnet-only
    faucet**: drips valueless test units from a genesis-funded account, seals a
    block so funds are immediately final, enforces a per-recipient cooldown,
    refuses to top up already-funded recipients, and stamps every receipt with a
    no-real-value disclaimer.
  - `http.rs` — axum/tokio (MIT) HTTP + WebSocket transport with every route under
    `/v1`, a 1 MiB request-body limit, typed status-code error mapping, and a
    `subscribe/blocks` WebSocket that pushes a `BlockEvent` on each new tip.
  - `webc-node run` — launches a redb-backed devnet node under `--data-dir`,
    recovering on restart, serving the API on `--listen`, and auto-sealing every
    2s (the devnet block target) when the mempool is non-empty.

Phase 3 acceptance status: restart without loss/duplication — met (verified);
corruption detected and reported — met; invalid transactions do not mutate state —
met (tested); APIs publish explicit versioning (`/v1`) and resource limits (body
limit, mempool caps, faucet limits) — met; browser creates wallet, receives faucet
funds, reads a proof, submits a transfer, and sees finality — met (verified end to
end against a running node). All Phase 3 acceptance conditions are satisfied.

Deliberately deferred within Phase 3: validator-set snapshot storage is wired
(`Table::ValidatorSets`, `BlockCommit.validator_set`) but not populated until
consensus (Phase 4); historical state snapshots/deltas beyond the latest.

## Phase 2 work in progress

Completed and verified:

- the SDK now generates and validates 24-word English BIP-39 recovery phrases
  through pinned `@scure/bip39` 2.2.0;
- devnet child keys use pinned `micro-key-producer` 0.9.0 hardened SLIP-0010 at
  the versioned all-chain testnet path `m/44'/1'/account'/0'/index'` while a
  WEBC mainnet SLIP-44 assignment remains unavailable;
- reviewed noble Ed25519 computes the public key before importing the raw seed
  into a non-extractable WebCrypto handle;
- public `WebcWallet` objects no longer expose that signing handle; a private
  weak map binds it to the trusted SDK instance, and mutable derivation buffers
  are cleared after use where JavaScript permits;
- bounded invalid phrase, checksum, passphrase, and child-index inputs fail with
  typed errors that do not echo secret contents;
- a fixed BIP-39/SLIP-0010 vector derives the same public key and WEBC address in
  TypeScript, signs in WebCrypto, and verifies in Rust;
- emitted ESM package imports now include `.js` extensions, and a plain Node
  package-entry smoke test prevents publishing a build that cannot load.
- authenticated encrypted keystore v1 uses pinned noble Argon2id at the fixed
  OWASP 19 MiB/t=2/p=1 profile and WebCrypto AES-256-GCM with fresh salt/IV;
- strict schema/AAD validation binds format, costs, address, public key, and
  derivation path, while malformed cost fields fail before KDF allocation and
  wrong-password/ciphertext/metadata corruption share one authentication error;
- concurrent KDF jobs are serialized around the library's shared scratch block,
  mutable secret buffers are cleared where possible, and routine unlock returns
  no phrase or private-key handle;
- adversarial tests cover round-trip/restart JSON, randomness, concurrent jobs,
  wrong passwords, ciphertext and public-metadata tampering, hostile KDF costs,
  unknown fields, Unicode/length limits, and strict hexadecimal decoding.
- transaction wire/signing V3 now includes `protocol_version` and `chain_id`
  under `WEBC_SIGNED_TRANSACTION_V3`; Rust execution rejects a valid signature
  made for another chain or unsupported version before mutation, and shared
  Rust/TypeScript fixtures freeze the new bytes, signature, and transaction hash.
- strict wallet message v1 accepts only connect, native-transfer signing, and
  revoke with exact field sets, bounded integer/string inputs, secure browser
  origins, and exact opener/source response routing without wildcard targets;
- wallet-issued session IDs and monotonic sequences complement bounded random
  request-ID replay tracking, while serialized service execution makes
  cumulative principal and fee limits race-free;
- every browser-authenticated origin receives its own wallet-secret-derived
  authorization lane, and the supported service refuses host-selected lanes,
  arbitrary-byte signing, host-authored display text, and unsupported actions;
- the trusted top-level popup UI renders hostile values through `textContent`
  and displays origin, action, recipient, amount, asset, maximum fee, chain, and
  lane before every explicit approval; framed execution is refused;
- the host widget no longer creates or returns an in-process wallet. It opens a
  different-origin trusted popup and returns only public connection data plus a
  client that validates source/origin, signed bytes, and exact requested fields;
- malformed schema/origin/source, replay, stale session, concurrent spend,
  blind-display injection, DOM injection, same-origin widget, and full
  host/service exchange tests pass.

Persistent encrypted permission storage and automatic lane setup are now
implemented in the SDK:

- `permission-store.ts` is an authenticated encrypted-at-rest store (v1) for the
  trusted wallet's per-origin grants — assigned lane, scopes, spend limits, and
  cumulative `spent_amount`. It reuses the audited keystore pattern: AES-256-GCM
  under an Argon2id key (OWASP 19 MiB / t=2 / p=1) through the shared
  `argon2.ts` serialization gate, fresh salt/IV per export, and a strict bounded
  schema (max 256 grants, secure-origin-only, 32-byte lane, limits validated by
  `parseSpendLimits`, `spent_amount` never above the grant's own cumulative cap,
  de-duplicated and sorted by origin). The store is bound to one wallet identity
  (address + Ed25519 public key) as AES-GCM additional data, so one wallet's
  store cannot load as another's (`IDENTITY_MISMATCH`), and any tamper shares one
  `AUTHENTICATION_FAILED` code with a wrong password. `openPermissionStore`
  derives the KDF key once and keeps it as a non-extractable WebCrypto key,
  returning a `save` port that re-encrypts with only a fresh IV, so persisting
  after every spend costs no repeated Argon2.
- `TrustedWalletService` now takes an optional `persistence` port and
  `restoredGrants`. Restored grants rehydrate as dormant (lane + cumulative spend
  survive a restart, but the live session is empty so an origin must reconnect
  before signing — automatic lane setup without re-deriving or re-approving the
  lane). The service persists the full grant set after every connect, spend, and
  revoke inside its serial queue (no race), carries cumulative spend across
  reconnects (only an explicit user-confirmed revoke clears a grant, closing a
  budget-reset abuse), and rolls back the mutation on any durable-write failure so
  in-memory and durable state never disagree in the dangerous (under-count)
  direction. An isolated adversarial review confirmed those invariants and found
  two issues, both fixed: `restoredGrants` is now re-validated in the service
  constructor (a hostile negative `spent_amount` can no longer widen the cap), and
  `revoke` now requires user confirmation (a silent host revoke can no longer be
  paired with a reconnect to reset the budget). A remaining known limitation,
  outside the cross-origin host model, is that the store has no anti-rollback
  counter against an attacker who can overwrite the wallet origin's own storage.
- A pre-existing host-client schema bug was fixed in the same area: the wallet
  connection result and signed-transaction result parsers omitted
  `authorization_policy_revision`, so the well-formed service responses were
  rejected on a key-count mismatch and the end-to-end exchange failed on every
  Node version (previously misattributed to a Node 22 WebCrypto gap). The field
  is now returned by the service (from a validated `authorizationPolicyRevision`
  option) and accepted by both parsers.

(Versioned on-chain authorization policy, on-chain recovery/rotation, session-key
revocation and constraints, and the ML-DSA-65 signature gate are implemented for
the single-node state machine — see below.)

Constrained on-chain session keys are now implemented for the single-node state
machine, following `docs/session-keys-implementation-plan.md`:

- `webc-chain::session_key` defines `SessionKeyId` (domain-separated derivation),
  `SessionKeyConstraints` (bound lane, allowed operations, per-use and cumulative
  amount and fee budgets, relative lifetime), the `SessionKey` record, and
  `SessionKeyConfig` (max lifetime epochs, max keys per account);
- `PostQuantumRoot` gained a domain-separated `commit`/`from_public_key`, and
  `PostQuantumRootReveal` now carries a public key **and an ML-DSA-65 signature**;
  its `verify(root, message)` binds the key to the stored commitment and then
  verifies the signature over the exact action via the replaceable
  `webc-crypto::mldsa` boundary (pinned `fips204` ML-DSA-65). Knowing the (public)
  root key is no longer enough — the root secret must sign the request;
- `StateKeyKind::SessionKey`, a `session_key_root` in the state commitment (bumped
  to `WEBC_STATE_COMMITMENT_V6`), and `ChainState.session_keys` store and commit
  the records; the Rust/TypeScript state-key wire vector was updated together;
- `Operation::InstallSessionKey`/`RevokeSessionKey` are critical actions gated to
  the default lane, an installed policy, and a valid ML-DSA-65 root **signature**
  over `session_key_authorization_message` (`WEBC_SESSION_KEY_AUTHORIZATION_V1`),
  which binds the chain id, owner, policy revision, nonce, and exact action so a
  captured signature cannot be replayed to another action, nonce, or revision;
- `verify_transaction_authorization` accepts a registered, policy-current,
  lane-bound session key in place of the active key, and execution enforces
  expiry (by epoch, never wall-clock), the transfers-only allow-list, per-use and
  cumulative amount, and per-use and cumulative fee before the operation runs,
  advancing the session's spend atomically;
- session keys hold no funds, so supply reconciliation is unchanged; a rotation
  (policy-revision change) invalidates outstanding keys; revocation is immediate.

The session-key Rust test matrix (in `state.rs` and `session_key.rs`) plus a
focused reveal-verification test and seven `webc-crypto::mldsa` tests cover the
lifecycle, per-use/budget/fee caps, the cumulative fee budget bounding a
compromised key, expiry boundaries, disallowed operations, lane binding and
non-default-lane transfers, revision invalidation, fail-closed install/revoke
paths, the per-account cap, serialization restart, a randomized spend-sequence
property test, and the ML-DSA root-signature gate. The signature-gate negatives
reject wrong action, wrong nonce, wrong key, and garbage signature, and — added
after an adversarial review found the binding was untested — a signature that
disagrees with the submitted transaction on constraints, owner, or chain id, all
with atomic rollback. Earlier adversarial reviews also fixed two medium findings
(unbounded fee drain; non-default-lane transfers failing their access-list check).

The post-quantum root **signature** gate (step 6) is now implemented behind the
replaceable `webc-crypto::mldsa` boundary. ML-DSA-65 is a named devnet candidate,
not a benchmarked or audited post-quantum-security claim, and the path stays
disabled for real funds. Still incomplete for this gate: benchmarks (session-key
and ML-DSA verify/sign vs Ed25519) and the browser/SDK session-key surface
(subkey generation, install/session signing, expiry display, cross-language
operation and reveal fixtures).

Primary-key **recovery and rotation** is now implemented on-chain, reusing the
same root-signature gate. `Operation::RotateActiveTransactionKey` replaces the
account's sole active Ed25519 key and is a critical action: default lane, an
installed policy, and a real ML-DSA-65 root signature over
`active_key_rotation_message` (`WEBC_ACTIVE_KEY_ROTATION_V1`, binding chain id,
owner, current policy revision, nonce, and the exact new key). Recovery works
even when the old key is lost or compromised: the transaction envelope may be
signed by the new key through a `PostQuantumRootRecovery` authorization path,
while the root signature is the real authority. A successful rotation advances
the policy revision — which invalidates every outstanding session key at use
time — and preserves the post-quantum recovery root, so portable recovery is
never silently dropped. Rotating to the same key is rejected. Eight adversarial
tests cover new-key recovery (with session invalidation), current-key rotation,
old-key rejection afterward, same-key, non-default-lane, missing-policy,
third-party envelope signer, and a misbound/forged-signature matrix over every
binding axis, all with atomic rollback. Session keys can never rotate: a session
signer is neither the active key nor the proposed new key, so authorization
rejects it before execution.

The **recovery root itself** can also be rotated.
`Operation::RotatePostQuantumRoot` replaces the committed post-quantum root while
preserving the active Ed25519 key, gated by the default lane, an installed
policy, and a signature by the **current** root over
`post_quantum_root_rotation_message` (`WEBC_POST_QUANTUM_ROOT_ROTATION_V1`,
binding chain id, owner, current revision, nonce, and the exact new root). The
envelope is signed by the current active key, so replacing the root requires both
the current root and the active key; a stolen root alone cannot rotate it.
Rotation bumps the revision (invalidating session keys) and rejects a same-root
no-op. Seven adversarial tests — including an end-to-end test that the new root
gains authority while the old root loses it — pass with atomic rollback. Both
halves of the authorization policy (active key and recovery root) can now be
recovered independently.

## Reusable prototype pieces

### `webc-crypto`

The crypto crate contains foundations for hashes, Ed25519 signatures, addresses, and Merkle-style proofs. These ideas are reusable after their formats, domain separation, dependencies, and error handling are reviewed against the new versioned authorization design.

### `webc-chain`

The chain crate contains prototype types and logic for:

- accounts, amounts, transactions, and blocks;
- fees and reward accounting;
- staking, delegation, validators, and slashing records;
- bridge messages, events, replay tracking, and trusted-relayer checks;
- state roots and account proofs;
- access-list scheduling experiments;
- consensus-related primitives.

These are starting points, not finished protocol modules.

### `webc-node`

The node crate contains a command-line demonstration. It is not yet a persistent network node, validator, or browser-facing devnet service.

### Browser packages

`sdk/webc-js` and `sdk/webc-widget` remain security-incomplete browser prototypes.
The package entry points build, and shared Rust/TypeScript fixtures now cover the
PoH-free block header, all native operation variants, every V1 state-key variant,
bridge/evidence replay hashes, and a complete Rust-signed transaction. Wallet
isolation, standard recovery/keystore behavior, and authorization policy remain.

## Confirmed-code mismatches

### Amounts and economics

- Native amounts now use the confirmed 12 decimals and exact string serialization.
- Inflation now follows the confirmed annual decay curve and 1% floor.
- Genesis and transition-level native supply accounting reconcile liquid,
  operator/delegated/unbonding stake, domain-isolated bridge escrow, pending
  rewards, fees, burns, and slashes without double counting.
- Fee and reward constants have not been selected from load tests.

### Consensus and staking

- The new registration and validator-set paths reject zero-collateral bootstrap
  power; legacy wire/state fields remain temporarily for explicit rejection and migration.
- Delegator and operator unbonding are delayed, churn-bounded, reward-preserving,
  and slashable; persisted-node integration awaits the storage phase.
- The authoritative V2 block header contains no PoH field. Rust rejects the
  removed legacy field, and a shared Rust/TypeScript fixture proves the same
  domain-separated block hash.
- There is no complete networked BFT consensus, validator set transition, finality certificate pipeline, or restart recovery.
- Signed vote payloads and objective double-vote verification now exist, but
  quorum callers do not yet enforce committee membership.
- Verified penalties reconcile operator/delegator mirrors and an explicit
  slashed-value bucket. A 64-case property test generates up to 127 arbitrary
  delegate/reward/slash/exit/claim steps per case and checks every accounting
  mirror, supply conservation, active-pool thresholds, and failed-call rollback
  after each step. This complements rather than replaces later fuzzing and
  persisted-node restart tests.

### Execution and parallelism

- Whole-block rollback and configured byte/unit limits are now enforced during
  local block construction; network block validation remains future work.
- Native operations now enforce versioned declared logical access at runtime and
  roll back undeclared or inexact access; public contract execution does not yet exist.
- Non-default authorization lanes have independent typed IDs, checked nonces,
  prepaid supply-accounted fee balances, exact access keys, V3 signing fields,
  and same-wallet parallel scheduling tests.
- Persistent owned objects have typed IDs/versions, namespace and owner checks,
  a 64 KiB payload bound, state-root commitments, exact runtime access, stale
  version/owner/size rollback tests, and cross-lane namespace parallelism.
  Shared-object mutation and localized fee markets remain disabled.
- Objective signed double-vote evidence is enforced; other penalty classes remain
  disabled until equally objective artifacts exist.

### Wallet and wire format

- Rust/TypeScript wire naming is snake_case and executable shared hashes cover
  every native operation and V1 state key. The SDK verifies and hashes a full
  Rust-signed transaction byte-for-byte.
- Recovery words, encrypted export, isolated transfer signing, origin display,
  and durable encrypted per-origin permission storage with automatic lane setup
  are implemented foundations. Broader operation confirmations (beyond native
  transfers) and in-browser production of the ML-DSA root reveal remain.

### Contracts, proofs, and tokens

- There is no selected or production-ready public smart-contract runtime.
- Native token/NFT and per-application governance features do not yet meet the confirmed scope.
- Merkle proof experiments exist, but Mina-inspired recursive/succinct chain verification is not implemented.
- Post-quantum account, validator, and bridge authorization is not implemented.

### Bridges

- Current bridge code is a trusted-relayer message prototype only.
- Native WEBC lock/release now moves through Ethereum/Solana-specific escrow
  buckets committed by the state root and supply report. Cross-domain,
  over-release, zero-value, native-mint, replay, and unauthorized paths fail
  atomically; external representation minting does not alter native supply.
- Ethereum Solidity contracts and Solana Rust programs are not complete.
- Native WEBC lock/mint and burn/release flows are not end-to-end tested across either chain.
- External token round trips are not end-to-end tested.
- Production finality proofs, asset adapters, rate limits, monitoring, pause/recovery operations, and audits are absent.

## Correct next milestone

Begin Phase 2 in `docs/development-plan.md`. The final Phase 1 audit completed
explicit staking/unbonding lifecycle states, current-epoch voting-power
stability, configurable seven-day cooldown targets, bounded object decoding,
checked validator/reward/quorum/base-fee arithmetic, and fail-closed rejection
of floating-point canonical signing input.

Phase 2's schema, shared-vector, snake-case wire, SDK-entry-point, independent
nonce-lane, standard mnemonic/Ed25519 derivation, authenticated encrypted
keystore, and isolated trusted-popup request/confirmation foundations now exist.
The versioned on-chain account authorization policy, its constrained session-key
portion, and the ML-DSA-65 root-signature gate on install/revoke are now
implemented (see the Phase 2 section above and
`docs/session-keys-implementation-plan.md`). Primary-key recovery and rotation
(`RotateActiveTransactionKey`) and recovery-root rotation
(`RotatePostQuantumRoot`) are now implemented too, and expired session keys are
pruned deterministically at each epoch boundary. The TypeScript SDK now exposes
the full session-key and rotation surface (operation constructors, access lists,
`deriveSessionKeyIdHex` matching Rust, browser session-subkey generation, and
epoch-based expiry display), with cross-language fixtures pinning byte-parity for
the four operations and the id derivation. A `webc-node bench` command gives an
indicative (non-reference, not-a-claim) ML-DSA-65 vs Ed25519 signature comparison;
reference-machine numbers and an end-to-end session-key vs Ed25519-transfer
benchmark are the only remaining session-key item.

Durable encrypted per-origin permission storage (`permission-store.ts`) and
automatic authorization-lane setup in `TrustedWalletService` are now implemented
(see the Phase 2 section above), which were the last outstanding Phase 2
wallet-wire/secret-isolation gate. With those and the session-key gate landed,
Phase 2's acceptance conditions are met except for the reference-machine
benchmark numbers. `docs/continuation-guide.md` and
`docs/session-keys-next-steps.md` hold the exact remaining sequence.

The next milestone is Phase 3 (local restartable node, storage traits, crash-safe
commits, and HTTP/WebSocket developer APIs) in `docs/development-plan.md`. RPC and
networking are Phase 3/4 work. Public contract VM, ZK expansion, and real-fund
bridge work remain disabled until their later gates.

## Documentation completed in this pass

- Added the authoritative decision record.
- Added the whitepaper design draft.
- Added the phased development plan.
- Replaced stale architecture, economics, bridge, security, roadmap, definition, and handoff documents.
- Updated `README.md` and `AGENTS.md` to direct future work to the same source of truth.

The 2026-07-13 handoff update also persisted cross-session safety, checkpoint,
validation, and commit rules. No protocol source code was changed by that update.
