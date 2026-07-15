# WEBC continuation guide

## Read first

1. `AGENTS.md`
2. `docs/decision-record.md`
3. `docs/development-plan.md`
4. `docs/whitepaper.md`
5. `docs/implementation-status.md`
6. `docs/index.md`
7. the supporting architecture, economics, bridge, or security document needed
   by the current task

The decision record wins when old code, tests, comments, or documents disagree.

Then inspect `git status --short --branch` and `git log -5 --oneline`. Preserve
all existing changes, determine the first incomplete item below, and continue it
without asking the user to restate recorded decisions or safety rules.

## What the user has already decided

Do not reopen confirmed product choices without new evidence. Important examples are the independent L1, Rust core, 10 million genesis supply, 12 decimals, 10% inflation with yearly 20% relative decline to a 1% floor, 100 WEBC validator-pool activation, 20 WEBC operator minimum at activation, continuous 20% operator self-stake, 1 WEBC minimum delegation, no PoH, 2-second blocks, parallel app isolation, hybrid account/object state, browser wallet isolation, and post-quantum-ready authorization.

The AI-era product direction was confirmed on 2026-07-15 and is recorded in `docs/decision-record.md`; do not reopen it without new evidence. In short: a Rust->WASM contract execution foundation with a WEBC high-level authoring language that lowers (transpiles) to the audited Rust framework (no second VM, no hand-written compiler backend); AI-native machine-readable contract docs + a component catalog serving human-only, human-with-AI, and AI-only development; anti-complexity contract tooling (opinionated structure, composable components, a WEBC clippy, and a pre-deploy review); a native staked oracle (reporters stake, median aggregation, slash liars, reusing staking/slashing); capped policy-based fee sponsorship (reputation/domain discounts deferred as unsafe); web-native targets (in-page payments, web games with real-time wallets and server-managed tokens, AI web-agent payments, site revenue-share at the app layer); and bidirectional Ethereum/Solana bridges with the priority ETH+SOL -> ERC-20/SPL sub-tokens + cross-chain messaging -> other chains (Bitcoin/Tron later). Non-negotiable qualities: fast, stable, secure, decentralized, low-fee.

Use simple Korean when speaking to the user, address them as 관리자 (administrator), and use 존댓말 (polite form). Explain unavoidable technical terms immediately.

## Current verified checkpoint

Phases 0, 1, 2, and 3 are complete; **Phase 4 (networking + signed BFT consensus)
is in progress — stage A-1 (networking plumbing), the A-2 consensus core, and most
of A-3 are done: received-block validation (`Node::import_block`), a full
multi-round Tendermint machine with locking and safe round changes
(`webc-chain::ConsensusMachine`), objective equivocation detection, and the async
`ConsensusDriver` that runs the machine over real TCP with mempool-fed proposals —
proven by loopback tests where three validator nodes finalize the same chain and a
gossiped transfer is finalized by all of them. What remains in A-3 is a state-sync
protocol to catch up a lagging/joining node** (see "Exact next work"). Always use
`git log` to discover the current branch tip;
the checkpoint list below names implementation history, not an instruction to
reset or return to an older commit. (The prototype remains unsafe for real funds,
and reference-machine benchmark numbers are still owed before any performance
claim.)

Completed Phase 1 work, in implementation order:

1. `c56d466` introduced 12-decimal native amounts and the confirmed annual
   inflation curve.
2. `eb48737` made local block construction atomic and enforced configured unit
   and canonical-byte limits.
3. `a7b01ea` removed synthetic bootstrap voting power and enforced validator-pool
   activation, operator stake, delegation ratio, and minimum-delegation rules.
4. `f2dba9d` made genesis debit operator stake, reject duplicate accounts, and
   reconcile gross native supply with an explicit invariant report.
5. The versioned-state milestone introduced exact logical keys, runtime access
   recording, fail-closed declaration checks, namespace scheduling tests, and a
   shared Rust/TypeScript canonical transfer fixture. Its commit follows the
   documentation handoff commit `7830145` in `git log`.
6. The signed-evidence milestone replaced label-only slashing with two
   domain-separated signed consensus votes, registered-key verification,
   order-independent replay protection, adversarial tests, and a shared vote
   fixture. Locate its commit immediately after `baddaba` in `git log`.
7. The slash-accounting milestone atomically reconciled operator stake,
   delegator positions/accounts, validator aggregates, a state-root-committed
   slashed-unit bucket, and the supply report. Locate it after `9e76c0c`.

The current code remains prototype-only and unsafe for real funds.

This project runs in an ephemeral cloud container; the GitHub repository is the
single source of truth. Always push to the designated branch mid-work and before
ending, and never leave valuable work only on local disk. `target/`,
`node_modules/`, and `dist/` are intentionally git-ignored but fully regenerable
because `Cargo.lock`, `pnpm-lock.yaml`, `rust-toolchain.toml`, and `.node-version`
are committed (`cargo build`, `pnpm install`).

Latest verified gate: the Rust side (2026-07-15, this cloud environment) passed
`cargo fmt --check`, strict workspace Clippy (`-D warnings`), **192 Rust tests
(120 `webc-chain` + 13 `webc-crypto` + 20 `webc-storage` + 15 `webc-net` +
23 `webc-node` + 1 gossip integration test)**, rustdoc with warnings denied, and
`webc-node demo`. The `webc-node run` devnet node was smoke-tested end to end
(health, faucet drip to a fresh wallet, block and fee queries, and kill/restart
recovery from the persisted redb store). The
TypeScript SDK (2026-07-15, Node 22) builds and passes 69/69 tests, the widget
suite 3/3, plus the package-entry and Markdown-link checks. Historical note: on a
Windows GNU host use `cargo +1.96.0-x86_64-pc-windows-gnu` (the MSVC target lacks
`link.exe`); the cloud Linux toolchain needs no override.

Reuse-over-reinvention is now a standing rule in `AGENTS.md`: prefer mature,
license-compatible crates (Apache-2.0-compatible only) for commodity plumbing;
write and own WEBC's protocol/economic logic, the swappable seams, and
cross-language canonical encoding. Phase 3 storage is redb (embedded ACID DB,
MIT OR Apache-2.0) behind the `KvStore` seam; the API is axum/tokio (MIT).

## Exact next work

The versioned on-chain authorization + constrained session-key gate is
**complete**. Do not redo any of it. What shipped (see
`docs/session-keys-implementation-plan.md`, `docs/session-keys-next-steps.md`, and
the Phase 2 section of `docs/implementation-status.md`):

- Versioned account authorization policy with a post-quantum recovery-root field.
- A real ML-DSA-65 root-**signature** gate (pinned `fips204` behind the
  replaceable `webc-crypto::mldsa` boundary) on session-key install/revoke, over
  `session_key_authorization_message` (`WEBC_SESSION_KEY_AUTHORIZATION_V1`, binding
  chain id, owner, policy revision, nonce, and action).
- Constrained session keys: per-use and cumulative amount and fee budgets, lane
  binding, epoch expiry with a deterministic epoch-boundary pruning sweep, and
  rotation invalidation.
- Primary active-key recovery/rotation (`RotateActiveTransactionKey`, recovery via
  a new-key-signed envelope + root signature) and recovery-root rotation
  (`RotatePostQuantumRoot`, current-root signature + active-key envelope). Both
  halves of the policy can be recovered independently; both had a clean isolated
  adversarial review.
- Browser/SDK surface: operation constructors, access lists, `deriveSessionKeyIdHex`,
  session-subkey generation, and epoch-based expiry display, with cross-language
  byte-parity fixtures.
- `webc-node bench` for an indicative (non-reference) ML-DSA-65 vs Ed25519 timing.

The single remaining session-key item: **reference-machine benchmark numbers**
(session-key vs Ed25519 transfer end to end, and ML-DSA verify/sign vs Ed25519),
which this cloud container cannot produce honestly. Publish reference numbers
before any performance claim.

Persistent encrypted wallet **permission storage** and **automatic
authorization-lane setup** are now **complete** in the SDK (the last outstanding
Phase 2 wallet-wire/secret-isolation gate). Do not redo them. What shipped:

- `sdk/webc-js/src/permission-store.ts`: an authenticated encrypted-at-rest store
  (v1) for per-origin grants (lane, scopes, limits, cumulative `spent_amount`),
  AES-256-GCM under an Argon2id key through the shared `argon2.ts` gate, bound to
  the wallet identity as AES-GCM additional data, with a strict bounded schema
  and a key-caching `openPermissionStore` port so per-spend saves need no
  repeated KDF.
- `TrustedWalletService` (`sdk/webc-js/src/wallet-service.ts`) gains optional
  `persistence` and `restoredGrants`: it restores dormant grants (lane + spend
  survive a restart; reconnect required before signing), persists after every
  connect/spend/revoke inside its serial queue, carries cumulative spend across
  reconnects (only revoke clears a grant), and rolls back on any durable-write
  failure so state never disagrees in the under-count direction.
- Fixed a real host-client schema bug found here: the connection and
  signed-transaction result parsers omitted `authorization_policy_revision`,
  which had failed the end-to-end exchange on every Node version (not a Node 22
  issue). SDK suite is now 69/69.

With this, Phase 2's acceptance conditions are met except reference-machine
benchmarks.

**Phase 3 is largely complete on the Rust node side.** What shipped (do not redo):

- `crates/webc-storage`: the `KvStore` seam (atomic, durable, ordered KV;
  `WriteBatch`, `Table` namespaces, typed `StorageError` with corruption as a
  reported outcome), an in-memory backend, and a durable crash-safe `RedbKvStore`
  built on the redb embedded ACID database (MIT OR Apache-2.0) — reused, not a
  hand-rolled WAL. A typed `ChainStore` maps blocks/latest-state/tip to the seam
  with one atomic per-block commit and startup consistency checks. 20 tests.
- `crates/webc-node` (now lib+bin):
  - `node.rs` — a restartable single-proposer `Node`: recovers latest state or
    initializes genesis, produces blocks via the existing `build_block` against a
    clone and commits atomically (memory and disk never disagree).
  - `mempool.rs` — admission (signature, chain id, per-lane nonce bounds, fee
    floor, best-effort affordability), replacement-by-fee, TTL expiry, and
    fee-priority nonce-contiguous block selection under a unit budget.
  - `service.rs` — a transport-independent `NodeService`: health, fees, account
    (+Merkle proof), object, block-by-height/hash, submit, seal, and a devnet
    faucet (rate-limited, refuses already-funded, valueless-labeled).
  - `http.rs` — axum/tokio (MIT) HTTP + WebSocket transport under `/v1` with a
    request-body limit and a new-block subscription.
  - `main.rs` `run` — launches a redb-backed devnet node, auto-sealing every 2s,
    smoke-tested incl. kill/restart recovery.

**The browser side is now done too:** `sdk/webc-js/src/node-client.ts`
(`WebcNodeClient`) is a typed, defensively-validated HTTP/WebSocket client for the
`/v1` API (health, fees, account, proof, blocks, submit, faucet, block
subscription), and `sdk/webc-js/demo/index.html` is a static reference site that
creates a wallet, calls the faucet, reads the account + Merkle proof, submits a
signed transfer, and watches finality live over the WebSocket. The node applies a
permissive devnet CORS policy so the browser page can reach it. The whole flow was
verified end to end against a running node — a `createWallet` + `signTransaction`
transfer is accepted by the node (browser canonical signing matches Rust exactly)
and the recipient is funded after the 2s auto-seal.

**Phase 3 is therefore complete** (all acceptance conditions met; the only broad
open item across phases remains reference-machine benchmark numbers, which this
cloud container cannot produce honestly).

**Phase 4 is in progress, split into three stages: A-1 (networking plumbing),
A-2 (signed BFT consensus core), A-3 (robustness).**

**Phase 4 A-1 (P2P networking plumbing) is complete** (do not redo). What shipped
is the new `crates/webc-net` crate — the swappable transport seam — plus the node
glue:

- `wire.rs`: the WEBC-owned gossip message set (`NetMessage::Transaction`), a
  self-describing envelope with a fixed magic + wire version, encode/decode that
  rejects foreign magic / unsupported version / oversize / trailing bytes, and a
  `message_id` for gossip loop suppression. Fixed-int bincode keeps magic/version
  at stable offsets (shared `codec.rs`).
- `handshake.rs`: mutual challenge/response peer authentication over Ed25519
  identity keys (reusing `webc-crypto`), each proof bound to the verifier's fresh
  challenge so a recorded handshake cannot be replayed. Pins chain id + wire
  version. `PeerId` names a node, distinct from account/consensus keys.
- `transport.rs`: authenticated TCP dial/listen behind a cloneable
  `NetworkHandle` (actor-pattern worker owns the peer table, no locking). Static
  bootstrap-peer list with capped-backoff reconnect; symmetric handshake rejects
  self-peering and cross-chain peers; flood gossip with a bounded FIFO seen-cache
  so a frame is delivered once and never loops. Reuses tokio + tokio-util
  length-delimited codec (both MIT).
- `webc-node` glue: `NodeService::admit_network_transaction` (tolerant gossip
  admission), `AppState::with_network` + `AppState::submit_transaction` (gossips
  only newly accepted local submissions), and `run_gossip_pump` (drains inbound
  gossip into the mempool; the transport already re-floods, so the pump only
  absorbs). `webc-node run --p2p-listen <addr> --peer <addr>...` joins the
  network with a fresh per-process identity; without them the node is standalone.
- Verified: an integration test propagates a transfer submitted to node A into
  node B's mempool over real authenticated loopback TCP.

Deliberately deferred to hardening/later: channel encryption (gossiped data is
public and consensus messages are individually signed, so devnet uses
authenticated plaintext framing); richer peer discovery beyond a static
bootstrap list; peer scoring/rate-limiting on repeated rejects.

**The A-2 signed BFT consensus core is done.** What shipped (do not redo):

- `webc-chain::consensus` — the `ValidatorSet` snapshot now carries each member's
  registered consensus key (`ValidatorPower.consensus_key`), so a finality
  certificate verifies against the snapshot alone. `SignedProposal`
  (`WEBC_CONSENSUS_PROPOSAL_V1`, leader-only, block-hash-bound) and
  `FinalityCertificate` (aggregate precommits, unique snapshot members, strictly
  `>2/3` power) with `build` and an independent `verify`.
- `webc-chain::round` — the consensus state machine. It began (A-2) as a
  single-round engine and is now (A-3) a full single-height, multi-round
  `ConsensusMachine` following Tendermint (arXiv:1807.04938, Algorithm 1):
  propose -> prevote -> precommit with safe round changes. It verifies every
  proposal/vote against the snapshot; a validator **locks** a value on precommit
  and thereafter only prevotes that value or nil (so honest nodes never prevote
  two blocks and two blocks can never both reach quorum); proposals carry a
  signed proof-of-lock `valid_round` for safe re-proposal (rule 28); three
  timeouts are surfaced as `ScheduleTimeout` actions and fed back as `Timeout`
  events (the machine reads no clock); `f+1` catch-up jumps a lagging node
  forward. Nil votes use the reserved all-zero sentinel hash (no wire change).
  Observers (`identity = None`) follow finality without voting. It emits
  `ConsensusAction`s (broadcast / schedule-timeout / need-block / commit /
  equivocation) for a driver to carry out; it does no I/O itself.
- `webc-net::wire` — `NetMessage` gained `Proposal`, `Vote`, and `Certificate`.
- `webc-node::node` — `produce_block` populates the per-epoch
  `Table::ValidatorSets` snapshot at each epoch's first block (previously wired
  but unpopulated). `Node::import_block` validates a received block by
  re-executing it (`webc-chain::apply_block` requires the recomputed header and
  receipts to match) and commits it through the store, which enforces height
  contiguity, parent linkage, and `state_root` — the receiving side of networked
  consensus and the basis for state sync.
- Deterministic tests prove: happy-path multi-validator convergence; a round
  change when the round-0 proposer is silent (all responsive nodes finalize the
  same block at a later round with a verifying certificate); the lock-safety
  property (a node locked on X never prevotes a conflicting Y); block import
  round-trip and tamper/gap rejection; and equivocation evidence that satisfies
  the existing slashing path.

A-2.1 (the `WEBC_LEADER_SCHEDULE_V1` stake-weighted leader schedule) remains as
before. `Vote`/`SignedVote`/`VoteType`/quorum math/`detect_double_votes` are the
primitives the above build on.

**The A-3 async consensus driver is done.** `webc-node::ConsensusDriver`
(`consensus_driver.rs`) runs one `ConsensusMachine` per height over real
`webc-net` TCP: it builds a candidate on `NeedProposalBlock`
(`Node::build_candidate` — build without commit), arms real tokio timers on
`ScheduleTimeout` (tagged by height so stale timers are dropped), routes gossiped
Proposal/Vote into the machine, commits on `Commit` via `import_block` and
advances to the next height, and stashes gossiped `Equivocation` evidence to
embed in its next proposal. A validator passes its consensus-key seed; an
observer (`None`) still follows and commits finalized blocks. A loopback
integration test (`tests/consensus_convergence.rs`) proves three validator nodes
(active at genesis via `self_stake` above the activation threshold) finalize the
same blocks at the same heights over the real transport; stable across repeated
runs.

The driver now also carries a **mempool**: it admits gossiped transactions,
proposes fee-priority nonce-ordered transactions under the block unit budget, and
prunes included/stale transactions after each commit — proven by an integration
test where a gossiped transfer is included in a block all three nodes finalize.

**What remains in Phase 4 A-3** is a **state-sync protocol** so a node that is
behind (or newly joining) fetches finalized blocks plus their certificates from a
checkpoint and imports them (`import_block` already validates and commits) without
replaying all history — the driver keeps lockstep nodes in sync but cannot catch
up a lagging node, since a gossiped `Certificate` carries a block hash but not the
block. Doing this well means persisting the finality certificate per height
(a new store table + `ChainStore` methods, written at commit time when the driver
holds the certificate) and adding block-request/response wire messages. Fork
choice is largely covered by the finality-certificate design (a node follows the
certified chain and commits only finalized blocks); objective double-vote evidence
is detected, embedded in proposals by the driver, and applied by the existing
slashing path — so that loop is closed end to end in code, pending a test that a
proposed block's evidence actually slashes.

Public contract runtime, the WEBC high-level language and tooling, the native
oracle, ZK expansion, the web/game platform, and real-fund bridge work stay
disabled until their later gates; the AI-era product direction for all of these
is now recorded in `docs/decision-record.md` and slotted into
`docs/development-plan.md` phases 6-14. Historical state snapshots/deltas beyond
the latest are a storage follow-up when proofs against past heights are needed.

## Working rules

- Preserve user changes in a dirty worktree.
- Never delete all files, broad directories, unrelated user data, or system data;
  never run broad cleanup or `git reset --hard`. Delete only a verified exact
  development-generated path inside its intended scope.
- Perform only repository development and necessary development-tool actions.
- Install required reputable development tools automatically when safe, prefer
  project/user scope, pin their versions, and verify their origin and integrity.
- Treat security and correctness as more important than speed or feature count.
- Keep protocol code deterministic and Rust-first.
- Keep modules focused, interfaces small, dependencies clear, and obsolete experiments quarantined.
- Add comments for reasons, invariants, security assumptions, and attack prevention rather than obvious syntax.
- Start every source file with its purpose, boundaries, data flow, and important security rules; document every public interface and its failure behavior.
- Use Rust wrapper types so amounts, block heights, epochs, nonces, chain IDs, and asset IDs cannot be mixed accidentally.
- Use typed errors, checked arithmetic, deterministic ordering, and canonical encoding; do not panic on hostile input.
- Forbid `unsafe` in protocol crates unless an isolated, reviewed exception includes a written safety argument and focused tests.
- Treat all external input as hostile and keep secrets out of logs.
- Use checked integer arithmetic.
- Add tests before or with each protocol repair.
- Update `docs/implementation-status.md` after material work.
- Commit each coherent, tested change promptly with a focused descriptive message.
- Before ending, record passed gates, remaining limitations, and the exact next
  task here so a fresh session can continue without relying on chat history.
- Record a user-approved product change in `docs/decision-record.md`.
- Never treat the existing trusted-relayer bridge as production-ready.
- Never claim TPS, finality, ZK, or quantum safety without measurements and complete coverage.

## Questions to postpone

The user does not need to choose technical constants now. Use benchmarks and public testnet evidence for epoch length, committee size, fee constants, block limits, and native-oracle economic parameters. The contract execution foundation (Rust->WASM) and the decision to build a WEBC high-level authoring language are settled; bring the user the language's surface-syntax look-and-feel and its name only when the language is actually designed. Ask the user later only for decisions that truly change policy, especially final distribution rules, production bridge trust, or emergency governance powers.
