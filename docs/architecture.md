# WEBC architecture

Source of truth for product/functional design: `WEBC-DEFINITION.md` (§
citations below). Labels per the honesty rule (§11): confirmed / planned /
experimental / not-yet-built.

## Overview

WEBC is an independent Rust Layer 1 optimized for browser use, website
applications, AI-agent participation, deterministic parallel execution, and
lightweight verification (§1, §6).

## State model — confirmed (§8, §15.29, §15.30)

WEBC uses one versioned state-key system with two developer-facing views —
the hybrid model, re-challenged and confirmed against object-only (§15.30):

- account-style balances for native WEBC and ordinary fungible tokens,
  staking, and payments;
- object-style state for NFTs, games, application data, and shared resources
  (Sui is the primary object-model reference; Solana a throughput reference —
  §15.29).

Every transaction declares which state keys it reads and which it may change.
Execution rejects undeclared access. Transactions with no conflicting writable
keys may run in parallel, but the committed result must equal a deterministic
serial order. (Implemented in the prototype for native operations.)

Application namespaces isolate unrelated sites. Common transfers must not
write one global token object. Hot shared state should be divided into safe
buckets when its rules allow. Wallets use independent authorization/nonce
lanes so several sites can transact concurrently.

**Intentionally-shared infrastructure is the deliberate exception (§15.8 →
§15.13):** canonical DEX pools and popular oracle feeds are shared across
applications by design. Their contention answer is per-block batch settlement
(one uniform clearing price per pair per block) plus localized pricing on the
shared object itself, not namespace isolation.

Non-default authorization lanes hold an independent replay nonce and a bounded
prepaid fee balance. Opening or funding a lane is authorized by the default
account lane and moves native value into a supply-accounted lane bucket. After
that, unrelated site operations can pay fees and advance nonce state without
writing the shared account record. Lane IDs are public origin-policy
identifiers, not secrets or replacements for signature verification.

The Phase 2 wallet service derives one recoverable lane per site from a
domain-separated wallet signature over the browser-authenticated HTTPS origin.
The host cannot propose another lane through the supported transfer API. This
derivation is off-chain wallet policy; consensus continues to treat the
32-byte lane as opaque and requires that it be opened/funded before use.

Persistent application objects use a fixed 32-byte `ObjectId`, application
namespace, explicit owner, and monotonically increasing version. Native
create, mutate, and transfer operations require exact object and namespace
access keys; mutation and transfer also require the signed expected version
and current address ownership. Payloads are capped at 64 KiB. Large files stay
off-chain. Shared ownership is represented but mutation remains disabled until
a public runtime supplies a separately reviewed authorization rule.

## Consensus and speed — two tracks (§8, §15.40, §15.42)

The target is a permissionless, stake-based design with fast BFT-style
finality and a rotating stake-weighted committee. PoH is not used.

**Conservative public claim (until benchmarks):** ~2s blocks, ~6–8s normal
finality, ~12s degraded — what the current prototype targets.

**Decided engineering targets (§15.42 — claims only after public benchmarks):**

- **Fast path (planned, launch scope, not-yet-built):** single-owner
  operations (own-balance payments — credits are commutative — and own-object
  moves) skip global ordering: validators individually verify and
  countersign; a quorum of signatures is a certificate of effective finality
  at ~0.4–0.8s; consensus checkpoints the certificates. The
  FastPay/Sui-fast-path technique (§15.40). Contended/shared state stays on
  the consensus path. Protocol design scope: `speed-roadmap.md`.
- **Consensus path (planned):** ~1s blocks, ~1–2s finality normal, ≤4s
  degraded, with a Mysticeti-class DAG-BFT reference design. The prototype's
  Tendermint-style machine is the current implementation; migration is
  benchmark-gated engineering work (`code-reconciliation-worklist.md`).
- Guardrail: the mid-range hardware floor (§15.23, §15.26) must not silently
  rise to buy these targets.

Committee size, epoch length, message timeouts, and block limits remain
technical values chosen through simulations, fault tests, and public testnet
measurement.

**Two structural gaps to resolve before they get expensive (2026-07-16
review; still open):**
- *Committee sampling is unbuilt.* The confirmed design has a rotating
  stake-weighted sub-committee vote per block with no global validator cap.
  The current finality certificate requires >2/3 of the **whole** active
  validator-set snapshot — a correct first step, but O(N) votes / O(N²)
  gossip. Sub-committee sampling needs its own ADR and a security argument;
  the finality path should be committee-parameterized. Votes must also travel
  as **aggregated signatures** (§15.19 — planned), not per-validator
  messages.
- *Historical state.* `ChainStore` keeps latest-only state. Light clients and
  account/object proofs need historical state commitments; decide the
  archival/snapshot/state-delta strategy in a storage ADR before the proofs
  phase. See `docs/review/2026-07-16-plan-review.md` §4.

Vote economics (§15.23, §15.28 — confirmed): no per-vote fees; votes are
permissioned, bounded consensus messages — only current committee keys may
vote, one vote per member per round, equivocation costs stake, persistent
invalid senders are scored down and banned at the p2p layer.

Stake changes are snapshotted at epoch boundaries. Delegation exits pass
through versioned pending, queued, cooling, and withdrawable states plus a
global bounded FIFO churn queue
([`ADR-0008`](adr/0008-stake-lifecycle-and-exit-queue.md)).

## Bandwidth, memory, and storage frugality (§15.19, §15.22, §15.24, §15.27) — planned

Communication is expected to be the bottleneck (and the cloud egress billing
bomb), RAM next:

- **zstd compression on by default** across gossip/wire and the storage
  layer. Compression lives only in the envelope: hashes and signatures are
  always computed over canonical uncompressed bytes, so two peers compressing
  differently still agree on every hash (§15.24).
- **Compact-block relay:** blocks reference transactions by hash; peers fetch
  only bodies they lack.
- **Vote aggregation:** committee votes travel as aggregated signatures.
- **SSD-first state:** the protocol runs with state on SSD plus a modest RAM
  cache — never a full-state-in-RAM requirement. zram is a documented
  operator option in the official image, not a protocol rule (§15.26).
- **Storage pricing:** deposit + deletion rebate (occupancy pricing);
  hot/cold tiering with archive nodes; Walrus-style erasure-coded blob layer
  as phase 2 (§15.22, §15.27). Not-yet-built.
- Amount encoding: variable-length integers at rest and on the wire; u128 in
  RAM during execution; 256-bit multiply/divide intermediates (§15.14).
  Storage/wire varint encoding is not-yet-built.

## Deterministic execution

A block is accepted only if every transaction and protocol operation is
valid. Whole-block application is atomic. Supply, stake, fees, nonces, object
versions, and state roots are consensus data. The scheduler may execute
independent work concurrently, but consensus commits one deterministic
result. Load claims require sustained public benchmarks on stated hardware.

## Smart-contract path (§9, §15.41, §15.43)

Security-critical operations begin as audited Rust native modules. The
contract execution foundation is restricted, deterministic WASM with Rust as
the first authoring language. Above it, **Weft** (working name — the decided
WEBC authoring language, §15.41) lowers to the audited Rust framework,
inheriting Rust/WASM safety and performance without a second VM or a
hand-written compiler backend. Move VM and EVM are not the native runtime;
Ethereum/Solana compatibility comes through bridges. A contract
linter/analyzer and a pre-deploy review keep contracts small and maintainable.

**Compilation-boundary invariant (permanent).** The chain accepts and stores
only deterministic WASM bytecode plus metadata. All compilation — Weft →
Rust framework → WASM — happens **off-chain and untrusted**. On-chain
validation is limited to WASM validation, gas metering, and access-list
enforcement. A source-language or Rust compiler must never run inside block
execution.

**Sequencing and pluggable authoring front-end (owner-confirmed).** The
interim Rust embedded-DSL / SDK authoring path ships first (Phase 7a) so
contracts are possible before the language exists; a stable contract **ABI**
and a stable "authoring front-end → lowering → audited Rust framework → WASM"
seam are frozen; Weft mounts later (Phase 7b) as one more front end over the
*same* target — never a rewrite. Weft's never-break architecture (deployed
WASM runs forever; editions; stable ABI; reproducible builds — §15.43) builds
on this seam. See `weft-language-plan.md` and `docs/development-plan.md`.

Contracts cannot access websites, files, device randomness, or wall-clock
time directly. They communicate with browser or server agents through events
and signed receipts, and read external data through the native oracle
(pull-based, at-most-once-per-block updates, accuracy-weighted bonded
reporters — §15.17, §15.21; see `oracle-economics.md`).

## Shared-infrastructure execution: batch settlement (§15.13, §15.18, §15.37) — planned, not-yet-built

Swaps against canonical pools are submitted as intents with declared access
sets (parallel-friendly); each block settles all intents on a pair at one
uniform clearing price — removing the serial hot-object bottleneck and making
intra-block ordering games meaningless. The batch is mandatory (no bypass
lane). Orders are short-lived on-chain intents (limit price, deadline,
fill-or-cancel) retried by the protocol across batches. Engine-level design
scope: `dex-batch-settlement.md`.

## Proofs and browser clients (§8, §15.25)

The first light client verifies headers, validator certificates, and
Merkle/state proofs. zk usage policy (confirmed, §15.25): succinct
light-client verification yes; optional zk state compression later for
mass-tiny-object applications (phase 2, never a launch dependency — §15.29);
zk never on the consensus critical path. Proof generation may run on stronger
machines; browser verification stays small and fast. Display-only reads are
free via light-client proofs (§15.21).

## Keys

Account authorization is versioned. Each standard wallet starts with a
post-quantum root/recovery path; constrained session keys are permitted under
strict limits (implemented in the prototype — see
`session-keys-implementation-plan.md`). Details live in the security
documents.

## Node environment (§15.26) — planned

WEBC ships an **official container image** — the standard way to run a
validator — with zram, zstd, and kernel/database tuning on by default (an
operator convenience, never a consensus rule). Minimum and recommended specs
are split deliberately: a low floor for broad entry, a higher recommended
profile for comfort. The floor may rise over time only through governance
with **measured demand** evidence and a published multi-year hardware
roadmap. See `validator-operations.md`.

## Modules

The intended boundaries are:

```text
crypto and authorization
state and execution
parallel scheduler
fees and economics
staking and consensus
fast path (planned)
storage and networking
proofs and light clients
contract runtime (Weft authoring seam)
oracle
DEX / batch settlement
agent commerce (mandates, service registry)
browser SDK and wallet
Ethereum/Solana bridges
```

Each boundary is versioned and replaceable so a proof system, signature
system, VM, database, or bridge design can be upgraded without rewriting the
whole chain.
