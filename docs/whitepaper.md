# WEBC / WEB COIN whitepaper draft

Status: design draft for prototype and devnet engineering
Date: 2026-07-17
Source of truth: `WEBC-DEFINITION.md` (§ citations below). Security,
cryptography, and robustness live in the separate security documents
(`security.md` and the ADRs) by deliberate scope split.

This document describes the intended WEBC network. It is not a promise that
the current repository implements these features and not a claim of mainnet
readiness. Capabilities are labeled **confirmed** (decided design, or decided
and implemented where stated), **planned** (decided direction, mechanics being
designed), **experimental**, or **not-yet-built** (§11 honesty rule).

## 1. Summary

WEBC is an independent Layer-1 blockchain built for the web and the AI era
(§1). Its purpose is to let any website, web app, web game, or software agent
send and receive money, issue assets, and run applications as naturally as
they load a page — with fast, cheap, final transactions, without asking users
to leave the site or hand their accounts to it. Its native coin is **WEB COIN
(ticker: WEBC)**.

WEBC's two identity-level bets:

- **Web-native (§3):** a site adds a wallet, a payment, a token, or a game
  with a small amount of integration; the user stays on the site and stays in
  control; unrelated apps stay isolated in scheduling and pricing.
- **AI-native (§6):** three kinds of participants — humans, humans working
  with AI, and fully autonomous AI agents — are first-class in both building
  and using the chain: machine-readable documentation and interfaces, a
  component catalog, agent commerce primitives (mandates, a service registry,
  HTTP-402-style flows), and an authoring language (Weft) optimized for AI to
  read and write.

The design combines: a hybrid account/object state model (Sui as the primary
object-model reference, Solana as a throughput reference — §15.29, §15.30);
declared state access and parallel execution (§8); a rotating stake-weighted
BFT committee (§8); a two-track speed strategy with a sub-second fast path for
single-owner operations (§15.40, §15.42); per-block uniform-price batch
settlement as the native swap semantics (§15.18, §15.37); a native oracle with
real reporter economics (§15.17); browser-grade light verification (§8); and
bidirectional Ethereum/Solana bridges (§10). WEBC does not use Proof of
History (§8).

## 2. Goals

### 2.1 Website-native use (§3, §5)

A website should be able to add: wallet connection and creation; WEBC payments
and transfers; tokens and NFTs; subscriptions and sponsored fees; conditional
access and file-download authorization; simple games and swaps; staking and
delegation; bridge operations. The host website must not gain access to wallet
secrets; signing occurs in an isolated trusted wallet surface that displays
exactly what is being authorized (security documents own the details).

### 2.2 AI-native use (§6)

- **Three equal audiences:** human-only, human-with-AI, and AI-only workflows
  are first-class for building and using the chain.
- **Machine-readable everything:** documentation, contract interfaces, and a
  component catalog structured so an agent can assemble an application from
  documented building blocks.
- **Agent commerce:** agents pay and are paid in WEBC within budgets and
  permissions their principals set — revocable on-chain **mandates**, an
  on-chain **service registry**, and HTTP-402-style payment flows (§15.5,
  §15.32; see `agent-commerce.md`).
- **An authoring language optimized for AI** to write and read: **Weft**
  (§15.41; see §7 below and `weft-language-plan.md`).

### 2.3 Lightweight verification (§5, §8)

Browsers do not download the ledger. A browser verifies a compact proof of a
finalized checkpoint plus a small proof for the specific account or object it
cares about. Full validators still execute and verify blocks; archive nodes
preserve history; proof workers may use dedicated hardware. Display-only reads
(e.g. a site showing live prices to thousands of visitors) are free via
light-client proofs (§15.21).

### 2.4 Honest performance goals (§8, §15.40, §15.42)

Public claims track measured reality. Until sustained public benchmarks prove
more, the **conservative public claim is ~2-second blocks and ~6–8-second
finality (~12s degraded)** — the figures the current prototype targets.

The decided **engineering targets** (to be claimed only after public
benchmarks — §15.42):

- **Fast path** — single-owner operations (payments from one's own balance,
  own-object moves): **~0.4–0.8s effective finality** via validator quorum
  certificates (the FastPay/Sui-fast-path technique), **launch scope**.
- **Consensus path** — shared state (pools, batch settlement, multi-party
  contracts): **~1s blocks, ~1–2s finality normal, ≤4s degraded**, using a
  Mysticeti-class DAG-BFT reference design.
- Guardrail: the mid-range hardware floor (§15.23, §15.26) is unchanged; if
  benchmarks show these targets need a higher floor, that trade-off returns to
  the owner/governance explicitly.

Published TPS claims must include hardware, transaction type, contention,
validator count, geography, and sustained-test duration. See
`speed-roadmap.md`.

## 3. Native coin (§7)

- Name: WEB COIN; ticker: WEBC.
- Genesis supply: 10,000,000 WEBC; precision: 12 decimals.
- Amounts: u128 storage/compute, 256-bit multiply/divide intermediates,
  variable-length encoding at rest and on the wire (§15.14, §15.19).
- Issuance: 10%/yr multiplied by 0.8 each year to a 1% floor (~11 years),
  accruing smoothly by block/epoch.

### 3.1 Distribution (§15.33, §15.38 — confirmed allocation)

No founder, developer, foundation, investor, or private-sale allocation. The
decided split: **25%** contributor pool (vesting retroactive awards) / **5%**
validator-bootstrap grant ceiling (stake-locked, vest by proven operation) /
**30%** usage-linked fee subsidies over ~10 years / **15%** cross-chain
airdrop in three history-weighted waves with per-wallet caps / **15%**
ecosystem fund paid as non-transferable fee credits / **10%**
governance-locked strategic reserve. Every channel is capped, monitored,
individually stoppable, and has a reversion path.

Fairness is defined as public rules, equal access, and no insider privilege —
not equal-per-human (§15.11). Rejected channels: mining, identity
verification, sales/auctions (§15.16). The founder is paid under the same
published contribution rules as everyone, with the expectation disclosed that
the founder earns a meaningful early share (§15.16). Test-network coins never
convert; nothing before the announced program earns rewards (§7). Full
mechanics: `distribution-program.md` and `tokenomics.md`.

### 3.2 Inflation (§7)

```text
rate(year) = max(1%, 10% * 0.8^year)
```

Smooth per-epoch accrual; the floor provides an enduring security budget. A
bootstrap-phase budget keyed to staked amount is proposed (§15.2, **planned**,
decided at the economics freeze).

## 4. Accounts, objects, and parallel execution (§8)

WEBC uses one unified state-key scheduler over two developer-facing kinds of
state — the **hybrid model**, re-challenged and confirmed against a pure
object model (§15.30): object-only chains pay a coin-fragment UX tax exactly
on payments, WEBC's #1 product; WEBC instead accepts a two-record-type engine
under one state tree.

### 4.1 Account-style state

WEBC and fungible-token balances, authorization lanes, staking and
delegation, validator rewards, bridge accounting. Keeps wallet and payment UX
simple.

### 4.2 Object-style state

NFTs and game items, escrows and conditional payments, swap orders, game
sessions, application-owned records, capabilities. Owned objects carry
explicit identifiers, versions, and authorization rules (Sui is the primary
reference — §15.29).

### 4.3 Declared access

Every transaction declares the state it reads and writes; the runtime enforces
the list; undeclared access fails and rolls back. Non-conflicting transactions
run concurrently. Entrypoint declarations in Weft mirror these access sets at
the source level (§15.43).

### 4.4 Application isolation

Each application gets its own namespace: a busy app does not create
congestion, cost, or contention for unrelated ones. Ordinary transfers touch
per-owner balances, never one global object. The same wallet transacts on
several sites at once through independent authorization lanes (§8).

**Intentionally-shared infrastructure** (canonical DEX pools, popular oracle
feeds) is the deliberate exception to isolation: those objects are shared
across applications by design, and their scheduling/pricing answer is batch
settlement (§15.13) plus localized pricing on the shared object itself
(§15.8 tension, resolved in §15.13).

## 5. Fees (§7, §15.35)

- Base fees are cheap by default, dynamic under load, priced by real work.
- Localized congestion pricing; only a small network-wide floor under global
  overload.
- 50% of base fees burned; 50% to participant rewards; optional priority fee.
- Sponsorship: sites pay users' fees within hard per-user/app/operation/day
  caps; launch values are measurement-tuned placeholders (§15.35).
- Storage is priced as occupancy: deposit + deletion rebate, hot/cold tiering
  (§15.22); Walrus-style blob layer in phase 2 (§15.27).
- No fixed fiat-denominated fee promise (§7).

Details: `tokenomics.md`.

## 6. Consensus and speed (§8, §15.40, §15.42)

WEBC targets a permissionless, stake-based design with fast BFT-style
finality, where a rotating, stake-weighted committee votes on each block so
not everyone votes on everything (§8). PoH is not used.

### 6.1 Participation (§7)

- Anyone may run a verification node without stake.
- Producing/voting validators stake; delegators back them without servers.
- Pool activation: ≥100 WEBC total; operator ≥20 WEBC and ≥20% of pool;
  delegation ≤80%; minimum delegation 1 WEBC; no global validator cap.
- Middle-path economics: low stake floor + mid-range hardware; **no per-vote
  fees** — votes are permissioned aggregated consensus messages, not
  transactions (§15.23, §15.28).

### 6.2 The two-track speed strategy (§15.40, §15.42 — planned, not-yet-built)

- **Track 1 — fast path (launch-scope engineering target):** operations that
  touch only state a single party controls (paying from one's own balance —
  credits are commutative — moving one's own objects) skip global ordering:
  validators individually verify and countersign; a quorum of signatures is a
  certificate of effective finality at ~0.4–0.8s; consensus checkpoints the
  certificates afterward. This covers payments — WEBC's #1 product. Contended
  and shared state stays on the consensus path.
- **Track 2 — consensus stretch (benchmark-gated):** a Mysticeti-class
  DAG-BFT reference design targeting ~1s blocks / ~1–2s finality (≤4s
  degraded) on the decided mid-range hardware floor.
- The prototype's Tendermint-style machine and the ~2s / 6–8s figures remain
  the conservative fallback claim until benchmarks prove the targets.

### 6.3 Finality

A block finalizes when more than two thirds of the selected stake-weighted
voting power signs the required stage. Certificates validate chain ID, height,
round, block hash, validator-set snapshot, voting power, and signatures.
Committee votes travel as **aggregated signatures** (§15.19 — planned;
the prototype gossips individual votes). The UX ladder (§15.39): apps show
results at execution (next block) and treat finality as a background upgrade;
only high-value actions gate on finality.

### 6.4 Slashing (security documents own the mechanics)

Severe penalties require objective signed evidence; downtime receives lost
rewards and softer penalties. Vote spam is structurally impossible without
vote fees: only committee keys may vote, one vote per member per round,
equivocation costs stake, persistent invalid senders are banned at the p2p
layer (§15.28).

### 6.5 Bandwidth and memory frugality (§15.19, §15.24 — planned)

Communication is expected to be the bottleneck and the classic cloud egress
billing bomb: zstd compression on by default across wire and storage (hashes
are always computed over canonical uncompressed bytes, so compression never
breaks verification — §15.24); compact-block relay (blocks reference
transactions by hash; peers fetch only bodies they lack); aggregated votes;
SSD-first state with a modest RAM cache — never a full-state-in-memory
requirement.

## 7. Smart contracts, Weft, agents, and the oracle (§9)

### 7.1 Execution foundation — confirmed (§9)

Contracts run on a restricted, deterministic **WASM** engine, authored in Rust
first (through a friendly framework), compiled off-chain. Move VM and EVM are
not the native runtime; Ethereum/Solana compatibility comes through bridges.
The chain accepts only deterministic WASM + metadata; no compiler ever runs
on-chain (compilation-boundary invariant — `architecture.md`).

### 7.2 The authoring language: Weft — confirmed design (§15.41, §15.43, §15.44) — not-yet-built

Weft (working name, owner-renamable; `.weft`) is a domain language for WEBC
applications that lowers to the audited Rust framework — a front end over a
stable seam, never a second engine:

- TypeScript-familiar brace surface with Rust-grade semantics.
- Money is special: a built-in exact money type on u128 base units with
  decimal literals; each asset its own type; asset values are **linear** —
  they cannot be duplicated or silently dropped; the compiler rejects code
  that loses money.
- Predictability: immutable by default; no null (Option), no exceptions
  (Result), no floats, no macros; bounded loops; entrypoints declare
  `reads`/`writes`; no wall clock or ambient randomness.
- AI-native mechanics: one canonical formatter; a compiler-emitted
  machine-readable interface manifest feeding the component catalog;
  compiler-enforced structured doc-comments; diagnostics written as
  actionable fix suggestions; one-file components sized for a model's
  context; small regular grammar; docs-as-data with a CI-tested examples
  corpus.
- Never-break architecture: deployed WASM runs forever; breaking changes ship
  only as editions with `weft migrate`; stable ABI at the WASM boundary;
  reproducible builds; stdlib deprecations never remove within an edition.
- Sequencing: an interim Rust eDSL/SDK ships first (Phase 7a); Weft mounts
  later over the same frozen ABI/lowering seam (Phase 7b).

Full plan: `weft-language-plan.md`.

### 7.3 Keeping applications maintainable (§9)

Opinionated uniform structure, small composable components, a component
catalog with machine-readable docs, automated analysis/linting, and a
pre-deployment review step (including AI review).

### 7.4 How applications reach the outside world (§9)

On-chain code cannot browse, read files, call services, or read the clock.
**External data** enters through the native oracle; **external actions** (file
transfers, webhooks, API calls) are performed by browser or server agents
acting on on-chain events, optionally returning signed receipts; the chain
records authorization, payment, and content hashes; file bytes stay off-chain.

### 7.5 The native oracle — confirmed direction (§15.17, §15.21) — not-yet-built

Many independent bonded reporters submit values; the network aggregates them
(e.g. median) so no single reporter dictates the answer. The economics:
consumers pay → revenue is distributed to reporters weighted by accuracy and
liveness; **pull-based updates** — a feed updates on demand, at most once per
block, and that value is shared by every consumer in the block;
an optional **first-party publisher** class (e.g. exchanges reporting their
own data); ecosystem-fund seeding that is usage-proportional, accuracy-gated,
capped, and auto-sunsetting; small per-fresh-read fees plus app
subscriptions; display-only reads free via light clients. Persistent outliers
lose standing (slashing mechanics in the security documents). Feed creation is
permissionless for a fee with a canonical registry (§15.6). Details:
`oracle-economics.md`.

### 7.6 AI-agent commerce — confirmed (§15.5, §15.32) — not-yet-built

- **Mandate objects** — a digital permission slip a principal grants an
  agent: principal, agent key, total budget and spent counters (u128), expiry
  epoch, counterparty policy (open or allowlist), per-transaction max, rate
  limit; **no re-delegation**; **instant revocation**; every spend references
  the mandate ID for a complete audit trail; any site can verify a mandate
  on-chain before serving the agent.
- **Service registry** — services publish machine-readable prices and
  interfaces for agent discovery (schema design open, see
  `agent-commerce.md`).
- **HTTP-402-style flows** — an agent pays for a resource inside an ordinary
  web request cycle.

## 8. The native DEX: shared pools and batch settlement (§15.13, §15.18, §15.37) — confirmed direction, not-yet-built

- **Liquidity separated from storefront.** Default: one canonical, shared,
  deep pool per asset pair in a public registry. Three site participation
  modes: (1) *storefront* — embed a swap widget over the canonical pool and
  attach a **disclosed** frontend fee; (2) *liquidity contributor* — a site's
  small pool deposits into the canonical pool and earns a share of its fees;
  (3) *independent pool* — for niche or custom markets (e.g. a game's item
  economy). Custom pools are the exception, not the default (liquidity
  fragmentation gives worse prices — §15.8).
- **Trust as an on-chain track record:** the registry records age, volume,
  fee history, and incident flags; wallets and aggregators filter on it. A
  storefront inherits the canonical pool's trust and only needs to earn a
  reputation for honest fees.
- **Mandatory per-block uniform-price batch settlement** is the native swap
  semantics (owner-decided, §15.37): swaps are submitted as intents
  (parallel-friendly); each block settles all intents on a pair at one
  clearing price; intra-block ordering games (sandwiches, front-running)
  become meaningless; there is **no instant-bypass lane**. Precedents: CoW
  Protocol, Penumbra (§15.18).
- **Chain-native retry:** an order is a short-lived on-chain intent with the
  user's limit price, a deadline (default ~10s, user-set), and a
  fill-or-cancel flag; the protocol keeps it in subsequent batches until
  filled, cancelled, or expired; a retried order never fills worse than the
  user's limit; pending orders are cancellable anytime (§15.37).
- **MEV policy:** extractive MEV is not monetized (§15.37); benign arbitrage
  that keeps pool prices aligned is welcome and pays ordinary fees.
- Latency honesty (§15.18, §15.39): a normal order fills in its first batch;
  the retry window matters only when the user's limit was not met, where the
  alternative is failing instantly.

Remaining mechanics (limit/slippage details, multi-hop routing,
shared-infrastructure pricing) are delegated design: `dex-batch-settlement.md`.

## 9. Tokens, NFTs, and application governance

Anyone can create fungible tokens and NFTs by paying normal fees, with
configurable properties (name, symbol, decimals, supply, minting, burning,
transfer rules, authority handling — §5). Wallets must prominently display
issuer powers. Applications and tokens may deploy their own governance
instances (proposals, quorum, delegation, timelocks) for a fee (§11). Core
protocol governance follows the public proposal-and-adoption process in §14
below.

## 10. ZK and post-quantum readiness

### 10.1 Where zk fits — confirmed policy (§15.25)

- **Yes:** succinct light-client verification of finalized checkpoints (§8) —
  prove once, verify millions of times cheaply.
- **Yes (later, optional):** compressed state for applications with masses of
  tiny objects — phase-2, never a launch dependency (§15.29).
- **No:** zk on the validator-to-validator consensus critical path — proving
  costs orders of magnitude more than executing; consensus bandwidth is
  reduced by aggregation, compact relay, and zstd instead (§15.19).

Merkle proofs remain the first implementation and fallback behind a versioned
proof interface.

### 10.2 Signature agility (security documents own the details)

Accounts use versioned authorization policies with a post-quantum
root/recovery path from creation; ML-DSA is the first candidate; strict-PQ vs
PQ-root-plus-session-keys is still an open technical gate. No full
post-quantum claim unless account signatures, consensus signatures,
commitments, and proofs are all covered.

## 11. Ethereum and Solana bridges (§10)

Bidirectional by design: lock native WEBC → mint wrapped WEBC on
Ethereum/Solana; burn wrapped → release native. Inbound: lock a supported
external asset → mint a WEBC-side representation tied to its exact origin
(chain, contract/program, identifier); burn → release. Delivery priority:
native ETH and SOL first, then standard sub-tokens and cross-chain messaging,
then additional chains (Bitcoin, Tron) later. Two same-name assets from
different origins are never the same thing.

**Cross-chain UX direction (§15.36 — planned, details open):** one action
("Send to Ethereum/Solana") with an upfront total-cost-and-time quote, a
single status view tracking both chains' finality, and a guaranteed refund
path on failure.

The trust, verification, and safety model for real value lives in the security
documents and `bridge.md`; real funds stay disabled until separately audited
and approved.

## 12. Wallet privacy and policy trees (research)

Taproot-inspired policy commitments (reveal only the path used) and
account-based stealth addresses remain research items; any scheme must address
browser scanning, spam, recovery, and post-quantum key agreement before
mainnet activation. (Unchanged; security-adjacent.)

## 13. Mainnet readiness

WEBC is not mainnet-ready until it has, at minimum: multi-node networking and
peer protection; durable storage and state sync; signed BFT consensus and
finality certificates; complete economic and slashing invariants; audited
wallet and key management; measured parallel execution and localized fees;
tested light-client verification; an audited contract runtime; production
bridge design with separate audits; the public distribution specification
(now: the `distribution-program.md` mechanics frozen and published);
long-running public testnet and adversarial testing; monitoring, upgrade, and
incident-response processes. The Phase 5.5 core security-review gate
(decision-record) applies before higher layers stack on the core.

## 14. Governance and launch philosophy (§11, §15.36)

Fair launch: no permanent founder key, no pre-mined insider allocation, no
mandatory protocol fee to a founder. Core changes follow a public
proposal-and-adoption process; the founder acts as initial maintainer with a
published sunset to an elected committee (§15.36 — planned). Honesty is a
product value: WEBC does not claim performance, finality, or readiness it has
not demonstrated (§11).

## 15. References and inspirations

- Sui object model and consensusless fast path: <https://docs.sui.io/doc/sui.pdf>
- FastPay (fast-path quorum certificates): <https://arxiv.org/abs/2003.11506>
- Mysticeti DAG-BFT: <https://arxiv.org/abs/2310.14821>
- Solana program execution and scheduling: <https://solana.com/docs/core/programs/program-execution>
- CoW Protocol batch auctions: <https://docs.cow.fi/>
- Penumbra batch swaps: <https://protocol.penumbra.zone/>
- Frequent batch auctions (Budish et al.): <https://academic.oup.com/qje/article/130/4/1547/1916146>
- Walrus erasure-coded blobs: <https://docs.walrus.site/>
- Mina succinct verification: <https://docs.minaprotocol.com/>
- Ethereum governance: <https://ethereum.org/governance/>
- NIST ML-DSA: <https://csrc.nist.gov/pubs/fips/204/final>

These are references, not codebases WEBC promises to copy wholesale.
