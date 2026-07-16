# WEBC — a product, economic, and functional definition

Status: standalone briefing document. Self-contained on purpose.
Audience: an advanced reasoning model (and any human reader) asked to study WEBC
in prose — not code — and propose ways to make it **better** as a product, an
economy, and a platform.

## How to read this document

- This is a **definition for ideation.** It describes what WEBC *is* and *aims to
  be*, so a reader can reason about improvements, gaps, and new directions.
- It is **self-contained**: you do not need any other file to understand WEBC from
  this document.
- **Security, cryptography, robustness, and threat-modeling are intentionally out
  of scope here.** WEBC treats those as first-class, but they are defined and
  reviewed in separate documents. This briefing is deliberately about the product,
  the economy, the user and developer experience, and the functional design — so
  that improvement ideas focus on *what WEBC does and for whom*, not on how it is
  hardened. When a mechanism below has a security dimension, it is described only at
  the functional level (what it accomplishes), not the protective level.
- Where a design point is **decided**, it is stated plainly. Where it is **still
  open**, it is marked — those open points are the most fruitful places to propose
  improvements. A closing section lists open directions explicitly.

---

## 1. Essence in one paragraph

WEBC is an independent Layer-1 blockchain built for the web and the AI era. Its
purpose is to let any website, web app, web game, or software agent send and
receive money, issue assets, and run applications as naturally as they load a page
— with fast, cheap, final transactions, and without asking users to leave the
site or hand their accounts to it. Its native coin is **WEB COIN (ticker: WEBC)**.
It is designed so that three kinds of builders and users — humans, humans working
with AI, and fully autonomous AI agents — are all first-class participants, both in
*using* the chain and in *building* on it.

## 2. Identity

- **Project name:** WEBC
- **Native coin:** WEB COIN
- **Ticker:** WEBC
- **What it is:** an independent, custom Layer-1 blockchain (its own network), not a
  token issued on Ethereum, Solana, or any other chain.
- **Core language of the network software:** Rust.
- **Primary language for building websites/apps on it:** TypeScript (with more
  authoring options over time — see §9).
- **Audience:** global and general-purpose — not tied to one country, industry, or
  single application.
- **One-line description:** a blockchain that makes payments, assets, and
  applications feel native to the browser and to the internet, usable by people and
  by AI agents alike.

## 3. Why WEBC exists (the problem it addresses)

Today, using cryptocurrency inside an ordinary website is awkward. Users install
heavy extensions, approve confusing prompts, jump between apps, and often hand
control to whichever site they are on. Developers stitch together many tools, and
fees or congestion on unrelated apps can spill over and slow everyone down. And
almost nothing is designed for the emerging reality that **software agents (AIs)
will increasingly transact on their own** — browsing, buying, selling, and paying
for services.

WEBC's bet is that the web needs a money-and-application layer that is:

- **Web-native:** a site adds a wallet, a payment, a token, or a game with a small
  amount of integration, and the user stays on the site and stays in control.
- **Fast and cheap enough to feel instant and free** for ordinary use.
- **Parallel and isolated**, so a popular app or token does not congest or raise
  costs for unrelated ones.
- **AI-native**, so autonomous and AI-assisted workflows are supported end to end —
  both building applications and transacting on them.
- **Fairly launched**, with no pre-allocated founder or investor share.

## 4. Who WEBC is for

- **Everyday users** who want to pay, get paid, hold tokens/NFTs, and use on-chain
  apps directly from a website, keeping control of their own accounts.
- **Website and app developers** who want to add payments, assets, memberships,
  games, or marketplaces without building blockchain infrastructure themselves.
- **Game developers**, including makers of simple in-page/HTML games, who want
  real-time wallets, server-managed in-game tokens, and low-friction
  player-to-player transfers.
- **AI agents and AI-assisted developers** who read machine-readable documentation
  and a catalog of composable building blocks to assemble applications, and who can
  transact autonomously within limits set by their principals.
- **Participants in the network economy** — those who stake to help run the network,
  those who delegate their stake to others, and those who run verification nodes.

## 5. What WEBC lets you do (core capabilities)

- **Payments and transfers** of the native coin, in-page and peer-to-peer,
  including easy exchange during a conversation or a game.
- **User-created assets:** anyone can create fungible tokens and NFTs by paying
  normal network fees, with configurable properties (name, symbol, decimals,
  supply, minting, burning, transfer rules, authority handling).
- **Applications and objects:** on-chain application state for NFTs, game items,
  escrows, orders, sessions, marketplaces, memberships, and more.
- **Staking and delegation:** help run the network and earn rewards, or delegate to
  an operator without running a server.
- **Sponsored usage:** a site or app can pay its users' fees within strict, bounded
  budgets, so end-users can transact for free from that site.
- **Cross-chain movement:** bring value to and from Ethereum and Solana (see §10).
- **External data via a native oracle:** applications can consume outside
  information (prices, results, feeds) that many independent reporters submit and
  the network aggregates, so no single reporter dictates the value.
- **Web-native actions:** file purchase/download authorization, subscriptions,
  conditional payments, memberships, simple and web games, swaps, donations,
  reward-for-attention (opt-in ad) flows, and site-level revenue-sharing — built at
  the application layer so the base protocol stays simple.
- **Verification without heavy hardware:** browsers and lightweight clients can
  verify compact proofs of the chain's state rather than downloading everything
  (see §8), so confirming a payment or an account balance stays cheap.

## 6. The AI-native thesis (WEBC's distinctive bet)

WEBC is explicitly designed for a world where AI is a primary builder and user of
software. Concretely:

- **Three equal audiences:** human-only, human-with-AI, and AI-only workflows are
  all first-class, for both *building on* and *using* the chain.
- **Machine-readable everything:** documentation, contract interfaces, and a
  **component catalog** are structured so an AI agent can read them and assemble an
  application from documented, composable building blocks — the same catalog also
  serves human and human+AI developers.
- **AI web-agent commerce:** agents can pay and be paid in WEBC while browsing and
  acting, within budgets and permissions their principals set, enabling
  machine-to-machine and human-to-machine commerce.
- **An authoring language optimized for AI to write and read** (see §9), with
  documentation aimed at machine consumption, while staying easy for humans.

This is the trait most worth pushing further: *what does a blockchain look like when
autonomous agents are expected to be ordinary participants, not an afterthought?*

## 7. Economic model (money and incentives)

WEBC's economics are simple and fixed where it matters, and tuned by measurement
where numbers should come from evidence.

**The coin**
- **Genesis supply:** 10,000,000 WEBC.
- **Precision:** 12 decimal places (the smallest unit is 0.000000000001 WEBC).
- Amounts are always whole numbers of base units internally; the economy never
  depends on approximate/fractional arithmetic.

**Issuance (inflation)**
- New coins are issued to reward those who help run the network.
- The annual issuance rate **starts at 10%** and is **multiplied by 0.8 each year**
  (a 20% relative reduction per year) until it reaches a **1% floor**, which it
  hits after roughly 11 years.
- Rewards accrue **smoothly** over time (by block/epoch), never in one big annual
  jump.
- The 1% floor provides an enduring, predictable reward for network participants
  once the early high-issuance period ends.

**Distribution (how the genesis supply is meant to reach people)**
- **No fixed founder, developer, foundation, investor, or private-sale allocation
  — a fair-launch intent.**
- **30%** is reserved for people who make verifiable contributions after a publicly
  announced participation program begins.
- **70%** is reserved for broad, global public distribution.
- Test-network coins have no value and never convert into real coins; activity
  before the public program begins earns nothing automatically.
- The exact fair-distribution mechanism is **still open** and is one of the most
  important design problems (see §12).

**Fees (what using the network costs)**
- Fees are **cheap by default and dynamic under load**, priced by the real work a
  transaction does (computation, state access, storage growth, contention).
- **Localized pricing:** congestion on one application does not raise fees for
  unrelated applications; only a small network-wide floor applies during global
  overload.
- **Fee split:** half of the base fee is **burned** (removed from supply) and half
  funds **rewards** for network participants. An optional priority fee can speed up
  inclusion.
- **Sponsorship:** sites can pay users' fees within hard, bounded budgets (per user,
  per app, per operation, and per day), so a site can offer free usage without being
  drainable.
- WEBC deliberately does **not** promise a fixed fiat-denominated fee, because that
  would require trusting an external price source; it aims for negligible
  normal-payment fees and prices expensive operations by measured resource use.

**Participation economics (staking and delegation)**
- Producing/participating operators **stake** WEBC; anyone can also run a
  non-producing verification node without staking.
- Others can **delegate** their stake to an operator and share in rewards.
- A validator pool becomes active at **100 WEBC** total stake, of which the operator
  supplies at least **20 WEBC** and always at least **20%** of the pool; delegation
  supplies at most **80%**; the minimum single delegation is **1 WEBC**.
- There is **no global cap** on how many validators can register.
- Withdrawing staked coins takes a waiting period (about 7 minutes on the test
  network, about 7 days on the main network) — the network does not promise instant
  redemption.
- Correct participation earns rewards; provable misbehavior can cost stake (the
  incentive exists to keep the network honest; its mechanics live in the separate
  security documents and are out of scope here).

## 8. Performance and execution model (how it feels and scales)

WEBC's performance goals are **engineering targets**, to be proven by sustained
benchmarks before being claimed — not marketing numbers.

- **Block time target:** ~2 seconds.
- **Normal finality target:** ~6–8 seconds (a payment is settled and irreversible);
  ~12 seconds even under degraded network conditions.
- **Consensus style:** a permissionless, stake-based design with fast, BFT-style
  finality, where a rotating, stake-weighted subset of validators votes on each
  block so not everyone has to vote on everything. (WEBC deliberately does **not**
  use continuous "proof-of-history" hashing.)
- **Parallel execution is a core requirement, not an optimization.** Unrelated
  transactions run at the same time. This is achieved by combining two ideas:
  - every transaction **declares in advance** which state it will read and write,
    so the network can run non-conflicting transactions concurrently; and
  - application data can be held as **owned objects with versions**, so independent
    items don't block each other.
- **Hybrid state model:** simple **account-style balances** for coins, tokens,
  staking, and payments; **object-style state** for NFTs, game items, escrows,
  orders, sessions, and app-owned data. Developers pick whichever fits.
- **Application isolation:** each application gets its own namespace, so a busy app
  or token does not create congestion, cost, or contention for unrelated ones.
  Ordinary transfers touch **per-owner balances**, never one shared global object,
  which is what lets unrelated activity run in parallel.
- **Independent activity lanes:** the same wallet can transact on several sites at
  once without one site's activity serializing behind another's.
- **Lightweight verification:** browsers verify a compact proof of a finalized
  checkpoint plus a small proof for the specific account or object they care about,
  rather than downloading the whole ledger — inspired by succinct-verification
  designs so ordinary users and ordinary devices can check the chain cheaply.

## 9. Applications and the authoring experience

**The execution foundation (decided).** Smart contracts run on a restricted,
deterministic **WebAssembly (WASM)** engine, with **Rust** as the first authoring
language compiled to WASM off-chain. This is the fast, predictable execution core.
Other chains' virtual machines (e.g. the EVM or Move VM) are **not** the native
runtime; compatibility with Ethereum and Solana comes through bridges (see §10),
not by running their programs natively.

**The authoring roadmap (decided sequencing).**
- **First**, contracts are written in Rust (through a friendly Rust
  library/framework) and compiled to WASM off-chain, so real applications become
  possible early.
- **Later**, WEBC adds its **own high-level authoring language** — designed to be
  easy and intuitive for humans and especially productive for AI to read and write —
  that lowers (transpiles) down to the same audited Rust framework. It is a friendly
  *front end*, not a second engine, so it inherits the speed and predictability of
  the core.
- The architecture is deliberately built so this future language **plugs in as one
  more front end over a stable target**, rather than requiring a rewrite.
- **Design intent for that language:** optimize for AI to author and to read, ship
  machine-oriented documentation, stay easy for human developers, be compiled (not
  interpreted), and take ergonomic cues from modern, safety-oriented languages
  rather than older contract languages. Its exact look-and-feel and name are still
  open.

**Keeping applications maintainable (a first-class product goal).** WEBC treats
contract quality as something the platform protects, not something left to
developer discipline:
- an opinionated, uniform structure and **small composable components** instead of
  sprawling monoliths;
- a **component catalog** and machine-readable docs so builders (human or AI)
  assemble apps from documented, reusable parts;
- automated analysis/linting and a pre-deployment review step (including automated/
  AI review) to catch overly complex or unsafe patterns before an app ships.

**How applications reach the outside world.** On-chain code stays deterministic: it
does not directly browse the web, read files, call arbitrary services, or read the
clock. Instead:
- **External data** comes in through the **native oracle**: many independent
  reporters submit values, and the network aggregates them (e.g. by median) so no
  single reporter controls the answer. External oracles remain optional.
- **External actions** (file transfers, button actions, webhooks, API calls,
  headless work) are performed by browser or server **agents** that act on on-chain
  events and can return signed receipts; the chain records authorization, payment,
  and content hashes. File contents normally stay off-chain; only their hashes and
  permissions live on-chain.

**Native app building blocks WEBC targets:** fungible tokens with configurable
policies, NFTs, swaps, conditional payments, sponsored fees, simple and web games,
memberships and access rules, subscriptions, marketplaces, donations and
payment/subscription links, and optional per-application governance.

## 10. Cross-chain (bridges as a capability)

WEBC is meant to connect to the largest ecosystems, in both directions:
- **Outbound:** lock native WEBC and mint a wrapped representation on Ethereum or
  Solana; burn the wrapped form to release native WEBC.
- **Inbound:** lock a supported Ethereum or Solana asset and mint a WEBC-side
  representation tied to its exact origin; burn it to release the original.
- **Delivery priority:** native ETH and SOL first (ideally in parallel), then their
  standard sub-tokens and cross-chain messaging so applications on different chains
  can communicate — not only move assets — and additional chains (such as Bitcoin
  and Tron) later.
- Each represented asset is tied to its exact origin (chain, contract/program,
  identifier), so two differently-sourced assets that merely share a name are never
  treated as the same thing.

(The trust, verification, and safety model for moving *real* value across chains is
defined in the separate security documents and is out of scope here; this section
describes only the intended capability.)

## 11. Governance and launch philosophy

- **Fair launch:** no permanent founder key, no pre-mined insider allocation, no
  mandatory protocol fee routed to a founder or team. Voluntary donations and
  optional revenue-share are supported at the application layer.
- **Open evolution:** core changes follow a public, proposal-and-adoption process
  (in the spirit of open internet standards) rather than automatic rule by the
  largest coin holders. Applications and tokens may create their **own** optional
  governance instances (proposals, quorum, delegation, timelocks) for a fee.
- **Honesty as a product value:** WEBC does not claim performance, finality, or
  readiness it has not demonstrated; capabilities are labeled as confirmed,
  planned, experimental, or not-yet-built.

## 12. Non-negotiable qualities and design principles

WEBC commits to being, at the same time: **fast, stable, secure, decentralized, and
low-fee.** Ease of use and ease of integration must never be bought by weakening
these. (Security is a non-negotiable quality but is defined and hardened in separate
documents, per this briefing's scope.)

Product-level principles worth preserving in any improvement:
- keep the base protocol **simple**, and push richness to the application layer;
- keep unrelated applications **isolated** in scheduling and pricing;
- keep ordinary users on **lightweight devices and browsers**, not specialized
  hardware;
- make the common things (a payment, a token, a wallet, a game) **easy**, and make
  advanced things **possible**;
- treat **AI participants** as ordinary, expected users and builders.

## 13. What "better" could mean — open directions for improvement

These are genuinely open and are the most valuable places to think. They are
product, economic, and experience questions, not security questions.

- **Fair distribution design.** How should 30% reach real contributors and 70%
  reach a broad global public, rewarding *useful, verifiable work* rather than raw
  account count or uptime, with public rules, diminishing returns, and an appeal
  process — while resisting people gaming it? This is unsolved and high-impact.
- **Fee and sponsorship economics.** What fee curves, sponsorship budgets, and
  incentives make WEBC feel free to end-users while remaining sustainable and
  un-drainable, and while keeping unrelated apps isolated?
- **The authoring language and catalog.** What surface syntax, component model, and
  documentation format would make WEBC the easiest chain for AI agents *and* humans
  to build safe, composable applications on? What is the ideal "catalog of building
  blocks" for AI-assembled apps?
- **AI-agent commerce patterns.** What primitives, permissions, budgets, and
  discovery mechanisms best support autonomous agents paying and being paid — and
  new markets (machine-to-machine services, attention, data, compute)?
- **Web and game experience.** What integration surface makes adding WEBC to a
  website, web app, or plain HTML game genuinely trivial, including real-time wallet
  creation and server-managed in-game economies?
- **Staking and participation design.** How to keep validation broadly
  decentralized and rewarding without a hardware arms race, and how delegation,
  rewards, and participation UX should feel.
- **Cross-chain user experience.** What makes moving value and messages to/from
  Ethereum and Solana feel one-click and trustworthy to ordinary users?
- **Adoption strategy.** What flagship applications, developer ergonomics, and
  network effects would make a web-native, AI-native chain actually get used?
- **Beyond the current scope.** What capabilities is WEBC *missing* that its
  web-native, AI-native, fair-launch identity implies it should have?

## 14. Quick reference (plain-language glossary)

- **WEBC / WEB COIN:** the native coin; also the project/network name.
- **Layer-1:** a base blockchain that runs on its own, not on top of another chain.
- **Validator / operator:** a participant who helps produce and confirm blocks by
  staking coins.
- **Delegator:** someone who backs a validator with their stake and shares rewards
  without running a server.
- **Staking:** locking coins to help run the network and earn rewards.
- **Finality:** the point at which a transaction is settled and cannot be reversed.
- **Fee burn:** permanently removing part of each fee from the supply.
- **Token / NFT:** user-created assets — interchangeable (token) or unique (NFT).
- **Namespace:** an application's isolated area of the state, so apps don't
  interfere with each other.
- **Oracle:** the mechanism that brings outside data on-chain via many independent
  reporters aggregated together.
- **Bridge:** the mechanism for moving value between WEBC and other chains.
- **WASM:** the fast, predictable engine that runs application code.

---

## 15. Improvement log (living section)

This section records the ongoing improvement review between the owner and the
reviewing model. Each entry carries a status: **decided**, **recommended**
(reviewer recommends, owner has not confirmed), **proposed** (a concrete design
sketch, open to challenge), or **open** (unsolved). Sessions are ephemeral; this
section is the persistent memory of the review. Newest entries last.

### 2026-07-16 — Round 1: economics, distribution, agents, oracle, DEX

**15.1 Base-unit integer width — recommended: u128, keep 12 decimals, keep 10M supply.**
Finding: 10,000,000 WEBC × 10^12 base units = 10^19, which already uses 54% of a
u64's range (~1.845 × 10^19). Under the issuance schedule (10% decaying ×0.8/yr to a
1% floor), total supply reaches ~15.6M WEBC by year ~11 and overflows u64 around
year ~28 (fee burn may delay this but cannot be guaranteed to). Options compared:

| Option | Overflow horizon | Pros | Cons |
|---|---|---|---|
| u128 amounts, 12 dp, 10M supply | ~4,500 years | No economic change; finest granularity for AI micropayments | Amount fields double to 16 bytes; 128-bit math is compiler-emulated in WASM (minor cost); JS needs BigInt (needed for u64 anyway) |
| u64, 9 dp, 10M supply | ~750 years | Smallest state, native u64 speed, Solana-standard precision | If WEBC price exceeds ~$1,000 (a ~$10B cap), the smallest unit exceeds a micro-dollar — coarse for per-request AI payments in success scenarios |
| u64, 12 dp, 1M supply | ~290 years | Keeps 12 dp on u64 | Pure re-denomination (no real economic change); high sticker price per coin deters retail psychologically; weakest headroom |

On "any fixed-width integer eventually overflows under a perpetual 1% floor": true
in the limit, but u128 pushes the horizon to ~4,500 years, fee burn can make net
growth ≤ 0, and a re-denomination hard fork centuries out is acceptable. The
practical bar is "never within the protocol's meaningful lifetime," which u128
clears by orders of magnitude. Recommendation: **u128 everywhere an amount is
stored or computed** (balances, supply counters, reward math), keeping the decided
12-dp / 10M-supply economics untouched. Status: **recommended** (owner leaning,
not confirmed).

**15.2 Genesis bootstrap for a fair-launch PoS — proposed path.**
Problem: validators need stake, but at a fair launch nobody holds coins, and
distribution needs a running network. Precedents: nearly every PoS L1 (Cosmos,
Polkadot, Solana, Avalanche, Cardano, Celestia…) bootstrapped from sale/investor/
foundation allocations — unavailable to WEBC by principle. Pure-PoS fair launches
are rare and cautionary (Nxt 2013: genesis distributed to 73 buyers → extreme
concentration). PoW chains fair-launch easily because work is external to the
chain; several chains (Peercoin, Decred, Ethereum in spirit) used PoW *first* to
distribute, then PoS — but mining contradicts WEBC's lightweight-device identity.
Proposed WEBC path, consistent with the existing 30% contributor pool and the
"testnet earns nothing before the announced program" rule:
1. Publicly announce the participation program; run an **incentivized validator
   recruitment program on the test network** as its first contribution track.
2. At genesis, allocate earned rewards from the 30% pool to those proven operators
   → day one starts with a real, distributed validator set that owns stake.
3. A labeled **bootstrap phase** with issuance keyed to *staked amount* (reward
   budget = rate × total stake, capped by the schedule's % of total supply), so a
   tiny early staking base cannot capture outsized absolute issuance.
4. Published sunset criteria (validator count, stake dispersion, distribution
   progress) for exiting the bootstrap phase.
Status: **proposed**.

**15.3 Public distribution (the 70%) — fee-cashback rejected; "fair" reframed.**
The reviewer's earlier fee-cashback idea fails the owner's critique: rebate > fee
makes spam profitable; rebate = fee makes spam free; rebate < fee is merely a fee
discount, not distribution. Per-account diminishing returns do not survive sybil
account farms. General lesson adopted: **any giveaway keyed to a resource sybils
can manufacture (accounts, transactions, uptime) is gameable; distribution must
key to something genuinely scarce** — capital, verified identity, or hard-to-fake
work. A further tension is unique to WEBC: an AI-native chain that welcomes
autonomous agents as first-class users cannot coherently gate rewards on "proof of
being human." Therefore the document's working definition of *fair* becomes:
**open access under public rules with no privileged insiders — not equal-per-human.**
Working portfolio (each channel capped, monitored, individually stoppable, spread
over ~10 years): (a) usage-linked fee subsidies (honest framing: subsidized
acquisition, not free money — ungameable because spam always net-costs);
(b) recurring **open public auctions** with proceeds burned or routed to the
ecosystem fund — sybil-proof by construction, equal access, but in tension with
"fair launch" optics since it resembles a sale: flagged for owner judgment;
(c) optional privacy-preserving identity-gated claims as an experimental slice.
Status: **open** (highest-value unsolved problem; portfolio approach proposed).

**15.4 Founder compensation — honesty gap flagged.**
The project has a solo founder who will plausibly earn a meaningful share of the
30% contributor pool through genuine, verifiable work. If that happens without
being stated up front, "fair launch, no founder allocation" becomes misleading in
substance even if true in form — reputationally worse than an explicit allocation.
Options: (a) declare a modest explicit founder allocation with long vesting, or
(b) keep zero allocation but pre-publish the rules by which founder contributions
are valued and paid from the 30% pool, ideally with some review not controlled by
the founder alone. Either is defensible; silence is not. Status: **open — owner
decision required.**

**15.5 AI-agent commerce primitives — adopted direction.**
Three protocol-level standards: (a) a **mandate** object — an on-chain, instantly
revocable authorization a principal grants an agent, carrying total budget,
expiry, counterparty allowlist, and per-transaction limits; (b) an on-chain
**service registry** where services publish machine-readable prices and
interfaces for agent discovery (the commerce counterpart of the component
catalog); (c) compatibility with **HTTP 402-style web payment flows** so an agent
can pay for a resource inside an ordinary web request cycle. Status: **decided
direction** (owner approved; detailed design pending).

**15.6 Oracle reporter economics — proposed.**
The definition specifies aggregation (median of many reporters) but no reason for
reporters to exist. Proposal: reporters register per feed with a stake; consuming
applications pay per-read or subscription fees; fees are distributed to reporters
weighted by accuracy (closeness to the accepted aggregate) and liveness;
persistent outliers lose standing (slashing mechanics belong to the security
docs). Feed creation is permissionless for a fee, with a canonical feed registry.
Two honest open issues: (a) cold start — before apps pay fees, reporter rewards
need seeding from issuance or the ecosystem fund, with a sunset; (b) free-riding —
once a value is on-chain anyone can read it; either enforce read-fees at the
runtime level (possible since WEBC controls the execution engine) or accept
partial public-good funding. Status: **proposed**.

**15.7 Ecosystem fund — proposed (owner-amended shape).**
Owner direction: not an automatic carve-out per site, but a **grant program** —
projects committing to build on WEBC apply and receive support, primarily as
sponsored-fee underwriting, funded by ~10–20% taken from the 70% public pool.
Reviewer refinements: (a) pay grants as **non-transferable fee credits** rather
than liquid coins — they cannot be dumped on the market and are spendable only as
usage, which aligns the grant with real adoption; (b) restate the distribution
split explicitly (e.g. 30% contributors / 55–60% public / 10–15% ecosystem) rather
than hiding the fund inside "70% public" — otherwise the fair-launch accounting
becomes misleading; (c) name the grant decision process: initially transparent
public applications against published criteria (with the founder deciding, stated
honestly), migrating to community review as governance matures — an undefined
decider is a centralization and credibility hole. Status: **proposed**.

**15.8 Native per-site liquidity pools and a WEBC DEX layer — owner idea, refined.**
Owner concept: any site can trivially create its own liquidity pool, set fees at
fine granularity, expose it for others to use; other sites can route through an
existing site's pool and add their own surcharge; aggregators arise that pick the
best pool across sites; combined with bridges this yields a fast, cheap, web-native
exchange experience. Reviewer critique and refinement:
- **Real strength:** "an exchange as an embeddable website component" fits WEBC's
  web-native identity and the surcharge model is a natural site-level revenue
  share. An in-protocol swap building block is already in §9's target list.
- **Main flaw — liquidity fragmentation:** thousands of small per-site pools give
  worse prices, higher slippage, and easy arbitrage extraction against stale small
  pools; aggregation only partially compensates. Precedent: virtually all DEX
  volume consolidates into a few deep pools per pair (Uniswap-style), with many
  *frontends* charging interface fees (the proven shape of the owner's surcharge
  idea).
- **Refined model:** separate **liquidity** from **storefront**. Default: one
  canonical, shared, deep pool per asset pair in a public registry; any site
  embeds a swap component against shared pools and attaches its own **disclosed**
  frontend fee (surcharges must be on-chain-visible so users see the full fee
  breakdown; silent markup stacking is a user-harm and trust risk). Custom
  private per-site pools remain possible as the exception (e.g. a game's item
  economy), not the default.
- **Isolation tension to resolve:** §8 promises per-application namespaces and
  localized fee pricing, but shared pools are by definition shared hot objects
  across applications; routing a swap through several pools touches several
  namespaces. The pricing/scheduling model needs an explicit answer for
  intentionally-shared infrastructure objects.
Status: **proposed** (direction approved in spirit by owner; fragmentation
refinement pending owner view).

### 2026-07-16 — Round 2: u128 costs quantified, bootstrap grants, DEX architecture

**15.9 u128 cost quantification (extends 15.1).**
Owner asked for concrete impact numbers. Estimated deltas versus u64:
- **Compute:** 128-bit add/subtract is ~2 CPU instructions; multiply/divide lower
  to library routines in WASM (~5–20× a u64 op). A transfer performs tens of
  amount operations (nanoseconds total), while verifying its signature alone costs
  tens of microseconds — amount arithmetic is well under ~0.1% of transaction CPU.
  No measurable TPS effect.
- **Speed/finality:** block time and finality are set by network and consensus
  (seconds); arithmetic contributes nothing perceptible.
- **State size:** +8 bytes per stored amount. Balance-heavy records grow roughly
  5–10%; most other state is unaffected.
- **Bandwidth and fees:** encode amounts as variable-length integers on the wire
  (small values stay small), so transaction size grows ~0–2%; the fee impact is
  limited to the storage component — a few percent at worst.
- **Precedent:** Ethereum computes all value in 256-bit words at global scale;
  128-bit is half that width.
Conclusion: the only real cost is ~8 extra bytes per stored amount; everything
else is noise. Status: **recommended; awaiting owner confirmation** (owner
leaning yes).

**15.10 Bootstrap validator grants — owner proposal, adopted with refinements.**
Owner's shape: split the 30% contributor pool into **25% general contributions +
up to 5% validator-bootstrap grants**. Operators first prove themselves on the
test network; at mainnet genesis they receive **stake-locked coins** (usable only
for staking) to run validators; after a period the coins become their own.
Reviewer refinements folded into the working design:
1. **Vest by operation, not by calendar:** the grant unlocks gradually per epoch
   of provably correct validation (target horizon 1–2 years); quitting early or
   misbehaving forfeits the remainder.
2. **Select on sustained correct operation over weeks, not raw computing power**
   — compute is rentable; reliability is the scarce, honest signal.
3. A small **personal co-stake**, ramping over time, so operators have their own
   money at risk beyond the gift.
4. **Per-operator cap plus diversity criteria** (hosting provider, geography) so
   the validator set is not concentrated on one cloud; sybil applicants gain
   little because grants are capped per identity and forfeitable.
5. Grants **count as the operator's own share** for the ≥20 WEBC / ≥20%-of-pool
   activation rule.
6. The 5% is a **ceiling, not a target** — unused budget returns to the general
   contributor pool.
7. **Phase-0 honesty:** founder-run nodes at genesis are acceptable if labeled
   temporary, with published criteria for retiring them.
Status: **decided direction** (parameter details open).

**15.11 Distribution, restated simply (extends 15.3).** There is no known way to
hand out free coins to strangers that sybils cannot game. WEBC therefore promises
"public rules, equal access, no insider privilege" — not "equal amount per
human" — and uses several capped, stoppable channels instead of betting on one.
Two owner decisions remain **pending**: (a) founder compensation — an explicit
small vested allocation, or zero allocation with pre-published rules for valuing
the founder's contributions; (b) whether recurring open auctions are acceptable
as one distribution channel.

**15.12 Ecosystem fund — upgraded to decided.** Owner approved 15.7 as refined:
grant program with applications against published criteria; grants paid as
non-transferable fee credits; the distribution split restated explicitly;
founder-judged initially (stated honestly), migrating to community review.

**15.13 DEX architecture round 2 — owner additions folded in.**
Owner keeps small pools, wants small pools able to **contribute to big pools**, a
structure that **uses trust**, and one that **exploits parallelism**. Working
architecture:
- **Three participation modes per site:** (1) *storefront* — embed a swap widget
  over the canonical shared pool and add a disclosed frontend fee; (2) *liquidity
  contributor* — the site's small pool deposits into the canonical pool and earns
  a share of its fees (the owner's "small pool feeds the big pool"); (3)
  *independent pool* — for niche or custom markets (e.g. a game's item economy).
- **Trust as an on-chain track record:** the pool/storefront registry records
  age, volume, fee history, and incident flags; wallets and aggregators filter on
  it. A storefront built over the canonical pool inherits the pool's trust and
  only needs to earn a reputation for honest fees — users never have to trust a
  small site's own liquidity.
- **Parallelism via per-block batch settlement:** swaps are submitted as intents
  (parallel-friendly, fits declared read/write sets), and each ~2-second block
  settles all intents on a pair at **one uniform clearing price**. This removes
  the serial hot-object bottleneck *and* makes sandwich/front-running attacks
  meaningless (ordering inside a block no longer matters) — most chains retrofit
  this; WEBC can make it the native default. Liquidity sharding stays a later
  option for extreme pairs.
Status: **decided direction** (mechanics open).

### Process notes (owner-decided, 2026-07-16)

- All work happens on `main`; no side branches. Every review round commits its
  results to this file (this section), because working sessions are ephemeral.
- Stale work branches were merged or discarded on 2026-07-16; this repository's
  `main` is the single line of history.
- Owner stance: decided points are the owner's, but better-argued alternatives are
  welcome at any time; the reviewer must review the owner's ideas critically, not
  deferentially, and must present pros/cons for every option when asking for a
  decision.

---

*Scope reminder: this briefing intentionally omits security, cryptography, and
robustness topics, which WEBC treats as first-class but defines elsewhere. Use this
document to reason about WEBC as a product, an economy, and an experience — and to
propose how to make it better.*
