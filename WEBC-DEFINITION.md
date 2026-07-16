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

*Scope reminder: this briefing intentionally omits security, cryptography, and
robustness topics, which WEBC treats as first-class but defines elsewhere. Use this
document to reason about WEBC as a product, an economy, and an experience — and to
propose how to make it better.*
