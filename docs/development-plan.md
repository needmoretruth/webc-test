# WEBC development plan

Status: authoritative implementation plan
Date: 2026-07-17
Product scope source: `WEBC-DEFINITION.md` (§16 lists decided vs delegated;
§15 wins over older sections). This plan implements those decisions; it never
re-litigates them. Honesty labels (§11) apply to every claim.

Implementation checkpoint: Phases 0-3 passed their repository gates; Phase 4
(networking and signed BFT consensus) is active. Phase 4 A-1 (authenticated P2P
networking and transaction gossip), the A-2 consensus core, and the A-3
deterministic core are done: the stake-weighted leader schedule, the
Proposal/Vote/Certificate wire messages, the per-epoch validator-set snapshot
writer, a self-verifying finality certificate, received-block validation
(`Node::import_block`), a full multi-round Tendermint machine with locking and
safe round changes (`webc-chain::ConsensusMachine`), and objective equivocation
detection — proven by deterministic tests. The async `ConsensusDriver` runs the
machine over real `webc-net` TCP, feeds its mempool into proposals, and
certificate-verified state sync lets a late-joining node catch up — proven by
loopback tests. **Phase 4's consensus mechanism is NOT complete or safe:** a
2026-07-16 read-only review reported HIGH-severity consensus
safety/liveness/DoS gaps (no `valid(v)` re-execution before
prevote/lock/finalize, a silent halt on failed import, unbounded attacker-round
memory, and no vote/lock WAL → crash-restart self-equivocation — see
`docs/review/findings.md` C1–C4 and the P0 list in the remaining-work section
below). This marker records progress and does not weaken any acceptance
criterion below.

This plan is written so a new development session can continue without
inventing product decisions. Read `AGENTS.md`, `WEBC-DEFINITION.md` (§16
first), `docs/decision-record.md`, this file, `docs/whitepaper.md`, and
`docs/implementation-status.md` before changing protocol code.

## Working rule

The current repository is a prototype, not the new protocol baseline. Preserve
useful code, but do not extend known-invalid assumptions merely because tests
currently pass.

Every phase must:

- keep deterministic state transitions;
- use typed errors;
- add invariant and adversarial tests;
- update implementation status and decision records;
- avoid claims not demonstrated by repeatable tests (public speed claims stay
  at ~2s / 6–8s until the `speed-roadmap.md` gates pass — §15.42);
- keep real bridge funds disabled;
- keep economics configurable until the relevant phase freezes them.

## Phase order at a glance

```text
0   repository/spec baseline                     — complete
1   deterministic protocol core repair           — complete
2   wallet wire format + security foundation     — complete (ref benchmarks owed)
3   local node, storage, developer APIs          — complete
4   networking + signed BFT consensus            — ACTIVE, not safe yet
5   staking pools and economics
5.5 core freeze + independent security review    — owner-confirmed gate
6   parallel execution, localized fees, storage deposits
7a  contract runtime + interim Rust authoring + native oracle
7b  Weft language and tooling (later, same seam)
8   native DEX and batch settlement
9   agent commerce (mandates, service registry, HTTP-402)
10  succinct proofs and post-quantum experiments
11  fast path and speed-roadmap benchmarks
12  web/internet platform and flagship applications
13  tokens, NFTs, application governance
14  bridge prototypes and cross-chain UX
15  validator operations stack
16  public incentivized testnet + distribution program
17  mainnet gates
18  production bridges
19  phase-2 additions (blob layer, zk state compression)
```

Phases 0–7 keep their historical numbering (other documents reference them);
8+ are renumbered in this revision.

## Phase 0: repository and specification baseline — complete

Goal: make the repository safe to continue. (Tasks and acceptance preserved in
git history; all gates passed.)

## Phase 1: repair the reusable protocol core — complete

Goal: a correct deterministic single-node state machine before networking.
Delivered: 12-decimal amounts, the confirmed inflation curve, staking
activation rules (100/20/80/1), ADR-0008 exit lifecycle, genesis
reconciliation, atomic block execution, declared-access enforcement, signed
slashing evidence, supply invariant report — each with invariant and
adversarial tests. (Details in `implementation-status.md`.)

## Phase 2: wallet wire format and security foundation — complete (reference benchmarks owed)

Goal: browser-created transactions exactly understood by Rust nodes without
exposing keys to host sites. Delivered through the session-key gate (see
`session-keys-implementation-plan.md`); the single open item is
reference-machine benchmark numbers, which this cloud container cannot
produce honestly.

## Phase 3: local node, storage, and developer APIs — complete

Goal: a restartable node usable by browsers and local applications.
Delivered: `webc-storage` (redb-backed, crash-safe), the restartable node,
mempool, HTTP/WS APIs, devnet faucet, browser node client, and the reference
demo site — verified end to end.

## Phase 4: networking and signed consensus — ACTIVE, not safe yet

Goal: a real multi-machine devnet with staked permissionless validators.

### Tasks

- implement authenticated peer identities and peer discovery;
- gossip transactions, proposals, votes, and finality certificates;
- rate-limit and score peers without making stake mandatory for ordinary
  verification nodes;
- implement deterministic leader schedule and stake snapshots;
- implement signed prevote/precommit (or selected BFT equivalent);
- select rotating stake-weighted voting committees without a global
  validator-count cap;
- verify chain ID, height, round, proposal hash, validator membership, and
  voting power;
- implement fork choice, lock rules, timeout/round changes, and state sync;
- implement objective double-vote/invalid-proposal evidence;
- keep PoH absent from consensus.

### Acceptance

- geographically separated nodes converge on one finalized chain;
- normal blocks finalize in 6-8 seconds under the target test topology (the
  conservative claim; §15.42 stretch targets are Phase 11's job);
- delayed/lost messages trigger safe round changes, not conflicting finality;
- <1/3 malicious voting power cannot finalize invalid/conflicting blocks;
- evidence from signed conflicting votes triggers the correct slash exactly
  once;
- a joining node syncs from a checkpoint without replaying all history.

(The current detailed P0/P1 worklist is in the "Immediate next implementation
milestone" section at the end of this file.)

## Phase 5: staking pools and economics

Goal: complete the economic-security rules before public incentivization.

### Tasks

- enforce 20/80 operator/delegator pool ratio continuously;
- enforce the 100 WEBC activation minimum and 20 WEBC operator minimum;
- enforce the 1 WEBC minimum per active delegation position;
- implement activation/deactivation queues and epoch snapshots;
- make stake splitting unable to increase voting power or bypass limits;
- implement commission, reward accounting, claims, compounding, dust rules;
- implement inflation curve and fee distribution against supply invariants;
- define severe malicious slashes and softer operational penalties
  (severity percentages are an owner decision at this freeze — AGENTS.md);
- define correlated slashing for coordinated provable attacks;
- add public validator performance/reward/slash data;
- add faucet-funded devnet staking UX;
- **decide the §15.2 bootstrap-phase issuance proposal with the owner**
  (issuance keyed to staked amount during bootstrap; sunset criteria);
- prepare the stake-locked grant and vest-by-operation primitives the
  bootstrap program needs (`distribution-program.md` §3.2) so Phase 16 does
  not retrofit them.

### Acceptance

- property tests cover arbitrary delegation/reward/slash/withdraw sequences;
- no operator can exceed allowed delegation leverage; pools below threshold
  follow the safe deactivation rule; no reward-accounting dust;
- withdrawal cannot evade the slashable evidence window;
- reward totals reconcile exactly;
- economic simulations document centralization and attack-cost scenarios.

## Phase 5.5: core freeze and independent security review — owner-confirmed gate

Goal: an earlier independent security-review gate for the security-critical
core (consensus + cryptography + economics), recorded in
`docs/decision-record.md`, before higher layers stack on it. Additional to
the pre-mainnet audits, not a replacement.

### Tasks

- freeze the core (versioned interfaces, no behavior changes in flight);
- resolve every open blocking finding from `docs/review/findings.md` first —
  at minimum the CONFIRMED HIGH/critical items, each with a reproduction test
  then a fix;
- add the supply-chain CI gate (`cargo-deny` + JS advisory scan) and stand up
  fuzz targets (wire decode, canonical encoding, mempool admission, tx
  execution);
- prepare an audit package: threat model, invariants, consensus safety
  argument (including committee sampling if adopted), economic model;
- obtain an independent/external review of the frozen core.

### Acceptance

- no open HIGH/critical finding remains for the core;
- supply-chain and fuzz gates run green in CI;
- the external review's blocking findings are resolved before Phase 6+ builds
  on the core.

## Phase 6: parallel execution, localized fees, and storage deposits

Goal: unrelated sites and applications do not block each other at the state
scheduler or fee layer, and storage is priced as occupancy (§15.22).

### Tasks

- implement application namespace registry;
- implement enforced account/object read/write declarations end to end;
- build deterministic parallel batches and transactional overlays;
- resolve deterministic commit order and retry behavior;
- implement per-resource/application congestion measurement;
- implement localized base/priority pricing plus a network-wide minimum;
- implement fair block packing so one hot application cannot monopolize
  capacity;
- implement sponsor/paymaster accounts with the §15.35 cap structure
  (per-user / per-app / per-operation / per-day; launch values are
  measurement placeholders);
- **implement storage deposit + deletion rebate** (§15.22): per-byte deposit
  locked on write, majority refund on delete, supply-invariant accounted;
- design the hot/cold tiering boundary (archive-node interface + proofs) as
  an ADR now, implementation may lag (§15.22);
- adopt the frugality defaults where they land naturally at this layer:
  varint amount encoding at rest/wire (§15.14 — a wire-version bump), zstd
  storage-layer compression (§15.19/15.24);
- build sharded examples for tokens, games, swaps, and site sessions.

### Benchmarks

Run on at least: minimum reference machine (4 cores, 8 GB, SSD); recommended
(8 cores, 16 GB, NVMe); a performance machine with published specs. Measure
simple transfers, conflicting transfers, independent applications, token
transfers, storage-heavy contracts, and adversarial access lists.

### Acceptance

- unrelated application traffic executes concurrently;
- one application's congestion does not raise another's localized price;
- global saturation stays bounded by fair capacity rules;
- storage deposits/rebates reconcile in the supply invariant under
  create/delete/crash-restart property tests;
- sustained simple-transfer benchmark reaches staged 100/500/1,000/2,000+ TPS
  gates before any claim is published;
- deterministic roots match across thread counts and machines.

## Phase 7: contract runtime, native oracle, then Weft

Goal: ship the parallel contract runtime on the Rust→WASM foundation and the
native oracle with its decided economics. Sequencing (owner-confirmed): the
authoring language is a later, separately-resourced project (7b); an interim
Rust-eDSL/SDK path ships first (7a).

### Phase 7a — runtime + interim Rust authoring (ships first)

- restricted deterministic WASM, Rust-first, is the execution engine;
- Move VM and EVM are not the native runtime; compatibility comes via bridges;
- benchmark the WASM runtime against the reference applications before
  freezing the ABI;
- contracts authored in Rust (embedded-DSL/SDK over the audited framework),
  compiled off-chain to deterministic WASM;
- freeze a stable contract **ABI** and the "authoring front-end → lowering →
  audited Rust framework → WASM" **seam** as a versioned, swappable boundary;
  the chain only ever accepts deterministic WASM + metadata;
- the framework exposes catalog building blocks behind small uniform
  interfaces (§15.44 quality bar) — the same components Weft will surface.

### Phase 7b — Weft language and tooling (later, separate project)

Execute `weft-language-plan.md` within the decided §15.41/15.43/15.44
commitments: grammar/type/linearity/manifest specs, the CI-tested examples
corpus, the single-binary toolchain, editions policy, linter/pre-deploy
review, and the AI-authoring acceptance evaluation. Weft plugs into the 7a
seam; never a runtime rewrite.

### Native oracle (with §15.17/15.21 economics)

Execute `oracle-economics.md`: feed registry + bonded reporters + median
aggregation; **pull-based at-most-once-per-block updates**; per-fresh-read /
shared-read / subscription fees; accuracy/liveness-weighted revenue
distribution; ecosystem-fund seeding hooks (usage-proportional,
accuracy-gated, capped, auto-sunset); first-party publisher class; free
display-only reads via light clients.

### Common reference applications

- fungible token with mint/freeze/revoke policy;
- NFT collection;
- **canonical-pool swap intent settled in a per-block uniform-price batch**
  (replaces the old per-transaction constant-product reference — §15.37);
- commit/reveal rock-paper-scissors;
- conditional payment/refund;
- sponsored website membership/payment;
- mandate-gated paid API call (agent commerce preview);
- object/account contention stress test.

### Acceptance

- publish benchmark code/results; freeze the versioned ABI;
- reference applications pass on the interim Rust path (7a) and later compile
  from Weft to the same behavior (7b);
- the linter/pre-deploy review rejects the anti-pattern fixtures;
- the oracle resists a single lying reporter, distributes revenue by
  accuracy/liveness, sunsets unconsumed feeds, and slashes provably wrong
  reports exactly once;
- oracle read-fee amortization curves are published before any "cheap
  oracle" claim.

## Phase 8: native DEX and batch settlement

Goal: the decided DEX architecture (§15.13/15.18/15.37) as the native swap
layer. Execute `dex-batch-settlement.md`.

### Tasks

- pool/storefront registry with on-chain track records;
- canonical pool objects + LP accounting (batch-cadence deposits/withdrawals);
- intent objects (limit price, deadline, fill-or-cancel), escrow,
  expiry/cancel;
- per-pair uniform-price batch clearing inside `build_block`/`apply_block`,
  netting first, pool as residual counterparty, pro-rata partial fills;
- chain-native retry across batches; no bypass lane exists anywhere;
- multi-hop routing through WEBC as numeraire with all-or-nothing atomicity;
- disclosed storefront fee attribution;
- per-pair congestion domains (shared-infrastructure pricing);
- SDK swap component + pending-intent UX (§15.39 ladder).

### Acceptance

- order-arrival-permutation invariance: any permutation of the same intent
  set clears identically (the anti-MEV property, tested adversarially);
- a retried order never fills worse than its limit; cancel/expiry return
  escrow atomically;
- multi-hop orders never strand partial legs;
- unrelated pairs' congestion prices stay independent;
- fee disclosure is complete on-chain for every settlement;
- no code path allows settlement outside the batch.

## Phase 9: agent commerce

Goal: the decided AI-agent primitives (§15.5/15.32). Execute
`agent-commerce.md`.

### Tasks

- mandate objects with runtime-enforced budget/expiry/allowlist/per-tx/rate
  limits, instant revocation, no re-delegation, audit indexing;
- service registry objects (v1 schema), fee-priced registration, revisions,
  track-record fields;
- HTTP-402 flow: challenge validation against the registry, mandate payment,
  receipt handling; subscription objects;
- SDK: principal mandate management, agent client, service middleware;
- docs-as-data registry snapshot pipeline.

### Acceptance

- adversarial suite: over-budget, expired, rate-limited, revoked-mid-flight,
  re-delegation, allowlist bypass, replayed invoices — all fail closed;
- an end-to-end testnet demo: an autonomous agent discovers a service in the
  registry, pays under a mandate, and receives the resource, with the
  principal's audit trail and instant revocation demonstrated.

## Phase 10: succinct proofs and post-quantum experiments

Goal: browsers verify compact finalized state; WEBC determines a defensible
quantum posture. (zk policy: light verification yes; never on the consensus
path; state compression is Phase 19 — §15.25.)

### Tasks

- versioned `StateProof` and finalized-checkpoint proof interfaces; Merkle
  fallback retained;
- the historical-state/archival ADR implemented (prereq from `architecture.md`);
- compare proof backends; prefer post-quantum-friendly hash/STARK assumptions;
- benchmark proof generation and browser verification;
- benchmark ML-DSA transactions and post-quantum validator attestations;
- prototype proof aggregation of post-quantum signatures;
- define proof-lag rules and failure fallback;
- publish a cryptographic threat model and migration plan.

### Acceptance

- browser verifies checkpoint and account/object inclusion without trusting
  one RPC; verification stays small and fast on target browsers;
- invalid transitions/signatures cannot produce accepted proofs;
- mainnet security wording exactly matches what is implemented;
- free display-only reads (§15.21) work against light-client proofs.

## Phase 11: fast path and speed-roadmap benchmarks

Goal: the launch-scope fast path (§15.40/15.42) and the public benchmark
program. Execute `speed-roadmap.md`.

### Tasks

- static fast-path eligibility from declared access sets (single-owner
  writes + commutative credits);
- validator countersigning + stake-weighted quorum certificates; certified
  credits spendable immediately; checkpointing into consensus blocks within
  a bounded block count;
- owner self-equivocation handling (own-account lock, consensus resolution),
  validator-set rotation mid-certificate, cross-path replay protection,
  degraded fallback to the consensus path;
- frugality set completion: aggregated committee votes, compact-block relay,
  zstd wire compression (§15.19) — prerequisites for honest speed numbers;
- committee sampling ADR + implementation (rotating stake-weighted
  sub-committee with the honest-super-majority argument);
- DAG-BFT (Mysticeti-class) prototype and like-for-like benchmark vs the
  Tendermint baseline; adopt by ADR only if it wins on reference hardware;
- run the full `speed-roadmap.md` benchmark gates on the published reference
  machines.

### Acceptance

- fast-path p95 latency lands in ~0.4–0.8s on reference topology before that
  number is claimed anywhere;
- consensus-path stretch numbers (~1s / 1–2s) claimed only after their gates;
- a fast-path-ineligible operation can never obtain a fast-path certificate
  (adversarial tests);
- the hardware floor is unchanged, or the trade-off was explicitly returned
  to the owner (§15.42 guardrail);
- until gates pass, all public materials keep ~2s / 6–8s.

## Phase 12: web and internet platform and flagship applications

Goal: safe embedded website use plus the §15.36 flagship candidates.

### Tasks

- publish TypeScript SDK, isolated wallet surface, framework-free widget;
  framework adapters after the core API stabilizes;
- payment requests, subscriptions, sponsored transactions, token/NFT
  operations, staking, governance clients;
- namespace registration and permission inspection; event subscriptions and
  headless-agent toolkit;
- **flagship 1:** in-page payment/tipping widget embeddable in minutes;
- **flagship 2:** HTML-game starter kit — real-time wallet creation,
  server-managed item economy, player-to-player transfers;
- **flagship 3:** DEX storefront widget over the canonical pools (Phase 8);
- **flagship 4:** AI-agent API marketplace demo (Phase 9 showcase);
- non-web integration module; file/content hash helpers; donation/payment
  links; origin/security indicators and a transaction simulator.

### Acceptance

- malicious host-site suite cannot read keys through supported APIs;
- unrelated sites share a wallet without sharing permissions;
- each flagship runs as a public testnet demo with honest labels;
- file purchase/download demo verifies payment and content hash without
  storing file bytes on-chain.

## Phase 13: tokens, NFTs, and application governance

Goal: native low-cost asset creation and configurable application rules.

### Tasks

- native token/NFT registries and metadata commitments;
- mint/burn/freeze/pause/authority transfer/revocation; transfer-policy hooks
  without global bottlenecks;
- governance instances (snapshots, quorum, timelocks, delegation, execution
  policy);
- wallet warnings for centralized/restrictive assets;
- spam-resistant creation/deployment/storage fees (deposit-based, §15.22).

### Acceptance

- ordinary transfers never write one global mint object;
- freeze/pause powers visible before signing; revoked authority cannot
  return;
- governance snapshots prevent double voting and after-snapshot manipulation.

## Phase 14: bridge prototypes and cross-chain UX

Goal: prove bidirectional accounting with no real value, delivering the
§15.36 UX direction.

### Tasks

- delivery priority per §10: native ETH and SOL first, then sub-tokens
  (ERC-20, Token/Token-2022) and cross-chain messaging, other chains later;
- versioned cross-chain message format and asset identifiers;
- Solidity Ethereum mock bridge + wrapped WEBC; Rust Solana mock bridge;
- WEBC lock/mint/burn/release state machines; metadata/decimal normalization;
- relayer/guardian test service, replay database, reorg handling,
  confirmation rules;
- **one-action UX:** upfront total-cost-and-time quote, single status view
  across both chains, guaranteed refund path on failure (§15.36);
- per-asset limits, pause, delayed large exits, monitoring, incident drills.

### Acceptance

- WEBC round-trips to Ethereum/Solana and back; external test tokens
  round-trip; double mint/release and replay fail; decimal conversion exact
  or rejected; reorg tests create no unbacked assets;
- the quote/status/refund UX works through induced failures;
- all UIs state assets are valueless test assets.

## Phase 15: validator operations stack

Goal: the §15.26 standard operating environment before public recruitment.
Execute `validator-operations.md`.

### Tasks

- official container image (zram, zstd, kernel/DB tuning on by default),
  reproducible build, signed releases;
- keystore-based key provisioning (no argv/env secrets);
- sizing guides, egress budgeting, flat-bandwidth provider notes;
- min/recommended spec table frozen from Phase 11 benchmark data;
- monitoring endpoints, alert defaults, upgrade/rollback/state-sync drills;
- the published multi-year hardware roadmap page.

### Acceptance

- a new operator goes from zero to a synced, monitored validator on the
  image alone, on minimum-floor hardware, following only the shipped docs;
- client-side bandwidth budgets keep measured egress within the published
  worksheet numbers.

## Phase 16: public incentivized testnet and distribution program

Goal: the only activity period eligible for the **25% contributor pool** and
the **5% validator-bootstrap ceiling** (§15.33/15.38). Execute
`distribution-program.md`.

### Preconditions

- the complete distribution specification (all six channels: mechanics,
  scoring, caps, appeal process, snapshot policy) is frozen and published
  **before start**; no retrospective private-development rewards;
- stake-locked grant + vest-by-operation primitives ready (Phase 5);
- airdrop claim machinery (light-client source-wallet proofs, per-wave
  Merkle snapshots) and fee-credit machinery (non-transferable, expiring)
  implemented and audited;
- security reporting and privacy policy published.

### Tasks

- operate the long-running public testnet on the Phase 15 stack;
- run the contributor tracks with the public ledger and periodic audits;
- run the validator recruitment/evaluation window (diversity quotas);
- rehearse upgrades, outages, attacks, recovery;
- publish per-round award calculations reproducible from public evidence.

### Acceptance

- distribution results are reproducible from public evidence;
- no single contribution class dominates the pool;
- major Sybil/farming scenarios are measured and mitigated (usage-subsidy
  wash-usage nets negative; airdrop caps hold under farmed-wallet
  simulations);
- the network survives extended public adversarial operation.

## Phase 17: mainnet gates

Mainnet does not launch merely because features exist. Required gates:

- protocol, consensus, economics, wallet, runtime, proof, DEX, oracle,
  mandate, and distribution specifications frozen;
- multiple independent security audits (in addition to the Phase 5.5 core
  review);
- bridge remains disabled for real funds unless separately approved/audited;
- genesis file and allocation proofs (contributor awards, bootstrap grants,
  airdrop wave 1) publicly reproducible;
- validator set has sufficient independent stake/operators before genesis;
  founder-run nodes labeled temporary with published retirement criteria;
- monitoring and incident response operational;
- client releases reproducible and signed; no founder master key;
- upgrade/governance process published, including the founder-maintainer
  sunset plan (§15.36);
- public risk disclosure published; public speed claims match measured
  reality (§15.42).

## Phase 18: production bridges

Real-fund bridges are post-mainnet or separately gated.

- Prefer light-client/ZK verification where feasible; if a guardian/quorum
  bridge is temporarily used, publish every trust assumption, key holder,
  threshold, limit, pause path, and exit risk.
- Separate audits for Ethereum contracts, Solana programs, WEBC bridge
  logic, relayers, and operations.
- Begin with low per-asset limits; raise only after measured safe operation.
- Bitcoin/Tron come only after Ethereum/Solana are proven.

## Phase 19: phase-2 additions

Decided as later work, never launch dependencies:

- **Walrus-style erasure-coded blob layer** for bulk content, paid in WEBC
  (§15.27);
- **zk state compression** for mass-tiny-object applications (§15.25,
  §15.29);
- liquidity sharding for extreme pairs if data demands it (§15.13);
- hot/cold tier automation beyond the Phase 6 ADR boundary.

## Immediate next implementation milestone

Phases 0-3 are complete and **Phase 4 (networking and signed BFT consensus) is
active**. A-1, the A-2 consensus core, and the A-3 deterministic core are done
(leader schedule, consensus wire messages, snapshot writer, self-verifying
certificate, `import_block`, multi-round Tendermint `ConsensusMachine` with
locking and safe round changes, equivocation detection, the async
`ConsensusDriver` over TCP with mempool-fed proposals, and
certificate-verified state sync — all proven by deterministic/loopback tests).

The remaining Phase 4 work (P0 items first, from the 2026-07-16 plan review —
`docs/review/findings.md` C1–C8 and `docs/review/2026-07-16-plan-review.md`
§6; reproduce each finding with a failing test before fixing it):

1. **(P0, C1) validate a proposed block before prevoting/locking/finalizing**
   — dry-run `apply_block` against current state (the `valid(v)` predicate)
   so a Byzantine leader cannot obtain a certificate for an unimportable
   block;
2. **(P0, C2) never halt silently on a failed finalized-block import** —
   distinguish an invalid block (post-finality emergency) from a transient
   storage error (retry/surface);
3. **(P0, C3) bound per-height consensus memory** — reject/park messages
   beyond `current_round + K`, cap stored future rounds, evict decided
   rounds;
4. **(P0, C4) persist a durable WAL of own votes/locks before broadcasting**
   — a crash-restart must not self-equivocate. **Urgent: the
   equivocation→slash loop is already live (commit `0e4b4c5`), so an honest
   restart today can actually be slashed. This must land before any network
   run with honest restarts;**
5. publish a reference-machine finality-timing number (cannot be produced in
   a cloud container);
6. **DONE (commit `0e4b4c5`)** — equivocation-to-slash wired end to end;
7. **Largely DONE (commit `a2e774e`)** — machine-level Byzantine safety test;
   a multi-node-over-TCP version is optional follow-up;
8. carry a proof-of-lock certificate with re-proposals and scale timeouts by
   round (C5/C6), gate state-sync replies on a verified higher-height
   certificate (C7);
9. add supply-chain (`cargo-deny`) and fuzz-target CI gates (plan review
   §3.5–3.6);
10. update `docs/implementation-status.md` and `docs/continuation-guide.md`
    after every completed item and mark resolved findings with commit hashes.

Only after consensus is stable (through the Phase 5.5 gate) should the
contract runtime, Weft, the oracle, the DEX, agent commerce, the fast path,
the platform, and the bridges be expanded.
