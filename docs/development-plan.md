# WEBC development plan

Status: authoritative implementation plan  
Date: 2026-07-15

Implementation checkpoint: Phases 0-3 passed their repository gates; Phase 4
(networking and signed BFT consensus) is active. Phase 4 A-1 (authenticated P2P
networking and transaction gossip), the A-2 consensus core, and the A-3
deterministic core are done: the stake-weighted leader schedule, the
Proposal/Vote/Certificate wire messages, the per-epoch validator-set snapshot
writer, a self-verifying finality certificate, received-block validation
(`Node::import_block`), a full multi-round Tendermint machine with locking and
safe round changes (`webc-chain::ConsensusMachine`), and objective equivocation
detection — proven by deterministic tests (multi-validator convergence, a round
change under a silent proposer, and the lock-safety property). The async
`ConsensusDriver` that runs the machine over real `webc-net` TCP is done too,
the driver feeds its mempool into proposals, and certificate-verified state sync
lets a late-joining node catch up — proven by loopback tests (three validators
finalize one chain, a gossiped transfer is finalized by all, a late node catches
up via sync). **Phase 4's consensus mechanism is NOT complete or safe:** beyond the
already-known equivocation-to-slash wiring, a 2026-07-16 read-only review reported
HIGH-severity consensus safety/liveness/DoS gaps (no `valid(v)` re-execution before
prevote/lock/finalize, a silent halt on failed import, unbounded attacker-round
memory, and no vote/lock WAL → crash-restart self-equivocation — see
`docs/review/findings.md` C1–C4 and the P0 list in the remaining-work section
below). This marker records progress and does not weaken any acceptance criterion
below.

This plan is written so a new development session can continue without inventing product decisions. Read `AGENTS.md`, `docs/decision-record.md`, this file, `docs/whitepaper.md`, and `docs/implementation-status.md` before changing protocol code.

## Working rule

The current repository is a prototype, not the new protocol baseline. Preserve useful code, but do not extend known-invalid assumptions merely because tests currently pass.

Every phase must:

- keep deterministic state transitions;
- use typed errors;
- add invariant and adversarial tests;
- update implementation status and decision records;
- avoid claims not demonstrated by repeatable tests;
- keep real bridge funds disabled;
- keep economics configurable until the relevant phase freezes them.

## Phase 0: repository and specification baseline

Goal: make the repository safe to continue.

### Tasks

- initialize/verify Git history and add a suitable `.gitignore`;
- install/pin the Rust toolchain and formatting/lint configuration;
- configure workspace lints to forbid `unsafe` in protocol crates by default and fail CI on unexplained warnings;
- define the module/public-interface documentation template and apply it to every module changed in this phase;
- introduce distinct Rust types for consensus values that must not be mixed, beginning with amounts/base units, heights, epochs, nonces, chain IDs, assets, and validator IDs;
- replace panic-based handling of external and consensus input with typed errors as affected modules are repaired;
- add CI for format, lint, Rust tests, TypeScript build/tests, and documentation-link checks;
- fix broken text encoding in legacy documentation/comments;
- mark legacy prototype defaults as non-authoritative;
- add architecture decision records for state, consensus, fees, wallet authorization, proofs, contracts, and bridges;
- add a protocol configuration version and chain ID policy.

### Acceptance

- clean reproducible build from a fresh checkout;
- Rust documentation generation succeeds, changed public interfaces are documented, and protocol crates contain no unexplained `unsafe`, panic-on-input, or unchecked consensus-number conversion;
- `cargo fmt --check`, `cargo clippy`, and `cargo test --workspace` pass;
- TypeScript SDK/widget build and tests pass;
- no document claims the prototype is mainnet-ready;
- all confirmed decisions link to `docs/decision-record.md`.

## Phase 1: repair the reusable protocol core

Goal: create a correct deterministic single-node state machine before networking.

### Mandatory replacements/fixes

- change native precision from 9 to 12 decimals;
- replace six-month halving code with the confirmed annual-rate decay and 1% floor;
- remove zero-collateral/bootstrap validator behavior from the new protocol path;
- enforce operator self-stake >=20% of pool stake;
- implement 7-minute devnet and configurable 7-day mainnet unstaking queues;
- make stake changes epoch-snapshotted so an intra-epoch exit cannot change the
  current validator set;
- implement the lifecycle and global FIFO churn queue from ADR-0008, including
  `PendingActivation`, `Active`, `ExitQueued`, `CoolingDown`, `Withdrawable`, and
  one-time `Withdrawn` accounting;
- treat 7-minute devnet and 7-day mainnet delays as normal minimum targets while
  allowing bounded queue congestion to extend mass exits;
- move pools that fail projected 100/20/80 rules into a deterministic draining
  state for the next snapshot rather than removing voting power mid-epoch;
- repair genesis accounting so balances, stake, supply, burns, bridge escrow, and rewards reconcile;
- make block execution atomic, not merely individual transactions;
- enforce block byte/unit limits before commit;
- validate declared access lists against actual native-operation access;
- make slashing evidence contain and verify real signed artifacts;
- update delegated balances when delegated stake is slashed;
- preserve pending rewards across partial/full undelegation according to an explicit rule;
- checkpoint earned rewards when an exit is admitted, stop new rewards during
  cooldown, and keep the position slashable through its evidence window;
- remove/deprecate PoH from the authoritative block protocol;
- delete stale Rust/TypeScript signing-mismatch documentation only after executable cross-language tests prove compatibility.

### New state primitives

- versioned `StateKey` covering accounts, token balances, objects, modules, application namespaces, and protocol state;
- account authorization lanes for parallel multi-site activity;
- versioned object ID/owner/version model;
- atomic transaction journal/overlay;
- supply invariant report.

### Tests

- conservation: genesis + issuance = liquid + staked + delegated + escrowed + rewards + burned adjustments;
- block rollback after a late failing transaction;
- undeclared access rejection;
- cross-application non-conflict scheduling;
- same-wallet independent lane concurrency;
- slashing updates operator, validator aggregate, delegators, and accounts consistently;
- FIFO/churn processing survives serialization/restart and mass-exit tests;
- current-epoch validator power is unchanged by exit requests;
- inflation reference vectors across floor transition;
- 12-decimal amount serialization across Rust/TypeScript.

## Phase 2: wallet wire format and security foundation

Goal: browser-created transactions are exactly understood by Rust nodes without exposing keys to host sites.

### Tasks

- freeze canonical transaction and signing schemas with explicit version/domain/chain ID;
- generate shared Rust/TypeScript test vectors;
- replace camelCase/snake_case ambiguity with one documented wire schema;
- restore/create the missing SDK public entry point and package exports;
- use standard mnemonic and Ed25519 derivation libraries rather than custom derivation;
- define encrypted keystore v1 with authenticated encryption and password-hardening parameters;
- implement isolated trusted-origin wallet UI and postMessage request protocol;
- add permission scopes, spend limits, origin display, and human-readable signing confirmation;
- add versioned account authorization policies and post-quantum root-key fields;
- prototype ML-DSA signing in browser/WASM and Rust;
- add recovery, rotation, revocation, and limited session-key tests.

### Acceptance

- Rust verifies transactions signed by every supported browser;
- TypeScript verifies Rust vectors;
- host page cannot read wallet secrets through the supported integration API;
- malformed origins/messages and blind-sign requests are rejected;
- keystore corruption/wrong-password tests fail safely;
- no private key is logged, serialized accidentally, or sent to the node.

## Phase 3: local node, storage, and developer APIs

Goal: a restartable node usable by browsers and local applications.

### Tasks

- define storage traits before choosing a database backend;
- store finalized blocks, headers, receipts, state snapshots/deltas, validator sets, and proof metadata;
- implement crash-safe transactional commits and startup recovery;
- add HTTP/WebSocket APIs for health, account/object queries, proofs, blocks, transaction submission, subscriptions, fees, and faucet;
- add mempool validation, per-lane nonce ordering, expiration, replacement, and fee prioritization;
- create devnet-only faucet with rate limits and clear no-value labeling;
- add browser SDK clients and a reference demo site.

### Acceptance

- restart without losing or duplicating committed state;
- corruption is detected and reported;
- invalid transactions do not mutate state;
- browser creates wallet, receives faucet funds, verifies proof, submits transfer, and sees finality;
- APIs publish explicit versioning and resource limits.

## Phase 4: networking and signed consensus

Goal: a real multi-machine devnet with staked permissionless validators.

### Tasks

- implement authenticated peer identities and peer discovery;
- gossip transactions, proposals, votes, and finality certificates;
- rate-limit and score peers without making stake mandatory for ordinary verification nodes;
- implement deterministic leader schedule and stake snapshots;
- implement signed prevote/precommit (or selected BFT equivalent);
- select rotating stake-weighted voting committees without a global validator-count cap;
- verify chain ID, height, round, proposal hash, validator membership, and voting power;
- implement fork choice, lock rules, timeout/round changes, and state sync;
- implement objective double-vote/invalid-proposal evidence;
- keep PoH absent from consensus.

### Acceptance

- geographically separated nodes converge on one finalized chain;
- normal blocks finalize in 6-8 seconds under the target test topology;
- delayed/lost messages trigger safe round changes, not conflicting finality;
- <1/3 malicious voting power cannot finalize invalid/conflicting blocks;
- evidence from signed conflicting votes triggers the correct slash exactly once;
- a joining node syncs from a checkpoint without replaying all history.

## Phase 5: staking pools and economics

Goal: complete the economic-security rules before public incentivization.

### Tasks

- enforce 20/80 operator/delegator pool ratio continuously;
- enforce the confirmed 100 WEBC activation minimum and 20 WEBC operator minimum at activation;
- enforce the confirmed 1 WEBC minimum for each active delegation position;
- implement activation/deactivation queues and epoch snapshots;
- make stake splitting unable to increase voting power or bypass activation/rate limits;
- implement commission, reward accounting, claims, compounding options, and dust rules;
- implement inflation curve and fee distribution against supply invariants;
- define severe malicious slashes and softer operational penalties;
- define correlated slashing for coordinated provable attacks;
- add public validator performance/reward/slash data;
- add faucet-funded devnet staking UX.

### Acceptance

- property tests cover arbitrary delegation/reward/slash/withdraw sequences;
- no operator can use delegation above the allowed leverage;
- pools below 100 WEBC cannot produce or vote, and falling below the threshold follows an explicit safe deactivation rule;
- delegations below 1 WEBC cannot become active or create reward-accounting dust;
- withdrawal cannot evade evidence from the slashable period;
- reward totals reconcile exactly;
- economic simulations document centralization and attack-cost scenarios.

## Phase 5.5: core freeze and independent security review (owner-confirmed gate)

Goal: an earlier independent security-review gate for the security-critical core,
recorded in `docs/decision-record.md` (owner-confirmed 2026-07-16), before the
contract/ZK/bridge/platform layers stack on top of it. This is additional to the
Phase-13 pre-mainnet audits, not a replacement.

### Tasks

- freeze the consensus + cryptography + economics core (versioned interfaces, no
  behavior changes in flight);
- resolve every open blocking finding from `docs/review/findings.md` first — at
  minimum the CONFIRMED HIGH/critical items (C1–C4 consensus, the C4 vote/lock WAL
  that the now-live slash loop makes urgent, F1 reward-dust supply leak, E1 epoch
  wiring), each with a reproduction test then a fix;
- add the supply-chain CI gate (`cargo-deny` advisories/licenses/bans + a JS
  advisory scan) and stand up fuzz targets (wire decode, canonical encoding,
  mempool admission, tx execution) as part of the freeze evidence;
- prepare an audit package: threat model, invariants, the consensus safety
  argument (including committee sampling if adopted), and the economic model;
- obtain an independent/external review of the frozen core.

### Acceptance

- no open HIGH/critical finding remains in `docs/review/findings.md` for the core;
- the supply-chain and fuzz gates run in CI and are green;
- the external review's blocking findings are resolved before Phase 6+ builds on the
  core.

## Phase 6: parallel execution and localized fees

Goal: unrelated sites and applications do not block each other at the state scheduler or localized fee layer.

### Tasks

- implement application namespace registry;
- implement enforced account/object read/write declarations;
- build deterministic parallel batches and transactional overlays;
- resolve deterministic commit order and retry behavior;
- implement per-resource/application congestion measurement;
- implement localized base/priority pricing plus a network-wide minimum;
- implement fair block packing so one hot application cannot monopolize all capacity;
- implement sponsor/paymaster accounts with budgets and abuse protection;
- build sharded examples for tokens, games, swaps, and site sessions.

### Benchmarks

Run on at least:

- minimum reference machine: 4 CPU cores, 8 GB RAM, SSD;
- recommended reference machine: 8 CPU cores, 16 GB RAM, NVMe;
- performance machine with published full specifications.

Measure simple transfers, conflicting transfers, independent applications, token transfers, swaps, games, storage-heavy contracts, and adversarial access lists.

### Acceptance

- unrelated application traffic executes concurrently;
- congestion price for one isolated application does not raise another's localized price;
- global saturation remains bounded by fair capacity rules;
- sustained simple-transfer benchmark reaches staged 100/500/1,000/2,000+ TPS gates before any claim is published;
- deterministic roots match across thread counts and machines.

## Phase 7: contract runtime, native oracle (interim authoring), then the WEBC language

Goal: ship the parallel contract runtime on the chosen Rust->WASM foundation and
the native staked oracle. **Sequencing (owner-confirmed 2026-07-16): the bespoke
WEBC high-level language is a LATER, separately-resourced project (Phase 7b); an
interim Rust-eDSL/SDK authoring path ships first (Phase 7a) so contracts become
possible before the language exists.**

### Phase 7a — runtime + interim Rust authoring (ships first)

- restricted deterministic WebAssembly, Rust-first, is the execution engine;
- Move VM and EVM are not the native runtime; Ethereum/Solana compatibility is delivered by the bridges in Phase 11/14, not by running their bytecode here;
- benchmark the WASM runtime against the reference applications below to validate throughput, determinism, and parallel access enforcement before freezing the ABI;
- contracts are authored in Rust (an embedded-DSL / SDK over the audited framework) and compiled **off-chain** to deterministic WASM;
- **design for the language to plug in later (owner requirement):** freeze a stable
  contract **ABI** and a stable **"authoring front-end → lowering → audited Rust
  framework → WASM" seam**, and treat the authoring front-end as a *versioned,
  swappable boundary* (like the crypto/storage/proof seams). The Rust-eDSL is the
  first front-end over this seam; the WEBC language is a later front-end over the
  **same** lowering/ABI target — adding it must never require rewriting the runtime
  or the framework. Keep the off-chain-compilation invariant: the chain only ever
  accepts deterministic WASM + metadata (see `architecture.md`).

### Phase 7b — WEBC high-level authoring language and tooling (later, separate project)

- build the WEBC high-level contract language as a front end (parser + lowering) that transpiles to the audited Rust framework and its components, inheriting Rust/WASM safety and determinism; do not build a second VM or an independent compiler backend; it plugs into the Phase-7a authoring seam rather than replacing the runtime;
- ship a component catalog and machine-readable documentation so AI agents, AI-assisted developers, and human-only developers can all assemble contracts from documented, audited building blocks;
- enforce an opinionated, uniform contract structure and small composable components instead of monoliths;
- ship a contract linter/analyzer (a WEBC clippy) plus a pre-deploy review step (including automated/AI review) that block long functions, missing access declarations, and unsafe patterns before deployment;
- auto-derive each contract's read/write access declarations from the language where possible so developers do not hand-maintain them.

### Native oracle

- implement a native staked oracle: reporters stake WEBC, submit values as ordinary signed transactions, and reported values are aggregated (for example by median) so one reporter cannot forge the answer;
- slash provably wrong or conflicting reports through the existing staking/slashing path;
- keep contracts unable to touch the network directly: oracle data enters as transactions so every node computes the same result;
- expose external oracle integration as an option, not a requirement.

### Common reference applications

- fungible token with mint/freeze/revoke policy;
- NFT collection;
- constant-product token swap;
- commit/reveal rock-paper-scissors;
- conditional payment/refund;
- sponsored website membership/payment;
- object/account contention stress test.

### Evaluation

- execution throughput and latency;
- memory and binary size;
- deterministic sandbox complexity;
- parallel access enforcement;
- developer code volume and tooling;
- TypeScript client generation;
- auditability and known security history;
- ZK proof cost;
- Solidity ecosystem compatibility;
- upgrade and maintenance burden.

### Acceptance

- publish benchmark code/results;
- freeze a versioned contract ABI on the WASM runtime;
- WEBC high-level language contracts lower to the Rust framework and pass the reference-application suite;
- the linter/pre-deploy review rejects the anti-pattern fixtures (oversized functions, undeclared access, unsafe patterns);
- the native oracle resists a single lying reporter in tests and slashes provably wrong reports exactly once;
- never claim source-level Solidity compatibility without EVM-semantic conformance tests.

## Phase 8: succinct proofs and post-quantum experiments

Goal: browsers verify compact finalized state and WEBC determines a defensible mainnet quantum posture.

### Tasks

- define versioned `StateProof` and finalized-checkpoint proof interfaces;
- retain Merkle proof implementation as fallback;
- compare at least two proof backends where practical;
- prefer post-quantum-friendly hash/STARK assumptions for long-term design;
- benchmark block/state-transition proof generation and browser verification;
- benchmark ML-DSA transactions and post-quantum validator attestations;
- prototype proof aggregation of post-quantum signatures;
- define proof-lag rules and failure fallback;
- publish a cryptographic threat model and migration plan.

### Acceptance

- browser verifies checkpoint and account/object inclusion without trusting one RPC;
- proof verification stays small and fast on target browsers;
- invalid state transition and invalid signature batches cannot produce accepted proofs;
- mainnet security wording exactly matches what is implemented;
- no dependency on one proof vendor is embedded without a replacement/version path.

## Phase 9: web and internet platform

Goal: safe embedded website use plus broader web/internet-native integration
(sites, web apps, web games, and AI agents), easier to adopt than Ethereum or
Solana.

### Tasks

- publish TypeScript SDK, isolated wallet surface, and framework-free widget;
- add React/Vue/Svelte adapters only after the core API stabilizes;
- add payment requests, subscriptions, sponsored transactions, token/NFT operations, staking, and governance clients;
- add application namespace registration and permission inspection;
- add event subscriptions and headless-agent toolkit;
- add a web-game integration module: real-time in-page wallet creation, server-managed tokens, and low-friction player-to-player transfers, embeddable in plain HTML games;
- add an AI web-agent payment toolkit so agents can pay and receive WEBC while browsing, within sponsor caps;
- add in-page payment and easy peer-to-peer exchange flows, plus optional reward-for-attention (ad) and application-layer site fee surcharge/revenue-share examples;
- add a non-web integration module so native applications embed WEBC the same way a website does;
- add file/content hash helpers and encrypted-access examples;
- add one-click voluntary donation/payment links;
- add origin/security indicators and a user-readable transaction simulator.

### Acceptance

- malicious host-site test suite cannot read keys through supported APIs;
- unrelated sites use the same wallet without sharing site permissions;
- demo sites run concurrently without scheduler contention when state is independent;
- file purchase/download demo verifies payment and content hash without storing file bytes on-chain.

## Phase 10: tokens, NFTs, and application governance

Goal: native low-cost asset creation and configurable application rules.

### Tasks

- implement native token/NFT registries and metadata commitments;
- implement mint/burn/freeze/pause/authority transfer/revocation;
- implement transfer-policy hooks without a global token bottleneck;
- implement governance instances with snapshots, quorum, timelocks, delegation, and execution policy;
- implement wallet warnings for centralized/restrictive assets;
- add spam-resistant creation/deployment/storage fees.

### Acceptance

- ordinary transfers do not write one global mint object;
- freeze/pause powers are visible before acceptance/signing;
- revoked authority cannot be restored;
- governance snapshots prevent double voting and balance-after-snapshot manipulation.

## Phase 11: bridge prototypes

Goal: prove bidirectional accounting with no real value.

### Tasks

- follow the confirmed delivery priority: native ETH and SOL first (ideally in parallel, otherwise Ethereum then Solana), then their sub-tokens (ERC-20, Solana Token/Token-2022) and cross-chain messaging so contracts on different chains can communicate, then other chains later;
- freeze versioned cross-chain message format and asset identifiers;
- build Solidity Ethereum mock bridge and wrapped WEBC token;
- build Rust Solana mock bridge program and wrapped WEBC mint;
- implement WEBC lock/mint/burn/release state machines;
- support standard Ethereum tokens and Solana Token/Token-2022 metadata;
- add relayer/guardian test service, replay database, reorg handling, and confirmation rules;
- add browser bridge UI for test assets;
- add per-asset limits, pause, delayed large exits, monitoring, and incident drills.

### Acceptance

- native WEBC round-trips WEBC -> Ethereum/Solana -> WEBC in test environments;
- external test tokens round-trip origin -> WEBC -> origin;
- double mint/release and cross-domain replay fail;
- decimal conversion is exact or rejects unsupported amounts;
- origin-chain reorg tests do not create unbacked assets;
- all UIs state that assets are valueless test assets.

## Phase 12: public incentivized testnet and distribution measurement

Goal: begin the only activity period eligible for the 30% contributor distribution.

### Preconditions

- public contribution/distribution specification published before start;
- metrics, caps/diminishing returns, anti-duplicate strategy, audit method, and appeal process frozen;
- no retrospective private-development rewards;
- security reporting and privacy policy published.

### Tasks

- operate long-running public testnet;
- reward useful verified validation, proof work, bugs, code, documentation, tooling, and adversarial tests;
- publish contribution ledger and periodic audits;
- test validator geographic/network diversity;
- rehearse upgrades, outages, attacks, and recovery.

### Acceptance

- distribution results are reproducible from public evidence;
- no single contribution class can dominate the pool;
- major Sybil/farming scenarios are measured and mitigated;
- network survives extended public adversarial operation.

## Phase 13: mainnet gates

Mainnet does not launch merely because features exist.

Required gates:

- protocol, consensus, economics, wallet, runtime, proof, and distribution specifications frozen;
- multiple independent security audits;
- bridge remains disabled for real funds unless separately approved/audited;
- genesis file and allocation proofs publicly reproducible;
- validator set has sufficient independent stake/operators before genesis;
- monitoring and incident response operational;
- client release reproducible and signed;
- no founder master key;
- upgrade/governance process published;
- public risk disclosure published.

## Phase 14: production bridges

Real-fund bridges are a post-mainnet or separately gated launch.

- Prefer light-client/ZK verification where feasible.
- If a guardian/quorum bridge is temporarily used, publish every trust assumption, key holder, threshold, limit, pause path, and exit risk.
- Require separate audits for Ethereum contracts, Solana programs, WEBC bridge logic, relayers, and operations.
- Begin with low per-asset limits and increase only after measured safe operation.
- Bitcoin and Tron are later targets than Ethereum/Solana and carry higher trust complexity (Bitcoin has no native contracts, forcing federation/multisig assumptions); do not begin them before the Ethereum/Solana bridges are proven.

## Immediate next implementation milestone

Phases 0-3 are complete and **Phase 4 (networking and signed BFT consensus) is
active**. A-1, the A-2 consensus core, and the A-3 deterministic core are done:

1. the network message set carries Proposal, Vote, and Certificate — done;
2. the per-epoch validator-set stake snapshot writer is populated — done;
3. the finality certificate (aggregate precommits, snapshot membership, strictly
   >2/3 power) is self-verifying — done;
4. `Node::import_block` validates a received block by re-execution and commits it
   through the store — done;
5. the consensus state machine is a full multi-round Tendermint `ConsensusMachine`
   with locking, proof-of-lock re-proposal, three timeouts, and `f+1` catch-up —
   done; proven by deterministic tests for convergence, round change under a
   silent proposer, and lock safety;
6. objective equivocation detection surfaces double-vote evidence for the existing
   slashing path — done.

7. the async network driver (`webc-node::ConsensusDriver`) runs a
   `ConsensusMachine` per height over real TCP — candidate build on
   `NeedProposalBlock`, real timers on `ScheduleTimeout`, gossiped consensus
   messages into the machine, commit on `Commit` via `import_block`, gossiped
   evidence into the next block — proven by a loopback test where three validator
   nodes converge on one finalized chain — done.

8. the driver feeds its mempool into proposed blocks (admits gossiped
   transactions, selects fee-priority nonce-ordered transactions, prunes after
   commit) — proven by a test where a gossiped transfer is finalized by all
   nodes — done.

9. certificate-verified state sync (per-height certificate persistence,
   BlockRequest/BlockResponse wire messages, and a unified live-or-sync per-height
   loop) lets a late-joining node catch up — proven by a loopback test — done.

The remaining Phase 4 work (P0 items first, from the 2026-07-16 plan review —
`docs/review/findings.md` C1–C8 and `docs/review/2026-07-16-plan-review.md` §6;
reproduce each finding with a failing test before fixing it):

10. **(P0, C1) validate a proposed block before prevoting/locking/finalizing it** —
    the driver must dry-run `apply_block` against current state (the `valid(v)`
    predicate) so a Byzantine leader cannot obtain a finality certificate for an
    unimportable block;
11. **(P0, C2) never halt silently on a failed finalized-block import** —
    distinguish an invalid block (a post-finality emergency) from a transient
    storage error (retry/surface); do not treat it as a clean exit;
12. **(P0, C3) bound per-height consensus memory** — reject/park messages beyond
    `current_round + K`, cap stored future rounds, evict decided rounds, so an
    attacker-chosen `u32` round cannot OOM the node;
13. **(P0, C4) persist a durable WAL of own votes/locks before broadcasting** — so
    a crash-restart cannot make an honest validator self-equivocate. **Now urgent:
    the equivocation→slash loop is already live (item 15 is DONE), so an honest
    restart today can actually be slashed. This must land before this runs on any
    network with honest restarts;**
14. publish a reference-machine finality-timing number (cannot be produced in this
    cloud container);
15. **DONE (commit `a6197ac`)** — consensus-detected equivocation is wired to an
    applied slash: header `evidence_root` + block `evidence` executed atomically in
    `build_block`/`apply_block`, the driver auto-includes machine-detected
    equivocation, and a determinism test exists. (Independently verified this
    session; the `SubmitSlashingEvidence` transaction path also remains.) Ordering
    note preserved: item 13 (C4 WAL) should have preceded this and is now urgent;
16. **Largely DONE (commit `75d054b`)** — the machine-level
    `less_than_one_third_byzantine_power_cannot_finalize_conflicting_blocks` test
    exists; a multi-node-over-TCP integration version is optional follow-up;
17. carry a proof-of-lock certificate with re-proposals and scale timeouts by round
    (C5/C6 liveness), and make state-sync a directed reply gated on a verified
    higher-height certificate (C7);
18. add supply-chain (`cargo-deny`) and fuzz-target CI gates (plan review §3.5–3.6);
19. update `docs/implementation-status.md` and `docs/continuation-guide.md` after
    every completed item, and mark the resolved `docs/review/findings.md` entry
    with its commit hash.

Only after consensus is stable should the contract runtime, the WEBC high-level
language and tooling, the native oracle, the web platform, and the bridges be
expanded.
