# WEBC plan review — 2026-07-16

Author: plan-review session (read-only; no source code changed).
Audience: the project owner (관리자) and the future implementer models
(Claude Opus 4.8 / GPT-5.6 Sol).

This document critically re-examines the existing WEBC plan and design decisions.
Its job is not to rewrite decisions for their own sake, but to (1) separate what
is sound from what is risky, (2) name the decisions that are genuinely the
owner's to make, and (3) hand the next sessions a concrete, prioritized worklist.

Method and limits: every document under `docs/` and `AGENTS.md` was read in full.
Source was **sampled**, not fully audited — the crypto boundary
(`webc-crypto`), the consensus snapshot/certificate (`consensus.rs`), the
state-root construction (`state.rs`), canonical encoding, and the wire types were
read directly; most of `state.rs` (6.9k LoC), `round.rs`, the driver, and the SDK
were reviewed by focused sub-agents (see `docs/review/findings.md`). Treat any
claim here about unread code as provisional.

---

## 1. What is sound — keep it, do not re-litigate

Reflexively "burning down" a plan is as harmful as blindly keeping it. These
choices are well-reasoned and should stay:

- **Determinism discipline is real, not just aspirational.** Every consensus
  state map is a `BTreeMap`/`BTreeSet`; the state root hashes domain-separated,
  canonically-JSON-encoded leaves (`state.rs:952`, `leaf_hash`), not
  iteration-order-dependent bincode. Floating point is rejected in the canonical
  encoder (`canonical.rs`). This is the single most important correctness
  property of a chain and it is being respected.
- **Replaceable seams are in place where they matter:** `webc-crypto::mldsa`
  (single ML-DSA seam), `KvStore` (storage), `NetworkHandle` (transport). This is
  the right way to keep a security-critical dependency swappable.
- **Honesty about status.** The docs consistently label what is mock, unaudited,
  unsafe-for-real-funds, and benchmark-pending, and refuse to claim TPS/finality/
  PQ-safety without evidence. This is exactly right for a crypto project and must
  be preserved.
- **Fund-movement conservatism:** checked integer arithmetic, an explicit
  `SupplyInvariantReport`, per-domain bridge escrow buckets, atomic block overlay
  with whole-block rollback. (Correctness of the details is being verified — see
  findings — but the discipline is correct.)
- **The phase ordering** (repair core -> wallet -> node/storage -> consensus ->
  economics -> parallelism -> contracts -> proofs -> platform -> assets ->
  bridges -> testnet -> mainnet) is a defensible dependency order. Do not reorder
  it casually.

The conclusion of this review is **not** "start over." It is "the foundation is
disciplined; the risks are in scope realism, a few specific security gaps, and
under-specified areas that will be expensive to retrofit if left implicit."

---

## 2. Decision provenance (who owns each choice)

Per `AGENTS.md`: user-made decisions must not be overturned without the owner's
approval; AI/unknown-origin decisions can be adjusted autonomously if small, or
reported if large.

**Owner-confirmed (do NOT change without approval)** — from
`docs/decision-record.md`: 10M genesis / 12 decimals / 10% inflation × 0.8 →
1% floor; 30/70 distribution; delegated-PoS BFT, no PoH, 2s blocks, 6–8s
finality; 100 WEBC pool activation / 20 WEBC operator min / 20% operator self-
stake / 80% delegation cap / 1 WEBC min delegation; 7 min devnet / 7 day mainnet
unbonding; fees 50% burn / 50% reward; parallel execution (Solana access lists +
Sui objects); hybrid account/object state; browser wallet secret isolation;
post-quantum-ready versioned auth (ML-DSA candidate); Mina-inspired ZK direction;
bidirectional ETH/SOL bridges; **Rust→WASM contract foundation + a WEBC high-
level authoring language that lowers to an audited Rust framework**; native
staked oracle; the AI-era product direction.

**AI/implementation-origin (adjustable with recorded rationale)** — Tendermint
(arXiv:1807.04938) as the specific BFT algorithm; redb; axum/tokio; bincode for
storage/framing + canonical-JSON for cross-language signing; `fips204` crate;
Ed25519 for consensus + network-identity keys; SLIP-0010 path `m/44'/1'/…`;
Argon2id parameters. These are reasonable and none needs reversal today; they are
listed so a future session knows they are not owner mandates.

**Still-deferred owner decisions (correctly not asked yet):** final public-
distribution / anti-duplicate mechanism; production bridge trust/proof model;
mainnet governance emergency powers; the contract language's surface syntax and
names. Add to this list (see §4): **slashing severity percentages** — these are
economic policy of the same kind as inflation, and are not yet fixed.

---

## 3. Security review against the crypto-mandated checklist

The goal requires these be examined as separate items.

### 3.1 Keys and secret management
- Ed25519 secret keys are non-`Serialize`; ML-DSA secret is
  non-`Debug`/`Serialize`/`Clone`; browser signing handles are non-extractable in
  a module-private WeakMap. Good.
- **Open concern — validator/consensus key provisioning at the node.** How the
  node receives its consensus-key seed and network-identity key (CLI arg? file?
  env var?) determines whether secrets leak via process listing, shell history,
  or logs. This is being checked in the network/node sub-review; if seeds are
  passed as CLI args, that is a finding (visible in `ps`). Resolution belongs in
  an ADR on node key management (keystore file with 0600 perms, not argv).
- No hardware-security-module / remote-signer story for validators yet — fine for
  devnet, must be named as a mainnet gate.

### 3.2 Fund-movement correctness
- Discipline is right (checked arithmetic, supply report, atomic overlay). Detail
  correctness (overflow on reward/fee splits, remainder rules, double-count in
  reconciliation) is under sub-agent review; see `findings.md`.

### 3.3 Transaction atomicity and reentrancy
- Native execution is an overlay committed only on full success; whole-block is a
  parent overlay. There is no public contract VM yet, so cross-contract
  reentrancy does not exist today — **but** the reentrancy threat model must be
  written before the WASM runtime lands (Phase 7), not after.

### 3.4 External-input validation
- Wire decoding claims size/magic/version/trailing-byte checks; mempool claims
  signature/nonce/fee/affordability admission. Being verified in sub-review
  (bincode decode bounds are the key question — an unbounded length prefix is a
  classic memory-exhaustion vector).

### 3.5 Dependency supply chain
- The reuse + license rule in `AGENTS.md` is good and specific.
- **Gap: no automated supply-chain gate in CI.** There is no `cargo-deny`
  (advisories + licenses + banned crates) and no `pnpm audit` step. For a crypto
  project this should be a CI gate, not a manual habit. Recommendation: add
  `cargo-deny check` and a JS advisory scan to `.github/workflows/ci.yml`, and
  pin `fips204`/`ed25519-dalek`/`redb` explicitly (already pinned in the lock).
- `fips204 0.4.6` is a young crate for a security primitive; correctly isolated
  behind a seam and used only for the rare recovery-root signature, and correctly
  labeled "not a PQ-security claim." Acceptable for devnet.

### 3.6 Test and audit plan
- Present: unit, property (64-case up to 127-step sequences), adversarial,
  cross-language byte fixtures, restart-equivalence. This is strong.
- **Thin/absent:** (a) no fuzz harness despite `AGENTS.md` naming fuzzing —
  wire decoders, canonical encoding, mempool admission, and tx execution are the
  obvious first `cargo-fuzz` targets and should start now; (b) no consensus
  model/■safety checking beyond unit tests; (c) the multi-node Byzantine test
  (<1/3 power cannot finalize conflicting blocks) is still owed; (d) reference-
  machine benchmarks owed (acknowledged; cloud container cannot produce them).
- **Audit gating is back-loaded.** Independent audit appears only at Phase 13
  (mainnet). For an AI-alternating-implementation crypto core, recommend an
  earlier external review checkpoint for the consensus + crypto + economics
  layers, before the platform is stacked on top. This is an owner/process
  decision — see §5 Q1.

---

## 4. Architectural gaps that get expensive if left implicit

These are not bugs; they are under-specified foundations. Deciding them late
forces schema or protocol churn.

1. **Consensus committee vs. whole-set voting (confirmed-requirement gap).** The
   owner confirmed a *rotating stake-weighted sub-committee* so "every validator
   does not have to vote for every block," and *no global validator cap*. The
   implemented `FinalityCertificate` requires >2/3 of the **whole** active
   validator-set snapshot (`consensus.rs:100` explicitly: "the committee for this
   prototype is the whole active validator set"). Whole-set voting is a correct,
   safe *first step*, but it is O(N) votes / O(N²) gossip per block and cannot
   meet "not everyone votes" or scale to an uncapped set with 6–8s finality. The
   sub-committee sampling is unbuilt and is **not trivially safe** (the sampled
   committee must itself hold an honest super-majority with high probability —
   this needs a VRF/sortition design and a security argument). Action: keep
   whole-set for devnet, but (a) stop describing consensus as "complete" without
   this caveat, (b) write an ADR for committee sampling before Phase 5/6, (c) make
   the finality path committee-parameterized so the later change is not a rewrite.

2. **Latest-only state retention.** `ChainStore` keeps only the latest state
   (`chainstore.rs`, acknowledged in Phase 3 docs). The Mina-style light client
   and "Merkle/object proof for the relevant account" goal require serving proofs
   and, for ZK, historical state commitments. Retrofitting historical
   state/state-deltas after mainnet schema is frozen is costly. Action: decide the
   archival / historical-state / snapshot strategy as a storage ADR **before**
   Phase 8 (proofs), ideally scoped in Phase 6.

3. **Equivocation-to-slash is now WIRED (updated after finding commit `0e4b4c5`).**
   This item originally read "unwired"; that was true of the docs but not of the
   code — the GPT implementer had wired it on 2026-07-15 without updating the status
   docs. The block header commits an `evidence_root`, the block body carries
   `evidence` executed atomically in `build_block`/`apply_block`, and the driver
   auto-includes machine-detected equivocation (`pending_evidence` +
   `build_candidate`). **The live gap is now the reverse risk: with no durable
   vote/lock WAL (C4), the live slash loop can slash an honest validator that
   crashed and restarted mid-height.** Actions: (a) fix C4 *before* this runs on a
   network; (b) independently adversarially review the 0e4b4c5 evidence path
   (verification in progress this session) — confirm evidence is signature/snapshot-
   verified before slashing, is replay-protected (no double-slash), is bounded, and
   cannot be used to slash an honest peer; (c) still-open policy sub-questions:
   dedup/expiry window and interaction with the unbonding slashable window, and the
   **slash severity percentages, which are economic policy the owner must eventually
   set** (§5).

4. **Contract compilation boundary (safety-critical invariant, currently
   implicit).** The confirmed design ("high-level language lowers to a Rust
   framework, Rust→WASM, reuse LLVM") must make one invariant explicit and
   permanent: **the chain accepts and stores only deterministic WASM bytecode +
   metadata; all source→Rust→WASM compilation happens off-chain and is untrusted;
   on-chain validation is limited to WASM validation, gas metering, and
   access-list enforcement.** If a source compiler ever runs in the block path, it
   destroys determinism and creates an enormous attack surface. This is a
   clarification to record now (architecture + Phase 7), not a change of decision.

5. **Fork-choice / equivocation at the block level under committee change.** The
   finality-certificate design ("follow the certified chain, commit only
   finalized blocks") is sound for the single-height Tendermint machine, but the
   validator-set transition across epochs (who signs the certificate for the
   block that *changes* the set, long-range/weak-subjectivity assumptions for
   syncing nodes) is not yet specified. Action: an ADR on epoch/validator-set
   transition + weak-subjectivity checkpoint before Phase 5 economics.

6. **Epoch advancement is not wired into the real block path (confirmed).** The
   epoch machinery (`finish_epoch`, reward distribution, unbonding maturation,
   session-key expiry) is only invoked by the demo, never by `produce_block` /
   `import_validated` / the consensus commit path. So a running node never advances
   epochs. The fix is not just "call it" — the rollover trigger must be a
   deterministic height-derived function executed identically inside `apply_block`
   on every node, or honest nodes diverge on the state root at the boundary. This
   is both a "the feature is dead in the real path" bug (E1) and a consensus-design
   decision (how epoch length maps to height); record it in the consensus/epoch ADR.

---

## 5. Decisions that need the owner (to be asked in chat, batched)

Only genuinely owner-owned, design-shaping choices are raised.

- **Q1 — Review/process gate. RESOLVED 2026-07-16: owner chose (A)** — insert an
  earlier independent security-review gate for the consensus + crypto + economics
  core before the contract/ZK/bridge layers stack on it, additional to the Phase-13
  mainnet audits. Recorded in `docs/decision-record.md` ("Security review process")
  and scheduled as **Phase 5.5** in `docs/development-plan.md`.

- **Q2 — Contract language sequencing. RESOLVED 2026-07-16: owner chose (A)** —
  ship an interim Rust-eDSL/SDK → off-chain-WASM authoring path first; the bespoke
  WEBC language is a later, separately-resourced project. **Owner added a
  requirement:** design the interim structure to be flexible/replaceable so the
  WEBC language mounts later with minimal rework (a stable contract ABI + a
  versioned, swappable "authoring front-end → lowering → audited Rust framework →
  WASM" seam; the language is one more front-end over the same target, never a
  runtime rewrite). Recorded in `docs/decision-record.md`, `docs/architecture.md`,
  and staged as Phase 7a/7b in `docs/development-plan.md`. The off-chain-compilation
  invariant (§4.4) stands.

- **Deferred, not asked now (recorded so it is not lost):** slashing severity
  percentages and downtime-penalty schedule are economic policy of the same class
  as inflation; they will be brought to the owner with a threat model at the
  Phase 5 economics freeze, alongside the already-deferred distribution, bridge-
  trust, and governance-emergency decisions.

### Process observation (not a question — a governance finding)

The single most consequential code change of the last work session — commit
`0e4b4c5`, which made the equivocation→slash loop LIVE (80% slash + tombstone) —
landed together with a test commit (`a2e774e`) **without updating any status doc**.
`continuation-guide.md`, `implementation-status.md`, and `development-plan.md` all
still said "equivocation is not wired," the exact opposite of the shipped code. A
review that trusted the docs would have (a) missed that a fund-destroying path is
live and (b) told the next session to build something that already exists. The
`AGENTS.md` "keep the two status docs in sync, one decision one home" rule exists
precisely to prevent this; it was not followed. The concrete recommendation is the
Definition-of-Done and CI already point at: no consensus/economic change merges
without the status-doc update in the same change, and — better — a check that
fails CI when code touching `crates/webc-*/src/{round,consensus,block_builder,
state}.rs` lands without a same-PR docs touch. This is a stronger argument for the
earlier-review gate in Q1.

---

## 6. Prioritized worklist for the next sessions

Ordered so value survives an interruption. (P0 = do before building more on top.)

- **P0** Fix the CONFIRMED consensus safety/liveness/DoS findings before building
  on consensus: C1 (validate a block before prevote/lock/finalize), C2 (no silent
  halt on failed import), C3 (bound per-height round memory), C4 (durable vote/lock
  WAL — a prerequisite for the slash-wiring below). See `findings.md`.
- **P0** Wire epoch advancement deterministically into the real block path (E1):
  today `finish_epoch`'s only caller is the demo, so a running node never advances
  epochs (rewards/unbonding/expiry are dead), and however it gets wired MUST be a
  height-derived function inside `apply_block` or nodes fork at the boundary.
- **P0** Equivocation-to-slash is already wired (commit `0e4b4c5`), so the P0 here
  is: (a) fix C4 (vote/lock WAL) BEFORE this live slash loop is exposed to a network
  with honest restarts, and (b) adversarially verify the 0e4b4c5 evidence path
  (signature/snapshot verification before slashing, replay protection, bounds,
  no-slash-of-honest-peer). §4.3.
- **P0** Add the multi-node Byzantine safety test (<1/3 power cannot finalize
  conflicting blocks). Owed Phase 4 acceptance item.
- **P1** Pin the genesis total supply (G1): assert `minted_supply ==
  Amount::from_webc(10_000_000)` in `from_genesis` — the current invariant is a
  tautology that would accept a wrong total. Cheap, high-value.
- **P1** Fix `slash_locked` to respect the slashable window and not penalize
  matured/withdrawable stake (U1). Economic-security correctness.
- **P1** Make the scheduler serializable-order-preserving before the Phase-6
  executor consumes it (SC1); validate the block timestamp (E2).
- **P1** Add `cargo-deny` (advisories/licenses/bans) + JS advisory scan to CI.
  §3.5.
- **P1** Stand up `cargo-fuzz` targets for wire decode, canonical encoding,
  mempool admission, and tx execution. §3.6.
- **P1** ADR: node key management (no seeds in argv; keystore file, 0600). §3.1.
- **P1** ADR: committee sampling design + keep the finality path committee-
  parameterized. §4.1.
- **P2** ADR: historical-state / archival / snapshot strategy before proofs. §4.2.
- **P2** ADR: epoch validator-set transition + weak-subjectivity checkpoint. §4.5.
- **P2** Record the off-chain contract-compilation invariant in architecture +
  Phase 7. §4.4.
- **P2 (doc hygiene)** Replace cross-document **line-number** references with
  section/symbol references. `session-keys-implementation-plan.md` cites
  `AGENTS.md`/ADR/plan line ranges that rot on any edit (the 2026-07-16 AGENTS.md
  restructure already invalidated its `AGENTS.md lines …` citations; a caveat was
  added, but new docs should cite sections, not lines).
- **Ongoing** reference-machine benchmarks (needs real hardware, not this cloud).

See `docs/review/findings.md` for the line-level code findings from this session.
