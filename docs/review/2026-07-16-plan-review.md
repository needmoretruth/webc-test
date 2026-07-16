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

3. **Equivocation-to-slash is unwired (the core PoS security loop).** The machine
   detects double-votes and emits verifiable `DoubleVoteEvidence`, but the driver
   never applies it: `block.evidence` is neither committed by the header nor
   executed, and slashing only fires via an `Operation::SubmitSlashingEvidence`
   transaction. PoS security *is* slashing; an un-actuated detector is not
   security. Under-specified sub-questions: who submits evidence (proposer duty
   vs. permissionless bounty), is there a whistleblower reward, is evidence
   committed by an evidence-root in the header, what is the dedup/expiry window,
   and how does it interact with the unbonding slashable window. Action: an ADR
   for the evidence pipeline before implementing, plus an end-to-end "offender's
   stake is actually reduced" test. Note the **slash severity percentages are
   economic policy the owner must eventually set** (§5).

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

---

## 5. Decisions that need the owner (to be asked in chat, batched)

Only genuinely owner-owned, design-shaping choices are raised. See the session
chat for the plain-language version with options and a recommendation.

- **Q1 — Review/process gate.** Given a security-critical chain implemented by
  alternating AI sessions, insert an **earlier independent security-review gate**
  for the consensus + crypto + economics core (before the contract/ZK/bridge
  layers are stacked), rather than only the Phase-13 mainnet audits? (Owner-owned:
  cost, ambition, risk tolerance.) Recommendation: yes — schedule a core-freeze +
  external review after Phase 5.

- **Q2 — Contract language sequencing.** Reaffirm building the bespoke WEBC
  high-level language on the current schedule, or first ship an interim
  "WASM + Rust-eDSL/SDK" path so contracts are possible sooner while the language
  is a later, separately-resourced project? (Owner-owned: it is your product
  decision; you are owed the feasibility/cost picture.) Recommendation: keep the
  decision, but explicitly stage it — WASM+SDK first, bespoke language after the
  runtime and tooling are proven — and record the off-chain-compilation invariant
  from §4.4.

- **Deferred, not asked now (recorded so it is not lost):** slashing severity
  percentages and downtime-penalty schedule are economic policy of the same class
  as inflation; they will be brought to the owner with a threat model at the
  Phase 5 economics freeze, alongside the already-deferred distribution, bridge-
  trust, and governance-emergency decisions.

---

## 6. Prioritized worklist for the next sessions

Ordered so value survives an interruption. (P0 = do before building more on top.)

- **P0** Wire consensus-detected equivocation to an applied slash (ADR + header
  evidence path or auto-submit + end-to-end slash test). §4.3.
- **P0** Add the multi-node Byzantine safety test (<1/3 power cannot finalize
  conflicting blocks). Owed Phase 4 acceptance item.
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
