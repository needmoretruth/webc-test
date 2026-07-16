# WEBC speed roadmap

Sources: `WEBC-DEFINITION.md` §8, §15.18, §15.39, §15.40, §15.42. Status: the
two-track strategy and targets are **decided**; the fast-path protocol design
is delegated engineering work scoped here. Labels per §11.

## 1. Claim policy — decided (§15.42, §11)

- **Conservative public claim (current):** ~2s blocks, ~6–8s normal finality,
  ~12s degraded — what the prototype targets today.
- **Engineering targets (decided, claims only after sustained public
  benchmarks):**
  - fast path: **~0.4–0.8s** effective finality for single-owner operations
    (launch scope);
  - consensus path: **~1s blocks, ~1–2s finality normal, ≤4s degraded**.
- Every published number states hardware, transaction mix, contention,
  validator count, geography, and test duration.
- **Guardrail (decided):** the mid-range hardware floor (§15.23, §15.26) is
  unchanged; if benchmarks show a target requires a higher floor, that
  trade-off returns to the owner/governance explicitly — speed must not be
  bought by silently raising hardware requirements.

## 2. Why two tracks (§15.39, §15.40)

- Throughput ≠ latency: transactions pipeline; finality time is not a rate
  limit. The UX ladder stands: apps show results at execution (~next block)
  and treat finality as a background upgrade; only high-value actions gate on
  finality (§15.39).
- The competitive frontier is sub-second (Sui fast path; Solana's approved
  Alpenglow targeting ~150ms), so complacency at 6–8s is not acceptable —
  but WEBC's decentralization principle rules out buying speed with
  data-center hardware (§15.18). Hence: a consensusless fast path where
  global ordering is unnecessary, and a modern DAG-BFT consensus where it is.

## 3. Track 1 — the fast path (planned, launch scope, not-yet-built)

**Scope (§15.40):** operations touching only state a single party controls:
- paying from one's own balance (credits to the receiver are commutative);
- moving/mutating one's own objects (game items, own NFTs).

**Mechanism (FastPay/Sui-fast-path technique, production-proven):**
validators individually verify and countersign the operation; a quorum of
signatures forms a **certificate of effective finality** at ~0.4–0.8s;
consensus later checkpoints certificates into blocks. Contended/shared state
(pools, batch settlement, multi-party contracts) stays on the consensus path.

**Delegated protocol design — scoped here:**
1. **Eligibility rule:** an operation qualifies iff its declared write set is
   entirely owner-sequenced state (own balance debit + commutative credits +
   own objects). The eligibility check must be static from the declared
   access set — no execution needed to classify.
2. **Owner sequencing:** fast-path safety derives from the owner's own
   sequence numbers (per-lane nonces already exist): a client that
   equivocates its own sequence can only lock its own account until
   consensus checkpointing resolves it — the classic FastPay property; it
   cannot harm third parties.
3. **Certificates:** stake-weighted countersignatures over the signed
   operation; quorum matches the consensus safety threshold; certificates
   are gossiped, spendable immediately (a certified credit can be consumed),
   and included in the next checkpoint block.
4. **Checkpointing:** every certified fast-path operation is embedded in a
   consensus block within a bounded number of blocks; the state root commits
   both paths; light clients verify fast-path effects through the checkpoint.
5. **Interaction with batch settlement:** fast path never touches shared
   pools; a payment funding a swap intent is fast-path, the swap itself is
   consensus-path (§15.13).
6. **Failure modes to design and test:** owner self-equivocation (lock, then
   consensus resolution), validator-set rotation mid-certificate, fee
   accounting parity with consensus-path fees, replay across paths, and
   degraded-mode fallback (fast path unavailable → operations route through
   consensus with no correctness loss, only latency).

## 4. Track 2 — consensus stretch (planned, benchmark-gated)

- Reference design: **Mysticeti-class DAG-BFT** (§15.40, §15.42) targeting
  ~1s blocks / ~1–2s finality on the decided mid-range hardware floor.
- The prototype's Tendermint-style machine remains the working consensus
  until: (a) its HIGH-severity findings are fixed (`docs/review/findings.md`),
  (b) the Phase 5.5 security gate passes, and (c) a DAG-BFT prototype beats
  it in like-for-like benchmarks on reference hardware. Migration is an ADR +
  benchmark decision, not a rewrite-by-default
  (`code-reconciliation-worklist.md`).
- Supporting frugality work that both tracks need (§15.19): aggregated
  committee votes, compact-block relay, zstd everywhere, committee sampling.

## 5. Benchmark gates (extends development-plan)

Published on the reference machines (minimum / recommended / performance —
development-plan Phase 6), each sustained and reproducible:

1. Baseline: current machine, 2s blocks — finality distribution, TPS staged
   gates (100/500/1k/2k+).
2. Frugality deltas: zstd + compact relay + vote aggregation bandwidth
   reduction (claim: consensus bandwidth collapses per §15.19 — verify).
3. Fast-path prototype: certificate latency distribution p50/p95/p99 across
   geography; claim ~0.4–0.8s only if p95 lands inside it.
4. DAG-BFT prototype vs Tendermint baseline on identical hardware/topology.
5. Degraded-network suites (loss/latency injection): consensus ≤4s target;
   fast-path fallback correctness.
6. Hardware-floor audit per §15.42: if any gate needs more than the floor,
   escalate to the owner before adopting the result.

Until each gate passes publicly, public materials keep the conservative
claim. This is the §11 honesty rule applied to speed.
