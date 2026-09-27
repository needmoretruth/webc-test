# Definition gap analysis

Date: 2026-07-17
Baseline: `WEBC-DEFINITION.md` (rounds 1–12, completed 2026-07-16) — the single
source of truth for product, economic, experience, and functional design.
Priority rule applied throughout (per the definition's own reading rules): §15
overrides §1–§13; §15 overrides §16 where they differ.

This document lists every point where the repository's other documents diverge
from the definition, so the documentation overhaul that follows is traceable.
It changes no document by itself. `WEBC-DEFINITION.md` itself is read-only.

Status labels used below follow the honesty rule (§11): **confirmed** /
**planned** / **experimental** / **not-yet-built**.

---

## A. Cross-cutting gaps (affect many documents)

### A1. Genesis distribution: the 30/70 split is superseded — HIGH

Every existing document states "30% contributors / 70% broad public
distribution" and calls the mechanism unsolved. The definition **decides** the
full allocation (§15.33, approved §15.38):

| Channel | Share | Notes |
|---|---|---|
| Contributor pool | 25% | vests 1–2 yr per award (§15.33) |
| Validator bootstrap grants | 5% ceiling | stake-locked, vest by proven operation, unused reverts (§15.10, §15.15) |
| Usage subsidies | 30% | ~10 yr, decaying annual ceiling (§15.33) |
| Cross-chain airdrop | 15% | three 5% waves (launch/+12mo/+24mo), history-weighted, per-wallet caps, no fame weighting (§15.16, §15.31, §15.33) |
| Ecosystem fund | 15% | non-transferable fee credits, published criteria (§15.7, §15.12) |
| Strategic reserve | 10% | governance-locked, drains to subsidies if untouched 5 yr (§15.33) |

Also superseded/added:
- "Fair" is redefined: **public rules, equal access, no insider privilege — not
  equal-per-human** (§15.11).
- Rejected channels: mining, identity verification, sales/auctions (§15.16).
- Founder compensation is decided: paid under the same published contribution
  rules, disclosed expectation that the founder earns a meaningful early share,
  measurement starts only at public announcement (§15.4, §15.16). No current
  document carries this disclosure — an honesty gap.
- Genesis validator bootstrap path (§15.2 **proposed**, §15.10/15.15 decided
  direction) appears nowhere.

Documents affected: `README.md`, `AGENTS.md`, `docs/tokenomics.md`,
`docs/whitepaper.md` §3.1, `docs/decision-record.md`, `docs/definition.md`,
`docs/development-plan.md` (Phase 12 "30% contributor distribution"),
`docs/index.md`.

### A2. Performance targets: §15.42 supersedes the 2s / 6–8s numbers — HIGH

All documents state 2s blocks / 6–8s finality / ~12s degraded as *the* targets.
The definition lowers the engineering targets (§15.40, §15.42):

- **Fast path** (single-owner operations — payments, own-object moves):
  ~0.4–0.8s effective finality via quorum certificates, **launch scope**.
- **Consensus path** (shared state): ~1s blocks, ~1–2s finality normal,
  ≤4s degraded, with a Mysticeti-class DAG-BFT reference design.
- §8's 2s / 6–8s figures remain the **conservative public claim** until public
  benchmarks prove the new targets ("engineering target, to be claimed only
  after public benchmarks").
- Hardware floor must not silently rise to buy speed; that trade-off returns to
  the owner explicitly (§15.42 guardrail).

No document mentions the two-track strategy, the fast path, or the DAG-BFT
reference design. The current consensus code is a Tendermint-style machine —
see `docs/code-reconciliation-worklist.md`.

Documents affected: `README.md`, `AGENTS.md`, `docs/whitepaper.md` §1/§2.3/§6,
`docs/architecture.md`, `docs/decision-record.md`, `docs/roadmap.md`,
`docs/development-plan.md`, `docs/definition.md`, `docs/index.md`.

### A3. DEX and per-block batch settlement: absent everywhere — HIGH

The definition decides a native DEX architecture (§15.8, §15.13, §15.18,
§15.34, §15.37, §15.39):

- canonical shared pool per pair + three site participation modes
  (storefront / liquidity contributor / independent pool);
- all frontend fees on-chain-disclosed; trust via an on-chain track-record
  registry;
- **mandatory per-block uniform-price batch settlement as the native default
  swap semantics** (no instant-bypass lane) — kills sandwich/front-running;
- chain-native retry: an order is an on-chain intent with limit price,
  deadline (~10s default), fill-or-cancel flag; protocol retries across
  batches; user-selectable per order;
- MEV revenue policy: WEBC does not fund validators with extractive MEV;
  benign arbitrage remains welcome.

No existing document mentions any of this. `docs/development-plan.md` Phase 7
even names a "constant-product token swap" reference application with
per-transaction semantics, which contradicts the mandatory batch default.

### A4. Oracle economics: mechanism documented, economics missing — HIGH

Existing docs (whitepaper §7, decision-record, architecture) describe staked
reporters + median aggregation + slashing only. The definition decides the full
economic design (§15.6, §15.17, §15.21):

- consumers pay → accuracy-weighted, bonded reporters;
- **pull-based updates**, at most once per block, shared by all consumers in
  that block;
- optional first-party publisher class;
- ecosystem-fund seeding: usage-proportional, accuracy-gated, capped,
  auto-sunsetting;
- small flat per-fresh-read fee + app subscriptions; **display-only reads are
  free** via light-client proofs;
- accepted leakage on slow feeds (treated closer to public goods).

### A5. Storage pricing and bulk data: absent — MEDIUM

The definition decides (§15.22, §15.27): storage **deposit + deletion rebate**
(Sui-style occupancy pricing, not Solana-style rent), hot/cold tiering with
archive nodes, and a Walrus-style erasure-coded blob layer as **phase 2**.
Existing docs only say "storage growth is priced" (whitepaper §5,
decision-record fees). No deposit/rebate, no tiering, no blob layer anywhere.

### A6. Validator economics and networking frugality: partially documented — MEDIUM

Decided in the definition but missing from the docs:

- the deliberate **middle path**: low stake floor (100/20 WEBC) + mid-range
  hardware target; explicitly no Solana-style per-vote fees — votes are
  permissioned aggregated consensus messages, spam-controlled by
  admission/quotas/slashing (§15.23, §15.28);
- bandwidth frugality as a first-class budget: zstd on by default (wire and
  storage), compact-block relay (never send the same bytes twice), vote
  aggregation, SSD-first state with modest RAM (§15.19, §15.24, §15.29);
- official tuned container image as the standard validator environment;
  min/recommended spec split; floor raisable only with measured demand and a
  published hardware roadmap (§15.26);
- zk policy: succinct light-client verification yes; optional state
  compression later; **never on the consensus critical path** (§15.25).

Existing docs partially align (whitepaper §2.3 hardware wording, ZK sections)
but none state the vote-fee stance, compression defaults, container image, or
spec-floor governance.

### A7. The authoring language is now designed: Weft — HIGH

`docs/decision-record.md` lists the language's surface syntax and name under
"Explicitly not decided yet", and records design leanings "from Go and the
Solana/Sui contract languages". The definition **decides** the design
(§15.41, §15.43, §15.44):

- working name **Weft** (`.weft`), owner-renamable; trademark/domain search
  before public branding;
- TypeScript-familiar brace surface, Rust-grade semantics;
- built-in exact money type on u128 base units; per-asset types; **linear
  assets** (cannot be duplicated or dropped);
- no null / no exceptions / no floats / no macros; `Option`/`Result`;
  bounded loops; entrypoints declare `reads`/`writes`;
- one canonical formatter; compiler-emitted machine-readable manifest;
  compiler-enforced structured doc-comments; error messages as fix suggestions;
- single-binary toolchain (`weft fmt/check/test/build`, LSP);
- never-break architecture: WASM artifacts run forever, editions, stable ABI,
  reproducible builds, stdlib stability;
- AI-first mechanics: one-file components, small regular grammar, docs-as-data
  (LLM-ingestible bundle, CI-tested examples corpus), error-driven convergence.

The Go-leaning wording in `decision-record.md` is superseded by the TS-familiar
surface decision (§15 is newer). The Phase 7a/7b sequencing (interim Rust
eDSL first, language later over the same seam) remains valid and consistent.

### A8. AI-agent commerce primitives: mandate spec decided — MEDIUM

Existing docs mention "AI web agents that pay and get paid within sponsor
caps" only. The definition decides (§15.5, §15.32):

- **mandate** objects: principal, agent key, total budget/spent, expiry,
  counterparty policy, per-tx max, rate limit, **no re-delegation**, instant
  revocation, full audit trail;
- an on-chain **service registry** (machine-readable prices/interfaces;
  schema design is delegated open work);
- HTTP-402-style payment-flow compatibility.

### A9. AI-native identity is understated — MEDIUM

§6 makes the AI-native thesis WEBC's distinctive bet: three equal audiences,
machine-readable everything, agent commerce, an AI-optimized language.
`README.md` and `docs/definition.md` barely mention it; the whitepaper summary
does not name it. The rewritten documents must present it as identity, not a
feature bullet.

### A10. Honesty labels — MEDIUM

§11/§16 require every capability and number to be labeled confirmed / planned /
experimental / not-yet-built. Existing docs use prose caveats but not the
labels. All rewritten and new documents must carry them, and public performance
claims must stay at the conservative figures (~2s / 6–8s) until benchmarks
(§15.42).

### A11. Amount representation: final shape partially reflected — LOW (docs) / MEDIUM (code)

`decision-record.md` says "Suggested internal amount type: unsigned 128-bit
integer". The definition finalizes (§15.14, §15.19): u128 storage/compute +
**256-bit intermediates** for multiply/divide + **variable-length encoding at
rest and on the wire**. Code already stores `Amount(u128)` (confirmed); the
widening-intermediate and varint-encoding parts are not yet built — carried in
the code worklist, and the docs must state the full decided shape. (Update
2026-09-26: the 256-bit intermediate landed in `441bc22`.)

### A12. Governance and launch process: minimal process sketched — LOW

§15.36 sketches: public proposals in the open repo, fixed comment window,
reference implementation + testnet trial, validator/ecosystem signaling,
founder as initial maintainer **with a published sunset** to an elected
committee. Existing WIP-process text (whitepaper §12) is consistent in spirit
but lacks the founder-maintainer disclosure and sunset. Details remain open
(delegated design).

### A13. Cross-chain UX and flagship applications — LOW

§15.36 records the direction: one-action send with upfront total-cost/time
quote, single status view across both chains, guaranteed refund path; four
flagship candidates (payment/tipping widget, HTML-game starter kit, DEX
storefront widget, AI-agent API marketplace). Absent from `docs/bridge.md`
and everywhere else. Details are delegated open design.

---

## B. Per-document findings

### B1. `README.md` — rewrite
- 30/70 distribution implied via linked docs; "Confirmed identity" block lists
  2s / 6–8s as the targets without the two-track qualifier (A2).
- AI-native identity missing from the description (A9).
- "Design direction" omits: DEX/batch settlement, oracle economics, storage
  deposits, Weft, fast path, distribution program.
- Start-here reading order must begin with `WEBC-DEFINITION.md`.

### B2. `docs/index.md` — rewrite
- Authority order lists `AGENTS.md` → `decision-record.md` → … and does not
  mention `WEBC-DEFINITION.md` at all. New order must put the definition first
  for product/economic/experience/functional questions (security documents
  remain a separate authority track by design — definition scope note).
- Must list the new system documents (section D below).

### B3. `docs/definition.md` — rewrite as a pointer summary
- Duplicates an outdated short definition (30/70 implied, no AI-native thesis,
  "high-level language" unnamed). Becomes a one-page summary that defers to
  `WEBC-DEFINITION.md` §1–§14 with citations.

### B4. `docs/tokenomics.md` — major rewrite
- Distribution section is fully superseded (A1).
- Missing: usage-subsidy channel mechanics, airdrop waves/caps/weighting,
  ecosystem fee credits (non-transferable), strategic reserve, bootstrap
  grants, founder-compensation disclosure.
- Fees: missing storage deposit/rebate (A5), oracle read fees (A4), DEX
  disclosed frontend fees + MEV revenue policy (A3), sponsorship launch
  placeholders (§15.35).
- Staking: middle-path rationale and no-per-vote-fee stance missing (A6).
- Keep: supply/precision, inflation curve, 50/50 split, 100/20/80/1 staking
  rules, exit-queue reference (all confirmed by §7/§16).

### B5. `docs/whitepaper.md` — major rewrite
- §1 summary: add AI-native identity, hybrid model framing per §15.29/15.30
  (Sui primary object reference), two-track speed.
- §2.3/§6: performance figures per A2; consensus section must present the
  DAG-BFT reference design and fast path as planned engineering work while the
  current Tendermint-style machine is the prototype reality.
- §3.1: distribution per A1.
- §5: fees per B4.
- §7: oracle economics per A4; agent mandates per A8; Weft per A7.
- New sections needed: DEX/batch settlement (A3), storage economics (A5),
  distribution program summary (A1).
- §8 (tokens/governance): add governance process sketch per A12.

### B6. `docs/architecture.md` — targeted update
- Consensus numbers per A2; add fast-path lane and vote aggregation/committee
  sampling as planned design (the "two structural gaps" note stays, now tied
  to §15.40/15.42).
- State model: cite §15.29/15.30 (hybrid confirmed; Sui object reference).
- Add: batch-settlement execution consequence (shared-infrastructure objects —
  the §15.8 isolation tension and its §15.13 resolution), storage
  deposit/rebate + tiering (A5), bandwidth frugality + zstd envelope rule
  (§15.24), zk placement policy (§15.25).
- Weft/authoring section: name the language, cite A7; the compilation-boundary
  invariant and 7a/7b seam stay (consistent with §15.41/15.43).

### B7. `docs/roadmap.md` — rewrite
- Order of work must add: fast path (launch scope), DEX batch settlement,
  oracle economics, distribution program build-out, Weft toolchain, storage
  deposits + blob layer (phase 2), validator container image, benchmark gates
  for the new speed targets.

### B8. `docs/development-plan.md` — full re-plan (mission step 4)
- Phase 12 "30% contributor distribution" → 25% + program build (A1).
- Phase 7 reference app "constant-product token swap" → canonical-pool swap
  with per-block uniform-price batch settlement (A3).
- No phases exist for: DEX, oracle economics, mandates/service registry,
  distribution machinery (vesting, stake-locked grants, fee credits, airdrop
  claims), fast path, speed-target benchmarks, storage deposits, blob layer,
  container image. The rewritten plan adds them; the current Phase 4/5/5.5
  content (consensus hardening, security gate) remains the immediate path and
  is unchanged in substance.

### B9. `docs/decision-record.md` — reconcile and demote
- Currently claims to be "the authoritative short record"; it now defers to
  `WEBC-DEFINITION.md` for product/economic/experience/functional decisions
  and keeps only implementation gates + security-adjacent decisions.
- Outdated content: 30/70 split (A1), 2s/6–8s as sole targets (A2), language
  "not decided yet" + Go leanings (A7), "precise distribution mechanism open"
  (A1), amount type "suggested" (A11).
- Keep: wallet/security sections, bridge rules, Phase 5.5 gate, PQ rules —
  the definition deliberately does not cover security (§ scope note), so these
  survive with terminology alignment only.

### B10. `AGENTS.md` — facts update only
- "Confirmed protocol/product decisions" block: distribution (A1), speed
  targets (A2), and add pointer that `WEBC-DEFINITION.md` is the product SSOT.
- Required reading order: insert `WEBC-DEFINITION.md`.
- All working rules, safety rules, and standing user instructions remain
  untouched.

### B11. `docs/bridge.md` — additive update
- Add the cross-chain UX direction (§15.36, open design) and the delivery
  priority already in `decision-record.md`. Safety boundary text unchanged
  (security scope).

### B12. `docs/security.md` — terminology alignment only
- Per mission scope: no weakening/deletion. Only alignment needed: none of its
  claims conflict with the definition (it cites no distribution or timing
  numbers). Add one line noting the definition/security document split so
  readers know where product claims live. Known-gaps section stays.

### B13. `docs/ai-handoff.md` — small update
- Reading order gains `WEBC-DEFINITION.md` at the top for product questions.
- The "do not revive" list stays; add "do not revive the 30/70 split or the
  6–8s-only speed framing".

### B14. Historical artifacts — no rewrite
`docs/review/*` (plan review, findings, codebase map), `docs/adr/*`,
`docs/session-keys-implementation-plan.md`, `docs/session-keys-next-steps.md`,
`docs/code-documentation-template.md`, `docs/continuation-guide.md` (status
doc; its recorded decisions section gets a one-line pointer to the definition
in the next status update, not a rewrite of history). Review findings and ADRs
record what was true when written; they are not authority and say so.

---

## C. New documents to create (mission step 3)

| Document | Sources | Contents |
|---|---|---|
| `docs/distribution-program.md` | §15.2, 15.3, 15.10–15.12, 15.15, 15.16, 15.20, 15.31, 15.33, 15.38 | full allocation, channel mechanics, release shapes, reversion paths, anti-farming rules, founder rule, bootstrap grants |
| `docs/dex-batch-settlement.md` | §15.8, 15.13, 15.18, 15.34, 15.37, 15.39 | pool/storefront architecture, batch semantics, retry, registry, MEV policy, delegated mechanics to design |
| `docs/oracle-economics.md` | §15.6, 15.17, 15.21 | reporter economics, pull model, read fees, seeding, first-party publishers |
| `docs/weft-language-plan.md` | §9, §15.41, 15.43, 15.44 | design commitments, toolchain, editions, AI-first mechanics, spec-writing plan, 7a/7b integration |
| `docs/speed-roadmap.md` | §8, §15.18, 15.39, 15.40, 15.42 | two-track strategy, fast-path protocol design scope, claim policy, benchmark gates, hardware-floor guardrail |
| `docs/validator-operations.md` | §15.2, 15.10, 15.19, 15.23, 15.24, 15.26, 15.28 | middle path, spec floor/recommended, container image, bandwidth budgets, bootstrap program |
| `docs/agent-commerce.md` | §6, §15.5, 15.32 + open item 8 | mandate object spec, HTTP-402 flow, service-registry schema (initial design of the delegated open item) |
| `docs/code-reconciliation-worklist.md` | mission scope limit | prioritized code-vs-definition divergences; no code changes |

Open items delegated by §16 that are *designed inside* the documents above
rather than getting their own file now: cross-chain UX details (→ bridge.md),
governance process details (→ whitepaper/decision-record until a dedicated doc
is warranted), flagship applications (→ development plan adoption phase),
service registry schema (→ agent-commerce.md), Weft grammar spec (→ weft plan,
actual spec is implementation work), fast-path protocol (→ speed roadmap,
protocol spec is engineering work).

---

## D. Questions for the owner

None blocking. Two notes recorded for transparency:

1. §15.2's bootstrap-phase issuance (reward budget keyed to staked amount with
   published sunset criteria) is still **proposed**, not decided. The new docs
   label it "planned (proposed in §15.2)" and it can be revisited at the
   Phase 5 economics freeze.
2. `docs/decision-record.md`'s role shrinks (B9). If the owner prefers to keep
   it as the single decision index instead, the alternative is to copy every
   §15/§16 decision into it — rejected here because duplicating the definition
   invites drift; the definition is read-only and authoritative by owner rule.
