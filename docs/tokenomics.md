# WEBC token economics

Source of truth: `WEBC-DEFINITION.md` (§7, §15, §16). Every claim below cites
its deciding section. Labels follow the honesty rule (§11): **confirmed**
(decided design), **planned** (decided direction, mechanics being designed),
**experimental**, **not-yet-built** (decided but no code exists).

## Native unit — confirmed (§7, §15.14, §15.19)

- Genesis supply: `10,000,000 WEBC`
- Precision: 12 decimals; smallest unit `0.000000000001 WEBC`
- Integer accounting: `1 WEBC = 1,000,000,000,000` base units
- Amount representation: **u128** for storage and compute; **256-bit
  intermediates** for multiply/divide paths (widening arithmetic);
  **variable-length integer encoding** at rest and on the wire so small values
  stay small (§15.14). The u128 storage type is implemented; widening
  intermediates and varint encoding are not-yet-built (see
  `code-reconciliation-worklist.md`).

All protocol arithmetic uses checked integers. Floating-point numbers never
decide balances, fees, rewards, supply, or stake (§7).

## Issuance — confirmed (§7)

The annual issuance rate starts at 10% and is multiplied by 0.8 each year
until it reaches a 1% floor (reached after roughly 11 years):

```text
rate(year) = max(1%, 10% * 0.8^year)
```

Rewards accrue smoothly by block/epoch, never in one annual jump. The 1% floor
provides an enduring reward for network participants. Implemented and tested
in the prototype (confirmed in code).

**Bootstrap-phase issuance — planned (proposed in §15.2, not yet decided):**
during a labeled bootstrap phase, the reward budget may be keyed to *staked
amount* (rate × total stake, capped by the schedule's percentage of supply) so
a tiny early staking base cannot capture outsized absolute issuance, with
published sunset criteria. To be settled at the Phase 5 economics freeze.

## Genesis distribution — confirmed allocation (§15.33, approved §15.38)

There is no fixed founder, developer, foundation, investor, or private-sale
allocation (§7, §11). "Fair" means **public rules, equal access, no insider
privilege — not equal-per-human** (§15.11). The full allocation:

| Channel | Share | Release shape |
|---|---|---|
| Contributor pool (retroactive awards) | 25% | paid as earned after public announcement; each award vests linearly over 1–2 years |
| Validator bootstrap grants | 5% **ceiling** | stake-locked; vest by proven operation (§15.10); unused budget reverts to the contributor pool |
| Usage subsidies (fee support for real users/apps) | 30% | ~10 years; annual ceiling starts at ~15% of the channel, decays ~×0.85/yr; unspent rolls forward |
| Cross-chain airdrop | 15% | three waves of 5% (launch, +12 mo, +24 mo); per-wallet caps; unclaimed after 12 months per wave flows into usage subsidies |
| Ecosystem fund | 15% | grants paid as **non-transferable fee credits**; annual budget cap ≈ 1/5 of the channel; published criteria |
| Strategic reserve | 10% | governance-locked; assignable only to an existing channel by public governance; drains gradually into usage subsidies if untouched for 5 years |

Design logic (§15.33): the two usage-linked channels dominate (45%) because
they are the least gameable and directly buy adoption; the airdrop is modest
and staged so farmers cannot harvest it at once; every channel has a reversion
path so nothing sits dead. All channels are capped, monitored, and
individually stoppable (§15.3).

Rules that survive from the original intent (§7):
- test-network coins have no value and never convert into real coins;
- activity before the publicly announced program begins earns nothing.

### Rejected distribution channels — confirmed (§15.16)

Mining (hardware conflicts with WEBC's lightweight identity), identity
verification (an AI-native chain cannot gate rewards on proof-of-humanity,
§15.3), and open auctions/sales (money-for-coins is out).

### Cross-chain airdrop rules — confirmed (§15.16, §15.31, §15.33)

- Eligibility: prove control of an existing Solana or Ethereum wallet.
- Weighted by **past, costly-to-fake history** (wallet age, cumulative gas,
  staking history) — never by wallet count.
- Snapshot at an **unannounced or already-past date**.
- Per-wallet caps with diminishing weight; breadth over depth.
- **No fame weighting** (owner-confirmed, §15.31). Outreach to visible
  builders is funded as explicit ecosystem-fund partnerships instead (§15.20).
- Professional farmers holding aged wallets are bounded by caps and
  quality-weighting, not pretended away (§15.16).

### Ecosystem fund — confirmed (§15.7, §15.12)

A grant program, not an automatic carve-out: projects apply against published
criteria; grants are paid as **non-transferable fee credits** (spendable only
as usage, cannot be dumped); decisions are founder-judged initially — stated
honestly — migrating to community review as governance matures. The fund also
seeds oracle reporter rewards (§15.17) and partnerships.

### Founder compensation — confirmed (§15.16)

The founder is paid under the **same published contribution rules as
everyone**, with no special allocation. Stated plainly per the honesty rule:
early on, the founder is likely the main contributor and will therefore earn a
meaningful share of the contributor pool. Contribution measurement begins only
after the public announcement, not at first launch.

### Validator bootstrap grants — confirmed direction (§15.10, §15.15)

Up to 5% of genesis as stake-locked grants to operators who proved sustained
correct operation on the test network: vesting by epochs of provably correct
validation (1–2 year horizon; quitting or misbehaving forfeits the remainder),
selection on reliability over raw compute, a personal co-stake that ramps over
time, per-operator caps plus hosting/geography diversity criteria, grants
count toward the operator's ≥20 WEBC / ≥20% share, unused budget reverts.
Founder-run nodes at genesis are acceptable if labeled temporary with
published retirement criteria (phase-0 honesty). Parameter details open.

## Fees — confirmed direction (§7, §15.35)

- Base fees are cheap by default and dynamic under load, priced by real work:
  computation, state access, storage growth, contention (§7).
- **Localized pricing:** congestion on one application does not raise fees for
  unrelated applications; only a small network-wide floor applies during
  global overload (§7, §8).
- **Fee split:** 50% of the base fee is burned, 50% funds participant rewards
  (§7). Implemented in the prototype (confirmed in code). An optional priority
  fee speeds inclusion.
- No fixed fiat-denominated fee promise (§7).
- **Launch parameters are measurement-tuned placeholders — confirmed as
  method (§15.35):** near-zero floor for ordinary transfers; sponsorship
  defaults at launch ~20 sponsored operations per user per app per day,
  per-app daily budgets inside hard protocol caps, sponsorship limited to
  simple operations. All values move with testnet data; none are promises.

### Sponsorship — confirmed direction (§7, §15.35)

Sites pay users' fees within hard, bounded budgets (per user, per app, per
operation, per day) so a site can offer free usage without being drainable.
Usage subsidies from the public pool (§15.33) flow through this same
mechanism — honestly framed as subsidized acquisition, not free money, because
spam always net-costs the spammer (§15.3).

### Storage pricing — confirmed direction (§15.22, §15.27) — not-yet-built

- **Deposit + deletion rebate** (Sui-style): writing state locks a deposit
  proportional to bytes; deleting refunds most of it. Storage is priced as
  occupancy, not a one-way purchase.
- **Hot/cold tiers:** only execution-relevant state stays hot; history and
  long-untouched objects move to archive nodes with proofs, restorable on
  demand.
- Bulky content (files, media) stays off-chain with hashes on-chain (§9);
  a **Walrus-style erasure-coded blob layer** paid in WEBC is phase 2
  (§15.27). A dedicated storage chain is not needed (§15.22).

### Oracle fees — confirmed direction (§15.17, §15.21) — not-yet-built

Consumers pay: a small flat per-fresh-read fee plus cheap app-level
subscriptions, distributed to reporters weighted by accuracy and liveness.
A feed updates at most once per block and that value is shared by every
consumer in the block. **Display-only reads are free** via light-client
proofs; fees apply only when a transaction consumes the value on-chain.
Cold-start seeding comes from the ecosystem fund: usage-proportional,
accuracy-gated, capped, auto-sunsetting (§15.17). See `oracle-economics.md`.

### DEX fees and MEV policy — confirmed (§15.13, §15.37) — not-yet-built

- Every storefront/frontend fee over the canonical shared pools must be
  **disclosed on-chain**; silent markup stacking is treated as user harm.
- **WEBC does not fund validators with extractive MEV** (§15.37): batch
  settlement removes intra-block ordering games; validators are paid by
  issuance, 50% of base fees, and priority fees. If that proves insufficient,
  the lever is adjusting those parameters by governance — never re-opening
  user exploitation. Benign cross-venue arbitrage pays ordinary fees and is
  welcome. See `dex-batch-settlement.md`.

## Staking and delegation — confirmed (§7)

- A validator pool activates at **100 WEBC** total stake; the operator
  supplies at least **20 WEBC** and always at least **20%** of the pool;
  delegation supplies at most **80%**; minimum single delegation **1 WEBC**.
- No global cap on registered validators.
- Unstaking delay: ~7 minutes on the test network, ~7 days on the main
  network; no instant-redemption promise.
- Correct participation earns rewards; provable misbehavior costs stake
  (mechanics live in the security documents, out of the definition's scope).

These values are confirmed starting rules; changing them requires public
governance with advance notice and must not follow an automatic external price
feed. Stake exits follow [`ADR-0008`](adr/0008-stake-lifecycle-and-exit-queue.md)
(FIFO queue, churn budget, cooldown, slashable window) — implemented in the
prototype.

### Validator economics: the deliberate middle path — confirmed (§15.23, §15.28)

- Ethereum makes stake expensive and hardware cheap; Solana inverted it. WEBC
  takes the middle: **low stake floor + mid-range hardware** (a decent
  multi-core server with NVMe and ~1 Gbps — an ordinary cloud instance).
  §12's lightweight-device promise applies to users verifying, not validators
  producing.
- **No per-vote fees.** Votes are permissioned, bounded consensus messages,
  not fee-paying transactions: only current committee keys may vote, one vote
  per member per round, equivocation costs stake, invalid senders are banned
  at the p2p layer (§15.28). Participating in consensus costs nothing; only
  misbehavior costs.
- Bandwidth frugality protects operators from metered-egress billing as well
  as throughput (§15.19): zstd everywhere, compact-block relay, vote
  aggregation. Node docs ship sizing guides and recommend flat-bandwidth
  providers (§15.23). See `validator-operations.md`.

## Donations and governance — confirmed direction (§11, §15.36)

Wallets, sites, users, and validators may expose voluntary donations; the
protocol contains no mandatory founder fee or hidden recipient (§11).

Core changes follow a public proposal-and-adoption process, not automatic rule
by the largest holders (§11). The minimal process (planned, §15.36): public
proposals in the open repository, a fixed comment window, reference
implementation plus testnet trial before adoption, validators and ecosystem
signaling acceptance, and the founder acting as initial maintainer **with a
published sunset** to an elected committee. Applications and tokens may create
their own optional governance instances for a fee (§11).
