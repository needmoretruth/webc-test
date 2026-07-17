# WEBC distribution program plan

Sources: `WEBC-DEFINITION.md` §7, §15.2, §15.3, §15.10–15.12, §15.15, §15.16,
§15.20, §15.31, §15.33, §15.38. Status: the **allocation and channel rules are
decided**; this document plans the program mechanics inside those decisions.
Everything here is **not-yet-built**; labels mark what is decided vs designed
here (delegated) vs open.

## 1. Principles — decided

- **Fairness definition (§15.11):** public rules, equal access, no insider
  privilege — *not* equal-per-human. An AI-native chain cannot gate rewards on
  proof-of-humanity (§15.3).
- **Key to scarcity (§15.3):** any giveaway keyed to a resource sybils can
  manufacture (accounts, transactions, uptime) is gameable; every channel
  keys to something genuinely scarce (capital history, hard-to-fake work,
  real usage that net-costs spammers).
- **Rejected channels (§15.16):** mining, identity verification,
  auctions/sales.
- **Portfolio, not one bet (§15.3):** several capped, monitored, individually
  stoppable channels spread over ~10 years.
- **Honesty (§11, §15.16):** test-network coins never convert; nothing earns
  before the public announcement; the founder is paid under the same
  published rules with the expectation disclosed.

## 2. The allocation — decided (§15.33, approved §15.38)

| # | Channel | Share | Release shape | Reversion path |
|---|---|---|---|---|
| 1 | Contributor pool | 25% | paid as earned after public announcement; each award vests linearly 1–2 yr | — (terminal pool; receives reversions) |
| 2 | Validator bootstrap grants | 5% ceiling | stake-locked; vests by proven operation | unused budget → contributor pool |
| 3 | Usage subsidies | 30% | ~10 yr; annual ceiling ~15% of channel decaying ×0.85/yr; unspent rolls forward | — (receives reversions) |
| 4 | Cross-chain airdrop | 15% | three 5% waves: launch, +12 mo, +24 mo | unclaimed 12 mo per wave → usage subsidies |
| 5 | Ecosystem fund | 15% | annual budget cap ≈ 1/5 of channel; published criteria | fee credits expire back to the fund (designed below) |
| 6 | Strategic reserve | 10% | governance-locked | untouched 5 yr → drains gradually into usage subsidies |

## 3. Channel mechanics

### 3.1 Contributor pool (25%) — decided direction; mechanics designed here

Decided (§7, §15.16): retroactive awards for verifiable contributions after a
publicly announced program start; published rules; 1–2 yr linear vesting per
award; the founder participates under the same rules, disclosed.

Designed here (delegated):
- **Contribution tracks:** code and review, security findings (severity-
  weighted), documentation and machine-readable docs/catalog entries,
  tooling, testing/adversarial work, validator operation outside the grant
  program, ecosystem integrations. Every track has published scoring rules
  and per-identity caps with diminishing returns.
- **Ledger and audit:** a public contribution ledger; awards reproducible
  from public evidence; a fixed appeal window per award round; periodic
  third-party audit of the scoring.
- **Anti-gaming:** multiple signals per award (no single-metric farming);
  review by maintainers who did not author the work; collusion checks across
  rounds.
- **Founder disclosure line (must appear in program rules, §15.16):** early
  on, the founder is likely the main contributor and will therefore earn a
  meaningful share; measurement begins only at the public announcement.

### 3.2 Validator bootstrap grants (5% ceiling) — decided (§15.10, §15.15)

- Prove sustained correct operation on the test network over weeks
  (reliability, not raw compute — compute is rentable).
- At mainnet genesis: **stake-locked** coins usable only for staking; they
  count toward the operator's ≥20 WEBC / ≥20%-of-pool requirement.
- **Vest by operation:** unlock per epoch of provably correct validation
  (target horizon 1–2 years); quitting early or misbehaving forfeits the
  remainder.
- Personal co-stake requirement, ramping over time.
- Per-operator cap + hosting-provider and geography diversity criteria.
- Unused budget reverts to the contributor pool. Founder-run genesis nodes
  are acceptable if labeled temporary with published retirement criteria.
- Genesis bootstrap sequence (§15.2 — proposed status): recruit on testnet as
  the first contribution track → allocate earned grants at genesis so day one
  has a real distributed validator set → labeled bootstrap phase with
  issuance keyed to staked amount and published sunset criteria. The
  issuance-keying piece is **still proposed**, to be decided at the Phase 5
  economics freeze.

### 3.3 Usage subsidies (30%) — decided direction; mechanics designed here

Decided (§15.3, §15.33): usage-linked fee subsidies — honestly framed as
subsidized acquisition, not free money; ungameable because spam always
net-costs the spammer; ~10-year run with a decaying annual ceiling.

Designed here (delegated):
- Delivery rides the **existing sponsorship mechanism** (§7, §15.35): the
  protocol's subsidy pool underwrites per-user/per-app/per-day capped fee
  sponsorship for registered applications, so end users transact free within
  caps.
- **Application registration:** apps opt in under published criteria (real
  user-facing service, disclosed team or site identity, no wash-usage
  patterns); allocation proportional to *distinct funded usage*, not raw
  transaction count; per-app caps with diminishing returns.
- **Wash-usage defense:** subsidies never exceed fees actually burned/paid by
  the subsidized operations (a spammer cannot extract more than they spend);
  anomaly monitoring with per-app suspension (each channel is individually
  stoppable — §15.3).
- Unspent annual budget rolls forward within the channel.

### 3.4 Cross-chain airdrop (15%) — decided (§15.16, §15.31, §15.33)

- Prove control of an existing **Solana or Ethereum** wallet to claim.
- Weight by **past, costly-to-fake history**: wallet age, cumulative gas
  spent, staking history — never wallet count.
- Snapshot at an **unannounced or already-past date** per wave.
- Per-wallet caps with diminishing weight; breadth over depth; **no fame
  weighting** (§15.31).
- Three waves (launch, +12, +24 months) so later real users still benefit and
  farmers cannot harvest everything at once; per-wave unclaimed funds flow to
  usage subsidies after 12 months.
- Honest bound (§15.16): professional farmers with aged wallets are bounded
  by caps and quality weighting, not eliminated.
- Designed here: claims run on-chain with light-client proof of the source
  wallet's signature; per-wave Merkle snapshot published at claim-open so
  awards are reproducible; wave 2/3 criteria may additionally weight
  *WEBC-side usage since the prior wave* (subject to the §15.3 scarcity rule:
  weight only fee-burning usage, published in advance).

### 3.5 Ecosystem fund (15%) — decided (§15.7, §15.12)

- A **grant program**: public applications against published criteria.
- Grants paid as **non-transferable fee credits** — spendable only as usage
  (sponsored fees, deployment costs, oracle seeding), never dumpable.
- Decision process: founder-judged initially, stated honestly; migrates to
  community review as governance matures.
- Also funds: oracle reporter seeding (usage-proportional, accuracy-gated,
  capped, auto-sunsetting — §15.17) and explicit builder/creator
  partnerships (the legitimate form of the rejected fame-weighting — §15.20).
- Designed here: fee credits carry an expiry (e.g. 24 months) after which
  unused credits return to the fund's budget; annual budget cap ≈ 1/5 of the
  channel (§15.33).

### 3.6 Strategic reserve (10%) — decided (§15.33)

Governance-locked; may only be assigned to an existing channel by public
governance; if untouched for 5 years it drains gradually into usage
subsidies. No discretionary founder access.

## 4. Program sequencing — designed here

1. **Publish first, measure after (§7, §15.16):** the complete program rules
   (this document frozen into a public specification) are published before
   any qualifying work begins.
2. **Testnet phase:** contributor tracks + validator recruitment open;
   contribution ledger runs publicly.
3. **Genesis:** contributor awards and bootstrap grants allocated from proven
   ledger entries; airdrop wave 1 claim opens; genesis file and allocation
   proofs publicly reproducible (development-plan mainnet gates).
4. **Years 0–2:** usage subsidies ramp with real applications; airdrop waves
   2–3; ecosystem grants begin.
5. **Years 2–10:** decaying subsidy ceilings; reversion paths keep unused
   budget moving; governance matures toward community grant review.

## 5. Open items

- §15.2 bootstrap issuance keying (owner decision at economics freeze).
- Exact scoring weights per contributor track, subsidy registration criteria,
  and fee-credit expiry length — parameter work to freeze with the public
  specification (measurement placeholders per §15.35 method).
- Legal/regulatory review of the airdrop claim flow per jurisdiction is
  outside this document's scope and must precede the public program.
