# WEBC native oracle economics plan

Sources: `WEBC-DEFINITION.md` §9, §15.6, §15.17, §15.21. Status: the economic
design is **decided direction**; parameters and schemas are delegated and
designed here. Everything is **not-yet-built**. Slashing mechanics live in
the security documents (out of the definition's scope).

## 1. Decided design (§15.17)

The industry-converged three-part economics, plus two WEBC upgrades:

- **Consumers pay → accuracy-weighted reporter revenue → bonded reporters.**
  Reporters register per feed with a stake; consuming applications pay
  per-read and subscription fees; revenue is distributed to reporters
  weighted by accuracy (closeness to the accepted aggregate) and liveness;
  persistent outliers lose standing.
- **Upgrade 1 — pull-based updates:** a feed updates on demand when a
  transaction needs fresh data, **at most once per block**; that single value
  is shared by every consumer in the block; the first-needing transaction or
  an app subscription carries the update cost (§15.21). No constant pushes
  nobody reads.
- **Upgrade 2 — first-party publishers:** original data owners (e.g.
  exchanges) may register as a labeled publisher class for higher accuracy.
- **Display-only reads are free:** a site showing live prices to thousands of
  visitors reads state via light-client proofs without a transaction; fees
  apply only when a transaction consumes a value on-chain (§15.21). Per-user
  cost approaches zero as usage grows.
- **Read fees:** a small flat per-fresh-read fee plus cheap app-level
  subscriptions (runtime-enforced — possible because WEBC controls its
  execution engine); accepted leakage on slow-moving feeds, treated closer to
  public goods (§15.17 trade-off verdict).
- **Cold-start seeding from the ecosystem fund (§15.17):** paid in proportion
  to actual reads served, gated on accuracy, capped per feed and per
  reporter, auto-sunsetting for feeds without consumers.
- **Feed creation is permissionless for a fee** with a canonical feed
  registry (§15.6).
- Aggregation: median-style aggregation over independent reporters so no
  single reporter dictates the value (§9).

## 2. Delegated design — designed here

### 2.1 Feed lifecycle

1. **Create:** anyone pays the feed-creation fee, defining feed ID, value
   type/units, aggregation rule (median default), minimum reporter count,
   update staleness bound, and bond size class. The registry stores the
   canonical entry (machine-readable, catalog-compatible — §6).
2. **Report:** bonded reporters submit signed values as ordinary
   transactions. A pull request in block N aggregates the freshest valid
   reports into the feed's on-chain value, at most once per block.
3. **Consume:** a transaction declaring a read of the feed either (a) pays
   the per-fresh-read fee if it triggers the block's update, or (b) shares
   the already-updated value for the smaller shared-read fee; subscription
   apps prepay a period of shared reads.
4. **Sunset:** a feed with no paying consumers for the sunset window stops
   accruing seed subsidies (§15.17) and eventually archives; reactivation is
   a fresh creation fee against the same registry entry.

### 2.2 Reporter economics

- **Bond:** per-feed stake in WEBC; bond size class set at feed creation
  (higher-value feeds demand larger bonds). Bonds reuse the existing
  staking/slashing infrastructure (§9); slashing conditions and severity are
  security-document scope.
- **Revenue split per accounting epoch:** fees collected on a feed are
  distributed by score = f(accuracy, liveness): accuracy from distance to the
  accepted aggregate over the epoch; liveness from participation rate in
  pulled updates. Persistent outliers lose standing (score decays to zero →
  no revenue) independent of slashing.
- **First-party publishers** are flagged in the registry, carry the same bond
  rules, and their values are labeled in the aggregate's provenance so
  consumers can weight or require them.
- **Free-riding stance (§15.17):** a value can be re-published after one paid
  read, but for fast feeds a copied value goes stale in seconds; slow feeds
  are accepted as partial public goods.

### 2.3 Consumer interface

- Weft/framework component `oracle.read(feed)` — a declared read of the feed
  state key; the compiler's manifest exposes each entrypoint's feed
  dependencies (aligns with §15.41 declared access).
- Reads carry the feed's staleness bound: a transaction requiring fresher
  data than the current block value triggers (and pays for) the pull.
- Subscriptions are app-namespace objects: prepaid shared-read allowances,
  visible on-chain so costs are auditable.

## 3. Cheap/fast/accurate under web volume (§15.21)

The design's scaling argument, recorded for benchmarks to verify: one update
per block per feed regardless of consumer count; display reads free via light
clients; costs amortize across all consumers in a block; per-user cost → 0 as
usage grows. Benchmarks must publish read-fee amortization curves before any
"cheap oracle" claim (§11 honesty).

## 4. Build plan (phase alignment: development-plan Phase 8)

1. Feed registry + bonded reporter registration (reuses staking records).
2. Report ingestion + median aggregation + once-per-block pull gating,
   deterministic and whole-block atomic.
3. Read metering: per-fresh-read fee, shared-read fee, subscription objects.
4. Accuracy/liveness scoring + epoch revenue distribution.
5. Ecosystem-fund seeding hooks (usage-proportional, accuracy-gated, capped,
   auto-sunset — §15.17).
6. First-party publisher class + provenance labels.
7. Adversarial tests: a single lying reporter cannot move the median; a
   colluding minority below the aggregation threshold cannot; stale-value
   replay is rejected; seed-farming (self-reads) nets negative after fees.

## 5. Open parameters (measurement placeholders, §15.35 method)

Bond size classes, fee sizes (fresh read / shared read / subscription),
accuracy scoring window, sunset window, minimum reporter counts. All frozen
with testnet evidence at the relevant phase, not guessed now.
