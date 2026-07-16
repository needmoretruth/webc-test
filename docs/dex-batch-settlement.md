# WEBC native DEX and batch settlement plan

Sources: `WEBC-DEFINITION.md` §15.8, §15.13, §15.18, §15.34, §15.37, §15.39.
Status: architecture and settlement semantics are **decided**; the remaining
mechanics (limit/slippage details, multi-hop routing, shared-infrastructure
pricing) are delegated and designed here. Everything is **not-yet-built**.

## 1. Decided architecture (§15.13)

**Liquidity is separated from storefront.**

- **Canonical shared pools:** by default, one canonical, deep, shared pool per
  asset pair, listed in a public on-chain registry. Deep pools beat thousands
  of fragmented per-site pools on price, slippage, and arbitrage loss (§15.8).
- **Three site participation modes:**
  1. *Storefront* — a site embeds a swap widget over the canonical pool and
     attaches its own **disclosed** frontend fee.
  2. *Liquidity contributor* — a site's small pool deposits into the
     canonical pool and earns a proportional share of its fees.
  3. *Independent pool* — for niche/custom markets (e.g. a game's item
     economy); the exception, not the default.
- **All fees on-chain-disclosed:** users see the full breakdown (pool fee +
  frontend fee + network fee); silent markup stacking is user harm (§15.8).
- **Trust as an on-chain track record:** the registry records age, volume,
  fee history, and incident flags per pool and per storefront; wallets and
  aggregators filter on it. A storefront over the canonical pool inherits the
  pool's trust and only needs a reputation for honest fees.

## 2. Decided settlement semantics (§15.18, §15.37)

- **Mandatory per-block uniform-price batch settlement** is the native
  default swap semantics. No instant-bypass lane exists: a bypass would
  re-enable sandwich extraction against everyone in the batch, and only bots
  benefit from ~1s-faster execution (§15.34 analysis).
- Swaps are submitted as **intents** with declared access sets
  (parallel-friendly); each block settles all intents on a pair at **one
  uniform clearing price** — intra-block ordering games (sandwiches,
  front-running) become meaningless.
- **Chain-native retry (§15.37):** an order is a short-lived on-chain intent
  carrying limit price, deadline (default ~10s ≈ a few blocks, user-set), and
  a fill-or-cancel flag. The protocol keeps it in subsequent batches until
  filled, cancelled, or expired; the user's device need not stay online;
  nothing is re-signed. A retried order can never fill worse than its own
  limit; a pending order is cancellable at any moment.
- **MEV revenue policy (§15.37):** WEBC does not fund validators with
  extractive MEV. Validators are paid by issuance, 50% of base fees, and
  priority fees; adjusting those by governance is the only honest lever.
  Benign cross-venue arbitrage is welcome and pays ordinary fees.
- Precedents (§15.18): CoW Protocol (uniform-price batches in production),
  Penumbra (protocol-native per-block batch swaps). Solana/Sui do not do
  this; it is a differentiator.
- Latency honesty (§15.18, §15.39): a normal order fills in its first batch;
  UIs show the pending intent instantly and the result at execution.

## 3. Delegated mechanics — designed here

### 3.1 Order semantics

- **Order fields:** pair, direction, exact input amount, limit price (as a
  minimum acceptable output; required — "market" orders are a wallet-side
  convenience that sets a bounded default limit from the last clearing price
  plus a user-visible slippage allowance), deadline, fill-or-cancel flag,
  optional storefront ID (for disclosed fee attribution).
- **Partial fills:** when one side of a batch is larger, the clearing rule
  fills the price-compatible surplus side **pro-rata**; the unfilled remainder
  stays in the intent for the next batch (within deadline) — pro-rata is
  order-arrival-independent, preserving the no-ordering-games property.
- **Expiry/cancel:** expiry and cancellation return escrowed input
  atomically; a cancel in block N takes effect before block N's batch only if
  it is included in that block, otherwise in the next — deterministic, no
  race-dependent behavior.

### 3.2 Clearing rule (per pair, per block)

1. Collect all live intents on the pair (new + retrying).
2. Compute the uniform clearing price that maximizes matched volume between
   buy and sell intents against the pool curve (the pool acts as the
   residual counterparty at the clearing price; its curve moves once per
   batch, by the net amount only).
3. Fill every intent whose limit is compatible; pro-rata on the surplus side;
   emit one settlement event per intent.
4. Netting first, pool second: opposing user flow matches against itself
   before touching pool liquidity — better prices than sequential AMM swaps
   and no intra-block price zig-zag.

The exact curve family for canonical pools (constant-product vs stable-curve
per pair class) is a parameter decision at implementation, benchmarked; the
batch semantics above are curve-agnostic.

### 3.3 Multi-hop routing

- Canonical pools route through **WEBC as the default numeraire** (pair
  A/WEBC + WEBC/B) to keep the pair set dense without fragmenting liquidity.
- A multi-hop order is decomposed into legs executed in the **same block's**
  batches with an all-or-nothing guarantee: either every leg clears within
  the order's end-to-end limit, or the whole order retries/expires. No
  partially-routed stuck funds.
- Aggregation across independent pools (mode-3) is a wallet/aggregator-layer
  concern using the trust registry; the protocol only guarantees atomicity.

### 3.4 Shared-infrastructure pricing (the §15.8 isolation tension)

Canonical pools and hot feeds are intentionally shared objects. Pricing
answer, consistent with localized fees (§7/§8):

- Each canonical pool is its own **congestion domain**: contention on pair
  A/B raises the intent-submission fee for that pair only, never for
  unrelated pairs or apps.
- Because settlement is one batch write per block regardless of intent count,
  execution cost scales with intents, not with contention on a hot object —
  the batch itself is the anti-contention design (§15.13).
- Storefront fees are disclosed transfers inside the settlement, not separate
  transactions.

### 3.5 Liquidity provision

- LP deposits/withdrawals settle in the same per-block batch cadence (they
  are pool-state writes), valued at the block's clearing price — removing
  LP-vs-swapper intra-block games as well.
- Mode-2 (contributor) sites hold LP shares of the canonical pool; their
  earned fees are attributed on-chain so the "small pool feeds the big pool"
  economics are auditable (§15.13).
- Liquidity sharding for extreme pairs stays a later option (§15.13).

## 4. Build plan (phase alignment: development-plan Phase 8)

1. Registry + canonical pool objects + LP accounting (no batches yet, no
   public access — internal testnet only).
2. Intent objects, escrow, expiry/cancel, per-pair batch clearing in
   `build_block`/`apply_block` (deterministic, whole-block atomic).
3. Retry semantics + pro-rata partial fills + property tests
   (order-arrival-permutation invariance is the key adversarial test: any
   permutation of the same intent set must clear identically).
4. Multi-hop atomic routing.
5. Storefront fee attribution + trust-registry records.
6. SDK/widget: swap component, disclosed-fee display, pending-intent UX
   (§15.39 ladder: show executed at ~1 block, final at finality).

## 5. Open items

- Curve family per pair class (benchmark decision).
- Intent-submission fee constants and per-pair congestion parameters
  (measurement placeholders per §15.35 method).
- Whether wave-style batch settlement extends to NFT marketplaces (out of
  scope here; application-layer concern).
