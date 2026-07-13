# WEBC token economics

## Native unit

- Genesis supply: `10,000,000 WEBC`
- Precision: 12 decimals
- Smallest unit: `0.000000000001 WEBC`
- Integer accounting: `1 WEBC = 1,000,000,000,000` base units

All protocol arithmetic must use checked integers. Floating-point numbers must never decide balances, fees, rewards, supply, or stake.

## Genesis distribution

The intended mainnet distribution is:

- 30% for contributors to a publicly announced devnet/testnet program, awarded by published contribution rules;
- 70% for broad global public distribution;
- 0% fixed founder, developer, foundation, investor, or private-sale allocation.

Private work before the public contribution program does not earn mainnet coins. Devnet and testnet coins have no value and never convert directly to mainnet coins.

Duplicate-account resistance cannot rely only on account limits. The public program needs verifiable contribution categories, anti-collusion checks, review, an appeal period, and published results before genesis.

## Inflation

The annual inflation rate starts at 10%. Once per year, the rate is multiplied by 0.8 until it reaches a 1% floor.

```text
rate(year) = max(1%, 10% * 0.8^year)
```

It reaches the floor after about 11 yearly reductions. The exact issuance per block or epoch must derive from this annual rule without changing the yearly total because of rounding. Supply calculations and examples must be covered by tests.

There is no six-month halving in the confirmed design.

## Fees

Fees are cheap by default and dynamic under load:

- a base fee pays for ordinary resource use;
- 50% of the base fee is burned;
- 50% enters validator/delegator reward accounting;
- an optional priority fee goes to the block producer;
- a website or another account may sponsor a user's fee;
- congestion in one application namespace should not raise unrelated application fees, except for a bounded network-wide floor needed during global overload.

Exact numeric fee constants will be selected from reproducible load tests rather than guessed now.

## Staking and delegation

- Validators must stake on devnet and mainnet.
- A validator pool needs at least 100 WEBC total active stake to activate.
- At the activation threshold, the operator supplies at least 20 WEBC directly.
- A pool operator must provide at least 20% of the pool's total stake.
- Delegators may provide at most 80%.
- Each individual delegation must be at least 1 WEBC.
- Target unstaking delay: about 7 minutes on devnet and 7 days on mainnet.
- Correct work receives rewards; missed work loses rewards; provably malicious signed behavior can be slashed.

The 100 WEBC pool threshold and 1 WEBC minimum delegation are confirmed mainnet starting rules. The pool threshold is not a cap: larger pools must continue to maintain at least 20% operator stake. Changing either value after mainnet requires the normal public governance process and advance notice; neither value must follow an automatic external-price feed.

Stake exits follow [`ADR-0008`](adr/0008-stake-lifecycle-and-exit-queue.md).
An exit request does not change the current epoch's voting power. Requests enter
a deterministic FIFO queue, are admitted under a network-wide per-epoch churn
budget, cool down while remaining slashable for their active window, and become
claimable exactly once. The 7-minute/7-day values are normal minimum targets;
heavy network-wide exit demand can extend them. WEBC Layer 1 does not guarantee
instant redemption or depend on new deposits to pay earlier exits.

## Donations and governance

Wallets, sites, users, and validators may expose voluntary donations. The protocol must not contain a mandatory founder fee or hidden recipient.

Core protocol changes follow an open proposal and client-adoption process inspired by Ethereum. Tokens and applications may create their own optional on-chain votes and pay normal network fees.
