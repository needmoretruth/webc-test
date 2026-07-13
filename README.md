# WEBC / WEB COIN

WEBC is a prototype foundation for an independent Rust Layer-1 blockchain designed for browser- and website-native payments, applications, tokens, staking, succinct verification, and bidirectional Ethereum/Solana bridges.

> Status: research and prototype. The current code does not yet implement the newly confirmed protocol and must not be used with real funds.

## Start here

Read these documents in order:

1. [`AGENTS.md`](AGENTS.md)
2. [`docs/decision-record.md`](docs/decision-record.md)
3. [`docs/index.md`](docs/index.md)
4. [`docs/development-plan.md`](docs/development-plan.md)
5. [`docs/whitepaper.md`](docs/whitepaper.md)
6. [`docs/implementation-status.md`](docs/implementation-status.md)

Supporting documents:

- [`docs/definition.md`](docs/definition.md)
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/tokenomics.md`](docs/tokenomics.md)
- [`docs/bridge.md`](docs/bridge.md)
- [`docs/security.md`](docs/security.md)
- [`docs/continuation-guide.md`](docs/continuation-guide.md)

## Confirmed identity

- Project: `WEBC`
- Coin: `WEB COIN`
- Ticker: `WEBC`
- Chain: independent custom Layer 1
- Core language: Rust
- Genesis supply: `10,000,000 WEBC`
- Precision: 12 decimal places
- Consensus direction: permissionless delegated Proof of Stake with BFT-style finality
- Target block interval: 2 seconds
- Normal finality target: 6-8 seconds
- Validator pool activation minimum: 100 WEBC total, including at least 20 WEBC from the operator; minimum delegation is 1 WEBC
- PoH: not used

## Design direction

WEBC combines selected ideas rather than copying one chain wholesale:

- Solana-inspired declared state access and parallel execution;
- Sui-inspired owned/shared objects for NFTs and application state;
- Mina-inspired succinct ZK verification for browsers;
- simple account-style balances for payments and ordinary tokens;
- application namespaces and localized congestion pricing;
- isolated browser wallet signing;
- post-quantum-ready, versioned account authorization;
- bidirectional wrapped WEBC and external-asset bridges for Ethereum and Solana.

## Repository layout

```text
crates/
  webc-crypto/      existing cryptographic prototype
  webc-chain/       existing state-transition prototype
  webc-node/        existing CLI demo
sdk/
  webc-js/          browser SDK prototype
  webc-widget/      embedded widget prototype
docs/
  decision-record.md   confirmed decisions and technical gates
  development-plan.md  authoritative phased work plan
  whitepaper.md        protocol/product design draft
```

## Important warning about current code

The code remains a prototype with important incomplete boundaries, including:

- wallet isolation, recovery, and post-quantum authorization are incomplete;
- slashing classes beyond objective double-vote evidence are disabled;
- localized congestion fee markets and a public contract runtime are incomplete;
- production bridge proof verification, limits, monitoring, and audits are absent;
- PoH has been removed from authoritative block data and hashing;
- a trusted-relayer bridge prototype that is not safe for real assets.

See [`docs/implementation-status.md`](docs/implementation-status.md) before reusing any module.

## Legacy prototype commands

Once the Rust toolchain is installed:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo run -p webc-node -- demo
```

The immediate milestone is the remainder of Phase 1 in [`docs/development-plan.md`](docs/development-plan.md), not RPC or bridge expansion.
