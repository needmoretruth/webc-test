# WEBC bridge design

Capability scope and delivery priority come from `WEBC-DEFINITION.md` §10;
the cross-chain user-experience direction from §15.36. The trust,
verification, and safety model is owned by the security documents and the
safety-boundary sections below (out of the definition's scope by design).

## Required result

WEBC must support bidirectional movement with both Ethereum and Solana.

Delivery priority (§10): native ETH and SOL first (ideally in parallel), then
their standard sub-tokens (Ethereum ERC-20, Solana Token/Token-2022) and
cross-chain messaging so applications on different chains can communicate —
not only move assets — then additional chains (such as Bitcoin and Tron)
later.

### Native WEBC going outward

1. The user locks native WEBC in the WEBC bridge module.
2. A verified bridge message proves the lock.
3. The Ethereum contract or Solana program mints the same amount of wrapped WEBC.

### Wrapped WEBC coming home

1. The user burns wrapped WEBC on Ethereum or Solana.
2. A verified bridge message proves the burn and finality.
3. The WEBC bridge module releases the same amount of native WEBC.

### External assets coming to WEBC

1. A supported Ethereum token or Solana token is locked in its origin-chain vault.
2. WEBC verifies the message and mints a representation tied to the exact origin chain, contract/program, and asset identifier.
3. Returning it burns the WEBC representation and releases the origin asset.

An asset must never be represented only by its name or ticker. Two tokens called `USDC` are not automatically the same asset.

## Components

- WEBC bridge module and replay-protected message store;
- Solidity contracts on Ethereum;
- Rust programs on Solana;
- relayers that transport messages but cannot create valid messages by themselves;
- proof or approved signature verification on each destination;
- monitoring, rate limits, pause controls, and recovery procedures.

Every message includes version, source and destination network, source transaction/event, nonce, exact asset identity, amount, sender, recipient, and expiry or finality context. A message may execute only once.

## Token coverage

The bridge architecture should be generic enough for normal Ethereum ERC-20 and Solana token-program assets. This does not mean every token is automatically safe. Non-standard, upgradeable, transfer-tax, rebasing, frozen, malicious, or unusual assets require adapters, limits, or rejection.

## User experience direction — planned (§15.36, details open)

The product bar for cross-chain movement, delegated design work within the
recorded direction:

- **One action:** "Send to Ethereum/Solana" as a single step, with an upfront
  quote of the total cost and expected time before the user commits.
- **One status view:** a single tracker covering both chains' finality states,
  so the user never watches two explorers.
- **A guaranteed refund path on failure:** a transfer that cannot complete
  returns the funds; no silent stuck states.
- Wallets display represented assets with their exact origin so two same-name
  assets are never conflated (§10).

## Development stages

1. Define messages, events, domains, asset identities, and replay protection.
2. Test with mock assets and local Ethereum/Solana environments.
3. Add guardian or validator-quorum prototypes with explicit trust assumptions.
4. Research light-client or ZK verification and benchmark cost.
5. Choose the production trust/proof model through a public threat review.
6. Obtain independent audits for WEBC, Solidity, Solana, relayers, operations, and upgrade controls.
7. Launch with low limits, monitoring, pauses, and gradual increases.

## Safety boundary

The current Rust bridge code is only a trusted-relayer message prototype. It is not proof that the bidirectional bridge is complete or safe. No real funds should move until the production design is explicitly approved and separately audited.

The prototype now keeps native WEBC in a distinct escrow bucket per Ethereum or
Solana domain. Native lock moves value from liquid balance into that bucket;
release can only draw from the source domain's available escrow. External-asset
mint/burn uses a separate representation balance and cannot mint native WEBC.
These rules close local supply-accounting and cross-domain drain errors, but do
not authenticate real external-chain events. Trusted relayers and mock assets
remain mandatory until the later production bridge decision, audits, limits,
monitoring, and explicit approval.

Bridge pause powers must be narrow, transparent, delayed where safe, publicly monitored, and removable or governed after launch. Pausing new transfers must not silently confiscate existing assets.
