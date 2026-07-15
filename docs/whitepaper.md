# WEBC / WEB COIN whitepaper draft

Status: design draft for prototype and devnet engineering  
Date: 2026-07-12

This document describes the intended WEBC network. It is not a promise that the current repository already implements these features, and it is not a claim of mainnet readiness.

## 1. Summary

WEBC is a custom Rust Layer-1 blockchain for payments and applications embedded in websites and browsers.

The project aims to combine:

- Solana-inspired declared state access and parallel execution;
- Sui-inspired owned/shared object safety for application assets;
- Mina-inspired succinct ZK verification for lightweight browser clients;
- delegated Proof of Stake with fast BFT-style finality;
- a hybrid account/object state model;
- bidirectional Ethereum and Solana bridges;
- post-quantum-ready account and protocol versioning from genesis.

WEBC deliberately does not adopt Proof of History. A 2-second leader schedule, signed transaction batches, previous-block commitments, and stake-weighted finality provide ordering without the continuous hashing, proving overhead, and protocol complexity of PoH.

## 2. Goals

### 2.1 Website-native use

A website should be able to add:

- wallet connection and creation;
- WEBC payments and transfers;
- tokens and NFTs;
- subscriptions and sponsored fees;
- conditional access and file-download authorization;
- simple games and swaps;
- staking and delegation;
- Ethereum/Solana bridge operations.

The host website must not gain access to the user's wallet secrets. Signing occurs in an isolated, trusted wallet surface that displays exactly what is being authorized.

### 2.2 Lightweight verification

Browsers should not download the full ledger. A browser verifies:

1. a compact proof for a finalized checkpoint;
2. a Merkle/object proof for the relevant account or object;
3. the locally signed transaction before submission.

Full validators still execute and verify blocks. Archive nodes preserve complete historical data. Proof workers may generate succinct proofs using dedicated hardware.

### 2.3 Honest performance goals

WEBC targets:

- 2-second blocks;
- ordinary finality in approximately 6-8 seconds;
- a degraded-network UX target around 12 seconds;
- thousands of simple transfers per second after staged benchmarking;
- low browser and ordinary verification-node requirements;
- validator requirements closer to a normal modern desktop than a Solana-class server during early networks.

These are engineering targets, not measured claims. Published TPS must include hardware, transaction type, state contention, validator count, network geography, proof settings, and sustained-test duration.

## 3. Native coin

- Name: WEB COIN
- Ticker: WEBC
- Genesis supply: 10,000,000 WEBC
- Precision: 12 decimal places
- Base unit: 0.000000000001 WEBC

The smaller genesis supply is a display and distribution choice, not a guarantee of market price. Twelve decimals preserve fine-grained payments and fees regardless of the unit price.

### 3.1 Fair distribution intent

There is no fixed founder, developer, foundation, investor, or private-sale allocation.

- 30% is reserved for verifiable contributions made after a publicly announced devnet/testnet contribution program begins.
- 70% is reserved for broad global public distribution.
- Pre-announcement private development activity earns no automatic mainnet allocation.
- Devnet balances do not convert into mainnet balances.

The distribution mechanism must be published before qualifying work begins. It must not reward raw account creation, node count, or uptime alone. The final mechanism requires its own specification because a permissionless system cannot perfectly prove that two accounts belong to different humans without introducing identity assumptions.

### 3.2 Inflation

The annual issuance rate begins at 10%. Each year the rate is multiplied by 0.8 until it reaches a 1% floor.

```text
rate(year) = max(1%, 10% * 0.8^year)
```

The protocol distributes the equivalent reward smoothly by epoch/block. Before burns, the floor is reached after roughly 11 years. The 1% floor provides an enduring security budget when fees are low.

## 4. Accounts, objects, and parallel execution

WEBC uses one unified state-key scheduler over two developer-facing kinds of state.

### 4.1 Account-style state

Used for:

- WEBC and ordinary fungible-token balances;
- transaction authorization lanes;
- staking and delegation;
- validator rewards;
- bridge balances and accounting.

This keeps wallet and payment UX simple.

### 4.2 Object-style state

Used for:

- NFTs and game items;
- escrows and conditional payments;
- swap orders and positions;
- game sessions;
- application-owned records;
- contract capabilities and permissions.

Owned objects and shared objects have explicit identifiers, versions, and authorization rules.

### 4.3 Declared access

Every transaction lists the state it will read and write. The runtime enforces the list. Undeclared access fails and all transaction changes roll back.

The scheduler may run transactions concurrently only when their access sets do not conflict. This provides Solana-like scheduling without requiring every asset to become a coin object.

### 4.4 Application isolation

Each application receives a cryptographic namespace. Independent applications do not share locks or localized congestion prices merely because both use WEBC.

A globally popular application can still consume network bandwidth and block space. WEBC therefore combines localized contention pricing with a small network-wide floor, fair capacity allocation, and spam-resistant admission rules.

The same wallet may use independent authorization/nonce lanes for unrelated applications so activity on one website does not block unrelated activity elsewhere.

## 5. Fees

Fees pay for signatures, computation, state access, storage growth, and network capacity.

- Base fees adjust dynamically.
- Localized congestion applies primarily to the contested state/application lane.
- 50% of base fees are burned.
- 50% of base fees enter validator/delegator rewards.
- Priority fees reward timely inclusion.
- Applications may sponsor fees under explicit budgets and permissions.

WEBC does not promise a fixed fiat fee because that would require a trusted price oracle. It targets negligible normal-payment fees and prices expensive storage or computation according to measured resource use.

## 6. Consensus

WEBC targets permissionless delegated Proof of Stake with BFT-style finality.

### 6.1 Participation

- Anyone may run a verification node.
- Block-producing/voting validators must stake.
- Delegators may support validators without operating servers.
- A validator pool activates with at least 100 WEBC total active stake.
- At the activation threshold, the operator provides at least 20 WEBC directly.
- A validator operator supplies at least 20% of its pool's active stake.
- Delegation supplies at most 80%.
- Each individual delegation is at least 1 WEBC.
- Registered validator count is not globally capped.
- A rotating stake-weighted committee may vote for each block.

The minimum is an anti-spam and responsibility threshold, not a source of extra voting power. Splitting the same stake across many validator identities must not increase total voting power. Activation queues, performance checks, inactive-validator removal, and rotating committees keep large candidate sets from flooding consensus messages.

### 6.2 Finality

One scheduled validator proposes a block for a 2-second slot. A block finalizes only after more than two thirds of selected stake-weighted voting power signs the required vote stage.

Finality certificates must validate chain ID, height, round, block hash, validator-set snapshot, voting power, and every included signature/proof.

### 6.3 Slashing

Severe penalties require objective evidence:

- signing conflicting blocks/votes for the same step;
- signing an objectively invalid state transition;
- signing fraudulent bridge messages;
- other cryptographically provable equivocation.

Coordinated attacks may receive correlated penalties up to the full slashable stake. Downtime receives lost rewards and softer escalating penalties. Delegators accept validator risk, but operator self-stake is the first and strongest loss layer.

### 6.4 No PoH

WEBC does not use continuous PoH hashing. Signed ordered transaction batches, slot numbers, previous-block hashes, transaction roots, and finality votes provide the required order and audit trail with less complexity and less ZK overhead.

## 7. Smart contracts and web applications

Native security-critical features remain explicit Rust modules first: transfers, staking, slashing, fees, tokens, NFTs, governance, and bridge accounting.

The smart-contract execution foundation is restricted, deterministic WebAssembly with Rust as the first authoring language. Above it WEBC provides its own easy high-level authoring language that lowers (transpiles) to an audited Rust framework, so contracts stay as safe and fast as Rust while being simple enough for humans, AI-assisted developers, and AI agents to assemble from documented, audited components. WEBC builds only the language front end and reuses the Rust/LLVM toolchain; it does not add a second virtual machine or its own compiler backend. Move VM and EVM/Solidity are not the native runtime — Ethereum and Solana compatibility comes through bridges, not native bytecode execution. Contract quality is protected by an opinionated structure, composable components, a dedicated linter/analyzer, and a pre-deploy review step so contracts do not degrade into unmaintainable monoliths.

Contracts cannot directly click a browser button, read a file, call a website, or access the internet. Instead:

- the contract records authorization, payment, content hash, and an event;
- a browser or headless agent performs the external action;
- the agent may return a signed receipt;
- the chain verifies only deterministic inputs and signatures.

This model supports paid downloads, uploads, API calls, webhooks, memberships, subscriptions, games, and server automation without making blockchain execution depend on a particular website being online.

External data reaches contracts through a native staked oracle rather than direct network calls: reporters stake WEBC, submit values as ordinary transactions, and reported values are aggregated (for example by median), with provably wrong reports slashed through the existing staking and slashing infrastructure. This keeps oracle data deterministic, cheap, fast, and hard to manipulate, while external oracles remain optional.

## 8. Tokens, NFTs, and application governance

WEBC includes native creation of fungible tokens and NFTs.

Token issuers may configure minting, maximum supply, burning, authority transfer/revocation, per-account freeze, global pause, transfer rules, and sponsored-fee policies. Wallets must prominently display issuer powers.

Applications and tokens may deploy governance instances with configurable proposal, quorum, delegation, timelock, and voting rules. Core WEBC upgrades use a separate Ethereum-inspired public proposal and client-adoption process rather than automatic plutocratic execution.

## 9. ZK and post-quantum security

### 9.1 Succinct proofs

WEBC starts with Merkle proofs and a versioned proof interface. It evaluates hash/STARK-oriented recursive proofs for compact browser verification. Proof production is separable from ordinary validation and may lag a small number of finalized blocks under defined rules.

### 9.2 Signature agility

Every account has a versioned authorization policy and a post-quantum root/recovery path from creation. NIST ML-DSA is the first candidate for account authorization testing.

Raw post-quantum signatures are much larger than Ed25519. WEBC will test:

- strict post-quantum signatures on every transaction;
- post-quantum root keys authorizing short-lived, limited session keys;
- proof aggregation of many post-quantum signatures;
- post-quantum validator checkpoint/finality signatures.

The mainnet security claim depends on results and audits. A chain is not fully post-quantum merely because account recovery uses a post-quantum key; consensus signatures, commitments, bridges, and proof systems also matter.

## 10. Ethereum and Solana bridges

The bridge is bidirectional.

### 10.1 WEBC to external chains

1. Native WEBC is locked in a WEBC bridge vault.
2. A verified bridge message is delivered to Ethereum or Solana.
3. Wrapped WEBC is minted on the destination chain.
4. To return, wrapped WEBC is burned.
5. A verified burn message releases native WEBC.

### 10.2 External assets to WEBC

1. A supported Ethereum or Solana asset is locked on its origin chain.
2. A verified message mints a corresponding representation on WEBC.
3. The WEBC representation is burned to exit.
4. A verified message releases the origin-chain asset.

Ethereum contracts use Solidity. Solana bridge programs use Rust. WEBC stores origin chain, origin contract/mint, decimals, token standard, message nonce, source transaction, recipient, amount, and replay status.

The generic architecture targets Ethereum standard tokens and Solana Token/Token-2022 assets. Non-standard, taxed, rebasing, pausable, malicious, or upgradeable assets require explicit risk handling. No bridge can safely promise unconditional support for every possible token contract.

### 10.3 Production bridge safety

Early bridges use valueless mock assets. Real funds require:

- source-chain proof or audited quorum verification;
- domain-separated messages and replay protection;
- per-asset and global rate limits;
- emergency pause with transparent control and exit design;
- independent audits and continuous monitoring;
- incident-response and upgrade procedures;
- long testnet operation and adversarial exercises.

The long-term goal is light-client or ZK verification rather than permanent reliance on a small guardian set.

## 11. Wallet privacy and policy trees

WEBC will research Taproot-inspired account policy commitments: a wallet commits to several spending/recovery paths and reveals only the path used.

Account-based stealth addresses are possible using viewing keys and announcement events, but Bitcoin Silent Payments cannot be copied directly. A WEBC scheme must address browser scanning, spam, recovery, and post-quantum key agreement before mainnet activation.

## 12. Governance and upgrades

Mainnet has no permanent founder master key.

Core upgrades follow a public process:

1. publish a WEBC Improvement Proposal (WIP);
2. discuss security, economics, and compatibility publicly;
3. implement behind a disabled feature/version;
4. test on local networks, devnet, and testnet;
5. publish audits and activation parameters;
6. activate only after broad client, validator, node, and community adoption.

On-chain votes may signal support but do not automatically make unsafe code valid. Nodes always reject blocks that violate the protocol version they run.

## 13. Mainnet readiness

WEBC is not mainnet-ready until it has, at minimum:

- multiple-node networking and peer protection;
- durable transactional storage and state sync;
- signed BFT consensus and finality certificates;
- complete economic and slashing invariants;
- audited wallet and key management;
- measured parallel execution and localized fees;
- tested light-client/ZK proof verification;
- safe contract runtime selection and audits;
- production bridge design and separate bridge audits;
- public distribution specification;
- long-running public devnet/testnet and adversarial testing;
- monitoring, upgrade, and incident-response processes.

## 14. References and inspirations

- Solana program execution and writable-account scheduling: <https://solana.com/docs/core/programs/program-execution>
- Sui object and Move model: <https://docs.sui.io/doc/sui.pdf>
- Mina succinct blockchain documentation: <https://docs.minaprotocol.com/>
- Ethereum governance: <https://ethereum.org/governance/>
- Ethereum post-quantum roadmap: <https://ethereum.org/roadmap/future-proofing/quantum-resistance/>
- NIST ML-DSA standard: <https://csrc.nist.gov/pubs/fips/204/final>
- Bitcoin Taproot: <https://bips.dev/341/>
- Bitcoin Silent Payments: <https://bips.dev/352/>
- Ethereum stealth addresses: <https://eips.ethereum.org/EIPS/eip-5564>

These projects are references, not codebases or protocols WEBC promises to copy wholesale.
