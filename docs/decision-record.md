# WEBC confirmed decisions and technical gates

Last updated: 2026-07-15

This file is the authoritative short record of decisions made with the project owner. If an older document or the current prototype code conflicts with this file, this file wins until the conflict is deliberately resolved in code and tests.

## Product identity

- Chain: independent custom Layer-1 blockchain.
- Project: `WEBC`.
- Native coin: `WEB COIN`.
- Ticker: `WEBC`.
- Audience: global, not country-specific.
- Core implementation language: Rust.
- Primary use: browser- and website-native wallets, payments, tokens, applications, staking, and cross-chain assets.
- A website may embed WEBC features, but wallet secrets must remain isolated from the host website.
- Non-negotiable qualities across the protocol: fast, stable, secure, decentralized, and low-fee. Usability and ease-of-integration improvements must never be bought by weakening these.
- WEBC is designed for the AI development era: humans, human-with-AI, and AI-only workflows are all first-class for building on and using the chain.

## Native coin and distribution

- Genesis supply: `10,000,000 WEBC`.
- Native precision: 12 decimal places.
- One base unit: `0.000000000001 WEBC`.
- Suggested internal amount type: unsigned 128-bit integer.
- No fixed developer, founder, foundation, investor, or private-sale allocation.
- No mandatory protocol fee paid to the founder or development team.
- Voluntary donations may be supported through ordinary addresses, payment links, widgets, recurring-payment contracts, and optional validator/site reward splits.

### Genesis distribution

- 30% (`3,000,000 WEBC`): contributors who participate after a formally announced public devnet/testnet contribution program begins.
- 70% (`7,000,000 WEBC`): broad global public distribution.
- Activity before the public contribution program begins earns no mainnet allocation.
- Devnet/testnet balances never convert directly into mainnet WEBC.
- Contribution rewards must measure useful, verifiable work rather than raw account count, node count, uptime alone, or blocks produced alone.
- Duplicate-account resistance cannot be perfect without identity checks. The distribution design must use multiple contribution signals, diminishing returns, public rules, public calculations, and an appeal/audit process.
- The exact claim process, public-distribution routes, eligibility evidence, claim window, and treatment of unclaimed funds require a separate public distribution specification before mainnet.

## Monetary policy

- Initial annual inflation rate: 10%.
- Each year the inflation rate is multiplied by 80%, which is a 20% relative reduction.
- Long-term minimum annual inflation rate: 1%.
- Rewards accrue smoothly by epoch/block; they must not jump abruptly once per calendar year.
- Before fee burns, this curve reaches the 1% floor after roughly 11 years.
- Base transaction fees: 50% burned, 50% paid into validator/delegator reward accounting.
- Priority fees: paid to the block producer according to the final fee specification.
- Exact reward timing and epoch math must be deterministic and derived from chain parameters, not local wall-clock reads.

## Consensus and staking

- Consensus direction: permissionless delegated Proof of Stake with BFT-style finality.
- PoH is not part of the WEBC protocol or its safety mechanism.
- Target block interval: 2 seconds.
- Normal finality target: 6-8 seconds.
- Degraded-network finality UX target: no more than about 12 seconds under expected conditions.
- A block requires more than two thirds of the selected stake-weighted voting power to finalize.
- There is no fixed global cap on registered validators.
- A stake-weighted rotating subset may vote for each block so that every validator does not have to send a vote for every block.
- Anyone may run a non-producing verification node without stake.
- Producing/voting validators must stake, including on devnet.
- Devnet provides a faucet for valueless test WEBC.
- A validator pool activates at a minimum of 100 WEBC total active stake.
- At the 100 WEBC activation threshold, the operator must provide at least 20 WEBC directly.
- A validator operator must supply at least 20% of the validator pool's active stake.
- Delegation may supply at most 80%, so delegated stake cannot exceed four times operator self-stake.
- Each participant must delegate at least 1 WEBC per active delegation position.
- Devnet unstaking delay target: about 7 minutes.
- Mainnet unstaking delay target: about 7 days.
- Objective malicious actions receive severe slashing; downtime and operational mistakes receive lost rewards and softer, proportionate penalties.
- Slashing requires verifiable signed evidence. A vague accusation or the label "51% attack" is not evidence.

## Execution and parallelism

- Parallel execution is a core requirement, not an optional optimization.
- The parallel model combines Solana-style declared per-transaction access lists with Sui-style versioned owned objects: unrelated transactions run concurrently and owned-object versions guard against conflicts. The data model (`object.rs`) and the deterministic batch scheduler (`scheduler.rs`) already exist in the prototype; the remaining work is the parallel executor and the public contract runtime on top of them.
- The state model is hybrid:
  - account-style balances for WEBC, ordinary fungible-token balances, staking, delegation, and simple payments;
  - object-style state for NFTs, game items, escrows, orders, application sessions, and contract-owned data.
- Every transaction declares exact read-only and writable state keys.
- Runtime execution must reject and roll back any transaction that accesses undeclared state.
- Transactions whose writable/read sets do not conflict may execute in parallel.
- Each deployed application receives a unique application namespace.
- Application identity must not rely only on a mutable web domain name.
- Site A or token A becoming busy should not raise Site B or token B's localized congestion price when their state does not overlap.
- A small network-wide floor and fair block-capacity rules remain necessary to defend shared bandwidth and block space.
- Hot shared state must be avoidable through sharded/bucketed contract design.
- Ordinary token transfers must touch per-owner balances, not one global token balance object.
- The same wallet should support independent transaction lanes so unrelated activity on multiple sites does not serialize behind one global nonce.

## Fees

- Fee pricing is dynamic and based on computation, signatures, state reads/writes, storage growth, and localized contention.
- WEBC aims for fees slightly more conservative than Solana's very-low fee regime while remaining negligible for normal users.
- No USD-denominated fee guarantee is possible without trusting an external price feed.
- Exact base-unit prices are technical parameters to set through benchmarks and devnet load tests.
- Sites and applications may sponsor user fees through a constrained paymaster-style mechanism.
- Sponsors must be able to set per-user, per-application, per-operation, and daily limits.
- Token/NFT creation, persistent storage, and contract deployment cost more than a simple transfer.
- Priority fees must not allow one application to monopolize unrelated localized execution lanes.
- Sponsorship policies must be bounded, never open-ended: a sponsor sets eligibility (for example authenticated users or users with a site account) and hard caps (for example a per-user daily limit such as one dollar equivalent), and the protocol enforces the cap so a site cannot be drained.
- Reputation- or domain-based automatic fee discounts are deferred. They invite Sybil, gaming, and centralization problems (who decides which domain is "good"). The same goal — cheaper or free usage for a site's users — is met safely through capped, policy-based sponsorship above.

## Browser wallet and website security

- Wallet secrets stay on the user's device.
- Host websites must never receive the seed phrase, raw private key, or decrypted keystore.
- Embedded wallets run in an isolated trusted origin/frame or trusted wallet window, not in the host site's JavaScript context.
- The wallet displays the requesting site origin, action, recipient, amount, token, contract, and maximum fee before signing.
- Permissions are granted per site and can be revoked.
- Recovery supports standard mnemonic phrases, encrypted keystore files, and explicit private-key export with strong warnings.
- Do not invent custom cryptographic primitives.
- Use audited implementations and established standards for randomness, mnemonic handling, key derivation, authenticated encryption, and signing.
- Automatic cross-site wallet sharing is reserved for a future extension/native wallet; without it, users may import/recover the same wallet deliberately.
- Passkeys/hardware-backed approval may protect wallet unlocking and high-risk actions, but must not silently replace portable recovery.

## Post-quantum readiness

- Quantum readiness is a genesis design requirement.
- Address and account authorization formats are versioned and support multiple signature policies.
- Every standard wallet must include a post-quantum root/recovery policy from creation; no wallet should be permanently locked to only Ed25519.
- NIST ML-DSA is the initial account-signature candidate, subject to implementation audits and performance tests.
- Post-quantum signatures are much larger than Ed25519 signatures, so the implementation must benchmark strict post-quantum signing, limited short-lived session keys, and ZK/STARK-based signature aggregation.
- Critical actions such as recovery, key rotation, staking control, high-value transfer policy changes, and session-key authorization require the post-quantum root policy.
- Mainnet must not claim full post-quantum security unless account signatures, validator consensus signatures, commitments, and the chosen ZK proof system are all covered.
- The proof system should prefer post-quantum-friendly hash/STARK assumptions where practical and must be replaceable through a versioned proof interface.

## ZK and light clients

- The first ZK goal is succinct verification of chain/state correctness, inspired by Mina.
- Private transfers are not an initial requirement, but interfaces should leave room for optional privacy later.
- Browsers should verify a compact finalized checkpoint proof plus Merkle/object proofs for relevant state.
- Proof production may be performed by separate proof workers and must not force ordinary browsers or ordinary validators to own GPUs.
- The protocol must define behavior when the latest ZK proof lags behind the newest finalized block.
- Merkle proofs remain the fallback and first implementation while the ZK backend is evaluated.

## Smart contracts and web integration

- The core node and native protocol modules remain Rust.
- The smart-contract execution foundation is chosen: deterministic, restricted WebAssembly, with Rust as the first authoring language compiled to WASM. This is the safety/speed engine, not the language most developers write by hand.
- Above that foundation WEBC provides its own high-level contract language and framework, designed to be easy and intuitive for humans and AI. It is implemented as a safe authoring layer that lowers (transpiles) to the audited Rust framework and its components; it does not add a second from-scratch VM or a hand-written compiler backend, so it inherits Rust/WASM safety, determinism, and performance. WEBC builds the language front end (parser + lowering), and reuses the Rust/LLVM toolchain for the hard optimization/codegen work.
- The earlier caution against "inventing a new language" refers to a new low-level VM or an independent compiler backend, which WEBC does not build. A high-level authoring language that lowers to the audited Rust layer is explicitly wanted.
- Move VM and EVM/Solidity are not the native WEBC runtime. Ethereum/Solana compatibility is delivered through bridges (see the bridge section), not by executing their bytecode natively.
- AI-native development is a design goal: the language, framework, and documentation are machine-readable and composable so an AI agent can read a component catalog and assemble a contract from documented, audited building blocks. The same catalog serves human-only and human-with-AI developers.
- Contract quality is protected by tooling, not left to developer discipline. To keep contracts from becoming unmaintainable "spaghetti"/"god contracts": an opinionated, uniform contract structure; small composable components instead of monoliths; a dedicated contract linter/analyzer (a WEBC clippy) that flags long functions, missing access declarations, and unsafe patterns; and a pre-deploy review step (including automated/AI review) run before deployment.
- TypeScript is the primary website SDK language, with generated clients from contract interface descriptions.
- Contracts cannot access the internet, local files, wall-clock time, or random device state directly.
- External data reaches contracts through a native WEBC oracle rather than direct network calls, so every node still computes the same result:
  - oracle reporters stake WEBC, submit data as ordinary signed transactions, and reported values are aggregated (for example by median) so a single reporter cannot forge the answer;
  - provably wrong or conflicting oracle reports are slashable, reusing the existing staking and slashing infrastructure, which makes the native oracle cheap (no external chain), fast (WEBC block speed), and hard to manipulate;
  - the native oracle is the default path; external oracle integration remains possible but is not required.
- File upload/download, button actions, webhooks, headless services, and external APIs use a split design:
  - on-chain contract records payment, authorization, hashes, and events;
  - browser/server agents perform the external action and may return signed receipts.
- File bytes normally remain off-chain; WEBC stores content hashes, permissions, payment state, and optional encrypted-key release conditions.
- Required application capability includes swaps, conditional payments, sponsored fees, simple and web games, token policies, governance, NFT issuance, and website membership/access rules.
- Web-native application patterns are first-class targets: in-page payments; easy peer-to-peer WEBC exchange during a conversation; real-time wallet creation and server-managed tokens inside web games (including plain HTML games); AI web agents that pay and get paid in WEBC while browsing; optional reward-for-attention (ad) flows; and site-level fee surcharge or revenue-share, implemented at the application layer so the protocol stays simple.
- A dedicated WEBC module should let non-web applications integrate the same way a website does, so WEBC is optimized for the web and internet generally, not confined to websites.

## Native tokens, NFTs, and governance

- Anyone may create a WEBC-native fungible token by paying WEBC fees.
- Token configuration may include name, symbol, decimals, initial/max supply, additional minting, burning, transfer rules, per-account freeze, global pause, authority transfer, and authority revocation.
- Wallets must display restrictions and issuer authority prominently.
- WEBC-native NFTs are supported; external NFT bridging comes after fungible-token bridging.
- Tokens/applications may create their own governance instances for a fee.
- Governance configuration may include proposal thresholds, quorum, voting period, timelock, delegation, token-weighted votes, stake-weighted votes, or membership-NFT votes.
- Core WEBC protocol governance follows an Ethereum-inspired public improvement-proposal and client-adoption process, not automatic rule by the richest coin holders.
- Mainnet has no permanent founder master key.

## Ethereum and Solana bridge

- The bridge is bidirectional.
- Delivery priority: (1) native ETH and SOL first, ideally in parallel, otherwise Ethereum first then Solana; (2) their standard sub-tokens (Ethereum ERC-20, Solana Token/Token-2022) and cross-chain messaging so contracts on different chains can communicate, not only move assets; (3) additional chains such as Bitcoin and Tron later. Bitcoin/Tron are explicitly deferred because they carry higher trust complexity (Bitcoin has no native contracts, forcing federation/multisig assumptions).
- Native WEBC can be locked on WEBC and minted as wrapped WEBC on Ethereum or Solana.
- Wrapped WEBC can be burned on Ethereum or Solana and native WEBC released on WEBC.
- Supported Ethereum/Solana assets can be locked on their origin chain and represented on WEBC.
- Their WEBC representations can be burned and the origin-chain assets released.
- The bridge architecture should be generic for standard Ethereum tokens and Solana Token/Token-2022 assets, with metadata and decimal normalization.
- "All tokens" cannot mean every malicious or non-standard token is automatically safe. Risk metadata, standard checks, per-asset pause, and limits are required.
- Ethereum-side bridge contracts are written/audited in Solidity; Solana-side programs are written/audited in Rust.
- Prototype stages use valueless mock assets and explicitly trusted test relayers/guardians.
- Real-fund activation requires replay protection, domain separation, rate limits, per-asset caps, emergency pause, independent audits, monitoring, incident response, and an approved trust/proof model.
- Long-term preference: origin-chain light-client or ZK verification rather than permanent trust in a small guardian group.

## Privacy-inspired account features

- Taproot-inspired policy trees are desirable for smart accounts: reveal only the spending/recovery branch actually used.
- Account-based stealth addresses are technically possible and should be researched using scheme-versioned announcements and viewing keys.
- Bitcoin Silent Payments cannot be copied directly because it relies on Bitcoin UTXO inputs and quantum-vulnerable elliptic-curve key agreement.
- A mainnet stealth-address scheme must be evaluated for browser scanning cost, spam resistance, recovery, and post-quantum compatibility.

## Explicitly not decided yet

These are technical gates, not questions the project owner must answer now:

- exact epoch duration;
- exact block unit/byte limits at each devnet stage;
- exact initial fee-per-unit constants;
- validator committee size and selection algorithm;
- the WEBC high-level authoring language's exact surface syntax and name (the Rust->WASM execution foundation and the decision to provide a high-level language that lowers to the audited Rust layer are settled; only the language's look-and-feel and naming remain open, to be chosen when the language is designed);
- exact native-oracle economic parameters (reporter stake size, aggregation window, slash severity);
- final ZK/STARK backend;
- strict post-quantum-per-transaction versus post-quantum-root plus limited session-key policy;
- production bridge verification/trust implementation;
- precise anti-duplicate-account public distribution mechanism.

Each must be resolved by specifications, prototypes, benchmarks, threat models, tests, and audits before the relevant mainnet feature is enabled.
