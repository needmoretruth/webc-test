# WEBC architecture

## Overview

WEBC is an independent Rust Layer 1 optimized for browser use, website applications, deterministic parallel execution, and lightweight verification.

## State model

WEBC uses one versioned state-key system with two easy-to-use views:

- account-style balances for native WEBC and ordinary fungible tokens;
- object-style state for NFTs, games, application data, and shared resources.

Every transaction declares which state keys it will read and which it may change. Execution must reject undeclared access. Transactions with no conflicting writable keys may run in parallel, but their final result must be identical to a deterministic serial order.

Application namespaces isolate unrelated sites. Common transfers must not write one global token object. Hot shared state should be divided into safe buckets when its rules allow it. Wallets use independent authorization/nonce lanes so several sites can transact concurrently.

Non-default authorization lanes hold an independent replay nonce and a bounded
prepaid fee balance. Opening or funding a lane is authorized by the default
account lane and moves native value into a supply-accounted lane bucket. After
that, unrelated site operations can pay fees and advance nonce state without
writing the shared account record. Lane IDs are public origin-policy
identifiers, not secrets or replacements for signature verification.

The Phase 2 wallet service derives one recoverable lane per site from a
domain-separated wallet signature over the browser-authenticated HTTPS origin.
The host cannot propose another lane through the supported transfer API. This
derivation is off-chain wallet policy; consensus continues to treat the 32-byte
lane as opaque and requires that it be opened/funded before use.

Persistent application objects use a fixed 32-byte `ObjectId`, application
namespace, explicit owner, and monotonically increasing version. Native create,
mutate, and transfer operations require exact object and namespace access keys;
mutation and transfer also require the signed expected version and current
address ownership. Payloads are capped at 64 KiB. Large files stay off-chain.
Shared ownership is represented but mutation remains disabled until a public
runtime supplies a separately reviewed authorization rule.

## Consensus

The target is permissionless delegated Proof of Stake with BFT-style finality:

- target block interval: 2 seconds;
- normal finality target: 6-8 seconds;
- degraded user-experience target: roughly 12 seconds;
- stake is required to produce or vote on blocks;
- anyone may run a non-producing verification node;
- PoH is not used.

Committee size, epoch length, message timeouts, and block limits are technical values to choose through simulations, fault tests, and public testnet measurements.

**Two structural gaps to resolve before they get expensive (2026-07-16 review):**
- *Committee sampling is unbuilt.* The confirmed design has a rotating
  stake-weighted sub-committee vote per block (so not every validator votes) with
  no global validator cap. The current finality certificate requires >2/3 of the
  **whole** active validator-set snapshot — a correct first step, but O(N) votes /
  O(N²) gossip that cannot meet "not everyone votes" or scale. Sub-committee
  sampling needs its own ADR and a security argument (the sampled committee must
  itself hold an honest super-majority with high probability), and the finality
  path should be committee-parameterized so the later change is not a rewrite.
- *Historical state.* `ChainStore` keeps latest-only state. The Mina-style light
  client and account/object proofs, and later ZK checkpoints, need historical state
  commitments. Decide the archival / snapshot / state-delta strategy in a storage
  ADR before the proofs phase; retrofitting it after a frozen mainnet schema is
  costly. See `docs/review/2026-07-16-plan-review.md` §4.

Stake changes are snapshotted at epoch boundaries. Delegation exits pass through
versioned pending, queued, cooling, and withdrawable states plus a global bounded
FIFO churn queue. A pool that would fail the next 100 WEBC / 20 WEBC / 20% rules
drains out of the next snapshot; it never disappears during the current voting
snapshot. Details and failure behavior are fixed in
[`ADR-0008`](adr/0008-stake-lifecycle-and-exit-queue.md).

## Deterministic execution

A block is accepted only if every transaction and protocol operation is valid. Whole-block application is atomic: failure must leave the prior committed state unchanged. Supply, stake, fees, nonces, object versions, and state roots are consensus data.

The scheduler may execute independent work concurrently, but consensus commits one deterministic result. Load claims such as thousands of transactions per second require sustained public benchmarks on stated hardware.

## Smart-contract path

Security-critical operations begin as audited Rust native modules. The contract execution foundation is restricted, deterministic WASM with Rust as the first authoring language. Above it, WEBC provides its own high-level authoring language that lowers (transpiles) to an audited Rust framework, inheriting Rust/WASM safety and performance without a second VM or a hand-written compiler backend. Move VM and EVM are not the native runtime; Ethereum/Solana compatibility comes through bridges. A contract linter/analyzer and a pre-deploy review keep contracts small and maintainable.

**Compilation-boundary invariant (permanent).** The chain accepts and stores only
deterministic WASM bytecode plus metadata. All compilation — WEBC high-level
source → Rust framework → WASM — happens **off-chain and untrusted** (developer
machine or SDK, reusing the Rust/LLVM toolchain). On-chain validation is limited to
WASM validation, gas metering, and access-list enforcement. A source-language or
Rust compiler must never run inside block execution: doing so would destroy
determinism and create an enormous attack surface. The high-level language is an
off-chain authoring/SDK layer, not an on-chain interpreter.

Contracts cannot access websites, files, device randomness, or wall-clock time directly. They communicate with browser or server agents through events and signed receipts, and read external data through a native staked oracle (reporters stake, values are aggregated, wrong reports are slashed) so every node computes the same result.

## Proofs and browser clients

The first light client verifies headers, validator certificates, and Merkle/state proofs. A Mina-inspired ZK layer may later compress long verification history and selected state transitions. Proof generation may run on stronger machines; browser verification must stay small and fast.

## Keys

Account authorization is versioned. Each standard wallet starts with a post-quantum root/recovery path, while lighter session keys may be permitted only under strict limits if benchmarks and security analysis support them. Ethereum bridge verification may add secp256k1 without changing native account identity.

## Modules

The intended boundaries are:

```text
crypto and authorization
state and execution
parallel scheduler
fees and economics
staking and consensus
storage and networking
proofs and light clients
contract runtime
browser SDK and wallet
Ethereum/Solana bridges
```

Each boundary should be versioned and replaceable so a proof system, signature system, VM, database, or bridge design can be upgraded without rewriting the whole chain.
