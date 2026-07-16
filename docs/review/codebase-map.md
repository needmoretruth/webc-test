# WEBC codebase map

Last updated: 2026-07-16 (plan-review session, read-only)

Purpose: give a future session a fast, accurate mental model of where things live,
so it does not have to re-scan the tree. This is a navigation aid, not authority —
`docs/decision-record.md` and the code itself win on any disagreement.

Scope note: this map was built by reading the documents in full and **sampling**
the source (crypto boundary, consensus snapshot, state-root construction, wire).
Files marked "sampled" were read in part; files marked "not read" were only
located, not audited. See `docs/review/findings.md` for review coverage limits.

## Workspace layout

Rust workspace (`Cargo.toml`), 5 crates, plus a pnpm workspace for the SDK.

```
crates/
  webc-crypto/   pure crypto primitives (no chain logic)
  webc-chain/    the deterministic protocol core (the heart)
  webc-storage/  KvStore seam + redb backend + ChainStore
  webc-net/      async P2P transport seam (tokio)
  webc-node/     the runnable node: mempool, service, HTTP, consensus driver, CLI
sdk/
  webc-js/       TypeScript browser SDK (wallet, keystore, node client, demo)
  webc-widget/   framework-free host-embed widget
docs/            all design docs (see docs/index.md for authority order)
```

Dependency direction (must stay one-way): `webc-crypto` <- `webc-chain` <-
`webc-storage`/`webc-net` <- `webc-node`. Pure crates (`crypto`, `chain`,
`storage`) are synchronous and deterministic; async lives only in `net` and
`node`.

## webc-crypto (762 LoC) — reviewed

- `signature.rs` — Ed25519 wrappers (`Keypair`, `PublicKeyBytes`,
  `SignatureBytes`, `verify_signature`). Secret keys are non-`Serialize`. Human-
  readable serde = hex, binary serde = raw bytes.
- `mldsa.rs` — the single replaceable ML-DSA-65 (FIPS 204) seam over `fips204`.
  `ml_dsa65_verify` is total/deterministic (fails closed, no panics); secret key
  is non-`Debug`/`Serialize`/`Clone`. Used ONLY for the post-quantum recovery
  root on rare critical actions, never per ordinary transaction.
- `hash.rs` — `Hash256` (SHA-256), `digest`, `digest_many`, `ZERO`.
- `address.rs` — `Address::from_public_key`, bs58 `webc...` display.
- `merkle.rs` — binary Merkle root/proof, domain `WEBC_MERKLE_V1`, empty tree =
  `Hash256::ZERO`, odd layers duplicate last. (Duplicate-last is a known
  second-preimage foot-gun class; see findings.)

## webc-chain (~15k LoC) — the protocol core; partially sampled

Central file is `state.rs` (6903 LoC) — `ChainState` and every state
transition. Key facts verified:
- All state maps are `BTreeMap`/`BTreeSet` (deterministic iteration) — good.
- `state_root()` (line 952) hashes a `WEBC_STATE_COMMITMENT_V6` struct of
  sub-roots via **canonical JSON** (not bincode). Sub-roots built by
  `ordered_value_root`/`ordered_set_root` + `leaf_hash` (domain-separated,
  canonical JSON leaves).
- Restart round-trip tests use bincode (tuple-keyed maps can't be JSON objects);
  bincode is NOT in the consensus hashing path.

Other modules (located; most not fully audited):
- `amount.rs` — `Amount` (u128 base units, 12 decimals). Checked arithmetic.
- `account.rs`, `transaction.rs` (1226) — accounts, `Operation` enum, tx wire
  V3 (`WEBC_SIGNED_TRANSACTION_V3`, binds protocol version + chain id).
- `authorization.rs`, `authorization_policy.rs` (542) — versioned auth policy,
  post-quantum root, active-key rotation, root rotation.
- `session_key.rs` (422) — constrained session keys (budgets, lane, epoch expiry).
- `staking.rs`, `unbonding.rs` (609) — validator/delegation, ADR-0008 exit queue.
- `slashing.rs` (272) — `SlashingEvidence::DoubleVote` verify + apply.
- `consensus.rs` (1079) — `ValidatorSet` snapshot (carries per-member consensus
  key), `proposer_for` (stake-weighted, hash of height+round), `SignedProposal`,
  `FinalityCertificate`, quorum math (`has_two_thirds_power`, strictly >2/3).
  **NOTE: the "committee" is the WHOLE active validator set (line 100); rotating
  sub-committee sampling is unbuilt.** See findings / plan-review.
- `round.rs` (1614) — `ConsensusMachine`, multi-round Tendermint
  (arXiv:1807.04938 Alg.1): locking, valid_round proof-of-lock, 3 timeouts,
  f+1 catch-up, nil = all-zero sentinel hash, equivocation detection.
- `block.rs`, `block_builder.rs` (593), `genesis.rs`, `inflation.rs`, `fees.rs`,
  `object.rs`, `scheduler.rs` (deterministic access-list batcher), `state_key.rs`
  (versioned `StateKey`), `protocol.rs`, `canonical.rs` (cross-language JSON),
  `bridge.rs` (169, mock trusted-relayer escrow), `hex_bytes.rs`.

## webc-storage (~1.5k LoC)

- `kv.rs` — `KvStore` trait (atomic `WriteBatch`, `Table` namespaces,
  `StorageError::Corruption` as a reported outcome, never a panic).
- `memory.rs` — in-memory backend (tests). `redb_store.rs` — durable redb
  (MIT OR Apache-2.0) backend, one commit = one redb txn.
- `chainstore.rs` (659) — typed block/state/tip/certificate persistence, atomic
  per-block commit, startup consistency checks. **Latest-only state retention**
  (no historical state) — a known architectural limit (see plan-review).

## webc-net (~1.4k LoC)

- `wire.rs` (343) — `NetMessage` (Transaction / Proposal / Vote / Certificate /
  BlockRequest / BlockResponse), self-describing envelope, magic + wire version.
- `codec.rs` — shared bincode config (fixint) for stable magic/version offsets.
- `handshake.rs` (244) — mutual Ed25519 challenge/response, binds chain id + wire
  version, `PeerId` distinct from account/consensus keys. **Plaintext framing;
  channel encryption deliberately deferred** (gossip is public + signed).
- `transport.rs` (611) — authenticated TCP dial/listen behind `NetworkHandle`
  (actor pattern), static bootstrap peers, flood gossip with bounded FIFO
  seen-cache.

## webc-node (~3.6k LoC) — the runnable node

- `node.rs` (601) — restartable single-proposer `Node`: genesis/recover,
  `build_block`, `build_candidate`, `import_block`, `import_finalized_block`,
  `certified_block`.
- `mempool.rs` (734) — admission, replacement-by-fee, TTL, fee-priority
  nonce-contiguous selection under a unit budget. Reads no clock.
- `service.rs` (629) — transport-independent `NodeService` (health, fees,
  account+proof, object, blocks, submit, seal, devnet faucet).
- `http.rs` (551) — axum/tokio (MIT) HTTP+WS under `/v1`, body limit, block sub.
- `consensus_driver.rs` (516) — async `ConsensusDriver`: one `ConsensusMachine`
  per height over real TCP, tokio timers, mempool-fed proposals, commit +
  advance, state sync. **Does NOT yet apply consensus-detected equivocation
  slashes.**
- `gossip.rs`, `main.rs` (467, the `run`/`demo`/`bench` CLI).
- `tests/consensus_convergence.rs` (593) — loopback 3-validator convergence,
  gossiped-transfer inclusion, late-joiner state sync.

## SDK (sdk/webc-js/src, TypeScript) — partially sampled

- `wallet.ts`, `wallet-derivation.ts` — BIP-39 (24-word) + SLIP-0010 Ed25519,
  non-extractable WebCrypto handle in a module-private WeakMap.
- `keystore.ts` (650) — AES-256-GCM under Argon2id (19 MiB/t=2/p=1) v1 envelope.
- `permission-store.ts` (816) — encrypted per-origin grant store, identity-bound
  AAD, key-caching save port.
- `wallet-service.ts`/`-request.ts`/`-client.ts`/`-confirmation-ui.ts` — the
  isolated trusted-popup postMessage host boundary.
- `transaction.ts` (900) — canonical signing (must byte-match Rust `canonical.rs`),
  operation constructors, `deriveSessionKeyIdHex`.
- `session-key.ts`, `node-client.ts` (433, typed `/v1` HTTP/WS client), `types.ts`.
- `demo/index.html` — static reference site (wallet -> faucet -> proof -> transfer
  -> live finality).

## Validation gates (run before pushing code changes)

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
cargo run -p webc-node -- demo
# SDK:
pnpm install --frozen-lockfile && pnpm check   # build + test + doc-link check
```

Last green (per docs, 2026-07-15): Rust 192 tests; SDK 69/69 + widget 3/3.
This review session did NOT re-run the gates (docs-only, read-only).
