# WEBC implementation status

Last documentation audit: 2026-07-13

## Summary

The repository contains useful prototype pieces, but it does not yet implement the confirmed WEBC protocol. It must not be used with real funds or described as a working devnet.

The original audit was based on source inspection because Rust was unavailable
at that time. The Phase 0 section below records newer verification work; any
test result not repeated there remains historical evidence only.

The durable resume point is `docs/continuation-guide.md`. A fresh session must
also inspect `git status` and `git log` so documentation-only commits or preserved
user changes after the latest implementation checkpoint are not overlooked.

## Phase 0 baseline completed

The repository baseline has been repaired against the authoritative plan.
Completed and locally verified items are:

- recovered the damaged Git metadata without overwriting the working tree and
  retained a sibling backup of the original `.git` directory;
- pinned Rust `1.96.0`, Node.js `24.18.0`, and pnpm `11.7.0` in repository
  configuration;
- added workspace lint policy that forbids `unsafe` and denies compiler
  warnings in protocol crates;
- added Windows/Linux Rust CI plus TypeScript and local-document-link CI;
- restored the browser SDK public entry point and pnpm workspace/lock file;
- added initial TypeScript regression tests and passed both package builds,
  three tests, and the local Markdown-link check;
- added the source documentation template and technical ADRs for state,
  consensus, fees, wallet authorization, proofs, contracts, and bridges;
- added validated `ChainId`, `ProtocolVersion`, `BaseUnits`, `BlockHeight`,
  `Epoch`, `Nonce`, and `ValidatorId` types and committed protocol/chain identity
  into the in-memory state and block header.
- marked halving and bootstrap staking as legacy behavior and removed PoH from
  authoritative block data and hashing.

The Windows host uses the pinned Rust GNU toolchain with a checksum-verified
portable WinLibs GCC installation because MSVC Build Tools were unavailable.
The final Phase 0 gate passed `cargo fmt --check`, strict workspace Clippy,
the complete Rust workspace tests, Rust documentation with warnings denied, the
node demo, both TypeScript builds and tests, and the local Markdown-link check.
Legacy tests still exercise known-invalid prototype behavior; their success is
only a Phase 0 reproducibility result and does not satisfy Phase 1 invariants.

## Phase 1 completed

Completed and verified:

- native WEBC precision is now 12 decimals in Rust and TypeScript, with exact
  decimal-string vectors for one WEBC and the 10,000,000 WEBC genesis supply;
- the legacy halving schedule was replaced by the confirmed 10% initial annual
  rate, exact 0.8 yearly decay, and 1% floor;
- reward-period rounding uses cumulative integer budgets, so a complete year
  distributes exactly the annual issuance budget without floating point or
  wall-clock input;
- the inflation year-start supply is committed in deterministic chain state.
- block construction now executes in a whole-block overlay and commits only
  after every transaction, root, unit limit, and canonical byte limit succeeds;
- regression tests prove rollback after a late invalid transaction and after
  byte/unit limit failures.
- bootstrap registration now fails closed and consensus assigns no synthetic
  voting power to unstaked legacy records;
- validator pools remain pending until reaching 100 WEBC total stake with at
  least 20 WEBC operator stake, delegation is capped at four times operator
  stake, and individual delegations require at least 1 WEBC.
- genesis rejects duplicate accounts, debits operator stake from liquid
  allocations, and fails if its gross native supply does not reconcile;
- `SupplyInvariantReport` accounts for liquid, operator stake, delegation,
  pending rewards, fee rewards, and burned units without double-counting mirror indexes.
- versioned `StateKey` now distinguishes accounts, owner-scoped asset balances,
  validators, delegation positions, payer-scoped fee deltas, bridge/slashing
  replay markers, protocol fields, objects, modules, and application namespaces;
- native transaction execution records logical reads/writes and rejects missing,
  read-only writes, duplicates, overlap, unsupported versions, more than 256
  declared keys, and unused over-declarations before committing its overlay;
- scheduler conflicts now use the same versioned keys, with regression coverage
  proving unrelated application namespaces can share a batch;
- Rust and TypeScript share an executable canonical transfer fixture containing
  the versioned access list and snake-case fee wire fields.
- consensus votes now sign an explicit `WEBC_CONSENSUS_VOTE_V1` payload containing
  protocol version, chain ID, height, round, stage, block hash, and validator;
- double-vote slashing verifies both artifacts with the validator's registered
  consensus key and uses an order-independent replay identity;
- forged signatures, cross-chain reuse, same-block pairs, mismatched vote steps,
  and reversed duplicate submissions fail before any penalty, with a shared
  Rust/TypeScript canonical vote fixture;
- label-only invalid-block, bridge-fraud, downtime, and majority-attack evidence
  variants were removed from the accepted penalty path until objective signed
  verification is separately implemented.
- a verified slash now reduces the operator account, every affected delegation
  position, each delegator account mirror, and validator aggregates atomically;
- per-position basis-point rounding is deterministic and overflow-safe, and all
  removed units enter an explicit `slashed_units` bucket committed by the state
  root and included exactly once in supply reconciliation.

- native bridge escrow is isolated by external domain, committed by the state
  root, and reconciled exactly once in the supply report; wrong-domain and
  over-release paths roll back atomically. This remains a mock trusted-relayer
  flow and is not approval for real funds.

ADR-0008 now fixes the unbonding implementation boundary: epoch snapshots,
per-position lifecycle states, a deterministic FIFO churn queue, graceful pool
draining, a slashable cooldown window, and no Layer-1 instant-liquidity promise.
This is the accepted technical design and its single-node chain-state
integration is complete; durable restart integration remains a Phase 3 task.

Delegator exits now use the queue end to end: monotonic request IDs,
owner/validator binding, FIFO partial admission under a base-unit churn budget,
typed epoch cooldown/evidence boundaries, one-time matured claims, JSON restart
equivalence, account/delegation/validator updates, and state-root/supply
commitments. Exit requests do not change active voting stake until an epoch
boundary. Earned rewards survive full admission, and queued/cooling principal
remains slashable without double-counting destroyed units.
- operator self-stake uses the same typed queue without mixing it with delegation
  accounting; partial exits must preserve 100/20/80 activation rules, and a full
  operator exit is rejected while delegated stake remains.

## Latest full validation

On 2026-07-13, the pinned `1.96.0-x86_64-pc-windows-gnu` Rust toolchain passed
`cargo fmt --check`, strict workspace Clippy, 77 unit tests, documentation with
warnings denied, and the deterministic node demo. Node.js 24.18.0 with pnpm
11.7.0 passed both TypeScript builds, all 40 TypeScript tests, the emitted ESM
package-entry smoke test, and the
repository-local Markdown-link check.

The unqualified Windows Rust default targets MSVC and cannot link on this host
because MSVC Build Tools are not installed. This is not the verified project
path; use the pinned GNU toolchain and checksum-verified WinLibs compiler recorded
in Phase 0.

On 2026-07-14, after adding constrained session keys, the pinned Rust `1.96.0`
GNU toolchain (on Linux for this session) passed `cargo fmt --check`, strict
workspace Clippy, 98 unit tests, documentation with warnings denied, and the node
demo. Both TypeScript packages build. One pre-existing browser end-to-end test
(`wallet-service.test.ts`) fails only on this host's Node 22 because it requires
the verified Node 24 WebCrypto behaviour; it is unrelated to the session-key
change and fails identically without it. The cross-language state-key wire vector
passes on both Rust and TypeScript with its updated digest.

## Phase 2 work in progress

Completed and verified:

- the SDK now generates and validates 24-word English BIP-39 recovery phrases
  through pinned `@scure/bip39` 2.2.0;
- devnet child keys use pinned `micro-key-producer` 0.9.0 hardened SLIP-0010 at
  the versioned all-chain testnet path `m/44'/1'/account'/0'/index'` while a
  WEBC mainnet SLIP-44 assignment remains unavailable;
- reviewed noble Ed25519 computes the public key before importing the raw seed
  into a non-extractable WebCrypto handle;
- public `WebcWallet` objects no longer expose that signing handle; a private
  weak map binds it to the trusted SDK instance, and mutable derivation buffers
  are cleared after use where JavaScript permits;
- bounded invalid phrase, checksum, passphrase, and child-index inputs fail with
  typed errors that do not echo secret contents;
- a fixed BIP-39/SLIP-0010 vector derives the same public key and WEBC address in
  TypeScript, signs in WebCrypto, and verifies in Rust;
- emitted ESM package imports now include `.js` extensions, and a plain Node
  package-entry smoke test prevents publishing a build that cannot load.
- authenticated encrypted keystore v1 uses pinned noble Argon2id at the fixed
  OWASP 19 MiB/t=2/p=1 profile and WebCrypto AES-256-GCM with fresh salt/IV;
- strict schema/AAD validation binds format, costs, address, public key, and
  derivation path, while malformed cost fields fail before KDF allocation and
  wrong-password/ciphertext/metadata corruption share one authentication error;
- concurrent KDF jobs are serialized around the library's shared scratch block,
  mutable secret buffers are cleared where possible, and routine unlock returns
  no phrase or private-key handle;
- adversarial tests cover round-trip/restart JSON, randomness, concurrent jobs,
  wrong passwords, ciphertext and public-metadata tampering, hostile KDF costs,
  unknown fields, Unicode/length limits, and strict hexadecimal decoding.
- transaction wire/signing V3 now includes `protocol_version` and `chain_id`
  under `WEBC_SIGNED_TRANSACTION_V3`; Rust execution rejects a valid signature
  made for another chain or unsupported version before mutation, and shared
  Rust/TypeScript fixtures freeze the new bytes, signature, and transaction hash.
- strict wallet message v1 accepts only connect, native-transfer signing, and
  revoke with exact field sets, bounded integer/string inputs, secure browser
  origins, and exact opener/source response routing without wildcard targets;
- wallet-issued session IDs and monotonic sequences complement bounded random
  request-ID replay tracking, while serialized service execution makes
  cumulative principal and fee limits race-free;
- every browser-authenticated origin receives its own wallet-secret-derived
  authorization lane, and the supported service refuses host-selected lanes,
  arbitrary-byte signing, host-authored display text, and unsupported actions;
- the trusted top-level popup UI renders hostile values through `textContent`
  and displays origin, action, recipient, amount, asset, maximum fee, chain, and
  lane before every explicit approval; framed execution is refused;
- the host widget no longer creates or returns an in-process wallet. It opens a
  different-origin trusted popup and returns only public connection data plus a
  client that validates source/origin, signed bytes, and exact requested fields;
- malformed schema/origin/source, replay, stale session, concurrent spend,
  blind-display injection, DOM injection, same-origin widget, and full
  host/service exchange tests pass.

Still incomplete: persistent encrypted permission storage, automatic lane setup,
versioned on-chain authorization policy, recovery/rotation/revocation, session
constraints, and the ML-DSA prototype.

Constrained on-chain session keys are now implemented for the single-node state
machine, following `docs/session-keys-implementation-plan.md`:

- `webc-chain::session_key` defines `SessionKeyId` (domain-separated derivation),
  `SessionKeyConstraints` (bound lane, allowed operations, per-use and cumulative
  amount and fee budgets, relative lifetime), the `SessionKey` record, and
  `SessionKeyConfig` (max lifetime epochs, max keys per account);
- `PostQuantumRoot` gained a domain-separated `commit`/`from_public_key`, and a
  new `PostQuantumRootReveal` proves knowledge of the committed root before a
  critical action. This is a commitment reveal, not yet an ML-DSA signature;
- `StateKeyKind::SessionKey`, a `session_key_root` in the state commitment (bumped
  to `WEBC_STATE_COMMITMENT_V6`), and `ChainState.session_keys` store and commit
  the records; the Rust/TypeScript state-key wire vector was updated together;
- `Operation::InstallSessionKey`/`RevokeSessionKey` are critical actions gated to
  the default lane, an installed policy, and a matching post-quantum-root reveal;
- `verify_transaction_authorization` accepts a registered, policy-current,
  lane-bound session key in place of the active key, and execution enforces
  expiry (by epoch, never wall-clock), the transfers-only allow-list, per-use and
  cumulative amount, and per-use and cumulative fee before the operation runs,
  advancing the session's spend atomically;
- session keys hold no funds, so supply reconciliation is unchanged; a rotation
  (policy-revision change) invalidates outstanding keys; revocation is immediate.

Twenty Rust tests cover the lifecycle, per-use/budget/fee caps, the cumulative
fee budget bounding a compromised key, expiry boundaries, disallowed operations,
lane binding and non-default-lane transfers, revision invalidation, fail-closed
install/revoke paths, the per-account cap, serialization restart, and a
randomized spend-sequence property test. An adversarial review of the diff
raised two medium findings (unbounded fee drain; non-default-lane transfers
failing their access-list check) — both were fixed and covered by new tests.

Still incomplete for this gate: the ML-DSA root-*signature* gate (reveal is
commitment-only today), optional epoch-boundary expiry pruning, benchmarks, and
the browser/SDK session-key surface (subkey generation, install/session signing,
expiry display, cross-language operation fixtures).

## Reusable prototype pieces

### `webc-crypto`

The crypto crate contains foundations for hashes, Ed25519 signatures, addresses, and Merkle-style proofs. These ideas are reusable after their formats, domain separation, dependencies, and error handling are reviewed against the new versioned authorization design.

### `webc-chain`

The chain crate contains prototype types and logic for:

- accounts, amounts, transactions, and blocks;
- fees and reward accounting;
- staking, delegation, validators, and slashing records;
- bridge messages, events, replay tracking, and trusted-relayer checks;
- state roots and account proofs;
- access-list scheduling experiments;
- consensus-related primitives.

These are starting points, not finished protocol modules.

### `webc-node`

The node crate contains a command-line demonstration. It is not yet a persistent network node, validator, or browser-facing devnet service.

### Browser packages

`sdk/webc-js` and `sdk/webc-widget` remain security-incomplete browser prototypes.
The package entry points build, and shared Rust/TypeScript fixtures now cover the
PoH-free block header, all native operation variants, every V1 state-key variant,
bridge/evidence replay hashes, and a complete Rust-signed transaction. Wallet
isolation, standard recovery/keystore behavior, and authorization policy remain.

## Confirmed-code mismatches

### Amounts and economics

- Native amounts now use the confirmed 12 decimals and exact string serialization.
- Inflation now follows the confirmed annual decay curve and 1% floor.
- Genesis and transition-level native supply accounting reconcile liquid,
  operator/delegated/unbonding stake, domain-isolated bridge escrow, pending
  rewards, fees, burns, and slashes without double counting.
- Fee and reward constants have not been selected from load tests.

### Consensus and staking

- The new registration and validator-set paths reject zero-collateral bootstrap
  power; legacy wire/state fields remain temporarily for explicit rejection and migration.
- Delegator and operator unbonding are delayed, churn-bounded, reward-preserving,
  and slashable; persisted-node integration awaits the storage phase.
- The authoritative V2 block header contains no PoH field. Rust rejects the
  removed legacy field, and a shared Rust/TypeScript fixture proves the same
  domain-separated block hash.
- There is no complete networked BFT consensus, validator set transition, finality certificate pipeline, or restart recovery.
- Signed vote payloads and objective double-vote verification now exist, but
  quorum callers do not yet enforce committee membership.
- Verified penalties reconcile operator/delegator mirrors and an explicit
  slashed-value bucket. A 64-case property test generates up to 127 arbitrary
  delegate/reward/slash/exit/claim steps per case and checks every accounting
  mirror, supply conservation, active-pool thresholds, and failed-call rollback
  after each step. This complements rather than replaces later fuzzing and
  persisted-node restart tests.

### Execution and parallelism

- Whole-block rollback and configured byte/unit limits are now enforced during
  local block construction; network block validation remains future work.
- Native operations now enforce versioned declared logical access at runtime and
  roll back undeclared or inexact access; public contract execution does not yet exist.
- Non-default authorization lanes have independent typed IDs, checked nonces,
  prepaid supply-accounted fee balances, exact access keys, V3 signing fields,
  and same-wallet parallel scheduling tests.
- Persistent owned objects have typed IDs/versions, namespace and owner checks,
  a 64 KiB payload bound, state-root commitments, exact runtime access, stale
  version/owner/size rollback tests, and cross-lane namespace parallelism.
  Shared-object mutation and localized fee markets remain disabled.
- Objective signed double-vote evidence is enforced; other penalty classes remain
  disabled until equally objective artifacts exist.

### Wallet and wire format

- Rust/TypeScript wire naming is snake_case and executable shared hashes cover
  every native operation and V1 state key. The SDK verifies and hashes a full
  Rust-signed transaction byte-for-byte.
- Recovery words, encrypted export, isolated transfer signing, and origin display
  are implemented foundations. Post-quantum root authorization, durable
  permissions, broader operation confirmations, and session restrictions remain.

### Contracts, proofs, and tokens

- There is no selected or production-ready public smart-contract runtime.
- Native token/NFT and per-application governance features do not yet meet the confirmed scope.
- Merkle proof experiments exist, but Mina-inspired recursive/succinct chain verification is not implemented.
- Post-quantum account, validator, and bridge authorization is not implemented.

### Bridges

- Current bridge code is a trusted-relayer message prototype only.
- Native WEBC lock/release now moves through Ethereum/Solana-specific escrow
  buckets committed by the state root and supply report. Cross-domain,
  over-release, zero-value, native-mint, replay, and unauthorized paths fail
  atomically; external representation minting does not alter native supply.
- Ethereum Solidity contracts and Solana Rust programs are not complete.
- Native WEBC lock/mint and burn/release flows are not end-to-end tested across either chain.
- External token round trips are not end-to-end tested.
- Production finality proofs, asset adapters, rate limits, monitoring, pause/recovery operations, and audits are absent.

## Correct next milestone

Begin Phase 2 in `docs/development-plan.md`. The final Phase 1 audit completed
explicit staking/unbonding lifecycle states, current-epoch voting-power
stability, configurable seven-day cooldown targets, bounded object decoding,
checked validator/reward/quorum/base-fee arithmetic, and fail-closed rejection
of floating-point canonical signing input.

Phase 2's schema, shared-vector, snake-case wire, SDK-entry-point, independent
nonce-lane, standard mnemonic/Ed25519 derivation, authenticated encrypted
keystore, and isolated trusted-popup request/confirmation foundations now exist.
The versioned on-chain account authorization policy and its constrained
session-key portion are now implemented (see the Phase 2 section above and
`docs/session-keys-implementation-plan.md`). Recovery, rotation, and revocation
of the primary key, plus the ML-DSA root-signature gate and the browser/SDK
session-key surface, remain. `docs/continuation-guide.md` holds the exact
remaining sequence.

RPC and networking remain Phase 3/4 work. Public contract VM, ZK expansion, and
real-fund bridge work remain disabled until their later gates.

## Documentation completed in this pass

- Added the authoritative decision record.
- Added the whitepaper design draft.
- Added the phased development plan.
- Replaced stale architecture, economics, bridge, security, roadmap, definition, and handoff documents.
- Updated `README.md` and `AGENTS.md` to direct future work to the same source of truth.

The 2026-07-13 handoff update also persisted cross-session safety, checkpoint,
validation, and commit rules. No protocol source code was changed by that update.
