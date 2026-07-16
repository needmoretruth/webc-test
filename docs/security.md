# WEBC security model

## Current posture

WEBC is a research prototype and must not hold real funds. Security claims require code review, automated tests, public adversarial testing, independent audits, and operational drills.

## Core invariants

- Valid execution never creates or destroys value except through explicit mint, burn, inflation, fee, and slashing rules.
- Whole-block execution is atomic.
- The actual state touched by a transaction stays inside its declared read/write list.
- Parallel execution produces the same committed result as the required deterministic order.
- Nonces, object versions, bridge messages, votes, and proofs cannot be replayed.
- Invalid arithmetic fails instead of wrapping.
- State roots and finalized certificates commit to one exact history.

## Rust safety as a security control

Rust prevents many memory mistakes only when WEBC deliberately uses its protections. Protocol code uses separate types for amounts, heights, epochs, nonces, networks, assets, and validator identities; typed errors instead of panics on hostile input; checked arithmetic; deterministic ordering; and explicit ownership instead of hidden shared mutation. `unsafe` is forbidden in protocol crates by default. Comments explain security invariants, while compiler-checked types and runtime checks enforce them.

Every source module documents what it owns, what it may change, what it must never do, and how failure rolls back. Every public protocol interface documents authorization, units, limits, state changes, and error behavior. Documentation changes with code so a future developer or AI cannot follow a stale security assumption.

## Consensus and slashing

Slashing requires objective signed proof. The current Phase 1 path accepts only
two conflicting consensus votes whose domain-separated signatures verify against
the validator's registered consensus key and whose protocol version, chain ID,
height, round, and vote stage match. Reversed evidence has the same replay ID.
Invalid-block, bridge-fraud, downtime, lateness, and majority-attack labels cannot
trigger a penalty until their own objective artifact and verification path exists.
An accepted double-vote penalty atomically reduces operator and delegator stake
mirrors and moves removed units into a dedicated state-root-committed slashing
bucket; failure rolls back the entire submitting transaction.

Non-default wallet lanes isolate replay and fee state. Each lane has an opaque
32-byte public ID, checked nonce, and prepaid native fee balance committed by the
state root and supply invariant. Only a default-lane transaction can open or
fund a lane. Missing lanes, nonce reuse, insufficient prepaid fees, duplicate
creation, and attempts to manage lanes from another lane fail atomically.

Transaction wire V3 binds every Ed25519 signature to protocol version and chain
ID under `WEBC_SIGNED_TRANSACTION_V3`. A correctly signed transaction for a
different WEBC network or unsupported protocol version is rejected before fees
or state change, closing the remaining cross-network transaction replay path.

Objects add a second replay boundary: every mutation or ownership transfer must
name the stored namespace and exact current version. Only the current address
owner may change an owned object. Duplicate creation, stale versions, namespace
substitution, wrong owners, payloads above 64 KiB, and shared-object mutation in
the Phase 1 native path fail atomically. Object bytes and ownership are committed
by the global state root.

Validator consensus, withdrawal, and bridge keys should be separated. Key rotation and emergency recovery must be tested before mainnet.

## Browser wallet

The host website must not read wallet seeds or private keys. Signing happens in an isolated wallet boundary and shows the website origin, action, asset, amount, recipient, and maximum fee. The wallet must defend against misleading text, hidden requests, copied addresses, dependency attacks, browser storage theft, and repeated signing prompts.

Mnemonic backup, encrypted wallet export, and raw private-key export use established formats and audited libraries. Passkeys may improve convenience but do not replace recovery. Website sponsorship must not give a sponsor control of the user's funds.

The current Phase 2 derivation path uses 24-word English BIP-39 and hardened
SLIP-0010 Ed25519 at the explicitly devnet-only testnet path
`m/44'/1'/account'/0'/index'`. Phrase, passphrase, account, and index inputs are
bounded and invalid checksums fail before derivation. The public wallet object
does not expose a `CryptoKey`; its signing handle remains non-extractable and
module-private. JavaScript cannot guarantee erasure of immutable strings, so
the phrase and optional passphrase must exist only inside the trusted wallet
origin. Encrypted persistence and the host-facing request boundary are still
incomplete.

Encrypted recovery export now has a strict v1 envelope. Argon2id uses the fixed
OWASP 19 MiB/t=2/p=1 profile with a fresh 16-byte salt, then AES-256-GCM uses a
fresh 12-byte IV and a 128-bit tag. All public metadata is authenticated as
additional data. Unknown fields, oversized input, noncanonical hex, modified
costs, wrong passwords, ciphertext changes, and public-identity swaps fail
closed; a file cannot request arbitrary KDF memory or iterations. Routine unlock
returns only the non-extractable in-process wallet, not the phrase. Immutable
password/recovery strings still cannot be guaranteed erased by JavaScript, so
the trusted-origin boundary remains mandatory.

The supported host boundary now uses a different-origin, top-level trusted
wallet popup rather than returning `WebcWallet` to an embedded host widget. The
service checks browser-authenticated origin and exact opener source, refuses
insecure/opaque origins, never replies to `*`, rejects unknown fields and blind
display text, and supports only wallet-constructed native transfers. A random
request ID plus wallet-issued session/monotonic sequence prevents request replay;
origin-specific lanes prevent one site selecting another site's lane. Exact
per-transaction/cumulative principal and fee limits are race-free because
requests execute serially. Every transfer still shows origin, recipient, amount,
asset, maximum fee, chain, and lane in the trusted popup and requires a click.
Permissions are not yet durably persisted, and this browser boundary still
requires independent security review and real-browser adversarial testing.

## Post-quantum readiness

Accounts use versioned authorization and every standard wallet begins with a post-quantum root/recovery path. ML-DSA is an initial standards-based candidate. Strict post-quantum signatures, limited session keys, and proof aggregation must be benchmarked before choosing the normal transaction path.

No “quantum safe” claim is allowed unless wallet backup, account authorization, consensus keys, bridge keys, proofs, upgrades, and exposed old keys are all covered. Algorithms must be replaceable if future research finds weaknesses.

## Smart contracts and site agents

Contracts are deterministic and cannot directly access files, websites, devices, secrets, or wall-clock time. External agents are untrusted unless their action is proven or accepted by an explicit signer. File hashes prove exact bytes, not that the file is safe or truthful.

Contracts and native modules need resource limits, re-entry protection where relevant, authority checks, version rules, and reproducible builds.

## Bridge risk

Bridges are a separate high-risk system. Required controls include exact asset identity, finality checks, replay protection, mint/release accounting, independent implementations and audits, rate limits, monitoring, pause drills, key rotation, upgrade delay, and a public incident plan.

Generic token support does not make malicious or unusual tokens safe. Real bridge funds remain disabled until the production trust/proof model is approved.

## Known gaps from the 2026-07-16 plan review

A read-only review reported gaps that are not yet fixed. These are recorded here
so the security model does not read as stronger than the code. Full detail and
line references are in `docs/review/findings.md`; the prioritized fix order is in
`docs/review/2026-07-16-plan-review.md` §6. Each finding must be reproduced with a
test before it is fixed.

- **Consensus is not yet safe (HIGH).** A proposed block is prevoted, locked, and
  finalized without re-executing it, so a Byzantine leader can obtain a valid
  finality certificate for an unimportable block (findings C1). A failed
  finalized-block import silently halts the node (C2). Per-height consensus memory
  is keyed by an attacker-chosen round with no bound (C3, OOM). There is no durable
  write-ahead log of a validator's own votes/locks, so a crash-restart can make an
  honest validator self-equivocate (C4) — this must be fixed before equivocation is
  wired to a slash.
- **Slashing is detected but not applied.** Objective double-vote evidence is
  produced by the consensus machine but the driver never actuates a penalty; PoS
  economic security is therefore not yet in force.
- **The finality "committee" is the whole validator set.** The confirmed rotating
  stake-weighted sub-committee is unbuilt; whole-set voting does not scale to an
  uncapped validator set and is a first-step approximation only.
- **Node/network hardening gaps (devnet surface).** No handshake timeout, unbounded
  inbound connections and peer table, faucet drainable via unlimited fresh
  addresses, and unbounded WebSocket subscriptions (findings N1–N3, H1, H3).
- **No production validator-key provisioning yet.** Devnet uses fresh per-process
  and hardcoded devnet keys; a permissioned keystore path (no key material in
  argv) must exist before mainnet.
- **No automated supply-chain gate.** `cargo-deny` (advisories/licenses/bans) and a
  JS advisory scan are not yet in CI.

## Test strategy

Testing must include unit and property tests, malformed input, randomized state-machine sequences, parallel/serial equivalence, network partitions, validator equivocation, restart recovery, database corruption, wallet-origin attacks, bridge replay, supply reconciliation, and long-running public testnets.
