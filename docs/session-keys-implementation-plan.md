# WEBC constrained session-key implementation plan

Status: **core implemented (single-node); devnet-only, disabled for real funds.**
The on-chain state machine, operations, constraint enforcement, state-root and
supply integration, the full Rust test matrix (steps 1–5 of [§13](#13-staged-implementation-each-step-compiles-tests-and-commits-alone)),
and the **real ML-DSA-65 root-signature gate on install/revoke (step 6)** are
implemented and passing. Remaining: optional expiry pruning (step 7), benchmarks
(step 8), and the browser/SDK surface (step 9). The macro policy choice it
prototypes is still an open technical gate (see [§14](#14-open-decisions-and-gates)).

Implementation note: during review the design gained a **cumulative fee budget**
(`total_fee_budget` / `spent_fees`) beyond the original per-use fee cap, so a
compromised key's total blast radius is bounded by
`total_amount_budget + total_fee_budget` regardless of how many times it is used.

Date: 2026-07-14 (plan); 2026-07-14 (implementation)

This document specifies how WEBC will add **constrained session keys** to the
versioned account authorization model. It is the last file in the required
reading chain for this task: `AGENTS.md` → `docs/decision-record.md` →
`docs/development-plan.md` → `docs/continuation-guide.md` → this file. It does
not change any confirmed product or economic decision; it turns the existing
confirmed session-key rules into a reviewable, testable engineering plan.

A session key is a **limited, short-lived signing key** that a wallet may use to
authorize a narrow set of transactions on a website without exposing the
account's primary key or its post-quantum recovery root. In plain terms: a user
grants one website a temporary key that can only spend a little, only do a few
kinds of action, only from that site, and only until it expires.

---

## 1. Scope and non-goals

### In scope

- On-chain data model for a constrained session key attached to an account's
  versioned authorization policy.
- Deterministic verification and constraint enforcement inside the existing
  single-node state machine.
- Install and revoke operations gated as critical actions behind the account's
  post-quantum root.
- Deterministic, wall-clock-free expiry.
- The matching browser/SDK surface (session subkey generation, signing domain,
  wire types) and the mapping from the already-shipped off-chain grant model.
- The security invariants, threat model, and full test matrix required before
  the path can be called complete for devnet.

### Out of scope (explicitly deferred)

- Choosing session keys over strict post-quantum-per-transaction signing. That
  remains an **open gate** (`docs/decision-record.md` line 190) resolved only by
  benchmarks, threat models, and audits. This plan builds the session-key path
  as a prototype to measure, not a frozen decision.
- Post-quantum-**security** claims. Real ML-DSA-65 signature verification is now
  implemented on install/revoke behind the replaceable `webc-crypto::mldsa`
  boundary (step 6), but ML-DSA-65 remains a named devnet candidate: no
  benchmarks, no external review, and no security claim until step 8 and a later
  audit. The path stays disabled for real funds.
- Networking, RPC, mempool, and persistent storage integration (Phase 3/4).
- Any real-fund or mainnet enablement.

---

## 2. Confirmed constraints this design must satisfy

These are quoted from the authoritative documents. `docs/decision-record.md`
wins on product/economic policy; `AGENTS.md` holds standing engineering rules.

1. **The five mandatory constraints.** "Limited session keys may act only within
   explicit **origin, operation, amount, fee, and expiry** constraints."
   (`docs/adr/0004-wallet-authorization.md` line 8.)
2. **Amount resolves to two limits plus a fee cap.** "grants cap principal per
   transaction, cumulative principal for the grant, and maximum fee per
   transaction using exact base-unit integers"
   (`docs/adr/0004-wallet-authorization.md` lines 83-84).
3. **Authorization is a critical action gated by the post-quantum root.**
   "Critical actions such as recovery, key rotation, staking control, high-value
   transfer policy changes, and session-key authorization require the
   post-quantum root policy." (`docs/decision-record.md` line 120.)
4. **Every wallet keeps a post-quantum root from genesis; no account is locked to
   Ed25519.** (`docs/decision-record.md` line 117; `AGENTS.md` line 240.)
5. **Session/passkey convenience must not silently replace portable recovery.**
   (`docs/decision-record.md` line 111; `docs/security.md` line 59.)
6. **The wallet must display origin, action, recipient, amount, asset, and
   maximum fee before signing.** (`docs/decision-record.md` line 105;
   `AGENTS.md` line 244.)
7. **Permissions are per-site and revocable.** (`docs/decision-record.md`
   line 106.)
8. **Expiry must be deterministic and must never read wall-clock time.** Every
   deterministic state transition is forbidden from reading the local clock
   (`AGENTS.md` lines 87, 140); time-like protocol math derives from chain
   parameters (`docs/decision-record.md` line 47); the accepted precedent
   expresses every deadline as a typed epoch and forbids wall-clock decisions
   (`docs/adr/0008-stake-lifecycle-and-exit-queue.md` lines 41-43, 71-72).
9. **Benchmark before enabling on the normal transaction path.** "the
   implementation must benchmark strict post-quantum signing, limited short-lived
   session keys, and ZK/STARK-based signature aggregation"
   (`docs/decision-record.md` line 119; `AGENTS.md` line 242).
10. **Standing security rules.** "Use explicit domain separation, versioning,
    replay protection, size limits, time/resource limits, and fail-closed
    behavior." (`AGENTS.md` line 105.) Checked arithmetic for all value math
    (`AGENTS.md` line 90). Treat every wallet request and signature as hostile
    input (`AGENTS.md` line 101).

---

## 3. Where this fits in the plan

This is the final gate of **Phase 2** in `docs/development-plan.md`:

> "add versioned account authorization policies and post-quantum root-key
> fields; … add recovery, rotation, revocation, and limited session-key tests."
> (`docs/development-plan.md` lines 120-122.)

`docs/continuation-guide.md` lists the exact order (lines 68-71):

1. versioned account authorization policies + post-quantum root field — **done**
   (`crates/webc-chain/src/authorization_policy.rs`, wired into `ChainState`);
2. recovery, rotation, revocation, and **constrained session-key state/tests** —
   this plan is the session-key portion.

Recovery, rotation, and revocation of the *primary* key are sibling work; this
plan assumes they land alongside or just before session keys because session-key
install/revoke reuse the same "critical action gated by the root" machinery.
Where the two overlap, this document notes the shared surface.

---

## 4. Foundations already in the code

The design deliberately reuses shipped, tested machinery rather than inventing
parallel structures. What already exists:

- **Versioned policy container.** `AccountAuthorizationPolicy` is an externally
  tagged enum stored per account in
  `ChainState.authorization_policies: BTreeMap<Address, AccountAuthorizationPolicy>`
  (`crates/webc-chain/src/state.rs:212-214`). Its V1 doc comment already reserves
  the design slot: *"Session keys are added as explicit constrained records
  rather than silently overloading this active key"*
  (`crates/webc-chain/src/authorization_policy.rs:117-119`).
- **The single key-binding decision point.** `verify_transaction_authorization`
  binds `tx.public_key` to the account. For an installed policy the entire gate
  is (`crates/webc-chain/src/state.rs:545-547`):
  ```rust
  if &tx.public_key != policy.active_transaction_key() {
      return Err(ChainError::AuthorizationKeyMismatch);
  }
  ```
  This is the exact-equality check session keys must widen.
- **Authorization lanes.** `AuthorizationLane { owner, id, next_nonce: Nonce,
  fee_balance: Amount }` (`crates/webc-chain/src/authorization.rs:14-25`), keyed
  by `(Address, AuthorizationLaneId)` in `ChainState.authorization_lanes`
  (`state.rs:216`). A non-default lane already supplies both the replay nonce and
  the prepaid fee source during execution
  (`state.rs:987-997`, `state.rs:1023-1038`, `state.rs:1061-1070`). Session keys
  reuse this lane plumbing unchanged for replay and fees.
- **Per-origin lane derivation (off-chain).** The SDK already derives a stable
  32-byte lane id per origin as
  `lane = SHA-256( Ed25519_sign( wallet, "WEBC_ORIGIN_LANE_V1\0" || origin ) )`
  (`sdk/webc-js/src/wallet-service.ts:311-327`). This is the "origin" constraint
  in concrete form and is already on-chain-shaped.
- **The off-chain grant model.** `PermissionGrant` / `WalletSpendLimitsJson`
  already enforce per-tx principal cap, cumulative principal cap, per-tx fee cap,
  monotonic sequence, and origin/lane binding with serialized, race-free,
  checked-integer accounting (`sdk/webc-js/src/wallet-request.ts:33-40`,
  `sdk/webc-js/src/wallet-service.ts:73-80, 229-273`). On-chain session keys are
  the durable, consensus-enforced version of exactly these constraints.
- **Operation template for install/fund.** `InstallAuthorizationPolicy`,
  `OpenAuthorizationLane`, and `FundAuthorizationLane` show the exact pattern for
  a management operation gated to the default lane, declaring its own state-key
  write, and emitting an event (`crates/webc-chain/src/state.rs:1078-1144`).
- **Deterministic epoch boundary.** `current_epoch: u64` on `ChainState`
  (`state.rs:236`) advances only in `finish_epoch` with checked arithmetic
  (`state.rs:705-805`); `unbonding` shows the typed-`Epoch`-at-the-boundary
  convention for deadline math (`crates/webc-chain/src/unbonding.rs:342-400`).
- **Commitment and reconciliation.** `state_root` builds a `StateCommitment`
  (domain `WEBC_STATE_COMMITMENT_V5`) over per-subtree roots
  (`state.rs:813-892`); `SupplyInvariantReport` reconciles every native bucket
  (`state.rs:242-269, 415-487`). Both must gain a session-key entry.

**What does not exist yet:** any on-chain session-key type, operation, state-key
variant, or config; any ML-DSA / post-quantum signature verification (no such
crate is in `Cargo.toml`). The only signature scheme is `ed25519-dalek 2.1`
wrapped as `webc_crypto::{Keypair, PublicKeyBytes, SignatureBytes,
verify_signature}`; the only hash is SHA-256 via `webc_crypto::Hash256`.

---

## 5. Design decisions and rationale

Each decision below is a technical gate resolved here by analysis; parameter
*values* are left to benchmarks per `AGENTS.md` line 296.

### 5.1 A session key is an authorization credential, not a fund holder

**Decision.** A session key authorizes spending the *owner's* account under
strict limits. It does **not** hold its own balance. Principal moves from the
owner's account exactly as an ordinary transfer does; the session key only gates
and meters it.

**Consequence for supply.** Because no native units are locked inside a session
key, the supply invariant is untouched — funds remain counted in `liquid` until
spent or burned normally. This is the simpler side of the fork the state audit
identified: a prepaid-balance design (like lanes' `fee_balance`) would force a
new `session_key_fees` bucket in `SupplyInvariantReport`
(`state.rs:453-471`) and a new `state_root` subtree balance, adding accounting
surface for no product benefit. The off-chain grant model already treats a grant
as authority over the wallet's funds, not a separate pot
(`sdk/webc-js/src/wallet-service.ts:73-80`); the on-chain model matches it.

**We still add a `session_key_root` to the state commitment** (§8) because the
*record* is committed state — but it commits identity and constraints, not a
balance, so it never enters supply reconciliation.

### 5.2 Records live in a dedicated map keyed by `(owner, session-key id)`

**Decision.** Store session keys in a new top-level
`ChainState.session_keys: BTreeMap<(Address, SessionKeyId), SessionKey>`,
mirroring `authorization_lanes`. Do **not** nest them inside `Account` (which
holds only balance/nonce/stake buckets, `crates/webc-chain/src/account.rs:15-27`)
or inside `AccountAuthorizationPolicyV1` (which must stay a small, stable
signing/recovery descriptor). The policy remains the *authority* that gates
install/revoke; the records are the *constrained delegations* under it, exactly
as the V1 doc comment prescribes.

`SessionKeyId` is an opaque 32-byte identifier, defined as the SHA-256 of a
domain tag and the session public key so it is deterministic, collision-resistant,
and never a secret — the same shape as `AuthorizationLaneId` (a `Hash256`
newtype, `crates/webc-chain/src/protocol.rs:131-135`). Keying by the id (not the
raw key) keeps state keys fixed-size and lets verification look a key up in one
`BTreeMap` probe.

### 5.3 Session-key transactions reuse the existing lane, nonce, and fee path

**Decision.** A session key is bound at install time to exactly one
`authorization_lane` (its origin lane, or the default lane) and its transactions
**must** use that lane. Replay protection and fee payment then flow through the
already-tested lane machinery with no change:

- default lane → owner's `Account.nonce` and `Account.balance` for fees;
- non-default lane → `AuthorizationLane.next_nonce` and prepaid
  `AuthorizationLane.fee_balance`.

This confines all new logic to (a) accepting the session key in place of the
active key and (b) checking the session constraints. It avoids a second nonce
system and avoids touching the fee debit path. The only session-specific mutable
state is a **cumulative `spent` counter** used for the budget limit.

### 5.4 Expiry is a typed epoch, checked by integer comparison

**Decision.** Each session key stores `expires_after_epoch: Epoch`. A
session-key transaction is rejected when `self.current_epoch > expires_after_epoch.get()`
— i.e. the key is valid *through* its expiry epoch, inclusive. Install computes
`expires_after_epoch = current_epoch + lifetime` with
`checked_add(...).ok_or(ChainError::ArithmeticOverflow)?`, where `lifetime` is
clamped to `SessionKeyConfig.max_lifetime_epochs`.

This follows the ADR-0008 precedent that every deadline is an integer epoch
comparison and no wall-clock, file, network, or random value decides a
transition (`docs/adr/0008-…` lines 41-43, 71-72). The target block interval is
2 seconds (`docs/decision-record.md` line 53), so an epoch bound is the
deterministic proxy for "short-lived." `Epoch` is the existing typed wrapper
(`crates/webc-chain/src/protocol.rs:161-165`); the record uses the typed value
at its boundary as `unbonding` does.

Expiry is checked at **use** time (during transaction execution). A separate,
optional epoch-boundary sweep may later prune expired records from state to bound
map growth, but pruning is not required for correctness because a use check
already rejects an expired key; the plan lists pruning as an optional follow-up
(§13, step 7) so map size stays bounded under heavy churn.

### 5.5 Install and revoke are critical actions gated by the post-quantum root

**Decision.** `InstallSessionKey` and `RevokeSessionKey` are critical operations.
They:

1. require an **installed** policy on the sender (a legacy address-derived
   account with no policy cannot own session keys — it has no post-quantum root
   to gate them);
2. require the **default lane** and are signed by the account's **active
   transaction key**, matching how `InstallAuthorizationPolicy` and lane
   management are gated (`state.rs:1079-1080, 1097-1100`);
3. carry a **reveal that both binds the root public key to the stored commitment
   and proves an ML-DSA-65 signature by that root** over the exact action. The
   revealed key's SHA-256 commitment must equal the stored
   `post_quantum_root.public_key_hash`, and the accompanying signature must
   verify over the canonical authorization message
   (`crates/webc-chain/src/authorization_policy.rs`, `PostQuantumRootReveal::verify`).

**Implemented (step 6).** The reveal is a real ML-DSA-65 signature, not a
commitment-knowledge check. `PostQuantumRootReveal` carries `{scheme, public_key,
signature}`; `verify` (a) bounds both fields, (b) checks the scheme, (c) binds
the revealed public key to the stored commitment, then (d) verifies the signature
under it via the replaceable `webc-crypto::mldsa` boundary. The signed message is
`session_key_authorization_message(chain_id, owner, policy_revision, nonce,
action)` under the `WEBC_SESSION_KEY_AUTHORIZATION_V1` domain, so the signature is
bound to one exact install/revoke, one policy revision, and one nonce. This closes
the earlier gap: a public key is public and copyable from on-chain history, so
proving *knowledge* of it was no defense; proving control of the root *secret* for
this exact message is. A compromised active Ed25519 key therefore still cannot
authorize a critical action on its own. This satisfies the intent of
`docs/decision-record.md` line 120 for the single-node state machine. It remains
**devnet-only, disabled for real funds**: ML-DSA-65 is a named candidate behind a
replaceable boundary, not a benchmarked, reviewed post-quantum-security claim
(benchmarks are step 8).

Requiring an installed policy also satisfies the "must not silently replace
portable recovery" rule (`docs/decision-record.md` line 111): the recovery root
always exists and always outranks any session key; a session key can never
rotate the root, revoke recovery, or install another policy.

### 5.6 Allowed operations are an explicit, bounded allow-list

**Decision.** A session key stores an explicit allow-list of permitted operation
kinds. **v1 permits only `Transfer`**, matching the off-chain service, whose v1
permits only native WEBC transfers and builds the operation and access list
itself (`docs/adr/0004-wallet-authorization.md` lines 77, 95). Critical and
account-structural operations are **never** delegable to a session key —
`InstallAuthorizationPolicy`, `InstallSessionKey`, `RevokeSessionKey`,
`RegisterValidator`, `UnstakeValidator`, `SubmitSlashingEvidence`, all bridge
operations, and lane management are excluded by construction, not by
configuration, so a misconfigured allow-list cannot escalate. The allow-list is
represented as a small fixed-size set with a hard cap on entries so hostile input
cannot inflate it (`AGENTS.md` line 143).

### 5.7 Domain separation and versioning

New domain tags, following the existing `WEBC_*_V1` convention
(`crates/webc-chain/src/lib.rs:73`, `consensus.rs:15`, `slashing.rs:37`):

- `WEBC_SESSION_KEY_ID_V1` — hashed with the session public key to derive
  `SessionKeyId`.
- `WEBC_SESSION_KEY_AUTHORIZATION_V1` — the install/revoke request payload that
  the post-quantum root will eventually sign (v1: reveal + hash-match; later: a
  root signature).
- `WEBC_SESSION_KEY_LEAF_V1` — the `state_root` leaf domain for a session-key
  record.
- The **transaction** a session key signs continues to use the existing
  `WEBC_SIGNED_TRANSACTION_V4` domain unchanged (`lib.rs:73`), because the tx
  wire is identical — only the acceptance rule for `tx.public_key` differs. This
  avoids a signing-domain bump and keeps cross-language fixtures stable.

The session-key record schema is itself versioned (an enum, like
`AccountAuthorizationPolicy`) so a future `SessionKeyV2` can add fields with an
explicit migration path (`docs/adr/0001-versioned-state.md` line 23).

---

## 6. Proposed data structures

All types live in a new module `crates/webc-chain/src/session_key.rs` (records,
constraints, validation) plus small additions to `state_key.rs`, `transaction.rs`,
`state.rs`, `lib.rs`, and `protocol.rs`. Sketches below are **illustrative**, not
final code; field docs, module header, and `Invariants:` blocks follow
`docs/code-documentation-template.md` and the `authorization_policy.rs` model.

The shipped code (`crates/webc-chain/src/session_key.rs`) is authoritative and
refines these sketches in two ways: (1) the signed `SessionKeyConstraints` carry
a relative `lifetime_epochs`, and the stored `SessionKey` record holds the
absolute `expires_after_epoch` resolved at install (per §5.4), rather than an
absolute expiry inside the constraints; (2) the constraints gained a cumulative
`total_fee_budget` and the record a `spent_fees` counter, so fees are bounded
both per use and cumulatively.

```rust
// crates/webc-chain/src/session_key.rs (proposed)

/// Opaque, non-secret identity of one session key under an account.
/// Derived as SHA-256("WEBC_SESSION_KEY_ID_V1\0" || session_public_key).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
         Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionKeyId(Hash256);

/// Which operation kinds a session key may authorize. v1: transfers only.
/// A fixed, bounded set; never contains a critical or structural operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAllowedOperations {
    /// Native `Transfer` is permitted. The only v1 capability.
    pub transfer: bool,
}

/// Immutable constraint set fixed when a session key is installed.
///
/// Invariants:
/// - `max_amount_per_use <= total_amount_budget`;
/// - at least one allowed operation is set;
/// - `expires_after_epoch` was computed from a clamped, checked lifetime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionKeyConstraints {
    /// Lane this key must use; binds the key to one origin (or default).
    pub authorization_lane: AuthorizationLaneId,
    /// Operation kinds this key may authorize.
    pub allowed_operations: SessionAllowedOperations,
    /// Maximum native principal moved by one session-signed transaction.
    pub max_amount_per_use: Amount,
    /// Maximum cumulative native principal over the key's whole life.
    pub total_amount_budget: Amount,
    /// Maximum fee bid accepted on one session-signed transaction.
    pub max_fee_per_use: Amount,
    /// Last epoch (inclusive) in which the key may be used.
    pub expires_after_epoch: Epoch,
}

/// One installed, constrained session key. Holds no funds.
///
/// Invariants:
/// - `constraints` validate;
/// - `spent_amount <= constraints.total_amount_budget` at all times;
/// - `session_public_key` is a valid Ed25519 verifying key;
/// - the owning account has an installed policy with a post-quantum root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionKey {
    /// Stable account that installed and owns this key.
    pub owner: Address,
    /// Opaque identity used as the state-map and state-key selector.
    pub id: SessionKeyId,
    /// Ed25519 key that signs transactions under this session.
    pub session_public_key: PublicKeyBytes,
    /// Policy revision this key was installed under; a rotation revision
    /// change invalidates the key (fail-closed on stale sessions).
    pub policy_revision: AuthorizationPolicyRevision,
    /// Fixed constraints checked on every use.
    pub constraints: SessionKeyConstraints,
    /// Cumulative native principal already spent. Mutable; only grows.
    pub spent_amount: Amount,
}
```

Versioned wrapper (so schema can evolve):

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionKeyRecord {
    V1(SessionKey),
}
```

New config, added as a namespaced sub-config beside `staking`/`slashing`
(`ChainConfig` at `crates/webc-chain/src/state.rs:36-49`, and its `Default` at
`state.rs:51-64`):

```rust
/// Versioned-chain session-key limits. Values are benchmark/security gates,
/// not product-owner preferences.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeyConfig {
    /// Hard upper bound on a session key's lifetime, in consensus epochs.
    pub max_lifetime_epochs: u64,
    /// Maximum simultaneously installed session keys per account.
    pub max_session_keys_per_account: u32,
}
```

New `StateKeyKind` arm, adjacent to `AuthorizationLane`
(`crates/webc-chain/src/state_key.rs:51-55`), with a `StateKey::session_key`
constructor mirroring `authorization_lane` (`state_key.rs:129-131`) and an entry
added to the golden wire-vector digest test (`state_key.rs:317-353`):

```rust
/// Constraint and spend state for one delegated session key under an account.
SessionKey { owner: Address, session_key: SessionKeyId },
```

New `Operation` variants, beside `InstallAuthorizationPolicy`
(`crates/webc-chain/src/transaction.rs:96-114`):

```rust
/// Installs a constrained session key. Critical: requires the account's
/// post-quantum root reveal and the default lane.
InstallSessionKey {
    session_public_key: PublicKeyBytes,
    constraints: SessionKeyConstraints,
    /// Reveal of the committed post-quantum root public key.
    post_quantum_root_reveal: PostQuantumRootReveal,
    // Later gate: post_quantum_root_signature: MlDsaSignature,
},
/// Revokes an installed session key immediately. Critical: same gate.
RevokeSessionKey {
    session_key: SessionKeyId,
    post_quantum_root_reveal: PostQuantumRootReveal,
},
```

New `ChainError` variants, following the `AuthorizationLane*` family naming
(`crates/webc-chain/src/lib.rs:203-216`):

```
SessionKeyNotFound
SessionKeyAlreadyExists
SessionKeyExpired
SessionKeyLimitExceeded           // per-account count cap
SessionKeyLifetimeTooLong         // requested lifetime > config max
SessionKeyRequiresInstalledPolicy // legacy account cannot own session keys
SessionKeyManagementRequiresDefaultLane
SessionKeyLaneMismatch            // used a lane other than the bound one
SessionKeyOperationNotPermitted   // op kind not in the allow-list
SessionKeyAmountExceeded          // per-use principal cap
SessionKeyBudgetExceeded          // cumulative principal cap
SessionKeyFeeExceeded             // per-use fee cap
InvalidSessionKeyConstraints      // e.g. per-use > budget, empty allow-list
InvalidPostQuantumRootReveal      // reveal hash != committed root hash
```

New `Event` variants (`SessionKeyInstalled`, `SessionKeyRevoked`,
`SessionKeyUsed`) mirroring the `AuthorizationLane*` events emitted at
`state.rs:1091-1143`.

---

## 7. Verification and execution flow

The change set is deliberately surgical. Only two code paths gain logic; the rest
is reused unchanged.

### 7.1 Key binding — widen the single decision point

In `verify_transaction_authorization` (`crates/webc-chain/src/state.rs:538-548`),
replace the exact-equality gate at lines 545-547 with:

1. If `tx.public_key == policy.active_transaction_key()` → accept (unchanged
   fast path for the owner's own key).
2. Else, look up `self.session_keys.get(&(tx.sender, SessionKeyId::derive(&tx.public_key)))`:
   - not found → `AuthorizationKeyMismatch` (unchanged behaviour for an unknown
     key, so nothing new is accepted silently);
   - found → validate the session key is usable **for authorization purposes
     only** here: `session.policy_revision == policy.revision()` (a rotation
     invalidates it) else `AuthorizationKeyMismatch`; and
     `tx.authorization_lane == session.constraints.authorization_lane` else
     `SessionKeyLaneMismatch`. Expiry and spend limits are *not* checked here
     because this function must stay side-effect-free and pre-fee; they are
     enforced in execution (§7.2) where the operation and epoch are in hand and
     rollback is atomic.

Because `verify_transaction_authorization` runs before any fee change and before
the operation is applied — `execute_transaction` calls it at `state.rs:508`, then
applies the operation to a clone and commits with `*self = next` only on success
(`state.rs:510-512`) — a rejected session-key transaction mutates nothing; the
existing atomicity guarantee is inherited.

**Access-list impact.** Every transaction already forces a declared read of
`StateKey::authorization_policy(sender)`. A session-key transaction must **also**
declare a read+write of `StateKey::session_key(sender, id)` (write, because
`spent_amount` and the lane nonce mutate). The access recorder must add this key
during execution or the run fails closed with `UndeclaredStateWrite`
(`lib.rs:188`). The SDK builds the access list, so it adds the session-key state
key when signing with a session key (§9).

### 7.2 Constraint enforcement — in execution, before the operation applies

Inside `apply_verified_transaction`, when the transaction was authorized by a
session key (i.e. `tx.public_key` is not the active key), and **before** the
operation mutates balances:

1. **Expiry:** reject if `self.current_epoch > session.constraints.expires_after_epoch.get()`
   → `SessionKeyExpired`.
2. **Operation allow-list:** reject if the operation kind is not permitted →
   `SessionKeyOperationNotPermitted`. (v1: only `Transfer` may pass.)
3. **Per-use amount:** for a `Transfer { amount, .. }`, reject if
   `amount > session.constraints.max_amount_per_use` → `SessionKeyAmountExceeded`.
4. **Cumulative budget:** compute
   `next_spent = session.spent_amount.checked_add(amount).ok_or(ArithmeticOverflow)?`;
   reject if `next_spent > session.constraints.total_amount_budget` →
   `SessionKeyBudgetExceeded`.
5. **Per-use fee:** reject if the transaction's maximum fee
   (`gas_limit * max_fee_per_unit`, computed with checked arithmetic exactly as
   the off-chain client does, `sdk/webc-js/src/wallet-request.ts:266-273`)
   exceeds `session.constraints.max_fee_per_use` → `SessionKeyFeeExceeded`.
6. On success, write back `session.spent_amount = next_spent` and emit
   `SessionKeyUsed`. The principal transfer and fee debit then run through the
   existing unchanged transfer/fee/nonce code.

All comparisons use `Amount`'s checked helpers (`crates/webc-chain/src/amount.rs:44-82`).
Any failure returns a typed error and, because the whole `execute_transaction`
runs on a cloned overlay, rolls back with no partial mutation.

### 7.3 Install and revoke

`InstallSessionKey` (modeled on `InstallAuthorizationPolicy` and
`OpenAuthorizationLane`, `state.rs:1078-1121`):

1. require default lane else `SessionKeyManagementRequiresDefaultLane`;
2. require an installed policy on `tx.sender` else
   `SessionKeyRequiresInstalledPolicy`; validate the policy;
3. verify `post_quantum_root_reveal` hashes to the policy's stored
   `post_quantum_root.public_key_hash` — reached by matching the policy enum or
   by a new `post_quantum_root()` accessor added to `AccountAuthorizationPolicy`
   (which today exposes only `revision()` and `active_transaction_key()`,
   `authorization_policy.rs:138-149`) — else `InvalidPostQuantumRootReveal`
   *(v1: hash-match only; later: root signature)*;
4. `constraints.validate()` (per-use ≤ budget; non-empty allow-list; lifetime ≤
   `config.session_keys.max_lifetime_epochs` else `SessionKeyLifetimeTooLong`;
   compute `expires_after_epoch = current_epoch + lifetime` checked);
5. derive `id = SessionKeyId::derive(&session_public_key)`; declare
   `StateKey::session_key(sender, id)` as a write;
6. reject if it already exists → `SessionKeyAlreadyExists`; reject if the
   account already holds `max_session_keys_per_account` keys →
   `SessionKeyLimitExceeded` (count via a bounded scan of the sender's keys);
7. insert the record with `spent_amount = 0` and
   `policy_revision = policy.revision()`; emit `SessionKeyInstalled`.

`RevokeSessionKey`: same critical gate (default lane, installed policy, root
reveal), then remove `(sender, id)` from the map → `SessionKeyNotFound` if
absent; emit `SessionKeyRevoked`. Revocation is immediate and unconditional:
per-site revocability is a confirmed rule (`docs/decision-record.md` line 106)
and there is no cooldown — a compromised key must die at once.

Rotating the primary key (a sibling recovery/rotation operation) bumps
`policy.revision`, which **automatically invalidates every session key** via the
`policy_revision` check in §7.1. This is intentional defense-in-depth: rotating
away from a compromised primary key also kills all outstanding sessions without a
separate sweep.

---

## 8. State root and supply invariant

- **State root.** Add a `session_key_root` field to the `StateCommitment` struct
  (`state.rs:814-838`), computed with
  `ordered_value_root(b"WEBC_SESSION_KEY_LEAF_V1", self.session_keys.iter())`
  exactly like `authorization_lane_root` (`state.rs:849-852`, helper at
  `state.rs:1991-2001`). Because `session_keys` is a `BTreeMap`, leaf order is
  canonical without an explicit sort. Field placement is load-bearing (it feeds
  canonical JSON), so place it deterministically next to
  `authorization_lane_root`, and **bump the commitment domain**
  `WEBC_STATE_COMMITMENT_V5` → `WEBC_STATE_COMMITMENT_V6` (a state-root schema
  change).
- **Supply invariant.** No change to `SupplyInvariantReport`. Session keys hold
  no funds (§5.1), so they contribute nothing to reconciliation. The
  session-key test suite must nonetheless assert `supply_invariant_report().balanced`
  stays true across install/use/revoke, proving the "holds no funds" property
  empirically (add to `assert_staking_invariants`, `state.rs:2361-2444`).

---

## 9. Browser and SDK plan

The off-chain grant model already implements every constraint except expiry
(`sdk/webc-js/src/wallet-service.ts`); the SDK work is to (a) generate a session
subkey, (b) build session-signed transactions, and (c) surface expiry.

- **Session subkey.** Generate an ephemeral, **non-extractable** Ed25519
  `CryptoKey` via the existing `createWallet` path
  (`sdk/webc-js/src/wallet.ts:33-47`), which produces a key with "no recovery
  material." The private handle stays in the module-private `privateKeys` weak
  map (`sdk/webc-js/src/wallet.ts:17`); the public object exposes only address
  and public key. Dropping the reference makes the handle GC-eligible and
  unrecoverable — "short-lived" for free. The session public key is the on-chain
  `session_public_key`.
- **Install request.** The primary wallet (holding the root) signs an
  `InstallSessionKey` transaction under `WEBC_SIGNED_TRANSACTION_V4`, revealing
  the post-quantum root commitment. This is a critical action and shows the full
  confirmation screen (origin, action, the session's caps, expiry, chain).
- **Session-signed transfers.** The session subkey signs `Transfer` transactions
  with the same canonical payload builder (`transaction.ts:455-480`), setting
  `public_key = session public key`, `authorization_lane = the origin lane`, and
  an access list that includes `StateKey::session_key(owner, id)` and
  `StateKey::authorization_policy(owner)`. Amounts stay decimal strings; fees are
  the existing `FeeBidJson` snake_case wire (`transaction.ts:709-715`).
- **Constraint mapping.** Reuse the shipped limit types verbatim: the on-chain
  `max_amount_per_use` / `total_amount_budget` / `max_fee_per_use` are the
  durable form of `WalletSpendLimitsJson.max_amount_per_transaction` /
  `max_total_amount` / `max_fee_per_transaction`
  (`sdk/webc-js/src/wallet-request.ts:33-40`). Origin → lane uses the existing
  `deriveOriginAuthorizationLane` (`wallet-service.ts:311-327`).
- **Expiry surface (new).** Add an `expires_after_epoch` field to the install
  request and display it in the confirmation UI as a human-readable estimate
  ("about N minutes at 2s blocks", clearly labelled an estimate, never a
  guarantee). This is the one concept with no existing off-chain analog.
- **Cross-language fixtures.** Add a frozen fixture that installs a session key,
  signs a transfer with it in the SDK, and verifies it in Rust — mirroring the
  existing shared transaction fixture (`transaction.rs:879`,
  `sdk/webc-js/src/transaction.test.ts`). Add the new `StateKeyKind::SessionKey`
  variant to the shared state-key vector.

The host site never receives the session private key; the trusted wallet origin
holds it, exactly as it holds the primary key
(`docs/adr/0004-wallet-authorization.md` lines 10-11, 66-93).

---

## 10. Security invariants

Stated as testable properties (compare `docs/security.md` "Core invariants" and
ADR-0008's invariant list):

1. A session key can authorize **only** operation kinds in its allow-list; v1
   means transfers only, and never a critical, staking, bridge, or lane/policy
   operation.
2. A session-signed transaction never moves more than `max_amount_per_use` in one
   transaction and never exceeds `total_amount_budget` cumulatively; it never pays
   more than `max_fee_per_use` in one transaction and never exceeds
   `total_fee_budget` in cumulative fees. A compromised key's total blast radius
   is therefore bounded by `total_amount_budget + total_fee_budget` regardless of
   how many times it is used.
3. A session key is unusable once `current_epoch > expires_after_epoch`, decided
   only by integer epoch comparison against committed state — never by wall clock.
4. A session key is bound to one lane and one origin; it cannot act on another
   origin's lane.
5. Installing or revoking a session key requires a valid **ML-DSA-65 signature by
   the account's post-quantum root** over the exact action (bound to chain id,
   owner, policy revision, and nonce), plus the default lane and an installed
   policy. A legacy account cannot own session keys.
6. A session key can never install a policy, install or revoke another session
   key, rotate or revoke the root, or otherwise perform a critical action; the
   portable recovery root always outranks it and is never replaced by it.
7. Rotating the primary key (policy revision bump) invalidates every outstanding
   session key.
8. Revocation is immediate; a revoked key authorizes nothing thereafter.
9. Session keys hold no funds; `supply_invariant_report().balanced` is unaffected
   by any install/use/revoke sequence.
10. Every session-key state change is committed by the state root; a failed
    session-key transaction mutates nothing (atomic rollback).
11. All limit and expiry math uses checked arithmetic; overflow is an explicit
    error, never a wrap.
12. Malformed constraints, unknown fields, oversized allow-lists, a stale policy
    revision, a bad root reveal, or a lane mismatch all fail closed before any
    state change.

---

## 11. Threat model

**Attacks the design defends against.**

- *Host-site key theft / over-reach.* The site never sees the session private
  key; the session key can spend only a little, only certain actions, only from
  its origin, only until expiry.
- *Over-spend / unbounded authority.* Per-use, cumulative, and fee caps bound the
  blast radius; checked, serialized accounting prevents budget races.
- *Cross-origin confusion.* Lane binding stops one site using another's session.
- *Blind signing / clickjacking.* The wallet builds the operation and access
  list; there is no arbitrary-byte session signing, and the confirmation screen
  shows the exact fields (`docs/decision-record.md` line 105).
- *Root exposure under a quantum adversary.* Critical actions stay behind the
  post-quantum root; a compromised classical session key cannot escalate to
  recovery, rotation, staking, or policy changes.
- *Compromised active key forging a critical action.* Install/revoke require an
  ML-DSA-65 signature by the root over the exact action, not merely knowledge of
  the (public, copyable) root key. Holding the active Ed25519 key is not enough
  to install or revoke a session key; the root secret is required.
- *Root-signature replay / repurposing.* The signed message binds chain id,
  owner, policy revision, nonce, and the exact action, so a captured root
  signature cannot be moved to another action, another nonce, or a post-rotation
  policy revision. Adversarial tests cover wrong-action, wrong-nonce,
  wrong-key, and garbage-signature reveals.

**New attacks the design introduces and how each is closed.**

- *Compromised session key.* Bounded by caps + expiry + immediate revocation +
  inability to perform critical actions. Revocation and rotation-invalidation are
  tested paths (§12).
- *Cumulative-budget race.* Deterministic, serialized, checked `spent_amount`
  accounting on-chain; there is no concurrent mutation of one record within a
  block's deterministic order.
- *Replay across origins/lanes.* Domain-separated tx signing + chain-id + version
  binding (existing `WEBC_SIGNED_TRANSACTION_V4`), per-lane checked nonce, and
  lane binding on the session key.
- *Expiry evasion.* Deterministic epoch comparison against committed state; no
  local-clock surface to skew.
- *Downgrade / legacy-policy substitution.* Session keys require an installed
  policy with a root; install/revoke are critical actions; policy is versioned
  with explicit migration; unsupported/mismatched revisions are rejected before
  state change; a rotation invalidates sessions.
- *Silent recovery replacement.* Session keys are additive delegations under the
  root, never a substitute for it; the root and portable recovery always exist
  and always outrank sessions.

**Standing limitation.** Until ML-DSA verification exists, the "requires the
post-quantum root" gate is a commitment-knowledge check, not a root signature.
The whole path is therefore devnet-only and disabled for real funds
(`AGENTS.md` line 108; `docs/security.md` line 5) until benchmarked (§13, step 8)
and independently audited.

---

## 12. Required tests

Modeled on the existing patterns in `state.rs`, `unbonding.rs`, `slashing.rs`,
and `authorization_policy.rs`.

**Unit / fail-closed (each returns a specific `ChainError` and mutates nothing):**

- install rejected: no policy, non-default lane, bad root reveal, over-long
  lifetime, per-use > budget, empty allow-list, duplicate id, over the
  per-account cap;
- use rejected: expired key, disallowed operation kind, over per-use amount, over
  cumulative budget, over per-use fee, wrong lane, unknown session key, stale
  policy revision after rotation;
- revoke: unknown id rejected; revoked key then rejected on use;
- reuse `execute_with_rollback_check` (`state.rs:2446-2455`) so every rejection
  proves atomic rollback.

**Lifecycle / accounting:**

- install → several within-budget uses → budget-exhaustion boundary (spend up to,
  then one over) → revoke;
- `supply_invariant_report().balanced` holds after every step (add to
  `assert_staking_invariants`, `state.rs:2361-2444`);
- primary-key rotation invalidates outstanding sessions;
- expiry boundary tested on both sides of the exact epoch (use at
  `expires_after_epoch`, then at `expires_after_epoch + 1`) driven through
  `finish_epoch` (`state.rs:705-805`).

**Property test** (like `arbitrary_stake_sequences_preserve_all_accounting_mirrors`,
`state.rs:2538-2636`): a random stream of install/use/revoke/rotate/advance-epoch
actions over several accounts, asserting after every step that no key exceeds its
budget, no expired key is usable, per-account count ≤ cap, supply stays balanced,
and every failed action left state unchanged.

**Serialization / restart equivalence** (like
`serialization_restart_preserves_queue_result`, `unbonding.rs:522-548`):
round-trip `session_keys` through serde, advance an epoch on both copies, assert
identical outcomes and equal structs, and assert an unchanged state root.

**Cross-language fixtures:** frozen `StateKeyKind::SessionKey` wire vector (update
`state_key.rs:317-353`); an SDK-installed, SDK-session-signed transfer verified in
Rust; a pinned `SessionKeyId` derivation digest and a pinned
`WEBC_SESSION_KEY_LEAF_V1` leaf-hash digest (the fixed-digest pattern at
`slashing.rs:238-271`).

**State-root / golden digest:** update the state-commitment digest test for the
`V6` domain and the new subtree.

---

## 13. Staged implementation (each step compiles, tests, and commits alone)

Ordered so every step is independently reviewable and passes the full gate
(`cargo fmt --check`, strict Clippy, `cargo test --workspace`, doc build, node
demo; SDK build/tests for SDK steps) before the next begins, per the
continuation-guide commit rule.

1. **Types + config, no wiring.** Add `session_key.rs` (`SessionKeyId`,
   `SessionKeyConstraints`, `SessionKey`, `SessionKeyRecord`, `validate()`),
   `SessionKeyConfig` + `ChainConfig.session_keys` and its `Default`, and the new
   `ChainError` variants. Unit-test `validate()` and id derivation with a pinned
   digest. No behaviour change to transactions yet.
2. **State-key variant + commitment.** Add `StateKeyKind::SessionKey`, the
   constructor, the golden wire vector, `ChainState.session_keys`, the
   `session_key_root`, and the `V6` commitment bump. Test the state-root digest.
3. **Install / revoke operations.** Add the `Operation` variants and their
   execution with the critical-action gate (default lane, installed policy, root
   reveal hash-match), count cap, and events. Fail-closed unit tests.
4. **Key-binding widening.** Change `verify_transaction_authorization` to accept a
   registered session key (lane + revision checks only). Test that an unknown key
   still yields `AuthorizationKeyMismatch` and a rotation invalidates sessions.
5. **Use-time constraint enforcement.** Add expiry, allow-list, per-use amount,
   cumulative budget, and fee-cap checks plus `spent_amount` write-back and
   `SessionKeyUsed`. Lifecycle, boundary, property, and restart tests; supply
   reconciliation assertion.
6. **Post-quantum root signature. Done.** Added the pinned `fips204` ML-DSA-65
   verifier behind `webc-crypto::mldsa`; extended `PostQuantumRootReveal` to carry
   a signature and become `verify(root, message)`; built
   `session_key_authorization_message` over `WEBC_SESSION_KEY_AUTHORIZATION_V1`
   binding chain id, owner, policy revision, nonce, and action; wired both
   install/revoke arms; added adversarial tests (wrong action, wrong nonce, wrong
   key, garbage signature). The gate is now true root authorization, not
   commitment-knowledge. Still devnet-only pending benchmarks (step 8) and audit.
7. **Optional expiry pruning.** Add an epoch-boundary sweep in `finish_epoch` that
   drops expired records to bound map growth. Correctness does not depend on it
   (use-time checks already reject expired keys); it is purely a state-size guard,
   FIFO/deterministic and restart-stable.
8. **Benchmarks (gate before any claim).** Measure session-key transaction
   verification and install/revoke cost against the strict-per-transaction-PQ
   baseline and against ordinary Ed25519 transfers, on the reference machines in
   `docs/development-plan.md` lines 227-231. Publish results before the policy
   gate (§14) is considered for resolution.
9. **SDK surface.** Session subkey generation, install/session-signing helpers,
   expiry display, and cross-language fixtures (§9).

Each step updates `docs/implementation-status.md` and, when the next task
changes, `docs/continuation-guide.md`.

---

## 14. Open decisions and gates

- **Policy gate (product-adjacent, do not resolve prematurely).** "strict
  post-quantum-per-transaction versus post-quantum-root plus limited session-key
  policy" is explicitly undecided (`docs/decision-record.md` line 190) and is
  resolved only by "specifications, prototypes, benchmarks, threat models, tests,
  and audits" (line 194). This plan builds the prototype and the benchmark
  (steps 5, 8); the decision itself is surfaced to the user only when the
  post-quantum evidence (Phase 8 in `docs/development-plan.md`) is ready to
  freeze — ask only when a phase is ready to freeze, per `AGENTS.md` lines
  288-296. **Do not ask now.**
- **Parameters set by benchmark, not preference** (`AGENTS.md` line 296):
  `max_lifetime_epochs` and `max_session_keys_per_account`, and the fee/amount
  cap conventions. Defaults ship as conservative devnet placeholders,
  documented as such.
- **ML-DSA verification** is now implemented for the root-signature gate (step 6)
  via the pinned `fips204` ML-DSA-65 crate behind the replaceable
  `webc-crypto::mldsa` boundary. It is still not a post-quantum-**security** claim
  or a real-fund enabler: the scheme choice, its performance, and its
  side-channel posture remain a benchmark (step 8) and audit gate. Swapping the
  scheme should touch only the `mldsa` module and the `PostQuantumScheme` enum.
- **Fee source for session transfers.** v1 reuses whatever lane the key is bound
  to (default → owner balance; non-default → prepaid lane balance). A dedicated
  session fee-budget could be added later but would reintroduce a supply bucket
  and is not justified for the prototype.

---

## 15. Definition of done (devnet prototype)

Per `AGENTS.md` lines 147-154:

- module, function, and type docs describe the final behaviour, with `Invariants:`
  blocks on the consensus structs;
- unit, fail-closed, lifecycle, property, restart, and cross-language tests pass;
- `cargo fmt --check`, strict Clippy, `cargo test --workspace`, doc build with
  warnings denied, and the node demo pass; SDK build and tests pass;
- the state-root and supply invariants hold across all session-key sequences;
- the recorded limitations (ML-DSA-65 is an unbenchmarked, unaudited devnet
  candidate; devnet-only; disabled for real funds; open policy gate) are stated in
  code and `docs/implementation-status.md`;
- `docs/implementation-status.md` and `docs/continuation-guide.md` accurately
  state what is implemented and what remains.

The post-quantum root **signature** gate is now closed for the single-node state
machine (step 6). The path nonetheless stays **devnet-only and disabled for real
funds** until ML-DSA-65 benchmarks are published (step 8) and independent audits
and adversarial testing pass.

---

## 16. References

> Line numbers below are an indicative snapshot from when this plan was written and
> drift whenever a referenced file is edited (for example, `AGENTS.md` was
> restructured in the 2026-07-16 review). Treat the **section titles and symbol
> names** as authoritative and the line numbers as a hint only; do not trust a bare
> line number without confirming the target still matches. New cross-references
> should cite a section or symbol, not a line range.

**Confirmed decisions and rules**

- `AGENTS.md` — session-key gate and do-not-skip-ahead rule (lines 280-285), no
  wall-clock in transitions
  (87, 140), typed wrappers incl. `BlockHeight`/`Epoch` (135), benchmark session
  keys (242), display fields (244), post-quantum root from creation (240),
  security-first rules (105), definition of done (147-154).
- `docs/decision-record.md` — root gates session-key authorization (120),
  post-quantum root from genesis (117), passkeys ≠ recovery (111), display
  fields (105), per-site revocable (106), benchmark requirement (119), open
  policy gate (190-194), no wall-clock (47).
- `docs/development-plan.md` — Phase 2 tasks (121-122), reference machines
  (227-231).
- `docs/continuation-guide.md` — exact next work (68-71).
- `docs/whitepaper.md` §9.2 (214-231); `docs/security.md` (5, 13, 55-98);
  `docs/architecture.md` (Keys §, line 77).
- `docs/adr/0004-wallet-authorization.md` — the five constraints (8), grant caps
  (83-84), host protocol (66-98); `docs/adr/0008-…` — deterministic epoch
  deadlines (41-43, 71-72); `docs/adr/0001-versioned-state.md` — declared
  access, size limits, migration path (12-23).

**Code the plan builds on**

- `crates/webc-chain/src/authorization_policy.rs` — policy enum, `PostQuantumRoot`
  (79-109), session-key reservation comment (117-119).
- `crates/webc-chain/src/state.rs` — `verify_transaction_authorization` (523-549,
  decision point 545-547), `execute_transaction` (494-514), install/lane ops
  (1078-1144), `StateCommitment`/`state_root` (813-892), `SupplyInvariantReport`
  (242-269, 415-487), `current_epoch`/`finish_epoch` (236, 705-805),
  `assert_staking_invariants`/property test (2361-2444, 2538-2636), `ChainConfig`
  (36-64).
- `crates/webc-chain/src/authorization.rs` — `AuthorizationLane` template (14-36).
- `crates/webc-chain/src/state_key.rs` — `StateKeyKind` (36-80), constructor
  pattern (129-131), golden vector (317-353).
- `crates/webc-chain/src/transaction.rs` — `Operation` enum (94-238), signing
  payload/domain (751-781), fixture (879).
- `crates/webc-chain/src/protocol.rs` — `Epoch`/`Nonce`/`AuthorizationLaneId`
  wrappers (131-170), `consensus_integer!` (92-118).
- `crates/webc-chain/src/lib.rs` — `ChainError` (76-231), `SIGNING_DOMAIN` (73).
- `crates/webc-chain/src/{unbonding,slashing}.rs` — lifecycle, signed-evidence,
  restart, and fixed-digest test patterns.
- `sdk/webc-js/src/{wallet,wallet-service,wallet-request,transaction}.ts` —
  off-chain grant model, origin-lane derivation (311-327), weak-map key handling
  (17), signing payload (455-480), fee wire (709-715).
