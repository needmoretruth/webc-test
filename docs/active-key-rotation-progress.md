# Active-key recovery/rotation: implementation recipe (start fresh)

Durable plan for the **primary-key recovery and rotation** work (the "sibling"
item after the session-key gate in `docs/continuation-guide.md`). Read it with
`docs/session-keys-next-steps.md` and the Phase 2 section of
`docs/implementation-status.md`. Chat history is not the source of truth; this
file is.

## Status: NOT STARTED in the tree. Base = `6e54004` (session-key ML-DSA gate).

An earlier attempt built most of this but its container was reclaimed before the
work compiled or persisted, so **nothing is in the tree** — implement from scratch
using the exact code below. Base branch `claude/docs-session-keys-plan-ppk0dl` at
`6e54004` compiles and passes the full gate. This mirrors the just-shipped
session-key root-signature gate (`crates/webc-chain/src/session_key.rs`,
`authorization_policy.rs`, and the install/revoke arms in `state.rs`) — read those
first; rotation is the same pattern applied to the account's active key.

## What this feature is (design + security — decided, do not re-derive)

`Operation::RotateActiveTransactionKey { new_active_transaction_key,
post_quantum_root_reveal }` rotates the account's sole active Ed25519 key. It is
the **recovery path** when the active key is lost or compromised, gated exactly
like session-key install/revoke: default lane, installed policy, and a **real
ML-DSA-65 root signature** over the exact action. Confirmed against
`docs/decision-record.md` line 120 (recovery + key rotation are root-gated
critical actions) and line 111 (never silently drop portable recovery).

1. **Recovery works without the old key.** The transaction envelope may be signed
   by the *new* key (proving control of it); the root signature is the real
   authority. This needs a new `verify_transaction_authorization` path returning
   `TransactionAuthorization::PostQuantumRootRecovery`, produced **only** for
   `RotateActiveTransactionKey` and only when `tx.public_key ==
   new_active_transaction_key`. If the current active key signs instead, the
   ordinary `AccountKey` path is taken; both converge on the arm's root-signature
   check.
2. **Rotation bumps the policy revision**, which invalidates every outstanding
   session key (they check `session.policy_revision == policy.revision()`). The
   post-quantum root is **preserved**.
3. **Session keys can never rotate.** `enforce_session_key_use` runs before the
   operation match (`state.rs`, `if let TransactionAuthorization::SessionKey(id)`)
   and `session_permitted_principal` allows only `Transfer`, so a session-signed
   rotation is rejected with `SessionKeyOperationNotPermitted`. No code needed;
   add a test asserting it.
4. **Replay binding.** `active_key_rotation_message` binds domain
   (`WEBC_ACTIVE_KEY_ROTATION_V1`) + chain id + owner + current policy revision +
   nonce + the exact new key. A captured signature cannot move to another key,
   nonce, account, chain, or post-rotation revision.
5. **Reject rotating to the same key** (`ActiveKeyRotationToSameKey`).
6. `required_units` = 25_000 (same tier as `InstallAuthorizationPolicy`).

## Exact code to add, file by file

### `crates/webc-chain/src/lib.rs`
Add three `ChainError` variants (next to the session-key errors):
```rust
    #[error("active-key rotation must use the default lane")]
    ActiveKeyRotationRequiresDefaultLane,
    #[error("active-key rotation requires an installed policy with a post-quantum root")]
    ActiveKeyRotationRequiresInstalledPolicy,
    #[error("active-key rotation must change the active transaction key")]
    ActiveKeyRotationToSameKey,
```
Export `active_key_rotation_message` and `ACTIVE_KEY_ROTATION_DOMAIN` from the
`authorization_policy::{...}` re-export.

### `crates/webc-chain/src/authorization_policy.rs`
Widen imports to `use crate::{ChainError, ChainId};` and
`use webc_crypto::{Address, Hash256, PublicKeyBytes};`. Add a `rotate_active_key`
method on `AccountAuthorizationPolicy`:
```rust
    /// Produces the policy after rotating the active transaction key.
    ///
    /// The revision advances by one (invalidating every session key bound to the
    /// old revision) and the post-quantum recovery root is preserved unchanged, so
    /// rotation can never silently drop portable recovery.
    pub fn rotate_active_key(
        &self,
        new_active_transaction_key: PublicKeyBytes,
    ) -> Result<Self, ChainError> {
        match self {
            Self::V1(policy) => {
                let revision = policy
                    .revision
                    .checked_next()
                    .ok_or(ChainError::InvalidAuthorizationPolicyRevision)?;
                let rotated = Self::V1(AccountAuthorizationPolicyV1 {
                    revision,
                    active_transaction_key: new_active_transaction_key,
                    post_quantum_root: policy.post_quantum_root,
                });
                rotated.validate()?;
                Ok(rotated)
            }
        }
    }
```
And the domain + message builder (mirror `session_key_authorization_message`):
```rust
pub const ACTIVE_KEY_ROTATION_DOMAIN: &str = "WEBC_ACTIVE_KEY_ROTATION_V1";

pub fn active_key_rotation_message(
    chain_id: &ChainId,
    owner: Address,
    policy_revision: AuthorizationPolicyRevision,
    nonce: u64,
    new_active_transaction_key: &PublicKeyBytes,
) -> Result<Vec<u8>, ChainError> {
    #[derive(Serialize)]
    struct RotationMessage<'a> {
        domain: &'a str,
        chain_id: &'a ChainId,
        owner: Address,
        policy_revision: AuthorizationPolicyRevision,
        nonce: u64,
        new_active_transaction_key: &'a PublicKeyBytes,
    }
    crate::canonical::canonical_json_bytes(&RotationMessage {
        domain: ACTIVE_KEY_ROTATION_DOMAIN,
        chain_id,
        owner,
        policy_revision,
        nonce,
        new_active_transaction_key,
    })
}
```

### `crates/webc-chain/src/transaction.rs`
Add the operation variant (after `RevokeSessionKey`):
```rust
    /// Rotates the account's active Ed25519 transaction key (recovery/rotation).
    ///
    /// Critical action: default lane, installed policy, and a post-quantum root
    /// signature over the exact new key. The envelope is signed by the *new* key
    /// (recovery without the old key); rotation advances the policy revision,
    /// invalidating outstanding session keys.
    RotateActiveTransactionKey {
        new_active_transaction_key: PublicKeyBytes,
        post_quantum_root_reveal: PostQuantumRootReveal,
    },
```
`required_units`: group with `InstallAuthorizationPolicy` → 25_000.
`default_access_list_for_lane`: add an arm
```rust
            Self::RotateActiveTransactionKey { .. } => {
                push_unique_key(&mut read_write, StateKey::account(sender));
                push_unique_key(&mut read_write, StateKey::authorization_policy(sender));
            }
```
and exclude it from the read-only-policy line:
`if !matches!(self, Self::InstallAuthorizationPolicy { .. } | Self::RotateActiveTransactionKey { .. }) { push read_only authorization_policy }`.

### `crates/webc-chain/src/state.rs`
Add to `use crate::authorization_policy::{...}` the name `active_key_rotation_message`
(or call it fully-qualified). Add `webc_crypto::PublicKeyBytes` to scope if needed.

`TransactionAuthorization` gains a variant:
```rust
    /// A recovery/rotation transaction whose envelope is signed by the *new* key
    /// and whose real authority is the post-quantum root signature verified inside
    /// the `RotateActiveTransactionKey` arm.
    PostQuantumRootRecovery,
```
In `verify_transaction_authorization`, after the active-key check and before the
session-key path:
```rust
        if let Operation::RotateActiveTransactionKey {
            new_active_transaction_key,
            ..
        } = &tx.operation
        {
            if &tx.public_key == new_active_transaction_key {
                return Ok(TransactionAuthorization::PostQuantumRootRecovery);
            }
            return Err(ChainError::AuthorizationKeyMismatch);
        }
```
At the top of `apply_verified_transaction`, record the policy key as a **write**
for rotation too:
```rust
        if matches!(
            &tx.operation,
            Operation::InstallAuthorizationPolicy { .. }
                | Operation::RotateActiveTransactionKey { .. }
        ) {
            access.write(StateKey::authorization_policy(tx.sender))?;
        } else {
            access.read(StateKey::authorization_policy(tx.sender))?;
        }
```
Add the `Event` variant (in `pub enum Event`):
```rust
    ActiveTransactionKeyRotated {
        owner: Address,
        new_revision: crate::AuthorizationPolicyRevision,
        new_active_transaction_key: webc_crypto::PublicKeyBytes,
    },
```
Add the apply arm (after the `RevokeSessionKey` arm):
```rust
            Operation::RotateActiveTransactionKey {
                new_active_transaction_key,
                post_quantum_root_reveal,
            } => {
                if !tx.authorization_lane.is_default() {
                    return Err(ChainError::ActiveKeyRotationRequiresDefaultLane);
                }
                let (policy_revision, root, current_active) = {
                    let policy = self
                        .authorization_policies
                        .get(&tx.sender)
                        .ok_or(ChainError::ActiveKeyRotationRequiresInstalledPolicy)?;
                    policy.validate()?;
                    (
                        policy.revision(),
                        *policy.post_quantum_root(),
                        *policy.active_transaction_key(),
                    )
                };
                if *new_active_transaction_key == current_active {
                    return Err(ChainError::ActiveKeyRotationToSameKey);
                }
                let message = active_key_rotation_message(
                    &config.chain_id,
                    tx.sender,
                    policy_revision,
                    tx.nonce,
                    new_active_transaction_key,
                )?;
                if !post_quantum_root_reveal.verify(&root, &message)? {
                    return Err(ChainError::InvalidPostQuantumRootReveal);
                }
                // Policy state key already recorded as a write at the top of apply.
                let rotated = self
                    .authorization_policies
                    .get(&tx.sender)
                    .ok_or(ChainError::ActiveKeyRotationRequiresInstalledPolicy)?
                    .rotate_active_key(*new_active_transaction_key)?;
                let new_revision = rotated.revision();
                self.authorization_policies.insert(tx.sender, rotated);
                events.push(Event::ActiveTransactionKeyRotated {
                    owner: tx.sender,
                    new_revision,
                    new_active_transaction_key: *new_active_transaction_key,
                });
            }
```
Then `cargo build -p webc-chain` and fix any *other* non-exhaustive matches the
compiler flags for the new `Operation`/`Event` variants (let the compiler find
them — likely none beyond the apply match).

## Tests (`state.rs` tests module) — mirror the session-key adversarial style

Reuse the session-key test helpers (`pq_keypair()`, `reveal_over_message`,
`installed_policy_state`). Sign the rotation message with the shared ML-DSA key:
```rust
    fn rotation_reveal(owner: Address, nonce: u64, new_key: PublicKeyBytes) -> PostQuantumRootReveal {
        let message = crate::active_key_rotation_message(
            &ChainId::devnet(), owner, AuthorizationPolicyRevision::new(1), nonce, &new_key,
        ).unwrap();
        reveal_over_message(&message)
    }
```
Build the rotation tx with `Transaction::new_unsigned_in_lane_on_chain(...)` on the
default lane, `authorization_policy_revision = 1`, `public_key = new_key`, then
`sign_with_policy_key(&new_keypair)` (envelope signed by the NEW key = recovery).
Cover:
- **recovery-without-old-key**: new key signs + valid root sig → succeeds; active
  key is now the new key; revision is 2.
- **rotation-with-current-key**: old active key signs + valid root sig → succeeds
  (AccountKey path).
- **session keys invalidated after rotation**: install a session key, rotate, then
  a session-signed transfer fails `AuthorizationKeyMismatch`.
- **old active key rejected after rotation**: a transfer signed by the old key
  fails `AuthorizationKeyMismatch`.
- **adversarial root sig**: signature over wrong new key / wrong nonce / wrong
  chain / wrong owner / garbage → `InvalidPostQuantumRootReveal`, state unchanged.
- **same-key** → `ActiveKeyRotationToSameKey`.
- **non-default lane** → `ActiveKeyRotationRequiresDefaultLane`.
- **no installed policy** → the auth path error or
  `ActiveKeyRotationRequiresInstalledPolicy` (check which fires first, assert it).
- **envelope signed by a third key** (neither old nor new) →
  `AuthorizationKeyMismatch`.
- **rollback + state-root change** on success; supply invariant unaffected.

## Full gate + commit
`cargo fmt`, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D
warnings`, `cargo test --workspace`, `RUSTDOCFLAGS="-D warnings" cargo doc
--workspace --no-deps`, `cargo run -p webc-node --quiet -- demo`, `cd sdk/webc-js
&& pnpm build`, `node scripts/check-doc-links.mjs`. The pre-existing
`wallet-service.test.ts` Node-22 failure is unrelated. Update
`docs/implementation-status.md`, `docs/continuation-guide.md`, and
`docs/session-keys-next-steps.md`; delete this file once landed. **Commit and push
frequently** — an earlier attempt was lost to a container reclaim; do not leave
this uncommitted for long.

## Adversarial review — RUN IT ISOLATED
When reviewing via the Workflow tool, spawn review agents with
`isolation: 'worktree'` **or** read-only tools. A prior un-isolated review edited
the main tree during "experiments" and left a stray `#[serde(skip)]` on the
session-key `constraints` field (a real bug), caught only because a new binding
test failed. Do not repeat that.

## Follow-up (after active-key rotation lands)
`RotatePostQuantumRoot { new_post_quantum_root, post_quantum_root_reveal }` —
rotate the recovery root itself, signed by the **current** root over the new
commitment; new domain `WEBC_POST_QUANTUM_ROOT_ROTATION_V1`. Deferred to keep the
active-key change small.

## Working style (standing user instructions)
- Speak simple Korean; explain any unavoidable technical term plainly.
- Only stop for genuinely user-owned decisions (confirmed monetary policy, genesis
  distribution, mainnet emergency powers). Proceed autonomously otherwise.
- Commit and push after each coherent, tested step (this work was lost once for
  not doing so — commit early).
- When using subagents for long work, have each write its own progress to a file,
  and isolate any agent that can mutate files.
