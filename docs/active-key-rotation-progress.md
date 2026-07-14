# Active-key recovery/rotation: in-progress resume point

This is the durable handoff for the **primary-key recovery and rotation** work
(the "sibling" item after the session-key gate in `docs/continuation-guide.md`).
Read it with `docs/session-keys-next-steps.md` and the Phase 2 section of
`docs/implementation-status.md`. Chat history is not the source of truth; this
file is.

## Status: UNFINISHED, uncommitted work in the tree — DOES NOT COMPILE YET

- Base commit (pushed): `6e54004` (the ML-DSA-65 root-signature gate). The
  rotation work is **uncommitted** on top of it, on branch
  `claude/docs-session-keys-plan-ppk0dl`.
- Four files have WIP edits: `lib.rs`, `transaction.rs`, `authorization_policy.rs`,
  `state.rs`. The tree **will not compile** until the two remaining code pieces
  below are added (the `Operation` match in `apply_verified_transaction` is
  non-exhaustive without the new arm, and the `Event` variant is missing).
- Do **not** commit until it compiles, the full gate is green, and the adversarial
  review passes.

## What this feature is (design + security, decided — do not re-derive)

`Operation::RotateActiveTransactionKey { new_active_transaction_key,
post_quantum_root_reveal }` rotates the account's sole active Ed25519 key. It is
the **recovery path** when the active key is lost or compromised, and it is gated
exactly like session-key install/revoke: default lane, installed policy, and a
**real ML-DSA-65 root signature** over the exact action.

Key decisions (all confirmed against `docs/decision-record.md` line 120 —
recovery and key rotation are root-gated critical actions):

1. **Recovery works without the old key.** The transaction envelope may be signed
   by the *new* key (proving the recoverer controls it); the root signature is the
   real authority. This required a new `verify_transaction_authorization` path
   (already written) returning `TransactionAuthorization::PostQuantumRootRecovery`
   — produced **only** for `RotateActiveTransactionKey` and only when
   `tx.public_key == new_active_transaction_key`. If the current active key signs
   instead, the ordinary `AccountKey` path is taken; both converge on the arm's
   root-signature check.
2. **Rotation bumps the policy revision**, which invalidates every outstanding
   session key (they check `session.policy_revision == policy.revision()`). The
   post-quantum root is **preserved** (never silently dropped —
   `decision-record.md` line 111).
3. **Session keys can never rotate.** `enforce_session_key_use` runs before the
   operation match (`state.rs` ~line 1155) and `session_permitted_principal`
   allows only `Transfer`, so a session-signed rotation is rejected with
   `SessionKeyOperationNotPermitted`. (Confirmed; no code needed.)
4. **Replay binding.** `active_key_rotation_message` binds domain
   (`WEBC_ACTIVE_KEY_ROTATION_V1`) + chain id + owner + current policy revision +
   nonce + the exact new key. A captured signature cannot move to another key,
   nonce, account, chain, or post-rotation revision.
5. **Reject rotating to the same key** (`ActiveKeyRotationToSameKey`) to keep the
   action meaningful.
6. `required_units` = 25_000 (same tier as `InstallAuthorizationPolicy`).

## DONE so far (uncommitted, in the tree)

- **`lib.rs`**: added `ChainError::ActiveKeyRotationRequiresDefaultLane`,
  `ActiveKeyRotationRequiresInstalledPolicy`, `ActiveKeyRotationToSameKey`; and
  exported `active_key_rotation_message` + `ACTIVE_KEY_ROTATION_DOMAIN` from
  `authorization_policy`.
- **`transaction.rs`**: added `Operation::RotateActiveTransactionKey { ... }`;
  `required_units` arm (25_000, grouped with `InstallAuthorizationPolicy`);
  `default_access_list_for_lane` arm (read_write `account` + `authorization_policy`)
  and excluded rotation from the read-only-policy line.
- **`authorization_policy.rs`**: `ACTIVE_KEY_ROTATION_DOMAIN`,
  `active_key_rotation_message(chain_id, owner, policy_revision, nonce, new_key)`,
  and `AccountAuthorizationPolicy::rotate_active_key(new_key)` (bumps revision via
  `checked_next`, keeps the root, re-validates). Imports widened to `ChainId`,
  `Address`.
- **`state.rs`**: added `TransactionAuthorization::PostQuantumRootRecovery`; added
  the recovery path in `verify_transaction_authorization` (after the active-key
  check, before the session-key path); extended the top-of-`apply` policy-key
  access to record a **write** for rotation (grouped with
  `InstallAuthorizationPolicy`).

## REMAINING — finish these, in order

### 1. Add the `Event` variant (`state.rs`, in `pub enum Event`, after `SessionKeyUsed`/`SessionKeyRevoked`)

```rust
    ActiveTransactionKeyRotated {
        /// Account whose active transaction key was rotated.
        owner: Address,
        /// New policy revision after the rotation (invalidates old session keys).
        new_revision: crate::AuthorizationPolicyRevision,
        /// The new sole active Ed25519 transaction key.
        new_active_transaction_key: webc_crypto::PublicKeyBytes,
    },
```

(If `PublicKeyBytes` is not yet in scope in `state.rs`, either use the
fully-qualified `webc_crypto::PublicKeyBytes` as above, or add it to the
`use webc_crypto::{...}` line.)

### 2. Add the apply arm (`state.rs`, in the `match &tx.operation` inside `apply_verified_transaction`, after the `RevokeSessionKey` arm)

Add `active_key_rotation_message` to the `use crate::authorization_policy::{...}`
import (currently only `AccountAuthorizationPolicy`), or call it as
`crate::active_key_rotation_message(...)`.

```rust
            Operation::RotateActiveTransactionKey {
                new_active_transaction_key,
                post_quantum_root_reveal,
            } => {
                // Critical action: default lane, installed policy, and a real
                // ML-DSA root signature over the exact new key. The envelope may
                // be signed by the new key (recovery without the old key); the
                // root signature is the authority, not the active key.
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
                // The policy state key is already recorded as a write at the top
                // of apply, mirroring InstallAuthorizationPolicy.
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
compiler flags for the new `Operation`/`Event` variants (there may be matches in
`block_builder.rs`, event handling, or elsewhere — let the compiler find them).

### 3. Tests (`state.rs` tests module) — mirror the session-key adversarial style

A test-helper for signing the rotation message with the shared ML-DSA key is
needed (reuse `pq_keypair()` from the session-key tests, in the same module):

```rust
    fn rotation_reveal(owner: Address, nonce: u64, new_key: PublicKeyBytes) -> PostQuantumRootReveal {
        let message = crate::active_key_rotation_message(
            &ChainId::devnet(), owner, AuthorizationPolicyRevision::new(1), nonce, &new_key,
        ).unwrap();
        reveal_over_message(&message) // reuse the session-key helper
    }
```

Build the rotation tx with `Transaction::new_unsigned_in_lane_on_chain(...)` on the
default lane, `authorization_policy_revision = 1`, `public_key = new_key`, then
`sign_with_policy_key(&new_keypair)` so the envelope is signed by the NEW key
(recovery path). Cover:

- **recovery-without-old-key**: new key signs envelope + valid root sig →
  succeeds; policy active key is now the new key; revision is 2.
- **rotation-with-current-key**: old active key signs envelope + valid root sig →
  succeeds (AccountKey path).
- **session keys invalidated after rotation**: install a session key, rotate, then
  a session-signed transfer fails `AuthorizationKeyMismatch` (revision moved).
- **old active key rejected after rotation**: a normal transfer signed by the old
  active key fails `AuthorizationKeyMismatch`.
- **adversarial root sig**: signature over wrong new key / wrong nonce / wrong
  chain / wrong owner / garbage → `InvalidPostQuantumRootReveal`, state unchanged.
- **same-key** → `ActiveKeyRotationToSameKey`.
- **non-default lane** → `ActiveKeyRotationRequiresDefaultLane`.
- **no installed policy** → `ActiveKeyRotationRequiresInstalledPolicy` (or the
  no-policy auth path error — check which fires first and assert that).
- **envelope signed by a third key** (neither old active nor new) →
  `AuthorizationKeyMismatch` from `verify_transaction_authorization`.
- **rollback + state-root change** on success; `supply_invariant_report().balanced`
  unaffected (rotation moves no funds beyond the fee).

### 4. Full gate

`cargo fmt`, `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D
warnings`, `cargo test --workspace`, `RUSTDOCFLAGS="-D warnings" cargo doc
--workspace --no-deps`, `cargo run -p webc-node --quiet -- demo`, and the TS build
(`cd sdk/webc-js && pnpm build`) + `node scripts/check-doc-links.mjs`. The
pre-existing `wallet-service.test.ts` Node-22 failure is unrelated.

### 5. Docs + commit + push

Update `docs/implementation-status.md` (Phase 2 section + gate note + test count),
`docs/continuation-guide.md` (mark recovery/rotation done, name the next work),
and `docs/session-keys-next-steps.md` (Sibling section → done). Delete or shrink
this progress file once landed. Commit with a focused message and push to
`claude/docs-session-keys-plan-ppk0dl`.

### 6. Adversarial review — RUN IT ISOLATED THIS TIME

When reviewing via the Workflow tool, spawn the review agents with
`isolation: 'worktree'` **or** restrict them to read-only tools. In the previous
session the un-isolated review agents edited the main tree during their
"experiments" and left a stray `#[serde(skip)]` on the session-key
`constraints` field (a real bug), which was only caught because a new binding
test failed. Do not repeat that: isolate mutating-capable review agents.

## Follow-up (after active-key rotation lands)

Consider `RotatePostQuantumRoot { new_post_quantum_root, post_quantum_root_reveal }`
— rotating the recovery root itself, signed by the **current** root over the new
commitment. Same message/verify pattern, new domain
`WEBC_POST_QUANTUM_ROOT_ROTATION_V1`. This completes root-key hygiene but was
intentionally deferred to keep the active-key rotation change small.

## Working style (standing user instructions)
- Speak simple Korean; explain any unavoidable technical term plainly.
- Only stop for genuinely user-owned decisions (confirmed monetary policy, genesis
  distribution, mainnet emergency powers). Proceed autonomously otherwise.
- Commit and push after each coherent, tested step.
- When using subagents for long work, have each write its own progress to a file so
  it can resume after an interruption or usage-limit reset — and isolate any agent
  that can mutate files.
