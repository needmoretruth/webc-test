# Session-key work: resume point (for the next session)

This file is the durable handoff for continuing the constrained session-key work.
Read it together with `docs/session-keys-implementation-plan.md` (the full design)
and `docs/implementation-status.md`. Chat history is not the source of truth; this
file is.

## Where things stand

- **Done and committed** (`ecdd8fc`): plan steps 1–5 of
  `session-keys-implementation-plan.md` §13 — the full on-chain single-node state
  machine for constrained session keys, plus Rust tests and an adversarial review
  with two medium findings fixed (unbounded fee drain → cumulative
  `total_fee_budget`; non-default-lane transfer access-list bug).
- **Done — step 6, the real ML-DSA-65 root *signature* gate** (this session, on
  `claude/docs-session-keys-plan-ppk0dl`): `PostQuantumRootReveal` now carries a
  signature and verifies it under the committed root over the exact action. See
  "Step 6 — DONE" below for exactly what shipped.
- **Gates last green**: `cargo fmt --check`, strict clippy, 115 Rust tests (102
  `webc-chain` + 13 `webc-crypto`), rustdoc (warnings denied), node demo; both TS
  packages build; cross-language state-key vector passes. One pre-existing TS test
  (`wallet-service.test.ts`) fails only on Node 22 (repo wants Node 24) —
  unrelated to this work.
- **Working tree is clean** after each committed step.

## Remaining plan steps (do in this order, commit + push after each)

### Step 6 — real ML-DSA root **signature** gate — DONE

Shipped this session. What exists now (do not redo):

- `crates/webc-crypto/src/mldsa.rs` wraps the pinned `fips204` ML-DSA-65 crate:
  `ml_dsa65_verify(pk, msg, sig, ctx) -> Result<bool, CryptoError>` (deterministic,
  length-checked, fails closed on unparseable key), plus `ml_dsa65_keygen()` and a
  non-`Debug`/`Serialize`/`Clone` `MlDsa65SecretKey::sign`. Exported from
  `webc-crypto`. `fips204 = { version = "0.4.6", default-features = false,
  features = ["ml-dsa-65", "default-rng"] }` pinned in the workspace + crate.
- `PostQuantumRootReveal` is now `{ scheme, public_key (hex), signature (hex) }`.
  `verify(&self, root, message) -> Result<bool>` bounds both fields, checks the
  scheme, binds the public key to the stored commitment, then verifies the
  signature via the `mldsa` boundary. `matches` is gone.
  `MAX_POST_QUANTUM_SIGNATURE_BYTES` added.
- `session_key_authorization_message(chain_id, owner, policy_revision, nonce,
  action)` in `session_key.rs` builds the canonical signed bytes under
  `WEBC_SESSION_KEY_AUTHORIZATION_V1`; `SessionKeyAuthorizationAction` is
  `Install { session_public_key, constraints }` / `Revoke { session_key }`.
- Both install/revoke arms in `state.rs` build the message from
  `(config.chain_id, tx.sender, policy.revision(), tx.nonce, action)` and call
  `reveal.verify(&root, &message)?`.
- Tests: a process-wide ML-DSA keypair via `OnceLock`; `installed_policy_state`
  commits the root to the real public key; adversarial tests reject wrong-action,
  wrong-nonce, wrong-key, and garbage-signature reveals with rollback; a dedicated
  `install_session_key_binds_signature_to_constraints_owner_and_chain` test proves
  the signature also binds the exact constraints, owner, and chain id (an
  adversarial review found these three axes were unguarded — the test now closes
  that gap); a focused
  `reveal_verifies_only_a_real_root_signature_over_the_message` in
  `authorization_policy.rs`; seven `mldsa` unit tests.

Replay binding (unchanged reasoning, now enforced): the message binds `chain_id +
owner + policy_revision + tx.nonce + action`. Install/revoke require the default
lane, so `tx.nonce` is the account nonce and single-use; a captured signature
cannot be replayed at another nonce, moved to another action, or reused after a
rotation (different `policy_revision`).

### Step 7 — expiry pruning — DONE
`finish_epoch` now sweeps session keys whose `expires_after_epoch < next_epoch`
and removes them, emitting a `SessionKeyExpired` event per key. It is
deterministic (pure function of committed `next_epoch`, sorted iteration) and
restart-stable, and it changes no authorization outcome because the use-time
check already rejects expired keys — it only bounds map growth. A
restart-equivalence test advances a live state and a bincode-restored copy across
the same boundary and asserts identical state, root, and events.

### Step 8 — benchmarks
Session-key transaction verification vs ordinary Ed25519 transfer; and (after
step 6) ML-DSA-65 verify/sign vs Ed25519. Use the reference machines in
`development-plan.md` §Phase 6. Publish numbers before any policy claim.

### Step 9 — browser/SDK session-key surface
Session subkey generation (non-extractable Ed25519 via existing `wallet.ts`
pattern), install/session-signing helpers, expiry display, and the TS
`OperationJson` + cross-language fixtures for `InstallSessionKey`/`RevokeSessionKey`
and the new `PostQuantumRootReveal` shape. Note: ML-DSA signing in the browser
(for install/revoke) is heavy (WASM); scope it explicitly. The TS state-key
`SessionKey` variant already exists.

### Sibling (outside the session-key plan) — DONE
Primary-key **recovery and rotation** is implemented.
`Operation::RotateActiveTransactionKey` replaces the active Ed25519 key, gated by
the default lane, an installed policy, and a real ML-DSA-65 root signature over
`active_key_rotation_message` (`WEBC_ACTIVE_KEY_ROTATION_V1`). Recovery works
without the old key via a new-key-signed envelope and a `PostQuantumRootRecovery`
authorization path; rotation bumps the policy revision (invalidating session
keys) and preserves the recovery root. Eight adversarial tests pass. The
from-scratch recipe that used to live here has been removed now that the work has
landed; the implementation is in `crates/webc-chain/src/{state,transaction,
authorization_policy}.rs`.

### Sibling — rotate the post-quantum root itself — DONE
`RotatePostQuantumRoot { new_post_quantum_root, post_quantum_root_reveal }` is
implemented. It replaces the committed recovery root while preserving the active
Ed25519 key, gated by the default lane, an installed policy, and a signature by
the **current** root over `post_quantum_root_rotation_message`
(`WEBC_POST_QUANTUM_ROOT_ROTATION_V1`). The envelope is signed by the current
active key, so replacing the root needs both the current root and the active
key. Rotation bumps the revision (invalidating session keys) and rejects a
same-root no-op. Seven adversarial tests pass, including an end-to-end test
proving the new root gains authority while the old root loses it. With
`RotateActiveTransactionKey`, both halves of the policy can now be recovered
independently.

## Working style (standing user instructions for this work)
- Only stop for decisions that are genuinely the user's (confirmed monetary
  policy, genesis distribution rules, mainnet emergency-power design). Everything
  else — including the ML-DSA-65 crate choice, already a named candidate — proceed
  autonomously.
- Commit and push after each coherent step.
- When using subagents for long work, have each subagent write its own progress to
  a file as it goes, so it can resume after an interruption or a usage-limit reset.
- Speak simple Korean to the user and explain any unavoidable technical term in
  plain words.
