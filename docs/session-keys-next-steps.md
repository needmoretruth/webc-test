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
- **Gates last green**: Rust — `cargo fmt --check`, strict clippy, 133 Rust tests
  (120 `webc-chain` + 13 `webc-crypto`), rustdoc (warnings denied), node demo;
  cross-language state-key vector passes. TypeScript (Node 22) — both packages
  build, SDK suite 69/69, widget 3/3, package-entry + Markdown-link checks pass.
  The formerly "Node 22-only" `wallet-service.test.ts` failure was a real
  host-client schema bug (missing `authorization_policy_revision`), now fixed.
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

### Step 9 — browser/SDK session-key surface — DONE
The TypeScript SDK now builds every session-key and rotation operation with
byte-identical canonical encoding to Rust:
- `types.ts` adds `SessionKeyIdJson`, `SessionAllowedOperationsJson`,
  `SessionKeyConstraintsJson`, `PostQuantumRootRevealJson`, and the four new
  `OperationJson` variants (`InstallSessionKey`, `RevokeSessionKey`,
  `RotateActiveTransactionKey`, `RotatePostQuantumRoot`).
- `transaction.ts` adds the four operation constructors, a `sessionKeyKey`
  state-key helper, `deriveSessionKeyIdHex` (matching Rust `SessionKeyId::derive`),
  and access-list logic (rotations write the policy and are excluded from
  read-only; install derives its session-key id and needs the async builder).
- `session-key.ts` adds `generateSessionSubkey` (non-extractable Ed25519 via the
  `wallet.ts` pattern), `sessionSubkeyPublicKeyHex`, `sessionSubkeyIdHex`, and
  `describeSessionKeyExpiry` (epoch-based; never wall-clock).
- Cross-language fixtures pin byte-parity: a Rust test hashes the four operations
  with deterministic placeholder bytes and the SDK test asserts the identical
  canonical hash; a second pair pins the session-key id derivation.

Deliberately out of scope: producing the ML-DSA root reveal in the browser
(signing with the recovery root is heavy WASM and lives outside this SDK — the
constructors accept a reveal the owner produces elsewhere). Session subkeys sign
transfers through the normal `signTransaction` flow.

### Step 8 — benchmarks — tool landed; reference numbers still pending
`webc-node bench [--iterations N]` times Ed25519 sign/verify against ML-DSA-65
keygen/sign/verify and prints per-op microseconds, the verify/sign ratios, and
the key/signature sizes. It is prominently labelled indicative — **not** a
reference machine and **not** a performance claim.

Indicative ratios observed in this dev container (release build, ~300–500
iterations; do not cite as a claim): ML-DSA-65 verify ≈ 4–4.5× Ed25519 verify,
ML-DSA-65 sign ≈ 34–36× Ed25519 sign, signature 3309 B vs 64 B, public key
1952 B vs 32 B. Design takeaway: ML-DSA-65 is used only for the root signature on
rare critical actions (session-key install/revoke, active-key and root rotation),
never per ordinary Ed25519 transaction, so its cost and size are amortised.

Still to do on a real reference machine (`development-plan.md` §Phase 6): capture
session-key transaction verification vs an ordinary Ed25519 transfer end to end,
and publish reference numbers before making any performance claim.

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

### Sibling (Phase 2 wallet gate) — durable permission storage + auto lane — DONE
Persistent encrypted per-origin permission storage and automatic
authorization-lane setup landed in the SDK, the last outstanding Phase 2
wallet-wire/secret-isolation gate:
- `sdk/webc-js/src/permission-store.ts` — encrypted-at-rest grant store v1
  (AES-256-GCM under Argon2id via the shared `argon2.ts` gate), identity-bound as
  AES-GCM additional data, strict bounded schema, key-caching `openPermissionStore`
  port so per-spend saves need no repeated KDF.
- `TrustedWalletService` gains `persistence` + `restoredGrants`: dormant restore
  (lane + cumulative spend survive a restart; reconnect required before signing),
  persist after every connect/spend/revoke inside the serial queue, cumulative
  spend carried across reconnects (only revoke clears a grant), and transactional
  rollback on durable-write failure.
- Also fixed a real host-client schema bug in the same area (connection and
  signed-transaction result parsers omitted `authorization_policy_revision`),
  which had failed the end-to-end exchange on every Node version — not a Node 22
  issue. SDK suite is now 69/69.

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
