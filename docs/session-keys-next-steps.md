# Session-key work: resume point (for the next session)

This file is the durable handoff for continuing the constrained session-key work.
Read it together with `docs/session-keys-implementation-plan.md` (the full design)
and `docs/implementation-status.md`. Chat history is not the source of truth; this
file is.

## Where things stand

- **Done and committed** (`ecdd8fc`, pushed to `claude/docs-session-keys-plan-ppk0dl`):
  plan steps 1–5 of `session-keys-implementation-plan.md` §13 — the full on-chain
  single-node state machine for constrained session keys, plus 20 Rust tests and
  an adversarial review with two medium findings fixed (unbounded fee drain →
  cumulative `total_fee_budget`; non-default-lane transfer access-list bug).
- **Gates last green**: `cargo fmt --check`, strict clippy, 98 Rust tests, rustdoc
  (warnings denied), node demo; both TS packages build; cross-language state-key
  vector passes. One pre-existing TS test (`wallet-service.test.ts`) fails only on
  Node 22 (repo wants Node 24) — unrelated to this work.
- **Working tree is clean.** Nothing uncommitted.

## Remaining plan steps (do in this order, commit + push after each)

### Step 6 — real ML-DSA root **signature** gate (highest value, do first)

Why it matters: today `PostQuantumRootReveal` only proves knowledge of the root
**public** key. A public key is public — anyone can copy it from on-chain history —
so the current gate is cryptographically weak. The real gate is an ML-DSA
**signature** by the private root key over the exact critical action. This defends
the actual threat: a compromised active Ed25519 key must not be able to authorize
a new critical action (install/revoke session key).

Concrete build:

1. **Dependency**: `fips204 = { version = "0.4.6", default-features = false,
   features = ["ml-dsa-65", "default-rng"] }` in `crates/webc-crypto/Cargo.toml`.
   Confirmed available via `cargo` (crates.io HTTP API is blocked, but the cargo
   index works; `cargo add --dry-run` succeeded). `default-rng` is only for
   keygen/signing (wallet/tests); verification is deterministic and uses no RNG,
   so consensus stays deterministic. Pin it; note it as the named ML-DSA-65
   candidate, devnet-only, no post-quantum-security claim.

2. **`crates/webc-crypto/src/mldsa.rs`** (new module, replaceable crypto boundary):
   - `pub const ML_DSA_65_PUBLIC_KEY_LEN` / `ML_DSA_65_SIGNATURE_LEN` (from
     `fips204::ml_dsa_65::{PK_LEN, SIG_LEN}`; expect 1952 / 3309).
   - `pub fn ml_dsa65_verify(public_key: &[u8], message: &[u8], signature: &[u8],
     context: &[u8]) -> Result<bool, CryptoError>` — length-check first, then
     `PublicKey::try_from_bytes` + `pk.verify(msg, &sig, ctx)`. Deterministic.
   - Wallet/test helpers: `ml_dsa65_keygen() -> (pub, secret)` and a secret type
     with `.sign(msg, ctx) -> Vec<u8>` and a public type with `.to_bytes()`.
     Do **not** derive `Debug`/`Serialize`/`Clone` on the secret key.
   - fips204 0.4 API: `use fips204::ml_dsa_65; use fips204::traits::{SerDes,
     Signer, Verifier};` — `ml_dsa_65::try_keygen()` → `(PublicKey, PrivateKey)`;
     `sk.try_sign(&msg, &ctx)` → `[u8; SIG_LEN]`; `pk.verify(&msg, &sig, &ctx)` →
     `bool`; `pk.into_bytes()` / `PublicKey::try_from_bytes(bytes)`. Verify the
     exact signatures on first compile and adjust.
   - Export from `webc-crypto/src/lib.rs`.

3. **`crates/webc-chain/src/authorization_policy.rs`**: change
   `PostQuantumRootReveal` to `{ scheme, public_key: Vec<u8> (hex), signature:
   Vec<u8> (hex) }`. Add `MAX_POST_QUANTUM_SIGNATURE_BYTES` (~4096). `validate()`
   bounds both fields before any crypto. Replace `matches(&root)` with
   `verify(&self, root: &PostQuantumRoot, message: &[u8]) -> Result<bool>`:
   (1) size checks; (2) scheme == root.scheme; (3)
   `PostQuantumRoot::commit(scheme, &public_key) == root.public_key_hash`;
   (4) `webc_crypto::ml_dsa65_verify(&public_key, message, &signature, b"")`.
   Keep `WEBC_POST_QUANTUM_ROOT_V1` commitment domain.

4. **Canonical authorization message** (builder in
   `crates/webc-chain/src/session_key.rs`):
   `session_key_authorization_message(chain_id, owner, policy_revision, nonce,
   action) -> Result<Vec<u8>>`, where `action` is
   `enum SessionKeyAuthorizationAction { Install { session_public_key,
   constraints }, Revoke { session_key } }`. Serialize a struct with fields
   `domain: "WEBC_SESSION_KEY_AUTHORIZATION_V1"`, `chain_id`, `owner`,
   `policy_revision`, `nonce`, `action` via `crate::canonical::canonical_json_bytes`.
   Pass empty ML-DSA context (domain lives in the message).

   **Replay binding**: the message binds `chain_id + owner + policy_revision +
   tx.nonce + action`. Install/revoke require the default lane, so `tx.nonce` is
   the account nonce and is single-use; a captured PQ signature cannot be replayed
   (a second tx at that nonce fails `NonceMismatch`), and it cannot be moved to a
   different action because the action is signed.

5. **`crates/webc-chain/src/state.rs`** install/revoke arms: build the message
   from `(config.chain_id, tx.sender, policy.revision(), tx.nonce, action)` and
   call `reveal.verify(&root, &message)?` instead of `matches`. Everything else
   (default-lane gate, installed-policy gate, constraints, count cap) stays.

6. **Tests**: generate an ML-DSA-65 keypair in the helper; install the policy with
   `PostQuantumRoot::from_public_key(MlDsa65, &ml_dsa_pub_bytes)`; for each
   install/revoke, sign the authorization message with the ML-DSA secret key and
   put `{pubkey, signature}` in the reveal. Update `pq_reveal()` so it takes the
   action + nonce context (it must sign the exact message the chain rebuilds).
   Add adversarial tests: (a) valid pubkey but signature over the **wrong
   action/nonce** → rejected (proves binding); (b) wrong pubkey → rejected;
   (c) garbage signature → rejected. All fail closed with
   `InvalidPostQuantumRootReveal` and roll back.

7. **Docs**: update `session-keys-implementation-plan.md` §5.5 and §14 (gate is
   now a real signature, not commitment-only; ML-DSA-65 crate added behind the
   replaceable crypto boundary; still devnet-only, replaceable, no PQ-security
   claim), `implementation-status.md`, and this file.

Watch-outs: fips204 signatures are ~3.3 KB, so the InstallSessionKey operation and
its canonical tx bytes grow — fine for devnet. The workspace `forbid(unsafe)` lint
applies to our crates, not to the fips204 dependency. Strict clippy must stay
clean.

### Step 7 — optional expiry pruning
Epoch-boundary sweep in `finish_epoch` dropping session keys whose
`expires_after_epoch < current_epoch`, deterministic and restart-stable. Not
needed for correctness (use-time check already rejects expired keys); it only
bounds map growth. Add a restart-equivalence test.

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

### Sibling (outside the session-key plan, next per continuation-guide)
Primary-key **recovery and rotation** operations in Rust. Session keys already
invalidate when the policy revision changes, so wire the revision bump through
rotation and add tests.

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
