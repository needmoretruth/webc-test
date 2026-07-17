# ADR-0009: node and validator key management

Status: accepted for the provisioning design; implementation gated to the
validator-operations phase (mainnet readiness). Devnet keeps its current
per-process identity.

## Context

A running node uses two kinds of long-lived Ed25519 keys:

- a **network identity** key that names the node on the peer-to-peer wire, and
- a **validator consensus** key that signs proposals, prevotes, and precommits —
  the key whose double-signing is objective slashable evidence (ADR-0002).

Today (`webc-node`) the network identity is a fresh `Keypair::generate()` per
process and the devnet faucet uses a hard-coded seed `[7u8; 32]` for valueless
test units. Neither is a production validator-key story. Finding H5 flagged that
no real consensus-key provisioning path exists.

The dominant failure mode for validator keys is not cryptographic — it is
operational leakage: a seed on the command line is visible in `ps` and shell
history; an environment variable leaks into crash dumps, child processes, and
logging middleware; a key committed to config or an image is exfiltrated
wholesale. WEBC's own wallet stack already solved the analogous browser problem
with an Argon2id-hardened, AAD-bound, versioned keystore (ADR-0004), and the
project's pitfall list already forbids secrets in argv/env/logs/`Debug`.

## Decision

Provision validator/consensus keys from a **permissioned keystore file**, never
from argv or an environment variable.

1. **On-disk form.** The consensus key is stored in an encrypted keystore file
   with `0600` permissions in a node-operator-controlled directory. The file
   format reuses the SDK keystore discipline: a versioned envelope, an
   Argon2id-derived key with a distinct purpose label (finding S3), AES-256-GCM
   with the KDF parameters and salt bound as additional authenticated data, and a
   strict decoder that rejects unknown fields and hostile cost parameters before
   doing KDF work.
2. **Unlock.** The node reads the passphrase from an interactive prompt or a
   file descriptor / named pipe the operator controls — never a command-line
   flag (`ps`-visible) and never a plain environment variable. A future systemd
   integration may use `LoadCredentialEncrypted=`.
3. **In memory.** The decrypted signing key stays in a purpose-built secret type
   that is never `Debug`, `Serialize`, or `Clone`, is zeroized on drop where the
   underlying crate supports it, and is held only by the consensus signer. (Note:
   `ed25519_dalek::SigningKey` is not zeroized on drop; wrap it or migrate to a
   zeroizing variant when this lands.)
4. **Network identity vs. consensus key are distinct** keys with distinct files,
   so rotating the wire identity never touches slashable consensus material.
5. **Rotation.** Consensus-key rotation is an on-chain validator operation
   (already modeled by the versioned validator record's `consensus_key`); the
   keystore file is re-issued out of band and the on-chain key updated through
   the normal signed path. The equivocation checker must verify against the
   snapshot that was active at the offense height, not the current key (a note
   already recorded in `findings.md` under the equivocation-path verification).

## Consequences

- No validator secret is ever visible in `ps`, shell history, a crash dump, or a
  log line, closing the dominant real-world leakage vectors.
- The node depends on a passphrase source at start-up; an operator that wants
  unattended restart must supply it through an OS credential mechanism, which is
  the intended trade-off (availability convenience must not reintroduce a
  plaintext seed on disk or in the environment).
- Devnet is unaffected: it keeps the documented valueless per-process identity
  and hard-coded faucet seed. This ADR governs the mainnet/validator path and is
  implemented at the validator-operations phase, not before its gate.
