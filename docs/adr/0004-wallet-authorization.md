# ADR-0004: versioned wallet authorization

Status: accepted direction; normal post-quantum transaction policy remains a benchmark gate

Accounts reference a versioned authorization policy instead of permanently
binding an address to one signature algorithm. A standard wallet starts with a
post-quantum root/recovery branch. Limited session keys may act only within
explicit origin, operation, amount, fee, and expiry constraints.

Host-site JavaScript never receives seeds, private keys, or decrypted
keystores. Signing occurs in a trusted isolated origin and displays the exact
request. Every signed payload includes a protocol version, domain, and chain ID.

Transaction wire V3 signs `protocol_version` and canonical `chain_id` inside
`WEBC_SIGNED_TRANSACTION_V3`. Rust rejects unsupported versions and any signed
chain ID that differs from active configuration before state mutation. The
browser SDK applies the same chain-ID alphabet and version check before signing
or verifying; changing either field invalidates the signature.

## Phase 2 classical recovery boundary

- New recovery phrases use 256 bits of CSPRNG entropy and the 24-word English
  BIP-39 list. Imported phrases validate their checksum before derivation.
- BIP-39's optional passphrase remains supported and significant; the wallet
  cannot detect a wrong passphrase because every value deterministically creates
  a different wallet.
- Ed25519 children use hardened-only SLIP-0010 derivation through pinned reviewed
  libraries, not a project-specific derivation algorithm.
- Until WEBC receives a registered SLIP-44 mainnet coin type, devnet V1 uses the
  registered all-chain testnet coin type at `m/44'/1'/account'/0'/index'`.
  Mainnet must introduce a new named derivation version rather than changing V1.
- The public wallet object contains only address and public key. Its
  non-extractable WebCrypto signing handle is held in a module-private weak map.
- Mutable seed/key/chain-code buffers are cleared after import where JavaScript
  permits. Immutable mnemonic and passphrase strings cannot be reliably erased,
  so derivation stays inside the trusted wallet origin.

Classical derivation and encrypted persistence are only foundations. Isolated
request UI, recovery policy, and post-quantum root creation remain required
before this can be called a standard WEBC wallet.

## Encrypted keystore v1

Keystore v1 encrypts the validated BIP-39 phrase, optional mnemonic passphrase,
and account/index inside a strict authenticated envelope:

- password KDF: Argon2id version 19, 19,456 KiB, 2 iterations, 1 lane, unique
  16-byte salt, and 32-byte output;
- encryption: WebCrypto AES-256-GCM, unique 12-byte IV, 128-bit tag;
- authenticated additional data: format/version, complete fixed KDF and cipher
  metadata, public address/key, derivation scheme, and exact path;
- parser limits: exact field sets, a 16 KiB JSON ceiling, a 4 KiB ciphertext
  ceiling, exact lowercase hex lengths, and exact v1 KDF costs before KDF work;
- failure behavior: wrong password and authenticated tampering share one error,
  while malformed/unsupported schemas fail before expensive work;
- concurrency: Argon2 jobs are serialized because the reviewed JavaScript
  implementation uses a shared scratch block.

The 19 MiB/t=2 profile is an OWASP-listed minimum Argon2id profile. On the
2026-07-13 Windows development host it measured about 790 ms; the alternative
47 MiB/t=1 profile measured about 1,419 ms. These are development measurements,
not universal performance claims. Mobile/browser benchmarks can introduce a new
keystore version but must not let untrusted files select arbitrary costs.

## Isolated host request protocol v1

The supported host integration no longer gives a site a `WebcWallet` or key
handle. The host opens a top-level wallet popup on a different trusted HTTPS
origin and communicates through strict `postMessage` objects:

- the wallet trusts only browser-supplied `MessageEvent.origin` and exact
  `window.opener`; host-supplied origin text is absent from the wire;
- HTTP is rejected except loopback localhost development, opaque `null` origins
  are ignored, responses use the exact requesting origin and never `*`;
- every request has a 32-byte random ID, and every approved connection receives
  a wallet-generated session ID plus a monotonic signing sequence;
- one permission scope exists in v1: native WEBC transfers. The wallet builds
  the operation and access list itself; arbitrary-byte and host-description
  signing methods do not exist;
- each origin receives a deterministic lane derived from a domain-separated
  wallet signature of the browser-authenticated origin. Another origin cannot
  choose or reuse that lane through the supported service;
- grants cap principal per transaction, cumulative principal for the grant, and
  maximum fee per transaction using exact base-unit integers;
- every connection and every transfer still requires explicit trusted UI
  approval. The transfer screen derives origin, action, recipient, amount,
  asset, maximum fee, chain, and lane from the exact signing fields;
- service requests are serialized so cumulative limits and session sequences
  cannot race. Host clients retry the same ID while a popup loads, then verify
  the returned Ed25519 transaction and exact requested fields;
- the trusted service refuses framed execution and requires a top-level popup,
  reducing host-controlled overlay/clickjacking risk and keeping the wallet
  address-bar origin visible.

Permissions are currently in-memory and the v1 service signs only transfers.
The origin lane must already exist/funded on chain before a non-default-lane
transaction can execute. Persistent encrypted permissions, lane setup UX, and
additional operation-specific confirmation schemas remain later work.
