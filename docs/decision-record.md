# WEBC confirmed decisions and technical gates

Last updated: 2026-07-17

**Authority split (owner-decided 2026-07-16/17):** product, economic,
experience, and functional design decisions live in
[`WEBC-DEFINITION.md`](../WEBC-DEFINITION.md) — read its §16 handoff summary
first; §15 entries win over older sections. That file is read-only; do not
edit it — report contradictions to the owner instead. This record no longer
duplicates those decisions. It keeps what the definition deliberately does not
cover: **security-adjacent decisions, implementation gates, and process
rules.** If an older document or the prototype conflicts with either source,
the sources win until the conflict is deliberately resolved in code and tests.

## Product and economic decisions — see the definition

The following are decided in `WEBC-DEFINITION.md` and are **not** re-recorded
here (do not re-litigate; plan within them — §16 rules of engagement):

- identity, audience, Rust core, TypeScript SDK (§2);
- 10M genesis / 12 decimals / u128 + 256-bit intermediates + varint encoding
  (§7, §15.14, §15.19);
- issuance 10% → ×0.8/yr → 1% floor; 50/50 fee split (§7);
- the full distribution allocation 25/5/30/15/15/10 with release shapes,
  reversion paths, airdrop rules, ecosystem fee credits, and the founder
  compensation rule (§15.10–15.16, §15.31, §15.33, §15.38);
- staking rules (100/20/80/1), no validator cap, unstake delays (§7);
- middle-path validator economics; no per-vote fees; official container
  image; spec floor/roadmap governance (§15.23, §15.26, §15.28);
- hybrid state model, declared access, namespaces, lanes (§8, §15.29, §15.30);
- two-track speed strategy and lowered engineering targets; conservative
  public claims until benchmarks (§8, §15.39, §15.40, §15.42);
- WASM foundation, Phase 7a/7b sequencing, and the **Weft** language design
  (§9, §15.41, §15.43, §15.44);
- oracle economics (§15.6, §15.17, §15.21);
- DEX architecture and mandatory per-block batch settlement with chain-native
  retry; MEV revenue policy (§15.8, §15.13, §15.18, §15.34, §15.37);
- storage deposit/rebate, tiering, phase-2 blob layer (§15.22, §15.27);
- agent mandates, service registry, HTTP-402 flows (§15.5, §15.32);
- bridge capability scope and delivery priority (§10);
- governance/launch philosophy and the minimal process sketch (§11, §15.36);
- fairness definition and rejected distribution channels (§15.11, §15.16);
- zk usage policy (§15.25); bandwidth/RAM frugality (§15.19, §15.24).

## Security and wallet decisions (definition scope excludes these; this file owns them)

### Browser wallet and website security

- Wallet secrets stay on the user's device.
- Host websites must never receive the seed phrase, raw private key, or
  decrypted keystore.
- Embedded wallets run in an isolated trusted origin/frame or trusted wallet
  window, not in the host site's JavaScript context.
- The wallet displays the requesting site origin, action, recipient, amount,
  token, contract, and maximum fee before signing.
- Permissions are granted per site and can be revoked.
- Recovery supports standard mnemonic phrases, encrypted keystore files, and
  explicit private-key export with strong warnings.
- Do not invent custom cryptographic primitives; use audited implementations
  and established standards for randomness, mnemonics, key derivation,
  authenticated encryption, and signing.
- Automatic cross-site wallet sharing is reserved for a future
  extension/native wallet; users may import/recover the same wallet
  deliberately.
- Passkeys/hardware-backed approval may protect unlocking and high-risk
  actions, but must not silently replace portable recovery.

### Post-quantum readiness

- Quantum readiness is a genesis design requirement.
- Address and account authorization formats are versioned and support
  multiple signature policies.
- Every standard wallet includes a post-quantum root/recovery policy from
  creation; no wallet is permanently locked to only Ed25519.
- NIST ML-DSA is the initial account-signature candidate, subject to audits
  and performance tests.
- Post-quantum signatures are much larger than Ed25519, so the implementation
  must benchmark strict PQ signing, limited short-lived session keys, and
  ZK/STARK-based signature aggregation.
- Critical actions (recovery, key rotation, staking control, high-value
  policy changes, session-key authorization) require the post-quantum root
  policy.
- Mainnet must not claim full post-quantum security unless account
  signatures, validator consensus signatures, commitments, and the chosen
  proof system are all covered.
- The proof system prefers post-quantum-friendly hash/STARK assumptions where
  practical and must be replaceable through a versioned proof interface.

### Consensus and slashing (security dimension)

- Slashing requires objective signed evidence; a vague accusation or the
  label "51% attack" is not evidence.
- Severe evidence: conflicting signed votes/blocks, objectively invalid
  signed transitions, fraudulent signed bridge messages.
- Downtime and operational mistakes receive lost rewards and softer,
  proportionate penalties; coordinated provable attacks may receive
  correlated penalties.
- No zero-collateral block-producing validator path.
- Splitting the same stake across identities must not increase voting power.

### New-node and light-client starting checkpoint (owner-confirmed 2026-07-17)

- A new light node needs one recent known-good starting “bookmark” before it can
  verify later validator certificates itself.
- The current direction compares checkpoints from multiple independently
  operated public nodes or services. An official release checkpoint is optional
  and is not the sole authority. Any disagreement stops startup and warns the
  operator instead of silently choosing one answer.
- An operator may explicitly supply a checkpoint from a source they trust.
- The owner explicitly requires this direction and every delegated technical
  choice to remain reviewable and replaceable. Checkpoint validation, source
  retrieval, and source-acceptance policy must be separate modules so another
  trust policy can replace this one without changing consensus or transaction
  proof verification.
- ADR-0011 owns the technical boundary. Source count, publisher authentication,
  comparison threshold, schema, key rotation, transport, and limits are
  delegated engineering choices that must be versioned, tested, and documented
  with reasons and a migration path.

### Bridge safety

- Ethereum-side bridge contracts are written/audited in Solidity; Solana-side
  programs in Rust.
- Every message includes source/destination domains, nonce, exact asset
  identity, amount, recipient, source transaction, and replay protection;
  each message executes at most once.
- Generic token support never means every malicious/non-standard token is
  safe: risk metadata, standard checks, per-asset pause, and limits are
  required.
- Prototype stages use valueless mock assets and explicitly trusted test
  relayers/guardians.
- Real-fund activation requires replay protection, domain separation, rate
  limits, per-asset caps, emergency pause, independent audits, monitoring,
  incident response, and an approved trust/proof model.
- Long-term preference: origin-chain light-client or ZK verification rather
  than permanent trust in a small guardian group.

### Privacy-inspired account features (research)

- Taproot-inspired policy trees are desirable for smart accounts.
- Account-based stealth addresses should be researched with scheme-versioned
  announcements and viewing keys; Bitcoin Silent Payments cannot be copied
  directly; any scheme must be evaluated for browser scanning cost, spam
  resistance, recovery, and post-quantum compatibility before mainnet.

## Security review process (owner-confirmed 2026-07-16)

- Because the protocol is implemented by alternating AI sessions, an
  **earlier independent security-review gate** is required for the
  security-critical core — consensus, cryptography, and economics — **before**
  the contract runtime, ZK, bridge, and platform layers stack on top. This is
  in addition to the pre-mainnet audits, not a replacement.
- The gate: after the economics phase the core is **frozen** and submitted to
  independent review; higher layers do not build on the core until blocking
  findings are resolved.
- Motivation on record: the 2026-07-16 plan review (`docs/review/`) found
  fund-destroying and consensus-safety defects that "green" tests did not
  catch. See `docs/development-plan.md` for where this gate sits.

## Process rules

- All work happens on `main`; every review/planning round commits its results
  (sessions are ephemeral; the repository is the persistent memory)
  (definition process notes).
- Decided points are the owner's, but better-argued alternatives are welcome;
  the reviewer must review critically, not deferentially, and present
  pros/cons for every option when asking for a decision (definition process
  notes).
- A product/economic decision changes only with owner approval, and it is
  recorded by the owner's review process in `WEBC-DEFINITION.md` — not by
  editing this file.

## Explicitly not decided yet (technical gates)

These are technical gates, not questions the owner must answer now:

- exact epoch duration, committee size, and committee selection algorithm
  (must satisfy §15.19 vote aggregation and §8 rotating-committee design);
- exact block unit/byte limits at each devnet stage;
- exact initial fee-per-unit constants and storage-deposit rates (§15.35
  method: measurement-tuned placeholders);
- oracle economic parameters (reporter bond size, aggregation window, fee
  sizes) within the §15.17 design;
- DEX batch mechanics details (limit/slippage semantics, multi-hop routing,
  shared-infrastructure pricing) within §15.13/15.18/15.37;
- Weft grammar spec details within §15.41/15.43/15.44 (the design itself is
  decided; the full spec is implementation work);
- fast-path protocol design within §15.40/15.42 (hardware-floor trade-offs
  return to the owner explicitly);
- final ZK/STARK backend;
- strict post-quantum-per-transaction versus post-quantum-root plus limited
  session-key policy;
- production bridge verification/trust implementation;
- the §15.2 bootstrap-phase issuance proposal (decide at the economics
  freeze).

Each must be resolved by specifications, prototypes, benchmarks, threat
models, tests, and audits before the relevant mainnet feature is enabled.
