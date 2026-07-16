# WEBC / WEB COIN

WEBC is a prototype foundation for an independent Rust Layer-1 blockchain
built for the web and the AI era: browser- and website-native payments,
applications, tokens, and staking; first-class AI-agent participation
(mandates, a service registry, machine-readable everything); a native DEX
with per-block batch settlement; a native oracle with real reporter
economics; succinct browser verification; and bidirectional Ethereum/Solana
bridges.

> Status: research and prototype. The current code does not yet implement the
> confirmed protocol and must not be used with real funds.

## Start here

[`WEBC-DEFINITION.md`](WEBC-DEFINITION.md) is the single source of truth for
product, economic, experience, and functional design (read its §16 handoff
summary first). Then read in order:

1. [`AGENTS.md`](AGENTS.md)
2. [`docs/index.md`](docs/index.md) — documentation map and authority order
3. [`docs/decision-record.md`](docs/decision-record.md) — implementation gates and security-adjacent decisions
4. [`docs/development-plan.md`](docs/development-plan.md)
5. [`docs/whitepaper.md`](docs/whitepaper.md)
6. [`docs/implementation-status.md`](docs/implementation-status.md)

Supporting documents: see [`docs/index.md`](docs/index.md) for the full map,
including the system plans for distribution, the DEX, the oracle, the Weft
language, the speed roadmap, validator operations, and agent commerce.

## Confirmed identity (definition §2, §7, §16)

- Project: `WEBC` · Coin: `WEB COIN` · Ticker: `WEBC`
- Independent custom Layer 1; node software in Rust; TypeScript browser SDK
- Genesis supply: `10,000,000 WEBC`; precision: 12 decimals; amounts u128
- Issuance: 10%/yr ×0.8 each year to a 1% floor; fees split 50% burn / 50% rewards
- Distribution (decided, §15.38): 25% contributors / 5% validator bootstrap /
  30% usage subsidies / 15% airdrop in three waves / 15% ecosystem fund /
  10% strategic reserve — no founder, investor, or private-sale allocation
- Consensus: permissionless stake-based BFT with a rotating stake-weighted
  committee; no PoH; validator pool activates at 100 WEBC (operator ≥20 WEBC,
  ≥20% of pool; min delegation 1 WEBC)
- Speed: conservative public claim ~2s blocks / ~6–8s finality; decided
  engineering targets (claims only after public benchmarks, §15.42): fast
  path ~0.4–0.8s for single-owner operations, consensus ~1s blocks / ~1–2s
  finality
- Hybrid state model: account-style balances + object-style app state; Sui is
  the primary object reference (§15.29, §15.30)

## Design direction (definition §6, §8, §15)

- **AI-native as identity, not a feature:** humans, humans-with-AI, and
  autonomous agents are all first-class builders and users — machine-readable
  docs and interfaces, a component catalog, revocable agent mandates, an
  on-chain service registry, HTTP-402-style payment flows.
- **Weft** (working name): the decided authoring language — TS-familiar
  surface, Rust semantics, linear assets, exact money type, compiler-emitted
  machine manifest — lowering to an audited Rust/WASM framework.
- Declared state access + owned objects → parallel execution; per-app
  namespaces and localized fees.
- **Native DEX:** canonical shared pool per pair, disclosed frontend fees,
  mandatory per-block uniform-price batch settlement (no sandwich MEV);
  validators are not funded by extractive MEV.
- **Native oracle:** bonded, accuracy-weighted reporters; pull-based
  updates; display-only reads free.
- Storage as occupancy: deposit + deletion rebate; hot/cold tiering;
  erasure-coded blob layer as phase 2.
- Middle-path validator economics: low stake floor, mid-range hardware, no
  per-vote fees; zstd + compact relay + vote aggregation for frugality.
- Succinct light verification for browsers; zk never on the consensus path.
- Bidirectional wrapped WEBC and external-asset bridges for Ethereum/Solana.
- Fair launch honesty: the founder is paid under the same published
  contribution rules as everyone, disclosed up front (§15.16).

## Repository layout

```text
crates/
  webc-crypto/      cryptographic primitives (Ed25519, ML-DSA seam, hash, merkle)
  webc-chain/       deterministic state-transition core (the protocol heart)
  webc-storage/     KvStore seam + redb backend + ChainStore
  webc-net/         async P2P transport seam (tokio)
  webc-node/        runnable node: mempool, service, HTTP/WS, consensus driver, CLI
sdk/
  webc-js/          browser SDK prototype
  webc-widget/      embedded widget prototype
docs/
  index.md             documentation map (authority order)
  development-plan.md  authoritative phased work plan
  definition-gap-analysis.md  doc-vs-definition audit (2026-07-17)
  code-reconciliation-worklist.md  code-vs-definition divergences (no code changes yet)
  review/              review-session artifacts (codebase map, plan review, findings)
```

## Important warning about current code

The code remains a prototype with important incomplete boundaries, including:

- BFT consensus has the happy-path mechanism but a 2026-07-16 review reported
  HIGH-severity safety/liveness/DoS gaps (see `docs/review/findings.md`); it
  is not complete or safe;
- consensus-detected equivocation IS wired to an applied slash (commit
  a6197ac), but the no-vote-WAL gap (finding C4) means an honest validator
  restart can self-equivocate and be slashed — fix that before running on a
  network;
- the fast path, DEX/batch settlement, oracle, agent mandates, storage
  deposits, vote aggregation, and committee sampling from the definition are
  not-yet-built (see `docs/code-reconciliation-worklist.md`);
- wallet isolation, recovery, and post-quantum authorization are incomplete;
- slashing classes beyond objective double-vote evidence are disabled;
- localized congestion fee markets and a public contract runtime are
  incomplete;
- production bridge proof verification, limits, monitoring, and audits are
  absent; the trusted-relayer bridge prototype is not safe for real assets.

See [`docs/implementation-status.md`](docs/implementation-status.md) and
[`docs/review/findings.md`](docs/review/findings.md) before reusing any module.

## Legacy prototype commands

Once the Rust toolchain is installed:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo run -p webc-node -- demo
```

Phases 0–3 are complete and Phase 4 (networking + signed BFT consensus) is
active but not yet safe. This README does not restate detailed status (it
rots); see [`docs/continuation-guide.md`](docs/continuation-guide.md) for the
verified checkpoint and next task.
