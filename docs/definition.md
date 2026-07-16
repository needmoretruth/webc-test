# WEBC definition (summary)

The full, authoritative definition is [`WEBC-DEFINITION.md`](../WEBC-DEFINITION.md)
at the repository root — the single source of truth for product, economic,
experience, and functional design, completed with the owner on 2026-07-16.
Read its §16 handoff summary first; §15 overrides earlier sections where they
differ. This page is a one-screen orientation only and must not be edited into
a competing source.

## One-paragraph essence (§1)

WEBC is an independent Layer-1 blockchain built for the web and the AI era.
It lets any website, web app, web game, or software agent send and receive
money, issue assets, and run applications as naturally as they load a page —
fast, cheap, final, and without handing accounts to the site. Humans, humans
working with AI, and fully autonomous AI agents are all first-class
participants, in both using and building on the chain. Native coin: **WEB
COIN (WEBC)**.

## Identity (§2)

- Independent custom Layer 1 (not a token on another chain); node software in
  Rust; TypeScript browser SDK; global, general-purpose audience.
- 10,000,000 WEBC genesis, 12 decimals, u128 amounts (§7, §15.14).
- Hybrid state: account-style balances + object-style app state (§8, §15.30).
- Contracts: deterministic WASM, Rust first, then **Weft** — the decided
  AI-first authoring language lowering to the same audited framework (§9,
  §15.41).

## What makes it distinctive

- **AI-native thesis (§6):** machine-readable everything, a component
  catalog, agent mandates + service registry + HTTP-402 flows (§15.5,
  §15.32).
- **Batch-settled native DEX (§15.13, §15.37):** canonical shared pools,
  disclosed frontend fees, mandatory per-block uniform-price settlement — no
  sandwich MEV, and MEV is not monetized.
- **Two-track speed (§15.40, §15.42):** fast path ~0.4–0.8s for single-owner
  operations (launch scope); consensus ~1s blocks / ~1–2s finality — both
  engineering targets claimed only after public benchmarks; ~2s / 6–8s stays
  the conservative public claim meanwhile.
- **Decided fair-launch distribution (§15.38):** 25% contributors / 5%
  validator bootstrap / 30% usage subsidies / 15% airdrop (three waves) /
  15% ecosystem fee credits / 10% strategic reserve; founder paid under the
  same published rules, disclosed (§15.16).
- **Oracle with real economics (§15.17):** consumers pay, accuracy-weighted
  bonded reporters, pull-based updates, free display-only reads.
- **Frugal validators (§15.23, §15.26):** low stake floor + mid-range
  hardware, no per-vote fees, official tuned container image.

## Scope note

Security, cryptography, and robustness are first-class but deliberately live
in separate documents (`security.md`, ADRs) — the definition covers product,
economy, experience, and functional design only.

## Current status

This repository is a research prototype. It is not ready for real money,
production validators, or production bridges. See
`docs/implementation-status.md` for what the code actually does and
`docs/code-reconciliation-worklist.md` for the code-vs-definition gap.
