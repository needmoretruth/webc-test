# WEBC definition

## One-sentence definition

WEBC is an independent Layer-1 blockchain that lets websites and browser users make payments, create applications, issue assets, and verify the chain without handing wallet secrets to a website.

## Identity

- Project: `WEBC`
- Coin: `WEB COIN`
- Ticker: `WEBC`
- Native network: the WEBC Layer 1
- Genesis supply: `10,000,000 WEBC`
- Precision: 12 decimal places
- Core implementation language: Rust
- Browser SDK language: TypeScript

WEBC is not merely an Ethereum or Solana token. Native WEBC lives on its own network. Bridges will also let users create wrapped WEBC on Ethereum and Solana and return it to native WEBC.

## Product goal

A website should be able to add WEBC features through a small SDK or widget while users keep control of their keys. The network should support:

- browser wallets and website payments;
- native WEBC, user-created fungible tokens, and NFTs;
- staking, delegation, and public verification nodes;
- simple exchange, games, voting, and website-connected applications;
- parallel execution so unrelated applications do not block one another;
- short proofs so browsers can verify important chain facts;
- bidirectional Ethereum and Solana bridges.

## Technical identity

WEBC combines three design directions:

- Solana-inspired declared state access, parallel scheduling, and localized fees;
- Sui-inspired objects for NFTs and application-owned state;
- Mina-inspired compact proofs for lightweight browser verification.

Ordinary money and token balances use a simple account model. NFTs, games, and application state can use owned or shared objects. PoH is not part of the protocol.

## Website actions

On-chain code cannot directly click buttons, download files, call arbitrary websites, or read a device. Instead it emits a signed on-chain event. A browser or server agent performs the external action and can submit a signed receipt. File data normally stays off-chain; its hash and permission rules can be recorded on-chain.

## Current status

This repository is a research prototype. It is not ready for real money, production validators, or production bridges. See `docs/implementation-status.md` for the exact gap between the current code and the confirmed design.

The authoritative decisions are in `docs/decision-record.md`.
