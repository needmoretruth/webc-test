# WEBC code review findings log

Last updated: 2026-07-16 (plan-review session).

**Status of these findings:** produced by a read-only review (focused sub-agents +
direct sampling) during a docs-only session. They are **reported, not yet
reproduced**. Before fixing any item, the implementer must (1) reproduce it with a
failing test, then (2) fix, then (3) keep the test. A static-review finding can be
a false positive or already mitigated by a path the reviewer did not see — verify
first. No source code was changed in the review session.

Severity scale: critical (funds/consensus safety loss), high (network halt, DoS,
or self-inflicted slash), medium (liveness/fairness/limited DoS), low
(hardening), info (hygiene).

Coverage limits are recorded at the end. Absence from this list is NOT evidence of
correctness — large parts of `state.rs`, `unbonding.rs`, `staking.rs`,
`block_builder.rs`, storage durability, and all TS/Rust cross-fixture parity were
not deeply audited.

---

## webc-chain / webc-node — consensus (round.rs, consensus.rs, consensus_driver.rs)

- **C1 — HIGH — no block-validity check before prevoting.** `round.rs`
  (rule_propose, ~436-476) prevotes any hash-consistent, leader-signed proposal;
  `consensus_driver.rs` (~376-378) feeds proposals to the machine without
  re-executing the block. Tendermint Alg.1 (lines 22/28) requires the `valid(v)`
  predicate. A Byzantine leader can propose a semantically invalid block (bad
  state root, over-budget txs, bogus evidence); honest nodes prevote → lock →
  precommit it and produce a **valid FinalityCertificate for an unimportable
  block**. Fix: the driver must dry-run `apply_block` against current state before
  delivering the proposal event, or the machine must expose a validity hook.
- **C2 — HIGH — node silently terminates on a failed finalized-block import.**
  `consensus_driver.rs` `commit_if_decided` (~232-238) returns `true` on any
  `import_finalized_block` error and `run()` (~176-210) treats that as a clean
  exit — no log, no retry. With C1, one malicious proposer halts every honest
  node (all "finalize" the invalid block, all fail import, all exit). Even alone,
  a transient storage error kills the node. Fix: distinguish "block invalid"
  (post-finality this is a consensus emergency, not a shutdown) from storage
  errors (retry/surface); never exit silently.
- **C3 — HIGH — unbounded per-height memory keyed by attacker-chosen round
  (OOM).** `round.rs` stores `prevotes`/`precommits` keyed `(u32 round, Address)`
  and a **full Block** per round in `proposals`, with no window around
  `self.round`. Any snapshot member can sign valid votes for rounds `0..2^32`; a
  staked validator is the legitimate leader of ~p·2^32 rounds so its proposals
  pass `verify_in_set`. `rule_catch_up` and `has_one_third_participation` also
  iterate all keys per event (quadratic CPU). Fix: reject/park messages with
  `round > current_round + K`, cap stored future rounds, evict rounds below the
  decision round.
- **C4 — HIGH — no durable WAL of own votes/locks → crash-restart
  self-equivocation.** The machine is in-memory and the driver rebuilds a fresh
  machine per height from the seed. A validator restarting mid-height forgets it
  already prevoted/precommitted and re-votes (and `build_candidate` uses wall
  time, so a re-proposal differs), producing two signed conflicting votes =
  objective `DoubleVoteEvidence` → self-slash/tombstone once slashing is wired.
  Tendermint requires persisting `(height, round, step, lock, last-signed vote)`
  before broadcast. Fix: a durable vote/lock WAL consulted before signing.
  **Interaction: this makes the "wire equivocation to slash" work (plan §4.3)
  dangerous until C4 is fixed — you would slash honest nodes that restarted.**
- **C5 — MEDIUM — proof-of-lock (rule 28) not carried with re-proposals
  (liveness).** Good: the receiver verifies `valid_round` against locally-recorded
  2f+1 prevotes, not the proposer's claim. But those prevotes are not attached to
  the re-proposal and there is no vote-set gossip yet, so a node that missed round
  `vr` can never satisfy the guard and prevotes nil forever while the lock holder
  re-proposes. Fix: attach the 2f+1 prevote set (PoL certificate) to re-proposals
  and verify it, or gossip vote sets.
- **C6 — MEDIUM — constant (1s) timeouts instead of round-scaled.** `consensus_
  driver.rs` (~57-66, 460-467). Tendermint partial-synchrony liveness needs
  `timeout(r) = init + r·delta`; a fixed timeout below real delay fails every
  round identically (permanent liveness failure). Fix: scale each timeout by the
  round.
- **C7 — MEDIUM — state-sync bandwidth amplification.** `consensus_driver.rs`
  (~315-331) answers a `BlockRequest` via network-wide `broadcast`, not a directed
  reply; `request_if_behind` triggers on any message claiming a higher height with
  no proof. One spoofed high-height vote makes a node blast sync requests; one
  small request causes up to 16 full blocks broadcast to everyone. Fix: reply to
  the requesting peer only; gate sync on a verified higher-height certificate.
- **C8 — LOW — `has_two_thirds_power` threshold arithmetic is correct but
  fragile/undocumented.** `consensus.rs:170-178`. The nonstandard form
  `(total/3)*2 + ((total%3)*2)/3` is actually a strict >2/3 test and avoids the
  `total*2` u128 overflow that the naive `power*3 > total*2` would risk near
  u128::MAX — that is likely the real reason. Document the overflow rationale and
  add a property test. Not a bug today.
- **Verified good (consensus):** quorum math is checked and returns false on a
  zero/empty set (cannot finalize); locking conforms (a locked node never prevotes
  a conflicting value); first-vote-wins per (round, validator, type) prevents
  double-counting; certificate verify enforces domain separation, signer
  uniqueness, snapshot membership, and full height/round/block/chain binding; the
  leader schedule is deterministic and stake-weighted; stale timers are correctly
  ignored; hostile `on_event` errors are swallowed, not panicked. Nil sentinel
  (all-zero hash) is not practically forgeable, though an explicit
  `block_hash != NIL` guard would be good defense-in-depth.

## webc-net — transport / handshake / wire

- **N1 — HIGH — no handshake timeout (slowloris).** `transport.rs` (~258-289):
  the four-step handshake awaits frames with no deadline; a peer that connects and
  stalls holds a task + socket + FD forever. Fix: wrap the whole handshake in
  `tokio::time::timeout`.
- **N2 — HIGH — inbound connections are unbounded.** `transport.rs` (~209-223):
  every `accept()` spawns a handler with no concurrency cap, per-IP limit, or
  accept rate limit. With N1, unlimited half-open handshakes. Fix: bound in-flight
  inbound connections with a `Semaphore`; add a per-IP cap.
- **N3 — HIGH — peer table has no size cap.** `transport.rs` (~354, 374-379):
  `peers` grows one entry per successful handshake; identity keys are unauthenticated
  names anyone can mint, so a Sybil inflates the table without bound (memory +
  gossip amplification via `flood()`). Fix: cap peer count; reject/evict beyond a
  limit (with peer scoring later).
- **N4 — MEDIUM — no per-peer inbound rate limiting.** `transport.rs` (~384-395):
  one fast peer can monopolize the shared worker (hash/decode/re-flood) and crowd
  out honest peers. `try_send` avoids a hard stall, so this is fairness/throughput.
  Fix: per-peer token bucket before re-flood.
- **N5 — LOW — dial backoff resets on TCP connect, not on authenticated success.**
  `transport.rs` (~226-244): a host that accepts TCP but fails the handshake is
  redialed every 500 ms forever. Fix: reset backoff only after a successful
  authenticated connection.
- **N6 — LOW — bincode has no explicit `.with_limit()`.** `codec.rs` (13-17): a
  hostile 4 MiB frame can embed a length prefix claiming billions of elements;
  mitigated in practice by the 4 MiB frame bound + serde cautious capacity, but
  that is defense-by-accident. Fix: add `.with_limit(MAX_FRAME_BYTES)`.
- **Verified good (net):** frame magic/version/length/trailing-byte checks run
  before payload decode with `MAX_FRAME_BYTES` (4 MiB) enforced; the handshake is
  replay-resistant (signs the verifier's fresh challenge), binds domain + pubkey +
  chain id, and rejects self-peering and cross-chain peers. Channel encryption is
  a documented devnet deferral and nothing stronger is claimed. Consider binding a
  full two-challenge transcript hash if channel binding is added later.

## webc-node — HTTP / service / mempool / secrets

- **H1 — HIGH — faucet DoS via unlimited fresh addresses.** `http.rs` (~311-319)
  + `service.rs` (~360-430): cooldown/`max_recipient_balance` are keyed per
  recipient, so unlimited fresh addresses (1) drain the faucet, (2) grow
  `last_drip_ms` unbounded (never pruned), and (3) each drip calls `produce_block`
  = a full block build + durable commit per request (CPU/storage DoS). No global
  faucet rate limit. Fix: global token-bucket on the faucet; cap/expire
  `last_drip_ms`. (Devnet-only surface, but it is the deployed `run` path.)
- **H2 — MEDIUM — mempool has no fee-priority eviction, and `prune_expired` is
  never called in the `run` path.** `mempool.rs` (~228-231): when full (8192) a
  new tx is `Full`-rejected even if it bids far above the pool — a base-fee flood
  permanently blocks higher-fee honest txs. The single-proposer sealer
  (`main.rs` ~176-184) calls only `remove_obsolete`, never `prune_expired`
  (that lives in `consensus_driver.rs`), so expired txs occupy slots forever,
  making the fill permanent. Fix: evict the lowest-effective-fee entry to admit a
  strictly higher bidder; call `prune_expired` on the seal tick.
- **H3 — MEDIUM — unbounded WebSocket subscriptions.** `http.rs` (~321-327):
  `ws.on_upgrade` accepts unlimited concurrent, unauthenticated subscribers (FD/
  memory DoS). Fix: cap concurrent subscriptions.
- **H4 — LOW/MEDIUM — internal error strings leak to clients.** `http.rs`
  (~179-198): 5xx bodies return `to_string()` of `Internal`/`Storage`/`Node`
  errors (storage detail, chain internals). Fix: generic 5xx message to the
  client, log detail server-side.
- **H5 — INFO/mainnet-gate — no production consensus-key provisioning exists.**
  Node identity is a fresh per-process `Keypair::generate()` (no argv/env/file
  seed — good, nothing `ps`-visible or logged). The devnet faucet uses a
  hardcoded seed `[7u8;32]` (acceptable, documented valueless devnet). But there
  is no real validator consensus-key provisioning path yet; specify one (keystore
  file, 0600, never argv) before mainnet, and note dalek `SigningKey` is not
  zeroized on drop.
- **Verified good (node):** 1 MiB request-body limit; parsers map errors to 400;
  no panic reachable from network input in these files (all `unwrap`/`expect` are
  test-only, indexing is length-guarded, `service.lock()` recovers from poison);
  mempool admission checks signature, chain id, nonce bounds (64-gap cap), fee
  floor, affordability; RBF requires ≥10% bump.

## sdk/webc-js — browser wallet

No critical key-exfiltration path found. WeakMap isolation, exact-origin
postMessage, keystore AAD binding, and bigint accounting are fundamentally sound.

- **S1 — MEDIUM — confirmation double-click can approve two transfers.**
  `wallet-confirmation-ui.ts` (~131-144): the next queued request's Approve button
  mounts in the same position the instant the previous resolves; a hostile host
  queues two `sign_native_transfer` and a double-click on tx1 lands on tx2. Fix:
  disable Approve ~500 ms–1 s after render; require pointerdown+pointerup both
  after render.
- **S2 — LOW/MEDIUM — unbounded hostile strings hang the trusted popup.**
  `wallet-request.ts` (~391-458): `recipient` (O(n²) base58 decode) and `amount`
  (`BigInt()` on an arbitrarily long string) are parsed before length bounds; a
  megabyte payload freezes the popup main thread mid-confirmation. Fix: bound
  `recipient` (~64) and `amount` (≤39) before any decode.
- **S3 — LOW — no KDF purpose separation between keystore and permission store.**
  Both derive AES-256 from (password, salt) with identical Argon2id params and no
  domain/info; same password+salt ⇒ same key across formats. AAD domains differ so
  ciphertext swapping fails, but key reuse across contexts erodes the GCM margin.
  Fix: mix a purpose string (HKDF-expand with distinct `info`, or domain-prefixed
  salt).
- **S4 — LOW — replay-ID FIFO eviction is attacker-pumpable.** `wallet-service.ts`
  (~401-407): 2049 cheap messages evict any prior `request_id`. Transfers stay
  protected by session/sequence; exposure is connect/revoke replay. Fix: per-origin
  quotas or hard-reject when full.
- **S5 — LOW — reconnect can create a grant whose carried `spentAmount` exceeds
  the new `max_total_amount`.** `wallet-service.ts` (~277-285): fail-safe (never
  widens spend) but with persistence throws an opaque INTERNAL_ERROR after the user
  approved. Fix: reject/surface when `previous.spentAmount > newLimits.maxTotalAmount`
  at connect.
- **S6 — LOW — response size cap enforced after full buffering, in UTF-16 units.**
  `node-client.ts` (~277-289): `response.text()` buffers the whole body before the
  `.length > MAX` check and counts code units, not bytes; error messages carry up
  to 4 MiB of node-controlled text into host UI. Fix: stream with a byte cap;
  truncate server error strings to ~256.
- **S7/S8 — LOW — retry vs. replay-detection and sequence desync.**
  `wallet-client.ts`/`wallet-service.ts`: client re-posts the same request_id on
  backoff while the service treats duplicates as `REQUEST_REPLAY`; concurrent
  signs or a client timeout-after-user-approval desync the sequence counter
  (availability only; funds not moved but spend budget may be consumed). Fix:
  service caches and re-sends the original response per (origin, request_id);
  client resyncs sequence from the service.
- **Info:** F9 error-code oracle contradicts its own "share one code" doc
  (impact nil); F10 long-lived cached AES key with random IVs (within NIST bounds);
  F11 frozen wallet object has mutable `publicKey` array contents (fail-closed);
  F12 unbounded confirmation queue (prompt-fatigue). Cumulative grant cap tracks
  principal only — fees are per-tx capped but not cumulatively (design note).
- **Verified good (SDK):** exact `event.source` + secure-origin checks, responses
  never target `*`; randomness is exclusively `crypto.getRandomValues`/`subtle`
  (zero `Math.random`, zero `console.*`, static error strings); keystore AAD covers
  domain/format/version/full-KDF/IV/tag/public-metadata with pinned constants
  (no downgrade), uniform `AUTHENTICATION_FAILED`; canonical amounts are decimal
  strings, floats/non-safe-integers rejected; spend limits are bigint, serial, with
  rollback-on-write-failure that drops the signature; restored grants re-validated
  as hostile input.

## Fund-movement / supply (state.rs, amount.rs, fees.rs, inflation.rs, bridge.rs, unbonding.rs)

(Pending — sub-agent still running at the time of this write. Findings will be
appended and this section updated on completion.)

---

## Review coverage limits (what was NOT audited)

- Most of `state.rs` (6.9k LoC) beyond state-root construction and the sections
  the fund-movement agent covers; `staking.rs`, `block_builder.rs`, `genesis.rs`,
  `object.rs`, `scheduler.rs`, `fees.rs` internals.
- `webc-storage` redb durability and `commit_block` crash-atomicity (only the
  contract was read, not adversarially tested).
- Cross-language Rust↔TypeScript byte-parity was reviewed structurally, not by
  running the fixtures.
- Crypto primitive correctness of `ed25519-dalek` / `fips204` and RNG quality
  (trusted as reviewed upstream libraries).
- No dynamic testing, fuzzing, or reproduction — this was static review only.
  Every HIGH finding above deserves a dedicated reproduction test.
