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

- **C1 — HIGH — RESOLVED (commit `45f7396`) — no block-validity check before
  prevoting.** `round.rs` (rule_propose) prevoted any hash-consistent,
  leader-signed proposal; the driver fed proposals to the machine without
  re-executing the block. Tendermint Alg.1 (lines 22/28) requires the `valid(v)`
  predicate. A Byzantine leader could propose a semantically invalid block (bad
  state root, over-budget txs, bogus evidence); honest nodes prevoted → locked →
  precommitted it and produced a **valid FinalityCertificate for an unimportable
  block**. **Reproduced first** by
  `webc-node/tests/consensus_byzantine_proposal.rs`: pre-fix, the honest driver
  prevoted+precommitted a forged-state-root block and the harness assembled a
  fully verifying certificate for it. **Fix:**
  `ConsensusDriver::validate_proposal` — cheap authenticity gate
  (`verify_in_set`) first, then a local chain-position pin (height, parent,
  epoch, chain id — fields `apply_block` takes from the block itself), then a
  full `apply_block` dry-run on a scratch state clone; only an importable
  proposal reaches the machine, and each round's first authentic proposal is
  re-executed at most once (leader CPU-spam bounded).
- **C2 — HIGH — RESOLVED (commit `5ca197d`) — node silently terminates on a
  failed finalized-block import.** `commit_if_decided` returned `true` on any
  `import_finalized_block` error and `run()` treated that as a clean exit — no
  log, no retry; the sync path swallowed the error entirely. **Fix:** `run()`
  now returns a typed `DriverExit` (`NetworkClosed` / `StorageFailed` /
  `CertifiedBlockInvalid` / `SnapshotFailed`); transient storage I/O is
  retried with backoff before giving up, corruption/inconsistency fail closed
  immediately, and a certified-but-unimportable block is surfaced as a
  consensus emergency from both the live and sync paths (the sync path also
  pins responses to the local chain position first). Tests
  (`tests/consensus_import_failure.rs`, written first — the pre-fix API could
  not even express a failure): persistent-failure typed exit after retries,
  transient-failure survival, and a genuinely certified (3-of-4 keys) invalid
  block surfacing as `CertifiedBlockInvalid`.
- **C3 — HIGH — RESOLVED (commit `bc3869b`) — unbounded per-height memory keyed
  by attacker-chosen round (OOM).** `round.rs` stored `prevotes`/`precommits`
  keyed `(u32 round, Address)` and a **full Block** per round in `proposals`,
  with no window around `self.round`; any snapshot member could sign valid
  votes for rounds `0..2^32`. **Reproduced first** by
  `round.rs::far_future_rounds_are_ignored_and_stale_rounds_are_evicted`.
  **Fix:** a sliding round window — ingestion ignores messages more than
  `MAX_FUTURE_ROUNDS` (32) above the current round, each round change evicts
  storage more than `MAX_PAST_ROUNDS` (32) below it (lock/valid value live in
  dedicated fields and are never evicted; signing only happens at the current
  round so evicted guards cannot re-enable an old step), and the driver applies
  the same horizon before its C1 block re-execution so far-future leader
  proposals cannot burn CPU. Beyond-window nodes recover via next-height state
  sync.
- **C4 — HIGH — RESOLVED (commit `90c28ac`) — no durable WAL
  of own votes/locks → crash-restart self-equivocation.** The machine was
  in-memory and the driver rebuilt a fresh machine per height from the seed. A
  validator restarting mid-height forgot it already prevoted/precommitted and
  re-voted (and `build_candidate` uses wall time, so a re-proposal differed),
  producing two signed conflicting votes = objective `DoubleVoteEvidence` →
  self-slash/tombstone via the live a6197ac slash loop.
  **Reproduced first** (per AGENTS.md pitfall 7) by
  `webc-node/tests/consensus_restart.rs::a_restarted_validator_never_signs_a_conflicting_vote`:
  pre-fix, the restarted round-0 proposer re-proposed a different-timestamp
  block and re-prevoted it, and the conflicting pair verified as objective
  slashable evidence. **Fix:** `ConsensusWalRecord` (own signed
  proposals/votes + locked/valid state) journaled by the machine
  (`ConsensusMachine::wal_record`), persisted durably by the driver **before
  every own broadcast** (`Node::persist_consensus_wal` →
  `ChainStore::put_consensus_wal`, new `Table::ConsensusWal`, pruned
  atomically when the height commits), and replayed on restart
  (`ConsensusMachine::restore`) so a restored machine re-enters the journaled
  round, never re-signs a recorded step, and keeps its lock. Journal write
  failure fails closed (message never broadcast); an unreadable/invalid
  journal drops the height to non-voting observer mode. Covered by the
  restart integration test plus machine tests (`restart_without_journal_
  replay_self_equivocates`, `restored_machine_never_resigns_a_recorded_step`,
  `restore_preserves_the_lock_across_a_restart`,
  `restored_proposer_does_not_repropose_its_recorded_round`,
  `restore_rejects_corrupt_or_foreign_journals`) and storage round-trip/prune/
  redb-restart tests.

- **ADVERSARIAL VERIFICATION (2026-07-16 workflow): C1, C2, C3, C4 are all
  CONFIRMED** by a second independent read of the exact code:
  - C1 CONFIRMED — `round.rs:293-302` proposal ingestion calls only
    `verify_in_set` (signature/leader) then stores the block; `rule_propose`
    (`round.rs:436-476`) prevotes on lock state alone; the driver never
    re-executes. `import_finalized_block` re-runs `apply_block` but only
    POST-finalization, so it protects local state yet cannot stop certificate
    formation for an invalid block.
  - C2 CONFIRMED — `consensus_driver.rs:232-238` `commit_if_decided` returns
    `true` on import error (doc comment at :217 confirms "fatal storage error,
    signaling the caller to stop"); `run()` :175-180 halts. Remotely reachable.
  - C3 CONFIRMED — `round.rs:171-175` per-height maps keyed by `u32` round only
    (a `SignedProposal` carries a full `Block`); the sole guard is the per-height
    check (:294,:304); round is unbounded. Mitigation: attacker must be a snapshot
    validator.
  - C4 CONFIRMED — `consensus_driver.rs:150-172` builds a fresh
    `ConsensusMachine` each height off committed height with no persisted vote/lock
    state; `round.rs` module doc: "performs no networking or persistence."

- **DOC-vs-CODE RECONCILIATION (important).** The status docs (continuation-guide,
  implementation-status, development-plan) said equivocation-to-slash was NOT wired
  and a Byzantine test was owed. Two commits by the GPT implementer landed on
  2026-07-15 AFTER those docs were last written and were NOT reflected in them:
  - `a6197ac feat(consensus): apply header-committed equivocation slashes` — the
    block header now commits an `evidence_root` (`block.rs:45`), the block body
    carries `evidence: Vec<SlashingEvidence>`, `build_block`/`apply_block` execute
    `apply_block_slashing_evidence` before user txs inside the atomic overlay
    (`block_builder.rs:66-78,171`), and the driver auto-includes machine-detected
    equivocation (`consensus_driver.rs:481-502`, `pending_evidence` +
    `build_candidate(..., evidence, ...)` + `prune_pending_evidence`). So the
    **equivocation → slash loop is wired end to end** (with a
    `header_committed_evidence_slashes_and_imports_deterministically` test), not
    missing. The docs were stale; they have been corrected.
  - `75d054b test(consensus): reject sub-third conflicting finality` — adds
    `round.rs::less_than_one_third_byzantine_power_cannot_finalize_conflicting_blocks`
    (machine-level; a full multi-NODE-over-TCP Byzantine integration test may still
    be wanted, but the core safety property is now tested).
  - **Safety escalation from this reconciliation:** because the slash loop is now
    LIVE, finding **C4 is no longer latent** — an honest validator that crashes and
    restarts mid-height and re-votes produces objectively valid `DoubleVoteEvidence`
    that this path will ACTUALLY slash. C4 (durable vote/lock WAL) must be fixed
    BEFORE this is run on any network where honest restarts happen.

- **EQUIVOCATION-PATH VERIFICATION (2026-07-16, independent trace of a6197ac).**
  Result: **the evidence path implementation is otherwise CORRECT/SAFE, but running
  it live before C4 is a HIGH/critical operator-fund risk.**
  - Otherwise-safe (verified): the header binds `evidence_root` (altering/reordering
    `block.evidence` changes the block id and invalidates any certificate;
    `apply_block` recomputes the root over the received order and requires
    `rebuilt.header == block.header`, so no reject-valid-block-by-ordering vector);
    `MAX_BLOCK_SLASHING_EVIDENCE = 64` is enforced before any signature check;
    evidence executes before user txs on a clone with whole-block atomic rollback;
    `apply_slashing_evidence` verifies snapshot membership + both signatures + is
    replay-protected by order-independent `evidence.hash()` (no double-slash);
    `pending_evidence` is populated ONLY from the local machine's verified
    `Equivocation` (no network injection), so a peer with no private key **cannot
    forge evidence to frame an honest validator**.
  - The one critical gap (KEY QUESTION answered YES): the machine is rebuilt fresh
    per height (`consensus_driver.rs:157`, `round.rs:205-214`) with no reload of
    cast votes / lock state, so an honest validator that crashes mid-height and
    re-votes emits objectively valid self-equivocation, indistinguishable from
    malicious. Peers generate and gossip the evidence independently (the victim
    cannot suppress it), and `apply_slashing_evidence` applies **`double_sign_bps =
    8000` (80%) + tombstone**. Ordinary operator restarts therefore destroy stake.
    **Fix (gating dependency, not optional): a durable vote+lock WAL fsync'd before
    broadcast and replayed on startup; a validator must never sign a second vote for
    a `(height, round, step)` it already signed — land this BEFORE the live evidence
    path is exposed to a network.**
  - Two minor notes: (i) `apply_slashing_evidence` verifies against the *current*
    validators map / consensus key, not the vote-height snapshot — a key rotation
    between offense and processing could let an offender escape or gate processing to
    while-still-a-member (note, not a double-vote blocker); (ii) `pending_evidence`
    can accumulate one entry per real offender per round during a liveness stall
    (LOW — each requires a genuine offense, so not a cheap flood).
- **C5 — MEDIUM — proof-of-lock (rule 28) not carried with re-proposals
  (liveness).** Good: the receiver verifies `valid_round` against locally-recorded
  2f+1 prevotes, not the proposer's claim. But those prevotes are not attached to
  the re-proposal and there is no vote-set gossip yet, so a node that missed round
  `vr` can never satisfy the guard and prevotes nil forever while the lock holder
  re-proposes. Fix: attach the 2f+1 prevote set (PoL certificate) to re-proposals
  and verify it, or gossip vote sets.
- **C6 — MEDIUM — RESOLVED (commit `90ae433`) — constant timeouts instead of
  round-scaled.** `DriverTimeouts` now carries an `increment` and `for_kind`
  computes `base + round·increment` (saturating), the standard Tendermint
  `timeout(r) = init + r·delta`, so some round eventually outlasts any finite
  delay and liveness is restored once the network stabilizes. Unit-tested for
  linear scaling and overflow saturation.
- **C7 — MEDIUM — RESOLVED (commit `0813e7c`) — state-sync bandwidth
  amplification.** The driver answered a `BlockRequest` via network-wide
  `broadcast` and requested sync on any higher-height claim. **Fix:**
  `NetworkHandle::send_to` delivers a directed reply and the transport no longer
  refloods a `BlockResponse` (point-to-point, not gossip); `serve_block_request`
  replies only to the requesting peer; sync is requested solely by
  `request_if_certified_ahead`, which fires only on a `FinalityCertificate` for
  a higher height that verifies against the current validator snapshot (the
  driver now gossips the certificate on commit so behind nodes learn of finality
  with proof). Cross-epoch certificate anchoring stays E4. Tests:
  `webc-net::send_to_reaches_only_the_named_peer` and
  `webc-node/tests/consensus_sync_gating.rs`.
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

## webc-chain — execution / access-control (state.rs, state_key.rs, object.rs, session_key.rs)

**Reviewed clean — no correctness or access-control defect found.** An adversarial
read verified all five properties: (1) undeclared/inexact access fails and rolls
back the whole tx (`StateAccessRecorder::read/write/finish`, `state_key.rs:248-270`
— `UnusedDeclaredStateAccess` also blocks over-declaration padding); (2) read-only
keys cannot be written; (3) session-key substitution enforces lane binding,
allow-list, per-use + cumulative amount + fee budgets, and expiry in
`enforce_session_key_use` BEFORE the operation runs, advancing spend in the same
overlay, and `session_permitted_principal` rejects every non-Transfer op so a
session key can never authorize staking/bridge/object/policy ops; (4) object
mutation/transfer requires exact namespace + owner + version (rolls back on stale);
(5) no `unwrap`/panic/index on untrusted paths in the non-test region; all
amount/nonce/version math is checked. `execute_transaction` mutates a clone and
commits only on `Ok`, and its sole non-test caller (`block_builder.rs:90`)
propagates errors, so an invalid tx cannot be cheaply block-included.

## webc-chain — supply / staking / bridge (verified findings)

- **G1 — MEDIUM — genesis supply invariant is tautological; it never pins the
  10,000,000 WEBC total.** `state.rs:486-488, 551-564`: `from_genesis` rejects
  genesis only when `SupplyInvariantReport.balanced` is false, but `balanced` is
  `accounted == self.minted_supply` and `minted_supply` is DEFINED as the checked
  sum of genesis balances — a self-referential identity that always holds. A
  genesis with the wrong total supply would still "balance." CONFIRMED. Fix: add an
  explicit `minted_supply == Amount::from_webc(10_000_000)` check (or a
  `ChainConfig` expected-total) in `from_genesis`.
- **U1 — MEDIUM — `slash_locked` over-penalizes and ignores the slashable
  window.** `unbonding.rs:285-320`: it takes no `epoch` parameter and applies the
  penalty to `request.withdrawable` (principal that `mature`/`advance_epoch` has
  already moved past both cooldown and the slashable window), in addition to
  cooling tranches. This contradicts ADR-0008 ("cooling stays slashable through its
  window; withdrawable has passed it"). CONFIRMED. Fix: pass the current epoch (or
  store a per-tranche `slashable_through`) and slash only principal still inside its
  slashable window; exclude `withdrawable`.
- **U2 — LOW — settled unbonding requests are never pruned.** `unbonding.rs:402`:
  claimed requests linger forever in `self.requests`; `mature`/`slash_locked`/
  `queued_for` re-scan them every epoch (unbounded state + growing per-epoch cost).
  Fix: prune fully-settled requests past any replay window, or move audit history to
  a separately-bounded structure.
- **B1 — MEDIUM — unbounded bridge-recipient hex decode.** `hex_bytes.rs:32-38`:
  `deserialize` runs `hex::decode(text)` with no length bound; it backs the
  `recipient: Vec<u8>` of `BridgeLock`/`BridgeBurn` (`transaction.rs:266,278`),
  unlike object payloads which use `object::bounded_hex`. PLAUSIBLE (real code gap;
  exploitability bounded by the outer frame/body limits). Fix: a bounded-hex
  deserializer / `MAX_BRIDGE_RECIPIENT_BYTES` cap rejecting over-length at decode.

### Fund arithmetic (dedicated pass — completed)

- **F1 — HIGH — epoch reward distribution silently drops the cross-validator
  division remainder, breaking supply conservation.** `state.rs:740-818`
  `apply_epoch_rewards`: `total_reward = inflation + validator_fee_pool`; each
  validator gets `floor(total_reward * validator_stake / total_active_stake)`. The
  **inner** dust (within a validator's own stakers) is recaptured to the validator
  (correct), but the **outer** remainder `total_reward − Σ validator_share` is
  assigned to no one, while `minted_supply += inflation` (full) and
  `validator_fee_pool = 0` unconditionally. Net: the supply invariant
  (`accounted == minted_supply`) breaks by the outer dust (0..num_validators−1 base
  units) EVERY epoch, cumulatively — real fee-pool units are destroyed (not burned,
  not credited) and `minted_supply` over-counts claimable supply. Only ever loses
  units, never creates. **Invisible with a single active validator** (`mul_ratio`
  is exact, dust = 0), so single-validator tests miss it; it manifests with ≥2
  validators. If a future epoch path enforces `SupplyInvariantReport.balanced` this
  becomes CRITICAL (state-root divergence / halt). It is currently latent because
  epoch rewards are not yet wired into the real block path (E1). Fix: retain
  `leftover = total_reward − Σ validator_share` in `validator_fee_pool` (carry
  forward) instead of zeroing it — mirroring the inner-dust handling — so
  `accounted_new = accounted_old + inflation = minted_supply_new`.
- **F2 — LOW — `floor_rate_bps == 0` passes `InflationSchedule::validate`.**
  `inflation.rs:106-115`: a zero floor drives the rate loop to an
  `ArithmeticOverflow` error at large years instead of converging (fail-closed, not
  fund loss). Fix: reject `floor_rate_bps == 0`, or short-circuit when the numerator
  reaches 0.
- **Verified correct (fund arithmetic):** the 50/50 fee split conserves exactly
  with one documented odd-unit rule (odd dust → validator reward; `fees.rs:50-52`,
  `amount.rs:85`); dynamic base fee is all-checked u128 with `try_from` narrowing,
  no float (`fees.rs:66`); inflation `max(1%, 10%·0.8^year)` uses pure
  integer/rational math and a telescoping cumulative-integer per-period budget that
  distributes exactly the annual units with no drift (`inflation.rs:48-104`); the
  `Amount` type is fully checked (`checked_mul_bps`/`checked_mul_ratio` split
  whole/remainder to avoid intermediate overflow and compute exact floors), with no
  unchecked `as` narrowing anywhere; reward accrual is `checked_add`-only with the
  claim path zeroing on payout (no double-credit).
- Not traced by this pass: `effective_fee_per_unit`, `required_units`,
  `debit_native`, `total_stake()`/`is_active()` bodies, the reward claim/withdraw
  path beyond grep confirmation, and `Amount`'s `Deserialize`.

## webc-storage — durability

- **ST1 — MEDIUM — no chain identity is persisted or validated at the storage
  layer.** `chainstore.rs:99,131`: `open` takes no expected chain-id and stores
  none (only `META_SCHEMA_VERSION`, `META_TIP`); `verify_tip_consistency` checks
  state-snapshot + `state_root` + block-header-hash but never chain id. CONFIRMED.
  (The node layer claims to refuse a mismatched chain id — confirm that check
  actually runs above `ChainStore`, else a store from another chain could be
  resumed.) Fix: persist `ChainId` in Meta at first open and compare it in `open`.
- Otherwise the storage seam looked sound (atomic per-block commit, corruption as a
  reported error) within the slices read; redb crash-atomicity across the
  block+state+cert+validator-set tuple was not adversarially exercised.

## webc-chain — scheduler determinism

- **SC1 — HIGH (latent) — greedy first-fit batching is not serializable-order
  preserving.** `scheduler.rs:20-32`: each tx is placed in the FIRST
  non-conflicting batch, so a later tx can land in an EARLIER batch than an earlier
  tx it conflicts with, reversing their commit order. CONFIRMED. **Severity is
  latent**: `scheduler.rs` returns only `Vec<Vec<usize>>` with no executor wired
  yet, so there is no state-root divergence today — but it must be fixed before the
  Phase-6 parallel executor consumes it. Fix: place each tx only in a batch at or
  after every earlier conflicting tx's batch (highest-conflicting-batch rule).
- **SC2 — LOW — conflict detection keys on the full versioned `StateKey`.**
  `state_key.rs:89`: `version` is part of `Eq`/`Ord`, so two keys with the same
  logical `kind` but different `version` are treated as non-conflicting and could
  share a parallel batch. Fix: scope conflict detection on the version-independent
  logical identity, or assert all keys are `CURRENT_PROTOCOL_VERSION`.
- Verified good: batch formation itself is deterministic (ordered `Vec` +
  `BTreeSet<StateKey>`; per-tx access lists collected into `BTreeSet` so input
  order/dupes don't matter); no wall-clock/RNG.

## webc-chain — transaction wire

- **T1 — LOW — `Operation` enum lacks `#[serde(deny_unknown_fields)]`.**
  `transaction.rs:95-96`: every sibling wire type (`AccessList`, `FeeBid`,
  `Transaction`) has it; the enum variants do not, so an externally-tagged variant
  may accept unknown fields. CONFIRMED (low impact — the signature still binds the
  canonical bytes, but strict decode is the project's own standard). Fix: add
  `deny_unknown_fields` to `Operation`.

## Dependency supply chain

- **D1 — HIGH — no `cargo-deny`/`cargo-audit` gate in CI.** `.github/workflows/
  ci.yml`: fmt/clippy/test/doc only; no advisory (RUSTSEC/yanked) scan, no license
  policy enforcement (the Apache-compatible-only rule is manual), no ban on
  unexpected/duplicate crates or non-crates.io sources. CONFIRMED. Fix: add a
  `cargo-deny check` job (advisories + bans + licenses allow-list + sources
  crates.io-only).
- **D2 — MEDIUM — no JS advisory scan in CI.** No `pnpm audit`/OSV step; the JS
  crypto deps (`@noble/*`, `@scure/*`, `micro-key-producer`) are pinned but
  unscanned. Fix: `pnpm audit --audit-level=high` or OSV-scanner.
- **D3 — LOW — duplicate major versions in the lock** (getrandom 0.2/0.3,
  rand_core 0.6/0.9, thiserror 1/2, tokio-tungstenite 0.24/0.29). Align where
  feasible; enforce with cargo-deny bans.
- **D4 — LOW/known — `fips204 0.4.6`** is a young pre-1.0 crate on the recovery-
  root verify path; keep it pinned behind the `webc-crypto::mldsa` seam (already
  the case) and track RUSTSEC/upstream. **INFO — `bincode 1.3`** is the frozen 1.x
  line; track a 2.x migration behind the codec/storage boundary later.
- **D5 — RESOLVED / FALSE ALARM (recorded as a discipline example).** Static review
  flagged as CRITICAL that `serde_json 1.0.150` depends on an unknown crate `zmij`
  (Cargo.lock:876) instead of `ryu` — the classic dependency-substitution shape.
  **Verified benign against crates.io:** `zmij` is a David Tolnay (`dtolnay`) crate
  — the same author as serde/serde_json/ryu — a Schubfach-based ryu successor
  (~244M downloads, first published 2025-12-18), and serde_json 1.0.150 legitimately
  depends on `zmij ^1.0`. Not an attack. This is exactly why findings are verified
  before acting; the real remaining action is D1 (`cargo-deny`), which would answer
  such questions automatically.

## Cross-language byte parity (Rust canonical.rs vs TS canonical.ts / transaction.ts)

- **X1 — MEDIUM — bridge recipient hex not lowercase-validated in the SDK.**
  `transaction.ts:311-342`: `bridgeLock`/`bridgeBurn` copy `recipient` verbatim
  while `installSessionKey`/rotations call `requireLowercaseHex`; Rust emits
  lowercase and re-serializes during `verify`, so an upper/mixed-case recipient
  produces a silent signing/verification MISMATCH (fail-closed, not a forgery).
  CONFIRMED. Fix: `requireLowercaseHex` in the bridge constructors (or make Rust
  reject non-lowercase so both sides share one norm).
- **X2 — MEDIUM — object id/namespace/data hex not validated in the SDK.**
  `transaction.ts:202-248`: `createObject`/`mutateObject`/`transferObject` pass hex
  through unvalidated → same silent mismatch class as X1. CONFIRMED. Fix:
  lowercase-validate these fields in the TS constructors.
- **X3 — LOW — integer-range parity.** `canonical.rs:74` accepts any
  `is_u64()||is_i64()` integer and re-emits it; `canonical.ts:65` rejects anything
  above `Number.isSafeInteger` (2^53-1). A `u64` counter above 2^53 carried as a
  JSON number would diverge (or the TS side rejects a payload Rust accepts). Fix:
  encode large integer fields as decimal strings on both sides (as amounts already
  are), or have Rust reject >2^53-1 in `canonicalize_value`.
- **X4 — LOW — amount-string parity.** Amounts are decimal strings both sides
  (parity holds for well-formed input), but the TS constructors don't validate the
  amount-string shape; a value Rust's u128 decimal form would not produce could be
  signed. Fix: validate `^(0|[1-9][0-9]*)$` in the TS helpers.
- **X5 — INFO / invariant to keep — key-sort parity.** Rust sorts object keys by
  UTF-8 byte order; TS uses `Array.sort` (UTF-16 code-unit order). Identical for
  ASCII, and every signed-payload key is a fixed ASCII field today. Keep the
  invariant: never put a non-ASCII or dynamic object key in a signed payload; if
  unavoidable, replace the JS default sort with an explicit UTF-8 byte comparator.

## Additional under-covered areas (completeness critic — for the NEXT review/build)

These were surfaced but not fully audited; several are latent-but-serious.

- **E1 — HIGH (latent) — epoch advancement is not wired into the real block path.**
  `current_epoch` only advances inside `finish_epoch`/`distribute_epoch_rewards`
  (`state.rs` ~685-932), whose ONLY caller in the node tree is the demo
  (`main.rs:355`). `produce_block`, `import_validated`, and the consensus commit
  path never advance the epoch; `apply_block`/`build_block` copy `epoch` from state
  without advancing it. So on a running node, rewards, `unbonding.advance_epoch`,
  slashable-window maturation, and session-key expiry never fire. Worse, whatever
  eventually triggers the rollover MUST be a deterministic height-derived function
  executed identically inside `apply_block` on every node — if it is out-of-band or
  clock-driven, honest nodes diverge on the state root at the boundary (a fork).
  Fix: derive epoch from height deterministically and run reward+unbonding+expiry
  inside the state transition, ordered identically everywhere.
- **E2 — MEDIUM (latent) — block timestamp is unvalidated.** `timestamp_ms` is
  proposer-supplied, copied verbatim (`block_builder.rs:112`), and `apply_block`/
  `import_validated` never check monotonicity vs parent or a future-drift ceiling.
  Benign only while nothing consensus-visible reads time; a stake-griefing/reward-
  manipulation vector the moment epoch/expiry/fee logic keys off it. Fix: enforce
  `timestamp > parent.timestamp` and a bounded drift now, before the coupling.
- **E3 — MEDIUM — Merkle proof DoS + leaf/internal domain separation.**
  `merkle.rs:88` `verify_merkle_proof` loops over `proof.steps` with no length
  bound (browser/light clients verify node-supplied proofs → a huge proof pins
  client CPU); `hash_pair` uses one domain for internal nodes with no distinct leaf
  prefix, and odd layers duplicate the last node (the RFC-6962 second-preimage
  "duplicate-last" foot-gun). Fix: cap proof length, add a distinct leaf-vs-internal
  domain prefix, and review odd-layer handling.
- **E4 — P1 — long-range / weak-subjectivity sync.** State sync hands a late node
  a block + certificate, validator sets are per-epoch snapshots, and state is
  latest-only (ST/§4.2) — a fresh node has no trusted anchor and must trust whoever
  answers; withdrawn validators' old keys enable classic long-range forgery. Needs
  a weak-subjectivity checkpoint and a defined trust anchor for incoming certs
  (ties to plan §4.5).
- **E5 — P1 — eclipse / gossip abuse.** Static bootstrap list, flood gossip, no
  peer scoring/ban/inbound-diversity/anti-eclipse; an adversary owning a target's
  few bootstrap peers can censor, withhold the head, or feed a higher-height claim
  that triggers sync from the attacker (ties to C7). Also check mempool per-peer/
  per-sender rate + total-bytes bounds.
- **E6 — P2 — consensus signing-domain scope.** Confirm every signed consensus
  object (proposal/prevote/precommit/certificate) uses a distinct per-message-type
  domain so a prevote can't be replayed as a precommit or across height/round/chain,
  and that Ed25519 non-canonical/malleable signatures can't yield two encodings of
  "the same" vote (interacts with equivocation detection). `canonical.rs` rejects
  floats/sorts keys, but the review did not confirm the full scope of what goes
  through it on the consensus path.
- **E7 — P2 — reentrancy/metering once a VM exists (gated).** No VM today; flag for
  the review that must run the moment the contract runtime lands (cross-object
  reentrancy, deterministic gas metering across nodes, no float/clock/iteration-
  order nondeterminism inside contracts, and the escrow release path becoming
  attacker-reachable).
- **E8 — P2 — dual state encoders.** `state_root` uses canonical JSON
  (`WEBC_STATE_COMMITMENT_V6`) while restart round-trips tuple-keyed maps via
  bincode. Confirm no state field is reachable only through the bincode path such
  that a JSON-invisible mutation could diverge on-disk vs. committed root.

---

## Review coverage limits (what was NOT audited)

Now covered (2026-07-16 workflow, read-only): execution/access-control (clean),
storage durability contract, scheduler determinism, transaction wire strictness,
staking/unbonding lifecycle, genesis accounting, dependency supply chain, and
cross-language byte-parity — plus adversarial re-verification of consensus C1–C4.

Now also covered: fund arithmetic (fee split, base fee, inflation, reward
distribution, `Amount`) — see the "Fund arithmetic" subsection above (one HIGH
supply-conservation bug F1; the rest verified correct).

Still NOT audited / owed:
- redb crash-atomicity across the block+state+cert+validator-set tuple (contract
  read, not fault-injected).
- The completeness-critic areas E1–E8 above were surfaced, not fully audited.
- Crypto primitive correctness of `ed25519-dalek`/`fips204` and RNG quality
  (trusted as reviewed upstream libraries).
- **No dynamic testing, fuzzing, or reproduction — static review only.** Every
  HIGH/CONFIRMED finding deserves a dedicated reproduction test before a fix
  (per `AGENTS.md` pitfall 7). CONFIRMED verdicts mean two independent reads agreed
  on the code facts, not that a runtime exploit was demonstrated.
