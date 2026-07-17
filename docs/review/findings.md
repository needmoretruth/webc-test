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
- **C5 — MEDIUM — RESOLVED (commit `3b2b460`) — proof-of-lock (rule 28) not
  carried with re-proposals (liveness).** A node that missed round `vr` could
  never satisfy the local 2f+1-prevote guard and prevoted nil forever while the
  lock holder re-proposed. **Fix:** `SignedProposal` now carries a
  `proof_of_lock: Vec<SignedVote>` — empty for a fresh proposal, the 2f+1
  prevotes for `(height, valid_round, block_hash)` on a re-proposal. The
  prevotes are self-signed (not covered by the proposer's signature, so
  unforgeable and un-repointable); `verify_in_set` rejects a missing/sub-quorum/
  mismatched/padded PoL (`ConsensusProofOfLockInvalid`); the machine absorbs the
  verified PoL prevotes into its tally so the rule-28 guard passes for a node
  that missed the round. Wire bumped to `NET_PROTOCOL_VERSION = 2` (Rust-only
  consensus format, no cross-language fixture). Tests in `round.rs`.
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
- **C8 — LOW — RESOLVED (commit `ff289e3`) — `has_two_thirds_power` threshold
  arithmetic is correct but fragile/undocumented.** `consensus.rs:170-178`. The
  nonstandard form `(total/3)*2 + ((total%3)*2)/3` is a strict >2/3 test that
  avoids the `total*2` u128 overflow the naive `power*3 > total*2` would risk near
  u128::MAX. **Fix:** extracted into the documented, overflow-safe
  `strictly_exceeds_fraction` helper (used by both the 2/3 and 1/3 checks) with
  proptest coverage vs. the naive reference and an explicit `u128::MAX` overflow
  test. Reproduced/covered first by `two_thirds_threshold_matches_reference`,
  `one_third_threshold_matches_reference`, and
  `two_thirds_threshold_does_not_overflow_near_u128_max`.
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

- **N1 — HIGH — RESOLVED (commit `52b87a4`) — no handshake timeout (slowloris).** `transport.rs` (~258-289):
  the four-step handshake awaits frames with no deadline; a peer that connects and
  stalls holds a task + socket + FD forever. Fix: wrap the whole handshake in
  `tokio::time::timeout`.
- **N2 — HIGH — RESOLVED (commit `478ebed`) — inbound connections are unbounded.** `transport.rs` (~209-223):
  every `accept()` spawns a handler with no concurrency cap, per-IP limit, or
  accept rate limit. With N1, unlimited half-open handshakes. Fix: bound in-flight
  inbound connections with a `Semaphore`; add a per-IP cap.
- **N3 — HIGH — RESOLVED (commit `5b0955f`) — peer table has no size cap.** `transport.rs` (~354, 374-379):
  `peers` grows one entry per successful handshake; identity keys are unauthenticated
  names anyone can mint, so a Sybil inflates the table without bound (memory +
  gossip amplification via `flood()`). Fix: cap peer count; reject/evict beyond a
  limit (with peer scoring later).
- **N4 — MEDIUM — RESOLVED (commit `8f08257`) — no per-peer inbound rate limiting.** `transport.rs` (~384-395):
  one fast peer can monopolize the shared worker (hash/decode/re-flood) and crowd
  out honest peers. `try_send` avoids a hard stall, so this is fairness/throughput.
  Fix: per-peer token bucket before re-flood.
- **N5 — LOW — RESOLVED (commit `647e472`) — dial backoff resets on TCP connect, not on authenticated success.**
  `transport.rs` (~226-244): a host that accepts TCP but fails the handshake is
  redialed every 500 ms forever. Fix: reset backoff only after a successful
  authenticated connection.
- **N6 — LOW — RESOLVED (commit `123e528`) — bincode has no explicit `.with_limit()`.** `codec.rs` (13-17): a
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

- **H1 — HIGH — RESOLVED (commit `ec327c7`) — faucet DoS via unlimited fresh
  addresses.** Per-recipient cooldown/`max_recipient_balance` did not bound work
  from an attacker rotating fresh addresses (each drip builds and commits a block).
  **Fix:** a global token bucket (`FAUCET_GLOBAL_BURST = 100`, ~1 drip/s refill)
  checked before any block work, and `last_drip_ms` is pruned to entries within the
  cooldown so it cannot grow without bound. Reproduced first by
  `faucet_global_rate_limit_bounds_total_drips` and
  `faucet_token_bucket_refills_over_time_and_caps_at_burst`.
- **H2 — MEDIUM — RESOLVED (commit `ec327c7`) — mempool has no fee-priority
  eviction, and `prune_expired` is never called in the `run` path.** A full pool
  `Full`-rejected every newcomer (a base-fee flood permanently blocked higher-fee
  honest txs), and the seal tick never pruned TTL-expired txs. **Fix:** a full pool
  evicts the lowest-effective-fee entry for a STRICTLY higher bidder (deterministic
  key tiebreak); `seal_block` calls `prune_expired` before selection. Reproduced
  first by `full_pool_evicts_lowest_fee_for_a_strictly_higher_bidder` and
  `seal_prunes_expired_transactions`.
- **H3 — MEDIUM — RESOLVED (commit `ec327c7`) — unbounded WebSocket
  subscriptions.** `ws.on_upgrade` accepted unlimited concurrent, unauthenticated
  subscribers (FD/memory DoS). **Fix:** an atomic counter caps live subscriptions
  at `MAX_WS_SUBSCRIPTIONS = 256` (503 past the cap), released by an RAII guard when
  the connection ends or the upgrade never completes. Reproduced first by
  `reserve_slot_bounds_concurrent_reservations`.
- **H4 — LOW/MEDIUM — RESOLVED (commit `ec327c7`) — internal error strings leak to
  clients.** 5xx bodies returned `to_string()` of `Internal`/`Storage`/`Node`
  errors (storage detail, chain internals). **Fix:** a 5xx logs the detail
  server-side and returns a generic message; 4xx client errors still return their
  detail. Reproduced first by `internal_errors_do_not_leak_detail_to_clients` and
  `client_errors_still_return_their_detail`.
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

- **S1 — MEDIUM — RESOLVED (commit `e71a842`) — confirmation double-click can approve two transfers.**
  `wallet-confirmation-ui.ts` (~131-144): the next queued request's Approve button
  mounts in the same position the instant the previous resolves; a hostile host
  queues two `sign_native_transfer` and a double-click on tx1 lands on tx2. Fix:
  disable Approve ~500 ms–1 s after render; require pointerdown+pointerup both
  after render.
- **S2 — LOW/MEDIUM — RESOLVED (commit `f01b47d`) — unbounded hostile strings hang the trusted popup.**
  `wallet-request.ts` (~391-458): `recipient` (O(n²) base58 decode) and `amount`
  (`BigInt()` on an arbitrarily long string) are parsed before length bounds; a
  megabyte payload freezes the popup main thread mid-confirmation. Fix: bound
  `recipient` (~64) and `amount` (≤39) before any decode.
- **S3 — LOW — RESOLVED (commit `3215e1e`) — no KDF purpose separation between keystore and permission store.**
  Both derive AES-256 from (password, salt) with identical Argon2id params and no
  domain/info; same password+salt ⇒ same key across formats. AAD domains differ so
  ciphertext swapping fails, but key reuse across contexts erodes the GCM margin.
  Fix: mix a purpose string (HKDF-expand with distinct `info`, or domain-prefixed
  salt).
- **S4 — LOW — RESOLVED (commit `e177545`) — replay-ID FIFO eviction is attacker-pumpable.** `wallet-service.ts`
  (~401-407): 2049 cheap messages evict any prior `request_id`. Transfers stay
  protected by session/sequence; exposure is connect/revoke replay. Fix: per-origin
  quotas or hard-reject when full.
- **S5 — LOW — RESOLVED (commit `d1a7aed`) — reconnect can create a grant whose carried `spentAmount` exceeds
  the new `max_total_amount`.** `wallet-service.ts` (~277-285): fail-safe (never
  widens spend) but with persistence throws an opaque INTERNAL_ERROR after the user
  approved. Fix: reject/surface when `previous.spentAmount > newLimits.maxTotalAmount`
  at connect.
- **S6 — LOW — RESOLVED (commit `08c47e7`) — response size cap enforced after full buffering, in UTF-16 units.**
  `node-client.ts` (~277-289): `response.text()` buffers the whole body before the
  `.length > MAX` check and counts code units, not bytes; error messages carry up
  to 4 MiB of node-controlled text into host UI. Fix: stream with a byte cap;
  truncate server error strings to ~256.
- **S7/S8 — LOW — RESOLVED (commit `e177545`; S8 sequence-resync residual noted) — retry vs. replay-detection and sequence desync.**
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

- **G1 — MEDIUM — RESOLVED (commit `9c77a35`) — genesis supply invariant is
  tautological; it never pins the 10,000,000 WEBC total.** `state.rs:486-488,
  551-564`: `from_genesis` rejects genesis only when
  `SupplyInvariantReport.balanced` is false, but `balanced` is `accounted ==
  self.minted_supply` and `minted_supply` is DEFINED as the checked sum of genesis
  balances — a self-referential identity that always holds. A genesis with the
  wrong total supply would still "balance." CONFIRMED. **Fix:** added
  `ChainConfig::expected_total_supply: Option<Amount>` (`#[serde(default)]` →
  `None`, so trusted in-crate test fixtures are unaffected) and a
  `GENESIS_TOTAL_SUPPLY = Amount::from_webc(10_000_000)` const (`from_webc` is now
  `const`); `from_genesis` rejects a mismatched total via the new
  `ChainError::GenesisSupplyMismatch`. Devnet genesis now pins the same
  10,000,000 WEBC as mainnet in the single valueless faucet account. Reproduced
  first by `genesis_pins_the_declared_total_supply`,
  `genesis_accepts_an_allocation_matching_the_declared_total`, and
  `genesis_without_a_declared_total_skips_the_pin`.
- **U1 — MEDIUM — RESOLVED (commit `202126a`) — `slash_locked` over-penalizes and
  ignores the slashable window.** `unbonding.rs:285-320`: it took no `epoch`
  parameter and applied the penalty to `request.withdrawable` (principal that
  `mature`/`advance_epoch` has already moved past both cooldown and the slashable
  window), in addition to cooling tranches. This contradicts ADR-0008 ("cooling
  stays slashable through its window; withdrawable has passed it"). CONFIRMED.
  **Fix:** each `CoolingTranche` now stores `slashable_through`; `slash_locked`
  takes the current epoch and slashes only tranches whose window is still open,
  and never touches `withdrawable`. Reproduced first by
  `slash_locked_skips_cooling_past_its_slashable_window` and
  `slash_locked_never_slashes_matured_withdrawable_principal`.
- **U2 — LOW — RESOLVED (commit `202126a`) — settled unbonding requests are never
  pruned.** `unbonding.rs:402`: claimed requests lingered forever in
  `self.requests`; `mature`/`slash_locked`/`queued_for` re-scanned them every epoch
  (unbounded state + growing per-epoch cost). **Fix:** `advance_epoch` prunes
  fully-settled requests (no live principal in any bucket); IDs are monotonic and
  never reused, so a pruned request cannot be revived or replayed. Reproduced first
  by `advance_epoch_prunes_fully_settled_requests`.
- **B1 — MEDIUM — RESOLVED (commit `09e6165`) — unbounded bridge-recipient hex
  decode.** `hex_bytes.rs:32-38`: `deserialize` runs `hex::decode(text)` with no
  length bound; it backs the `recipient: Vec<u8>` of `BridgeLock`/`BridgeBurn`
  (`transaction.rs:266,278`), unlike object payloads which use
  `object::bounded_hex`. PLAUSIBLE (real code gap; exploitability bounded by the
  outer frame/body limits). **Fix:** added `bridge::bounded_recipient_hex` (checks
  length before decode, `MAX_BRIDGE_RECIPIENT_BYTES = 128`, even-length check),
  applied to `BridgeLock`/`BridgeBurn` recipients and `BridgeMessage`
  sender/recipient. The shared `hex_bytes` stays unbounded for the larger
  post-quantum key fields. Serialized bytes are unchanged, so canonical hashes and
  the cross-language SDK fixtures still pass. Reproduced first by
  `bridge_lock_recipient_is_bounded_before_decode`,
  `bridge_message_rejects_oversized_address_before_decode`, and
  `bridge_message_rejects_odd_length_address_hex`.

### Fund arithmetic (dedicated pass — completed)

- **F1 — HIGH — RESOLVED (commit `33ea4dc`) — epoch reward distribution silently
  drops the cross-validator division remainder, breaking supply conservation.**
  **Fix:** `apply_epoch_rewards` now sums the floored per-validator shares and
  retains `total_reward − Σ share` in `validator_fee_pool` (carried to the next
  epoch) instead of zeroing it, so `accounted == minted_supply` holds after
  distribution. Reproduced first by
  `epoch_rewards_conserve_supply_across_multiple_validators` (a balanced
  two-validator state with an odd fee pool stays balanced only with the remainder
  retained). Original analysis: `state.rs:740-818`
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
- **F2 — LOW — RESOLVED (commit `5a0e460`) — `floor_rate_bps == 0` passes
  `InflationSchedule::validate`.** `inflation.rs:106-115`: a zero floor drives the
  rate loop to an `ArithmeticOverflow` error at large years instead of converging
  (fail-closed, not fund loss). **Fix:** `validate` now rejects
  `floor_rate_bps == 0` (WEBC always has a positive floor, §7). Reproduced first by
  `zero_floor_rate_is_rejected`.
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

- **ST1 — MEDIUM — RESOLVED (commit `ed61134`) — no chain identity is persisted or
  validated at the storage layer.** `chainstore.rs:99,131`: `open` took no expected
  chain-id and stored none; `verify_tip_consistency` never checked chain id.
  CONFIRMED. **Fix:** `ChainStore::open` now takes the expected `ChainId`, stamps it
  in `Meta` (`META_CHAIN_ID`) on a fresh store alongside the schema version, and on
  reopen rejects a mismatch with the new `StorageError::ChainIdMismatch` before any
  state is read. `Node::open` passes its configured chain id through. Reproduced
  first by `open_rejects_a_store_from_a_different_chain`.
- Otherwise the storage seam looked sound (atomic per-block commit, corruption as a
  reported error) within the slices read; redb crash-atomicity across the
  block+state+cert+validator-set tuple was not adversarially exercised.

## webc-chain — scheduler determinism

- **SC1 — HIGH (latent) — RESOLVED (commit `5a0e460`) — greedy first-fit batching
  is not serializable-order preserving.** `scheduler.rs:20-32`: each tx was placed
  in the FIRST non-conflicting batch, so a later tx could land in an EARLIER batch
  than an earlier tx it conflicts with, reversing their commit order. CONFIRMED.
  Latent (no executor wired yet), but a Phase-6 divergence source. **Fix:**
  `parallel_batches` now places each tx in the first batch at or after every
  earlier batch it conflicts with (highest-conflicting-batch rule). Reproduced
  first by `conflicting_pairs_keep_their_commit_order_across_batches`.
- **SC2 — LOW — RESOLVED (commit `5a0e460`) — conflict detection keys on the full
  versioned `StateKey`.** `state_key.rs:89`: `version` is part of `Eq`/`Ord`, so
  two keys with the same logical `kind` but different `version` were treated as
  non-conflicting and could share a parallel batch. **Fix:** the scheduler now keys
  conflict detection on the version-independent `StateKeyKind`. Reproduced first by
  `keys_conflict_on_logical_identity_regardless_of_version`.
- Verified good: batch formation itself is deterministic (ordered `Vec` +
  `BTreeSet<StateKey>`; per-tx access lists collected into `BTreeSet` so input
  order/dupes don't matter); no wall-clock/RNG.

## webc-chain — transaction wire

- **T1 — LOW — RESOLVED (commit `09e6165`) — `Operation` enum lacks
  `#[serde(deny_unknown_fields)]`.** `transaction.rs:95-96`: every sibling wire
  type (`AccessList`, `FeeBid`, `Transaction`) has it; the enum variants do not, so
  an externally-tagged variant may accept unknown fields. CONFIRMED (low impact —
  the signature still binds the canonical bytes, but strict decode is the project's
  own standard). **Fix:** added `#[serde(deny_unknown_fields)]` to `Operation`;
  serialization is unchanged. Reproduced first by
  `operation_rejects_unknown_variant_fields`.

## Dependency supply chain

- **D1 — HIGH — RESOLVED (commit `91760e2`) — no `cargo-deny`/`cargo-audit` gate
  in CI.** **Fix:** `deny.toml` + a `cargo-deny` CI job enforce advisories
  (RUSTSEC + yanked), a permissive-only license allow-list, no wildcard
  versions, and crates.io-only sources. The bincode 1.3.3 UNMAINTAINED advisory
  is ignored with a documented reason (frozen 1.x behind the codec/storage seam;
  finding D4) and a removal condition. Internal crates marked `publish = false`
  so their path deps are not read as public-crate wildcards. Passes locally
  (`advisories ok, bans ok, licenses ok, sources ok`).
- **D2 — MEDIUM — RESOLVED (commit `91760e2`) — no JS advisory scan in CI.**
  **Fix:** a `pnpm audit --audit-level=high --prod` CI job scans the shipped SDK
  dependencies (`@noble/*`, `@scure/*`, `micro-key-producer`); production deps
  are clean today. Scoped to production so dev-only tooling advisories
  (vitest/esbuild dev server) do not block the merge gate.
- **D3 — LOW — RESOLVED (commit `607035d`) — duplicate major versions in the
  lock** (getrandom 0.2/0.3, rand_core 0.6/0.9, thiserror 1/2, tokio-tungstenite
  0.24/0.29). **Fix:** the one duplicate we directly controlled — a webc-node
  dev-dependency on tokio-tungstenite 0.24 while axum pulls 0.29 — is aligned to
  0.29 (single WebSocket stack). The rest are purely transitive through crypto and
  error crates; `deny.toml` keeps `multiple-versions = "warn"` so they stay visible
  without blocking the gate, with the rationale documented.
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

- **X1 — MEDIUM — RESOLVED (commit `9dfd761`) — bridge recipient hex not lowercase-validated in the SDK.**
  `transaction.ts:311-342`: `bridgeLock`/`bridgeBurn` copy `recipient` verbatim
  while `installSessionKey`/rotations call `requireLowercaseHex`; Rust emits
  lowercase and re-serializes during `verify`, so an upper/mixed-case recipient
  produces a silent signing/verification MISMATCH (fail-closed, not a forgery).
  CONFIRMED. Fix: `requireLowercaseHex` in the bridge constructors (or make Rust
  reject non-lowercase so both sides share one norm).
- **X2 — MEDIUM — RESOLVED (commit `1ef080d`) — object id/namespace/data hex not validated in the SDK.**
  `transaction.ts:202-248`: `createObject`/`mutateObject`/`transferObject` pass hex
  through unvalidated → same silent mismatch class as X1. CONFIRMED. Fix:
  lowercase-validate these fields in the TS constructors.
- **X3 — LOW — RESOLVED (commit `ff289e3`) — integer-range parity.**
  `canonical.rs:74` accepted any `is_u64()||is_i64()` integer and re-emitted it;
  `canonical.ts:65` rejects anything above `Number.isSafeInteger` (2^53-1). **Fix:**
  `canonicalize_value` now rejects an integer outside ±(2^53-1) via
  `ChainError::CanonicalIntegerOutOfSafeRange`, matching the TS encoder, so no bare
  integer can diverge between Rust and the browser in a signed payload. Amounts
  already use decimal strings; the authorization-policy revision bound is exactly
  2^53-1, so the same rule is now enforced one layer earlier for every field.
  Reproduced first by `integers_beyond_the_js_safe_range_are_rejected`.
- **X4 — LOW — RESOLVED (commit `598cd16`) — amount-string parity.** Amounts are decimal strings both sides
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

- **E1 — HIGH (latent) — RESOLVED (commit `33ea4dc`) — epoch advancement is not
  wired into the real block path.** `current_epoch` only advanced inside
  `finish_epoch`/`distribute_epoch_rewards`, whose only node-tree caller was the
  demo, so a running node never advanced the epoch (rewards, unbonding maturation,
  slashable-window maturation, session-key expiry never fired). **Fix:**
  `build_block` (re-run identically by `apply_block`) now runs the rollover
  deterministically when `height.is_multiple_of(StakingConfig.blocks_per_epoch)`
  (default 60) — a pure function of the committed height, so honest nodes cannot
  diverge at the boundary. Couples with F1 (the now-live reward path conserves
  supply). Reproduced first by
  `epoch_advances_deterministically_at_height_boundaries`.
- **E2 — MEDIUM (latent) — RESOLVED (commit `392018d`) — block timestamp is
  unvalidated.** `timestamp_ms` was proposer-supplied, copied verbatim
  (`block_builder.rs:112`), and `apply_block`/`import_validated` never checked
  monotonicity vs parent or a future-drift ceiling. **Fix:** deterministic
  monotonicity is now a state-transition rule — `ChainState.last_block_timestamp_ms`
  (committed by `state_root`, domain bumped to `WEBC_STATE_COMMITMENT_V7`) and
  `build_block` rejects a non-increasing timestamp via
  `ChainError::NonMonotonicBlockTimestamp`; producers clamp to `max(supplied,
  parent+1)`. A clock-based future-drift bound (30 s) rejects far-future proposals
  in the driver's `validate_proposal`. Reproduced first by
  `block_timestamps_must_strictly_increase`,
  `produce_block_clamps_timestamp_to_stay_monotonic`, and
  `future_drift_bound_tolerates_skew_and_rejects_gross_drift`.
- **E3 — MEDIUM — RESOLVED (commit `c797f00`; residual documented) — Merkle proof
  DoS + leaf/internal domain separation.** `merkle.rs:88` `verify_merkle_proof`
  looped over `proof.steps` with no length bound (browser/light clients verify
  node-supplied proofs → a huge proof pins client CPU); `hash_pair` uses one domain
  for internal nodes, and odd layers duplicate the last node. **Fix (DoS, the
  exploitable part):** `verify_merkle_proof` rejects proofs longer than
  `MAX_MERKLE_PROOF_STEPS` (64, i.e. 2^64 leaves) before hashing. **Second-preimage
  analysis (documented in the module):** internal nodes carry the `WEBC_MERKLE_V1`
  domain, distinct from every separately-domained caller leaf, so the RFC-6962
  leaf/internal confusion does not apply here even though leaves are pre-hashed.
  **Residual (deferred, documented):** removing the odd-layer duplicate-last would
  change every historical root and the cross-language SDK root computation, so it is
  a deliberate coordinated root-format change, not a silent one; it cannot forge
  WEBC's fixed-leaf-set consensus roots. Reproduced first by
  `verify_rejects_an_over_length_proof_without_hashing_it`.
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
- **Static review only for the original pass.** CONFIRMED verdicts meant two
  independent reads agreed on the code facts, not that a runtime exploit was
  demonstrated. **Update (commits `90c28ac`, `45f7396`, `5ca197d`, `bc3869b`,
  `90ae433`, `0813e7c`, `91760e2`):** the consensus P0/P1 findings C1–C4, C6,
  and C7 were each reproduced with a failing test first, then fixed and kept
  (per `AGENTS.md` pitfall 7); and continuous fuzz harnesses now exist for the
  wire decoder, canonical encoder, transaction decode/verify, and mempool
  admission (`fuzz/`, run in CI's `fuzz-smoke` job). Remaining consensus finding:
  C5 (proof-of-lock re-proposals). The other under-covered areas (E1–E8, redb
  fault injection, crypto primitives) are still owed.
