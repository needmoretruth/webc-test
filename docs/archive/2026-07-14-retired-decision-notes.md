# Retired 2026-07-14 decision notes (archive)

Status: **archive — not current policy.** These sections were recorded with the
owner on 2026-07-14 on a review branch that was never merged. The branch was
retired on 2026-09-26: its code fixes that still applied were ported (`441bc22`,
`e65056a`), and its two open review findings are tracked as A1 and C9 in
`docs/review/findings.md`. The decision text below is kept verbatim so nothing
is lost. `WEBC-DEFINITION.md` (then `docs/decision-record.md`) wins wherever it
differs.

Known differences from the current tree:

- **Commission.** This text says "no fixed maximum" with a timelock on
  increases; the code enforces a 20% cap (`max_commission_bps: 2_000` in
  `crates/webc-chain/src/staking.rs`) and has no commission-change operation.
  Owner decision pending.
- **Superseded:** slashing (ADR-0012), governance vote delegation (deferred in
  `docs/continuation-guide.md`), session-key minting (the current code requires
  the post-quantum root), and consensus timing targets (`WEBC-DEFINITION.md`
  §15.42).
- **Consensus engine.** The current consensus code is a Tendermint-style BFT
  engine (`docs/decision-record.md`), not a port of Sui's `consensus/core`; the
  port strategy and verification gate below are recorded direction, not current
  state.
- **Fees.** The rule that localized pricing applies only at the priority/tip
  layer has not been checked against `crates/webc-chain/src/fees.rs`.

## From `docs/decision-record.md` (2026-07-14)

### Consensus engine and fast path (decided with the project owner on 2026-07-14)

- Implementation strategy is adopt-and-adapt, not build-from-scratch. WEBC ports the mainnet-proven
  Sui/Mysten leaderless DAG-BFT consensus (the `consensus/core` Mysticeti implementation) and adapts
  it onto WEBC's own newtypes, cryptography boundary, and state model, rather than hand-writing a BFT
  protocol. Reason: consensus safety bugs cannot be found by testing alone and are catastrophic, so a
  proven implementation is safer than an original one. Building from scratch is rejected as too risky
  and slow.
- License is clean and non-copyleft. Sui's consensus is Apache-2.0 (verified in the `consensus/core`
  file headers: `SPDX-License-Identifier: Apache-2.0`), and WEBC is now Apache-2.0 as well (decided
  2026-07-14, changed from the earlier `MIT OR Apache-2.0`), so the licenses are identical and
  incorporation is fully clean with no "contamination": Apache-2.0 is permissive, imposes no
  obligation beyond attribution, and includes an explicit patent grant. Ported files must retain
  Mysten's copyright and Apache-2.0 headers, note significant changes, and carry any upstream
  `NOTICE`. Grouping ported code in a dedicated consensus crate is preferred for organization and
  clear attribution, though no longer required for license separation now that the whole project is
  Apache-2.0.
- "Port" means study, extract, and adapt, not copy-paste. The upstream crate is coupled to Sui's
  authority/execution framework and its own types; adapting it to WEBC newtypes, the `webc-crypto`
  boundary (browser-matching Ed25519 plus the post-quantum root), and WEBC state is itself
  substantial work and a tracked risk, not a free drop-in.
- Owned-object fast path is included from the start, not deferred. Transactions that touch only
  single-owner objects finalize through a signed-certificate consistent-broadcast path (a quorum of
  more than two thirds of stake-weighted signatures) WITHOUT full consensus ordering, giving the
  lowest payment latency. Transactions that touch shared (multi-writer) objects go through the
  DAG-BFT consensus path for total ordering. Because porting Sui's engine brings fast-path machinery
  along, the plan carries it in from day one rather than bolting it on later. The known cost is
  accepted: two finalization paths to verify, equivocation handling (a single-owner object that is
  double-signed becomes locked until epoch change), and matching wallet/client logic.
- The state model must therefore distinguish single-owner versus shared objects as a first-class,
  early state-machine property, because the fast path depends on it.


### Commission, concentration, and slashing (decided with the project owner on 2026-07-14)

- Validator commission is a free market with no fixed maximum. The earlier code-level 20% cap is
  relaxed. Protection for passive delegators comes from timing, not a value ceiling.
- A commission increase only takes effect after a notice/timelock window (target about 21-28 days,
  longer than the mainnet unstaking delay so a delegator can exit before an increase applies). The
  exact window is a tunable parameter.
- Every commission increase is an on-chain event; wallets/SDKs surface it to that validator's
  delegators. The chain cannot push notifications itself.
- A delegation may carry an optional "maximum acceptable commission". When a validator's commission
  increase would exceed it, that delegation is automatically moved into the unbonding queue at the
  moment the increase takes effect. (Roadmap.)
- No saturation / per-validator stake cap is added now (option B). Reason: a per-validator cap or
  reward-saturation curve does not stop real concentration — one entity simply splits stake across
  several validator identities it controls — so it only nudges honest, passive delegation while
  adding complexity to the delicate reward path. It only affects rewards, never voting power.
  Saturation stays a documented future option to be tuned with real data if concentration is
  measured. Concentration is instead resisted by: acquisition cost, correlated slashing of
  coordinated attacks, and the fair 70% public distribution.
- Total issuance is NOT made responsive to the staking ratio. The existing design (fixed inflation
  curve, split among stakers by share) already self-balances participation: fewer stakers share the
  same fixed reward at a higher yield, which attracts more, and vice versa.
- Dynamic/decaying minimum-stake tied to coin price appreciation is deferred (decide later). If
  pursued it must be an oracle-free schedule or governance-adjustable, never a trusted price feed.
- Slashing expansion roadmap: downtime/poor liveness receives a soft penalty (lost rewards plus
  temporary jailing, optionally a tiny slash), measured from objectively missed blocks. Coordinated,
  provably simultaneous attacks receive correlated slashing that scales toward full loss. Being large
  or "monopoly risk" is never itself slashable, because it is not an action and would burn innocent
  delegators.


### Fee model (decided with the project owner on 2026-07-14)

- WEBC uses a hybrid fee model: a proven Sui-style gas base plus a WEBC-specific localized congestion
  layer. This replaces the earlier plan of a fully original per-application base-fee market.
- Base gas has two parts: a computation component and a storage component.
- Storage is funded by a Sui-style storage fund with rebate: creating persistent state pays its
  storage cost up front into a fund, and deleting state refunds it. This makes state growth
  economically self-limiting (you pay to bloat, you are refunded to shrink) and is the chosen answer
  to long-term state growth. It is a decided requirement regardless of the congestion layer.
- Congestion pricing is LOCAL, not global. When the network is busy, only the busy application's or
  object's price rises, so unrelated sites (for example a small donation button) stay cheap while a
  viral application is congested. This preserves the "each website is independent" product intent.
- For safety the localized dimension is applied at the proven priority/tip layer (as Solana's local
  fee markets do), on top of the standard gas base, rather than making the base fee itself
  per-application (which no production chain has shipped and which stays unproven). Priority fees must
  never let one application monopolize unrelated localized execution lanes.
- A small network-wide floor and fair block-capacity rules still defend shared bandwidth and block
  space against global spam.


### Account key hierarchy and quantum migration (decided with the project owner on 2026-07-14)

- Three key tiers, not a deep delegation chain:
  1. Post-quantum master root (ML-DSA, cold): highest authority, rarely used. It may
     revoke, recover, rotate the hot key, and mint unconstrained keys. It is
     committed at account creation as a hash (see post-quantum readiness above).
  2. Hot transaction key (Ed25519, the policy `active_transaction_key`): signs
     everyday transactions; fast and small. Unlimited by default, with optional limits.
  3. Session keys (Ed25519, constrained): short-lived keys scoped to a site/use with
     mandatory constraints.
- Shallow tree only (maximum depth two): master to hot key, and master or hot key to
  session-key leaves. Session keys never mint further keys. Deep delegation chains are
  rejected because per-transaction verification would have to walk the whole chain,
  limit inheritance becomes error-prone, revocation must cascade, and the extra
  verification surface invites key-management bugs.
- Session-key minting authority is BOTH (option A): the hot key may mint ONLY
  constrained session keys (each must carry at least an amount cap or a block-height
  expiry), while the master root may mint unconstrained keys and may revoke, recover,
  and rotate. Rationale: this splits convenience (hot key issues limited sessions
  without touching the cold key) from safety (master holds unlimited power plus
  revocation/recovery), so a stolen hot key can only create capped, expiring sessions.
  "Hot key only" is rejected (a stolen hot key could mint unlimited sessions);
  "master only" is rejected (every session would need a heavy cold ML-DSA signature).
- Session-key constraints are deterministic: an amount cap and/or a block-height expiry
  (never wall-clock time), optionally an operation scope. They are stored in the account
  policy, enforced by consensus on every transaction the session key signs, and
  revocable. The hot key itself may optionally carry the same kind of limits.
- Buildability: hot-key-minted limited session keys need only Ed25519 and are
  implementable now. Master minting, revocation, and recovery depend on ML-DSA
  verification and are deferred until ML-DSA is implemented, audited, and benchmarked;
  scaffold the flow behind that gate meanwhile.
- Quantum migration path: because the account uses versioned authorization and
  pre-commits an ML-DSA root at creation while Ed25519 is still safe, WEBC can move to
  quantum-only by adding a policy version whose active key is ML-DSA, authorized by the
  pre-committed master root, keeping the same account address and identity. The
  pre-committed root is what makes this safe: migration is authorized by a key that is
  still unbreakable at migration time, defeating a "harvest now, break later" attack on
  the exposed Ed25519 public key. Honest limits: this is a managed protocol upgrade
  (governance plus client and validator rollout), not an instant switch; it also
  requires migrating consensus/validator signatures and likely STARK signature
  aggregation; legacy accounts that never installed a policy/root are not protected; and
  full post-quantum security is not claimed until account, consensus, commitment, and
  proof layers are all covered.


### Governance voting model (decided with the project owner on 2026-07-14; implementation is a later-phase roadmap item)

- Voting power comes from a dedicated governance lock, held SEPARATELY from validator staking, not
  from validator/delegator stake. Keeping them separate means voting never exposes a voter to
  validator slashing, and it lets lock duration drive weight. Requiring a lock (rather than mere
  balance) blocks flash-loan/borrowed-token voting.
- Conviction weighting: the longer coins are locked, the more voting weight they carry, so long-term
  commitment counts for more than raw wealth held briefly.
- Vote delegation (liquid democracy) is supported so small holders can delegate to representatives.
- Lock mechanics: a warm-up delay after locking before voting power activates (blocks last-minute
  lock-and-swing manipulation); on unlock, voting power is removed immediately while the coins
  themselves are released only after a cooldown (blocks vote-then-dump).
- No special fee to vote (a voting tax would suppress participation). Anti-spam instead uses a
  refundable deposit to CREATE a proposal. Ordinary transaction fees still apply to lock/unlock/vote
  transactions.
- Web-native participation: users vote directly from the browser wallet/SDK, and any website may open
  a governance instance scoped to its application namespace/domain with its own configured rules.
- Honest limit recorded: true one-person-one-vote is impossible without trustless on-chain identity
  (the same Sybil problem), so "democratic" here means plutocracy-mitigated (conviction + delegation
  + the fair 70% public distribution), not literal per-person equality.


### Explicitly not decided yet (additions from 2026-07-14)

- exact initial fee-per-unit constants, including base gas prices, the storage price and rebate
  percentage, storage-fund mechanics, and the localized priority-congestion curve;
- DAG-BFT structural parameters (round/wave timing, block dissemination fan-out, committee size and
  the stake-weighted rotating-subset selection algorithm), and the exact achievable block-cadence and
  finality numbers, all to be fixed by benchmark rather than promised now;
- how much of Sui's `consensus/core` is ported verbatim versus reimplemented on WEBC newtypes, and
  the exact fast-path certificate/equivocation-locking rules, to be settled during the port;
- exact ML-DSA session-key parameters and post-quantum signature-aggregation approach
  (the account signing model itself is decided: post-quantum master root + hot Ed25519 +
  constrained session keys, not strict post-quantum-per-transaction; see the account key
  hierarchy entry);
- production bridge verification/trust implementation;
- precise anti-duplicate-account public distribution mechanism;
- commission-increase timelock length, governance lock warm-up/cooldown and conviction curve,
  proposal deposit size, and saturation parameters if saturation is ever enabled;
- whether and how a dynamic/decaying minimum validator stake is scheduled (deferred);
- reference and minimum validator hardware specifications (deferred): the target is a moderate
  middle — more accessible than Solana's very high requirements, but not so low that parallel
  execution and DAG-BFT cannot keep up — with exact specs fixed by benchmark, not promised now.

## From `docs/development-plan.md` (2026-07-14)

### Cross-cutting safety-verification gate

Because leaderless DAG-BFT plus a dual fast/consensus path is hard to get right,
the following gate must pass before the ported engine backs any public network or
value-bearing state. It is not optional and is not a single phase; it accompanies
Phase 4 and is re-checked whenever the consensus glue changes.

- a written safety and liveness argument tied to the adopted protocol's published
  proofs, with every WEBC-specific deviation (committee rotation, fast-path
  locking, epoch boundaries, checkpoint rules) called out;
- differential/conformance tests against upstream Mysticeti reference behavior or
  vectors where available;
- an adversarial suite covering partitions, delayed/dropped messages, equivocation,
  and Byzantine voting up to just under one third of stake;
- a machine-checked specification (for example TLA+/Apalache) of the WEBC-specific
  glue that differs from upstream, sufficient to model-check the safety property
  that no two conflicting states finalize.
