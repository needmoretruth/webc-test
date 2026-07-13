# ADR-0008: snapshotted stake lifecycle and bounded exit queue

Status: accepted for Phase 1 implementation

## Context

WEBC permits direct delegation into validator pools. If a withdrawal immediately
reduced live voting power, one small exit could push a pool below 100 WEBC or
break the 20/80 operator ratio during an active consensus round. That would make
committee membership depend on transaction ordering and could amplify a mass
exit into a safety incident.

Ethereum, liquid-staking protocols, and Solana solve different parts of this
problem. Ethereum uses snapshotted validator state and rate-limited exits; since
Pectra, legacy validators remain capped at 32 ETH effective balance while
compounding validators may range from 32 to 2048 ETH, so “every validator is
always one fixed 32 ETH unit” is no longer a complete description. Lido adds a
separate FIFO withdrawal queue and liquidity buffer above Ethereum consensus.
Solana represents stake in separate accounts and applies activation/deactivation
over epoch boundaries subject to network-wide warmup/cooldown limits.

## Decision

WEBC adopts a non-custodial Layer-1 lifecycle, not a protocol promise of instant
liquidity.

### Position states

Every operator stake and delegation amount is explicitly in one of these states:

1. `PendingActivation`: funded but not yet voting or earning;
2. `Active`: included in the immutable current-epoch stake snapshot;
3. `ExitQueued`: the owner requested exit, but the amount remains active,
   reward-earning, and slashable until admitted by the churn queue;
4. `CoolingDown`: removed from new voting snapshots and no longer earning, but
   still locked and slashable for evidence from its active window;
5. `Withdrawable`: the delay and slashable evidence window both ended;
6. `Withdrawn`: claimed exactly once and removed from locked-stake accounting.

Requests use a consensus sequence number and are processed FIFO. They record the
owner, validator, amount in base units, request epoch, admission epoch, earliest
release epoch, slashable-through epoch, and reward checkpoint. No wall-clock,
local file, network observation, or random value may decide a transition.

### Snapshots and graceful validator transitions

- Stake and committee membership are immutable within an epoch.
- Transactions may queue stake changes during an epoch, but only the deterministic
  epoch transition changes effective voting power.
- A pool is selected only if the next snapshot has at least 100 WEBC total active
  stake, at least 20 WEBC operator stake, and at least 20% operator stake.
- If admitted exits make the next snapshot invalid, the pool becomes `Draining`
  and is excluded from the next validator snapshot. It is never removed halfway
  through the current snapshot.
- A draining/inactive operator may keep a verification node online but cannot
  produce or vote. Remaining delegators retain individually owned positions and
  may exit or later redelegate; an operator cannot confiscate, cancel, or delay
  their valid FIFO requests.
- Operator partial exit cannot leave an active pool below the operator minimum or
  20% ratio. The operator must top up, wait for delegation exits, or drain the
  pool. Delegator exit rights are never conditioned on replacement deposits.

### Bounded churn and release

- Each epoch admits at most a configured number of base units from the global
  activation and exit queues. The value is versioned protocol configuration and
  must be selected by simulation/load tests, not product-owner preference.
- The confirmed “about 7 minutes devnet / about 7 days mainnet” is the normal
  minimum cooldown target, not a guaranteed deadline during a network-wide exit.
  Queue congestion may extend it.
- A cooling position becomes withdrawable only at
  `max(earliest_release_epoch, slashable_through_epoch + 1)`.
- Evidence submitted within the slashable window applies before release even if
  the owner requested exit earlier. Finalized claims cannot be replayed.
- Already-earned rewards are checkpointed when exit is admitted and remain
  claimable across partial/full exit. Cooling stake earns no new rewards.

### Liquidity buffers

WEBC consensus does not mint a liquid receipt token, borrow new deposits to pay
old exits, or promise immediate redemption. A future optional liquid-staking
application may maintain a Lido-like buffer, but it is a separately audited
application with explicit liquidity, oracle, slashing-socialization, and run
risk. Its receipt token never changes Layer-1 ownership or queue priority.

## Security invariants

- Mid-epoch stake transactions cannot change the current validator set.
- Queue processing is deterministic, FIFO, bounded, and identical after restart.
- `Active + ExitQueued + CoolingDown + Withdrawable + Withdrawn + slashed` value
  reconciles without double counting; only active stake contributes voting power.
- No exit bypasses objective evidence from its slashable period.
- No pool below the confirmed stake/ratio thresholds appears in a new snapshot.
- A mass exit degrades participation gradually by configured churn rather than
  invalidating many validators in one block.

## Required tests

- request/admission/maturity boundary tests on both sides of every epoch;
- partial and full exits with reward checkpoint preservation;
- exit plus same-window slash ordering and rollback;
- pool transition at 100/20/80 boundaries without mid-epoch power changes;
- FIFO and churn-cap tests under more requests than one epoch can admit;
- serialization/restart tests yielding the same queue and state root;
- randomized delegate/reward/slash/exit/claim sequences with supply invariants.

## References

- Ethereum staking withdrawals and current validator credential types:
  <https://ethereum.org/staking/withdrawals/>
- Ethereum EIP-7251 stake-weighted churn and compounding validators:
  <https://eips.ethereum.org/EIPS/eip-7251>
- Lido FIFO withdrawal queue and protocol buffer:
  <https://docs.lido.fi/contracts/withdrawal-queue-erc721/>
- Solana stake-account activation/deactivation lifecycle:
  <https://solana.com/docs/references/staking/stake-accounts>
