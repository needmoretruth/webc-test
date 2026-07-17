# ADR-0012: inactivity leak and slashing posture

Status: **proposed** — records the design direction and the owner-owned numbers
still to finalize for the economic-security phase (Phase 5). The slashing
_mechanism_ (objective evidence → slash → burn → tombstone) is already
implemented; this ADR fixes the _shape_ of the liveness-recovery ("inactivity
leak") mechanism and the _posture_ of the severity numbers, and enumerates the
exact constants the owner will confirm (owner direction 2026-07-17).

## Context

WEBC uses Tendermint-style BFT: a block is final once it collects **> 2/3**
precommit voting power. This gives instant, deterministic finality but inherits
Tendermint's liveness cliff — **if more than 1/3 of voting power goes offline the
chain cannot finalize and halts.** The owner directed (2026-07-17) that WEBC
should **not** halt permanently in that case: it should apply an **Ethereum-style
inactivity leak** so the offline validators' effective weight is drained until
the online set again exceeds 2/3 and finality resumes.

The owner also directed that the **slashing severity numbers are not final** —
they must live in a flexible config (`SlashingPolicy`, and the new
`InactivityLeakConfig`) with provisional defaults, to be **finalized later by
referencing Ethereum, Solana, Sui, Polkadot, and Cardano**. This ADR compiles
that reference comparison and proposes the WEBC design so the numbers can be
chosen against evidence rather than guessed.

## Reference comparison (sourced 2026-07-17)

| Chain | Mass-offline (> 1/3) behavior | Inactivity leak? | Equivocation / double-sign slash | Downtime penalty | Rejoin after fault |
|---|---|---|---|---|---|
| **Ethereum** (Casper FFG + LMD-GHOST) | Chain keeps producing un-finalized; finality stalls | **Yes — quadratic leak.** `INACTIVITY_SCORE_BIAS=4`, `…RECOVERY_RATE=16`, `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX=2^24`; per-epoch drain ≈ `score·balance/(4·2^24)`, cumulative ∝ `t(t+1)`. Drains only non-participating validators until participating set > 2/3. | Correlation penalty ≈ **3 × (fraction of total stake slashed in the ~36-day window)**, plus a base minimum + whistleblower reward. Isolated fault ≈ small; mass-correlated → up to 100%. | Small per-epoch inactivity penalty (miss ⇒ forgo ~what you'd have earned); **no stake slash** for mere downtime outside a leak. | Force-exit on slash; cannot rejoin with same key. |
| **Polkadot** (BABE + GRANDPA, NPoS) | BABE keeps producing; GRANDPA finality stalls | No automated leak | **`slash = min((3·x/n)², 1)`** (x offenders of n validators): 1/100 → 0.09%, 5/100 → 2.25%, 20/100 → 36%, → 100% for large coordinated. Backing-invalid = 100%, for-invalid = 2%, against-valid = 0%. | **No auto-slash for offline** — "chilling" (removal from active set) only; offline slash currently 0%. | 27–28-day grace before a slash applies; **governance can cancel/reverse** a slash; chilled validators can re-validate. |
| **Solana** (Tower BFT) | **Halts** (needs > 2/3 to root) | No — coordinated **manual restart** needing ~80% of stake online; non-responsive validators can be de-staked from the restart snapshot | Historically **none**. SIMD-0204 records violations (no slash); SIMD-0212 (proposed, not activated) = quadratic proportional, weight 10 duplicate-block vs 1 vote, `≈(3·max(0,TSS−NC)/TS)²`, 0% below a Nakamoto threshold, → 100% near 1/3 offending. | Delinquency = **opportunity cost only** (missed rewards); no jail, no slash. | Free rejoin; no tombstone. |
| **Sui** (Narwhal/Bullshark) | Halts beyond f faulty | No | **Tallying rule** — slashes only **staking rewards, never principal**; needs > 2/3 validator votes; covers downtime or equivocation. | Rewards-only (same tallying rule). | Low performers dropped at epoch boundary; can rejoin. |
| **Cardano** (Ouroboros Praos) | Longest-chain; tolerates offline pools probabilistically (no BFT halt) | N/A (not BFT) | **No slashing at all** — delegation is non-custodial, funds never leave the wallet, nothing is slashable. | None — offline pools simply miss rewards (delegators too). | N/A. |

**What the evidence says.** (1) Only Ethereum has an automated inactivity leak;
every other BFT chain here either halts and recovers socially (Solana), stalls
finality (Polkadot/Sui), or is not BFT (Cardano). (2) **Severity is driven by
_correlation_, not by isolated faults** — Polkadot `(3x/n)²`, Ethereum `3×`
fraction, Solana `(3·…)²` all make an isolated offender cheap and a coordinated
attack near-total. (3) **Downtime is rarely slashed** — Polkadot chills, Solana
and Cardano do nothing, Sui touches only rewards; Ethereum's downtime cost is a
mild reward-forgone, escalating only via the leak. This materially informs the
WEBC numbers: an aggressive _flat_ isolated slash (the earlier placeholder 80%,
or even 25%) is out of line with reference practice, whereas a
_correlation-scaled_ slash with a small isolated floor is the norm.

## Decision (direction)

### 1. Inactivity leak (liveness recovery)

Adopt an **Ethereum-style inactivity leak adapted to Tendermint**, opt-in via a
new `InactivityLeakConfig` (disabled by default until the owner confirms the
numbers and the consensus-safety design):

- **Participation record.** Track, per validator, participation in recent
  finalized blocks (precommits contributed). This is derivable from the
  finality certificates the chain already produces, and is committed to state so
  every node agrees deterministically.
- **Activation.** When finality has stalled for `leak_activation_epochs`
  (no new finalized height), enter **leak mode**.
- **Leak.** While in leak mode, each epoch drains a **growing (quadratic)**
  fraction of each *non-participating* validator's effective weight/stake, per an
  `INACTIVITY_PENALTY_QUOTIENT`-style curve; participating validators are exempt
  and their score decays. Drained units are **burned** (moved to `slashed_units`,
  the existing sink), consistent with the burn-not-redistribute rule.
- **Exit.** Leak mode ends when the participating set's weight again exceeds the
  `finality_quorum` (2/3), at which point finality resumes.

**The hard part (flagged for careful design + owner confirmation).** Vanilla
Tendermint cannot commit anything without 2/3, so it cannot _agree_ to reduce an
offline validator's weight while it is stalled — the very agreement the leak
needs is what is missing. Ethereum escapes this because LMD-GHOST yields a
canonical _un-finalized_ chain everyone follows and the leak is applied there,
with finality catching up. WEBC therefore needs one of:

- **(a) A recovery mode** that lets the online proposer extend an un-finalized
  but fork-choice-canonical chain which applies the deterministic leak, with
  finality re-established once drained weights cross 2/3. (Closest to Ethereum;
  the most protocol work; needs a safety argument that the recovery chain cannot
  finalize two conflicting histories.)
- **(b) A governance/weak-subjectivity restart** (Solana/Polkadot style): accept
  the halt, recover via an out-of-band signed checkpoint (ties into ADR-0011),
  no protocol leak. Simplest; but "halts", which the owner wants to avoid.
- **(c) Hybrid:** automatic bounded leak over a recovery chain with a governance
  backstop if it cannot converge.

This ADR proposes **(a)** as the direction (it is what "the network doesn't
halt" requires) while recording that the recovery-mode safety design and its
constants are owner-confirmed at this phase, not decided unilaterally.

### 2. Slashing posture

Keep the implemented mechanism (objective signed evidence → slash whole pool
pro-rata → burn via `slashed_units` → tombstone/jail; replay-guarded). Set the
_numbers_ against the reference evidence, in flexible config:

- **Equivocation / double-sign (severe):** a **correlation-scaled** slash —
  `slash_fraction = min(100%, max(base, k · correlated_fraction^p))` — with a
  **small isolated `base`** (reference isolated faults are 0.09%–5%, far below
  the old placeholders) ramping to 100% for coordinated attacks (Polkadot
  `p=2, k=3`; Ethereum `p=1, k=3`). Tombstone on severe fault.
- **Downtime / liveness:** **jail (re-bondable) + forgone rewards, with little or
  no stake slash** — matching Polkadot/Solana/Sui/Cardano practice. Sustained
  mass downtime is handled by the **inactivity leak**, not a flat downtime slash.
  (This supersedes the earlier provisional "0.1% downtime slash".)
- **Burn, not redistribute** (unchanged, implemented): no bounty to manufacture
  faults.
- **Tombstone vs jail:** tombstone (permanent, key-banned) for equivocation;
  jail (temporary, re-bondable after a cooldown) for downtime.

## The owner-owned numbers to finalize

Config constants, all defaulted conservatively / disabled until confirmed:

- Inactivity leak: `leak_activation_epochs`, the leak curve/quotient
  (`INACTIVITY_PENALTY_QUOTIENT` analogue), `finality_quorum` target (2/3), the
  per-epoch max leak, whether principal or only rewards leak, and **which
  recovery family (a/b/c)**.
- Slashing: equivocation `base`, correlation `k` and exponent `p`, the
  correlation window length, the jail cooldown, and any (probably zero) downtime
  slash.

## Consequences

- With the leak, a > 1/3-offline event degrades but does not permanently halt the
  chain: offline weight bleeds until the online set can finalize again — at the
  cost of a bounded, deterministic, burned leak from the offline validators.
- Aligning severity to correlation (small isolated, steep coordinated) matches
  every reference chain and avoids over-punishing honest failover accidents while
  keeping coordinated attacks fatal.
- The recovery-mode consensus change (option a) is the one item that must clear a
  safety review before implementation; until then the leak config stays disabled
  and WEBC retains the ADR-0011 weak-subjectivity restart as the fallback.
