//! Deterministic FIFO admission and maturity for stake exit requests.
//!
//! This module owns queue ordering and request lifecycle math, but it does not
//! mutate accounts, validator aggregates, rewards, or voting snapshots. The
//! chain state consumes returned transitions atomically. Requests can be
//! admitted in partial tranches so one request larger than an epoch's churn
//! budget cannot block every request behind it. All time is expressed in typed
//! consensus epochs; no wall clock or local timer is read here.

use crate::{Amount, ChainError, Epoch};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use webc_crypto::Address;

/// Principal source determining which active stake mirror admission reduces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnbondingKind {
    /// Validator operator self-stake.
    OperatorStake,
    /// One delegator's active position.
    Delegation,
}

/// Explicit lifecycle states that may coexist across a partially admitted request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnbondingStatus {
    /// Principal remains active while waiting for epoch churn admission.
    ExitQueued,
    /// Admitted principal is inactive but still inside its delay/evidence window.
    CoolingDown,
    /// Matured principal may be claimed exactly once by the owner.
    Withdrawable,
    /// Principal was already claimed and remains only as audit history.
    Withdrawn,
}

/// Monotonic identifier assigned to one unbonding request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnbondingRequestId(u64);

impl UnbondingRequestId {
    /// Constructs an ID from its consensus sequence number.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the consensus sequence number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One admitted amount cooling until both delay and evidence windows end.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoolingTranche {
    /// Stake amount in native base units.
    pub amount: Amount,
    /// Epoch at whose boundary this amount left active voting stake.
    pub admitted_epoch: Epoch,
    /// Last epoch (inclusive) at which this tranche is still slashable.
    ///
    /// ADR-0008 invariant: cooling principal is slashable only through its
    /// evidence window. When the normal cooldown is longer than the slashable
    /// window, a tranche can still be cooling (not yet `Withdrawable`) *after*
    /// this epoch — and it must no longer be slashable then. `slash_locked`
    /// compares the current epoch against this field so the window, not the
    /// cooldown, governs slashing.
    pub slashable_through: Epoch,
    /// First epoch at which the amount may be claimed if no slash applies.
    pub release_epoch: Epoch,
}

/// Persistent owner-scoped request, including partially admitted amounts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbondingRequest {
    /// Stable FIFO request ID.
    pub id: UnbondingRequestId,
    /// Delegator that owns and may claim the request.
    pub owner: Address,
    /// Validator pool from which stake exits.
    pub validator: Address,
    /// Active stake bucket from which this principal exits.
    pub kind: UnbondingKind,
    /// Epoch in which the signed request was accepted.
    pub requested_epoch: Epoch,
    /// Amount still active and waiting for churn admission.
    pub queued: Amount,
    /// Admitted amounts still inside their slashable cooldown window.
    pub cooling: Vec<CoolingTranche>,
    /// Matured amount available for a one-time owner claim.
    pub withdrawable: Amount,
    /// Total amount already claimed, retained for replay-safe audit history.
    pub claimed: Amount,
    /// Informational position reward snapshot at request time.
    ///
    /// This is not a second claimable balance. Canonical reward ownership stays
    /// in the delegation record so multiple partial requests cannot duplicate it.
    pub reward_checkpoint: Amount,
}

impl UnbondingRequest {
    /// Returns all principal ever assigned to this request.
    pub fn total_principal(&self) -> Result<Amount, ChainError> {
        self.cooling
            .iter()
            .try_fold(self.queued, |total, tranche| {
                total
                    .checked_add(tranche.amount)
                    .ok_or(ChainError::ArithmeticOverflow)
            })?
            .checked_add(self.withdrawable)
            .and_then(|total| total.checked_add(self.claimed))
            .ok_or(ChainError::ArithmeticOverflow)
    }

    /// Returns every lifecycle state currently represented by this request.
    ///
    /// Partial churn admission can make queued and cooling tranches coexist, so
    /// a request deliberately exposes a list rather than hiding that state in a
    /// single lossy label.
    pub fn lifecycle_states(&self) -> Vec<UnbondingStatus> {
        let mut states = Vec::with_capacity(4);
        if !self.queued.is_zero() {
            states.push(UnbondingStatus::ExitQueued);
        }
        if self.cooling.iter().any(|tranche| !tranche.amount.is_zero()) {
            states.push(UnbondingStatus::CoolingDown);
        }
        if !self.withdrawable.is_zero() {
            states.push(UnbondingStatus::Withdrawable);
        }
        if !self.claimed.is_zero() {
            states.push(UnbondingStatus::Withdrawn);
        }
        states
    }
}

/// State change that the chain accounting layer must apply atomically.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnbondingTransition {
    /// Amount stops voting/earning and enters its slashable cooldown.
    Admitted {
        request_id: UnbondingRequestId,
        owner: Address,
        validator: Address,
        kind: UnbondingKind,
        amount: Amount,
    },
    /// Cooling amount becomes eligible for an owner claim.
    Matured {
        request_id: UnbondingRequestId,
        owner: Address,
        validator: Address,
        kind: UnbondingKind,
        amount: Amount,
    },
}

/// Serializable FIFO queue with deterministic partial admission.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbondingQueue {
    next_id: u64,
    fifo: VecDeque<UnbondingRequestId>,
    requests: BTreeMap<UnbondingRequestId, UnbondingRequest>,
}

/// Cooling/withdrawable principal destroyed by a verified validator slash.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnbondingSlashOutcome {
    /// Per-owner locked principal loss that account mirrors must apply.
    pub locked_losses: BTreeMap<Address, Amount>,
    /// Checked total of `locked_losses` added to the protocol slash bucket.
    pub total_locked_slashed: Amount,
}

impl UnbondingQueue {
    /// Adds one non-zero exit request without changing active stake.
    pub fn request(
        &mut self,
        owner: Address,
        validator: Address,
        kind: UnbondingKind,
        amount: Amount,
        requested_epoch: Epoch,
        reward_checkpoint: Amount,
    ) -> Result<UnbondingRequestId, ChainError> {
        if amount.is_zero() {
            return Err(ChainError::UnbondingAmountZero);
        }
        let id = UnbondingRequestId::new(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or(ChainError::ArithmeticOverflow)?;
        self.fifo.push_back(id);
        self.requests.insert(
            id,
            UnbondingRequest {
                id,
                owner,
                validator,
                kind,
                requested_epoch,
                queued: amount,
                cooling: Vec::new(),
                withdrawable: Amount::ZERO,
                claimed: Amount::ZERO,
                reward_checkpoint,
            },
        );
        Ok(id)
    }

    /// Borrows one request for query and claim authorization.
    pub fn get(&self, id: UnbondingRequestId) -> Option<&UnbondingRequest> {
        self.requests.get(&id)
    }

    /// Iterates requests in stable identifier order for invariant inspection.
    ///
    /// Callers receive immutable records only; queue mutation remains confined
    /// to lifecycle methods so external code cannot bypass FIFO admission.
    pub fn requests(&self) -> impl Iterator<Item = &UnbondingRequest> {
        self.requests.values()
    }

    /// Returns active stake already promised to queued requests for a position.
    pub fn queued_for(
        &self,
        owner: Address,
        validator: Address,
        kind: UnbondingKind,
    ) -> Result<Amount, ChainError> {
        self.requests
            .values()
            .filter(|request| {
                request.owner == owner && request.validator == validator && request.kind == kind
            })
            .try_fold(Amount::ZERO, |total, request| {
                total
                    .checked_add(request.queued)
                    .ok_or(ChainError::ArithmeticOverflow)
            })
    }

    /// Reduces queued promises by up to the slash already applied to active stake.
    ///
    /// FIFO queued principal absorbs the position's verified active loss first.
    /// This conservative rule prevents an exit request from escaping a slash and
    /// guarantees queued principal never exceeds the remaining active position.
    pub fn apply_active_slash(
        &mut self,
        owner: Address,
        validator: Address,
        kind: UnbondingKind,
        active_loss: Amount,
    ) -> Result<Amount, ChainError> {
        let mut remaining = active_loss;
        let mut reduced = Amount::ZERO;
        for id in &self.fifo {
            if remaining.is_zero() {
                break;
            }
            let request = self
                .requests
                .get_mut(id)
                .ok_or(ChainError::UnbondingRequestNotFound)?;
            if request.owner != owner || request.validator != validator || request.kind != kind {
                continue;
            }
            let loss = Amount(request.queued.0.min(remaining.0));
            request.queued = request
                .queued
                .checked_sub(loss)
                .ok_or(ChainError::ArithmeticOverflow)?;
            remaining = remaining
                .checked_sub(loss)
                .ok_or(ChainError::ArithmeticOverflow)?;
            reduced = reduced
                .checked_add(loss)
                .ok_or(ChainError::ArithmeticOverflow)?;
        }
        self.fifo.retain(|id| {
            self.requests
                .get(id)
                .is_some_and(|request| !request.queued.is_zero())
        });
        Ok(reduced)
    }

    /// Applies the verified penalty rate to cooling principal still inside its
    /// slashable window at `epoch`.
    ///
    /// ADR-0008: only principal still inside its evidence window is slashable.
    /// Matured `withdrawable` principal has passed the window and is never
    /// slashed here, and a cooling tranche whose `slashable_through` epoch has
    /// passed (because the normal cooldown is longer) is skipped. `epoch` is the
    /// current consensus epoch at which the evidence is being applied.
    pub fn slash_locked(
        &mut self,
        validator: Address,
        penalty_bps: u16,
        epoch: Epoch,
    ) -> Result<UnbondingSlashOutcome, ChainError> {
        let mut outcome = UnbondingSlashOutcome::default();
        for request in self
            .requests
            .values_mut()
            .filter(|request| request.validator == validator)
        {
            let mut owner_loss = Amount::ZERO;
            for tranche in &mut request.cooling {
                // Skip tranches whose slashable window has closed; withdrawable
                // principal is excluded entirely (it has fully matured).
                if epoch > tranche.slashable_through {
                    continue;
                }
                let loss = tranche
                    .amount
                    .checked_mul_bps(penalty_bps)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                tranche.amount = tranche
                    .amount
                    .checked_sub(loss)
                    .ok_or(ChainError::ArithmeticOverflow)?;
                owner_loss = owner_loss
                    .checked_add(loss)
                    .ok_or(ChainError::ArithmeticOverflow)?;
            }
            if !owner_loss.is_zero() {
                let prior = outcome
                    .locked_losses
                    .get(&request.owner)
                    .copied()
                    .unwrap_or(Amount::ZERO);
                outcome.locked_losses.insert(
                    request.owner,
                    prior
                        .checked_add(owner_loss)
                        .ok_or(ChainError::ArithmeticOverflow)?,
                );
                outcome.total_locked_slashed = outcome
                    .total_locked_slashed
                    .checked_add(owner_loss)
                    .ok_or(ChainError::ArithmeticOverflow)?;
            }
        }
        Ok(outcome)
    }

    /// Advances maturity and admits FIFO principal within one epoch churn budget.
    ///
    /// `cooldown_epochs` and `slashable_epochs` are epoch counts. The release
    /// boundary is the later of the normal cooldown and the end of the evidence
    /// window. Returned transitions must be applied in order by the caller.
    pub fn advance_epoch(
        &mut self,
        epoch: Epoch,
        max_admission: Amount,
        cooldown_epochs: u64,
        slashable_epochs: u64,
    ) -> Result<Vec<UnbondingTransition>, ChainError> {
        let mut transitions = Vec::new();
        self.mature(epoch, &mut transitions)?;

        let mut remaining = max_admission;
        while !remaining.is_zero() {
            let Some(id) = self.fifo.front().copied() else {
                break;
            };
            let request = self
                .requests
                .get_mut(&id)
                .ok_or(ChainError::UnbondingRequestNotFound)?;
            let admitted = Amount(request.queued.0.min(remaining.0));
            let cooldown_end = epoch
                .get()
                .checked_add(cooldown_epochs)
                .ok_or(ChainError::ArithmeticOverflow)?;
            // Last epoch (inclusive) the tranche stays slashable, then one past
            // it for the release boundary.
            let slashable_through = epoch
                .get()
                .checked_add(slashable_epochs)
                .ok_or(ChainError::ArithmeticOverflow)?;
            let slashable_end = slashable_through
                .checked_add(1)
                .ok_or(ChainError::ArithmeticOverflow)?;
            request.queued = request
                .queued
                .checked_sub(admitted)
                .ok_or(ChainError::ArithmeticOverflow)?;
            request.cooling.push(CoolingTranche {
                amount: admitted,
                admitted_epoch: epoch,
                slashable_through: Epoch::new(slashable_through),
                release_epoch: Epoch::new(cooldown_end.max(slashable_end)),
            });
            remaining = remaining
                .checked_sub(admitted)
                .ok_or(ChainError::ArithmeticOverflow)?;
            transitions.push(UnbondingTransition::Admitted {
                request_id: id,
                owner: request.owner,
                validator: request.validator,
                kind: request.kind,
                amount: admitted,
            });
            if request.queued.is_zero() {
                self.fifo.pop_front();
            }
        }

        // U2: drop fully-settled requests so the queue does not grow without
        // bound and every per-epoch scan (`mature`, `slash_locked`, `queued_for`)
        // stays cheap. A request is settled once no live principal remains in any
        // bucket — it has been fully claimed or fully slashed. Request IDs are
        // monotonic and never reused, so a pruned request cannot be revived or
        // replayed: a later claim on its ID fails with `UnbondingRequestNotFound`,
        // identical to an ID that never existed.
        self.requests.retain(|_, request| {
            !(request.queued.is_zero()
                && request.withdrawable.is_zero()
                && request.cooling.is_empty())
        });

        Ok(transitions)
    }

    fn mature(
        &mut self,
        epoch: Epoch,
        transitions: &mut Vec<UnbondingTransition>,
    ) -> Result<(), ChainError> {
        for request in self.requests.values_mut() {
            let mut still_cooling = Vec::with_capacity(request.cooling.len());
            for tranche in request.cooling.drain(..) {
                if tranche.release_epoch <= epoch {
                    request.withdrawable = request
                        .withdrawable
                        .checked_add(tranche.amount)
                        .ok_or(ChainError::ArithmeticOverflow)?;
                    transitions.push(UnbondingTransition::Matured {
                        request_id: request.id,
                        owner: request.owner,
                        validator: request.validator,
                        kind: request.kind,
                        amount: tranche.amount,
                    });
                } else {
                    still_cooling.push(tranche);
                }
            }
            request.cooling = still_cooling;
        }
        Ok(())
    }

    /// Claims all matured principal for the authorized owner exactly once.
    pub fn claim(&mut self, id: UnbondingRequestId, owner: Address) -> Result<Amount, ChainError> {
        let request = self
            .requests
            .get_mut(&id)
            .ok_or(ChainError::UnbondingRequestNotFound)?;
        if request.owner != owner {
            return Err(ChainError::UnbondingOwnerMismatch);
        }
        if request.withdrawable.is_zero() {
            return Err(ChainError::UnbondingNotWithdrawable);
        }
        let amount = request.withdrawable;
        request.withdrawable = Amount::ZERO;
        request.claimed = request
            .claimed
            .checked_add(amount)
            .ok_or(ChainError::ArithmeticOverflow)?;
        Ok(amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    #[test]
    fn fifo_partial_admission_and_maturity_are_deterministic() {
        let owner = Keypair::from_seed([1u8; 32]).address();
        let validator = Keypair::from_seed([2u8; 32]).address();
        let mut queue = UnbondingQueue::default();
        let first = queue
            .request(
                owner,
                validator,
                UnbondingKind::Delegation,
                Amount::from_units(7),
                Epoch::new(1),
                Amount::ZERO,
            )
            .expect("request");
        let second = queue
            .request(
                owner,
                validator,
                UnbondingKind::Delegation,
                Amount::from_units(5),
                Epoch::new(1),
                Amount::ZERO,
            )
            .expect("request");

        let transitions = queue
            .advance_epoch(Epoch::new(2), Amount::from_units(10), 3, 1)
            .expect("advance");
        assert_eq!(transitions.len(), 2);
        assert_eq!(queue.get(first).expect("first").queued, Amount::ZERO);
        assert_eq!(
            queue.get(second).expect("second").queued,
            Amount::from_units(2)
        );
        assert_eq!(
            queue.get(second).expect("second").lifecycle_states(),
            vec![UnbondingStatus::ExitQueued, UnbondingStatus::CoolingDown]
        );
        assert!(queue
            .advance_epoch(Epoch::new(4), Amount::ZERO, 3, 1)
            .expect("before maturity")
            .is_empty());
        assert_eq!(
            queue
                .advance_epoch(Epoch::new(5), Amount::ZERO, 3, 1)
                .expect("maturity")
                .len(),
            2
        );
        assert_eq!(
            queue.claim(first, owner).expect("claim"),
            Amount::from_units(7)
        );
        assert_eq!(
            queue.get(first).expect("first").lifecycle_states(),
            vec![UnbondingStatus::Withdrawn]
        );
        assert!(matches!(
            queue.claim(first, owner),
            Err(ChainError::UnbondingNotWithdrawable)
        ));
    }

    #[test]
    fn serialization_restart_preserves_queue_result() {
        let owner = Keypair::from_seed([3u8; 32]).address();
        let validator = Keypair::from_seed([4u8; 32]).address();
        let mut original = UnbondingQueue::default();
        original
            .request(
                owner,
                validator,
                UnbondingKind::Delegation,
                Amount::from_units(11),
                Epoch::new(7),
                Amount::from_units(2),
            )
            .expect("request");
        let bytes = serde_json::to_vec(&original).expect("serialize queue");
        let mut restarted: UnbondingQueue = serde_json::from_slice(&bytes).expect("restore queue");

        let expected = original
            .advance_epoch(Epoch::new(8), Amount::from_units(6), 2, 2)
            .expect("advance original");
        let actual = restarted
            .advance_epoch(Epoch::new(8), Amount::from_units(6), 2, 2)
            .expect("advance restored");
        assert_eq!(actual, expected);
        assert_eq!(restarted, original);
    }

    #[test]
    fn queued_and_cooling_principal_remain_slashable() {
        let owner = Keypair::from_seed([5u8; 32]).address();
        let validator = Keypair::from_seed([6u8; 32]).address();

        let mut queued = UnbondingQueue::default();
        let queued_id = queued
            .request(
                owner,
                validator,
                UnbondingKind::Delegation,
                Amount::from_units(80),
                Epoch::new(1),
                Amount::ZERO,
            )
            .expect("request");
        assert_eq!(
            queued
                .apply_active_slash(
                    owner,
                    validator,
                    UnbondingKind::Delegation,
                    Amount::from_units(64),
                )
                .expect("active slash"),
            Amount::from_units(64)
        );
        assert_eq!(
            queued.get(queued_id).expect("request").queued,
            Amount::from_units(16)
        );

        let mut cooling = UnbondingQueue::default();
        let cooling_id = cooling
            .request(
                owner,
                validator,
                UnbondingKind::Delegation,
                Amount::from_units(80),
                Epoch::new(1),
                Amount::ZERO,
            )
            .expect("request");
        cooling
            .advance_epoch(Epoch::new(2), Amount::from_units(80), 3, 3)
            .expect("admission");
        // Admitted at epoch 2 with slashable_epochs = 3, so slashable through
        // epoch 5; slash while still inside the window.
        let outcome = cooling
            .slash_locked(validator, 8_000, Epoch::new(2))
            .expect("locked slash");
        assert_eq!(outcome.total_locked_slashed, Amount::from_units(64));
        assert_eq!(
            cooling
                .get(cooling_id)
                .expect("request")
                .total_principal()
                .expect("principal"),
            Amount::from_units(16)
        );
    }

    #[test]
    fn slash_locked_skips_cooling_past_its_slashable_window() {
        // U1: with a long cooldown and a short evidence window, a tranche can be
        // still cooling but past its slashable window. It must NOT be slashed.
        let owner = Keypair::from_seed([7u8; 32]).address();
        let validator = Keypair::from_seed([8u8; 32]).address();
        let mut queue = UnbondingQueue::default();
        let id = queue
            .request(
                owner,
                validator,
                UnbondingKind::OperatorStake,
                Amount::from_units(100),
                Epoch::new(1),
                Amount::ZERO,
            )
            .expect("request");
        // Admit at epoch 2 with slashable_epochs = 1 (window through epoch 3) and
        // cooldown_epochs = 5 (release at epoch 7).
        queue
            .advance_epoch(Epoch::new(2), Amount::from_units(100), 5, 1)
            .expect("admission");

        // Inside the window (epoch 3): slashable.
        let mut inside = queue.clone();
        let outcome = inside
            .slash_locked(validator, 8_000, Epoch::new(3))
            .expect("in-window slash");
        assert_eq!(outcome.total_locked_slashed, Amount::from_units(80));

        // Past the window but still cooling (epoch 5): nothing slashed.
        let outcome = queue
            .slash_locked(validator, 8_000, Epoch::new(5))
            .expect("out-of-window slash");
        assert_eq!(outcome.total_locked_slashed, Amount::ZERO);
        assert_eq!(
            queue
                .get(id)
                .expect("request")
                .total_principal()
                .expect("principal"),
            Amount::from_units(100)
        );
    }

    #[test]
    fn slash_locked_never_slashes_matured_withdrawable_principal() {
        // U1: matured principal has passed its slashable window entirely.
        let owner = Keypair::from_seed([9u8; 32]).address();
        let validator = Keypair::from_seed([10u8; 32]).address();
        let mut queue = UnbondingQueue::default();
        let id = queue
            .request(
                owner,
                validator,
                UnbondingKind::OperatorStake,
                Amount::from_units(50),
                Epoch::new(1),
                Amount::ZERO,
            )
            .expect("request");
        // Admit at epoch 2 (slashable through 3, release at 4), then advance past
        // release so the tranche matures into withdrawable.
        queue
            .advance_epoch(Epoch::new(2), Amount::from_units(50), 2, 1)
            .expect("admission");
        queue
            .advance_epoch(Epoch::new(5), Amount::ZERO, 2, 1)
            .expect("maturity");
        assert_eq!(
            queue.get(id).expect("request").withdrawable,
            Amount::from_units(50)
        );
        let outcome = queue
            .slash_locked(validator, 8_000, Epoch::new(5))
            .expect("slash after maturity");
        assert_eq!(outcome.total_locked_slashed, Amount::ZERO);
        assert_eq!(
            queue.get(id).expect("request").withdrawable,
            Amount::from_units(50)
        );
    }

    #[test]
    fn advance_epoch_prunes_fully_settled_requests() {
        // U2: a fully claimed request is dropped on the next epoch advance so the
        // queue does not grow without bound.
        let owner = Keypair::from_seed([11u8; 32]).address();
        let validator = Keypair::from_seed([12u8; 32]).address();
        let mut queue = UnbondingQueue::default();
        let id = queue
            .request(
                owner,
                validator,
                UnbondingKind::Delegation,
                Amount::from_units(9),
                Epoch::new(1),
                Amount::ZERO,
            )
            .expect("request");
        queue
            .advance_epoch(Epoch::new(2), Amount::from_units(9), 1, 1)
            .expect("admission");
        // Mature (release at epoch 4) then claim everything.
        queue
            .advance_epoch(Epoch::new(4), Amount::ZERO, 1, 1)
            .expect("maturity");
        assert_eq!(
            queue.claim(id, owner).expect("claim"),
            Amount::from_units(9)
        );
        assert!(
            queue.get(id).is_some(),
            "settled request still present pre-prune"
        );
        // The next advance prunes the fully-settled request.
        queue
            .advance_epoch(Epoch::new(5), Amount::ZERO, 1, 1)
            .expect("prune advance");
        assert!(queue.get(id).is_none(), "settled request pruned");
        assert_eq!(queue.requests().count(), 0);
    }
}
