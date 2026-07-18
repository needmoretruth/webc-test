//! Protocol-version-2 transaction admission and execution boundaries.
//!
//! Purpose: turn a hostile signed V5 wire value into progressively stronger
//! typed states before any consensus mutation. This module currently owns the
//! stateless [`ValidatedTransactionV1`] boundary; state/height/fee preparation
//! and two-level execution follow in the same module. It does not decode HTTP,
//! choose mempool policy, build blocks, or persist lifecycle records.
//!
//! Data flows from `TransactionV5` through signature/chain/structure checks and
//! an exact access-list recomputation. Only the opaque validated wrapper may
//! enter preparation. Security boundary: callers cannot construct the wrapper
//! with struct syntax, so a sponsored transaction that omits payer or grant
//! state cannot accidentally reach fee reservation.

use crate::{
    ActionV1, Amount, AuthorizationLaneId, BlockHeight, ChainId, ChainState, FeePayerV1,
    FeePaymentV1, FeeRate, GasUnits, Nonce, Operation, SessionKey, SessionKeyId, SponsorUseCount,
    SponsorUseNonce, TransactionKindV1, TransactionV5, TransactionValidationErrorV1,
    LEGACY_AUTHORIZATION_POLICY_REVISION,
};
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, Hash256, PublicKeyBytes};

/// Durable replay, fee-budget, use-count, and revocation state for one grant.
///
/// A grant may be revoked before its first use, so `grant_digest` is optional.
/// Once a use records the digest it never changes; presenting another immutable
/// grant under the same `(sponsor, grant_id)` is rejected during preparation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SponsorGrantStateV1 {
    /// Digest of the first complete signed grant observed, or none before use.
    pub grant_digest: Option<Hash256>,
    /// Exact use nonce required by the next includable sponsored transaction.
    pub next_use_nonce: SponsorUseNonce,
    /// Actual native base units charged across all included uses.
    pub total_charged: Amount,
    /// Number of included uses, including chargeable action failures.
    pub uses: SponsorUseCount,
    /// Permanent owner-authorized revocation marker.
    pub revoked: bool,
}

/// Stable state-dependent rejection before a transaction becomes includable.
///
/// These failures consume no nonce or fee. Arithmetic/invariant errors remain
/// distinct because an internal state inconsistency is never a chargeable user
/// failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TransactionPreparationErrorV1 {
    /// The signed validity window excludes the candidate block height.
    #[error("V5 transaction is outside its signed height window")]
    HeightOutsideValidity,
    /// Static action units exceed the sender-authorized gas limit.
    #[error("V5 gas limit is below statically required units")]
    GasLimitTooLow,
    /// The maximum rate cannot pay the current block base fee.
    #[error("V5 maximum fee rate is below the current base fee")]
    FeeBidBelowBase,
    /// The sender account or selected sender lane does not exist.
    #[error("V5 sender or authorization lane was not found")]
    SenderStateNotFound,
    /// The sender key, policy revision, session constraints, or expiry is invalid.
    #[error("V5 sender authority is not valid in current state")]
    SenderAuthorizationInvalid,
    /// The signed sender nonce is not the next nonce in its lane.
    #[error("V5 sender nonce does not match current state")]
    SenderNonceMismatch,
    /// The selected payer account or prepaid lane does not exist.
    #[error("V5 fee payer or payer lane was not found")]
    FeePayerStateNotFound,
    /// The payer cannot reserve `gas_limit * max_fee_per_unit`.
    #[error("V5 fee payer cannot cover the maximum reserve")]
    InsufficientFeeReserve,
    /// The sponsor signing key is not the sponsor's current authority.
    #[error("V5 sponsor authority is not valid in current state")]
    SponsorAuthorizationInvalid,
    /// Durable state under this grant id belongs to another immutable grant.
    #[error("V5 sponsor grant digest conflicts with durable state")]
    SponsorGrantMismatch,
    /// The grant was permanently revoked by its sponsor.
    #[error("V5 sponsor grant is revoked")]
    SponsorGrantRevoked,
    /// The use nonce is not the durable next nonce.
    #[error("V5 sponsor use nonce does not match current state")]
    SponsorNonceMismatch,
    /// The signed maximum use count has already been reached.
    #[error("V5 sponsor grant use count is exhausted")]
    SponsorUsesExhausted,
    /// Worst-case reservation would exceed the signed cumulative budget.
    #[error("V5 sponsor grant cumulative budget is exhausted")]
    SponsorBudgetExceeded,
    /// A checked consensus calculation overflowed or decoded state was invalid.
    #[error("V5 preparation encountered an invalid internal state")]
    InvalidState,
}

/// Stateful sender authority selected during preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedAuthorizationV1 {
    /// The account's active or legacy address-derived transaction key.
    AccountKey,
    /// An installed constrained session key whose budgets advance on inclusion.
    SessionKey(SessionKeyId),
}

/// A validated V5 transaction proven includable against one state snapshot.
///
/// Preparation is pure: it captures checked identities, units, fee rates,
/// reserve, and authority without mutating balances, nonces, or grant records.
/// It must be consumed against the same ordered parent state snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedTransactionV1 {
    validated: ValidatedTransactionV1,
    transaction_id: crate::TransactionId,
    fee_payer: FeePayerV1,
    fee_reserve: Amount,
    required_units: GasUnits,
    base_fee_per_unit: FeeRate,
    effective_priority_fee_per_unit: FeeRate,
    authorization: PreparedAuthorizationV1,
}

impl PreparedTransactionV1 {
    /// Borrows the stateless-validated signed transaction.
    pub const fn validated(&self) -> &ValidatedTransactionV1 {
        &self.validated
    }

    /// Returns the complete signed transaction identity used by receipts.
    pub const fn transaction_id(&self) -> crate::TransactionId {
        self.transaction_id
    }

    /// Returns the exact account/lane that must reserve the fee.
    pub const fn fee_payer(&self) -> FeePayerV1 {
        self.fee_payer
    }

    /// Returns `gas_limit * max_fee_per_unit` in native base units.
    pub const fn fee_reserve(&self) -> Amount {
        self.fee_reserve
    }

    /// Returns checked static units for every action or cancellation.
    pub const fn required_units(&self) -> GasUnits {
        self.required_units
    }

    /// Returns the current block base rate captured during preparation.
    pub const fn base_fee_per_unit(&self) -> FeeRate {
        self.base_fee_per_unit
    }

    /// Returns the signed priority rate capped by maximum-minus-base room.
    pub const fn effective_priority_fee_per_unit(&self) -> FeeRate {
        self.effective_priority_fee_per_unit
    }

    /// Returns the state authority selected for later budget accounting.
    pub const fn authorization(&self) -> PreparedAuthorizationV1 {
        self.authorization
    }
}

/// A signed V5 transaction whose stateless admission checks have passed.
///
/// Invariants: the schema and chain are supported, sender/sponsor signatures
/// verify, all structural bounds hold, and the signed access list exactly equals
/// the deterministic authorization/fee/action union. Stateful nonce, balance,
/// height, policy, and sponsor-budget checks belong to preparation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedTransactionV1 {
    transaction: TransactionV5,
}

impl ValidatedTransactionV1 {
    /// Verifies one hostile signed transaction without changing chain state.
    ///
    /// `expected_chain` is the genesis-fixed replay domain. Any signature,
    /// sponsor binding, bound, chain, or exact-access failure is returned as a
    /// stable validation error and the candidate remains unincludable/free.
    pub fn validate(
        transaction: TransactionV5,
        expected_chain: &ChainId,
    ) -> Result<Self, TransactionValidationErrorV1> {
        transaction.verify_for_chain(expected_chain)?;
        if transaction.access_list != transaction.expected_access_list()? {
            return Err(TransactionValidationErrorV1::InvalidAccessList);
        }
        Ok(Self { transaction })
    }

    /// Borrows the fully checked signed transaction.
    pub const fn transaction(&self) -> &TransactionV5 {
        &self.transaction
    }

    /// Returns ownership for the later preparation or durable admission layer.
    pub fn into_transaction(self) -> TransactionV5 {
        self.transaction
    }
}

impl ChainState {
    /// Prepares one validated transaction against the current ordered state.
    ///
    /// This pure check performs no reservation or nonce mutation. It verifies
    /// height, static units, base-fee coverage, sender authority/nonce/session
    /// constraints, payer reserve, and sponsor replay/budget/revocation state.
    /// The returned value is snapshot-specific and must be consumed before any
    /// other transaction changes the same logical keys.
    pub fn prepare_transaction_v1(
        &self,
        validated: ValidatedTransactionV1,
        height: BlockHeight,
    ) -> Result<PreparedTransactionV1, TransactionPreparationErrorV1> {
        let transaction = validated.transaction();
        if !transaction.validity.contains(height) {
            return Err(TransactionPreparationErrorV1::HeightOutsideValidity);
        }

        let required_units = transaction
            .required_units()
            .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
        if transaction.fee_bid.gas_limit < required_units {
            return Err(TransactionPreparationErrorV1::GasLimitTooLow);
        }
        let priority_room = transaction
            .fee_bid
            .max_fee_per_unit
            .checked_sub(self.current_base_fee_per_unit)
            .ok_or(TransactionPreparationErrorV1::FeeBidBelowBase)?;
        let fee_reserve = Amount::from_units(
            u128::from(transaction.fee_bid.gas_limit)
                .checked_mul(u128::from(transaction.fee_bid.max_fee_per_unit))
                .ok_or(TransactionPreparationErrorV1::InvalidState)?,
        );

        let authorization = prepare_sender_authorization(self, transaction, fee_reserve)?;
        let expected_nonce =
            sender_nonce(self, transaction.sender, transaction.authorization.lane)?;
        if expected_nonce != transaction.authorization.nonce {
            return Err(TransactionPreparationErrorV1::SenderNonceMismatch);
        }

        let fee_payer = match &transaction.fee_payment {
            FeePaymentV1::SenderLane => FeePayerV1 {
                address: transaction.sender,
                lane: transaction.authorization.lane,
            },
            FeePaymentV1::Sponsored(sponsor_use) => {
                prepare_sponsor_use(self, transaction, sponsor_use, height, fee_reserve)?;
                FeePayerV1 {
                    address: sponsor_use.grant.sponsor,
                    lane: sponsor_use.grant.payer_lane,
                }
            }
        };
        if payer_balance(self, fee_payer)? < fee_reserve {
            return Err(TransactionPreparationErrorV1::InsufficientFeeReserve);
        }

        Ok(PreparedTransactionV1 {
            transaction_id: transaction
                .transaction_id()
                .map_err(|_| TransactionPreparationErrorV1::InvalidState)?,
            fee_payer,
            fee_reserve,
            required_units: GasUnits::new(required_units),
            base_fee_per_unit: FeeRate::new(self.current_base_fee_per_unit),
            effective_priority_fee_per_unit: FeeRate::new(
                transaction.fee_bid.priority_fee_per_unit.min(priority_room),
            ),
            authorization,
            validated,
        })
    }
}

fn prepare_sender_authorization(
    state: &ChainState,
    transaction: &TransactionV5,
    fee_reserve: Amount,
) -> Result<PreparedAuthorizationV1, TransactionPreparationErrorV1> {
    if !state.accounts.contains_key(&transaction.sender) {
        return Err(TransactionPreparationErrorV1::SenderStateNotFound);
    }
    let Some(policy) = state.authorization_policies.get(&transaction.sender) else {
        if transaction.authorization.policy_revision != LEGACY_AUTHORIZATION_POLICY_REVISION
            || Address::from_public_key(&transaction.sender_public_key) != transaction.sender
        {
            return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
        }
        return Ok(PreparedAuthorizationV1::AccountKey);
    };
    policy
        .validate()
        .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
    if transaction.authorization.policy_revision != policy.revision() {
        return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
    }
    if &transaction.sender_public_key == policy.active_transaction_key() {
        return Ok(PreparedAuthorizationV1::AccountKey);
    }

    let session_id = SessionKeyId::derive(&transaction.sender_public_key);
    let session = state
        .session_keys
        .get(&(transaction.sender, session_id))
        .ok_or(TransactionPreparationErrorV1::SenderAuthorizationInvalid)?;
    validate_session_authority(state, transaction, session, fee_reserve)?;
    Ok(PreparedAuthorizationV1::SessionKey(session_id))
}

fn validate_session_authority(
    state: &ChainState,
    transaction: &TransactionV5,
    session: &SessionKey,
    fee_reserve: Amount,
) -> Result<(), TransactionPreparationErrorV1> {
    session
        .validate()
        .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
    if session.owner != transaction.sender
        || session.session_public_key != transaction.sender_public_key
        || session.policy_revision != transaction.authorization.policy_revision
        || session.constraints.authorization_lane != transaction.authorization.lane
        || session.expires_after_epoch.get() < state.current_epoch
    {
        return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
    }

    let TransactionKindV1::Actions(program) = &transaction.kind else {
        return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
    };
    let mut principal = Amount::ZERO;
    for action in &program.actions {
        let ActionV1::Native { operation } = action else {
            return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
        };
        let Operation::Transfer { amount, .. } = operation.as_ref() else {
            return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
        };
        principal = principal
            .checked_add(*amount)
            .ok_or(TransactionPreparationErrorV1::InvalidState)?;
    }
    let constraints = &session.constraints;
    if !constraints.allowed_operations.transfer
        || principal > constraints.max_amount_per_use
        || session
            .spent_amount
            .checked_add(principal)
            .ok_or(TransactionPreparationErrorV1::InvalidState)?
            > constraints.total_amount_budget
        || fee_reserve > constraints.max_fee_per_use
        || session
            .spent_fees
            .checked_add(fee_reserve)
            .ok_or(TransactionPreparationErrorV1::InvalidState)?
            > constraints.total_fee_budget
    {
        return Err(TransactionPreparationErrorV1::SenderAuthorizationInvalid);
    }
    Ok(())
}

fn sender_nonce(
    state: &ChainState,
    sender: Address,
    lane: AuthorizationLaneId,
) -> Result<Nonce, TransactionPreparationErrorV1> {
    if lane.is_default() {
        return state
            .accounts
            .get(&sender)
            .map(|account| Nonce::new(account.nonce))
            .ok_or(TransactionPreparationErrorV1::SenderStateNotFound);
    }
    let lane_state = state
        .authorization_lanes
        .get(&(sender, lane))
        .ok_or(TransactionPreparationErrorV1::SenderStateNotFound)?;
    if lane_state.owner != sender || lane_state.id != lane {
        return Err(TransactionPreparationErrorV1::InvalidState);
    }
    Ok(lane_state.next_nonce)
}

fn payer_balance(
    state: &ChainState,
    payer: FeePayerV1,
) -> Result<Amount, TransactionPreparationErrorV1> {
    if payer.lane.is_default() {
        return state
            .accounts
            .get(&payer.address)
            .map(|account| account.balance)
            .ok_or(TransactionPreparationErrorV1::FeePayerStateNotFound);
    }
    let lane = state
        .authorization_lanes
        .get(&(payer.address, payer.lane))
        .ok_or(TransactionPreparationErrorV1::FeePayerStateNotFound)?;
    if lane.owner != payer.address || lane.id != payer.lane {
        return Err(TransactionPreparationErrorV1::InvalidState);
    }
    Ok(lane.fee_balance)
}

fn prepare_sponsor_use(
    state: &ChainState,
    transaction: &TransactionV5,
    sponsor_use: &crate::SponsorUseV1,
    height: BlockHeight,
    fee_reserve: Amount,
) -> Result<(), TransactionPreparationErrorV1> {
    let grant = &sponsor_use.grant;
    if !grant.validity.contains(height)
        || !account_key_is_current(state, grant.sponsor, &grant.sponsor_public_key)?
    {
        return Err(TransactionPreparationErrorV1::SponsorAuthorizationInvalid);
    }
    let record = state
        .sponsor_grants
        .get(&(grant.sponsor, grant.grant_id))
        .copied()
        .unwrap_or_default();
    if record.revoked {
        return Err(TransactionPreparationErrorV1::SponsorGrantRevoked);
    }
    if record
        .grant_digest
        .is_some_and(|digest| digest != sponsor_use.grant_digest)
    {
        return Err(TransactionPreparationErrorV1::SponsorGrantMismatch);
    }
    if record.next_use_nonce != sponsor_use.use_nonce {
        return Err(TransactionPreparationErrorV1::SponsorNonceMismatch);
    }
    if record.uses.get() >= grant.max_uses {
        return Err(TransactionPreparationErrorV1::SponsorUsesExhausted);
    }
    if record
        .total_charged
        .checked_add(fee_reserve)
        .ok_or(TransactionPreparationErrorV1::InvalidState)?
        > grant.max_cumulative_fee
    {
        return Err(TransactionPreparationErrorV1::SponsorBudgetExceeded);
    }
    if transaction.sender != grant.sender {
        return Err(TransactionPreparationErrorV1::SponsorGrantMismatch);
    }
    Ok(())
}

fn account_key_is_current(
    state: &ChainState,
    account: Address,
    key: &PublicKeyBytes,
) -> Result<bool, TransactionPreparationErrorV1> {
    if !state.accounts.contains_key(&account) {
        return Ok(false);
    }
    let Some(policy) = state.authorization_policies.get(&account) else {
        return Ok(Address::from_public_key(key) == account);
    };
    policy
        .validate()
        .map_err(|_| TransactionPreparationErrorV1::InvalidState)?;
    Ok(policy.active_transaction_key() == key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Account, ActionScopeV1, ActionV1, Amount, AuthorizationLaneId, AuthorizationPolicyRevision,
        BlockHeight, ChainState, FeeBid, FeePaymentV1, Nonce, Operation, SponsorGrantId,
        SponsorGrantV1, SponsorUseCount, SponsorUseNonce, SponsorUseV1, TransactionAuthorizationV1,
        ValidityWindowV1, TRANSACTION_V5_PROTOCOL_VERSION,
    };
    use webc_crypto::{Hash256, Keypair};

    fn sender_paid_fixture(sender: &Keypair, recipient: &Keypair) -> TransactionV5 {
        let mut transaction = TransactionV5::for_actions_unsigned(
            ChainId::devnet(),
            sender.address(),
            sender.public_key(),
            TransactionAuthorizationV1 {
                lane: AuthorizationLaneId::DEFAULT,
                policy_revision: AuthorizationPolicyRevision::new(0),
                nonce: Nonce::new(0),
            },
            ValidityWindowV1::new(BlockHeight::new(10), BlockHeight::new(20)),
            vec![ActionV1::native(Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_units(100),
            })],
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 5,
                priority_fee_per_unit: 1,
            },
            FeePaymentV1::SenderLane,
        )
        .expect("bounded sender fixture");
        transaction.sign(sender).expect("sender fixture signs");
        transaction
    }

    fn sponsored_fixture(
        sender: &Keypair,
        recipient: &Keypair,
        sponsor: &Keypair,
        exact_access: bool,
    ) -> TransactionV5 {
        let mut transaction = sender_paid_fixture(sender, recipient);
        transaction.sender_signature = None;
        let validity = transaction.validity;
        let mut grant = SponsorGrantV1 {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            grant_id: SponsorGrantId::new(Hash256([0x44; 32])),
            sponsor: sponsor.address(),
            sponsor_public_key: sponsor.public_key(),
            payer_lane: AuthorizationLaneId::DEFAULT,
            sender: sender.address(),
            site_namespace: None,
            application_namespace: None,
            action_scope: ActionScopeV1::exact(transaction.kind.digest().expect("action digest")),
            validity,
            max_fee_per_transaction: Amount::from_units(5_000),
            max_cumulative_fee: Amount::from_units(50_000),
            max_uses: 10,
            sponsor_signature: None,
        };
        grant.sign(sponsor).expect("grant signs");
        transaction.fee_payment = FeePaymentV1::Sponsored(Box::new(
            SponsorUseV1::for_transaction(
                grant,
                SponsorUseNonce::new(0),
                &transaction.kind,
                transaction.fee_bid,
            )
            .expect("sponsor use"),
        ));
        if exact_access {
            transaction.access_list = transaction.expected_access_list().expect("exact access");
        }
        transaction.sign(sender).expect("sponsored fixture signs");
        transaction
    }

    fn funded_state(sender: &Keypair, sponsor: Option<&Keypair>) -> ChainState {
        let mut state = ChainState {
            current_base_fee_per_unit: 2,
            ..ChainState::default()
        };
        state.accounts.insert(
            sender.address(),
            Account::with_balance(Amount::from_units(20_000)),
        );
        if let Some(sponsor) = sponsor {
            state.accounts.insert(
                sponsor.address(),
                Account::with_balance(Amount::from_units(20_000)),
            );
        }
        state
    }

    #[test]
    fn validation_accepts_exact_sender_and_sponsor_access() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsor = Keypair::from_seed([3; 32]);

        assert!(ValidatedTransactionV1::validate(
            sender_paid_fixture(&sender, &recipient),
            &ChainId::devnet()
        )
        .is_ok());
        assert!(ValidatedTransactionV1::validate(
            sponsored_fixture(&sender, &recipient, &sponsor, true),
            &ChainId::devnet()
        )
        .is_ok());
    }

    #[test]
    fn validation_rejects_sender_shaped_sponsor_access_and_wrong_chain() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsor = Keypair::from_seed([3; 32]);

        assert_eq!(
            ValidatedTransactionV1::validate(
                sponsored_fixture(&sender, &recipient, &sponsor, false),
                &ChainId::devnet(),
            ),
            Err(TransactionValidationErrorV1::InvalidAccessList)
        );
        assert_eq!(
            ValidatedTransactionV1::validate(
                sender_paid_fixture(&sender, &recipient),
                &ChainId::new("webc-other-1").expect("test chain"),
            ),
            Err(TransactionValidationErrorV1::WrongChain)
        );
    }

    #[test]
    fn sponsor_grant_state_is_exact_and_committed_by_the_state_root() {
        let sponsor = Keypair::from_seed([3; 32]);
        let grant_id = SponsorGrantId::new(Hash256([0x44; 32]));
        let record = SponsorGrantStateV1 {
            grant_digest: Some(Hash256([0x55; 32])),
            next_use_nonce: SponsorUseNonce::new(7),
            total_charged: Amount::from_units(123),
            uses: SponsorUseCount::new(3),
            revoked: false,
        };
        let value = serde_json::to_value(record).expect("grant state serializes");
        assert_eq!(value["next_use_nonce"], "7");
        assert_eq!(value["uses"], "3");
        assert_eq!(value["total_charged"], "123");

        let state = ChainState::default();
        let before = state.state_root().expect("empty state root");
        let mut with_grant = state;
        with_grant
            .sponsor_grants
            .insert((sponsor.address(), grant_id), record);
        assert_ne!(with_grant.state_root().expect("grant state root"), before);
        let restored: ChainState =
            bincode::deserialize(&bincode::serialize(&with_grant).expect("state serializes"))
                .expect("state restores");
        assert_eq!(restored, with_grant);
    }

    #[test]
    fn preparation_is_pure_and_checks_height_nonce_fee_and_reserve() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let state = funded_state(&sender, None);
        let before = state.clone();
        let prepared = state
            .prepare_transaction_v1(
                ValidatedTransactionV1::validate(
                    sender_paid_fixture(&sender, &recipient),
                    &ChainId::devnet(),
                )
                .expect("valid sender transaction"),
                BlockHeight::new(10),
            )
            .expect("transaction prepares");
        assert_eq!(prepared.fee_reserve(), Amount::from_units(5_000));
        assert_eq!(prepared.required_units(), GasUnits::new(500));
        assert_eq!(prepared.base_fee_per_unit(), FeeRate::new(2));
        assert_eq!(prepared.effective_priority_fee_per_unit(), FeeRate::new(1));
        assert_eq!(state, before);

        let outside = state.prepare_transaction_v1(
            ValidatedTransactionV1::validate(
                sender_paid_fixture(&sender, &recipient),
                &ChainId::devnet(),
            )
            .expect("valid sender transaction"),
            BlockHeight::new(21),
        );
        assert_eq!(
            outside,
            Err(TransactionPreparationErrorV1::HeightOutsideValidity)
        );

        let mut wrong_nonce = sender_paid_fixture(&sender, &recipient);
        wrong_nonce.authorization.nonce = Nonce::new(1);
        wrong_nonce.sender_signature = None;
        wrong_nonce.sign(&sender).expect("wrong nonce signs");
        assert_eq!(
            state.prepare_transaction_v1(
                ValidatedTransactionV1::validate(wrong_nonce, &ChainId::devnet())
                    .expect("nonce is stateful"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SenderNonceMismatch)
        );

        let mut poor_state = state;
        poor_state
            .accounts
            .get_mut(&sender.address())
            .expect("sender account")
            .balance = Amount::from_units(4_999);
        assert_eq!(
            poor_state.prepare_transaction_v1(
                ValidatedTransactionV1::validate(
                    sender_paid_fixture(&sender, &recipient),
                    &ChainId::devnet(),
                )
                .expect("valid sender transaction"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::InsufficientFeeReserve)
        );
    }

    #[test]
    fn preparation_checks_sponsor_replay_revocation_and_cumulative_budget() {
        let sender = Keypair::from_seed([1; 32]);
        let recipient = Keypair::from_seed([2; 32]);
        let sponsor = Keypair::from_seed([3; 32]);
        let transaction = sponsored_fixture(&sender, &recipient, &sponsor, true);
        let FeePaymentV1::Sponsored(use_record) = &transaction.fee_payment else {
            panic!("sponsored fixture")
        };
        let key = (use_record.grant.sponsor, use_record.grant.grant_id);
        let digest = use_record.grant_digest;
        let state = funded_state(&sender, Some(&sponsor));

        assert!(state
            .prepare_transaction_v1(
                ValidatedTransactionV1::validate(transaction.clone(), &ChainId::devnet())
                    .expect("valid sponsored transaction"),
                BlockHeight::new(10),
            )
            .is_ok());

        let mut replayed = state.clone();
        replayed.sponsor_grants.insert(
            key,
            SponsorGrantStateV1 {
                grant_digest: Some(digest),
                next_use_nonce: SponsorUseNonce::new(1),
                total_charged: Amount::ZERO,
                uses: SponsorUseCount::new(1),
                revoked: false,
            },
        );
        assert_eq!(
            replayed.prepare_transaction_v1(
                ValidatedTransactionV1::validate(transaction.clone(), &ChainId::devnet())
                    .expect("valid sponsored transaction"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorNonceMismatch)
        );

        let mut revoked = state.clone();
        revoked.sponsor_grants.insert(
            key,
            SponsorGrantStateV1 {
                revoked: true,
                ..SponsorGrantStateV1::default()
            },
        );
        assert_eq!(
            revoked.prepare_transaction_v1(
                ValidatedTransactionV1::validate(transaction.clone(), &ChainId::devnet())
                    .expect("valid sponsored transaction"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorGrantRevoked)
        );

        let mut exhausted = state;
        exhausted.sponsor_grants.insert(
            key,
            SponsorGrantStateV1 {
                grant_digest: Some(digest),
                total_charged: Amount::from_units(46_000),
                ..SponsorGrantStateV1::default()
            },
        );
        assert_eq!(
            exhausted.prepare_transaction_v1(
                ValidatedTransactionV1::validate(transaction, &ChainId::devnet())
                    .expect("valid sponsored transaction"),
                BlockHeight::new(10),
            ),
            Err(TransactionPreparationErrorV1::SponsorBudgetExceeded)
        );
    }
}
