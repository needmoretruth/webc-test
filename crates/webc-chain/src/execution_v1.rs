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

use crate::{ChainId, TransactionV5, TransactionValidationErrorV1};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActionScopeV1, ActionV1, Amount, AuthorizationLaneId, AuthorizationPolicyRevision,
        BlockHeight, FeeBid, FeePaymentV1, Nonce, Operation, SponsorGrantId, SponsorGrantV1,
        SponsorUseNonce, SponsorUseV1, TransactionAuthorizationV1, ValidityWindowV1,
        TRANSACTION_V5_PROTOCOL_VERSION,
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
}
