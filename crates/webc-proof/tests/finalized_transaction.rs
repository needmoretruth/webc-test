//! End-to-end adversarial tests for checkpoint-anchored finalized proofs.
//!
//! These fixtures build real Ed25519 finality certificates, an epoch transition,
//! a signed V5 transaction, a reconciled V1 receipt, and both indexed Merkle
//! paths. They exercise the public proof API as a browser or light client would,
//! without database or network shortcuts.

use std::collections::BTreeMap;

use webc_chain::{
    calculate_fee_summary_v1, transaction_leaf_v1, ActionV1, Amount, AuthorizationLaneId,
    AuthorizationPolicyRevision, BlockHeaderV4, BlockHeight, BlockPositionV1, ChainId, Epoch,
    FeeBid, FeePayerV1, FeePaymentV1, FeeRate, FeeSummaryV1, FinalityAuthoritySetV1,
    FinalityCertificate, GasUnits, Nonce, Operation, ReceiptStatusV1, ReceiptV1, SignedVote,
    TransactionAuthorizationV1, TransactionId, TransactionIndex, TransactionV5, ValidatorPower,
    ValidatorSet, ValidityWindowV1, Vote, VoteType, RECEIPT_V1, TRANSACTION_V5_PROTOCOL_VERSION,
};
use webc_crypto::{Address, Hash256, Keypair};
use webc_proof::{
    build_indexed_merkle_proof, validate_checkpoint_v1, verify_finalized_transaction_proof_v1,
    AuthoritySetTransitionV1, CheckpointErrorV1, CheckpointRequirementsV1, CheckpointV1,
    FinalizedTransactionProofErrorV1, FinalizedTransactionProofRequirementsV1,
    FinalizedTransactionProofV1, ValidatedCheckpointV1, AUTHORITY_SET_TRANSITION_V1, CHECKPOINT_V1,
    FINALIZED_TRANSACTION_PROOF_V1, MAX_AUTHORITY_TRANSITIONS_V1,
    MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES, MAX_INDEXED_MERKLE_SIBLINGS,
};

fn authority(seed: u8, epoch: u64) -> (Keypair, FinalityAuthoritySetV1) {
    let key = Keypair::from_seed([seed; 32]);
    let mut validators = BTreeMap::new();
    validators.insert(
        key.address(),
        ValidatorPower {
            validator: key.address(),
            power: Amount::from_units(100),
            consensus_key: key.public_key(),
        },
    );
    let set = ValidatorSet {
        validators,
        total_power: Amount::from_units(100),
    };
    let authority_set = FinalityAuthoritySetV1::from_validator_set(
        TRANSACTION_V5_PROTOCOL_VERSION,
        ChainId::devnet(),
        Epoch::new(epoch),
        &set,
    )
    .expect("fixture authority set");
    (key, authority_set)
}

#[allow(
    clippy::too_many_arguments,
    reason = "test header exposes every committed root"
)]
fn header(
    height: u64,
    epoch: u64,
    current: &FinalityAuthoritySetV1,
    next: &FinalityAuthoritySetV1,
    proposer: Address,
    tx_root: Hash256,
    receipt_root: Hash256,
) -> BlockHeaderV4 {
    BlockHeaderV4 {
        protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
        chain_id: ChainId::devnet(),
        height: BlockHeight::new(height),
        epoch: Epoch::new(epoch),
        previous_hash: Hash256::digest(b"previous"),
        state_root: Hash256::digest(b"state"),
        account_root: Hash256::digest(b"account"),
        tx_root,
        receipt_root,
        evidence_root: Hash256::ZERO,
        finality_authority_set_root: current.commitment().expect("current root"),
        next_finality_authority_set_root: next.commitment().expect("next root"),
        proposer,
        timestamp_ms: height * 1_000,
        base_fee_per_unit: 2,
    }
}

fn certificate(header: &BlockHeaderV4, signer: &Keypair) -> FinalityCertificate {
    let block_hash = header.hash().expect("header hash");
    let vote = SignedVote::sign(
        Vote {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: header.chain_id.clone(),
            height: header.height.get(),
            round: 0,
            vote_type: VoteType::Precommit,
            block_hash,
            validator: signer.address(),
        },
        signer,
    )
    .expect("fixture vote");
    FinalityCertificate {
        protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
        chain_id: header.chain_id.clone(),
        height: header.height.get(),
        round: 0,
        block_hash,
        precommits: vec![vote],
    }
}

fn transaction(height: u64) -> TransactionV5 {
    let sender = Keypair::from_seed([11; 32]);
    let recipient = Keypair::from_seed([12; 32]);
    let mut transaction = TransactionV5::for_actions_unsigned(
        ChainId::devnet(),
        sender.address(),
        sender.public_key(),
        TransactionAuthorizationV1 {
            lane: AuthorizationLaneId::DEFAULT,
            policy_revision: AuthorizationPolicyRevision::new(0),
            nonce: Nonce::new(1),
        },
        ValidityWindowV1::new(BlockHeight::new(height), BlockHeight::new(height + 2)),
        vec![ActionV1::native(Operation::Transfer {
            to: recipient.address(),
            amount: Amount::from_units(5),
        })],
        FeeBid {
            gas_limit: 100,
            max_fee_per_unit: 5,
            priority_fee_per_unit: 1,
        },
        FeePaymentV1::SenderLane,
    )
    .expect("fixture transaction");
    transaction.sign(&sender).expect("fixture signature");
    transaction
}

fn fee_summary(transaction: &TransactionV5) -> FeeSummaryV1 {
    calculate_fee_summary_v1(
        FeePayerV1 {
            address: transaction.sender,
            lane: transaction.authorization.lane,
        },
        GasUnits::new(100),
        GasUnits::new(10),
        FeeRate::new(2),
        FeeRate::new(5),
        FeeRate::new(1),
    )
    .expect("fixture fee summary")
}

fn fixture() -> (
    ValidatedCheckpointV1,
    FinalizedTransactionProofV1,
    FinalizedTransactionProofRequirementsV1,
) {
    let (outgoing_key, outgoing) = authority(1, 0);
    let (incoming_key, incoming) = authority(2, 1);
    let checkpoint_header = header(
        9,
        0,
        &outgoing,
        &outgoing,
        outgoing_key.address(),
        Hash256::ZERO,
        Hash256::ZERO,
    );
    let checkpoint = validate_checkpoint_v1(
        CheckpointV1 {
            version: CHECKPOINT_V1,
            certificate: certificate(&checkpoint_header, &outgoing_key),
            header: checkpoint_header,
            authority_set: outgoing.clone(),
        },
        &CheckpointRequirementsV1::new(ChainId::devnet(), BlockHeight::new(9), Epoch::new(0)),
    )
    .expect("fixture checkpoint");

    let transition_header = header(
        10,
        0,
        &outgoing,
        &incoming,
        outgoing_key.address(),
        Hash256::ZERO,
        Hash256::ZERO,
    );
    let transition = AuthoritySetTransitionV1 {
        version: AUTHORITY_SET_TRANSITION_V1,
        certificate: certificate(&transition_header, &outgoing_key),
        header: transition_header,
        outgoing_authority_set: outgoing,
        incoming_authority_set: incoming.clone(),
    };

    let transaction = transaction(11);
    let transaction_id = transaction.transaction_id().expect("transaction ID");
    let position = BlockPositionV1::new(BlockHeight::new(11), TransactionIndex::new(0));
    let receipt = ReceiptV1 {
        version: RECEIPT_V1,
        position,
        transaction_id,
        sender: transaction.sender,
        status: ReceiptStatusV1::Succeeded,
        fee_summary: fee_summary(&transaction),
        events: Vec::new(),
    };
    let transaction_leaf = transaction_leaf_v1(position, transaction_id).expect("tx leaf");
    let receipt_leaf = receipt.leaf().expect("receipt leaf");
    let target_header = header(
        11,
        1,
        &incoming,
        &incoming,
        incoming_key.address(),
        transaction_leaf,
        receipt_leaf,
    );
    let proof = FinalizedTransactionProofV1 {
        version: FINALIZED_TRANSACTION_PROOF_V1,
        authority_transitions: vec![transition],
        target_certificate: certificate(&target_header, &incoming_key),
        target_header,
        target_authority_set: incoming,
        transaction,
        receipt,
        transaction_proof: build_indexed_merkle_proof(&[transaction_leaf], 0).expect("tx proof"),
        receipt_proof: build_indexed_merkle_proof(&[receipt_leaf], 0).expect("receipt proof"),
    };
    let requirements =
        FinalizedTransactionProofRequirementsV1::new(ChainId::devnet(), transaction_id, 10);
    (checkpoint, proof, requirements)
}

#[test]
fn verifies_transition_certificate_and_both_merkle_roots() {
    let (checkpoint, proof, requirements) = fixture();
    let verified = verify_finalized_transaction_proof_v1(&proof, &checkpoint, &requirements)
        .expect("complete finalized proof");
    assert_eq!(verified.transaction_id, requirements.transaction_id);
    assert_eq!(verified.position, proof.receipt.position);
    assert_eq!(verified.block_hash, proof.target_header.hash().unwrap());
    assert_eq!(verified.checkpoint_digest, checkpoint.digest);
    assert_ne!(proof.digest().unwrap(), verified.block_hash);
}

#[test]
fn rejects_skipped_transition_and_wrong_requested_transaction() {
    let (checkpoint, mut proof, requirements) = fixture();
    proof.authority_transitions.clear();
    assert_eq!(
        verify_finalized_transaction_proof_v1(&proof, &checkpoint, &requirements),
        Err(FinalizedTransactionProofErrorV1::TargetAuthorityMismatch)
    );

    let (_, proof, mut wrong_request) = fixture();
    wrong_request.transaction_id = TransactionId::new(Hash256::digest(b"other"));
    assert_eq!(
        verify_finalized_transaction_proof_v1(&proof, &checkpoint, &wrong_request),
        Err(FinalizedTransactionProofErrorV1::UnexpectedTransactionId)
    );
}

#[test]
fn rejects_position_leaf_root_and_certificate_tampering() {
    let (checkpoint, proof, requirements) = fixture();

    let mut wrong_position = proof.clone();
    wrong_position.receipt.position.transaction_index = TransactionIndex::new(1);
    assert_eq!(
        verify_finalized_transaction_proof_v1(&wrong_position, &checkpoint, &requirements),
        Err(FinalizedTransactionProofErrorV1::MerklePositionMismatch)
    );

    let mut wrong_leaf = proof.clone();
    wrong_leaf.transaction_proof.leaf = Hash256::digest(b"wrong leaf");
    assert_eq!(
        verify_finalized_transaction_proof_v1(&wrong_leaf, &checkpoint, &requirements),
        Err(FinalizedTransactionProofErrorV1::InvalidTransactionLeaf)
    );

    let mut wrong_root = proof.clone();
    wrong_root.target_header.receipt_root = Hash256::digest(b"wrong root");
    wrong_root.target_certificate =
        certificate(&wrong_root.target_header, &Keypair::from_seed([2; 32]));
    assert_eq!(
        verify_finalized_transaction_proof_v1(&wrong_root, &checkpoint, &requirements),
        Err(FinalizedTransactionProofErrorV1::InvalidReceiptProof)
    );

    let mut duplicate_vote = proof;
    duplicate_vote
        .target_certificate
        .precommits
        .push(duplicate_vote.target_certificate.precommits[0].clone());
    assert_eq!(
        verify_finalized_transaction_proof_v1(&duplicate_vote, &checkpoint, &requirements),
        Err(FinalizedTransactionProofErrorV1::Checkpoint(
            CheckpointErrorV1::CertificateInvalid
        ))
    );
}

#[test]
fn outer_size_and_collections_are_bounded_before_verification() {
    let (checkpoint, proof, requirements) = fixture();
    let oversized = vec![b' '; MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES + 1];
    assert_eq!(
        FinalizedTransactionProofV1::decode_json(&oversized, &checkpoint, &requirements),
        Err(FinalizedTransactionProofErrorV1::ProofTooLarge {
            actual: MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES + 1,
            maximum: MAX_FINALIZED_TRANSACTION_PROOF_V1_JSON_BYTES,
        })
    );

    let mut too_many = proof.clone();
    too_many.authority_transitions =
        vec![too_many.authority_transitions[0].clone(); MAX_AUTHORITY_TRANSITIONS_V1 + 1];
    assert_eq!(
        verify_finalized_transaction_proof_v1(&too_many, &checkpoint, &requirements),
        Err(FinalizedTransactionProofErrorV1::TooManyTransitions {
            actual: MAX_AUTHORITY_TRANSITIONS_V1 + 1,
            maximum: MAX_AUTHORITY_TRANSITIONS_V1,
        })
    );

    let mut hostile_json = serde_json::to_value(proof).expect("proof JSON");
    hostile_json["transaction_proof"]["siblings"] = serde_json::Value::Array(vec![
        serde_json::Value::String(Hash256::ZERO.to_hex());
        MAX_INDEXED_MERKLE_SIBLINGS + 1
    ]);
    let bytes = serde_json::to_vec(&hostile_json).expect("hostile JSON bytes");
    assert_eq!(
        FinalizedTransactionProofV1::decode_json(&bytes, &checkpoint, &requirements),
        Err(FinalizedTransactionProofErrorV1::MalformedProof)
    );
}
