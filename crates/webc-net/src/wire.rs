//! WEBC peer-to-peer wire format.
//!
//! This is WEBC-owned protocol logic: the set of gossiped message types and the
//! self-describing envelope that carries them. The envelope pins a fixed magic
//! and a network protocol version so a node rejects foreign or incompatible
//! frames before deserializing an attacker-controlled payload.
//!
//! Framing (splitting a byte stream into discrete frames) is delegated to a
//! mature length-delimited codec at the transport layer; this module only
//! defines what a single frame's bytes mean.

use serde::{Deserialize, Serialize};
use webc_chain::{FinalityCertificate, SignedProposal, SignedVote, Transaction};
use webc_crypto::Hash256;

use crate::codec::{decode as decode_frame, encode as encode_frame};
use crate::error::NetError;

/// Fixed four-byte tag beginning every WEBC network frame.
pub const NET_PROTOCOL_MAGIC: [u8; 4] = *b"WEBC";

/// Current peer-to-peer wire version. Bumped on any breaking frame change.
pub const NET_PROTOCOL_VERSION: u16 = 1;

/// Maximum size of a single decoded frame payload, in bytes.
///
/// This bounds the memory a single peer can force the node to allocate for one
/// message. It is generous enough for a full block's worth of transactions but
/// small enough that a hostile peer cannot exhaust memory with one frame.
pub const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// One gossiped peer-to-peer message.
///
/// A-1 carries transactions between mempools; A-2 adds the three signed
/// consensus artifacts. The envelope's wire version guards compatibility as the
/// set grows. Large payloads are boxed so the enum stays small on the stack.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetMessage {
    /// A signed transaction being propagated toward validators' mempools.
    Transaction(Box<Transaction>),
    /// A leader's signed block proposal for a height and round.
    Proposal(Box<SignedProposal>),
    /// A validator's signed prevote or precommit.
    Vote(Box<SignedVote>),
    /// A finality certificate proving a block reached precommit quorum.
    Certificate(Box<FinalityCertificate>),
}

/// Self-describing envelope wrapping one [`NetMessage`] on the wire.
///
/// The magic and version are serialized first so [`decode_message`] can reject
/// an incompatible frame cheaply before trusting the payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Envelope {
    magic: [u8; 4],
    version: u16,
    payload: NetMessage,
}

/// Encodes one message into its exact frame bytes (magic + version + payload).
pub fn encode_message(message: &NetMessage) -> Result<Vec<u8>, NetError> {
    let envelope = Envelope {
        magic: NET_PROTOCOL_MAGIC,
        version: NET_PROTOCOL_VERSION,
        payload: message.clone(),
    };
    let bytes = encode_frame(&envelope)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(NetError::FrameTooLarge {
            maximum: MAX_FRAME_BYTES,
        });
    }
    Ok(bytes)
}

/// Decodes one frame, rejecting foreign magic, unsupported versions, oversize
/// payloads, and trailing bytes before returning the message.
pub fn decode_message(bytes: &[u8]) -> Result<NetMessage, NetError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(NetError::FrameTooLarge {
            maximum: MAX_FRAME_BYTES,
        });
    }
    // Cheaply reject an incompatible frame before deserializing the payload:
    // the first bytes are the fixed magic, then the little-endian version.
    if bytes.len() < 6 {
        return Err(NetError::MalformedFrame);
    }
    if bytes[0..4] != NET_PROTOCOL_MAGIC {
        return Err(NetError::BadMagic);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != NET_PROTOCOL_VERSION {
        return Err(NetError::UnsupportedVersion { actual: version });
    }
    // The shared codec rejects trailing bytes: a frame consumes exactly its bytes.
    let envelope: Envelope = decode_frame(bytes)?;
    Ok(envelope.payload)
}

/// Stable content identity of an encoded frame, used to suppress gossip loops.
///
/// Two byte-identical frames share an ID, so a node that has already seen and
/// forwarded a message drops later copies instead of re-flooding them.
pub fn message_id(encoded_frame: &[u8]) -> Hash256 {
    Hash256::digest(encoded_frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_chain::{Amount, FeeBid, Operation, Transaction};
    use webc_crypto::Keypair;

    fn sample_transaction() -> Transaction {
        let sender = Keypair::from_seed([9u8; 32]);
        let recipient = Keypair::from_seed([10u8; 32]);
        Transaction::for_operation(
            &sender,
            0,
            Operation::Transfer {
                to: recipient.address(),
                amount: Amount::from_webc(1),
            },
            FeeBid {
                gas_limit: 1_000,
                max_fee_per_unit: 1,
                priority_fee_per_unit: 0,
            },
        )
        .expect("sign sample transaction")
    }

    #[test]
    fn round_trips_a_transaction_message() {
        let message = NetMessage::Transaction(Box::new(sample_transaction()));
        let encoded = encode_message(&message).unwrap();
        assert_eq!(&encoded[0..4], &NET_PROTOCOL_MAGIC);
        let decoded = decode_message(&encoded).unwrap();
        let NetMessage::Transaction(tx) = decoded else {
            panic!("expected a transaction message");
        };
        assert_eq!(tx.hash().unwrap(), sample_transaction().hash().unwrap());
    }

    fn sample_block(proposer: webc_crypto::Address) -> webc_chain::Block {
        webc_chain::Block {
            header: webc_chain::BlockHeader {
                protocol_version: webc_chain::CURRENT_PROTOCOL_VERSION,
                chain_id: webc_chain::ChainId::devnet(),
                height: 1,
                epoch: 0,
                previous_hash: Hash256([0u8; 32]),
                state_root: Hash256([0x11; 32]),
                account_root: Hash256([0x22; 32]),
                tx_root: Hash256([0x33; 32]),
                receipt_root: Hash256([0x44; 32]),
                proposer,
                timestamp_ms: 1_700_000_000_000,
                base_fee_per_unit: 1,
            },
            transactions: Vec::new(),
            receipts: Vec::new(),
            evidence: Vec::new(),
        }
    }

    fn sample_vote(validator: &Keypair) -> SignedVote {
        SignedVote::sign(
            webc_chain::Vote {
                protocol_version: webc_chain::CURRENT_PROTOCOL_VERSION,
                chain_id: webc_chain::ChainId::devnet(),
                height: 1,
                round: 0,
                vote_type: webc_chain::VoteType::Precommit,
                block_hash: Hash256::digest(b"block"),
                validator: validator.address(),
            },
            validator,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_a_proposal_message() {
        let leader = Keypair::from_seed([1u8; 32]);
        let proposal = SignedProposal::sign(
            webc_chain::CURRENT_PROTOCOL_VERSION,
            webc_chain::ChainId::devnet(),
            1,
            0,
            None,
            sample_block(leader.address()),
            leader.address(),
            &leader,
        )
        .unwrap();
        let message = NetMessage::Proposal(Box::new(proposal.clone()));
        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        let NetMessage::Proposal(got) = decoded else {
            panic!("expected a proposal message");
        };
        assert_eq!(got.payload.block_hash, proposal.payload.block_hash);
    }

    #[test]
    fn round_trips_a_vote_message() {
        let validator = Keypair::from_seed([2u8; 32]);
        let vote = sample_vote(&validator);
        let message = NetMessage::Vote(Box::new(vote.clone()));
        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        let NetMessage::Vote(got) = decoded else {
            panic!("expected a vote message");
        };
        assert_eq!(got.payload.validator, vote.payload.validator);
    }

    #[test]
    fn round_trips_a_certificate_message() {
        let validator = Keypair::from_seed([3u8; 32]);
        let certificate = FinalityCertificate {
            protocol_version: webc_chain::CURRENT_PROTOCOL_VERSION,
            chain_id: webc_chain::ChainId::devnet(),
            height: 1,
            round: 0,
            block_hash: Hash256::digest(b"block"),
            precommits: vec![sample_vote(&validator)],
        };
        let message = NetMessage::Certificate(Box::new(certificate.clone()));
        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        let NetMessage::Certificate(got) = decoded else {
            panic!("expected a certificate message");
        };
        assert_eq!(got.block_hash, certificate.block_hash);
    }

    #[test]
    fn identical_frames_share_a_message_id() {
        let message = NetMessage::Transaction(Box::new(sample_transaction()));
        let a = encode_message(&message).unwrap();
        let b = encode_message(&message).unwrap();
        assert_eq!(message_id(&a), message_id(&b));
    }

    #[test]
    fn rejects_foreign_magic() {
        let message = NetMessage::Transaction(Box::new(sample_transaction()));
        let mut encoded = encode_message(&message).unwrap();
        encoded[0] = b'X';
        assert!(matches!(
            decode_message(&encoded).unwrap_err(),
            NetError::BadMagic
        ));
    }

    #[test]
    fn rejects_unsupported_version() {
        let message = NetMessage::Transaction(Box::new(sample_transaction()));
        let mut encoded = encode_message(&message).unwrap();
        // Overwrite the little-endian version field (bytes 4..6) with 0xFFFF.
        encoded[4] = 0xFF;
        encoded[5] = 0xFF;
        assert!(matches!(
            decode_message(&encoded).unwrap_err(),
            NetError::UnsupportedVersion { actual: 0xFFFF }
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let message = NetMessage::Transaction(Box::new(sample_transaction()));
        let mut encoded = encode_message(&message).unwrap();
        encoded.push(0);
        assert!(decode_message(&encoded).is_err());
    }

    #[test]
    fn rejects_a_truncated_frame() {
        assert!(matches!(
            decode_message(&[0u8; 3]).unwrap_err(),
            NetError::MalformedFrame
        ));
    }
}
