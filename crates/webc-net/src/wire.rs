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
use webc_chain::{Block, FinalityCertificate, SignedProposal, SignedVote, Transaction};
use webc_crypto::Hash256;

use crate::codec::{
    compress_payload, decode as decode_frame, decompress_payload, encode as encode_frame,
};
use crate::error::NetError;

/// Fixed four-byte tag beginning every WEBC network frame.
pub const NET_PROTOCOL_MAGIC: [u8; 4] = *b"WEBC";

/// Current peer-to-peer wire version. Bumped on any breaking frame change.
///
/// v2 (C5): `SignedProposal` gained a `proof_of_lock` prevote set, changing the
/// bincode layout of `NetMessage::Proposal`, so a v1 node cannot decode a v2
/// proposal frame.
///
/// v3 (P6, WEBC §15.19/§15.24): the message-envelope payload gained a transparent
/// compression tag (`codec::compress_payload`), so the bytes after the header are
/// now `tag + raw-or-zstd` rather than a bare bincode payload — a v2 node cannot
/// parse a v3 frame's body. The handshake pins this version and stays
/// uncompressed, so mismatched peers cleanly refuse to connect (a typed
/// `UnsupportedVersion`) rather than misparse.
pub const NET_PROTOCOL_VERSION: u16 = 3;

/// Length of the clear frame header: the fixed magic followed by the
/// little-endian wire version. These bytes are never compressed, so
/// [`decode_message`] can reject a foreign or incompatible frame at fixed offsets
/// before decompressing or deserializing any attacker-controlled payload.
const FRAME_HEADER_LEN: usize = NET_PROTOCOL_MAGIC.len() + 2;

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
    /// A state-sync request for finalized blocks starting at `from_height`.
    BlockRequest {
        /// First height requested (inclusive).
        from_height: u64,
        /// Maximum number of consecutive blocks to return.
        max: u32,
    },
    /// A state-sync response carrying one certified finalized block.
    BlockResponse(Box<CertifiedBlock>),
}

/// A finalized block bundled with the certificate that proves its finality, sent
/// during state sync so a catching-up node can verify before importing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertifiedBlock {
    /// The finalized block.
    pub block: Block,
    /// The certificate proving strictly over two thirds precommitted it.
    pub certificate: FinalityCertificate,
}

/// Encodes one message into its exact frame bytes.
///
/// Frame layout: `magic (4) ++ version_le (2) ++ body`, where `body` is the
/// transparent compression envelope produced by `compress_payload` over the
/// bincode of the message — a 1-byte tag (`0x00` raw / `0x01` zstd) followed by
/// the raw bytes or a zstd frame, whichever is smaller (WEBC §15.19/§15.24). The
/// magic and version stay in the clear so a peer can reject an incompatible frame
/// before touching the payload. Compression is on by default and applies only to
/// this post-handshake message envelope; the handshake frames are left raw (see
/// `compress_payload`).
pub fn encode_message(message: &NetMessage) -> Result<Vec<u8>, NetError> {
    // Serialize the payload (bincode, itself capped at MAX_FRAME_BYTES by the
    // shared codec), then wrap it in the compression envelope.
    let payload = encode_frame(message)?;
    let body = compress_payload(&payload);

    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    frame.extend_from_slice(&NET_PROTOCOL_MAGIC);
    frame.extend_from_slice(&NET_PROTOCOL_VERSION.to_le_bytes());
    frame.extend_from_slice(&body);
    // Defense in depth at the length-delimited layer: the encoded (compressed)
    // frame must still fit one legal frame, matching the transport codec's
    // `max_frame_length`.
    if frame.len() > MAX_FRAME_BYTES {
        return Err(NetError::FrameTooLarge {
            maximum: MAX_FRAME_BYTES,
        });
    }
    Ok(frame)
}

/// Decodes one frame, rejecting foreign magic, unsupported versions, oversize or
/// bomb payloads, and trailing bytes before returning the message.
pub fn decode_message(bytes: &[u8]) -> Result<NetMessage, NetError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(NetError::FrameTooLarge {
            maximum: MAX_FRAME_BYTES,
        });
    }
    // Cheaply reject an incompatible frame before decompressing/deserializing the
    // payload: the first bytes are the fixed magic, then the little-endian
    // version — both live in the clear, ahead of the compression tag.
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(NetError::MalformedFrame);
    }
    if bytes[0..4] != NET_PROTOCOL_MAGIC {
        return Err(NetError::BadMagic);
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != NET_PROTOCOL_VERSION {
        return Err(NetError::UnsupportedVersion { actual: version });
    }
    // Decompress the body under the frame budget (this rejects a decompression
    // bomb before allocating unbounded memory), then decode the payload. The
    // shared codec rejects trailing bytes: a frame consumes exactly its bytes.
    let payload = decompress_payload(&bytes[FRAME_HEADER_LEN..])?;
    let message: NetMessage = decode_frame(&payload)?;
    Ok(message)
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
                evidence_root: Hash256([0x55; 32]),
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
    fn round_trips_a_block_request_message() {
        let message = NetMessage::BlockRequest {
            from_height: 7,
            max: 32,
        };
        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        assert!(matches!(
            decoded,
            NetMessage::BlockRequest {
                from_height: 7,
                max: 32
            }
        ));
    }

    #[test]
    fn round_trips_a_block_response_message() {
        let leader = Keypair::from_seed([4u8; 32]);
        let block = sample_block(leader.address());
        let certificate = FinalityCertificate {
            protocol_version: webc_chain::CURRENT_PROTOCOL_VERSION,
            chain_id: webc_chain::ChainId::devnet(),
            height: 1,
            round: 0,
            block_hash: block.hash().unwrap(),
            precommits: vec![sample_vote(&leader)],
        };
        let message = NetMessage::BlockResponse(Box::new(CertifiedBlock {
            block: block.clone(),
            certificate,
        }));
        let decoded = decode_message(&encode_message(&message).unwrap()).unwrap();
        let NetMessage::BlockResponse(got) = decoded else {
            panic!("expected a block response message");
        };
        assert_eq!(got.block.hash().unwrap(), block.hash().unwrap());
    }

    #[test]
    fn large_compressible_message_is_smaller_on_the_wire_and_round_trips() {
        // A block carrying many identical transactions is large and highly
        // compressible (WEBC §15.19/§15.24): the on-wire frame must come out well
        // under the raw bincode payload, yet still decode back to the same message.
        let leader = Keypair::from_seed([8u8; 32]);
        let mut block = sample_block(leader.address());
        block.transactions = vec![sample_transaction(); 2_000];
        let certificate = FinalityCertificate {
            protocol_version: webc_chain::CURRENT_PROTOCOL_VERSION,
            chain_id: webc_chain::ChainId::devnet(),
            height: 1,
            round: 0,
            block_hash: block.hash().unwrap(),
            precommits: vec![sample_vote(&leader)],
        };
        let message = NetMessage::BlockResponse(Box::new(CertifiedBlock {
            block: block.clone(),
            certificate,
        }));

        let raw_payload = encode_frame(&message).expect("bincode the payload");
        let encoded = encode_message(&message).expect("encode the frame");
        // The compression tag sits right after the clear magic+version header.
        assert_eq!(
            encoded[FRAME_HEADER_LEN], 0x01,
            "a large compressible payload must be sent zstd-compressed"
        );
        assert!(
            encoded.len() < raw_payload.len() / 2,
            "compressed frame ({} bytes) must be far smaller than the raw payload ({} bytes)",
            encoded.len(),
            raw_payload.len()
        );

        let decoded = decode_message(&encoded).expect("decode the frame");
        let NetMessage::BlockResponse(got) = decoded else {
            panic!("expected a block response message");
        };
        assert_eq!(got.block.transactions.len(), 2_000);
        assert_eq!(got.block.hash().unwrap(), block.hash().unwrap());
    }

    #[test]
    fn a_wire_decompression_bomb_is_rejected() {
        // End-to-end anti-zip-bomb check at the frame boundary: a hand-forged
        // frame whose zstd body would expand past MAX_FRAME_BYTES is rejected with
        // a typed error (no panic, no gigabyte allocation). Built by hand: a valid
        // clear header, then the zstd tag over a frame that decompresses past the
        // cap.
        let bomb = crate::codec::compress_payload(&vec![0u8; MAX_FRAME_BYTES + 1]);
        // `compress_payload` chose zstd for an all-zero buffer over the cap.
        assert_eq!(bomb[0], 0x01, "the bomb body must be zstd-tagged");
        let mut frame = Vec::new();
        frame.extend_from_slice(&NET_PROTOCOL_MAGIC);
        frame.extend_from_slice(&NET_PROTOCOL_VERSION.to_le_bytes());
        frame.extend_from_slice(&bomb);
        // The whole forged frame is tiny, so it clears the length checks and
        // reaches the bounded decompressor, which rejects it.
        assert!(
            matches!(
                decode_message(&frame),
                Err(NetError::FrameTooLarge { maximum }) if maximum == MAX_FRAME_BYTES
            ),
            "a frame that decompresses past the cap must be rejected as FrameTooLarge"
        );
    }

    #[test]
    fn a_truncated_compressed_frame_is_rejected() {
        // A genuinely compressed frame, chopped mid-zstd-body, must yield a typed
        // error rather than a panic.
        let leader = Keypair::from_seed([9u8; 32]);
        let mut block = sample_block(leader.address());
        block.transactions = vec![sample_transaction(); 2_000];
        let certificate = FinalityCertificate {
            protocol_version: webc_chain::CURRENT_PROTOCOL_VERSION,
            chain_id: webc_chain::ChainId::devnet(),
            height: 1,
            round: 0,
            block_hash: block.hash().unwrap(),
            precommits: vec![sample_vote(&leader)],
        };
        let message = NetMessage::BlockResponse(Box::new(CertifiedBlock { block, certificate }));
        let encoded = encode_message(&message).expect("encode the frame");
        assert_eq!(
            encoded[FRAME_HEADER_LEN], 0x01,
            "payload must be compressed"
        );
        // Keep the header and the tag, drop the tail of the zstd body.
        let truncated = &encoded[..FRAME_HEADER_LEN + 1 + 8];
        assert!(
            decode_message(truncated).is_err(),
            "a truncated compressed frame must be rejected, not decoded"
        );
    }

    #[test]
    fn an_unknown_compression_tag_is_rejected() {
        // A valid clear header followed by an unknown compression tag is malformed.
        let mut frame = Vec::new();
        frame.extend_from_slice(&NET_PROTOCOL_MAGIC);
        frame.extend_from_slice(&NET_PROTOCOL_VERSION.to_le_bytes());
        frame.push(0xEE); // neither RAW (0x00) nor ZSTD (0x01)
        frame.extend_from_slice(b"whatever");
        assert!(matches!(
            decode_message(&frame).unwrap_err(),
            NetError::MalformedFrame
        ));
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
