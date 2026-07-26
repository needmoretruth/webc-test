//! Protocol-2 block and V4 header commitments.
//!
//! Purpose: provide a new, unambiguous block container for signed V5
//! transactions and V1 receipts without reinterpreting the frozen protocol-1
//! `Block`/V3-header bytes. Responsibilities: define the V4 header domain and
//! cross-language JSON shape, bind current and next finality-authority roots,
//! validate bounded transaction/receipt/evidence collections, and recompute all
//! ordered roots. Non-responsibilities: execute actions, select transactions,
//! verify a finality certificate, store blocks, or choose authority sets.
//!
//! Data flow: deterministic execution produces transactions, receipts, state
//! roots, evidence, and authority commitments. A proposer constructs this value;
//! validators call [`BlockV4::validate`] before signing its header hash. Storage
//! accepts only a validated block plus its matching state and certificate.
//!
//! Security boundary: blocks are hostile network input. Validation checks the
//! outer byte and collection ceilings before signature/root loops, verifies every
//! signed transaction for this exact chain and height, rejects duplicate IDs,
//! and binds each typed receipt to its exact position. The two authority roots
//! are signed header data; later proof code verifies the committed set contents.

use std::{fmt, marker::PhantomData};

use serde::{
    de::{SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use webc_crypto::{Address, Hash256};

use crate::{
    canonical::canonical_json_bytes, evidence_root, receipt_root_v1, transaction_root_v1,
    verify_transaction_receipt_binding, BlockHeight, ChainError, ChainId, Epoch, ProtocolVersion,
    ReceiptError, ReceiptV1, SlashingEvidence, TransactionV5, TransactionValidationErrorV1,
    MAX_BLOCK_SLASHING_EVIDENCE, TRANSACTION_V5_PROTOCOL_VERSION,
};

/// Domain separating V4 block-header hashes from every legacy or future header.
pub const BLOCK_HEADER_V4_DOMAIN: &str = "WEBC_BLOCK_HEADER_V4";

/// Absolute canonical JSON bound for one complete protocol-2 block.
pub const MAX_BLOCK_V4_CANONICAL_BYTES: usize = 4 * 1024 * 1024;

/// Maximum transactions/receipts one protocol-2 block may retain or validate.
pub const MAX_BLOCK_V4_TRANSACTIONS: usize = 8_192;

/// Header committed by protocol-2 validators.
///
/// `finality_authority_set_root` names the outgoing set certifying this block;
/// `next_finality_authority_set_root` names the set authorized at the next
/// height. They are equal outside an authority transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeaderV4 {
    /// Must equal protocol version 2.
    pub protocol_version: ProtocolVersion,
    /// Replay-protection network identifier fixed by genesis.
    pub chain_id: ChainId,
    /// Monotonic finalized block height, encoded as a decimal string in JSON.
    #[serde(with = "block_height_decimal")]
    pub height: BlockHeight,
    /// Validator-snapshot epoch, encoded as a decimal string in JSON.
    #[serde(with = "epoch_decimal")]
    pub epoch: Epoch,
    /// Hash of the immediately preceding authoritative block.
    pub previous_hash: Hash256,
    /// Root of every consensus state subtree after execution.
    pub state_root: Hash256,
    /// Account-only root for lightweight account proofs.
    pub account_root: Hash256,
    /// Ordered, position-bound root of signed V5 transactions.
    pub tx_root: Hash256,
    /// Ordered root of position-bound V1 receipts.
    pub receipt_root: Hash256,
    /// Ordered root of objective slashing-evidence identifiers.
    pub evidence_root: Hash256,
    /// Commitment to the outgoing authority set certifying this header.
    pub finality_authority_set_root: Hash256,
    /// Commitment to the authority set allowed to certify the next height.
    pub next_finality_authority_set_root: Hash256,
    /// Validator operator selected to propose this block.
    pub proposer: Address,
    /// Consensus-supplied Unix timestamp in milliseconds, as a decimal string.
    #[serde(with = "u64_decimal")]
    pub timestamp_ms: u64,
    /// Native base units charged per execution unit, as a decimal string.
    #[serde(with = "u64_decimal")]
    pub base_fee_per_unit: u64,
}

impl BlockHeaderV4 {
    /// Validates version and non-empty authority/height commitments.
    pub fn validate(&self) -> Result<(), BlockV4Error> {
        if self.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION {
            return Err(BlockV4Error::UnsupportedProtocolVersion);
        }
        if self.height.get() == 0 {
            return Err(BlockV4Error::ZeroHeight);
        }
        if self.finality_authority_set_root == Hash256::ZERO
            || self.next_finality_authority_set_root == Hash256::ZERO
        {
            return Err(BlockV4Error::EmptyAuthorityCommitment);
        }
        Ok(())
    }

    /// Returns the exact domain-separated identifier validators certify.
    pub fn hash(&self) -> Result<Hash256, BlockV4Error> {
        self.validate()?;
        #[derive(Serialize)]
        struct HeaderHashPayload<'a> {
            domain: &'static str,
            header: &'a BlockHeaderV4,
        }
        canonical_json_bytes(&HeaderHashPayload {
            domain: BLOCK_HEADER_V4_DOMAIN,
            header: self,
        })
        .map(Hash256::digest)
        .map_err(BlockV4Error::CanonicalEncoding)
    }
}

/// Authoritative protocol-2 block data committed by a [`BlockHeaderV4`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockV4 {
    /// V4 header and all execution/finality commitments.
    pub header: BlockHeaderV4,
    /// Signed V5 transactions in canonical execution order.
    #[serde(deserialize_with = "bounded_transactions::deserialize")]
    pub transactions: Vec<TransactionV5>,
    /// Typed V1 result corresponding one-to-one with each transaction.
    #[serde(deserialize_with = "bounded_receipts::deserialize")]
    pub receipts: Vec<ReceiptV1>,
    /// Objective signed slashing artifacts applied before user actions.
    #[serde(deserialize_with = "bounded_evidence::deserialize")]
    pub evidence: Vec<SlashingEvidence>,
}

impl BlockV4 {
    /// Decodes and fully validates hostile canonical JSON under the 4 MiB cap.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, BlockV4Error> {
        if bytes.len() > MAX_BLOCK_V4_CANONICAL_BYTES {
            return Err(BlockV4Error::BlockTooLarge {
                actual: bytes.len(),
                maximum: MAX_BLOCK_V4_CANONICAL_BYTES,
            });
        }
        let block = serde_json::from_slice::<Self>(bytes).map_err(|_| BlockV4Error::Malformed)?;
        block.validate()?;
        Ok(block)
    }

    /// Validates hostile block structure, signatures, validity, and every root.
    ///
    /// Collection ceilings run before signature and hashing loops. This is pure
    /// and does not verify finality or mutate chain state.
    pub fn validate(&self) -> Result<(), BlockV4Error> {
        self.header.validate()?;
        if self.transactions.len() > MAX_BLOCK_V4_TRANSACTIONS {
            return Err(BlockV4Error::TooManyTransactions {
                actual: self.transactions.len(),
                maximum: MAX_BLOCK_V4_TRANSACTIONS,
            });
        }
        if self.receipts.len() > MAX_BLOCK_V4_TRANSACTIONS {
            return Err(BlockV4Error::TooManyReceipts {
                actual: self.receipts.len(),
                maximum: MAX_BLOCK_V4_TRANSACTIONS,
            });
        }
        if self.evidence.len() > MAX_BLOCK_SLASHING_EVIDENCE {
            return Err(BlockV4Error::TooManyEvidence {
                actual: self.evidence.len(),
                maximum: MAX_BLOCK_SLASHING_EVIDENCE,
            });
        }
        for (index, transaction) in self.transactions.iter().enumerate() {
            transaction
                .verify_for_chain(&self.header.chain_id)
                .map_err(|source| BlockV4Error::InvalidTransaction { index, source })?;
            if !transaction.validity.contains(self.header.height) {
                return Err(BlockV4Error::TransactionOutsideValidity { index });
            }
        }
        verify_transaction_receipt_binding(self.header.height, &self.transactions, &self.receipts)?;
        if transaction_root_v1(self.header.height, &self.transactions)? != self.header.tx_root {
            return Err(BlockV4Error::TransactionRootMismatch);
        }
        if receipt_root_v1(&self.receipts)? != self.header.receipt_root {
            return Err(BlockV4Error::ReceiptRootMismatch);
        }
        if evidence_root(&self.evidence).map_err(BlockV4Error::Evidence)?
            != self.header.evidence_root
        {
            return Err(BlockV4Error::EvidenceRootMismatch);
        }
        let bytes = canonical_json_bytes(self).map_err(BlockV4Error::CanonicalEncoding)?;
        if bytes.len() > MAX_BLOCK_V4_CANONICAL_BYTES {
            return Err(BlockV4Error::BlockTooLarge {
                actual: bytes.len(),
                maximum: MAX_BLOCK_V4_CANONICAL_BYTES,
            });
        }
        Ok(())
    }

    /// Returns the block identifier, exactly the validated V4 header hash.
    pub fn hash(&self) -> Result<Hash256, BlockV4Error> {
        self.validate()?;
        self.header.hash()
    }
}

fn deserialize_bounded_vec<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVisitor<T, const MAX: usize>(PhantomData<T>);

    impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVisitor<T, MAX>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "a protocol-2 block array with at most {MAX} entries"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > MAX) {
                return Err(serde::de::Error::custom(
                    "protocol-2 block collection exceeds its entry limit",
                ));
            }
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX {
                    return Err(serde::de::Error::custom(
                        "protocol-2 block collection exceeds its entry limit",
                    ));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(PhantomData))
}

mod bounded_transactions {
    use super::*;

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<TransactionV5>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_bounded_vec::<D, TransactionV5, MAX_BLOCK_V4_TRANSACTIONS>(deserializer)
    }
}

mod bounded_receipts {
    use super::*;

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<ReceiptV1>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_bounded_vec::<D, ReceiptV1, MAX_BLOCK_V4_TRANSACTIONS>(deserializer)
    }
}

mod bounded_evidence {
    use super::*;

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<SlashingEvidence>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_bounded_vec::<D, SlashingEvidence, MAX_BLOCK_SLASHING_EVIDENCE>(deserializer)
    }
}

/// Fail-closed validation errors for protocol-2 blocks and V4 headers.
#[derive(Debug, thiserror::Error)]
pub enum BlockV4Error {
    /// Header protocol version is not 2.
    #[error("V4 header requires protocol version 2")]
    UnsupportedProtocolVersion,
    /// A finalized user block cannot use genesis height zero.
    #[error("V4 block height must be greater than zero")]
    ZeroHeight,
    /// Either current or next authority commitment is the empty sentinel.
    #[error("V4 header authority-set commitments must be non-zero")]
    EmptyAuthorityCommitment,
    /// JSON bytes could not be decoded as the strict V4 schema.
    #[error("V4 block JSON is malformed")]
    Malformed,
    /// Complete canonical block bytes exceed the hard network/storage envelope.
    #[error("V4 block size {actual} exceeds maximum {maximum}")]
    BlockTooLarge {
        /// Observed canonical or hostile input byte count.
        actual: usize,
        /// Hard maximum byte count.
        maximum: usize,
    },
    /// Transaction array exceeds the hard block count limit.
    #[error("V4 block transaction count {actual} exceeds maximum {maximum}")]
    TooManyTransactions {
        /// Observed transaction count.
        actual: usize,
        /// Hard maximum transaction count.
        maximum: usize,
    },
    /// Receipt array exceeds the hard block count limit.
    #[error("V4 block receipt count {actual} exceeds maximum {maximum}")]
    TooManyReceipts {
        /// Observed receipt count.
        actual: usize,
        /// Hard maximum receipt count.
        maximum: usize,
    },
    /// Evidence array exceeds the existing objective-evidence limit.
    #[error("V4 block evidence count {actual} exceeds maximum {maximum}")]
    TooManyEvidence {
        /// Observed evidence count.
        actual: usize,
        /// Hard maximum evidence count.
        maximum: usize,
    },
    /// Signed transaction failed exact chain/signature/structure validation.
    #[error("V4 block transaction {index} is invalid: {source}")]
    InvalidTransaction {
        /// Zero-based rejected transaction position.
        index: usize,
        /// Stable V5 validation failure.
        source: TransactionValidationErrorV1,
    },
    /// A signed validity window does not contain this block height.
    #[error("V4 block transaction {index} is outside its signed height range")]
    TransactionOutsideValidity {
        /// Zero-based rejected transaction position.
        index: usize,
    },
    /// Transaction/receipt positional or fee binding failed.
    #[error("V4 transaction/receipt binding is invalid: {0}")]
    Receipt(#[from] ReceiptError),
    /// Objective evidence could not be hashed safely.
    #[error("V4 evidence is invalid: {0}")]
    Evidence(ChainError),
    /// Header transaction root differs from the shared position-bound root.
    #[error("V4 transaction root does not match its header")]
    TransactionRootMismatch,
    /// Header receipt root differs from the shared typed-receipt root.
    #[error("V4 receipt root does not match its header")]
    ReceiptRootMismatch,
    /// Header evidence root differs from the existing objective-evidence root.
    #[error("V4 evidence root does not match its header")]
    EvidenceRootMismatch,
    /// Canonical JSON encoding failed.
    #[error("V4 block or header cannot be canonically encoded")]
    CanonicalEncoding(ChainError),
}

fn deserialize_decimal_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(serde::de::Error::custom(
            "expected canonical unsigned decimal string",
        ));
    }
    value.parse::<u64>().map_err(serde::de::Error::custom)
}

mod u64_decimal {
    use super::*;

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_decimal_u64(deserializer)
    }
}

mod block_height_decimal {
    use super::*;

    pub fn serialize<S>(value: &BlockHeight, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.get().to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BlockHeight, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_decimal_u64(deserializer).map(BlockHeight::new)
    }
}

mod epoch_decimal {
    use super::*;

    pub fn serialize<S>(value: &Epoch, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.get().to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Epoch, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_decimal_u64(deserializer).map(Epoch::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    fn fixture_header() -> BlockHeaderV4 {
        BlockHeaderV4 {
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height: BlockHeight::new(42),
            epoch: Epoch::new(3),
            previous_hash: Hash256([0x00; 32]),
            state_root: Hash256([0x11; 32]),
            account_root: Hash256([0x22; 32]),
            tx_root: Hash256([0x33; 32]),
            receipt_root: Hash256([0x44; 32]),
            evidence_root: Hash256([0x55; 32]),
            finality_authority_set_root: Hash256([0x66; 32]),
            next_finality_authority_set_root: Hash256([0x77; 32]),
            proposer: Keypair::from_seed([1; 32]).address(),
            timestamp_ms: 1_700_000_000_000,
            base_fee_per_unit: 5,
        }
    }

    #[test]
    fn v4_header_hash_matches_the_browser_fixture() {
        let header = fixture_header();
        assert_eq!(
            header.hash().unwrap().to_hex(),
            "9855e491949296206f38c03e12a5f4aa82ca332170d1e42bb9dc1dfab5bb9949"
        );
        let json = serde_json::to_value(header).unwrap();
        assert_eq!(json["height"], "42");
        assert_eq!(json["epoch"], "3");
        assert_eq!(json["timestamp_ms"], "1700000000000");
        assert_eq!(json["base_fee_per_unit"], "5");
    }

    #[test]
    fn empty_v4_block_validates_shared_empty_roots() {
        let mut header = fixture_header();
        header.tx_root = Hash256::ZERO;
        header.receipt_root = Hash256::ZERO;
        header.evidence_root = Hash256::ZERO;
        let block = BlockV4 {
            header,
            transactions: Vec::new(),
            receipts: Vec::new(),
            evidence: Vec::new(),
        };
        block.validate().unwrap();
    }

    #[test]
    fn rejects_root_tampering_and_noncanonical_integer_json() {
        let mut header = fixture_header();
        header.tx_root = Hash256::ZERO;
        header.receipt_root = Hash256::ZERO;
        header.evidence_root = Hash256::ZERO;
        let block = BlockV4 {
            header,
            transactions: Vec::new(),
            receipts: Vec::new(),
            evidence: Vec::new(),
        };
        let mut value = serde_json::to_value(&block).unwrap();
        value["header"]["tx_root"] = serde_json::Value::String("99".repeat(32));
        let tampered = serde_json::from_value::<BlockV4>(value).unwrap();
        assert!(matches!(
            tampered.validate(),
            Err(BlockV4Error::TransactionRootMismatch)
        ));

        let mut value = serde_json::to_value(&block).unwrap();
        value["header"]["height"] = serde_json::Value::String("042".into());
        assert!(serde_json::from_value::<BlockV4>(value).is_err());
        let mut value = serde_json::to_value(&block).unwrap();
        value["header"]["height"] = serde_json::Value::Number(42.into());
        assert!(serde_json::from_value::<BlockV4>(value).is_err());
    }

    #[test]
    fn hostile_outer_bytes_are_bounded_before_json_decode() {
        assert!(matches!(
            BlockV4::decode_json(&vec![b' '; MAX_BLOCK_V4_CANONICAL_BYTES + 1]),
            Err(BlockV4Error::BlockTooLarge { .. })
        ));
    }

    #[test]
    fn hostile_binary_collection_length_fails_before_decoding_elements() {
        #[derive(Debug, Deserialize)]
        struct TransactionList {
            #[serde(deserialize_with = "bounded_transactions::deserialize")]
            #[allow(dead_code)]
            values: Vec<TransactionV5>,
        }
        #[derive(Serialize)]
        struct HostileList {
            values: Vec<u8>,
        }

        // These bytes are deliberately not transactions. The advertised count
        // alone is enough to fail; no element decode or large typed allocation
        // is attempted after trusting a hostile bincode length prefix.
        let bytes = bincode::serialize(&HostileList {
            values: vec![0; MAX_BLOCK_V4_TRANSACTIONS + 1],
        })
        .expect("hostile list encodes");
        let error = bincode::deserialize::<TransactionList>(&bytes)
            .expect_err("oversized block collection must fail");
        assert!(error
            .to_string()
            .contains("protocol-2 block collection exceeds its entry limit"));
    }
}
