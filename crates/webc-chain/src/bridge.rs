//! Versioned bridge identities, messages, events, and prototype authorization.
//!
//! This module defines deterministic wire data but does not verify Ethereum or
//! Solana finality. The state machine owns escrow, replay protection, and asset
//! accounting. Incoming messages remain disabled unless a prototype trusted
//! relayer is explicitly configured; no type here makes real-fund bridging safe.

use crate::{Amount, ChainError};
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, Hash256};

/// Maximum length, in bytes, of a bridge external sender/recipient address
/// byte string.
///
/// External-chain addresses are small — 20 bytes on EVM chains, 32 bytes on
/// Solana, 32 bytes for a native WEBC address — so 128 leaves generous headroom
/// for any supported domain while rejecting a hostile message that carries a
/// multi-kilobyte "address" to inflate the decoded allocation and the canonical
/// message hash (finding B1). This is deliberately much smaller than
/// `object::MAX_OBJECT_DATA_BYTES`: an address is not a payload.
pub const MAX_BRIDGE_RECIPIENT_BYTES: usize = 128;

/// Human-readable hex codec for bridge external-address byte fields that bounds
/// length *before* decoding (finding B1).
///
/// The shared `crate::hex_bytes` codec is intentionally unbounded because it
/// also carries large post-quantum key material; bridge address fields are tiny
/// and hostile, so they use this stricter codec instead. Mirrors
/// `object::bounded_hex`: the serialized form (lowercase hex) is byte-identical,
/// so canonical hashes and cross-language SDK parity are unchanged — only the
/// decode path gains a bound and an even-length check.
pub(crate) mod bounded_recipient_hex {
    use super::MAX_BRIDGE_RECIPIENT_BYTES;
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        // Two hex characters per byte; check the string length before decoding
        // so a hostile length prefix cannot size an allocation.
        if encoded.len() > MAX_BRIDGE_RECIPIENT_BYTES * 2 {
            return Err(D::Error::custom(
                "bridge address exceeds maximum byte length",
            ));
        }
        if encoded.len() % 2 != 0 {
            return Err(D::Error::custom("bridge address hex length must be even"));
        }
        hex::decode(encoded).map_err(D::Error::custom)
    }
}

/// External chains WEBC intends to interoperate with.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExternalChain {
    /// Native WEBC Layer-1 domain.
    Webc,
    /// Ethereum execution-layer domain.
    Ethereum,
    /// Solana domain.
    Solana,
}

/// Asset identifier for native and wrapped bridge assets.
///
/// `External` covers assets such as USDC/USDT. In a production bridge this must
/// be tied to audited allowlists and issuer/contract metadata.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssetId {
    /// Native WEBC issued and accounted by this Layer 1.
    NativeWebc,
    /// Wrapped WEBC representation, identified by its origin domain.
    WrappedWebc {
        /// Domain whose native WEBC escrow backs this representation.
        origin_chain: ExternalChain,
    },
    /// External fungible asset represented on WEBC.
    External {
        /// Domain where the canonical asset contract or mint exists.
        origin_chain: ExternalChain,
        /// Display symbol only; never sufficient as asset identity.
        symbol: String,
        /// Exact source contract/program mint identity.
        contract_or_mint: String,
    },
}

/// Prototype bridge authorization config.
///
/// This is intentionally conservative: incoming mint/release messages are not
/// permissionless. A future bridge can replace this with guardian signatures,
/// Ethereum/Solana light-client proofs, or ZK proofs. Until then, only explicit
/// trusted relayers may submit incoming bridge messages.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Whether the prototype accepts any incoming message submissions.
    pub incoming_messages_enabled: bool,
    /// Explicit prototype relayers; this is not production proof verification.
    pub trusted_relayers: Vec<Address>,
}

impl BridgeConfig {
    /// Returns whether `relayer` may enter the still-prototype verification path.
    pub fn can_submit_incoming(&self, relayer: Address) -> bool {
        self.incoming_messages_enabled && self.trusted_relayers.contains(&relayer)
    }
}

/// Replay-protected cross-chain message.
///
/// A production bridge would verify these messages with guardian signatures,
/// source-chain light-client proofs, or ZK proofs. The prototype stores a hash of
/// each processed message so the same message cannot mint/release twice.
///
/// `sender` and `recipient` are byte buffers (an external address and a WEBC
/// address respectively). They are serialized as lowercase hex strings so the
/// canonical message hash is reproducible by the browser SDK without
/// negotiating Rust's default byte-array JSON encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMessage {
    /// Domain where the proven lock or burn occurred.
    pub source_chain: ExternalChain,
    /// Domain expected to apply this message.
    pub destination_chain: ExternalChain,
    /// Source-domain sequence number; replay identity also commits the source transaction.
    pub nonce: u64,
    /// Exact origin and contract/mint-bound asset identity.
    pub asset: AssetId,
    /// Source-domain sender bytes encoded as lowercase hex on human-readable wires.
    #[serde(with = "crate::bridge::bounded_recipient_hex")]
    pub sender: Vec<u8>,
    /// Destination-domain recipient bytes encoded as lowercase hex.
    #[serde(with = "crate::bridge::bounded_recipient_hex")]
    pub recipient: Vec<u8>,
    /// Quantity in the asset's protocol base units; state execution rejects zero.
    pub amount: Amount,
    /// Finalized source transaction/event commitment.
    pub source_tx: Hash256,
}

impl BridgeMessage {
    /// Returns the canonical replay identity shared by Rust and browser clients.
    pub fn hash(&self) -> Result<Hash256, ChainError> {
        // Canonical JSON keeps bridge message hashes stable across Rust and
        // the browser SDK, so replay protection works identically on both sides.
        let bytes = crate::canonical::canonical_json_bytes(self)?;
        Ok(Hash256::digest(bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeEvent {
    /// Native WEBC entered domain-isolated escrow.
    Locked {
        /// Outgoing canonical bridge message.
        message: BridgeMessage,
        /// Canonical message/replay hash.
        message_hash: Hash256,
    },
    /// An external representation was minted on WEBC.
    Minted {
        /// Authorized incoming source message.
        message: BridgeMessage,
        /// Canonical message/replay hash.
        message_hash: Hash256,
    },
    /// An external representation was burned on WEBC.
    Burned {
        /// Outgoing canonical bridge message.
        message: BridgeMessage,
        /// Canonical message/replay hash.
        message_hash: Hash256,
    },
    /// Native WEBC left source-domain escrow and became liquid.
    Released {
        /// Authorized incoming burn message.
        message: BridgeMessage,
        /// Canonical message/replay hash.
        message_hash: Hash256,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    #[test]
    fn bridge_message_hash_matches_browser_fixture() {
        let recipient = Keypair::from_seed([2u8; 32]).address();
        let message = BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 9,
            asset: AssetId::External {
                origin_chain: ExternalChain::Ethereum,
                symbol: "USDC".to_owned(),
                contract_or_mint: "0x1234".to_owned(),
            },
            sender: vec![0xab, 0xcd],
            recipient: recipient.as_bytes().to_vec(),
            amount: Amount::from_units(77),
            source_tx: Hash256([0x77; 32]),
        };
        assert_eq!(
            message.hash().expect("fixture hashes").to_hex(),
            "4c984acec3e91d74db4d81ccce74b6cd8214ff56626747ced5f24b673b83ce85"
        );
    }

    #[test]
    fn bridge_message_rejects_oversized_address_before_decode() {
        // B1: a hostile over-length recipient hex is rejected at the length
        // check, before any Vec<u8> is allocated. Pre-fix, the unbounded
        // `hex_bytes` codec would decode it into a large allocation.
        let mut value = serde_json::to_value(BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 1,
            asset: AssetId::NativeWebc,
            sender: vec![1, 2, 3],
            recipient: vec![4, 5, 6],
            amount: Amount::from_units(1),
            source_tx: Hash256([0u8; 32]),
        })
        .expect("serializes");
        // (MAX + 1) bytes encoded as hex exceeds the bound.
        value["recipient"] = serde_json::Value::String("ab".repeat(MAX_BRIDGE_RECIPIENT_BYTES + 1));
        assert!(serde_json::from_value::<BridgeMessage>(value).is_err());
    }

    #[test]
    fn bridge_message_rejects_odd_length_address_hex() {
        let mut value = serde_json::to_value(BridgeMessage {
            source_chain: ExternalChain::Ethereum,
            destination_chain: ExternalChain::Webc,
            nonce: 1,
            asset: AssetId::NativeWebc,
            sender: vec![1, 2, 3],
            recipient: vec![4, 5, 6],
            amount: Amount::from_units(1),
            source_tx: Hash256([0u8; 32]),
        })
        .expect("serializes");
        value["sender"] = serde_json::Value::String("abc".to_owned());
        assert!(serde_json::from_value::<BridgeMessage>(value).is_err());
    }
}
