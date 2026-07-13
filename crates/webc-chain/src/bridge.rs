//! Versioned bridge identities, messages, events, and prototype authorization.
//!
//! This module defines deterministic wire data but does not verify Ethereum or
//! Solana finality. The state machine owns escrow, replay protection, and asset
//! accounting. Incoming messages remain disabled unless a prototype trusted
//! relayer is explicitly configured; no type here makes real-fund bridging safe.

use crate::{Amount, ChainError};
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, Hash256};

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
    #[serde(with = "crate::hex_bytes")]
    pub sender: Vec<u8>,
    /// Destination-domain recipient bytes encoded as lowercase hex.
    #[serde(with = "crate::hex_bytes")]
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
}
