//! Versioned block and header commitments.
//!
//! This module defines consensus data only; it does not execute transactions or
//! decide finality. A header receives already validated roots and metadata from
//! block execution. Hashing is domain-separated and deterministic. Invalid
//! serialization returns a typed error and cannot partially change chain state.

use crate::{ChainError, ChainId, ProtocolVersion, Receipt, SlashingEvidence, Transaction};
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, Hash256};

/// Header committed by validators.
///
/// `state_root` commits to all major state subtrees and global accounting
/// counters. `account_root` is exposed separately so browser light wallets can
/// verify account proofs without understanding every internal subtree.
///
/// The header hash is computed from canonical JSON (not Rust-only bincode), so
/// browsers can recompute the same hash when verifying light-client proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockHeader {
    /// Protocol configuration schema used to validate this block.
    pub protocol_version: ProtocolVersion,
    /// Replay-protection network identifier fixed by genesis.
    pub chain_id: ChainId,
    /// Monotonic block height, starting at one after genesis.
    pub height: u64,
    /// Consensus epoch number whose validator snapshot authorizes the block.
    pub epoch: u64,
    /// Hash of the immediately preceding authoritative block.
    pub previous_hash: Hash256,
    /// Root committing every consensus state subtree after block execution.
    pub state_root: Hash256,
    /// Account-only root exposed for lightweight balance proofs.
    pub account_root: Hash256,
    /// Merkle root of signed transactions in execution order.
    pub tx_root: Hash256,
    /// Merkle root of deterministic receipts in transaction order.
    pub receipt_root: Hash256,
    /// Ordered Merkle root of objective slashing-evidence identifiers.
    ///
    /// This binds every system-level slash to the validator-signed block hash;
    /// changing, removing, or reordering evidence therefore invalidates finality.
    pub evidence_root: Hash256,
    /// Validator operator address that proposed this block.
    pub proposer: Address,
    /// Consensus-validated Unix timestamp in milliseconds; execution never reads a clock.
    pub timestamp_ms: u64,
    /// Native base units charged per execution unit for this block.
    pub base_fee_per_unit: u64,
}

/// Stable domain tag mixed into the header hash. Bumping this invalidates all
/// existing block hashes, so only change it when deliberately taking a
/// breaking header-format change.
pub const BLOCK_HEADER_DOMAIN: &str = "WEBC_BLOCK_HEADER_V3";

impl BlockHeader {
    pub fn hash(&self) -> Result<Hash256, ChainError> {
        // Wrap with a domain tag so a header can never be confused with any
        // other WEBC artifact that happens to share the same JSON shape.
        let wrapped = HeaderHashPayload {
            domain: BLOCK_HEADER_DOMAIN,
            header: self,
        };
        let bytes = crate::canonical::canonical_json_bytes(&wrapped)?;
        Ok(Hash256::digest(bytes))
    }
}

#[derive(Serialize)]
struct HeaderHashPayload<'a> {
    domain: &'static str,
    header: &'a BlockHeader,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Authoritative block data committed by its header hash.
pub struct Block {
    /// Versioned consensus header and all execution commitments.
    pub header: BlockHeader,
    /// Signed transactions in canonical execution order.
    pub transactions: Vec<Transaction>,
    /// Deterministic result corresponding one-to-one with each transaction.
    pub receipts: Vec<Receipt>,
    /// Objective signed artifacts included for independent slashing processing.
    pub evidence: Vec<SlashingEvidence>,
}

impl Block {
    /// Returns the block identifier, which is exactly the V3 header hash.
    pub fn hash(&self) -> Result<Hash256, ChainError> {
        self.header.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CURRENT_PROTOCOL_VERSION;
    use webc_crypto::Keypair;

    fn fixture_header() -> BlockHeader {
        BlockHeader {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            height: 7,
            epoch: 2,
            previous_hash: Hash256([0x00; 32]),
            state_root: Hash256([0x11; 32]),
            account_root: Hash256([0x22; 32]),
            tx_root: Hash256([0x33; 32]),
            receipt_root: Hash256([0x44; 32]),
            evidence_root: Hash256([0x55; 32]),
            proposer: Keypair::from_seed([1u8; 32]).address(),
            timestamp_ms: 1_700_000_000_000,
            base_fee_per_unit: 5,
        }
    }

    #[test]
    fn v3_header_hash_is_stable_and_rejects_removed_poh_field() {
        let header = fixture_header();
        assert_eq!(
            header.hash().expect("fixture hashes").to_hex(),
            "c5f26fe6564fcc1394e12cab50783f561ca586f0fb80a9c04b9fe5bdb3be7b74"
        );

        let mut legacy = serde_json::to_value(header).expect("fixture serializes");
        legacy.as_object_mut().expect("header is an object").insert(
            "poh_hash".to_owned(),
            serde_json::Value::String(Hash256::ZERO.to_hex()),
        );
        assert!(serde_json::from_value::<BlockHeader>(legacy).is_err());
    }
}
