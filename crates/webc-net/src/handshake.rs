//! Authenticated peer handshake.
//!
//! WEBC devnet peers authenticate one another with a mutual challenge/response
//! over their Ed25519 identity keys before exchanging any gossip. Each side
//! sends a fresh random challenge; the counterparty must return a signature over
//! *that* challenge, proving live possession of the private key for the identity
//! it advertises. Binding the signature to the verifier's fresh challenge stops
//! a recorded handshake from being replayed to impersonate a peer.
//!
//! This is WEBC-owned protocol logic; only the signature primitive itself is
//! reused from `webc-crypto`. The handshake authenticates identity and pins the
//! chain ID and wire version. It does not encrypt the channel: gossiped data is
//! public and every consensus-weighted message is independently signed, so
//! confidentiality adds nothing at this layer for devnet. Channel encryption is
//! a later hardening step, not an A-1 requirement.

use serde::{Deserialize, Serialize};
use webc_chain::ChainId;
use webc_crypto::{verify_signature, Keypair, PublicKeyBytes, SignatureBytes};

use crate::error::NetError;
use crate::wire::{NET_PROTOCOL_MAGIC, NET_PROTOCOL_VERSION};

/// Domain tag separating handshake signatures from every other WEBC signature.
pub const HANDSHAKE_DOMAIN: &str = "WEBC_P2P_HANDSHAKE_V1";

/// Length of the random handshake challenge, in bytes.
pub const CHALLENGE_LEN: usize = 32;

/// Stable network identity of a peer: its Ed25519 identity public key.
///
/// The identity key is distinct from any account or consensus key; it names a
/// node, not a wallet or a validator. Consensus authority still comes from the
/// per-message signatures a validator makes with its registered consensus key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub PublicKeyBytes);

impl PeerId {
    /// Returns the lowercase hex of the underlying identity public key.
    pub fn to_hex(self) -> String {
        self.0.to_hex()
    }
}

impl std::fmt::Display for PeerId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0.to_hex())
    }
}

/// First handshake frame: who I am, what I speak, and my fresh challenge.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeHello {
    /// Fixed WEBC magic, echoing the wire tag so a mismatch is caught early.
    pub magic: [u8; 4],
    /// Wire protocol version this peer speaks.
    pub protocol_version: u16,
    /// Chain this peer believes it is on.
    pub chain_id: ChainId,
    /// This peer's Ed25519 identity public key.
    pub public_key: PublicKeyBytes,
    /// Fresh random bytes the counterparty must sign to prove liveness.
    pub challenge: [u8; CHALLENGE_LEN],
}

/// Second handshake frame: proof over the challenge the counterparty sent.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeProof {
    /// Signature over [`handshake_signing_bytes`] for the peer's challenge.
    pub signature: SignatureBytes,
}

/// Exact bytes signed in a handshake proof.
///
/// Ordering is unambiguous: a fixed domain prefix, then the fixed-length
/// challenge and identity key, then the variable-length chain ID last.
pub fn handshake_signing_bytes(
    chain_id: &ChainId,
    challenge: &[u8; CHALLENGE_LEN],
    signer_public_key: &PublicKeyBytes,
) -> Vec<u8> {
    let mut bytes =
        Vec::with_capacity(HANDSHAKE_DOMAIN.len() + CHALLENGE_LEN + 32 + chain_id.as_str().len());
    bytes.extend_from_slice(HANDSHAKE_DOMAIN.as_bytes());
    bytes.extend_from_slice(challenge);
    bytes.extend_from_slice(signer_public_key.as_bytes());
    bytes.extend_from_slice(chain_id.as_str().as_bytes());
    bytes
}

/// Builds this node's [`HandshakeHello`] carrying a caller-supplied challenge.
pub fn build_hello(
    identity: &Keypair,
    chain_id: &ChainId,
    challenge: [u8; CHALLENGE_LEN],
) -> HandshakeHello {
    HandshakeHello {
        magic: NET_PROTOCOL_MAGIC,
        protocol_version: NET_PROTOCOL_VERSION,
        chain_id: chain_id.clone(),
        public_key: identity.public_key(),
        challenge,
    }
}

/// Signs the challenge a peer sent us, proving possession of our identity key.
pub fn build_proof(
    identity: &Keypair,
    chain_id: &ChainId,
    peer_challenge: &[u8; CHALLENGE_LEN],
) -> HandshakeProof {
    let message = handshake_signing_bytes(chain_id, peer_challenge, &identity.public_key());
    HandshakeProof {
        signature: identity.sign(&message),
    }
}

/// Validates the peer's hello against our expected chain and wire version.
///
/// Returns the peer's advertised [`PeerId`]. This does *not* yet prove the peer
/// holds the matching private key; that is established by
/// [`verify_peer_proof`] over the challenge we sent them.
pub fn accept_hello(
    hello: &HandshakeHello,
    expected_chain_id: &ChainId,
) -> Result<PeerId, NetError> {
    if hello.magic != NET_PROTOCOL_MAGIC {
        return Err(NetError::BadMagic);
    }
    if hello.protocol_version != NET_PROTOCOL_VERSION {
        return Err(NetError::UnsupportedVersion {
            actual: hello.protocol_version,
        });
    }
    if &hello.chain_id != expected_chain_id {
        return Err(NetError::ChainIdMismatch);
    }
    Ok(PeerId(hello.public_key))
}

/// Verifies a peer's proof over the challenge we sent them.
///
/// `our_challenge` is the exact challenge this node put in its own hello to the
/// peer. Success proves the peer holds the private key for `peer.0`, so the
/// returned identity is authenticated.
pub fn verify_peer_proof(
    peer: PeerId,
    chain_id: &ChainId,
    our_challenge: &[u8; CHALLENGE_LEN],
    proof: &HandshakeProof,
) -> Result<PeerId, NetError> {
    let message = handshake_signing_bytes(chain_id, our_challenge, &peer.0);
    verify_signature(&peer.0, &message, &proof.signature)
        .map_err(|_| NetError::InvalidHandshakeProof)?;
    Ok(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(seed: u8) -> [u8; CHALLENGE_LEN] {
        [seed; CHALLENGE_LEN]
    }

    #[test]
    fn mutual_handshake_authenticates_both_peers() {
        let chain = ChainId::devnet();
        let alice = Keypair::from_seed([1u8; 32]);
        let bob = Keypair::from_seed([2u8; 32]);

        // Each side picks a fresh challenge and announces itself.
        let alice_challenge = challenge(0xA1);
        let bob_challenge = challenge(0xB2);
        let alice_hello = build_hello(&alice, &chain, alice_challenge);
        let bob_hello = build_hello(&bob, &chain, bob_challenge);

        // Each validates the other's hello, learning the claimed identity.
        let bob_id = accept_hello(&bob_hello, &chain).unwrap();
        let alice_id = accept_hello(&alice_hello, &chain).unwrap();
        assert_eq!(bob_id, PeerId(bob.public_key()));
        assert_eq!(alice_id, PeerId(alice.public_key()));

        // Each signs the challenge the other sent, then the other verifies it.
        let alice_proof = build_proof(&alice, &chain, &bob_hello.challenge);
        let bob_proof = build_proof(&bob, &chain, &alice_hello.challenge);
        verify_peer_proof(bob_id, &chain, &alice_challenge, &bob_proof).unwrap();
        verify_peer_proof(alice_id, &chain, &bob_challenge, &alice_proof).unwrap();
    }

    #[test]
    fn rejects_a_peer_on_a_different_chain() {
        let ours = ChainId::devnet();
        let theirs = ChainId::new("webc-other-1").unwrap();
        let peer = Keypair::from_seed([3u8; 32]);
        let hello = build_hello(&peer, &theirs, challenge(1));
        assert!(matches!(
            accept_hello(&hello, &ours).unwrap_err(),
            NetError::ChainIdMismatch
        ));
    }

    #[test]
    fn rejects_a_proof_over_the_wrong_challenge() {
        let chain = ChainId::devnet();
        let peer = Keypair::from_seed([4u8; 32]);
        let peer_id = PeerId(peer.public_key());
        // Peer signs one challenge, but we verify against a different one.
        let signed_challenge = challenge(0x11);
        let our_actual_challenge = challenge(0x22);
        let proof = build_proof(&peer, &chain, &signed_challenge);
        assert!(matches!(
            verify_peer_proof(peer_id, &chain, &our_actual_challenge, &proof).unwrap_err(),
            NetError::InvalidHandshakeProof
        ));
    }

    #[test]
    fn rejects_a_proof_forged_by_another_key() {
        let chain = ChainId::devnet();
        let real = Keypair::from_seed([5u8; 32]);
        let impostor = Keypair::from_seed([6u8; 32]);
        let our_challenge = challenge(0x33);
        // The impostor signs the challenge but claims the real peer's identity.
        let forged = build_proof(&impostor, &chain, &our_challenge);
        assert!(matches!(
            verify_peer_proof(PeerId(real.public_key()), &chain, &our_challenge, &forged)
                .unwrap_err(),
            NetError::InvalidHandshakeProof
        ));
    }

    #[test]
    fn rejects_a_hello_with_foreign_wire_version() {
        let chain = ChainId::devnet();
        let peer = Keypair::from_seed([7u8; 32]);
        let mut hello = build_hello(&peer, &chain, challenge(1));
        hello.protocol_version = 0xFF;
        assert!(matches!(
            accept_hello(&hello, &chain).unwrap_err(),
            NetError::UnsupportedVersion { actual: 0xFF }
        ));
    }
}
