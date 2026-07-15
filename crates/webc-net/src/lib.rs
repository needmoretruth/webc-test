//! WEBC peer-to-peer networking.
//!
//! This crate is the swappable transport seam between WEBC's deterministic
//! protocol logic and the network. It owns the WEBC-specific pieces — the
//! gossip message set, the self-describing wire envelope, and the authenticated
//! peer handshake — while reusing mature, permissively licensed crates for the
//! commodity plumbing underneath (async runtime and length-delimited framing).
//!
//! Layering, from the bottom up:
//! - [`wire`]: what a single frame's bytes mean ([`NetMessage`], encode/decode).
//! - [`handshake`]: how two peers authenticate before exchanging gossip.
//!
//! The transport implementation (TCP dialing/listening, the peer table, and
//! flood gossip with loop suppression) is added on top of these in A-1.2. Pure
//! protocol crates (`webc-chain`, `webc-crypto`, `webc-storage`) stay fully
//! synchronous; all async lives here and in `webc-node`.

pub mod error;
pub mod handshake;
pub mod wire;

pub use error::NetError;
pub use handshake::{
    accept_hello, build_hello, build_proof, handshake_signing_bytes, verify_peer_proof,
    HandshakeHello, HandshakeProof, PeerId, CHALLENGE_LEN, HANDSHAKE_DOMAIN,
};
pub use wire::{
    decode_message, encode_message, message_id, NetMessage, MAX_FRAME_BYTES, NET_PROTOCOL_MAGIC,
    NET_PROTOCOL_VERSION,
};
