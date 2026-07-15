//! Typed errors for the WEBC peer-to-peer layer.
//!
//! Every failure that can be caused by a remote peer is a typed value, never a
//! panic: a hostile or buggy peer must not be able to crash the node. Transport
//! I/O is captured as a string because the underlying `std::io::Error` is not
//! `Clone`/`PartialEq` and the exact OS error text is only useful for logging.

/// Errors returned by the peer-to-peer transport and gossip layer.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// A transport read/write or bind/connect failed.
    #[error("network I/O error: {0}")]
    Io(String),
    /// A message could not be encoded or decoded to the wire format.
    #[error("network message serialization failed: {0}")]
    Serialization(String),
    /// A received frame is larger than the configured maximum.
    #[error("network frame exceeds the maximum of {maximum} bytes")]
    FrameTooLarge { maximum: usize },
    /// The frame did not begin with the WEBC protocol magic.
    #[error("network frame has an unknown protocol magic")]
    BadMagic,
    /// The frame was too short or otherwise structurally invalid.
    #[error("network frame is malformed")]
    MalformedFrame,
    /// The frame declared a network protocol version this node does not speak.
    #[error("unsupported network protocol version: {actual}")]
    UnsupportedVersion { actual: u16 },
    /// The peer presented a different chain identifier during the handshake.
    #[error("handshake chain ID mismatch")]
    ChainIdMismatch,
    /// The peer failed to prove possession of its advertised identity key.
    #[error("handshake identity proof is invalid")]
    InvalidHandshakeProof,
    /// The handshake frame was structurally malformed.
    #[error("handshake frame is malformed")]
    MalformedHandshake,
    /// A cryptographic verification failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] webc_crypto::CryptoError),
    /// The peer closed the connection before completing the handshake.
    #[error("peer closed the connection during the handshake")]
    HandshakeClosed,
    /// The background network worker is no longer running.
    #[error("network worker has stopped")]
    WorkerStopped,
}

impl From<bincode::Error> for NetError {
    fn from(error: bincode::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

impl From<std::io::Error> for NetError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}
