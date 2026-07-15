//! Shared bincode configuration for every WEBC network frame.
//!
//! Fixed-int encoding keeps leading fields (magic, version) at stable byte
//! offsets so a frame can be rejected cheaply before its payload is trusted, and
//! rejecting trailing bytes forces a frame to consume exactly its bytes. Both
//! the message envelope and the handshake frames use this identical config.

use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};

use crate::error::NetError;

pub(crate) fn frame_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, NetError> {
    Ok(frame_options().serialize(value)?)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, NetError> {
    Ok(frame_options().deserialize(bytes)?)
}
