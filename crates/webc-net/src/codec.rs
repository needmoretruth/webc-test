//! Shared bincode configuration for every WEBC network frame.
//!
//! Fixed-int encoding keeps leading fields (magic, version) at stable byte
//! offsets so a frame can be rejected cheaply before its payload is trusted, and
//! rejecting trailing bytes forces a frame to consume exactly its bytes. Both
//! the message envelope and the handshake frames use this identical config.
//!
//! Security boundary: this module turns hostile bytes into typed values. It must
//! never `unwrap`/`panic` on decode, and it must never let an attacker-chosen
//! length prefix drive unbounded work — hence the explicit byte limit below.

use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};

use crate::error::NetError;
use crate::wire::MAX_FRAME_BYTES;

/// Shared bincode config: fixed-int lengths, no trailing bytes, and a hard byte
/// cap ([`MAX_FRAME_BYTES`]).
///
/// Why the explicit limit (finding N6): a hostile frame can embed a
/// length/count prefix claiming billions of elements. The inbound decode is
/// already bounded in practice — the transport hands the codec a slice no larger
/// than `MAX_FRAME_BYTES` (the length-delimited codec's `max_frame_length` plus
/// [`crate::wire::decode_message`]'s own check), and serde caps its speculative
/// pre-allocation — but that is defense-by-accident. Binding the limit to
/// `MAX_FRAME_BYTES` here makes the codec fail closed on its own bound rather
/// than an external one: it rejects any attempt to serialize a value larger than
/// one legal frame at the source, so no code path can produce or trust an
/// over-frame buffer, and if the codec is ever pointed at an unbounded reader the
/// same cap applies to decode. Defense-in-depth for a length-prefix memory/CPU
/// exhaustion attack (AGENTS.md pitfall 4: bound hostile input before allocating
/// or looping on it).
pub(crate) fn frame_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_FRAME_BYTES as u64)
}

pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, NetError> {
    Ok(frame_options().serialize(value)?)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, NetError> {
    Ok(frame_options().deserialize(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N6 reproduce: the codec must enforce [`MAX_FRAME_BYTES`] as its own hard
    /// bound, failing closed on any value whose encoding would exceed one legal
    /// frame — instead of relying on an external post-hoc length check.
    ///
    /// Encoding a `Vec<u8>` of `MAX_FRAME_BYTES + 1` bytes produces a frame
    /// larger than the legal maximum. Before N6 (`frame_options` had no
    /// `.with_limit`), the codec happily serialized this over-frame buffer and
    /// left it to callers to notice; the byte limit makes the codec reject it at
    /// the source, so no code path can produce or trust a frame beyond the cap.
    #[test]
    fn rejects_encoding_beyond_one_frame() {
        let over_frame: Vec<u8> = vec![0u8; MAX_FRAME_BYTES + 1];
        assert!(
            encode(&over_frame).is_err(),
            "the codec byte limit must reject an over-frame encoding"
        );
    }

    /// A well-formed value that fits inside one frame still round-trips, so the
    /// limit does not reject legitimate traffic.
    #[test]
    fn round_trips_a_value_within_the_limit() {
        let value: Vec<u64> = (0..1_024).collect();
        let encoded = encode(&value).expect("encode within limit");
        let decoded: Vec<u64> = decode(&encoded).expect("decode within limit");
        assert_eq!(decoded, value);
    }
}
