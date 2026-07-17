//! Shared bincode configuration and transparent frame compression for WEBC
//! network frames.
//!
//! # Bincode config
//!
//! Variable-length integer encoding (WEBC §15.14): every integer in a frame —
//! most importantly every [`webc_chain::Amount`] — is written as a bincode
//! varint, so a small value costs a few bytes instead of a fixed 16 (`u128`) or 8
//! (`u64`). Rejecting trailing bytes forces a frame to consume exactly its bytes,
//! and a hard byte cap ([`MAX_FRAME_BYTES`]) bounds a hostile length/count prefix
//! (finding N6). Both the message envelope and the handshake frames use this
//! identical bincode config (via [`encode`]/[`decode`]).
//!
//! The clear frame header (magic + wire version) is written by [`crate::wire`] as
//! raw bytes *outside* bincode, so it stays at fixed offsets regardless of the
//! integer encoding: a foreign or wrong-version frame is still rejected before
//! its varint payload is decoded. The handshake `HandshakeHello` carries its own
//! magic/version as its first bincode fields, so bumping the wire version means a
//! peer speaking the other integer encoding fails the version check (or the
//! decode) and cleanly refuses to peer rather than misparsing — which is why this
//! encoding change is gated behind a `NET_PROTOCOL_VERSION` bump (3 → 4).
//!
//! # Transparent frame compression (WEBC §15.19/§15.24)
//!
//! §15.19/§15.24 decided zstd compression is on by default across wire *and*
//! storage. On the wire, [`compress_payload`]/[`decompress_payload`] wrap a
//! bincode payload in a 1-byte format tag followed by either the raw bytes or a
//! zstd frame — the same `0x00 = raw` / `0x01 = zstd` convention the storage
//! crate froze, so the two codecs read the same way. Only the **post-handshake
//! message envelope payload** is compressed ([`crate::wire`]); the handshake
//! frames are deliberately left raw — see the note on [`compress_payload`].
//!
//! # Security boundary — the decompression bomb
//!
//! This module turns hostile bytes into typed values. It must never
//! `unwrap`/`panic` on decode, and it must never let an attacker-chosen length
//! prefix *or a compressed frame* drive unbounded work.
//!
//! Wire frames are attacker-controlled, so — unlike the storage codec, whose
//! inputs are its own prior writes — a ~1 KB zstd frame can decompress to
//! gigabytes (a "zip bomb"). [`decompress_payload`] therefore decodes through a
//! **bounded** reader that yields at most [`MAX_FRAME_BYTES`] + 1 bytes: a frame
//! whose output would exceed the same budget an uncompressed frame obeys is
//! rejected with [`NetError::FrameTooLarge`] *before* any unbounded buffer is
//! allocated. The explicit bincode byte limit below is the matching bound on the
//! length-prefix side (finding N6). No `unwrap`, no `unsafe`.

use std::io::Read;

use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};

use crate::error::NetError;
use crate::wire::MAX_FRAME_BYTES;

/// Format tag for a payload carried verbatim (uncompressed).
///
/// Mirrors the storage codec's `0x00 = raw` tag so both WEBC compression seams
/// use one convention.
pub(crate) const RAW_TAG: u8 = 0x00;

/// Format tag for a payload carried as a zstd frame (mirrors storage `0x01`).
pub(crate) const ZSTD_TAG: u8 = 0x01;

/// zstd compression level. Level 3 is zstd's own default: near-peak ratio on the
/// structured bincode WEBC gossips (blocks, votes, certificates) at negligible
/// CPU, matching the §15.19 "negligible CPU" target.
const ZSTD_LEVEL: i32 = 3;

/// Payloads shorter than this are always sent raw. Below roughly this size a
/// zstd frame's fixed header/footer overhead exceeds any gain, so compressing
/// could only grow the frame; the small handshake-adjacent messages skip the
/// codec entirely and cost exactly one tag byte.
const MIN_COMPRESS_LEN: usize = 64;

/// Shared bincode config: variable-length integers, no trailing bytes, and a
/// hard byte cap ([`MAX_FRAME_BYTES`]).
///
/// Variable-length integers (WEBC §15.14): `.with_varint_encoding()` makes every
/// integer — and therefore every [`webc_chain::Amount`], whose non-human-readable
/// `Serialize` emits `serialize_u128` — encode compactly, a few bytes for a small
/// value instead of a fixed 16. This is a wire-format change, gated behind the
/// `NET_PROTOCOL_VERSION` 3 → 4 bump so a v3 peer never misparses a v4 frame.
///
/// Why the explicit limit (finding N6): a hostile frame can embed a
/// length/count prefix claiming billions of elements. Varint encoding does *not*
/// weaken this — the limit is what bounds it, not the integer width. The inbound
/// decode is already bounded in practice — the transport hands the codec a slice
/// no larger than `MAX_FRAME_BYTES` (the length-delimited codec's
/// `max_frame_length` plus [`crate::wire::decode_message`]'s own check), and
/// serde caps its speculative pre-allocation — but that is defense-by-accident.
/// Binding the limit to `MAX_FRAME_BYTES` here makes the codec fail closed on its
/// own bound rather than an external one: it rejects any attempt to serialize a
/// value larger than one legal frame at the source, so no code path can produce
/// or trust an over-frame buffer, and if the codec is ever pointed at an
/// unbounded reader the same cap applies to decode. Defense-in-depth for a
/// length-prefix memory/CPU exhaustion attack (AGENTS.md pitfall 4: bound hostile
/// input before allocating or looping on it).
pub(crate) fn frame_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_varint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_FRAME_BYTES as u64)
}

pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, NetError> {
    Ok(frame_options().serialize(value)?)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, NetError> {
    Ok(frame_options().deserialize(bytes)?)
}

/// Wraps a bincode `payload` in its on-the-wire physical form: a 1-byte format
/// tag followed by either the raw bytes or a zstd frame, whichever is smaller.
///
/// Adaptive skip: a payload below [`MIN_COMPRESS_LEN`], or one zstd cannot make
/// strictly smaller (incompressible / already-compressed data), is sent raw, so
/// the worst case is exactly one extra byte and space is never wasted — matching
/// the §15.19 note that compression "may skip … adaptively for incompressible
/// payloads".
///
/// Infallible by design: if compression is skipped or fails for any reason the
/// payload is sent raw, so encoding a frame never depends on compression
/// succeeding. Both peers run the same code, so no cross-version negotiation is
/// needed for this prototype; the tag byte reserves room to add further
/// algorithms (e.g. `0x02`) later without a flag day.
///
/// Only the post-handshake message envelope payload is compressed. The handshake
/// frames are intentionally left raw: the handshake is where peers negotiate the
/// wire version, so its frames must stay in the most stable possible format —
/// putting a compression tag *beneath* version negotiation would make the
/// framing itself impossible to ever version-negotiate. Those frames are tiny
/// and incompressible anyway, so compressing them would only add a tag byte.
pub(crate) fn compress_payload(payload: &[u8]) -> Vec<u8> {
    // Tiny payloads: never worth a zstd frame's overhead.
    if payload.len() < MIN_COMPRESS_LEN {
        return with_tag(RAW_TAG, payload);
    }
    // Compress; keep it only if strictly smaller than the raw form. `encode_all`
    // on an in-memory slice only fails on allocation-class errors; treat any
    // failure as "not compressible" and fall back to raw.
    match zstd::encode_all(payload, ZSTD_LEVEL) {
        Ok(compressed) if compressed.len() < payload.len() => with_tag(ZSTD_TAG, &compressed),
        _ => with_tag(RAW_TAG, payload),
    }
}

/// Reverses [`compress_payload`], returning the original bincode payload.
///
/// Fails closed on hostile input, never a panic or partial data:
/// - an empty body (missing tag) or an unknown tag → [`NetError::MalformedFrame`];
/// - a zstd frame that will not decode (truncated / garbage) →
///   [`NetError::Serialization`];
/// - a zstd frame whose output would exceed [`MAX_FRAME_BYTES`] (a decompression
///   bomb) → [`NetError::FrameTooLarge`], rejected *before* an unbounded buffer
///   is allocated (see [`decompress_zstd_bounded`]).
pub(crate) fn decompress_payload(body: &[u8]) -> Result<Vec<u8>, NetError> {
    let (tag, payload) = body.split_first().ok_or(NetError::MalformedFrame)?;
    match *tag {
        RAW_TAG => Ok(payload.to_vec()),
        ZSTD_TAG => decompress_zstd_bounded(payload),
        _ => Err(NetError::MalformedFrame),
    }
}

/// Decompresses a zstd `frame` while allocating no more than one frame budget.
///
/// The anti-zip-bomb mechanism: wire frames are attacker-controlled, so a small
/// zstd frame may claim to expand to gigabytes. Streaming the decoder through a
/// reader capped at [`MAX_FRAME_BYTES`] + 1 bytes means at most that many bytes
/// are ever produced or buffered — zstd decompresses block by block to fill the
/// bounded sink and is stopped the instant it would exceed the budget. If the
/// output reaches the cap it is rejected as [`NetError::FrameTooLarge`]; a
/// truncated or corrupt frame surfaces as a read error mapped to
/// [`NetError::Serialization`]. No `unwrap`, no `unsafe`, no unbounded
/// allocation.
fn decompress_zstd_bounded(frame: &[u8]) -> Result<Vec<u8>, NetError> {
    // Reading one extra byte lets us distinguish "fits the budget" from "would
    // exceed it": if the bounded reader yields cap + 1 bytes, the true output is
    // larger than the cap and the frame is rejected.
    let read_limit = MAX_FRAME_BYTES as u64 + 1;
    let decoder = zstd::stream::read::Decoder::new(frame).map_err(|error| {
        NetError::Serialization(format!("zstd frame could not be decompressed: {error}"))
    })?;
    // `Vec` grows adaptively to the real (bounded) output, so a small frame does
    // not eagerly reserve a full 4 MiB; `take` caps the total at cap + 1 bytes.
    let mut out = Vec::new();
    decoder
        .take(read_limit)
        .read_to_end(&mut out)
        .map_err(|error| {
            NetError::Serialization(format!("zstd frame could not be decompressed: {error}"))
        })?;
    if out.len() > MAX_FRAME_BYTES {
        return Err(NetError::FrameTooLarge {
            maximum: MAX_FRAME_BYTES,
        });
    }
    Ok(out)
}

/// Builds a tagged physical payload: one tag byte followed by `body`.
fn with_tag(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(tag);
    out.extend_from_slice(body);
    out
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

    /// The §15.14 payoff in the codec itself: variable-length integer encoding
    /// makes a small `u128` cost a few bytes, not a fixed 16 — the mechanism
    /// behind the per-`Amount` wire savings. Every value across the range must
    /// still round-trip exactly, including `u128::MAX` (which under bincode's
    /// varint costs one marker byte more than fixint's 16 — the accepted
    /// trade-off: only the very largest values pay full width).
    #[test]
    fn small_integers_use_varint_and_are_compact() {
        assert!(encode(&1u128).unwrap().len() < 16);
        assert!(encode(&255u128).unwrap().len() < 16);
        assert!(encode(&300u128).unwrap().len() < 16);
        for value in [0u128, 1, 250, 251, 300, u64::MAX as u128, u128::MAX] {
            let bytes = encode(&value).unwrap();
            assert_eq!(decode::<u128>(&bytes).unwrap(), value, "value {value}");
        }
    }

    /// Every payload must survive compress/decompress byte-for-byte, whatever the
    /// codec decides — the core "compression never alters content" guarantee.
    fn assert_payload_round_trips(payload: &[u8]) {
        let body = compress_payload(payload);
        assert!(!body.is_empty(), "the body always carries a tag byte");
        assert_eq!(decompress_payload(&body).unwrap(), payload);
    }

    #[test]
    fn round_trips_empty_tiny_and_large() {
        assert_payload_round_trips(b"");
        assert_payload_round_trips(b"x");
        assert_payload_round_trips(&[7u8; 63]); // just under the threshold
        assert_payload_round_trips(&[7u8; 64]); // exactly the threshold
        assert_payload_round_trips(&vec![0u8; 200_000]); // highly compressible
    }

    #[test]
    fn tiny_payloads_are_sent_raw() {
        let payload = vec![0u8; MIN_COMPRESS_LEN - 1];
        let body = compress_payload(&payload);
        assert_eq!(body[0], RAW_TAG);
        // Raw form is exactly the payload plus one tag byte.
        assert_eq!(body.len(), payload.len() + 1);
    }

    #[test]
    fn compressible_payloads_are_sent_compressed_and_smaller() {
        let payload = vec![0u8; 200_000];
        let body = compress_payload(&payload);
        assert_eq!(body[0], ZSTD_TAG);
        assert!(
            body.len() < payload.len() / 10,
            "expected strong compression, got {} bytes from {}",
            body.len(),
            payload.len()
        );
        assert_eq!(decompress_payload(&body).unwrap(), payload);
    }

    #[test]
    fn incompressible_payloads_fall_back_to_raw() {
        // High-entropy pseudo-random bytes zstd cannot shrink: sent raw at a cost
        // of exactly one tag byte over the input.
        let mut payload = vec![0u8; 4096];
        let mut state = 0x243f_6a88_85a3_08d3u64; // arbitrary non-zero seed
        for byte in payload.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state & 0xff) as u8;
        }
        let body = compress_payload(&payload);
        assert_eq!(body[0], RAW_TAG, "incompressible data must be sent raw");
        assert_eq!(body.len(), payload.len() + 1);
        assert_eq!(decompress_payload(&body).unwrap(), payload);
    }

    #[test]
    fn empty_body_is_malformed_not_panic() {
        assert!(matches!(
            decompress_payload(&[]).unwrap_err(),
            NetError::MalformedFrame
        ));
    }

    #[test]
    fn unknown_tag_is_malformed() {
        assert!(matches!(
            decompress_payload(&[0xff, 1, 2, 3]).unwrap_err(),
            NetError::MalformedFrame
        ));
    }

    #[test]
    fn truncated_zstd_frame_is_rejected_not_panic() {
        // A real zstd frame chopped in half must yield a typed error, not a panic.
        let body = compress_payload(&vec![9u8; 20_000]);
        assert_eq!(body[0], ZSTD_TAG);
        let truncated = &body[..body.len() / 2];
        assert!(matches!(
            decompress_payload(truncated).unwrap_err(),
            NetError::Serialization(_)
        ));
    }

    #[test]
    fn garbage_zstd_payload_is_rejected_not_panic() {
        // A zstd tag over bytes that are not a valid frame must not panic.
        assert!(matches!(
            decompress_payload(&[ZSTD_TAG, 0xde, 0xad, 0xbe, 0xef]).unwrap_err(),
            NetError::Serialization(_)
        ));
    }

    /// The decompression-bomb defence: a hand-forged frame whose zstd body
    /// expands past [`MAX_FRAME_BYTES`] is rejected with a typed error, before an
    /// unbounded buffer can be allocated. Constructed by compressing a buffer one
    /// byte larger than the cap (zeros, so the frame itself stays tiny — the
    /// essence of a zip bomb) and prefixing the zstd tag by hand.
    #[test]
    fn a_decompression_bomb_is_rejected_by_the_cap() {
        let oversized = vec![0u8; MAX_FRAME_BYTES + 1];
        let bomb_frame = zstd::encode_all(&oversized[..], ZSTD_LEVEL).expect("compress the bomb");
        // The compressed bomb is a tiny fraction of its decompressed size.
        assert!(
            bomb_frame.len() < MAX_FRAME_BYTES / 100,
            "the bomb frame must be small ({} bytes)",
            bomb_frame.len()
        );
        let body = with_tag(ZSTD_TAG, &bomb_frame);
        assert!(
            matches!(
                decompress_payload(&body),
                Err(NetError::FrameTooLarge { maximum }) if maximum == MAX_FRAME_BYTES
            ),
            "a frame that decompresses past the cap must be rejected as FrameTooLarge"
        );
    }

    /// A payload of exactly [`MAX_FRAME_BYTES`] (the largest legal size) still
    /// round-trips: the cap rejects only what is strictly over budget.
    #[test]
    fn a_payload_exactly_at_the_cap_still_round_trips() {
        let payload = vec![0u8; MAX_FRAME_BYTES];
        let body = compress_payload(&payload);
        assert_eq!(body[0], ZSTD_TAG, "all-zero data compresses");
        assert_eq!(decompress_payload(&body).unwrap().len(), MAX_FRAME_BYTES);
    }
}
