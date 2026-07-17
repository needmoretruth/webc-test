//! Transparent at-rest value compression for the durable backend.
//!
//! Purpose: shrink what WEBC writes to disk without changing anything a caller
//! observes. WEBC §15.19/§15.24 decided zstd compression is on by default across
//! wire and storage; §15.24 fixes the key invariant this module upholds —
//! **compression lives only in the physical envelope, never in the content.**
//! Hashes and signatures are always computed over the canonical (uncompressed)
//! bytes; a value read back is byte-identical to the value written, whether it
//! was stored compressed or raw. Compression is therefore a pure physical
//! encoding, invisible above the [`KvStore`](crate::KvStore) seam.
//!
//! Boundaries: this module compresses *values only* — keys are never touched, so
//! ordering, ranges, and `last_key` are unaffected. It performs no I/O; the redb
//! adapter calls [`encode_value`] on every value it writes and [`decode_value`]
//! on every value it reads (point reads and scans alike).
//!
//! Format (part of the on-disk layout — treat as frozen): every stored value is
//! prefixed with a 1-byte format tag so reads are never ambiguous.
//!
//! - `0x00` [`RAW_TAG`]  — the remaining bytes are the value verbatim.
//! - `0x01` [`ZSTD_TAG`] — the remaining bytes are a zstd frame of the value.
//!
//! A stored value is thus always at least one byte long. An empty physical
//! value, or any tag other than the two above, is damage and is reported as
//! [`StorageError::Corruption`] — the store fails closed, never panics.
//!
//! Adaptive skip: [`encode_value`] stores a value raw when compression cannot
//! help — either the value is below [`MIN_COMPRESS_LEN`] (too small for zstd's
//! frame overhead to pay off) or the compressed frame did not come out strictly
//! smaller than the input (incompressible / already-compressed data). This keeps
//! the worst case at exactly one extra byte and never wastes space, matching the
//! §15.19 note that the implementation "may skip compression adaptively for
//! incompressible payloads".

use crate::error::StorageError;

/// Format tag for a value stored verbatim (uncompressed).
pub(crate) const RAW_TAG: u8 = 0x00;

/// Format tag for a value stored as a zstd frame.
pub(crate) const ZSTD_TAG: u8 = 0x01;

/// zstd compression level. Levels 1–3 give near-peak ratio on the small
/// structured records WEBC stores (block/state/certificate bincode) at trivial
/// CPU cost; 3 is zstd's own default and the §15.19 "negligible CPU" target.
const ZSTD_LEVEL: i32 = 3;

/// Values shorter than this are always stored raw. Below roughly this size a
/// zstd frame's fixed header/footer overhead exceeds any gain, so attempting
/// compression could only ever grow the record. Keeping the threshold means the
/// common tiny keys' values (tips, schema stamps, indexes) skip the codec work
/// entirely.
const MIN_COMPRESS_LEN: usize = 64;

/// Wraps `value` in its stored physical form: a 1-byte format tag followed by
/// either the raw bytes or a zstd frame, whichever is smaller.
///
/// Infallible by design: if compression is skipped or fails for any reason the
/// value is stored raw, so a write is never blocked by the codec. The choice is
/// deterministic — the same input always yields the same stored bytes — because
/// zstd encoding at a fixed level is deterministic and the size comparison is
/// exact.
pub(crate) fn encode_value(value: &[u8]) -> Vec<u8> {
    // Tiny values: never worth a zstd frame's overhead.
    if value.len() < MIN_COMPRESS_LEN {
        return with_tag(RAW_TAG, value);
    }
    // Try to compress; keep it only if it is strictly smaller than the raw form.
    // `encode_all` on an in-memory slice only fails on allocation-class errors;
    // treat any failure as "not compressible" and fall back to raw so a write
    // never depends on compression succeeding.
    match zstd::encode_all(value, ZSTD_LEVEL) {
        Ok(compressed) if compressed.len() < value.len() => with_tag(ZSTD_TAG, &compressed),
        _ => with_tag(RAW_TAG, value),
    }
}

/// Reverses [`encode_value`]: reads the format tag and returns the canonical
/// (uncompressed) value.
///
/// Fails closed on hostile input. A missing tag (empty physical value), an
/// unknown tag, or a zstd frame that will not decode (truncated or garbage) all
/// yield [`StorageError::Corruption`] — never a panic, never partial data. No
/// `unwrap`, no `unsafe`.
pub(crate) fn decode_value(stored: &[u8]) -> Result<Vec<u8>, StorageError> {
    let (tag, payload) = stored.split_first().ok_or_else(|| {
        StorageError::Corruption("stored value is empty: missing format tag".into())
    })?;
    match *tag {
        RAW_TAG => Ok(payload.to_vec()),
        ZSTD_TAG => zstd::decode_all(payload).map_err(|error| {
            StorageError::Corruption(format!("zstd value could not be decompressed: {error}"))
        }),
        other => Err(StorageError::Corruption(format!(
            "unknown storage value format tag {other:#04x}"
        ))),
    }
}

/// Builds a tagged physical value: one tag byte followed by `body`.
fn with_tag(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 1);
    out.push(tag);
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every logical value must survive an encode/decode round trip byte-for-byte
    /// — the core §15.24 guarantee that compression never alters content.
    fn assert_round_trips(value: &[u8]) {
        let stored = encode_value(value);
        assert!(!stored.is_empty(), "stored form always carries a tag byte");
        assert_eq!(decode_value(&stored).unwrap(), value);
    }

    #[test]
    fn round_trips_empty_tiny_and_large() {
        assert_round_trips(b"");
        assert_round_trips(b"x");
        assert_round_trips(&[7u8; 63]); // just under the threshold
        assert_round_trips(&[7u8; 64]); // exactly the threshold
        assert_round_trips(&vec![0u8; 100_000]); // highly compressible
    }

    #[test]
    fn tiny_values_are_stored_raw() {
        // Below the threshold the codec must not even attempt compression.
        let value = vec![0u8; MIN_COMPRESS_LEN - 1];
        let stored = encode_value(&value);
        assert_eq!(stored[0], RAW_TAG);
        // Raw form is exactly the value plus the one tag byte.
        assert_eq!(stored.len(), value.len() + 1);
    }

    #[test]
    fn compressible_values_are_stored_compressed_and_smaller() {
        let value = vec![0u8; 100_000];
        let stored = encode_value(&value);
        assert_eq!(stored[0], ZSTD_TAG);
        // 100 KB of zeros must collapse to a tiny fraction of the original.
        assert!(
            stored.len() < value.len() / 10,
            "expected strong compression, got {} bytes from {}",
            stored.len(),
            value.len()
        );
        assert_eq!(decode_value(&stored).unwrap(), value);
    }

    #[test]
    fn incompressible_values_fall_back_to_raw() {
        // A pseudo-random, high-entropy payload zstd cannot shrink: it must be
        // stored raw, costing exactly one tag byte over the input.
        let mut value = vec![0u8; 4096];
        let mut state = 0x243f_6a88_85a3_08d3u64; // arbitrary non-zero seed
        for byte in value.iter_mut() {
            // xorshift64: cheap deterministic high-entropy stream, no deps.
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = (state & 0xff) as u8;
        }
        let stored = encode_value(&value);
        assert_eq!(stored[0], RAW_TAG, "incompressible data must be stored raw");
        assert_eq!(stored.len(), value.len() + 1);
        assert_eq!(decode_value(&stored).unwrap(), value);
    }

    #[test]
    fn empty_physical_value_is_corruption_not_panic() {
        let err = decode_value(&[]).unwrap_err();
        assert!(matches!(err, StorageError::Corruption(_)));
    }

    #[test]
    fn unknown_tag_is_corruption() {
        let err = decode_value(&[0xff, 1, 2, 3]).unwrap_err();
        assert!(matches!(err, StorageError::Corruption(_)));
    }

    #[test]
    fn truncated_zstd_frame_is_corruption_not_panic() {
        // Produce a real zstd record, then chop its frame in half.
        let value = vec![9u8; 10_000];
        let stored = encode_value(&value);
        assert_eq!(stored[0], ZSTD_TAG);
        let truncated = &stored[..stored.len() / 2];
        let err = decode_value(truncated).unwrap_err();
        assert!(matches!(err, StorageError::Corruption(_)));
    }

    #[test]
    fn garbage_zstd_payload_is_corruption_not_panic() {
        // A zstd tag over bytes that are not a valid frame must not panic.
        let err = decode_value(&[ZSTD_TAG, 0xde, 0xad, 0xbe, 0xef]).unwrap_err();
        assert!(matches!(err, StorageError::Corruption(_)));
    }
}
