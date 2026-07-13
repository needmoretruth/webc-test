//! Serde helper: encode `Vec<u8>` fields as lowercase hex strings instead of
//! JSON number arrays.
//!
//! Why this exists:
//! - Rust's default serde behavior turns `Vec<u8>` into a JSON array of
//!   numbers (`[1, 2, 3]`). That works, but it is verbose and (more
//!   importantly) the browser SDK must match that byte-for-byte during
//!   canonical signing. Hex strings are shorter, easier to audit, and align
//!   with how addresses, hashes, and signatures are already represented.
//! - The bridge module has `sender`/`recipient` byte fields that must be
//!   reproducible across Rust and TypeScript, so both sides must agree on a
//!   single encoding. Hex is the obvious choice.
//!
//! Usage:
//! ```ignore
//! #[serde(with = "crate::hex_bytes", default)]
//! pub recipient: Vec<u8>,
//! ```
//! On the TypeScript side, simply treat these fields as lowercase hex strings.

use serde::{Deserialize, Deserializer, Serializer};

/// Serializes a `&[u8]` as a lowercase hex string.
pub fn serialize<S>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(value))
}

/// Deserializes a lowercase hex string back into a `Vec<u8>`.
pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    hex::decode(text).map_err(serde::de::Error::custom)
}

/// Same as `serialize` but tolerates `Option<Vec<u8>>`-style fields marked `default`.
/// Currently unused, but kept available so future optional byte fields can opt
/// into hex without re-implementing the serializer.
pub fn deserialize_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)?
        .map(|text| hex::decode(text).map_err(serde::de::Error::custom))
        .transpose()
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Probe {
        #[serde(with = "super")]
        bytes: Vec<u8>,
    }

    #[test]
    fn round_trips_through_hex() {
        let original = Probe {
            bytes: vec![0, 1, 255, 32],
        };
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#"{"bytes":"0001ff20"}"#);
        let restored: Probe = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, original);
    }
}
