//! Canonical JSON encoding shared between Rust and the browser SDK.
//!
//! Both Rust and TypeScript must compute the *exact same* bytes for a
//! transaction's signing payload. If they disagree on a single byte, the
//! signature will not verify.
//!
//! We deliberately avoid Rust-only `bincode` for anything the browser must sign
//! or verify. Instead both sides use this deterministic JSON variant:
//!
//! 1. Object keys are sorted lexicographically (UTF-8 byte order).
//! 2. No insignificant whitespace.
//! 3. `Amount` values (u128) become decimal strings, never JSON numbers,
//!    because JavaScript cannot safely represent u128.
//! 4. Byte arrays (addresses, hashes, public keys, signatures) become
//!    lowercase hex strings.
//! 5. Arrays and nested objects follow the same rules recursively.
//!
//! The shape is tiny on purpose: a few hundred lines, no dependencies beyond
//! `serde_json`. That keeps the node light and the browser implementation
//! trivial to audit.

use crate::ChainError;
use serde::Serialize;
use serde_json::Value;

/// Serializes a `Serialize` value into canonical JSON bytes.
///
/// The input is anything serde can serialize (Rust structs with
/// `#[derive(Serialize)]`). The output is a stable byte string that both
/// Rust and TypeScript reproduce identically for the same logical value.
///
/// `Value`s go through `serde_json` first, so this function never panics on
/// custom types and does not depend on struct field declaration order:
/// `serde_json::to_value` normalizes everything into a JSON tree, and
/// `canonicalize_value` then sorts keys and re-encodes deterministically.
pub fn canonical_json_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, ChainError> {
    let json = serde_json::to_value(value)?;
    let normalized = canonicalize_value(json)?;
    Ok(encode(&normalized)?.into_bytes())
}

/// Returns the canonical JSON text for a serde-serializable value.
pub fn canonical_json_string<T: Serialize + ?Sized>(value: &T) -> Result<String, ChainError> {
    let json = serde_json::to_value(value)?;
    let normalized = canonicalize_value(json)?;
    encode(&normalized)
}

/// Recursively normalizes a JSON value into canonical form.
///
/// - Objects become key-sorted objects.
/// - Arrays are normalized element-wise (order preserved).
/// - Floating-point numbers are rejected because their cross-language spelling
///   and precision are unsafe in signed consensus payloads.
/// - All other scalars are passed through unchanged.
fn canonicalize_value(value: Value) -> Result<Value, ChainError> {
    match value {
        Value::Object(map) => {
            // BTreeMap over String keys gives us lexicographic byte ordering,
            // which matches the TypeScript `Object.keys(...).sort()` contract.
            let mut sorted = std::collections::BTreeMap::new();
            for (key, child) in map {
                sorted.insert(key, canonicalize_value(child)?);
            }
            Ok(Value::Object(sorted.into_iter().collect()))
        }
        Value::Array(items) => Ok(Value::Array(
            items
                .into_iter()
                .map(canonicalize_value)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        Value::Number(number) => {
            if number.is_u64() || number.is_i64() {
                Ok(Value::Number(number))
            } else {
                Err(ChainError::NonIntegerCanonicalNumber)
            }
        }
        other => Ok(other),
    }
}

/// Encodes a canonical JSON value into text with no insignificant whitespace.
fn encode(value: &Value) -> Result<String, ChainError> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(bool) => Ok(bool.to_string()),
        Value::Number(number) => Ok(number.to_string()),
        Value::String(text) => quote_string(text),
        Value::Array(items) => {
            let parts = items.iter().map(encode).collect::<Result<Vec<_>, _>>()?;
            Ok(format!("[{}]", parts.join(",")))
        }
        Value::Object(map) => {
            // `map` is a serde_json Map, but it preserves insertion order. We
            // re-sort here defensively so encoding never depends on the caller
            // having sorted already.
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            let parts = entries
                .into_iter()
                .map(|(key, value)| Ok(format!("{}:{}", quote_string(key)?, encode(value)?)))
                .collect::<Result<Vec<_>, ChainError>>()?;
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}

/// Encodes a string as a JSON string literal.
fn quote_string(text: &str) -> Result<String, ChainError> {
    // We reuse `serde_json`'s escaping by serializing a `Value::String`, which
    // guarantees RFC 8259 compliance for control characters and unicode.
    serde_json::to_string(text).map_err(ChainError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Sample {
        b: u64,
        a: String,
        nested: Nested,
    }

    #[derive(Serialize)]
    struct Nested {
        y: Vec<u64>,
        x: bool,
    }

    #[test]
    fn keys_are_sorted_and_whitespace_removed() {
        let sample = Sample {
            b: 1,
            a: "hi".to_string(),
            nested: Nested {
                y: vec![3, 2, 1],
                x: true,
            },
        };
        let canonical = canonical_json_string(&sample).unwrap();
        // Keys must appear in sorted order: a, b, nested (then nested: x, y).
        assert_eq!(
            canonical,
            r#"{"a":"hi","b":1,"nested":{"x":true,"y":[3,2,1]}}"#
        );
    }

    #[test]
    fn same_logical_value_produces_same_bytes() {
        // Insertion order should not matter for the canonical output.
        #[derive(Serialize)]
        struct Ordered {
            a: u64,
            b: u64,
        }
        #[derive(Serialize)]
        struct Reversed {
            b: u64,
            a: u64,
        }

        let ordered = canonical_json_string(&Ordered { a: 1, b: 2 }).unwrap();
        let reversed = canonical_json_string(&Reversed { b: 2, a: 1 }).unwrap();
        assert_eq!(ordered, reversed);
    }

    #[test]
    fn floating_point_input_is_rejected() {
        assert!(matches!(
            canonical_json_string(&serde_json::json!({ "unsafe": 1.5 })),
            Err(ChainError::NonIntegerCanonicalNumber)
        ));
    }
}
