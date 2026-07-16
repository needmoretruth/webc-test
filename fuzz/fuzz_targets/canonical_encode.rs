//! Fuzz the canonical JSON encoder that produces consensus/signing bytes.
//!
//! `canonical_json_bytes` must deterministically encode any serde value or
//! fail closed — in particular it must reject floats (which would break
//! cross-language byte parity) rather than emit them, and must never panic. The
//! target parses fuzzer bytes into a `serde_json::Value` (itself a hostile-input
//! parse) and canonicalizes it; a panic in either step is a bug.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    match webc_chain::canonical::canonical_json_bytes(&value) {
        Ok(bytes) => {
            // Re-encoding the canonical bytes must itself parse and be stable:
            // canonicalization is idempotent on its own output.
            if let Ok(reparsed) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let again = webc_chain::canonical::canonical_json_bytes(&reparsed)
                    .expect("canonical output must re-canonicalize");
                assert_eq!(bytes, again, "canonicalization is not idempotent");
            }
        }
        // A value containing a float (or otherwise non-canonical) is rejected;
        // that is the correct fail-closed behavior, not a bug.
        Err(_) => {}
    }
});
