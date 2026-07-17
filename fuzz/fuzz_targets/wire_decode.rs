//! Fuzz the peer-to-peer frame decoder against arbitrary bytes.
//!
//! `decode_message` is the first thing a node runs on a hostile peer's frame,
//! before any signature or semantic check. It must never panic, hang, or
//! over-allocate on malformed input — only return a typed error. This target
//! feeds it raw fuzzer bytes; the harness fails only if the decoder panics.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Any outcome (Ok/Err) is acceptable; a panic or hang is a bug.
    let _ = webc_net::decode_message(data);
});
