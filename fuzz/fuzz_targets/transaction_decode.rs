//! Fuzz transaction wire decoding and the signing-bytes derivation.
//!
//! A stored or gossiped transaction is hostile input. Decoding it (bincode) and
//! then deriving its canonical hash/verification bytes must never panic on any
//! byte string — only return a typed error or a well-formed value. This target
//! decodes arbitrary bytes as a `Transaction` and, on success, exercises the
//! hash and signature-verification paths (which must also be panic-free).

#![no_main]

use libfuzzer_sys::fuzz_target;
use webc_chain::Transaction;

fuzz_target!(|data: &[u8]| {
    let Ok(tx) = bincode::deserialize::<Transaction>(data) else {
        return;
    };
    // Deriving canonical bytes / hashing must not panic on a decoded-but-hostile
    // transaction.
    let _ = tx.hash();
    // Signature verification must fail closed, never panic, on arbitrary content.
    let _ = tx.verify();
});
