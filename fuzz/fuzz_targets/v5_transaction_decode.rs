//! Fuzz the bounded protocol-2 transaction JSON boundary.
//!
//! Purpose: exercise hostile V5 JSON decoding, structural checks, canonical
//! transaction identity, and chain-bound signature verification. It does not
//! mutate chain state or assume a candidate is valid. Data flow is raw fuzzer
//! bytes through the production bounded decoder and every stateless verifier.
//! Security boundary: no input may panic, hang, or bypass the 256 KiB ceiling.

#![no_main]

use libfuzzer_sys::fuzz_target;
use webc_chain::{ChainId, TransactionV5};

fuzz_target!(|data: &[u8]| {
    let Ok(transaction) = TransactionV5::decode_json(data) else {
        return;
    };
    let _ = transaction.validate_structure();
    let _ = transaction.transaction_id();
    let _ = transaction.verify_for_chain(&ChainId::devnet());
});
