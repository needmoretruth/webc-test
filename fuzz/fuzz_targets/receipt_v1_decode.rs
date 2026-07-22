//! Fuzz the bounded protocol-2 receipt JSON boundary.
//!
//! Purpose: exercise hostile receipt byte limits, bounded event decoding, and
//! local accounting/schema invariants. It does not trust a node, bind a receipt
//! to a transaction, or verify finality. Data flow is raw fuzzer bytes through
//! the production decoder and validator. Security boundary: malformed event
//! arrays must fail before unbounded allocation and no input may panic or hang.

#![no_main]

use libfuzzer_sys::fuzz_target;
use webc_chain::ReceiptV1;

fuzz_target!(|data: &[u8]| {
    let Ok(receipt) = ReceiptV1::decode_json(data) else {
        return;
    };
    let _ = receipt.validate();
});
