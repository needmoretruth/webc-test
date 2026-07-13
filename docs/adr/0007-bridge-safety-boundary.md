# ADR-0007: bridge safety boundary

Status: accepted for prototypes; production trust model unapproved

Bridge messages are versioned and domain-separated and include source and
destination domains, nonce, exact asset identity, amount, recipient, source
transaction, and finality context. Execution is replay protected and reconciles
mint, burn, lock, release, and escrow supply.

Prototype relayers use valueless assets. Relaying a message is not authority to
create one. Real-fund code paths remain disabled until the production proof or
trust model is approved, independently audited, rate-limited, monitored, and
tested through incident drills.
