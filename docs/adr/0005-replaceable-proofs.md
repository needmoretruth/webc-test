# ADR-0005: replaceable state and checkpoint proofs

Status: accepted direction; succinct backend remains a benchmark gate

Merkle account/object proofs are the first implementation and permanent
fallback. Succinct checkpoint proofs use a versioned interface that identifies
the proof system, public inputs, finalized checkpoint, and verification limits.

Consensus does not depend on a single proof vendor. Nodes reject unknown proof
versions and browsers expose proof lag instead of silently trusting an RPC.
