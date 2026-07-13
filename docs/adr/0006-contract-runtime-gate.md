# ADR-0006: evidence-based contract runtime selection

Status: accepted evaluation process; no runtime selected

Restricted WASM/Rust, Move VM, and EVM candidates implement identical reference
applications. Each must provide deterministic resource limits, enforced state
access, stable TypeScript clients, sandboxing, and a versioned ABI.

Only the candidate that passes security gates and wins the published benchmark
scorecard is enabled. Other runtimes stay disabled. Native Rust modules remain
the initial home of security-critical protocol operations.
