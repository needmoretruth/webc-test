# ADR-0006: evidence-based contract runtime selection

Status: accepted evaluation process; no runtime selected

Restricted WASM/Rust, Move VM, and EVM candidates implement identical reference
applications. Each must provide deterministic resource limits, enforced state
access, stable TypeScript clients, sandboxing, and a versioned ABI.

Only the candidate that passes security gates and wins the published benchmark
scorecard is enabled. Other runtimes stay disabled. Native Rust modules remain
the initial home of security-critical protocol operations.

## Off-chain contract-compilation invariant (§4.4)

Independent of which runtime wins, one invariant holds for every candidate:
**only the compiled, deterministic contract artifact is consensus input; source
compilation happens off chain.** The chain commits to a hash of the exact
deployed bytecode/module and its versioned ABI; it never compiles source, reads
a filesystem, or fetches a toolchain inside a state transition (the same
no-I/O / no-clock / no-RNG discipline every WEBC state transition already
follows). A verifier reproduces a deployment by compiling the published source
with the pinned toolchain off chain and checking the artifact hash matches the
on-chain commitment — the same commit-hash-on-chain / content-off-chain rule the
project uses for object payloads and agent receipts. This keeps consensus free
of compiler nondeterminism and supply-chain surface, and is a hard requirement of
the Phase-7 contract-runtime gate, not a per-runtime detail.
