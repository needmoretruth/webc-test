//! `webc-weft`: the Weft authoring front end — **earliest skeleton**.
//!
//! Weft is WEBC's decided application language (`docs/weft-language-plan.md`,
//! `docs/architecture.md`, `docs/adr/0014-contract-runtime.md`): a brace-style,
//! TypeScript-familiar surface with Rust-grade semantics that compiles
//! **off-chain to deterministic WebAssembly**. The permanent architectural
//! invariant it honors is that the chain runs only WASM — Weft is a *front end*
//! over the frozen contract ABI, **never a second VM or on-chain compiler**.
//!
//! # What this crate is (and is not, yet)
//!
//! This is the earliest walking skeleton of that front end: a small but **real**
//! compiler pipeline
//!
//! ```text
//!   source (.weft) → lex → parse → AST → sema → codegen → WAT → wasm bytes
//!                                                         └→ interface manifest
//! ```
//!
//! that produces a module the existing [`webc_vm`] engine runs and the
//! [`webc_chain`] runtime registers and invokes as an ordinary contract. It
//! deliberately implements only a tiny slice of the decided language — enough to
//! express a persistent counter / store-and-echo contract end-to-end — while
//! keeping the *shape* of the full design so later constructs (more types,
//! expressions, linear `Amount<T>`, generics, interfaces, editions) slot in
//! without a redesign.
//!
//! Two deliberate skeleton simplifications, each a documented extension point:
//! - **Codegen emits WAT text** and assembles it to wasm via the `wat` crate. The
//!   decided production backend lowers via the audited Rust framework and emits
//!   wasm directly; both produce the same engine-accepted artifact, so the front
//!   end (lex/parse/AST/sema/manifest) is unaffected by that swap.
//! - **Semantics are minimally checked.** The linear money-safety theorem, the
//!   full type system, and edition handling are future work; their seams (effect
//!   clauses, typed state, the manifest) are present now.
//!
//! Determinism is inherited end-to-end: the compiler is a pure function of its
//! source input, and the target engine is deterministic by construction.

#![forbid(unsafe_code)]

pub mod ast;
pub mod codegen;
pub mod error;
pub mod ir;
pub mod keys;
pub mod lexer;
pub mod manifest;
pub mod parser;
pub mod sema;
pub mod token;

pub use error::{Span, WeftError};
pub use manifest::InterfaceManifest;

use webc_crypto::Hash256;

/// Everything a deployer needs from one compiled `.weft` source.
///
/// The `wasm` bytes register as the chain's `WasmBytecode`; `footprint` feeds
/// `WasmContractManifest::new(.., footprint, ..)` verbatim (it is sorted and
/// de-duplicated, matching the chain's requirement); `manifest` is the
/// machine-readable interface for the catalog/agents; `wat` is the reference text
/// the skeleton assembled (useful for review and as a codegen oracle).
#[derive(Clone, Debug)]
pub struct Compiled {
    /// The deterministic wasm module the chain runs.
    pub wasm: Vec<u8>,
    /// The reference WAT the skeleton backend emitted before assembly.
    pub wat: String,
    /// The machine-readable interface manifest.
    pub manifest: InterfaceManifest,
    /// The contract's declared footprint (sorted, deduped state keys).
    pub footprint: Vec<Hash256>,
    /// The contract ABI version the module targets.
    pub abi_version: u32,
}

/// Compiles Weft source into a deployable artifact.
///
/// A pure function of `src`: `lex → parse → sema → codegen → assemble`, plus the
/// interface manifest. Fail-closed — an `Err` means nothing was emitted. Because
/// each stage is deterministic and the target engine is deterministic, the same
/// source always yields the same bytes (reproducible builds).
pub fn compile(src: &str) -> Result<Compiled, WeftError> {
    let tokens = lexer::lex(src)?;
    let ast = parser::parse(tokens)?;
    let module = sema::check(ast)?;
    let wat = codegen::lower(&module)?;
    let wasm = codegen::assemble(&wat)?;
    let manifest = manifest::build(&module, &wasm);
    let footprint = module.footprint();
    Ok(Compiled {
        abi_version: manifest.abi_version,
        wasm,
        wat,
        manifest,
        footprint,
    })
}
