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

pub mod error;

pub use error::{Span, WeftError};
