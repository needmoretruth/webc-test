//! Static, pre-execution validation of a candidate contract module.
//!
//! Validation is layered and fails closed at every step:
//! 1. a hard byte-size cap, checked before any parsing;
//! 2. a streaming structural pass ([`wasmparser`]) that enforces the
//!    linear-memory page budget and rejects features that widen the host or
//!    nondeterminism surface (shared/threaded memory, 64-bit memory, custom page
//!    sizes, imported memories/tables/globals, imports from any module other than
//!    `"webc"`, and the component model);
//! 3. a full compile with the deterministic engine, which rejects floats, SIMD,
//!    atomics, bulk-memory, reference types, and anything else the engine does
//!    not recognize.
//!
//! Because step 3 uses the very same [`crate::engine`] configuration that
//! [`crate::execute`] runs with, acceptance here is a precise predicate for
//! executability.

use wasmi::{Engine, Module};
use wasmparser::{Encoding, Parser, Payload, TypeRef};

use crate::engine::deterministic_engine;
use crate::error::VmError;
use crate::limits::VmLimits;

/// The one host module a contract may import from.
pub(crate) const HOST_MODULE: &str = "webc";

/// Validates `bytes` as a deterministic WEBC contract module under `limits`.
///
/// Returns `Ok(())` if the module is safe to execute, or a typed [`VmError`]
/// describing the first violation found. Never panics on hostile input.
///
/// Acceptance here is a precise predicate for executability: it runs the exact
/// checks [`crate::execute`] applies before instantiation, including a compile
/// with the deterministic engine.
pub fn validate_module(bytes: &[u8], limits: &VmLimits) -> Result<(), VmError> {
    compile_checked(bytes, limits).map(|_| ())
}

/// Size-checks, structurally validates, and compiles `bytes` with the
/// deterministic engine, returning the engine and compiled module.
///
/// Shared by [`validate_module`] (which discards the result) and
/// [`crate::execute`] (which runs it), so validation and execution can never
/// disagree and the module is compiled exactly once per call.
pub(crate) fn compile_checked(
    bytes: &[u8],
    limits: &VmLimits,
) -> Result<(Engine, Module), VmError> {
    if bytes.len() > limits.max_module_bytes {
        return Err(VmError::ModuleTooLarge {
            actual: bytes.len(),
            max: limits.max_module_bytes,
        });
    }

    structural_pass(bytes, limits)?;

    // Full validation + translation with the deterministic engine. This is the
    // authoritative feature gate: floats, SIMD, atomics, bulk-memory, reference
    // types, tail calls, and extended-const all fail here.
    let engine = deterministic_engine();
    let module =
        Module::new(&engine, bytes).map_err(|err| VmError::InvalidModule(err.to_string()))?;

    Ok((engine, module))
}

/// Streaming structural checks that the engine's compile step does not cover
/// (page budget) or that we want to reject earlier and more explicitly
/// (threads/atomics, memory64, imported non-func externs, components).
fn structural_pass(bytes: &[u8], limits: &VmLimits) -> Result<(), VmError> {
    let mut memory_count: u32 = 0;

    for payload in Parser::new(0).parse_all(bytes) {
        let payload = payload.map_err(|err| VmError::InvalidModule(err.to_string()))?;
        match payload {
            Payload::Version { encoding, .. } => {
                if encoding != Encoding::Module {
                    return Err(VmError::InvalidModule(
                        "component model is not supported".to_string(),
                    ));
                }
            }
            Payload::MemorySection(reader) => {
                for mem in reader {
                    let mem = mem.map_err(|err| VmError::InvalidModule(err.to_string()))?;
                    memory_count += 1;
                    if memory_count > 1 {
                        return Err(VmError::InvalidModule(
                            "multiple linear memories are not supported".to_string(),
                        ));
                    }
                    if mem.shared {
                        return Err(VmError::InvalidModule(
                            "shared (threaded/atomic) memory is not supported".to_string(),
                        ));
                    }
                    if mem.memory64 {
                        return Err(VmError::InvalidModule(
                            "64-bit memory is not supported".to_string(),
                        ));
                    }
                    if mem.page_size_log2.is_some() {
                        return Err(VmError::InvalidModule(
                            "custom memory page sizes are not supported".to_string(),
                        ));
                    }
                    check_pages(mem.initial, limits)?;
                    if let Some(max) = mem.maximum {
                        check_pages(max, limits)?;
                    }
                }
            }
            Payload::ImportSection(reader) => {
                // In this wasmparser line the import section yields groups of
                // imports; each group flattens to individual `Import`s.
                for group in reader {
                    let group = group.map_err(|err| VmError::InvalidModule(err.to_string()))?;
                    for item in group {
                        let (_offset, import) =
                            item.map_err(|err| VmError::InvalidModule(err.to_string()))?;
                        if import.module != HOST_MODULE {
                            return Err(VmError::InvalidModule(format!(
                                "import from unknown module `{}`; only `{HOST_MODULE}` is permitted",
                                import.module
                            )));
                        }
                        match import.ty {
                            TypeRef::Func(_) => {}
                            TypeRef::Memory(_) => {
                                return Err(VmError::InvalidModule(
                                    "importing linear memory is not permitted".to_string(),
                                ));
                            }
                            TypeRef::Table(_) => {
                                return Err(VmError::InvalidModule(
                                    "importing tables is not permitted".to_string(),
                                ));
                            }
                            TypeRef::Global(_) => {
                                return Err(VmError::InvalidModule(
                                    "importing globals is not permitted".to_string(),
                                ));
                            }
                            TypeRef::Tag(_) | TypeRef::FuncExact(_) => {
                                return Err(VmError::InvalidModule(
                                    "unsupported import kind".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(())
}

/// Rejects a page count above the configured maximum.
fn check_pages(pages: u64, limits: &VmLimits) -> Result<(), VmError> {
    if pages > u64::from(limits.max_memory_pages) {
        return Err(VmError::MemoryLimitExceeded {
            pages,
            max: limits.max_memory_pages,
        });
    }
    Ok(())
}
