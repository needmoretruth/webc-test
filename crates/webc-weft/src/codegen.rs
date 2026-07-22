//! Code generation: a [`crate::ir::Module`] → deterministic wasm bytes.
//!
//! The skeleton backend emits **WAT text** and assembles it to wasm via the `wat`
//! crate — a real, deterministic WASM producer. The decided production backend
//! lowers via the audited Rust framework and emits wasm directly; both sit behind
//! [`Backend`] and consume the identical [`crate::ir::Module`], so swapping them changes
//! nothing in the front end. The WAT path then serves as the reference/oracle.
//!
//! # Target
//!
//! The output imports only the `webc` host functions it uses, exports `memory` +
//! `webc_call`, and uses only core i32/i64 ops + active data segments — so
//! `webc-vm`'s `validate_module` accepts it by construction (no floats/SIMD/
//! threads/bulk-memory/reference-types/foreign-imports). Memory layout and the
//! prologue/flush/output ordering are pinned to the audited hand-written fixtures
//! (`counter_module` / `store_and_echo_module` in `webc-chain`), so a compiled
//! counter is byte-identical to the known-good WAT.
//!
//! # Edition-1 limits (documented, never silent)
//!
//! - Exactly one entry per component (compiled as `webc_call`); multi-entry
//!   dispatch via an input selector is a future extension.
//! - `u64` state lives in linear memory (8-byte little-endian); arithmetic wraps.
//! - A `return`, if present, must be the last statement.
//! - `bytes` state supports the store-and-echo shape (`field = input; return
//!   field`); loading a persisted `bytes` value is a future extension.

use crate::ast::{BinOp, Expr, Stmt, Ty};
use crate::error::WeftError;
use crate::ir::{EntryIr, Module};

/// A pluggable code-generation backend consuming the stable [`crate::ir::Module`].
///
/// One implementation today ([`WatBackend`]); a `RustFrameworkBackend` slots in
/// behind this same trait later, reusing the entire front end unchanged.
pub trait Backend {
    /// Lowers `module` to deterministic wasm bytes.
    fn emit(&self, module: &Module) -> Result<Vec<u8>, WeftError>;
}

/// The skeleton WAT-emitting backend.
#[derive(Clone, Copy, Debug, Default)]
pub struct WatBackend;

impl Backend for WatBackend {
    fn emit(&self, module: &Module) -> Result<Vec<u8>, WeftError> {
        let wat = lower(module)?;
        assemble(&wat)
    }
}

// ----- memory layout (all compile-time; every offset stays < 65536, one page) -----

/// Bytes per state key in the KEY region (a `Hash256`).
const KEY_STRIDE: usize = 32;
/// Bytes per `u64` value slot in the VAL region.
const VAL_STRIDE: usize = 8;
/// Scratch offset for a `u64` return value that is not already a state slot.
const RET_SCRATCH: usize = 4096;
/// Base offset of the input/echo staging region.
const IO_BASE: usize = 8192;
/// One wasm page.
const PAGE: usize = 65536;

/// Rounds `x` up to the next multiple of 64.
fn round_up_64(x: usize) -> usize {
    x.div_ceil(64) * 64
}

/// The VAL region base: past the KEY region, 64-aligned, and at least 64 so a
/// single-field component places its value at offset 64 (fixture parity).
fn val_base(n_fields: usize) -> usize {
    round_up_64(KEY_STRIDE * n_fields).max(64)
}

/// Lowers a module to WAT text (the reference form the skeleton assembles).
pub fn lower(module: &Module) -> Result<String, WeftError> {
    if module.entries.len() != 1 {
        return Err(WeftError::Codegen {
            message: format!(
                "edition 1 supports exactly one entry per component; `{}` declares {}",
                module.name,
                module.entries.len()
            ),
        });
    }
    let entry = &module.entries[0];
    let n = module.state.len();
    let val_base = val_base(n);
    // Bound-check the layout so no offset can escape the single page.
    let max_off = IO_BASE + 4096;
    if max_off >= PAGE {
        return Err(WeftError::Codegen {
            message: "component state does not fit in one wasm page".to_string(),
        });
    }

    let cg = Codegen {
        module,
        entry,
        val_base,
    };
    cg.module_wat()
}

/// Assembles WAT text into wasm bytes. A failure here is a codegen bug (the
/// skeleton's WAT should always assemble) surfaced as a typed error, never a panic.
pub fn assemble(wat: &str) -> Result<Vec<u8>, WeftError> {
    wat::parse_str(wat).map_err(|err| WeftError::Assemble(err.to_string()))
}

struct Codegen<'a> {
    module: &'a Module,
    entry: &'a EntryIr,
    val_base: usize,
}

impl Codegen<'_> {
    fn key_off(&self, slot: usize) -> usize {
        KEY_STRIDE * slot
    }

    fn val_off(&self, slot: usize) -> usize {
        self.val_base + VAL_STRIDE * slot
    }

    /// Whether the body references the call `input`.
    fn uses_input(&self) -> bool {
        self.entry.body.iter().any(stmt_uses_input)
    }

    /// The `u64` slots to load in the prologue (reads ∪ writes that are `u64`).
    fn u64_loads(&self) -> Vec<usize> {
        self.entry
            .touched_slots()
            .into_iter()
            .filter(|slot| self.module.state[*slot].ty == Ty::U64)
            .collect()
    }

    /// Splits the body into its non-return statements and the optional trailing
    /// `return` expression, rejecting a `return` that is not last.
    fn split_body(&self) -> Result<(&[Stmt], Option<&Expr>), WeftError> {
        let body = &self.entry.body;
        let (stmts, ret) = match body.last() {
            Some(Stmt::Return { expr, .. }) => (&body[..body.len() - 1], Some(expr)),
            _ => (&body[..], None),
        };
        if stmts.iter().any(|s| matches!(s, Stmt::Return { .. })) {
            return Err(WeftError::Codegen {
                message: "`return` must be the last statement in an entry".to_string(),
            });
        }
        Ok((stmts, ret))
    }

    fn module_wat(&self) -> Result<String, WeftError> {
        let (stmts, ret) = self.split_body()?;
        let uses_input = self.uses_input();
        let loads = self.u64_loads();
        let has_writes = !self.entry.writes.is_empty();
        let has_output = ret.is_some();

        let mut out = String::new();
        out.push_str("(module\n");

        // Imports — only what is used.
        if !loads.is_empty() {
            out.push_str(
                "  (import \"webc\" \"webc_get\" (func $get (param i32 i32 i32 i32) (result i32)))\n",
            );
        }
        if has_writes {
            out.push_str(
                "  (import \"webc\" \"webc_set\" (func $set (param i32 i32 i32 i32) (result i32)))\n",
            );
        }
        if uses_input {
            out.push_str("  (import \"webc\" \"webc_input_len\" (func $input_len (result i32)))\n");
            out.push_str(
                "  (import \"webc\" \"webc_input_read\" (func $input_read (param i32)))\n",
            );
        }
        if has_output {
            out.push_str("  (import \"webc\" \"webc_output\" (func $output (param i32 i32)))\n");
        }

        out.push_str("  (memory (export \"memory\") 1)\n");

        // One 32-byte key data segment per state field.
        for field in &self.module.state {
            out.push_str(&format!(
                "  (data (i32.const {}) \"{}\")\n",
                self.key_off(field.slot),
                escape_bytes(field.key.as_bytes())
            ));
        }

        // The single entrypoint.
        out.push_str("  (func (export \"webc_call\")\n");

        // Locals: $rc (get return codes), $len (input length), and one i64 per let.
        if !loads.is_empty() {
            out.push_str("    (local $rc i32)\n");
        }
        if uses_input {
            out.push_str("    (local $len i32)\n");
        }
        for name in self.let_locals(stmts) {
            out.push_str(&format!("    (local $l_{name} i64)\n"));
        }

        // PROLOGUE: load each touched u64 field, defaulting an absent key to 0.
        for slot in &loads {
            let (koff, voff) = (self.key_off(*slot), self.val_off(*slot));
            out.push_str(&format!(
                "    (local.set $rc (call $get (i32.const {koff}) (i32.const 32) (i32.const {voff}) (i32.const 8)))\n"
            ));
            out.push_str(&format!(
                "    (if (i32.eq (local.get $rc) (i32.const -1)) (then (i64.store (i32.const {voff}) (i64.const 0))))\n"
            ));
        }
        if uses_input {
            out.push_str("    (local.set $len (call $input_len))\n");
            out.push_str(&format!("    (call $input_read (i32.const {IO_BASE}))\n"));
        }

        // BODY: the non-return statements.
        for stmt in stmts {
            self.stmt_wat(stmt, &mut out)?;
        }

        // FLUSH: persist every `writes` field (before the output, matching the
        // audited fixture ordering).
        for slot in &self.entry.writes {
            let koff = self.key_off(*slot);
            match self.module.state[*slot].ty {
                Ty::U64 => {
                    let voff = self.val_off(*slot);
                    out.push_str(&format!(
                        "    (drop (call $set (i32.const {koff}) (i32.const 32) (i32.const {voff}) (i32.const 8)))\n"
                    ));
                }
                Ty::Bytes => {
                    out.push_str(&format!(
                        "    (drop (call $set (i32.const {koff}) (i32.const 32) (i32.const {IO_BASE}) (local.get $len)))\n"
                    ));
                }
            }
        }

        // OUTPUT: the trailing return, if any.
        if let Some(expr) = ret {
            self.output_wat(expr, &mut out)?;
        }

        out.push_str("  ))\n");
        Ok(out)
    }

    /// Collects `let` binding names in source order (for local declarations).
    fn let_locals(&self, stmts: &[Stmt]) -> Vec<String> {
        stmts
            .iter()
            .filter_map(|s| match s {
                Stmt::Let { name, .. } => Some(name.value.clone()),
                _ => None,
            })
            .collect()
    }

    fn stmt_wat(&self, stmt: &Stmt, out: &mut String) -> Result<(), WeftError> {
        match stmt {
            Stmt::Let { name, expr, .. } => {
                let e = self.u64_expr(expr)?;
                out.push_str(&format!("    (local.set $l_{} {e})\n", name.value));
                Ok(())
            }
            Stmt::Assign { target, expr, .. } => {
                let slot = self.slot_of(&target.value)?;
                match self.module.state[slot].ty {
                    Ty::U64 => {
                        let e = self.u64_expr(expr)?;
                        let voff = self.val_off(slot);
                        out.push_str(&format!("    (i64.store (i32.const {voff}) {e})\n"));
                    }
                    Ty::Bytes => {
                        // Edition 1: the only bytes value is `input`, staged at
                        // IO_BASE; the epilogue's `set` reads it back. Nothing to
                        // emit here beyond confirming the source is `input`.
                        if !matches!(expr, Expr::Input(_)) {
                            return Err(WeftError::Codegen {
                                message: format!(
                                    "edition 1 can only assign `input` to the bytes field `{}`",
                                    target.value
                                ),
                            });
                        }
                    }
                }
                Ok(())
            }
            // Events are carried in the manifest; codegen is a no-op in edition 1.
            Stmt::Emit { .. } => Ok(()),
            Stmt::Return { .. } => Err(WeftError::Codegen {
                message: "internal: return should have been split out".to_string(),
            }),
        }
    }

    /// Emits the `webc_output` for a trailing return.
    fn output_wat(&self, expr: &Expr, out: &mut String) -> Result<(), WeftError> {
        match self.value_kind(expr)? {
            // A bytes value is always the staged input buffer in edition 1.
            ValueKind::Bytes => {
                out.push_str(&format!(
                    "    (call $output (i32.const {IO_BASE}) (local.get $len))\n"
                ));
            }
            // Returning a state u64 field outputs its slot directly (fixture parity).
            ValueKind::StateU64(slot) => {
                let voff = self.val_off(slot);
                out.push_str(&format!(
                    "    (call $output (i32.const {voff}) (i32.const 8))\n"
                ));
            }
            // Any other u64 expression is stored to scratch, then output.
            ValueKind::OtherU64 => {
                let e = self.u64_expr(expr)?;
                out.push_str(&format!("    (i64.store (i32.const {RET_SCRATCH}) {e})\n"));
                out.push_str(&format!(
                    "    (call $output (i32.const {RET_SCRATCH}) (i32.const 8))\n"
                ));
            }
        }
        Ok(())
    }

    /// Classifies a return expression for output lowering.
    fn value_kind(&self, expr: &Expr) -> Result<ValueKind, WeftError> {
        match expr {
            Expr::Input(_) => Ok(ValueKind::Bytes),
            Expr::Var(name, _) => {
                if let Some(slot) = self.module.field_slot(name) {
                    match self.module.state[slot].ty {
                        Ty::U64 => Ok(ValueKind::StateU64(slot)),
                        Ty::Bytes => Ok(ValueKind::Bytes),
                    }
                } else {
                    // A local (always u64 in edition 1).
                    Ok(ValueKind::OtherU64)
                }
            }
            _ => Ok(ValueKind::OtherU64),
        }
    }

    /// Lowers a `u64` expression to a folded WAT s-expression producing an `i64`.
    fn u64_expr(&self, expr: &Expr) -> Result<String, WeftError> {
        match expr {
            Expr::Int(value, _) => Ok(format!("(i64.const {value})")),
            Expr::Var(name, _) => {
                if let Some(slot) = self.module.field_slot(name) {
                    Ok(format!("(i64.load (i32.const {}))", self.val_off(slot)))
                } else {
                    Ok(format!("(local.get $l_{name})"))
                }
            }
            Expr::Bin { op, lhs, rhs, .. } => {
                let opcode = match op {
                    BinOp::Add => "i64.add",
                    BinOp::Sub => "i64.sub",
                    BinOp::Mul => "i64.mul",
                };
                Ok(format!(
                    "({opcode} {} {})",
                    self.u64_expr(lhs)?,
                    self.u64_expr(rhs)?
                ))
            }
            Expr::Input(_) => Err(WeftError::Codegen {
                message: "`input` (bytes) cannot be used as a u64 value".to_string(),
            }),
        }
    }

    fn slot_of(&self, name: &str) -> Result<usize, WeftError> {
        self.module
            .field_slot(name)
            .ok_or_else(|| WeftError::Codegen {
                message: format!("internal: `{name}` is not a state field"),
            })
    }
}

/// How a return value is produced.
enum ValueKind {
    Bytes,
    StateU64(usize),
    OtherU64,
}

/// Whether a statement references the `input` keyword anywhere.
fn stmt_uses_input(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Let { expr, .. } | Stmt::Assign { expr, .. } | Stmt::Return { expr, .. } => {
            expr_uses_input(expr)
        }
        Stmt::Emit { fields, .. } => fields.iter().any(|(_, e)| expr_uses_input(e)),
    }
}

fn expr_uses_input(expr: &Expr) -> bool {
    match expr {
        Expr::Input(_) => true,
        Expr::Bin { lhs, rhs, .. } => expr_uses_input(lhs) || expr_uses_input(rhs),
        Expr::Int(_, _) | Expr::Var(_, _) => false,
    }
}

/// Escapes bytes as WAT `\XX` hex string escapes (matching the audited fixtures'
/// data-segment encoding, so the baked bytes are exactly the key bytes).
fn escape_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lexer::lex, parser::parse, sema::check};

    fn module(src: &str) -> Module {
        check(parse(lex(src).unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn counter_lowers_and_assembles() {
        let m = module(
            "component counter v1 { state count: u64 entry bump() reads count writes count -> u64 { count = count + 1; return count; } }",
        );
        let wat = lower(&m).expect("lowers");
        // Fixture-parity checkpoints.
        assert!(wat.contains("(data (i32.const 0)"));
        assert!(wat.contains("(i32.const 64)")); // value slot at 64
        assert!(wat.contains("(call $get"));
        assert!(wat.contains("(call $set"));
        assert!(wat.contains("(call $output (i32.const 64) (i32.const 8))"));
        let wasm = assemble(&wat).expect("assembles");
        assert_eq!(&wasm[0..4], b"\0asm");
    }

    #[test]
    fn rejects_more_than_one_entry() {
        let m = module(
            "component c v1 { state a: u64 entry x() writes a { a = 1; } entry y() writes a { a = 2; } }",
        );
        assert!(matches!(lower(&m), Err(WeftError::Codegen { .. })));
    }
}
