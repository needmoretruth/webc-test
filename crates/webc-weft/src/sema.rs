//! Semantic analysis: a [`crate::ast::Component`] → a resolved, checked
//! [`crate::ir::Module`].
//!
//! Edition-1 scope, but a real (not cosmetic) check. It:
//! - assigns each state field its derived key ([`crate::keys::state_key`]) and its
//!   declaration-order memory slot, rejecting duplicate field names;
//! - resolves each entry's `reads`/`writes` clauses to state-field slots (a clause
//!   naming a non-field is an error) — the source-level mirror of the chain's
//!   declared access;
//! - type-checks every statement and expression (u64 arithmetic is closed; a state
//!   read requires the field to be declared in `reads`/`writes`; an assignment
//!   target must be a `writes` field; a `return` must match the declared type);
//! - runs a **no-op linear/money-safety pass** (`linear_check`) — the seam where
//!   the decided `Amount<T>` linear-value theorem is enforced later, wired into the
//!   pipeline now so turning it on touches nothing upstream or downstream.
//!
//! Fail-closed: the first violation returns a typed [`WeftError::Sema`] with a
//! span. No panic on any well-formed-but-invalid program.

use std::collections::BTreeMap;

use crate::ast::{Component, Expr, Spanned, Stmt, Ty};
use crate::error::{Span, WeftError};
use crate::ir::{EntryIr, Field, Module};
use crate::keys::state_key;

/// Checks and lowers a parsed component into the backend-ready [`crate::ir::Module`].
pub fn check(component: Component) -> Result<Module, WeftError> {
    // ----- state fields: unique names, derived keys, declaration-order slots -----
    let mut state: Vec<Field> = Vec::with_capacity(component.state.len());
    let mut by_name: BTreeMap<String, usize> = BTreeMap::new();
    for (slot, decl) in component.state.iter().enumerate() {
        if by_name.contains_key(&decl.name.value) {
            return Err(sema(
                decl.name.span,
                format!("duplicate state field `{}`", decl.name.value),
            ));
        }
        by_name.insert(decl.name.value.clone(), slot);
        state.push(Field {
            name: decl.name.value.clone(),
            ty: decl.ty,
            key: state_key(&component.name.value, &decl.name.value),
            slot,
        });
    }

    // ----- events: unique names (payload types are already well-formed) -----
    let mut event_names: BTreeMap<String, ()> = BTreeMap::new();
    for event in &component.events {
        if event_names.insert(event.name.value.clone(), ()).is_some() {
            return Err(sema(
                event.name.span,
                format!("duplicate event `{}`", event.name.value),
            ));
        }
    }

    // ----- entries -----
    let mut entries = Vec::with_capacity(component.entries.len());
    for entry in &component.entries {
        let reads = resolve_effect(&entry.effects.reads, &by_name)?;
        let writes = resolve_effect(&entry.effects.writes, &by_name)?;
        let readable: Vec<usize> = reads.iter().chain(&writes).copied().collect();

        let checker = BodyChecker {
            component: &component,
            state: &state,
            by_name: &by_name,
            readable: &readable,
            writes: &writes,
            ret: entry.ret,
        };
        checker.check_body(&entry.body)?;
        linear_check(&entry.body);

        entries.push(EntryIr {
            name: entry.name.value.clone(),
            params: entry.params.clone(),
            ret: entry.ret,
            reads,
            writes,
            body: entry.body.clone(),
            docs: entry.docs.clone(),
        });
    }

    Ok(Module {
        name: component.name.value,
        version: component.version,
        docs: component.docs,
        state,
        entries,
        events: component.events,
    })
}

/// Resolves a `reads`/`writes` clause to state-field slot indices, rejecting a
/// name that is not a declared state field.
fn resolve_effect(
    names: &[Spanned<String>],
    by_name: &BTreeMap<String, usize>,
) -> Result<Vec<usize>, WeftError> {
    let mut slots = Vec::with_capacity(names.len());
    for name in names {
        match by_name.get(&name.value) {
            Some(slot) => slots.push(*slot),
            None => {
                return Err(sema(
                    name.span,
                    format!(
                        "effect clause names `{}`, which is not a state field",
                        name.value
                    ),
                ))
            }
        }
    }
    Ok(slots)
}

/// The no-op linear/money-safety pass. Edition 1 has no `Amount<T>` type, so there
/// is nothing to check; this exists to fix the pipeline stage now, so enabling the
/// linear theorem later (deposit/return/burn on every path) is a change confined
/// entirely to this function.
fn linear_check(_body: &[Stmt]) {
    // Intentionally empty — see the module docs. When `Ty::Amount(..)` lands, this
    // becomes the move/consume tracker; no caller changes.
}

/// Per-entry body type/effect checker over a small local-variable environment.
struct BodyChecker<'a> {
    component: &'a Component,
    state: &'a [Field],
    by_name: &'a BTreeMap<String, usize>,
    /// Slots readable in this entry (its reads ∪ writes).
    readable: &'a [usize],
    /// Slots writable in this entry (its writes clause).
    writes: &'a [usize],
    /// The entry's declared return type, if any.
    ret: Option<Ty>,
}

impl BodyChecker<'_> {
    fn check_body(&self, body: &[Stmt]) -> Result<(), WeftError> {
        // Locals accumulate as `let`s are seen (declared before use, no shadowing
        // of a state field or an existing local).
        let mut locals: BTreeMap<String, Ty> = BTreeMap::new();
        for stmt in body {
            self.check_stmt(stmt, &mut locals)?;
        }
        Ok(())
    }

    fn check_stmt(&self, stmt: &Stmt, locals: &mut BTreeMap<String, Ty>) -> Result<(), WeftError> {
        match stmt {
            Stmt::Let { name, expr, .. } => {
                if self.by_name.contains_key(&name.value) || locals.contains_key(&name.value) {
                    return Err(sema(
                        name.span,
                        format!("`{}` is already a state field or local", name.value),
                    ));
                }
                let ty = self.expr_type(expr, locals)?;
                locals.insert(name.value.clone(), ty);
                Ok(())
            }
            Stmt::Assign { target, expr, .. } => {
                let slot = match self.by_name.get(&target.value) {
                    Some(slot) => *slot,
                    None => {
                        return Err(sema(
                            target.span,
                            format!("cannot assign `{}`: not a state field", target.value),
                        ))
                    }
                };
                if !self.writes.contains(&slot) {
                    return Err(sema(
                        target.span,
                        format!(
                            "`{}` is assigned but not in the entry's `writes` clause",
                            target.value
                        ),
                    ));
                }
                let want = self.state[slot].ty;
                let got = self.expr_type(expr, locals)?;
                self.expect_ty(want, got, expr.span())?;
                Ok(())
            }
            Stmt::Return { expr, span } => {
                let got = self.expr_type(expr, locals)?;
                match self.ret {
                    Some(want) => self.expect_ty(want, got, expr.span()),
                    None => Err(sema(
                        *span,
                        "`return` in an entry that declares no return type".to_string(),
                    )),
                }
            }
            Stmt::Emit {
                event,
                fields,
                span,
            } => {
                // Edition 1: type-checked and carried into the manifest; codegen is a
                // no-op (the host has no event sink yet).
                let decl = self
                    .component
                    .events
                    .iter()
                    .find(|e| e.name.value == event.value)
                    .ok_or_else(|| sema(event.span, format!("unknown event `{}`", event.value)))?;
                for (fname, fexpr) in fields {
                    let field = decl
                        .fields
                        .iter()
                        .find(|p| p.name.value == fname.value)
                        .ok_or_else(|| {
                            sema(
                                fname.span,
                                format!("event `{}` has no field `{}`", event.value, fname.value),
                            )
                        })?;
                    let got = self.expr_type(fexpr, locals)?;
                    self.expect_ty(field.ty, got, fexpr.span())?;
                }
                let _ = span;
                Ok(())
            }
        }
    }

    /// Computes an expression's type, checking every referenced name is in scope.
    fn expr_type(&self, expr: &Expr, locals: &BTreeMap<String, Ty>) -> Result<Ty, WeftError> {
        match expr {
            Expr::Int(_, _) => Ok(Ty::U64),
            Expr::Input(_) => Ok(Ty::Bytes),
            Expr::Var(name, span) => {
                if let Some(ty) = locals.get(name) {
                    return Ok(*ty);
                }
                if let Some(slot) = self.by_name.get(name) {
                    if !self.readable.contains(slot) {
                        return Err(sema(
                            *span,
                            format!(
                                "state field `{name}` is read but not in the entry's \
                                 `reads`/`writes` clause"
                            ),
                        ));
                    }
                    return Ok(self.state[*slot].ty);
                }
                Err(sema(*span, format!("unknown name `{name}`")))
            }
            Expr::Bin { lhs, rhs, span, .. } => {
                let lt = self.expr_type(lhs, locals)?;
                let rt = self.expr_type(rhs, locals)?;
                if lt != Ty::U64 || rt != Ty::U64 {
                    return Err(sema(
                        *span,
                        "arithmetic operands must both be `u64`".to_string(),
                    ));
                }
                Ok(Ty::U64)
            }
        }
    }

    fn expect_ty(&self, want: Ty, got: Ty, span: Span) -> Result<(), WeftError> {
        if want == got {
            Ok(())
        } else {
            Err(sema(
                span,
                format!("type mismatch: expected {want:?}, found {got:?}"),
            ))
        }
    }
}

/// Builds a [`WeftError::Sema`] at `span`.
fn sema(span: Span, message: String) -> WeftError {
    WeftError::Sema { span, message }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;
    use crate::parser::parse;

    fn check_src(src: &str) -> Result<Module, WeftError> {
        check(parse(lex(src).unwrap()).unwrap())
    }

    #[test]
    fn checks_the_counter_and_keys_it() {
        let m = check_src(
            "component counter v1 { state count: u64 entry bump() reads count writes count -> u64 { count = count + 1; return count; } }",
        )
        .expect("counter checks");
        assert_eq!(m.state.len(), 1);
        assert_eq!(m.state[0].key, state_key("counter", "count"));
        assert_eq!(m.entries[0].writes, vec![0]);
        assert_eq!(m.footprint(), vec![state_key("counter", "count")]);
    }

    #[test]
    fn rejects_write_outside_writes_clause() {
        let e = check_src(
            "component c v1 { state a: u64 entry e() reads a -> u64 { a = 1; return a; } }",
        )
        .unwrap_err();
        assert!(matches!(e, WeftError::Sema { .. }));
    }

    #[test]
    fn rejects_read_outside_effects_and_unknown_name() {
        assert!(matches!(
            check_src("component c v1 { state a: u64 entry e() -> u64 { return a; } }"),
            Err(WeftError::Sema { .. })
        ));
        assert!(matches!(
            check_src("component c v1 { state a: u64 entry e() writes a { a = zzz; } }"),
            Err(WeftError::Sema { .. })
        ));
    }

    #[test]
    fn rejects_type_mismatch_and_duplicate_field() {
        // Assigning bytes `input` to a u64 field.
        assert!(matches!(
            check_src("component c v1 { state a: u64 entry e() writes a { a = input; } }"),
            Err(WeftError::Sema { .. })
        ));
        assert!(matches!(
            check_src("component c v1 { state a: u64 state a: u64 entry e() writes a { a = 1; } }"),
            Err(WeftError::Sema { .. })
        ));
    }

    #[test]
    fn checks_event_and_emit() {
        let m = check_src(
            "component c v1 { state a: u64 event Bumped { value: u64 } entry e() reads a writes a -> u64 { a = a + 1; emit Bumped { value: a }; return a; } }",
        )
        .expect("emit checks");
        assert_eq!(m.events.len(), 1);
    }
}
