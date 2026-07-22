//! The Weft abstract syntax tree (edition 1 subset).
//!
//! The parser produces this tree; [`crate::sema`] resolves and checks it into the
//! typed [`crate::ir::Module`] the backend consumes. Every node carries a
//! [`Span`] so a semantic diagnostic can point at the exact source. The `Ty`,
//! `Stmt`, and `Expr` enums are `#[non_exhaustive]`: future types, statements,
//! and expressions (more integer widths, `bool`, structs, `if`/`match`, linear
//! `Amount<T>`, …) are added as variants without disturbing existing arms — the
//! grammar's designed-in growth path.

use crate::error::Span;

/// A value paired with the source span it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spanned<T> {
    /// The wrapped value.
    pub value: T,
    /// Where in the source it appeared.
    pub span: Span,
}

impl<T> Spanned<T> {
    /// Pairs `value` with `span`.
    pub fn new(value: T, span: Span) -> Self {
        Self { value, span }
    }
}

/// A whole component — the unit of compilation (one file, one component).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    /// The component's name.
    pub name: Spanned<String>,
    /// The `vN` version / edition tag.
    pub version: u32,
    /// Leading `///` documentation.
    pub docs: Vec<String>,
    /// Declared persistent state fields.
    pub state: Vec<StateDecl>,
    /// Declared event types (parsed + manifested; codegen-deferred in edition 1).
    pub events: Vec<EventDecl>,
    /// Callable entrypoints.
    pub entries: Vec<Entry>,
}

/// One persistent state field: `state <name>: <type>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateDecl {
    /// The field name (also the manifest/effect key name).
    pub name: Spanned<String>,
    /// The field's declared type.
    pub ty: Ty,
    /// Leading `///` documentation.
    pub docs: Vec<String>,
}

/// A typed event declaration: `event <name> { <field>: <type>, ... }`.
///
/// Parsed and surfaced in the interface manifest; codegen is a no-op in edition 1
/// (the host has no event sink yet — see the extension notes in `codegen`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventDecl {
    /// The event's name.
    pub name: Spanned<String>,
    /// The event's payload fields.
    pub fields: Vec<Param>,
    /// Leading `///` documentation.
    pub docs: Vec<String>,
}

/// A callable entrypoint: `entry <name>(<params>) [reads ..] [writes ..] [-> ty] { .. }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The entrypoint name.
    pub name: Spanned<String>,
    /// Declared parameters (the skeleton wires at most one `bytes` param).
    pub params: Vec<Param>,
    /// The compiler-checked effect clauses (the source mirror of declared access).
    pub effects: Effects,
    /// The optional return type.
    pub ret: Option<Ty>,
    /// The statement body.
    pub body: Vec<Stmt>,
    /// Leading `///` documentation.
    pub docs: Vec<String>,
}

/// An entrypoint's declared effects: which state fields it reads and writes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Effects {
    /// State field names in the `reads` clause.
    pub reads: Vec<Spanned<String>>,
    /// State field names in the `writes` clause.
    pub writes: Vec<Spanned<String>>,
}

/// A named, typed binding (an entry/event parameter).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    /// The parameter name.
    pub name: Spanned<String>,
    /// The parameter type.
    pub ty: Ty,
}

/// A Weft type (edition 1 subset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ty {
    /// A 64-bit unsigned integer, stored as 8 little-endian bytes.
    U64,
    /// Opaque bounded bytes (the call input / an echoed value).
    Bytes,
}

/// A statement in an entry body.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stmt {
    /// `let <name> = <expr>;` — an immutable local binding.
    Let {
        /// The bound name.
        name: Spanned<String>,
        /// The bound expression.
        expr: Expr,
        /// The statement span.
        span: Span,
    },
    /// `<field> = <expr>;` — assign to a `writes` state field.
    Assign {
        /// The assigned state field name.
        target: Spanned<String>,
        /// The value expression.
        expr: Expr,
        /// The statement span.
        span: Span,
    },
    /// `emit <event> { <field>: <expr>, ... };` — parsed + manifested, codegen-deferred.
    Emit {
        /// The event name.
        event: Spanned<String>,
        /// The field initializers.
        fields: Vec<(Spanned<String>, Expr)>,
        /// The statement span.
        span: Span,
    },
    /// `return <expr>;` — submit the expression's bytes as the call output.
    Return {
        /// The returned expression.
        expr: Expr,
        /// The statement span.
        span: Span,
    },
}

/// An expression.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expr {
    /// A `u64` integer literal.
    Int(u64, Span),
    /// The `input` keyword — the call's input bytes.
    Input(Span),
    /// A reference to a state field or a local binding.
    Var(String, Span),
    /// A binary operation over `u64` operands.
    Bin {
        /// The operator.
        op: BinOp,
        /// The left operand.
        lhs: Box<Expr>,
        /// The right operand.
        rhs: Box<Expr>,
        /// The expression span.
        span: Span,
    },
}

impl Expr {
    /// The source span of this expression.
    pub fn span(&self) -> Span {
        match self {
            Expr::Int(_, span) | Expr::Input(span) | Expr::Var(_, span) => *span,
            Expr::Bin { span, .. } => *span,
        }
    }
}

/// A binary operator over `u64` (wrapping arithmetic in edition 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinOp {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
}
