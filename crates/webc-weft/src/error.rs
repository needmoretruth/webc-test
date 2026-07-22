//! Typed compiler diagnostics for Weft.
//!
//! Every failure the front end can produce is one typed [`WeftError`] carrying a
//! source [`Span`], so a diagnostic can point at the exact offending bytes. This
//! is the seam the decided design's "error-driven convergence" (machine-parseable
//! fix suggestions consumed by humans and AI authors) grows from — the skeleton
//! carries the position and a message; richer structured suggestions slot in as a
//! future field without changing call sites. No compilation failure ever panics.

use thiserror::Error;

/// A half-open byte range `[start, end)` into the compiled source text.
///
/// Byte offsets (not line/column) keep the lexer/parser cheap; a diagnostic
/// renderer can map an offset back to line/column against the original source.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Span {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl Span {
    /// An empty span at the given offset, used when a precise range is unknown
    /// (e.g. an unexpected end of input).
    pub const fn point(at: usize) -> Self {
        Self { start: at, end: at }
    }

    /// A span covering `[start, end)`.
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

/// A Weft compilation error, tagged by the pipeline stage that produced it.
///
/// Kept `Clone`/`PartialEq` so tests can assert on exact diagnostics and a future
/// LSP can deduplicate them. Each variant carries a [`Span`] (except the final
/// assembly step, which operates on generated WAT rather than user source).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum WeftError {
    /// The lexer hit a byte or token it does not recognize.
    #[error("lex error at bytes {}..{}: {message}", span.start, span.end)]
    Lex {
        /// Where in the source the offending bytes are.
        span: Span,
        /// Human- and machine-readable explanation.
        message: String,
    },
    /// The parser saw a token sequence the grammar does not accept.
    #[error("parse error at bytes {}..{}: {message}", span.start, span.end)]
    Parse {
        /// Where in the source the offending tokens are.
        span: Span,
        /// Human- and machine-readable explanation.
        message: String,
    },
    /// A semantic rule was violated (an undeclared field, an effect clause that
    /// names a non-existent state field, a duplicate declaration, …).
    #[error("semantic error at bytes {}..{}: {message}", span.start, span.end)]
    Sema {
        /// Where in the source the offending construct is.
        span: Span,
        /// Human- and machine-readable explanation.
        message: String,
    },
    /// The code generator could not lower a well-formed AST (a skeleton
    /// limitation reached, e.g. a construct not yet supported by the backend).
    #[error("codegen error: {message}")]
    Codegen {
        /// Human- and machine-readable explanation.
        message: String,
    },
    /// The emitted WAT could not be assembled into wasm bytes. This indicates a
    /// codegen bug (the skeleton's WAT should always assemble), surfaced rather
    /// than panicked.
    #[error("wasm assembly failed: {0}")]
    Assemble(String),
}

impl WeftError {
    /// The source span this error points at, if any (assembly errors have none).
    pub fn span(&self) -> Option<Span> {
        match self {
            WeftError::Lex { span, .. }
            | WeftError::Parse { span, .. }
            | WeftError::Sema { span, .. } => Some(*span),
            WeftError::Codegen { .. } | WeftError::Assemble(_) => None,
        }
    }
}
