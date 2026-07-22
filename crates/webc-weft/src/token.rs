//! Lexical tokens.
//!
//! One flat token stream feeds the parser. Every token carries its source
//! [`Span`] so parse/sema diagnostics can point at the exact bytes. [`TokenKind`]
//! is `#[non_exhaustive]`: new keywords/punctuation are added as the language
//! grows (an extension point) without breaking exhaustive matches elsewhere in
//! the same edition build.

use crate::error::Span;

/// A lexed token: what it is, and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    /// What kind of token this is.
    pub kind: TokenKind,
    /// The source byte range this token spans.
    pub span: Span,
}

impl Token {
    /// Builds a token of `kind` spanning `[start, end)`.
    pub fn new(kind: TokenKind, start: usize, end: usize) -> Self {
        Self {
            kind,
            span: Span::new(start, end),
        }
    }
}

/// The lexical category of a [`Token`].
///
/// Keywords are recognized by the lexer (an identifier whose text matches a
/// reserved word becomes the keyword token), so the parser never string-compares
/// identifiers against keywords.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenKind {
    // ----- keywords -----
    /// `component`
    Component,
    /// `state`
    State,
    /// `event`
    Event,
    /// `entry`
    Entry,
    /// `reads`
    Reads,
    /// `writes`
    Writes,
    /// `let`
    Let,
    /// `return`
    Return,
    /// `emit`
    Emit,
    /// `input` — the call's input bytes, a keyword primary (not a function).
    Input,
    /// `u64` type keyword.
    U64,
    /// `bytes` type keyword.
    Bytes,

    // ----- names & literals -----
    /// An identifier (also used for the `vN` version token, validated in the parser).
    Ident(String),
    /// A decimal integer literal (the lexer rejects `.`/exponent, so no floats).
    Int(u64),
    /// A `///` documentation comment's text (trimmed of the leading `///`).
    Doc(String),

    // ----- punctuation -----
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `:`
    Colon,
    /// `;`
    Semi,
    /// `,`
    Comma,
    /// `=`
    Eq,
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `*`
    Star,
    /// `->`
    Arrow,

    /// End of input (always the final token).
    Eof,
}

impl TokenKind {
    /// Maps an identifier's text to its keyword kind, or `None` if it is an
    /// ordinary identifier. The single source of truth for the reserved-word set.
    pub fn keyword(text: &str) -> Option<TokenKind> {
        Some(match text {
            "component" => TokenKind::Component,
            "state" => TokenKind::State,
            "event" => TokenKind::Event,
            "entry" => TokenKind::Entry,
            "reads" => TokenKind::Reads,
            "writes" => TokenKind::Writes,
            "let" => TokenKind::Let,
            "return" => TokenKind::Return,
            "emit" => TokenKind::Emit,
            "input" => TokenKind::Input,
            "u64" => TokenKind::U64,
            "bytes" => TokenKind::Bytes,
            _ => return None,
        })
    }

    /// A short human label used in "expected X, found Y" parse diagnostics.
    pub fn label(&self) -> String {
        match self {
            TokenKind::Ident(name) => format!("identifier `{name}`"),
            TokenKind::Int(value) => format!("integer `{value}`"),
            TokenKind::Doc(_) => "doc comment".to_string(),
            TokenKind::Eof => "end of input".to_string(),
            other => format!("`{}`", other.punct_or_keyword()),
        }
    }

    /// The literal spelling of a keyword/punctuation kind (for diagnostics).
    fn punct_or_keyword(&self) -> &'static str {
        match self {
            TokenKind::Component => "component",
            TokenKind::State => "state",
            TokenKind::Event => "event",
            TokenKind::Entry => "entry",
            TokenKind::Reads => "reads",
            TokenKind::Writes => "writes",
            TokenKind::Let => "let",
            TokenKind::Return => "return",
            TokenKind::Emit => "emit",
            TokenKind::Input => "input",
            TokenKind::U64 => "u64",
            TokenKind::Bytes => "bytes",
            TokenKind::LBrace => "{",
            TokenKind::RBrace => "}",
            TokenKind::LParen => "(",
            TokenKind::RParen => ")",
            TokenKind::Colon => ":",
            TokenKind::Semi => ";",
            TokenKind::Comma => ",",
            TokenKind::Eq => "=",
            TokenKind::Plus => "+",
            TokenKind::Minus => "-",
            TokenKind::Star => "*",
            TokenKind::Arrow => "->",
            // Non-fixed-spelling kinds are handled by `label` before reaching here.
            _ => "token",
        }
    }
}
