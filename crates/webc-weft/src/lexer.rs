//! The lexer: source text → a flat [`Token`] stream.
//!
//! A single forward byte scan. Whitespace and `//` line comments are skipped;
//! `///` doc comments are captured (they attach to the following declaration).
//! Identifiers whose text is a reserved word become keyword tokens
//! ([`TokenKind::keyword`]). A `.` or exponent inside a number is rejected here,
//! so no floating-point literal can ever reach later stages. Every failure is a
//! typed [`WeftError::Lex`] with the offending span — the lexer never panics.

use crate::error::{Span, WeftError};
use crate::token::{Token, TokenKind};

/// Tokenizes `src`, always ending with a single [`TokenKind::Eof`] token.
pub fn lex(src: &str) -> Result<Vec<Token>, WeftError> {
    let bytes = src.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];

        // Whitespace.
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // Comments: `///` doc (captured) vs `//` line (skipped).
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            let is_doc = i + 2 < bytes.len() && bytes[i + 2] == b'/';
            let start = i;
            let mut j = i + 2;
            while j < bytes.len() && bytes[j] != b'\n' {
                j += 1;
            }
            if is_doc {
                // Text after `///`, trimmed of surrounding spaces.
                let text = src[start + 3..j].trim().to_string();
                tokens.push(Token::new(TokenKind::Doc(text), start, j));
            }
            i = j;
            continue;
        }

        // Punctuation, including the two-byte `->`.
        if let Some((kind, len)) = punct(bytes, i) {
            tokens.push(Token::new(kind, i, i + len));
            i += len;
            continue;
        }

        // Identifiers / keywords: ALPHA (ALPHANUM | '_')* .
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            let text = &src[start..j];
            let kind =
                TokenKind::keyword(text).unwrap_or_else(|| TokenKind::Ident(text.to_string()));
            tokens.push(Token::new(kind, start, j));
            i = j;
            continue;
        }

        // Decimal integer literals. A following `.` or exponent is a hard error
        // (no floats in Weft), rather than being silently split into two tokens.
        if b.is_ascii_digit() {
            let start = i;
            let mut j = i + 1;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b'.' || bytes[j] == b'e' || bytes[j] == b'E') {
                return Err(WeftError::Lex {
                    span: Span::new(start, j + 1),
                    message: "floating-point and scientific-notation literals are not allowed in \
                              Weft; use integer arithmetic"
                        .to_string(),
                });
            }
            let text = &src[start..j];
            let value = text.parse::<u64>().map_err(|_| WeftError::Lex {
                span: Span::new(start, j),
                message: format!("integer literal `{text}` does not fit in u64"),
            })?;
            tokens.push(Token::new(TokenKind::Int(value), start, j));
            i = j;
            continue;
        }

        // Anything else is an unrecognized byte.
        return Err(WeftError::Lex {
            span: Span::new(i, i + 1),
            message: format!("unexpected character `{}`", b as char),
        });
    }

    tokens.push(Token::new(TokenKind::Eof, bytes.len(), bytes.len()));
    Ok(tokens)
}

/// Recognizes a punctuation token starting at `i`, returning its kind and byte
/// length. `->` (two bytes) is checked before `-`.
fn punct(bytes: &[u8], i: usize) -> Option<(TokenKind, usize)> {
    // Two-byte punctuation first.
    if bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'>' {
        return Some((TokenKind::Arrow, 2));
    }
    let kind = match bytes[i] {
        b'{' => TokenKind::LBrace,
        b'}' => TokenKind::RBrace,
        b'(' => TokenKind::LParen,
        b')' => TokenKind::RParen,
        b':' => TokenKind::Colon,
        b';' => TokenKind::Semi,
        b',' => TokenKind::Comma,
        b'=' => TokenKind::Eq,
        b'+' => TokenKind::Plus,
        b'-' => TokenKind::Minus,
        b'*' => TokenKind::Star,
        _ => return None,
    };
    Some((kind, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokenKind> {
        lex(src).unwrap().into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn lexes_keywords_idents_ints_and_punct() {
        let k = kinds("component counter v1 { state count : u64 = 5 + 1 ; }");
        assert_eq!(k[0], TokenKind::Component);
        assert_eq!(k[1], TokenKind::Ident("counter".into()));
        assert_eq!(k[2], TokenKind::Ident("v1".into()));
        assert!(k.contains(&TokenKind::State));
        assert!(k.contains(&TokenKind::U64));
        assert!(k.contains(&TokenKind::Int(5)));
        assert_eq!(*k.last().unwrap(), TokenKind::Eof);
    }

    #[test]
    fn captures_doc_skips_line_comment() {
        let k = kinds("/// hello\n// skip me\nstate");
        assert_eq!(k[0], TokenKind::Doc("hello".into()));
        assert_eq!(k[1], TokenKind::State);
    }

    #[test]
    fn lexes_arrow_distinct_from_minus() {
        assert_eq!(kinds("->")[0], TokenKind::Arrow);
        assert_eq!(kinds("-")[0], TokenKind::Minus);
    }

    #[test]
    fn rejects_float_literal() {
        assert!(matches!(lex("1.5"), Err(WeftError::Lex { .. })));
        assert!(matches!(lex("2e3"), Err(WeftError::Lex { .. })));
    }

    #[test]
    fn rejects_unknown_byte() {
        assert!(matches!(lex("@"), Err(WeftError::Lex { .. })));
    }
}
