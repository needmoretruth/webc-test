//! The parser: a [`Token`] stream → an [`ast::Component`].
//!
//! Straightforward recursive descent, one function per grammar production, so the
//! code reads like the EBNF in `docs/` and a new production is a new method. Every
//! failure is a typed [`WeftError::Parse`] carrying the offending span; the parser
//! never panics and never consumes past [`TokenKind::Eof`]. Doc comments (`///`)
//! encountered before a declaration attach to it.

use crate::ast::{
    BinOp, Component, Effects, Entry, EventDecl, Expr, Param, Spanned, StateDecl, Stmt, Ty,
};
use crate::error::{Span, WeftError};
use crate::token::{Token, TokenKind};

/// Parses a full component from `tokens` (as produced by [`crate::lexer::lex`]).
pub fn parse(tokens: Vec<Token>) -> Result<Component, WeftError> {
    Parser { tokens, pos: 0 }.parse_component()
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    // ----- token cursor helpers -----

    fn peek(&self) -> &TokenKind {
        // The lexer guarantees a trailing Eof, so indexing the last token is safe
        // even once `pos` reaches it; we never advance past Eof.
        &self.tokens[self.pos.min(self.tokens.len() - 1)].kind
    }

    fn peek_span(&self) -> Span {
        self.tokens[self.pos.min(self.tokens.len() - 1)].span
    }

    fn at(&self, kind: &TokenKind) -> bool {
        self.peek() == kind
    }

    fn bump(&mut self) -> Token {
        let token = self.tokens[self.pos.min(self.tokens.len() - 1)].clone();
        if self.pos < self.tokens.len() - 1 {
            self.pos += 1;
        }
        token
    }

    fn eat(&mut self, kind: &TokenKind) -> bool {
        if self.at(kind) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, kind: &TokenKind) -> Result<Token, WeftError> {
        if self.at(kind) {
            Ok(self.bump())
        } else {
            Err(self.err(format!(
                "expected {}, found {}",
                kind.label(),
                self.peek().label()
            )))
        }
    }

    fn err(&self, message: String) -> WeftError {
        WeftError::Parse {
            span: self.peek_span(),
            message,
        }
    }

    /// Consumes and concatenates any leading `///` doc comments.
    fn collect_docs(&mut self) -> Vec<String> {
        let mut docs = Vec::new();
        while let TokenKind::Doc(text) = self.peek() {
            docs.push(text.clone());
            self.bump();
        }
        docs
    }

    /// Consumes an identifier, returning its text and span.
    fn expect_ident(&mut self) -> Result<Spanned<String>, WeftError> {
        if let TokenKind::Ident(name) = self.peek() {
            let name = name.clone();
            let span = self.peek_span();
            self.bump();
            Ok(Spanned::new(name, span))
        } else {
            Err(self.err(format!(
                "expected an identifier, found {}",
                self.peek().label()
            )))
        }
    }

    // ----- productions -----

    fn parse_component(&mut self) -> Result<Component, WeftError> {
        let docs = self.collect_docs();
        self.expect(&TokenKind::Component)?;
        let name = self.expect_ident()?;
        let version = self.parse_version()?;
        self.expect(&TokenKind::LBrace)?;

        let mut state = Vec::new();
        let mut events = Vec::new();
        let mut entries = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            let item_docs = self.collect_docs();
            match self.peek() {
                TokenKind::State => state.push(self.parse_state_decl(item_docs)?),
                TokenKind::Event => events.push(self.parse_event_decl(item_docs)?),
                TokenKind::Entry => entries.push(self.parse_entry(item_docs)?),
                other => {
                    return Err(self.err(format!(
                        "expected `state`, `event`, or `entry`, found {}",
                        other.label()
                    )))
                }
            }
        }
        self.expect(&TokenKind::RBrace)?;
        self.expect(&TokenKind::Eof)?;
        Ok(Component {
            name,
            version,
            docs,
            state,
            events,
            entries,
        })
    }

    /// Parses the `vN` version token (an identifier like `v1`).
    fn parse_version(&mut self) -> Result<u32, WeftError> {
        let ident = self.expect_ident()?;
        let digits = ident
            .value
            .strip_prefix('v')
            .filter(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()));
        match digits.and_then(|d| d.parse::<u32>().ok()) {
            Some(version) => Ok(version),
            None => Err(WeftError::Parse {
                span: ident.span,
                message: format!("expected a version like `v1`, found `{}`", ident.value),
            }),
        }
    }

    fn parse_state_decl(&mut self, docs: Vec<String>) -> Result<StateDecl, WeftError> {
        self.expect(&TokenKind::State)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::Colon)?;
        let ty = self.parse_type()?;
        self.eat(&TokenKind::Semi); // optional trailing `;`
        Ok(StateDecl { name, ty, docs })
    }

    fn parse_event_decl(&mut self, docs: Vec<String>) -> Result<EventDecl, WeftError> {
        self.expect(&TokenKind::Event)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LBrace)?;
        let mut fields = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            fields.push(self.parse_param()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RBrace)?;
        Ok(EventDecl { name, fields, docs })
    }

    fn parse_entry(&mut self, docs: Vec<String>) -> Result<Entry, WeftError> {
        self.expect(&TokenKind::Entry)?;
        let name = self.expect_ident()?;
        self.expect(&TokenKind::LParen)?;
        let mut params = Vec::new();
        while !self.at(&TokenKind::RParen) && !self.at(&TokenKind::Eof) {
            params.push(self.parse_param()?);
            if !self.eat(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RParen)?;
        let effects = self.parse_effects()?;
        let ret = if self.eat(&TokenKind::Arrow) {
            Some(self.parse_type()?)
        } else {
            None
        };
        let body = self.parse_block()?;
        Ok(Entry {
            name,
            params,
            effects,
            ret,
            body,
            docs,
        })
    }

    fn parse_param(&mut self) -> Result<Param, WeftError> {
        let name = self.expect_ident()?;
        self.expect(&TokenKind::Colon)?;
        let ty = self.parse_type()?;
        Ok(Param { name, ty })
    }

    fn parse_effects(&mut self) -> Result<Effects, WeftError> {
        let mut effects = Effects::default();
        if self.eat(&TokenKind::Reads) {
            effects.reads = self.parse_ident_list()?;
        }
        if self.eat(&TokenKind::Writes) {
            effects.writes = self.parse_ident_list()?;
        }
        Ok(effects)
    }

    fn parse_ident_list(&mut self) -> Result<Vec<Spanned<String>>, WeftError> {
        let mut names = vec![self.expect_ident()?];
        while self.eat(&TokenKind::Comma) {
            names.push(self.expect_ident()?);
        }
        Ok(names)
    }

    fn parse_type(&mut self) -> Result<Ty, WeftError> {
        match self.peek() {
            TokenKind::U64 => {
                self.bump();
                Ok(Ty::U64)
            }
            TokenKind::Bytes => {
                self.bump();
                Ok(Ty::Bytes)
            }
            other => Err(self.err(format!(
                "expected a type (`u64` or `bytes`), found {}",
                other.label()
            ))),
        }
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>, WeftError> {
        self.expect(&TokenKind::LBrace)?;
        let mut stmts = Vec::new();
        while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
            stmts.push(self.parse_stmt()?);
        }
        self.expect(&TokenKind::RBrace)?;
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, WeftError> {
        let start = self.peek_span().start;
        match self.peek() {
            TokenKind::Let => {
                self.bump();
                let name = self.expect_ident()?;
                self.expect(&TokenKind::Eq)?;
                let expr = self.parse_expr()?;
                let end = self.expect(&TokenKind::Semi)?.span.end;
                Ok(Stmt::Let {
                    name,
                    expr,
                    span: Span::new(start, end),
                })
            }
            TokenKind::Return => {
                self.bump();
                let expr = self.parse_expr()?;
                let end = self.expect(&TokenKind::Semi)?.span.end;
                Ok(Stmt::Return {
                    expr,
                    span: Span::new(start, end),
                })
            }
            TokenKind::Emit => {
                self.bump();
                let event = self.expect_ident()?;
                self.expect(&TokenKind::LBrace)?;
                let mut fields = Vec::new();
                while !self.at(&TokenKind::RBrace) && !self.at(&TokenKind::Eof) {
                    let field = self.expect_ident()?;
                    self.expect(&TokenKind::Colon)?;
                    let value = self.parse_expr()?;
                    fields.push((field, value));
                    if !self.eat(&TokenKind::Comma) {
                        break;
                    }
                }
                self.expect(&TokenKind::RBrace)?;
                let end = self.expect(&TokenKind::Semi)?.span.end;
                Ok(Stmt::Emit {
                    event,
                    fields,
                    span: Span::new(start, end),
                })
            }
            TokenKind::Ident(_) => {
                // Assignment: `<field> = <expr> ;`
                let target = self.expect_ident()?;
                self.expect(&TokenKind::Eq)?;
                let expr = self.parse_expr()?;
                let end = self.expect(&TokenKind::Semi)?.span.end;
                Ok(Stmt::Assign {
                    target,
                    expr,
                    span: Span::new(start, end),
                })
            }
            other => Err(self.err(format!(
                "expected a statement (`let`, `return`, `emit`, or an assignment), found {}",
                other.label()
            ))),
        }
    }

    // Expression precedence: add -> mul -> primary (left-associative).

    fn parse_expr(&mut self) -> Result<Expr, WeftError> {
        self.parse_add()
    }

    fn parse_add(&mut self) -> Result<Expr, WeftError> {
        let mut lhs = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                TokenKind::Plus => BinOp::Add,
                TokenKind::Minus => BinOp::Sub,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_mul()?;
            let span = Span::new(lhs.span().start, rhs.span().end);
            lhs = Expr::Bin {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> Result<Expr, WeftError> {
        let mut lhs = self.parse_primary()?;
        while self.at(&TokenKind::Star) {
            self.bump();
            let rhs = self.parse_primary()?;
            let span = Span::new(lhs.span().start, rhs.span().end);
            lhs = Expr::Bin {
                op: BinOp::Mul,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                span,
            };
        }
        Ok(lhs)
    }

    fn parse_primary(&mut self) -> Result<Expr, WeftError> {
        let span = self.peek_span();
        match self.peek().clone() {
            TokenKind::Int(value) => {
                self.bump();
                Ok(Expr::Int(value, span))
            }
            TokenKind::Input => {
                self.bump();
                Ok(Expr::Input(span))
            }
            TokenKind::Ident(name) => {
                self.bump();
                Ok(Expr::Var(name, span))
            }
            TokenKind::LParen => {
                self.bump();
                let inner = self.parse_expr()?;
                self.expect(&TokenKind::RParen)?;
                Ok(inner)
            }
            other => Err(self.err(format!(
                "expected an expression (integer, `input`, name, or `( .. )`), found {}",
                other.label()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::lex;

    fn parse_src(src: &str) -> Result<Component, WeftError> {
        parse(lex(src).unwrap())
    }

    #[test]
    fn parses_the_counter() {
        let c = parse_src(
            "/// doc\ncomponent counter v1 {\n state count: u64\n entry bump() reads count writes count -> u64 {\n count = count + 1;\n return count;\n }\n}",
        )
        .expect("counter parses");
        assert_eq!(c.name.value, "counter");
        assert_eq!(c.version, 1);
        assert_eq!(c.state.len(), 1);
        assert_eq!(c.entries.len(), 1);
        let entry = &c.entries[0];
        assert_eq!(entry.effects.reads.len(), 1);
        assert_eq!(entry.effects.writes.len(), 1);
        assert_eq!(entry.ret, Some(Ty::U64));
        assert_eq!(entry.body.len(), 2);
    }

    #[test]
    fn rejects_bad_version_and_missing_type() {
        assert!(matches!(
            parse_src("component c x1 {}"),
            Err(WeftError::Parse { .. })
        ));
        assert!(matches!(
            parse_src("component c v1 { state s: }"),
            Err(WeftError::Parse { .. })
        ));
    }

    #[test]
    fn precedence_is_left_assoc_mul_over_add() {
        let c = parse_src("component c v1 { state a: u64 entry e() writes a { a = 1 + 2 * 3; } }")
            .unwrap();
        // 1 + (2 * 3): the top node is Add whose rhs is a Mul.
        if let Stmt::Assign { expr, .. } = &c.entries[0].body[0] {
            match expr {
                Expr::Bin {
                    op: BinOp::Add,
                    rhs,
                    ..
                } => {
                    assert!(matches!(**rhs, Expr::Bin { op: BinOp::Mul, .. }));
                }
                other => panic!("expected Add at top, got {other:?}"),
            }
        } else {
            panic!("expected assignment");
        }
    }
}
