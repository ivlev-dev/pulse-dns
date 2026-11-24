//! Лексер master-файла (RFC 1035 §5.1).
//!
//! Лексер выдаёт логические строки. Физические переводы строк внутри `(...)`,
//! комментарии `;` и пробелы между токенами не разрывают логическую строку.
//! Экранирование (`\DDD` и `\X`) сохраняется в токене «как есть»: имя и
//! character-string трактуют его по-разному, поэтому решение отложено до
//! потребителя.

use crate::error::{ErrorKind, Location, ParseError};
use crate::limits::Limits;

/// Токен логической строки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    /// Содержимое без внешних кавычек; escape-последовательности сохранены.
    pub text: String,
    /// Токен был целиком заключён в `"..."`.
    pub quoted: bool,
    /// Номер физической строки начала токена.
    pub line: u32,
    /// Номер колонки начала токена.
    pub column: u32,
}

impl Token {
    /// Позиция токена.
    pub fn location(&self, source: &str) -> Location {
        Location::new(source, self.line, self.column)
    }
}

/// Логическая строка.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    /// Токены в порядке появления.
    pub tokens: Vec<Token>,
    /// Номер первой физической строки.
    pub number: u32,
    /// Строка начиналась с пробела/таба (владелец наследуется).
    pub indented: bool,
}

/// Лексер по строке.
pub(crate) struct Lexer<'a> {
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    line: u32,
    column: u32,
    source: String,
    group_depth: usize,
    limits: Limits,
}

impl<'a> Lexer<'a> {
    /// Создаёт лексер.
    pub fn new(text: &'a str, source: impl Into<String>, limits: Limits) -> Self {
        Self {
            chars: text.char_indices().peekable(),
            line: 1,
            column: 1,
            source: source.into(),
            group_depth: 0,
            limits,
        }
    }

    /// Следующая логическая строка.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::UnterminatedQuote`], [`ErrorKind::UnterminatedGroup`],
    /// [`ErrorKind::UnbalancedGroup`] или [`ErrorKind::Limit`].
    pub fn next_line(&mut self) -> Result<Option<Line>, ParseError> {
        'lines: loop {
            let line_no = self.line;
            let mut tokens: Vec<Token> = Vec::new();
            let mut indented = false;

            loop {
                while let Some(&(_, ch)) = self.chars.peek() {
                    if ch == ' ' || ch == '\t' || ch == '\r' {
                        if tokens.is_empty() {
                            indented = true;
                        }
                        self.bump();
                    } else {
                        break;
                    }
                }

                let Some(&(_, ch)) = self.chars.peek() else {
                    if self.group_depth > 0 {
                        return Err(self.error_at(
                            line_no,
                            1,
                            ErrorKind::UnterminatedGroup {
                                depth: self.group_depth,
                            },
                        ));
                    }
                    if tokens.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(Line {
                        tokens,
                        number: line_no,
                        indented,
                    }));
                };

                match ch {
                    '\n' => {
                        self.bump();
                        if self.group_depth == 0 {
                            if tokens.is_empty() {
                                continue 'lines;
                            }
                            return Ok(Some(Line {
                                tokens,
                                number: line_no,
                                indented,
                            }));
                        }
                    }
                    ';' => self.skip_comment(),
                    '(' => {
                        self.group_depth = self.group_depth.saturating_add(1);
                        self.bump();
                    }
                    ')' => {
                        if self.group_depth == 0 {
                            let location = Location::new(&self.source, self.line, self.column);
                            return Err(ParseError::new(location, ErrorKind::UnbalancedGroup));
                        }
                        self.group_depth -= 1;
                        self.bump();
                    }
                    '"' => {
                        let token = self.scan_quoted()?;
                        tokens.push(token);
                    }
                    _ => {
                        let token = self.scan_bare()?;
                        tokens.push(token);
                    }
                }

                if tokens.len() > self.limits.max_line_tokens {
                    return Err(self.error_at(
                        line_no,
                        1,
                        ErrorKind::Limit {
                            what: "tokens in line",
                            value: tokens.len(),
                            max: self.limits.max_line_tokens,
                        },
                    ));
                }
            }
        }
    }

    fn scan_quoted(&mut self) -> Result<Token, ParseError> {
        let line = self.line;
        let column = self.column;
        self.bump();
        let mut text = String::new();
        loop {
            let Some(&(_, ch)) = self.chars.peek() else {
                return Err(self.error_at(line, column, ErrorKind::UnterminatedQuote));
            };
            match ch {
                '\n' => {
                    return Err(self.error_at(line, column, ErrorKind::UnterminatedQuote));
                }
                '"' => {
                    self.bump();
                    break;
                }
                '\\' => {
                    text.push('\\');
                    self.bump();
                    self.copy_escape(&mut text);
                }
                _ => {
                    text.push(ch);
                    self.bump();
                }
            }
        }
        Ok(Token {
            text,
            quoted: true,
            line,
            column,
        })
    }

    fn scan_bare(&mut self) -> Result<Token, ParseError> {
        let line = self.line;
        let column = self.column;
        let mut text = String::new();
        while let Some(&(_, ch)) = self.chars.peek() {
            match ch {
                ' ' | '\t' | '\r' | '\n' | ';' | '(' | ')' => break,
                '"' => {
                    text.push('"');
                    self.bump();
                    loop {
                        let Some(&(_, inner)) = self.chars.peek() else {
                            return Err(self.error_at(line, column, ErrorKind::UnterminatedQuote));
                        };
                        match inner {
                            '\n' => {
                                return Err(self.error_at(
                                    line,
                                    column,
                                    ErrorKind::UnterminatedQuote,
                                ));
                            }
                            '"' => {
                                text.push('"');
                                self.bump();
                                break;
                            }
                            '\\' => {
                                text.push('\\');
                                self.bump();
                                self.copy_escape(&mut text);
                            }
                            _ => {
                                text.push(inner);
                                self.bump();
                            }
                        }
                    }
                }
                '\\' => {
                    text.push('\\');
                    self.bump();
                    self.copy_escape(&mut text);
                }
                _ => {
                    text.push(ch);
                    self.bump();
                }
            }
        }
        Ok(Token {
            text,
            quoted: false,
            line,
            column,
        })
    }

    /// Копирует хвост escape-последовательности после уже скопированного `\`.
    ///
    /// Если следующий символ — цифра, копируются максимум три символа:
    /// неполная последовательность будет отвергнута декодером, но лексер не
    /// «склеит» её с соседним текстом.
    fn copy_escape(&mut self, text: &mut String) {
        for index in 0..3 {
            let Some(&(_, ch)) = self.chars.peek() else {
                break;
            };
            if index == 0 && !ch.is_ascii_digit() {
                text.push(ch);
                self.bump();
                return;
            }
            if !ch.is_ascii_digit() {
                return;
            }
            text.push(ch);
            self.bump();
        }
    }

    fn skip_comment(&mut self) {
        while let Some(&(_, ch)) = self.chars.peek() {
            if ch == '\n' {
                return;
            }
            self.bump();
        }
    }

    fn bump(&mut self) {
        let Some((_, ch)) = self.chars.next() else {
            return;
        };
        if ch == '\n' {
            self.line = self.line.saturating_add(1);
            self.column = 1;
        } else {
            self.column = self.column.saturating_add(1);
        }
    }

    fn error_at(&self, line: u32, column: u32, kind: ErrorKind) -> ParseError {
        ParseError::new(Location::new(&self.source, line, column), kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(text: &str) -> Vec<Line> {
        let mut lexer = Lexer::new(text, "<input>", Limits::default());
        let mut lines = Vec::new();
        while let Some(line) = lexer.next_line().expect("lex") {
            lines.push(line);
        }
        lines
    }

    #[test]
    fn comments_blank_lines_and_indent() {
        let lines = lex("; header\n\nwww A 192.0.2.1 ; inline\n  MX 10 mail\n");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].tokens.len(), 3);
        assert!(!lines[0].indented);
        assert_eq!(lines[1].tokens.len(), 3);
        assert!(lines[1].indented);
    }

    #[test]
    fn parentheses_join_lines_and_quotes_keep_spaces() {
        let lines = lex("@ IN SOA ns hostmaster (\n 1 2 3 4 5 )\n");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].tokens.len(), 10);
        let quoted = lex("x TXT \"a b\" \"c\\\"d\"\n");
        assert_eq!(quoted[0].tokens[2].text, "a b");
        assert!(quoted[0].tokens[2].quoted);
        assert_eq!(quoted[0].tokens[3].text, "c\\\"d");
    }

    #[test]
    fn bare_token_may_embed_quotes_for_svcb() {
        let lines = lex("x HTTPS 1 . alpn=\"h2,h3\"\n");
        assert_eq!(lines[0].tokens[4].text, "alpn=\"h2,h3\"");
        assert!(!lines[0].tokens[4].quoted);
    }

    #[test]
    fn unterminated_quote_and_group() {
        let mut lexer = Lexer::new("x TXT \"oops\n", "<input>", Limits::default());
        assert!(matches!(
            lexer.next_line(),
            Err(ParseError {
                kind: ErrorKind::UnterminatedQuote,
                ..
            })
        ));
        let mut lexer = Lexer::new("x TXT ( a b\n", "<input>", Limits::default());
        assert!(matches!(
            lexer.next_line(),
            Err(ParseError {
                kind: ErrorKind::UnterminatedGroup { depth: 1 },
                ..
            })
        ));
    }

    #[test]
    fn stray_close_paren_is_error() {
        let mut lexer = Lexer::new(")\n", "<input>", Limits::default());
        assert!(matches!(
            lexer.next_line(),
            Err(ParseError {
                kind: ErrorKind::UnbalancedGroup,
                ..
            })
        ));
    }
}
