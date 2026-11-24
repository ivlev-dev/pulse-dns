//! Ошибки разбора master-файла и предупреждения импорта.

use std::fmt;

use pulse_dns::{NameError, RdataError, RecordError, Rtype};
use thiserror::Error;

/// Позиция во входном файле.
///
/// `line` и `column` начинаются с единицы. Для ошибок, не привязанных к
/// конкретному токену (например, проверки зоны после разбора), указывается
/// позиция первой записи-нарушителя.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// Имя источника: имя файла или `<input>` для строки в памяти.
    pub source: String,
    /// Номер строки (с единицы).
    pub line: u32,
    /// Номер колонки (с единицы).
    pub column: u32,
}

impl Location {
    /// Создаёт позицию.
    #[must_use]
    pub fn new(source: impl Into<String>, line: u32, column: u32) -> Self {
        Self {
            source: source.into(),
            line,
            column,
        }
    }

    /// Позиция для ошибок уровня зоны, где строка неизвестна.
    #[must_use]
    pub fn unknown(source: impl Into<String>) -> Self {
        Self::new(source, 0, 0)
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.source, self.line, self.column)
    }
}

/// Классифицированная причина ошибки разбора.
#[derive(Debug, Error)]
pub enum ErrorKind {
    /// Ошибка чтения `$INCLUDE`-файла.
    #[error("cannot read include file: {0}")]
    Io(String),
    /// Нарушен явный лимит ресурсов.
    #[error("{what} {value} exceeds limit {max}")]
    Limit {
        /// Что именно ограничено.
        what: &'static str,
        /// Фактическое значение.
        value: usize,
        /// Максимум.
        max: usize,
    },
    /// Незакрытая кавычка.
    #[error("unterminated quoted string")]
    UnterminatedQuote,
    /// Незакрытая скобка группировки `(`.
    #[error("unterminated `(` group: {depth} group(s) still open")]
    UnterminatedGroup {
        /// Глубина вложенности на конец ввода.
        depth: usize,
    },
    /// Закрывающая скобка без открывающей.
    #[error("unexpected `)` without matching `(`")]
    UnbalancedGroup,
    /// Символ, недопустимый в master-файле.
    #[error("unexpected character {0:?}")]
    UnexpectedCharacter(char),
    /// Директива неизвестна.
    #[error("unknown directive {0}")]
    UnknownDirective(String),
    /// Директива распознана, но не поддерживается.
    #[error("directive {0} is not supported")]
    UnsupportedDirective(String),
    /// Неверный синтаксис директивы.
    #[error("directive {directive}: {message}")]
    Directive {
        /// Имя директивы (с `$`).
        directive: &'static str,
        /// Пояснение.
        message: String,
    },
    /// Ошибка `$INCLUDE`: путь вне разрешённого каталога, цикл, глубина.
    #[error("$INCLUDE {0}")]
    Include(String),
    /// В строке нет владельца, а наследовать нечего.
    #[error("record has no owner name and there is no previous owner to inherit")]
    MissingOwner,
    /// Невозможно определить TTL.
    #[error("record has no TTL: no $TTL, no previous TTL and no SOA minimum")]
    MissingTtl,
    /// В строке нет типа записи.
    #[error("record for owner {owner} has no record type")]
    MissingType {
        /// Владелец.
        owner: String,
    },
    /// Некорректное доменное имя.
    #[error("invalid name {input:?}: {source}")]
    Name {
        /// Исходный токен.
        input: String,
        /// Ошибка `pulse-dns`.
        #[source]
        source: NameError,
    },
    /// Владелец вне зоны (INV-7).
    #[error("owner {name} is outside zone {origin}")]
    OutOfZone {
        /// Владелец.
        name: String,
        /// Origin зоны.
        origin: String,
    },
    /// Некорректный TTL.
    #[error("invalid TTL {input:?}: {message}")]
    Ttl {
        /// Исходный токен.
        input: String,
        /// Пояснение.
        message: String,
    },
    /// Некорректное числовое поле.
    #[error("invalid {field} {input:?}")]
    Number {
        /// Имя поля.
        field: &'static str,
        /// Исходный токен.
        input: String,
    },
    /// Некорректная временная метка RRSIG.
    #[error("invalid RRSIG timestamp {input:?}: {message}")]
    Timestamp {
        /// Исходный токен.
        input: String,
        /// Пояснение.
        message: String,
    },
    /// Неизвестный мнемоник типа записи.
    #[error("unknown record type {0:?}")]
    Type(String),
    /// Класс, не поддерживаемый в v1 (INV-10).
    #[error("unsupported class {0}; only IN is allowed in v1")]
    UnsupportedClass(String),
    /// Тип записи не может встречаться в зоне.
    #[error("record type {0} is not allowed in a master file")]
    NotZoneType(Rtype),
    /// Некорректная RDATA для заявленного типа.
    #[error("{rr_type} RDATA: {message}")]
    Rdata {
        /// Тип записи.
        rr_type: Rtype,
        /// Пояснение.
        message: String,
    },
    /// Некорректная generic-форма `\# len hex`.
    #[error("RFC 3597 RDATA for {rr_type}: {message}")]
    GenericRdata {
        /// Тип записи.
        rr_type: Rtype,
        /// Пояснение.
        message: String,
    },
    /// Длина generic-RDATA не совпала с заявленной.
    #[error("RFC 3597 length mismatch: declared {declared}, actual {actual}")]
    Rdlength {
        /// Заявленная длина.
        declared: usize,
        /// Фактическая длина.
        actual: usize,
    },
    /// Запись не прошла валидацию домена.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// RDATA не прошла валидацию домена.
    #[error(transparent)]
    RdataValue(#[from] RdataError),
    /// Нарушение инварианта зоны.
    #[error("{0}")]
    Validation(String),
}

/// Ошибка разбора с точной позицией.
#[derive(Debug, Error)]
#[error("{location}: {kind}")]
pub struct ParseError {
    /// Позиция.
    pub location: Location,
    /// Причина.
    #[source]
    pub kind: ErrorKind,
}

impl ParseError {
    /// Создаёт ошибку.
    #[must_use]
    pub fn new(location: Location, kind: ErrorKind) -> Self {
        Self { location, kind }
    }

    /// Позиция ошибки.
    #[must_use]
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Причина ошибки.
    #[must_use]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }
}

/// Предупреждение импорта (не блокирует загрузку).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// Позиция записи/директивы.
    pub location: Location,
    /// Вид предупреждения.
    pub kind: WarningKind,
}

/// Вид предупреждения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarningKind {
    /// TTL превышал `2^31−1` и был clamp'нут (политика `WriteIntent::Import`).
    TtlClamped {
        /// Исходное значение.
        value: u32,
    },
}

impl fmt::Display for WarningKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TtlClamped { value } => write!(
                f,
                "TTL {value} exceeds 2^31-1 and was clamped to {}",
                pulse_dns::TTL_MAX
            ),
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: warning: {}", self.location, self.kind)
    }
}
