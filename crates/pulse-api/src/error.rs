//! Типизированные ошибки порта [`crate::port::ZoneAdmin`].

use thiserror::Error;

/// Что именно не найдено.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NotFound {
    /// Зона отсутствует или недоступна токену.
    #[error("zone not found")]
    Zone,
    /// RRset отсутствует.
    #[error("rrset not found")]
    Rrset,
}

/// Конфликт состояния ресурса.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Conflict {
    /// Зона уже существует.
    #[error("zone already exists")]
    ZoneExists,
    /// RRset уже существует.
    #[error("rrset already exists")]
    RrsetExists,
    /// Зона занята другой операцией.
    #[error("zone is busy")]
    ZoneBusy,
    /// Запись в secondary/forward-зону запрещена.
    #[error("zone is read-only")]
    ZoneReadOnly,
}

/// Field-level ошибка валидации (RFC 9457 `errors[]`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{pointer}: {code}: {detail}")]
pub struct FieldIssue {
    /// JSON Pointer на поле запроса.
    pub pointer: String,
    /// Машиночитаемый код.
    pub code: String,
    /// Человекочитаемое описание.
    pub detail: String,
}

impl FieldIssue {
    /// Создаёт field-level ошибку.
    pub fn new(
        pointer: impl Into<String>,
        code: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            pointer: pointer.into(),
            code: code.into(),
            detail: detail.into(),
        }
    }
}

/// Нарушение доменных инвариантов при записи.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invariant violation: {} issue(s)", .issues.len())]
pub struct InvariantViolation {
    /// Список field-level ошибок.
    pub issues: Vec<FieldIssue>,
}

impl InvariantViolation {
    /// Создаёт нарушение из одной ошибки.
    pub fn single(
        pointer: impl Into<String>,
        code: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            issues: vec![FieldIssue::new(pointer, code, detail)],
        }
    }

    /// Создаёт нарушение из списка.
    pub fn new(issues: Vec<FieldIssue>) -> Self {
        Self { issues }
    }
}

/// Ошибка порта администрирования зон.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdminError {
    /// Ресурс не найден.
    #[error(transparent)]
    NotFound(#[from] NotFound),
    /// Конфликт состояния.
    #[error(transparent)]
    Conflict(#[from] Conflict),
    /// `If-Match`/`If-None-Match` не совпал.
    #[error("precondition failed")]
    PreconditionFailed {
        /// Актуальный ETag ресурса на момент отказа.
        current_etag: Option<String>,
        /// Актуальная версия ресурса.
        current_version: Option<u64>,
    },
    /// Строгий режим требует `If-Match`.
    #[error("precondition required")]
    PreconditionRequired,
    /// Нарушены инварианты RRset/зоны.
    #[error(transparent)]
    InvariantViolation(#[from] InvariantViolation),
    /// Ресурс занят другой операцией.
    #[error("resource is busy")]
    Busy,
    /// Недействительный курсор пагинации.
    #[error("invalid cursor")]
    InvalidCursor,
    /// Внутренняя ошибка адаптера.
    #[error("internal store error")]
    Internal,
}

impl AdminError {
    /// Хелпер: зона не найдена.
    pub fn zone_not_found() -> Self {
        Self::NotFound(NotFound::Zone)
    }

    /// Хелпер: RRset не найден.
    pub fn rrset_not_found() -> Self {
        Self::NotFound(NotFound::Rrset)
    }

    /// Хелпер: нарушение инварианта с одним полем.
    pub fn invariant(
        pointer: impl Into<String>,
        code: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::InvariantViolation(InvariantViolation::single(pointer, code, detail))
    }
}
