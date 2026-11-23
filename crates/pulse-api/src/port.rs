//! Порт [`ZoneAdmin`]: администрирование зон и RRset.
//!
//! Порт синхронный и `Send + Sync`; реализации обязаны не паниковать на
//! ожидаемых ошибках и проверять `If-Match` **внутри** транзакции записи,
//! чтобы исключить окно TOCTOU между `GET` и мутацией.

use std::time::SystemTime;

use pulse_dns::{Name, Rdata, Rtype, Serial, Ttl};

use crate::error::AdminError;

/// Стабильный идентификатор зоны (`docs/spec/domain-model.md` §2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ZoneId(u32);

impl ZoneId {
    /// Создаёт идентификатор.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Числовое значение.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl std::fmt::Display for ZoneId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Тип зоны.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneKind {
    /// Первичная зона (источник истины).
    Primary,
    /// Вторичная зона (получает данные трансфером).
    Secondary,
    /// Forward-зона (резолвинг через upstream).
    Forward,
}

impl ZoneKind {
    /// Строковое представление для API.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
            Self::Forward => "forward",
        }
    }

    /// Разбирает значение из API.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "primary" => Some(Self::Primary),
            "secondary" => Some(Self::Secondary),
            "forward" => Some(Self::Forward),
            _ => None,
        }
    }

    /// Может ли зона редактироваться через RRset API.
    pub const fn is_writable(self) -> bool {
        matches!(self, Self::Primary)
    }
}

/// Политика denial-of-existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// NSEC (подпись v1).
    Nsec,
    /// NSEC3 (импортированные зоны; подпись — v1.1).
    Nsec3,
}

impl Denial {
    /// Строковое представление для API.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nsec => "nsec",
            Self::Nsec3 => "nsec3",
        }
    }

    /// Разбирает значение из API.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "nsec" => Some(Self::Nsec),
            "nsec3" => Some(Self::Nsec3),
            _ => None,
        }
    }
}

/// Условие `If-Match`/`If-None-Match`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// `*` — «любое существующее представление».
    Any,
    /// Конкретный ETag (без кавычек/W-префикса).
    Tag(String),
    /// Один из ETag (список `If-Match`).
    Tags(Vec<String>),
}

/// Предусловия мутации.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preconditions {
    /// `If-Match`.
    pub if_match: Option<Precondition>,
    /// `If-None-Match`.
    pub if_none_match: Option<Precondition>,
}

impl Preconditions {
    /// Нет условий.
    pub fn none() -> Self {
        Self::default()
    }

    /// Конструктор `If-Match: <tag>`.
    pub fn if_match(tag: impl Into<String>) -> Self {
        Self {
            if_match: Some(Precondition::Tag(tag.into())),
            if_none_match: None,
        }
    }

    /// Есть ли `If-Match`.
    pub fn has_if_match(&self) -> bool {
        self.if_match.is_some()
    }
}

/// Представление зоны для API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneView {
    /// Идентификатор.
    pub id: ZoneId,
    /// Origin в канонической форме с завершающей точкой.
    pub origin: Name,
    /// Тип зоны.
    pub kind: ZoneKind,
    /// Serial (RFC 1982).
    pub serial: Serial,
    /// Версия зоны (растёт на любом коммите).
    pub version: u64,
    /// Глобальный номер коммита.
    pub txn: u64,
    /// TTL по умолчанию.
    pub default_ttl: Ttl,
    /// Denial-of-existence.
    pub denial: Denial,
    /// Количество RRset.
    pub rrset_count: u32,
    /// ETag зоны.
    pub etag: String,
    /// Время создания.
    pub created_at: SystemTime,
    /// Время последнего изменения.
    pub updated_at: SystemTime,
}

/// Метаданные для создания/замены зоны.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneMetaInput {
    /// Тип зоны.
    pub kind: ZoneKind,
    /// TTL по умолчанию.
    pub default_ttl: Ttl,
    /// Denial-of-existence.
    pub denial: Denial,
}

/// Настройки зоны.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneSettings {
    /// TTL по умолчанию.
    pub default_ttl: Ttl,
    /// Denial-of-existence.
    pub denial: Denial,
}

/// Частичное изменение настроек зоны.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZoneSettingsPatch {
    /// Новый TTL по умолчанию.
    pub default_ttl: Option<Ttl>,
    /// Новая политика denial.
    pub denial: Option<Denial>,
}

impl ZoneSettingsPatch {
    /// Есть ли хотя бы одно изменение.
    pub const fn is_empty(&self) -> bool {
        self.default_ttl.is_none() && self.denial.is_none()
    }
}

/// Настройки зоны вместе с ETag/версией.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSettingsView {
    /// Origin зоны.
    pub zone: Name,
    /// Настройки.
    pub settings: ZoneSettings,
    /// Версия зоны.
    pub version: u64,
    /// ETag зоны.
    pub etag: String,
    /// Время последнего изменения.
    pub updated_at: SystemTime,
}

/// Результат создания/замены ресурса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome<T> {
    /// Ресурс создан.
    Created(T),
    /// Ресурс обновлён.
    Updated(T),
}

impl<T> WriteOutcome<T> {
    /// Внутреннее значение.
    pub fn value(&self) -> &T {
        match self {
            Self::Created(value) | Self::Updated(value) => value,
        }
    }

    /// Был ли ресурс создан.
    pub const fn is_created(&self) -> bool {
        matches!(self, Self::Created(_))
    }

    /// Преобразует значение.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> WriteOutcome<U> {
        match self {
            Self::Created(value) => WriteOutcome::Created(f(value)),
            Self::Updated(value) => WriteOutcome::Updated(f(value)),
        }
    }
}

/// Представление RRset для API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsetView {
    /// Origin зоны.
    pub zone: Name,
    /// Владелец набора.
    pub owner: Name,
    /// Тип записей.
    pub rr_type: Rtype,
    /// TTL набора.
    pub ttl: Ttl,
    /// RDATA в каноническом порядке.
    pub rdata: Vec<Rdata>,
    /// ETag набора (`"rr_<hash>"`).
    pub etag: String,
    /// Время последнего изменения.
    pub updated_at: SystemTime,
}

/// Входные данные `PUT` RRset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsetInput {
    /// TTL набора.
    pub ttl: Ttl,
    /// RDATA набора (непустой).
    pub rdata: Vec<Rdata>,
}

/// Частичное изменение RRset (`PATCH`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsetPatch {
    /// Новый TTL всего набора.
    pub ttl: Option<Ttl>,
    /// Добавляемые записи.
    pub add: Vec<Rdata>,
    /// Удаляемые записи.
    pub remove: Vec<Rdata>,
}

impl RrsetPatch {
    /// Есть ли хотя бы одно изменение.
    pub const fn is_empty(&self) -> bool {
        self.ttl.is_none() && self.add.is_empty() && self.remove.is_empty()
    }
}

/// Результат `PATCH` RRset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RrsetPatchOutcome {
    /// Набор обновлён.
    Updated {
        /// Новое состояние.
        rrset: RrsetView,
        /// Сколько записей добавлено.
        added: u32,
        /// Сколько записей удалено.
        removed: u32,
    },
    /// Набор удалён (удалена последняя запись).
    Deleted {
        /// Сколько записей удалено.
        removed: u32,
    },
}

/// Страница зон.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZonePage {
    /// Элементы страницы.
    pub items: Vec<ZoneView>,
    /// Курсор следующей страницы.
    pub next_cursor: Option<String>,
    /// Есть ли ещё элементы.
    pub has_more: bool,
}

/// Фильтр зон по allowlist токена.
pub trait ZoneAllow: Send + Sync {
    /// Разрешена ли зона.
    fn allows(&self, origin: &Name) -> bool;
}

/// Allowlist, разрешающий все зоны (bootstrap-токен без `zone_scope`).
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl ZoneAllow for AllowAll {
    fn allows(&self, _origin: &Name) -> bool {
        true
    }
}

impl ZoneAllow for crate::auth::ZoneScope {
    fn allows(&self, origin: &Name) -> bool {
        crate::auth::ZoneScope::allows(self, origin)
    }
}

/// Параметры списка зон.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListZones {
    /// Размер страницы (1..=500).
    pub limit: u32,
    /// Непрозрачный курсор.
    pub cursor: Option<String>,
    /// Фильтр по типу зоны.
    pub kind: Option<ZoneKind>,
}

/// Параметры списка RRset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListRrsets {
    /// Размер страницы (1..=500).
    pub limit: u32,
    /// Непрозрачный курсор.
    pub cursor: Option<String>,
    /// Точный owner.
    pub owner: Option<Name>,
    /// Суффикс owner.
    pub owner_suffix: Option<Name>,
    /// Типы записей.
    pub types: Vec<Rtype>,
}

/// Страница RRset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsetPage {
    /// Элементы страницы.
    pub items: Vec<RrsetView>,
    /// Курсор следующей страницы.
    pub next_cursor: Option<String>,
    /// Есть ли ещё элементы.
    pub has_more: bool,
}

/// Порт администрирования зон.
pub trait ZoneAdmin: Send + Sync + 'static {
    /// Готов ли store обслуживать запросы.
    fn ready(&self) -> bool;

    /// Список зон с keyset-пагинацией по `id`.
    fn list_zones(&self, query: &ListZones, allow: &dyn ZoneAllow) -> Result<ZonePage, AdminError>;

    /// Читает зону.
    fn get_zone(&self, origin: &Name) -> Result<ZoneView, AdminError>;

    /// Создаёт зону или полностью заменяет её метаданные.
    fn put_zone(
        &self,
        origin: &Name,
        meta: &ZoneMetaInput,
        preconditions: &Preconditions,
    ) -> Result<WriteOutcome<ZoneView>, AdminError>;

    /// Удаляет зону.
    fn delete_zone(&self, origin: &Name, preconditions: &Preconditions) -> Result<(), AdminError>;

    /// Список RRset зоны.
    fn list_rrsets(&self, origin: &Name, query: &ListRrsets) -> Result<RrsetPage, AdminError>;

    /// Читает RRset.
    fn get_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
    ) -> Result<RrsetView, AdminError>;

    /// Создаёт или полностью заменяет RRset.
    fn put_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        input: &RrsetInput,
        preconditions: &Preconditions,
    ) -> Result<WriteOutcome<RrsetView>, AdminError>;

    /// Атомарно применяет дельту к RRset.
    fn patch_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        patch: &RrsetPatch,
        preconditions: &Preconditions,
    ) -> Result<RrsetPatchOutcome, AdminError>;

    /// Удаляет RRset.
    fn delete_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        preconditions: &Preconditions,
    ) -> Result<(), AdminError>;

    /// Читает настройки зоны.
    fn get_settings(&self, origin: &Name) -> Result<ZoneSettingsView, AdminError>;

    /// Изменяет настройки зоны.
    fn patch_settings(
        &self,
        origin: &Name,
        patch: &ZoneSettingsPatch,
        preconditions: &Preconditions,
    ) -> Result<ZoneSettingsView, AdminError>;
}
