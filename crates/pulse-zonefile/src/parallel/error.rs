//! Ошибки модуля параллельной записи v2 (фаза A).
//!
//! Тип [`ParallelError`] отдельный от v1 [`crate::ZoneFileError`]: v1-контракт
//! (варианты, `Display`, `source`) не меняется, а v2 добавляет свои классы
//! отказов (file-fatal, zone-fatal, retryable publication).

use thiserror::Error;

/// Публичная классификация повреждения v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum V2CorruptKind {
    /// Superblock: обе копии невалидны или несовместимы.
    Superblock,
    /// `LayoutHead`: обе копии невалидны, геометрия не сходится.
    LayoutHead,
    /// `ALLOC_RECORD`: обе копии невалидны.
    AllocRecord,
    /// Writer registry повреждён.
    WriterRegistry,
    /// `RootEntry`: невалидные поля/CRC.
    RootEntry,
    /// `owner_zone` записи или страницы не совпадает со слотом при валидном CRC.
    ForeignOwner,
    /// Версия записи лежит не в своей ячейке ring (`version % 4`).
    RingSlotMismatch,
    /// Нарушена монотонность `version`/`page_limit`/`txn`.
    WatermarkRegression,
    /// Chain: цикл, нарушение порядка или превышение лимита переходов.
    RootChain,
    /// Номер страницы/смещение вне файла.
    Bounds,
    /// Файл усечён.
    Truncated,
}

impl V2CorruptKind {
    /// Признак file-fatal (запись запрещена до `fsck`).
    #[must_use]
    pub const fn is_file_fatal(self) -> bool {
        matches!(
            self,
            Self::Superblock
                | Self::LayoutHead
                | Self::AllocRecord
                | Self::WriterRegistry
                | Self::ForeignOwner
                | Self::RingSlotMismatch
                | Self::WatermarkRegression
        )
    }
}

/// Причина запрета записи (file-fatal, §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FatalKind {
    /// Обе копии `LayoutHead` невалидны или расходятся по геометрии.
    LayoutHead,
    /// Обе копии `ALLOC_RECORD` невалидны.
    AllocRecord,
    /// `ALLOC_RECORD.page_limit`/`txn_limit` ниже уже опубликованного.
    AllocWatermarkRegression,
    /// `version`/`page_limit` корня ниже восстановленного watermark.
    RootWatermarkRegression,
    /// Writer registry указывает на другого лидера/непуст в M1.
    ForeignLeader,
    /// `owner_zone`/`version` записи чужой зоны при валидном CRC.
    ForeignOwner,
    /// `root_page`/`prev_record`/`free_head` за `page_limit_at_commit`
    /// у достижимой головы (класс file-fatal по §9.2).
    HeadBeyondLimit,
    /// Стор открыт в режиме `read_only`.
    ReadOnlyOpen,
}

/// Какая копия A/B выбрана при восстановлении.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CopySource {
    /// Копия A.
    A,
    /// Копия B.
    B,
    /// Обе копии совпали.
    Both,
    /// Валидной копии нет.
    None,
}

/// Ошибки v2-модуля.
#[derive(Debug, Error)]
pub enum ParallelError {
    /// Ошибка ввода-вывода.
    #[error("v2 I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Повреждение файла.
    #[error("v2 corrupt file: {kind:?} (page {page:?})")]
    Corrupt {
        /// Класс повреждения.
        kind: V2CorruptKind,
        /// Номер страницы, если известен.
        page: Option<u32>,
    },

    /// File-fatal: файл открыт, чтение разрешено, запись запрещена до `fsck`.
    #[error("v2 file is write-locked until fsck: {reason:?}")]
    ReadOnly {
        /// Причина блокировки записи.
        reason: FatalKind,
    },

    /// Неподдерживаемая версия/размер страницы/режим.
    #[error("v2 unsupported: {what}")]
    Unsupported {
        /// Что именно не поддерживается.
        what: &'static str,
    },

    /// Файл занят другим writer'ом (M1: `LOCK_EX`).
    #[error("v2 zone file is busy")]
    Busy,

    /// Путь/дескриптор не является regular-файлом.
    #[error("v2 path is not a regular file")]
    NotRegularFile,

    /// Второй writer в одном процессе: зона уже под lease.
    #[error("v2 zone {zone} is leased by another writer")]
    ZoneBusy {
        /// Зона.
        zone: u32,
    },

    /// Зона/версия/поле выходят за границы контракта.
    #[error("v2 invalid argument: {field}")]
    InvalidArgument {
        /// Имя поля.
        field: &'static str,
    },

    /// Свободных слотов читателя нет.
    #[error("v2 reader table is full")]
    TooManyReaders,

    /// Двухфазный пин не получил стабильную версию за `PIN_ATTEMPTS`.
    #[error("v2 reader contended (retryable)")]
    ReaderContended,

    /// Зона деградирована (guard/zone-fatal) и доступна только на чтение.
    #[error("v2 zone {zone} degraded (epoch {epoch})")]
    ZoneDegraded {
        /// Зона.
        zone: u32,
        /// Значение `zone_guard` на момент отказа.
        epoch: u32,
    },

    /// Chain-лимит зоны исчерпан (патология, retryable).
    #[error("v2 zone {zone} writer stalled: root chain limit")]
    ZoneWriterStalled {
        /// Зона.
        zone: u32,
    },

    /// Запрошенная версия ниже доступной истории chain.
    #[error(
        "v2 zone {zone}: stale root (requested {requested}, oldest retained {oldest_retained})"
    )]
    StaleRoot {
        /// Зона.
        zone: u32,
        /// Запрошенный `version`.
        requested: u64,
        /// Самая старая доступная версия (0 — истории нет).
        oldest_retained: u64,
    },

    /// Зоны нет или она в состоянии tombstone.
    #[error("v2 zone {zone} has no published version")]
    NoZoneVersion {
        /// Зона.
        zone: u32,
    },

    /// Аллокатор упёрся в `page_count_max`.
    #[error("v2 map full: high water {high_water}, limit {page_count_max}")]
    MapFull {
        /// Текущий high water (первая невыданная страница).
        high_water: u64,
        /// Жёсткий лимит страниц.
        page_count_max: u32,
    },
}

impl ParallelError {
    /// Признак file-fatal ошибки (запись запрещена).
    #[must_use]
    pub const fn is_file_fatal(&self) -> bool {
        matches!(self, Self::ReadOnly { .. })
    }

    /// Признак retryable-ошибки (повторить публикацию/пин).
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ReaderContended | Self::ZoneWriterStalled { .. } | Self::ZoneBusy { .. }
        )
    }
}
