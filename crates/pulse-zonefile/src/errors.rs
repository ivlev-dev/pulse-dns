//! Ошибки формата (`zonefile-v1.md`, §21.1).

use std::fmt;

use thiserror::Error;

/// Версия формата.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// Мажорная версия.
    pub major: u16,
    /// Минорная версия.
    pub minor: u16,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Публичный вид повреждения (9 значений, ровно как в `domain-model` §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorruptKind {
    /// Обе meta-страницы невалидны либо повреждён superblock.
    NoValidMeta,
    /// CRC страницы не сходится.
    PageChecksum,
    /// Нарушен порядок ключей или сепараторы.
    TreeOrder,
    /// Границы, типы страниц, глубина, регион reader table.
    Bounds,
    /// Цикл или пересечение в freelist.
    FreelistCycle,
    /// TTL вне допустимого диапазона.
    BadTtl,
    /// Некорректный per-zone metadata-блок.
    BadZoneMeta,
    /// Некорректная overflow-цепочка или сумма RDATA.
    BadRdata,
    /// Некорректное RLE-имя.
    BadName,
}

/// Внутренняя детализация повреждения (в публичный контракт не выходит).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CorruptDetail {
    /// Неверная магия.
    BadMagic,
    /// Валидной meta-страницы нет.
    NoValidMeta,
    /// CRC не сходится.
    Checksum,
    /// Нарушен порядок ключей.
    KeyOrder,
    /// Несовпадение сепаратора.
    SeparatorMismatch,
    /// `page_no` не совпадает со слотом.
    PageNo,
    /// Неверный `page_type` для контекста.
    PageType,
    /// Дочерний указатель вне диапазона.
    ChildRange,
    /// Глубина дерева превышена.
    DepthExceeded,
    /// Смещение/длина вне страницы.
    OffsetOutOfRange,
    /// Файл усечён.
    Truncated,
    /// Цикл в цепочке.
    Cycle,
    /// Пересечение страниц.
    Overlap,
    /// TTL вне диапазона.
    TtlOutOfRange,
    /// Некорректное поле per-zone metadata.
    ZoneMetaField,
    /// Per-zone metadata-блок превышает предел.
    ZoneMetaTooLarge,
    /// Некорректная overflow-цепочка.
    OverflowChain,
    /// Сумма длин RDATA не сходится.
    RdataSum,
    /// Некорректное RLE-имя.
    BadNameEncoding,
    /// Байт компрессии в имени.
    CompressionByte,
    /// Некорректный регион reader table.
    BadReaderRegion,
}

/// Идентификатор нарушенного инварианта записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvariantId {
    /// Разные TTL внутри `RRset` (INV-1).
    TtlMismatch,
    /// Поддерево cut превышает лимит.
    CutSubtreeTooLarge,
    /// Нарушен порядок ключей.
    KeyOrder,
    /// Нарушен сепаратор ветвления.
    SeparatorMismatch,
    /// Дублирующийся `PageId`.
    DuplicatePage,
    /// Overflow-цепочка некорректна.
    OverflowChain,
    /// Глубина дерева превышена.
    DepthExceeded,
    /// `encoded_size` превышает страницу.
    EncodedSize,
    /// Нарушен инвариант lowercase.
    Lowercase,
    /// Коммит запросил режим слабее файлового (§4.1): после `durable_txn > 1`
    /// эффективный режим файла — `Sync`.
    DurabilityBelowFileMode,
}

impl fmt::Display for InvariantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Единый тип ошибок `pulse-zonefile`.
#[derive(Debug, Error)]
pub enum ZoneFileError {
    /// Ошибка ввода-вывода.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Повреждение файла.
    #[error("corrupt zone file: {kind:?} (page {page:?}, detail {detail:?})")]
    Corrupt {
        /// Публичный вид повреждения.
        kind: CorruptKind,
        /// Номер страницы, если известен.
        page: Option<u32>,
        /// Внутренняя детализация.
        detail: CorruptDetail,
    },

    /// Обе meta-страницы невалидны (отдельный вариант для ADR 0004).
    #[error("corrupt zone file: no valid meta page")]
    CorruptNoValidMeta,

    /// Файл короче `page_count_max * page_size`.
    #[error("truncated zone file")]
    TruncatedFile,

    /// Неподдерживаемая версия или обязательные feature-флаги.
    #[error(
        "unsupported version {found} (supported {supported}, required flags {required_flags:#x})"
    )]
    UnsupportedVersion {
        /// Найденная версия.
        found: Version,
        /// Поддерживаемая версия.
        supported: Version,
        /// Неизвестные обязательные биты.
        required_flags: u64,
    },

    /// Второй writer (lock-файл занят).
    #[error("zone file is busy: another writer holds the lock")]
    Busy,

    /// Lock-файл или файл зон не является regular-файлом
    /// (FIFO, device, каталог или symlink после `O_NOFOLLOW`).
    #[error("not a regular file")]
    NotRegularFile,

    /// Reader table заполнена.
    #[error("too many readers")]
    TooManyReaders,

    /// Двухфазный пин не удался за отведённое число попыток.
    #[error("reader slot contended")]
    ReaderContended,

    /// Читатели удерживают снапшоты слишком долго.
    #[error("readers stalled: oldest txn {oldest_txn}, since {since_ns} ns")]
    ReadersStalled {
        /// Самый старый удерживаемый `txnid`.
        oldest_txn: u64,
        /// Момент начала застоя, нс.
        since_ns: u64,
    },

    /// Адресное пространство файла исчерпано.
    #[error("map is full: high water {high_water} of {page_count_max} pages")]
    MapFull {
        /// Текущий high water.
        high_water: u32,
        /// Максимум страниц.
        page_count_max: u32,
    },

    /// Свободные страницы есть, но все «молодые».
    #[error("no reusable space: needed {needed}, free {free}")]
    NoSpace {
        /// Требуется страниц.
        needed: u32,
        /// Доступно страниц.
        free: u32,
    },

    /// Не удалось выделить/отобразить память под файл.
    #[error("map allocation failed for {size} bytes (errno {errno}): {hint}")]
    MapAllocFailed {
        /// Запрошенный размер.
        size: u64,
        /// Код ошибки `errno`.
        errno: i32,
        /// Подсказка оператору.
        hint: &'static str,
    },

    /// Пространство `zone_seq` исчерпано.
    #[error("zone id space exhausted")]
    IdSpaceExhausted,

    /// Неверный accessor (например, `lookup` для `RRSIG`).
    #[error("wrong accessor for this record type")]
    WrongAccessor,

    /// Имя слишком длинное.
    #[error("name too long")]
    NameTooLong,

    /// Метка слишком длинная.
    #[error("label too long")]
    LabelTooLong,

    /// RDATA одного RR превышает предел протокола.
    #[error("rdata too large")]
    RdataTooLarge,

    /// Payload `RRset` превышает предел формата.
    #[error("rrset too large")]
    RrsetTooLarge,

    /// Зона превышает лимит.
    #[error("zone too large")]
    ZoneTooLarge,

    /// Upstream-блоб превышает лимит.
    #[error("upstream blob too large")]
    UpstreamTooLarge,

    /// Per-zone metadata-блок превышает лимит.
    #[error("zone meta too large")]
    ZoneMetaTooLarge,

    /// Нарушен инвариант записи.
    #[error("invariant violation: {0}")]
    InvariantViolation(InvariantId),

    /// Операция записи запрещена.
    #[error("zone file is read-only")]
    ReadOnly,

    /// `Snapshot` создан другим `ZoneFile` (несовпадение `instance_uuid`):
    /// его пин относится к чужой reader table и не защищает страницы.
    #[error("snapshot belongs to a different zone file")]
    SnapshotFromDifferentFile,

    /// Откат на `txn` запрещён (страницы могли быть переиспользованы).
    #[error("refuse to roll back: target txn is below reclaim boundary")]
    RefuseToRollback,

    /// В режиме `Memory` (`NoSync`) выбрана meta новее `durable_txn`, но
    /// `OpenConfig.allow_unsynced_memory_recovery` не задан.
    #[error(
        "unsynced memory recovery refused: txnid {txnid} > durable_txn {durable_txn}; meta may have survived data"
    )]
    UnsyncedMemoryRecovery {
        /// `txnid` выбранной meta.
        txnid: u64,
        /// `durable_txn` выбранной meta.
        durable_txn: u64,
    },

    /// Файл откатился к initial-состоянию после существования.
    #[error(
        "rolled back to initial meta (instance {instance_uuid:?}, created {created_unix_ns} ns)"
    )]
    RolledBackToInitial {
        /// UUID экземпляра файла.
        instance_uuid: [u8; 16],
        /// Момент создания файла, нс.
        created_unix_ns: u64,
    },

    /// Файл уже существует (только для [`ZoneFile::create`](crate::ZoneFile::create)).
    #[error("zone file already exists")]
    AlreadyExists,
}

impl ZoneFileError {
    /// Создаёт ошибку повреждения с детализацией.
    #[must_use]
    pub(crate) const fn corrupt(
        kind: CorruptKind,
        page: Option<u32>,
        detail: CorruptDetail,
    ) -> Self {
        Self::Corrupt { kind, page, detail }
    }
}
