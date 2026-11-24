//! Константы формата файла зон v1 (спецификация `zonefile-v1.md`, §2).

/// Магия начала записи superblock.
pub const MAGIC: [u8; 8] = *b"PULSEZF1";

/// Мажорная версия формата.
pub const FORMAT_VERSION_MAJOR: u16 = 1;
/// Минорная версия формата.
pub const FORMAT_VERSION_MINOR: u16 = 0;

/// Размер страницы по умолчанию.
pub const PAGE_SIZE_DEFAULT: u32 = 4096;
/// Размер страницы 8192 байта.
pub const PAGE_SIZE_8192: u32 = 8192;
/// Размер страницы 16384 байта.
pub const PAGE_SIZE_16384: u32 = 16384;
/// Допустимые размеры страницы.
pub const PAGE_SIZE_ALLOWED: [u32; 3] = [PAGE_SIZE_DEFAULT, PAGE_SIZE_8192, PAGE_SIZE_16384];

/// Зарезервированный размер карты по умолчанию: 4 GiB.
pub const DEFAULT_MAP_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Тип страницы: meta.
pub const PAGE_TYPE_META: u32 = 1;
/// Тип страницы: branch B+tree.
pub const PAGE_TYPE_BRANCH: u32 = 2;
/// Тип страницы: leaf B+tree.
pub const PAGE_TYPE_LEAF: u32 = 3;
/// Тип страницы: overflow-цепочка.
pub const PAGE_TYPE_OVERFLOW: u32 = 4;
/// Тип страницы: freelist bucket.
pub const PAGE_TYPE_FREELIST: u32 = 5;
/// Тип страницы: словарь имён (зарезервировано).
pub const PAGE_TYPE_NAME_DICT: u32 = 6;
/// Тип страницы: reader table.
pub const PAGE_TYPE_READER_TABLE: u32 = 7;
/// Тип страницы: каталог секций (зарезервировано).
pub const PAGE_TYPE_SECTION_DIR: u32 = 8;
/// Тип страницы: per-zone metadata-блок.
pub const PAGE_TYPE_ZONE_META: u32 = 9;

/// Номер страницы superblock A.
pub const PAGE_SUPERBLOCK_A: u32 = 0;
/// Номер страницы superblock B.
pub const PAGE_SUPERBLOCK_B: u32 = 1;
/// Номер страницы meta A.
pub const PAGE_META_A: u32 = 2;
/// Номер страницы meta B.
pub const PAGE_META_B: u32 = 3;
/// Первый номер страницы, с которого начинаются данные (сразу за reader table).
pub const PAGE_DATA_FIRST: u32 = 4;
/// Номер первой страницы reader table.
pub const PAGE_READER_TABLE: u32 = 4;

/// Размер записи superblock в байтах.
pub const SUPERBLOCK_RECORD_SIZE: u32 = 4096;
/// Размер заголовка страницы данных.
pub const PAGE_HEADER_SIZE: u32 = 40;
/// Размер заголовка узла B+tree.
pub const NODE_HEADER_SIZE: u32 = 56;
/// Размер `LeafValue`.
pub const LEAF_VALUE_SIZE: u32 = 20;
/// Размер заголовка overflow-страницы.
pub const OVERFLOW_HEADER_SIZE: u32 = 48;
/// Размер заголовка freelist bucket.
pub const FREELIST_HEADER_SIZE: u32 = 64;
/// Размер заголовка per-zone metadata-блока.
pub const ZONE_META_HEADER_SIZE: u32 = 80;

/// Максимальная глубина дерева.
pub const MAX_TREE_DEPTH: u16 = 8;
/// Максимальная длина имени в wire-формате.
pub const MAX_NAME_WIRE: u32 = 255;
/// Максимальная длина одной метки.
pub const MAX_LABEL: u32 = 63;
/// Максимальный размер ключа.
pub const MAX_KEY_SIZE: u32 = MAX_NAME_WIRE + 6;
/// Интервал restart-точек листа.
pub const LEAF_RESTART_INTERVAL: u32 = 8;
/// Интервал restart-точек ветвления.
pub const BRANCH_RESTART_INTERVAL: u32 = 4;
/// Максимум overflow-страниц в цепочке `RRset`.
pub const MAX_OVERFLOW_PAGES: u32 = 64;
/// Максимальная длина RDATA одного RR.
pub const MAX_RDLENGTH: u32 = 65_535;

/// Минимальный размер item листа.
pub const MIN_LEAF_ITEM_BYTES: u32 = 25;
/// Минимальный размер item ветвления.
pub const MIN_BRANCH_ITEM_BYTES: u32 = 9;
/// Порог inline-хранения payload.
pub const INLINE_VALUE_MAX: u32 = 512;
/// Максимальный payload `RRset`.
pub const MAX_RRSET_PAYLOAD: u32 = 196_605;
/// Жёсткий лимит `RRset` на зону.
pub const MAX_RRSETS_PER_ZONE: u64 = 50_000_000;
/// Лимит записей поддерева cut.
pub const MAX_CUT_SUBTREE_RECORDS: u64 = 100_000;
/// Максимум forward-upstream записей.
pub const MAX_FORWARD_UPSTREAMS: u16 = 32;
/// Максимальный размер forward-блоба.
pub const MAX_FORWARD_BLOB: u32 = 4096;
/// Логический предел per-zone metadata-блока.
pub const MAX_ZONE_META: u32 = 262_144;

/// Число страниц цепочки `ZONE_META` для размера страницы по умолчанию.
pub const MAX_ZONE_META_PAGES: u32 = 65;
/// Синоним [`MAX_ZONE_META_PAGES`] с явным указанием «по умолчанию».
pub const MAX_ZONE_META_PAGES_DEFAULT: u32 = MAX_ZONE_META_PAGES;

/// Число страниц, необходимое для `MAX_ZONE_META` при заданном размере страницы.
///
/// Для недопустимых размеров (не больше заголовка overflow-страницы) вернёт 0.
#[must_use]
pub const fn max_zone_meta_pages(page_size: u32) -> u32 {
    if page_size <= OVERFLOW_HEADER_SIZE {
        return 0;
    }
    let usable = page_size - OVERFLOW_HEADER_SIZE;
    MAX_ZONE_META.div_ceil(usable)
}

/// Runtime-режим синхронизации: без fsync (экспериментальный).
pub const MODE_NOSYNC: u8 = 0;
/// Runtime-режим синхронизации: данные синхронизируются, meta — нет.
pub const MODE_NOMETASYNC: u8 = 1;
/// Runtime-режим синхронизации: данные и meta синхронизируются.
pub const MODE_SYNC: u8 = 2;
/// Runtime-режим синхронизации по умолчанию.
pub const DEFAULT_SYNC_MODE: u8 = MODE_SYNC;

/// Persistent-код `superblock.sync_mode`: `Sync` (данные и meta fsync'нуты).
///
/// Это отдельный enum (§4.1): его значения **не** совпадают с [`MODE_*`](MODE_SYNC).
pub const SYNC_MODE_SYNC: u8 = 0;
/// Persistent-код `superblock.sync_mode`: `Flush` (данные fsync'нуты, meta — нет).
pub const SYNC_MODE_FLUSH: u8 = 1;
/// Persistent-код `superblock.sync_mode`: `Memory` (ни данные, ни meta не форсируются).
pub const SYNC_MODE_MEMORY: u8 = 2;

/// Число слотов reader table.
pub const READER_SLOTS: u32 = 1024;
/// Максимум слотов reader table на поток.
pub const READER_SLOTS_PER_THREAD: u32 = 4;
/// Интервал maintenance-GC зон, мс.
pub const GC_INTERVAL_MS: u64 = 3_600_000;
/// Максимум reclaim-зон на коммит.
pub const MAX_RECLAIM_ZONES_PER_COMMIT: u32 = 16;
/// Максимум reclaim-страниц на коммит.
pub const MAX_RECLAIM_PAGES_PER_COMMIT: u32 = 8_192;
/// Размер слота reader table.
pub const READER_SLOT_SIZE: u32 = 32;
/// Размер собственного дескриптора страницы reader table.
pub const READER_PAGE_DESC_SIZE: u32 = 32;
/// Таймаут «застойного» читателя для диагностики, мс.
pub const STALE_READER_TIMEOUT_MS: u64 = 30_000;

/// Суффикс lock-файла writer'а.
pub const LOCK_FILE_SUFFIX: &str = ".lock";

/// Максимальный TTL.
pub const MAX_TTL: u32 = 0x7FFF_FFFF;
/// Максимальный номер страницы файла.
pub const MAX_FILE_PAGES: u32 = 0xFFFF_FFFE;
/// Guard числа зон в файле (спецификация §16).
pub const MAX_ZONES: u32 = 1_000_000;

/// Максимум сравнений на один lookup.
pub const MAX_COMPARISONS_PER_LOOKUP: u32 = 128;

/// Порог давности `created_unix_ns`, после которого откат к initial meta требует
/// подтверждения оператора (спецификация §13.7, шаг 10).
pub const ROLLBACK_ALERT_AGE_MS: u64 = 60_000;

/// Бит feature-флагов `required`: фронт-кодированные ключи.
pub const F_FRONT_CODED_KEYS: u64 = 1 << 0;
/// Бит feature-флагов `required`: `subtype` в ключе.
pub const F_RRSIG_SUBTYPE: u64 = 1 << 1;
/// Бит feature-флагов `required`: reader table присутствует.
pub const F_READER_TABLE: u64 = 1 << 2;
/// Бит feature-флагов `required`: overflow-страницы v1.
pub const F_OVERFLOW_V1: u64 = 1 << 3;
/// Бит feature-флагов `required`: канонический порядок NSEC.
pub const F_NSEC_CANONICAL_ORDER: u64 = 1 << 4;
/// Бит feature-флагов `required`: per-zone metadata-блок.
pub const F_ZONE_META_BLOCK: u64 = 1 << 5;
/// Бит feature-флагов `optional`: NSEC3 (резерв).
pub const F_NSEC3: u64 = 1 << 8;
/// Бит feature-флагов `optional`: ссылки на имена в RDATA (резерв).
pub const F_RDATA_NAME_REFS: u64 = 1 << 9;
/// Бит feature-флагов `optional`: BLAKE3-манифест (резерв).
pub const F_MANIFEST_BLAKE3: u64 = 1 << 10;
/// Бит feature-флагов `optional`: экспериментальная сборка.
pub const F_EXPERIMENTAL: u64 = 1 << 63;

/// Все биты `required`, известные версии 1.0.
pub const KNOWN_REQUIRED_FLAGS: u64 = F_FRONT_CODED_KEYS
    | F_RRSIG_SUBTYPE
    | F_READER_TABLE
    | F_OVERFLOW_V1
    | F_NSEC_CANONICAL_ORDER
    | F_ZONE_META_BLOCK;

/// Идентификатор секции CORE.
pub const SECTION_CORE: u16 = 1;
/// Идентификатор секции `NAME_DICT` (резерв).
pub const SECTION_NAME_DICT: u16 = 2;
/// Идентификатор секции `CHANGESET_LOG` (резерв).
pub const SECTION_CHANGESET_LOG: u16 = 3;
/// Идентификатор секции `ZONE_STATS` (резерв).
pub const SECTION_ZONE_STATS: u16 = 4;
/// Идентификатор секции `KEYRING_REFS` (резерв).
pub const SECTION_KEYRING_REFS: u16 = 5;
/// Идентификатор секции MANIFEST (резерв).
pub const SECTION_MANIFEST: u16 = 6;
/// Идентификатор секции `IXFR_HISTORY` (резерв).
pub const SECTION_IXFR_HISTORY: u16 = 7;
/// Размер дескриптора секции.
pub const SECTION_DESCRIPTOR_SIZE: u32 = 32;
/// Размер выравнивающего поля дескриптора секции.
pub const SECTION_PAD_SIZE: u32 = 4;
/// Размер зарезервированного хвоста дескриптора секции.
pub const SECTION_RESERVED_SIZE: u32 = 8;
/// Максимум секций в superblock.
pub const MAX_SECTIONS: u32 = 16;

/// Алгоритм контрольной суммы: CRC-32C.
pub const CHECKSUM_ALGO_CRC32C: u16 = 1;
/// Значение `endianness`: little-endian.
pub const ENDIANNESS_LITTLE: u8 = 0;

/// Флаг meta: требуется `fsck`.
pub const META_FLAG_NEEDS_FSCK: u16 = 1 << 0;
/// Флаг meta: подсказка «только чтение».
pub const META_FLAG_READONLY_HINT: u16 = 1 << 1;
/// Флаг meta: рекомендована компакция.
pub const META_FLAG_COMPACTION_SUGGESTED: u16 = 1 << 2;
/// Флаг meta: экспериментальный режим.
pub const META_FLAG_EXPERIMENTAL: u16 = 1 << 3;

/// Флаг слота: долгое удержание снапшота.
pub const READER_FLAG_LONG_HOLD: u64 = 1 << 0;
/// Флаг слота: читатель внутрипроцессный.
pub const READER_FLAG_IN_PROCESS: u64 = 1 << 1;
/// Число попыток двухфазного пина.
pub const PIN_ATTEMPTS: u32 = 8;

// --- Смещения полей superblock (спецификация §4) ---

pub(crate) const SB_OFF_MAGIC: usize = 0;
pub(crate) const SB_OFF_VERSION_MAJOR: usize = 8;
pub(crate) const SB_OFF_VERSION_MINOR: usize = 10;
pub(crate) const SB_OFF_PAGE_SIZE: usize = 12;
pub(crate) const SB_OFF_PAGE_COUNT_MAX: usize = 16;
pub(crate) const SB_OFF_FEATURE_REQUIRED: usize = 20;
pub(crate) const SB_OFF_FEATURE_OPTIONAL: usize = 28;
pub(crate) const SB_OFF_CHECKSUM_ALGO: usize = 36;
pub(crate) const SB_OFF_ENDIANNESS: usize = 38;
pub(crate) const SB_OFF_SUPERBLOCK_COPY: usize = 39;
pub(crate) const SB_OFF_CRC32C: usize = 40;
pub(crate) const SB_OFF_INSTANCE_UUID: usize = 44;
pub(crate) const SB_OFF_CREATED_UNIX_NS: usize = 60;
pub(crate) const SB_OFF_READER_REGION_OFF: usize = 68;
pub(crate) const SB_OFF_READER_REGION_LEN: usize = 76;
pub(crate) const SB_OFF_READER_REGION_ALIGN: usize = 84;
pub(crate) const SB_OFF_PAGE_META_A: usize = 88;
pub(crate) const SB_OFF_PAGE_META_B: usize = 92;
pub(crate) const SB_OFF_PAGE_DATA_FIRST: usize = 96;
pub(crate) const SB_OFF_PAGE_READER_TABLE: usize = 100;
pub(crate) const SB_OFF_PAGE_READER_TABLE_COUNT: usize = 104;
pub(crate) const SB_OFF_SECTION_COUNT: usize = 108;
pub(crate) const SB_OFF_SECTIONS: usize = 112;
pub(crate) const SB_OFF_SYNC_MODE: usize = 624;
pub(crate) const SB_OFF_SYNC_MODE_VERSION: usize = 625;
pub(crate) const SB_OFF_RESERVED_TAIL: usize = 4088;
pub(crate) const SB_OFF_RESERVED_TAIL2: usize = 4092;
/// Версия поля `sync_mode`, размещённого в reserved superblock.
pub const SYNC_MODE_FIELD_VERSION: u8 = 1;

// --- Смещения полей дескриптора секции (§4) ---

pub(crate) const SEC_OFF_ID: usize = 0;
pub(crate) const SEC_OFF_VERSION: usize = 2;
pub(crate) const SEC_OFF_FIRST_PAGE: usize = 4;
pub(crate) const SEC_OFF_PAGE_COUNT: usize = 8;
pub(crate) const SEC_OFF_PAD: usize = 12;
pub(crate) const SEC_OFF_FLAGS: usize = 16;
pub(crate) const SEC_OFF_RESERVED: usize = 24;

// --- Смещения полей meta (§5) ---

pub(crate) const META_OFF_PAGE_TYPE: usize = 0;
pub(crate) const META_OFF_FLAGS: usize = 4;
pub(crate) const META_OFF_PAGE_NO: usize = 8;
pub(crate) const META_OFF_CRC32C: usize = 12;
pub(crate) const META_OFF_TXNID: usize = 16;
pub(crate) const META_OFF_DURABLE_TXN: usize = 24;
pub(crate) const META_OFF_VERSION_MAJOR: usize = 32;
pub(crate) const META_OFF_VERSION_MINOR: usize = 34;
pub(crate) const META_OFF_PAGE_SIZE: usize = 36;
pub(crate) const META_OFF_HIGH_WATER: usize = 40;
pub(crate) const META_OFF_FREE_PAGE_COUNT: usize = 44;
pub(crate) const META_OFF_ZONE_DIR_ROOT: usize = 48;
pub(crate) const META_OFF_ZONE_DIR_LEVEL: usize = 52;
pub(crate) const META_OFF_ZONE_COUNT: usize = 56;
pub(crate) const META_OFF_FREELIST_HEAD: usize = 60;
pub(crate) const META_OFF_FREELIST_TAIL: usize = 64;
pub(crate) const META_OFF_FREELIST_BUCKETS: usize = 68;
pub(crate) const META_OFF_FREELIST_ENTRIES: usize = 72;
pub(crate) const META_OFF_READER_REGION_OFF: usize = 76;
pub(crate) const META_OFF_READER_REGION_LEN: usize = 80;
pub(crate) const META_OFF_OLDEST_READER_TXN: usize = 88;
pub(crate) const META_OFF_TOTAL_RRSETS: usize = 96;
pub(crate) const META_OFF_TOTAL_RRS: usize = 104;
pub(crate) const META_OFF_COMMIT_UNIX_NS: usize = 112;
pub(crate) const META_OFF_RECLAIM_TXN: usize = 120;
pub(crate) const META_OFF_NEXT_ZONE_SEQ: usize = 128;
pub(crate) const META_OFF_NAME_DICT_ROOT: usize = 132;
pub(crate) const META_OFF_CHANGESET_LOG_ROOT: usize = 136;
pub(crate) const META_OFF_MANIFEST_ROOT: usize = 140;
pub(crate) const META_OFF_LAST_ERROR_CODE: usize = 144;
pub(crate) const META_OFF_LAST_ERROR_PAGE: usize = 148;
pub(crate) const META_OFF_LAST_ERROR_TXN: usize = 152;
pub(crate) const META_OFF_FSCK_HINT: usize = 160;
pub(crate) const META_OFF_RESERVED: usize = 192;

/// Длина строки `fsck_hint` в meta.
pub const FSCK_HINT_LEN: usize = 32;

// --- Смещения заголовка страницы данных (§7) ---

pub(crate) const PAGE_OFF_PAGE_TYPE: usize = 0;
pub(crate) const PAGE_OFF_PAGE_FLAGS: usize = 4;
pub(crate) const PAGE_OFF_RESERVED0: usize = 6;
pub(crate) const PAGE_OFF_PAGE_NO: usize = 8;
pub(crate) const PAGE_OFF_RESERVED1: usize = 12;
pub(crate) const PAGE_OFF_TXN: usize = 16;
pub(crate) const PAGE_OFF_LSN: usize = 24;
pub(crate) const PAGE_OFF_CRC32C: usize = 32;
pub(crate) const PAGE_OFF_PAYLOAD_LEN: usize = 36;

/// Бит `page_flags`: ключи страницы фронт-кодированы.
pub const PAGE_FLAG_FRONT_CODED: u16 = 1 << 0;
/// Бит `page_flags`: страница ссылается на overflow-цепочку.
pub const PAGE_FLAG_HAS_OVERFLOW: u16 = 1 << 1;

// --- Смещения собственного дескриптора страницы reader table (§6.1) ---

pub(crate) const RTP_OFF_PAGE_TYPE: usize = 0;
pub(crate) const RTP_OFF_VERSION: usize = 4;
pub(crate) const RTP_OFF_PAGE_FLAGS: usize = 6;
pub(crate) const RTP_OFF_PAGE_NO: usize = 8;
pub(crate) const RTP_OFF_SLOTS_USED: usize = 12;
pub(crate) const RTP_OFF_CRC32C: usize = 16;
pub(crate) const RTP_OFF_RESERVED0: usize = 20;
pub(crate) const RTP_OFF_RESERVED1: usize = 24;

// --- Смещения полей слота reader table (§6.2) ---

pub(crate) const SLOT_OFF_OWNER: usize = 0;
pub(crate) const SLOT_OFF_ACTIVE: usize = 8;
pub(crate) const SLOT_OFF_HEARTBEAT: usize = 16;
pub(crate) const SLOT_OFF_FLAGS: usize = 24;

/// Геометрия региона reader table для заданного размера страницы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderGeometry {
    /// Число страниц в регионе.
    pub pages: u32,
    /// Число слотов на страницу.
    pub slots_per_page: u32,
    /// Смещение региона в файле.
    pub region_off: u64,
    /// Длина региона в байтах.
    pub region_len: u64,
    /// Выравнивание региона.
    pub region_align: u32,
    /// Номер первой страницы региона.
    pub first_page: u32,
}

impl ReaderGeometry {
    /// Вычисляет геометрию reader table для допустимого `page_size`.
    ///
    /// Возвращает `None`, если размер страницы не входит в [`PAGE_SIZE_ALLOWED`]
    /// или не позволяет вместить слоты.
    #[must_use]
    pub fn for_page_size(page_size: u32) -> Option<Self> {
        if !PAGE_SIZE_ALLOWED.contains(&page_size) {
            return None;
        }
        let usable = page_size.checked_sub(READER_PAGE_DESC_SIZE)?;
        let slots_per_page = usable / READER_SLOT_SIZE;
        if slots_per_page == 0 {
            return None;
        }
        let total_bytes = READER_SLOTS.checked_mul(READER_SLOT_SIZE)?;
        let pages = total_bytes.div_ceil(usable);
        let region_len = u64::from(pages).checked_mul(u64::from(page_size))?;
        let region_off = u64::from(PAGE_READER_TABLE).checked_mul(u64::from(page_size))?;
        Some(Self {
            pages,
            slots_per_page,
            region_off,
            region_len,
            region_align: page_size,
            first_page: PAGE_READER_TABLE,
        })
    }

    /// Номер страницы данных, следующий за регионом reader table.
    #[must_use]
    pub fn data_first(self) -> u32 {
        self.first_page.saturating_add(self.pages)
    }

    /// Максимальное число слотов, помещающихся в регион.
    #[must_use]
    pub fn capacity(self) -> u32 {
        self.pages.saturating_mul(self.slots_per_page)
    }
}

// Const-проверки размеров и смещений (спецификация §22).
const _: () = assert!(SUPERBLOCK_RECORD_SIZE == 4096);
const _: () = assert!(PAGE_HEADER_SIZE == 40);
const _: () = assert!(NODE_HEADER_SIZE == 56);
const _: () = assert!(LEAF_VALUE_SIZE == 20);
const _: () = assert!(OVERFLOW_HEADER_SIZE == 48);
const _: () = assert!(FREELIST_HEADER_SIZE == 64);
const _: () = assert!(ZONE_META_HEADER_SIZE == 80);
const _: () = assert!(READER_SLOT_SIZE == 32);
const _: () = assert!(READER_PAGE_DESC_SIZE == 32);
const _: () = assert!(SECTION_DESCRIPTOR_SIZE == 32);
const _: () = assert!(SB_OFF_INSTANCE_UUID == 44);
const _: () =
    assert!(SB_OFF_SECTIONS + (MAX_SECTIONS as usize) * (SECTION_DESCRIPTOR_SIZE as usize) == 624);
const _: () = assert!(META_OFF_RESERVED == 192);
const _: () = assert!(META_OFF_FSCK_HINT + FSCK_HINT_LEN == META_OFF_RESERVED);
const _: () = assert!(PAGE_DATA_FIRST == PAGE_READER_TABLE);
const _: () = assert!(max_zone_meta_pages(4096) == 65);
const _: () = assert!(max_zone_meta_pages(8192) == 33);
const _: () = assert!(max_zone_meta_pages(16384) == 17);
const _: () = assert!(
    SB_OFF_SYNC_MODE
        >= SB_OFF_SECTIONS + (MAX_SECTIONS as usize) * (SECTION_DESCRIPTOR_SIZE as usize)
);
const _: () = assert!(SB_OFF_SYNC_MODE_VERSION == SB_OFF_SYNC_MODE + 1);
const _: () = assert!(SB_OFF_RESERVED_TAIL == 4088);
const _: () = assert!(SB_OFF_RESERVED_TAIL2 == 4092);
const _: () = assert!(SEC_OFF_PAD == 12);
const _: () = assert!(SEC_OFF_RESERVED + 8 == SECTION_DESCRIPTOR_SIZE as usize);
const _: () = assert!(RTP_OFF_RESERVED0 == 20);
const _: () = assert!(RTP_OFF_RESERVED1 + 8 == READER_PAGE_DESC_SIZE as usize);
