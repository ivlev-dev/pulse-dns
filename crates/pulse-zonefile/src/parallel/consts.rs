//! Константы формата v2.0 для параллельной записи (фаза A).
//!
//! Единственный источник числовых значений раскладки фазы A. Раскладка полей
//! описана в `docs/spec/parallel-writes-v2.md` (§3.4, §4.1–4.4, §5.2, §10.1).
//! Смещения продублированы `const`-проверками в конце файла и модульными
//! тестами (`tests/v2_format.rs`), чтобы дрейф раскладки ломал сборку.

/// Магия файла v2.0.
pub const MAGIC_V2: [u8; 8] = *b"PULSEZF2";

/// Мажорная версия формата v2.
pub const FORMAT_VERSION_MAJOR_V2: u16 = 2;
/// Минорная версия формата v2.
pub const FORMAT_VERSION_MINOR_V2: u16 = 0;

/// Размер страницы, поддерживаемый фазой A.
///
/// Спецификация допускает 4/8/16 `КиБ`; фаза A реализует только 4096, потому что
/// раскладка root ring зафиксирована как «16 зон × 256 Б = 4096 Б».
pub const PAGE_SIZE_V2: u32 = 4096;

/// Страница `LayoutHead` A.
pub const PAGE_LAYOUT_HEAD_A: u32 = 2;
/// Страница `LayoutHead` B (отдельная 4 `КиБ` страница, F-2).
pub const PAGE_LAYOUT_HEAD_B: u32 = 3;
/// Страница writer registry (M3; в M1 валидна и пуста).
pub const PAGE_WRITER_REG: u32 = 4;
/// Страница `ALLOC_RECORD` A.
pub const PAGE_ALLOC_RECORD_A: u32 = 5;
/// Страница `ALLOC_RECORD` B (отдельная 4 `КиБ` страница, F-2).
pub const PAGE_ALLOC_RECORD_B: u32 = 6;
/// Первая страница региона reader table.
pub const PAGE_READER_TABLE: u32 = 7;

/// Тип страницы: регион root directory (номер/роль — из `LayoutHead`).
pub const PAGE_TYPE_ROOT_DIR: u32 = 10;
/// Тип страницы: chain-страница вытесненной версии корня.
pub const PAGE_TYPE_ROOT_CHAIN: u32 = 11;
/// Тип страницы: durable-барьер аллокатора.
pub const PAGE_TYPE_ALLOC_RECORD: u32 = 12;
/// Тип страницы: writer registry.
pub const PAGE_TYPE_WRITER_REG: u32 = 13;
/// Тип страницы: `LayoutHead`.
pub const PAGE_TYPE_LAYOUT_HEAD: u32 = 16;

/// Размер записи `LayoutHead` в байтах.
pub const LAYOUT_HEAD_RECORD_SIZE: u32 = 512;
/// Версия структуры `LayoutHead`.
pub const LAYOUT_HEAD_VERSION: u16 = 1;
/// Магия записи `LayoutHead`.
pub const LAYOUT_HEAD_MAGIC: [u8; 8] = *b"PLZH0002";

/// Размер записи `RootEntry` (D-A).
pub const ROOT_ENTRY_SIZE: u32 = 64;
/// Число версий в ring одной зоны.
pub const ROOT_VERSIONS: u32 = 4;
/// Число зон в одной странице-копии root directory.
pub const ZONES_PER_DIR_PAGE: u32 = 16;
/// Размер блока зоны в странице-копии: 4 версии × 64 Б.
pub const ROOT_BLOCK_SIZE: u32 = ROOT_VERSIONS * ROOT_ENTRY_SIZE;
/// Смещение `owner_zone` в заголовке chain-страницы.
pub const CHAIN_VERSION: u16 = 1;

/// Максимальное число звеньев chain при чтении.
pub const MAX_ROOT_CHAIN_HOPS: u32 = 4096;
/// Лимит chain-страниц на зону по умолчанию.
pub const MAX_ROOT_CHAIN_PAGES: u32 = 4096;

/// Размер записи `ALLOC_RECORD`.
pub const ALLOC_RECORD_SIZE: u32 = 256;
/// Версия структуры `ALLOC_RECORD`.
pub const ALLOC_RECORD_VERSION: u16 = 1;
/// Первый `seq` при создании файла.
pub const ALLOC_RECORD_SEQ_FIRST: u64 = 1;

/// Гранулярность диапазона аллокатора (64 `КиБ` @ 4096).
pub const ALLOC_EXTENT_PAGES: u32 = 16;
/// Локальный кеш страниц потока (1 CAS / 64 страницы).
pub const ALLOC_THREAD_CACHE_PAGES: u32 = 64;
/// Блок `txn`, резервируемый одним CAS.
pub const TXN_BATCH: u64 = 64;

/// Размер файлового слота reader table (v2).
pub const READER_SLOT_SIZE_V2: u32 = 128;
/// Число слотов файловой reader table.
pub const READER_SLOTS_V2: u32 = 1024;
/// Размер собственного дескриптора страницы reader region.
pub const READER_PAGE_DESC_SIZE: u32 = 32;
/// Максимум пинов зоны в одном слоте (D-D).
pub const READER_PINS: usize = 6;
/// Размер одного пина в слоте: `zone_seq u32 | pad u32 | version u64`.
pub const READER_PIN_SIZE: u32 = 16;
/// Число попыток двухфазного пина.
pub const PIN_ATTEMPTS: u32 = 8;
/// Размер одного сравнения/чтения chain-страницы.
pub const CHAIN_PAGE_SIZE: u32 = PAGE_SIZE_V2;

/// Максимальное число зон (guard §16 v1).
pub const MAX_ZONES_V2: u32 = 1_000_000;
/// Максимальное число зон по умолчанию (Q2).
pub const DEFAULT_MAX_ZONES: u32 = 65_536;
/// Размер карты по умолчанию: 1 `ГиБ` (262 144 страницы).
pub const DEFAULT_PAGE_COUNT_MAX: u32 = 1 << 18;

/// Значение «нет пина» / отсутствующий `version`.
pub const NO_VERSION: u64 = u64::MAX;

/// Тип `leader_term` в M1: один процесс, один координатор.
pub const LEADER_TERM_M1: u64 = 1;

// --- Group commit (B2b, §7.1) ---
/// Максимум зон в одной группе (§7.1 п. 8).
pub const MAX_BATCH_ZONES: u32 = 256;
/// Максимум суммы «веса» запросов группы (≈ байты) — `1 МиБ`.
pub const MAX_BATCH_BYTES: u64 = 1 << 20;
/// Максимальная задержка набора группы — 1 мс.
pub const MAX_BATCH_DELAY: std::time::Duration = std::time::Duration::from_millis(1);
/// Порог bulk-коммита: запрос больше — отдельная группа из одного элемента.
pub const BULK_COMMIT_BYTES: u64 = 256 << 10;
/// Ёмкость очереди координатора (запросов).
pub const QUEUE_ZONES: usize = 1024;
/// Бюджет байтов очереди координатора — `64 МиБ`.
pub const QUEUE_BYTES: u64 = 64 << 20;

// --- Утечки/`fsck --repair` (§6.5, R4) ---
/// Алерт-порог доли утечек: 1 % от `[data_first, DP)`.
pub const MAX_LEAK_RATIO: f64 = 0.01;
/// Порог в промилле для метрик/отчётов (`MAX_LEAK_RATIO * 1000`).
pub const MAX_LEAK_RATIO_PERMILLE: u64 = 10;

// --- Смещения `RootEntry` (§4.1) ---

pub(crate) const ROOT_OFF_CRC: usize = 0;
pub(crate) const ROOT_OFF_OWNER: usize = 4;
pub(crate) const ROOT_OFF_VERSION: usize = 8;
pub(crate) const ROOT_OFF_ROOT_PAGE: usize = 16;
pub(crate) const ROOT_OFF_PAGE_LIMIT: usize = 20;
pub(crate) const ROOT_OFF_PREV_RECORD: usize = 24;
pub(crate) const ROOT_OFF_META_ROOT: usize = 32;
pub(crate) const ROOT_OFF_IXFR_ROOT: usize = 36;
pub(crate) const ROOT_OFF_DELETED_TXN: usize = 40;
pub(crate) const ROOT_OFF_RRSET_COUNT: usize = 48;
pub(crate) const ROOT_OFF_SOA_SERIAL: usize = 52;
pub(crate) const ROOT_OFF_FREE_HEAD: usize = 56;
pub(crate) const ROOT_OFF_TREE_LEVEL: usize = 60;
pub(crate) const ROOT_OFF_STATE: usize = 62;
pub(crate) const ROOT_OFF_FLAGS: usize = 63;

// --- Смещения `LayoutHead` (512 Б, §10.1) ---

pub(crate) const LH_OFF_PAGE_TYPE: usize = 0;
pub(crate) const LH_OFF_VERSION: usize = 4;
pub(crate) const LH_OFF_FLAGS: usize = 6;
pub(crate) const LH_OFF_PAGE_NO: usize = 8;
pub(crate) const LH_OFF_CRC: usize = 12;
pub(crate) const LH_OFF_LAYOUT_SEQ: usize = 16;
pub(crate) const LH_OFF_GENERATION: usize = 24;
pub(crate) const LH_OFF_PAGE_SIZE: usize = 32;
pub(crate) const LH_OFF_MAX_ZONES: usize = 36;
pub(crate) const LH_OFF_ROOT_DIR_PAGES: usize = 40;
pub(crate) const LH_OFF_ROOT_DIR_A_FIRST: usize = 44;
pub(crate) const LH_OFF_ROOT_DIR_B_FIRST: usize = 48;
pub(crate) const LH_OFF_READER_TABLE: usize = 52;
pub(crate) const LH_OFF_READER_OFF: usize = 56;
pub(crate) const LH_OFF_READER_LEN: usize = 64;
pub(crate) const LH_OFF_DATA_FIRST: usize = 72;
pub(crate) const LH_OFF_WRITER_REG: usize = 76;
pub(crate) const LH_OFF_ALLOC_A: usize = 80;
pub(crate) const LH_OFF_ALLOC_B: usize = 84;
pub(crate) const LH_OFF_LAYOUT_A: usize = 88;
pub(crate) const LH_OFF_LAYOUT_B: usize = 92;
pub(crate) const LH_OFF_MAX_CHAIN: usize = 96;
pub(crate) const LH_OFF_READER_SLOTS: usize = 100;
pub(crate) const LH_OFF_PAGE_COUNT_MAX: usize = 104;
pub(crate) const LH_OFF_CREATED_NS: usize = 112;
pub(crate) const LH_OFF_LEADER_TERM: usize = 120;
pub(crate) const LH_OFF_MAGIC: usize = 128;
pub(crate) const LH_OFF_FEATURES: usize = 136;
pub(crate) const LH_OFF_RESERVED: usize = 144;

// --- Смещения `ALLOC_RECORD` (§3.4) ---

pub(crate) const ALLOC_OFF_PAGE_TYPE: usize = 0;
pub(crate) const ALLOC_OFF_VERSION: usize = 4;
pub(crate) const ALLOC_OFF_FLAGS: usize = 6;
pub(crate) const ALLOC_OFF_PAGE_NO: usize = 8;
pub(crate) const ALLOC_OFF_CRC: usize = 12;
pub(crate) const ALLOC_OFF_SEQ: usize = 16;
pub(crate) const ALLOC_OFF_PAGE_LIMIT: usize = 24;
pub(crate) const ALLOC_OFF_TXN_LIMIT: usize = 32;
pub(crate) const ALLOC_OFF_WRITE_NS: usize = 40;
pub(crate) const ALLOC_OFF_LEADER_TERM: usize = 48;
pub(crate) const ALLOC_OFF_EPOCH_HINT: usize = 56;
pub(crate) const ALLOC_OFF_WRITER_PID: usize = 64;
pub(crate) const ALLOC_OFF_RESERVED: usize = 72;

// --- Смещения chain-страницы (§4.4) ---

pub(crate) const CHAIN_OFF_PAGE_TYPE: usize = 0;
pub(crate) const CHAIN_OFF_VERSION: usize = 4;
pub(crate) const CHAIN_OFF_FLAGS: usize = 6;
pub(crate) const CHAIN_OFF_PAGE_NO: usize = 8;
pub(crate) const CHAIN_OFF_CRC: usize = 12;
pub(crate) const CHAIN_OFF_OWNER: usize = 16;
pub(crate) const CHAIN_OFF_RESERVED0: usize = 20;
pub(crate) const CHAIN_OFF_EVICTED_TXN: usize = 24;
pub(crate) const CHAIN_OFF_ENTRY: usize = 32;
pub(crate) const CHAIN_OFF_RESERVED: usize = CHAIN_OFF_ENTRY + ROOT_ENTRY_SIZE as usize;

// --- Смещения writer registry (§10.1) ---

pub(crate) const REG_OFF_PAGE_TYPE: usize = 0;
pub(crate) const REG_OFF_VERSION: usize = 4;
pub(crate) const REG_OFF_FLAGS: usize = 6;
pub(crate) const REG_OFF_PAGE_NO: usize = 8;
pub(crate) const REG_OFF_CRC: usize = 12;
pub(crate) const REG_OFF_LEADER_TERM: usize = 16;
pub(crate) const REG_OFF_WRITER_PID: usize = 24;
pub(crate) const REG_OFF_HEARTBEAT_NS: usize = 32;
pub(crate) const REG_OFF_WRITER_COUNT: usize = 40;
pub(crate) const REG_OFF_RESERVED: usize = 44;

// --- Смещения superblock v2 (§10.1) ---

pub(crate) const SB2_OFF_MAGIC: usize = 0;
pub(crate) const SB2_OFF_VERSION_MAJOR: usize = 8;
pub(crate) const SB2_OFF_VERSION_MINOR: usize = 10;
pub(crate) const SB2_OFF_PAGE_SIZE: usize = 12;
pub(crate) const SB2_OFF_PAGE_COUNT_MAX: usize = 16;
pub(crate) const SB2_OFF_FEATURE_REQUIRED: usize = 20;
pub(crate) const SB2_OFF_CHECKSUM_ALGO: usize = 28;
pub(crate) const SB2_OFF_ENDIANNESS: usize = 30;
pub(crate) const SB2_OFF_COPY: usize = 31;
pub(crate) const SB2_OFF_CRC: usize = 32;
pub(crate) const SB2_OFF_UUID: usize = 36;
pub(crate) const SB2_OFF_CREATED_NS: usize = 52;
pub(crate) const SB2_OFF_LAYOUT_A: usize = 60;
pub(crate) const SB2_OFF_LAYOUT_B: usize = 64;
pub(crate) const SB2_OFF_WRITER_REG: usize = 68;
pub(crate) const SB2_OFF_ALLOC_A: usize = 72;
pub(crate) const SB2_OFF_ALLOC_B: usize = 76;
pub(crate) const SB2_OFF_READER_TABLE: usize = 80;
pub(crate) const SB2_OFF_ROOT_DIR_FIRST: usize = 84;
pub(crate) const SB2_OFF_DATA_FIRST: usize = 88;
pub(crate) const SB2_OFF_MAX_ZONES: usize = 92;
pub(crate) const SB2_OFF_MAX_CHAIN: usize = 96;
pub(crate) const SB2_OFF_READER_SLOTS: usize = 100;
pub(crate) const SB2_OFF_SYNC_MODE: usize = 104;
pub(crate) const SB2_OFF_LAYOUT_VERSION: usize = 105;
pub(crate) const SB2_OFF_RESERVED: usize = 106;

// --- Смещения файлового слота reader table (§5.2) ---

pub(crate) const FRS_OFF_OWNER_TOKEN: usize = 0;
pub(crate) const FRS_OFF_EPOCH: usize = 8;
pub(crate) const FRS_OFF_N_PINS: usize = 16;
pub(crate) const FRS_OFF_KIND: usize = 18;
pub(crate) const FRS_OFF_FLAGS: usize = 19;
pub(crate) const FRS_OFF_PAD: usize = 20;
pub(crate) const FRS_OFF_HEARTBEAT_NS: usize = 24;
pub(crate) const FRS_OFF_PINS: usize = 32;
pub(crate) const FRS_OFF_RESERVED: usize = FRS_OFF_PINS + READER_PINS * READER_PIN_SIZE as usize;

// Const-проверки раскладки: дрейф размеров/смещений ломает сборку.
const _: () = assert!(ROOT_ENTRY_SIZE == 64);
const _: () = assert!(ROOT_OFF_CRC == 0);
const _: () = assert!(ROOT_OFF_OWNER == 4);
const _: () = assert!(ROOT_OFF_VERSION == 8);
const _: () = assert!(ROOT_OFF_ROOT_PAGE == 16);
const _: () = assert!(ROOT_OFF_PAGE_LIMIT == 20);
const _: () = assert!(ROOT_OFF_PREV_RECORD == 24);
const _: () = assert!(ROOT_OFF_META_ROOT == 32);
const _: () = assert!(ROOT_OFF_IXFR_ROOT == 36);
const _: () = assert!(ROOT_OFF_DELETED_TXN == 40);
const _: () = assert!(ROOT_OFF_RRSET_COUNT == 48);
const _: () = assert!(ROOT_OFF_SOA_SERIAL == 52);
const _: () = assert!(ROOT_OFF_FREE_HEAD == 56);
const _: () = assert!(ROOT_OFF_TREE_LEVEL == 60);
const _: () = assert!(ROOT_OFF_STATE == 62);
const _: () = assert!(ROOT_OFF_FLAGS == 63);
const _: () = assert!(ROOT_BLOCK_SIZE == 256);
const _: () = assert!(ZONES_PER_DIR_PAGE * ROOT_BLOCK_SIZE == PAGE_SIZE_V2);
const _: () = assert!(LAYOUT_HEAD_RECORD_SIZE == 512);
const _: () = assert!(LH_OFF_RESERVED < LAYOUT_HEAD_RECORD_SIZE as usize);
const _: () = assert!(ALLOC_RECORD_SIZE == 256);
const _: () = assert!(ALLOC_OFF_WRITER_PID == 64);
const _: () = assert!(ALLOC_OFF_RESERVED == 72);
const _: () = assert!(CHAIN_OFF_ENTRY == 32);
const _: () = assert!(CHAIN_OFF_RESERVED == 96);
const _: () = assert!(READER_SLOT_SIZE_V2 == 128);
const _: () = assert!(FRS_OFF_PINS == 32);
const _: () = assert!(FRS_OFF_RESERVED == 128);
const _: () = assert!(READER_PIN_SIZE as usize == 16);
const _: () = assert!(ALLOC_EXTENT_PAGES > 0);
const _: () = assert!(ALLOC_THREAD_CACHE_PAGES >= ALLOC_EXTENT_PAGES);
