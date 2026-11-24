//! `ParallelStore` — фаза A параллельной записи v2.0.
//!
//! Стор владеет файлом, layout-геометрией, ring-головами в памяти, аллокатором,
//! in-process пинами и durable-барьером `ALLOC_RECORD`. Публикация корня — две
//! фазы (данные + `ALLOC_RECORD` + chain → `fdatasync`; две копии `RootEntry` →
//! `fdatasync`), затем публикация головы в памяти.
//!
//! B+tree, per-zone пулы, group commit и межпроцессная запись — фаза B.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering, fence};
use std::sync::{Mutex, MutexGuard};

use rustix::fs::{FileType, Mode, OFlags, fdatasync, fstat, fsync, ftruncate, open as fs_open};

use crate::cache::PageCache;
use crate::consts::MAX_TREE_DEPTH;
use crate::lock::WriterLock;
use crate::parallel::alloc::{AllocHandle, AllocTicket, Allocator};
use crate::parallel::consts::{
    ALLOC_RECORD_SEQ_FIRST, ALLOC_RECORD_SIZE, DEFAULT_MAX_ZONES, DEFAULT_PAGE_COUNT_MAX,
    LAYOUT_HEAD_RECORD_SIZE, LEADER_TERM_M1, MAX_LEAK_RATIO, MAX_ROOT_CHAIN_HOPS,
    MAX_ROOT_CHAIN_PAGES, PAGE_ALLOC_RECORD_A, PAGE_ALLOC_RECORD_B, PAGE_LAYOUT_HEAD_A,
    PAGE_LAYOUT_HEAD_B, PAGE_SIZE_V2, PIN_ATTEMPTS, READER_SLOTS_V2, ROOT_ENTRY_SIZE,
    ROOT_VERSIONS,
};
use crate::parallel::error::{FatalKind, ParallelError, V2CorruptKind};
use crate::parallel::freepool::{BucketImages, FreeChain};
use crate::parallel::geometry::Geometry;
use crate::parallel::layout::{
    AllocRecord, LayoutHead, SuperblockV2, SyncModeV2, WriterRegistry, new_instance_uuid,
};
use crate::parallel::pagecache::{DEFAULT_PAGE_CACHE_V2_ENTRIES, PageCacheV2, PageCacheV2Stats};
use crate::parallel::pins::{EpochGuard, FreezeGuard, GcState, PinGuard, PinTable, Reader};
use crate::parallel::recovery::{
    FsckLiteReport, OpenConfigV2, RecoveryReport, merge_fatal, read_at, recover, scan_roots,
};
use crate::parallel::ring::Ring;
use crate::parallel::root::{RootEntry, RootFlags};

/// Сколько guard должен оставаться нечётным, чтобы зона считалась застрявшей.
const GUARD_STUCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Конфигурация создания v2-файла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreConfig {
    /// Жёсткий лимит страниц файла.
    pub page_count_max: u32,
    /// Максимальное число зон (слот 0 — каталог).
    pub max_zones: u32,
    /// Лимит chain-страниц на зону.
    pub max_root_chain_pages: u32,
    /// Число in-process слотов читателей.
    pub reader_slots: u32,
    /// Ёмкость кеша валидированных страниц (0 — кеш отключён).
    pub page_cache_entries: usize,
    /// Режим durability; фаза A поддерживает только [`SyncModeV2::Sync`].
    pub sync_mode: SyncModeV2,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            page_count_max: DEFAULT_PAGE_COUNT_MAX,
            max_zones: DEFAULT_MAX_ZONES,
            max_root_chain_pages: MAX_ROOT_CHAIN_PAGES,
            reader_slots: READER_SLOTS_V2,
            page_cache_entries: DEFAULT_PAGE_CACHE_V2_ENTRIES,
            sync_mode: SyncModeV2::Sync,
        }
    }
}

impl StoreConfig {
    /// Компактная конфигурация для тестов/бенчей.
    #[must_use]
    pub fn small(max_zones: u32, page_count_max: u32) -> Self {
        Self {
            page_count_max,
            max_zones,
            max_root_chain_pages: 64,
            ..Self::default()
        }
    }
}

/// Точка отказа для crash-injection (всегда вызывается, если хук установлен).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CrashPoint {
    /// До записи `ALLOC_RECORD` (страницы данных уже могли быть записаны).
    BeforeAllocRecord,
    /// После записи `ALLOC_RECORD` и chain-страниц, до `fdatasync` фазы 1.
    AfterPhase1Writes,
    /// После `fdatasync` фазы 1.
    AfterPhase1Fsync,
    /// Перед записью копии A корня.
    BeforeRootWrite,
    /// После записи копии A корня, до копии B.
    AfterRootCopyA,
    /// После записи обеих копий корня, до `fdatasync` фазы 2.
    AfterRootCopyB,
    /// После `fdatasync` фазы 2, до публикации головы в памяти.
    AfterPhase2Fsync,
    /// Перед публикацией головы в памяти.
    BeforeHeadPublish,
    /// После публикации головы в памяти (публикация подтверждена).
    AfterHeadPublish,
}

/// Хук crash-injection (тестовый harness; в production не устанавливается).
pub trait CrashHook: Send + Sync {
    /// Вызывается в точке [`CrashPoint`].
    fn at(&self, point: CrashPoint);
}

/// Хук инъекции ошибок ввода-вывода (тестовый harness B2b).
///
/// Проверяется перед каждым `fdatasync`; `true` — синхронно вернуть `EIO`.
pub trait IoFaultHook: Send + Sync {
    /// Инжектировать отказ на текущем `fdatasync`.
    fn fail_sync(&self) -> bool;
}

/// Запрос одной зоны для [`ParallelStore::commit_group`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupCommitRequest {
    /// Запись корня (её `owner_zone`/`version` должны быть валидны).
    pub entry: RootEntry,
    /// Страницы, освобождённые этим коммитом (bucket `drop_txn = version`).
    pub drops: Vec<u32>,
    /// Режим durability; у всех запросов одной группы должен совпадать.
    pub durability: SyncModeV2,
}

impl GroupCommitRequest {
    /// Запрос без освобождённых страниц.
    #[must_use]
    pub fn new(entry: RootEntry, durability: SyncModeV2) -> Self {
        Self {
            entry,
            drops: Vec::new(),
            durability,
        }
    }
}

/// Итог публикации корня.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishOutcome {
    /// Зона.
    pub zone: u32,
    /// Опубликованная версия (`txn`).
    pub version: u64,
    /// Durable `page_limit` после фазы 1.
    pub page_limit: u64,
    /// `prev_record` записи (chain-голова или 0).
    pub prev_record: u32,
    /// Вытесненная в chain страница (если была).
    pub evicted_page: Option<u32>,
}

/// Отчёт об утечках (`[data_first, DP)` + aborted `[DP, cursor)`).
#[derive(Debug, Clone, PartialEq)]
pub struct LeakReport {
    /// Страницы `[data_first, DP)`, недостижимые из структур.
    pub leaked_pages: u64,
    /// Номера утёкших страниц.
    pub leaked_page_ids: Vec<u32>,
    /// Ёмкость проверенной области `[data_first, DP)`.
    pub durable_pages: u64,
    /// Оценка `[DP, cursor)` — выделено, но не опубликовано/не durable.
    pub aborted_pages: u64,
    /// `leaked_pages / durable_pages`.
    pub ratio: f64,
    /// Порог [`MAX_LEAK_RATIO`].
    pub max_ratio: f64,
    /// Доля утечек выше порога (алерт `pw_alloc_leaked_pages_estimate`).
    pub exceeds_max_ratio: bool,
    /// File-fatal причина (пересечение множеств).
    pub fatal: Option<FatalKind>,
    /// Диагностика.
    pub issues: Vec<String>,
}

/// Итог `fsck --repair` (возврат утечек в пул).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairReport {
    /// Страниц возвращено в durable free-пул.
    pub repaired_pages: u64,
    /// Остаток утечек после повторной проверки.
    pub remaining_leaks: u64,
    /// Утечки, которые нельзя вернуть безопасно: они лежат в диапазоне
    /// повреждённых зон (пока зона в карантине, её страницы не трогаются).
    pub deferred_leaks: u64,
    /// Зоны, переведённые в read-only (`NEEDS_FSCK`) без правки данных.
    pub quarantined_zones: Vec<u32>,
    /// Нет пересечений; все утечки либо возвращены, либо отложены, а
    /// повреждённые зоны изолированы.
    pub ok: bool,
    /// Диагностика.
    pub issues: Vec<String>,
}

/// Снимок счётчиков стора.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoreStats {
    /// CAS-повторы страниц.
    pub alloc_cas_retries: u64,
    /// CAS-повторы `txn`.
    pub txn_cas_retries: u64,
    /// Переполнения 6 пинов (EPOCH-пин).
    pub reader_pin_overflow: u64,
    /// Публикации корней.
    pub publications: u64,
    /// Вытеснения в chain.
    pub chain_evictions: u64,
    /// Отказы `zone_snapshot` по конкуренции.
    pub reader_contended: u64,
    /// Деградации зон.
    pub zone_degraded: u64,
    /// Страниц выдано из пула (включая never-published).
    pub reclaimed_pages: u64,
    /// Страниц chain освобождено GC.
    pub chain_freed_pages: u64,
    /// Страниц передано donation-пулу.
    pub donated_pages: u64,
    /// Попаданий в кеш валидированных страниц.
    pub page_cache_hits: u64,
    /// Промахов кеша валидированных страниц.
    pub page_cache_misses: u64,
    /// Выполненных групп group commit.
    pub group_commits: u64,
    /// Зона-коммитов, прошедших через группы.
    pub group_members: u64,
    /// `fdatasync` в group commit (для `Sync` — ровно `2 * group_commits`).
    pub group_fsyncs: u64,
    /// Максимальный размер группы (зон).
    pub group_max_members: u64,
    /// Коммитов, отменённых в группе (retryable `ReaderContended`).
    pub group_aborted: u64,
    /// Оценка утечки `[DP, cursor)` (выделено, но не опубликовано).
    pub aborted_pages_estimate: u64,
}

/// Открытый v2-стор.
///
/// Обёртка [`std::sync::Arc`] рекомендована: все методы принимают `&self`.
pub struct ParallelStore {
    path: PathBuf,
    file: File,
    _lock: Option<WriterLock>,
    geometry: Geometry,
    superblock: SuperblockV2,
    layout: LayoutHead,
    allocator: Allocator,
    alloc_durable: Mutex<AllocDurable>,
    durable_page_limit: AtomicU64,
    durable_txn_limit: AtomicU64,
    published_txn: AtomicU64,
    /// Per-zone `D_z` (durable version): двигается только `Sync`-группой или
    /// `sync()`. `Flush`/`Memory` публикуют голову в памяти, но `D_z` не
    /// трогают (§7.2).
    durable_versions: Box<[AtomicU64]>,
    /// Режим durability файла (superblock `sync_mode`).
    file_mode: SyncModeV2,
    /// Липкий `Sync`: выставляется после первой durable-группы/`sync()`.
    sticky_sync: std::sync::atomic::AtomicBool,
    heads: Box<[PublishedHead]>,
    zone_guard: Box<[AtomicU32]>,
    zone_state: Box<[AtomicU8]>,
    chain_depth: Box<[AtomicU32]>,
    pins: PinTable,
    gc: GcState,
    leases: Box<[Mutex<()>]>,
    raw_cache: Option<PageCacheV2>,
    node_cache: Option<PageCache>,
    pools: Box<[Mutex<FreePoolShard>]>,
    donation: Mutex<Vec<DonationEntry>>,
    fatal: Mutex<Option<FatalKind>>,
    read_only: bool,
    crash_hook: Option<Box<dyn CrashHook>>,
    io_fault_hook: Option<Box<dyn IoFaultHook>>,
    /// Моделируемая задержка `fdatasync` (тесты/бенчи; 0 — выключено).
    sync_delay_ns: AtomicU64,
    /// Сериализация моделируемого fsync (как у одного inode).
    sync_delay_gate: Mutex<()>,
    stats: StatsCounters,
    report: RecoveryReport,
}

struct AllocDurable {
    seq: u64,
    page_limit: u64,
    txn_limit: u64,
}

/// Per-zone состояние рекламации (под шардированным `Mutex`).
#[derive(Debug, Clone, Default)]
struct ZoneFreePool {
    chain: FreeChain,
    immediate: Vec<u32>,
    loaded: bool,
    dirty: bool,
}

/// Шард пулов: разные зоны в одном шарде сериализуют только писателей.
#[derive(Debug, Default)]
struct FreePoolShard {
    zones: HashMap<u32, ZoneFreePool>,
}

/// Страница donation-пула (`owner_zone` освобождается при выдаче).
#[derive(Debug, Clone, Copy)]
struct DonationEntry {
    page: u32,
    donated_at: u64,
}

/// Подготовленная рекламация: образы bucket-страниц и новый `free_head`.
struct ReclaimPrep {
    pool: Option<ZoneFreePool>,
    free_head: u32,
    images: BucketImages,
    chain_page: Option<u32>,
    /// Максимальный номер страницы, упомянутой bucket'ами/free-списком.
    max_page: u32,
}

/// Подготовленный (но ещё не записанный) коммит зоны.
///
/// План создаётся в потоке писателя (lease зоны удерживается вызывающим) и
/// выполняется координатором group commit: это позволяет собрать несколько зон
/// в одну пару `fdatasync` (§7.1).
pub(crate) struct PreparedPublish {
    /// Зона.
    pub zone: u32,
    /// Итоговая запись корня (`free_head`/`prev_record`/лимит уже проставлены).
    pub record: RootEntry,
    /// Координаты ячейки ring.
    pub slot: crate::parallel::geometry::ZoneSlot,
    /// Вытеснение в chain: `(страница, вытесненная запись, evicted_txn)`.
    chain_write: Option<(u32, RootEntry, u64)>,
    /// Staging-пул, bucket-образы и `free_head`.
    reclaim: ReclaimPrep,
    /// Минимальный `page_limit_at_commit`.
    minimum_limit: u64,
    /// Прежняя ячейка ring (`version % 4`) на момент плана.
    old: Option<RootEntry>,
    /// Оценка байтов коммита для лимитов группы.
    weight: u64,
}

impl PreparedPublish {
    /// Оценка байтов запроса (для порогов группы и backpressure).
    #[must_use]
    pub const fn weight(&self) -> u64 {
        self.weight
    }
}

#[derive(Default)]
struct StatsCounters {
    publications: AtomicU64,
    chain_evictions: AtomicU64,
    reader_contended: AtomicU64,
    zone_degraded: AtomicU64,
    reclaimed_pages: AtomicU64,
    chain_freed_pages: AtomicU64,
    donated_pages: AtomicU64,
    group_commits: AtomicU64,
    group_members: AtomicU64,
    group_fsyncs: AtomicU64,
    group_max_members: AtomicU64,
    group_aborted: AtomicU64,
}

const ZONE_DEGRADED: u8 = 1 << 0;
const ZONE_NEEDS_FSCK: u8 = 1 << 1;
const CHAIN_UNKNOWN: u32 = u32::MAX;
const LEASE_SHARDS: usize = 256;
const FREE_POOL_SHARDS: usize = 256;
static FALLBACK_LEASE: Mutex<()> = Mutex::new(());
/// Запасной шард пула (используется только при нарушении индексации).
static FALLBACK_POOL: std::sync::LazyLock<Mutex<FreePoolShard>> =
    std::sync::LazyLock::new(|| Mutex::new(FreePoolShard::default()));

impl std::fmt::Debug for ParallelStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParallelStore")
            .field("path", &self.path)
            .field("geometry", &self.geometry)
            .field("durable_page_limit", &self.durable_page_limit())
            .field("durable_txn_limit", &self.durable_txn_limit())
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

impl ParallelStore {
    /// Создаёт новый файл v2.
    ///
    /// # Errors
    ///
    /// `Busy` — lock занят; `Io` — файл существует/ошибка записи;
    /// `Unsupported` — режим не `Sync`; `MapFull`/`InvalidArgument` — геометрия.
    pub fn create(path: &Path, config: StoreConfig) -> Result<Self, ParallelError> {
        let geometry = Geometry::new(
            config.max_zones,
            config.page_count_max,
            config.max_root_chain_pages,
            config.reader_slots,
        )?;
        let lock = acquire_lock(path)?;
        let file = open_file(path, OFlags::CREATE | OFlags::EXCL)?;
        let lock_path = WriterLock::path_for(path);
        let result = Self::create_locked(
            path,
            geometry,
            file,
            lock,
            config.page_cache_entries,
            config.sync_mode,
        );
        match result {
            Ok(store) => Ok(store),
            Err(error) => {
                let _ = std::fs::remove_file(path);
                let _ = std::fs::remove_file(&lock_path);
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn create_locked(
        path: &Path,
        geometry: Geometry,
        file: File,
        lock: WriterLock,
        page_cache_entries: usize,
        sync_mode: SyncModeV2,
    ) -> Result<Self, ParallelError> {
        ftruncate(&file, geometry.file_size()).map_err(std::io::Error::from)?;
        let uuid = new_instance_uuid();
        let superblock_a = SuperblockV2::for_geometry(geometry, 0, uuid, sync_mode);
        let superblock_b = SuperblockV2::for_geometry(geometry, 1, uuid, sync_mode);
        write_at(&file, 0, &superblock_a.encode())?;
        write_at(&file, u64::from(PAGE_SIZE_V2), &superblock_b.encode())?;
        let layout_a = LayoutHead::for_geometry(geometry, PAGE_LAYOUT_HEAD_A, 1, 1, 0);
        let layout_b = LayoutHead::for_geometry(geometry, PAGE_LAYOUT_HEAD_B, 1, 1, 0);
        write_at(
            &file,
            u64::from(PAGE_LAYOUT_HEAD_A) * u64::from(PAGE_SIZE_V2),
            &layout_a.encode(),
        )?;
        write_at(
            &file,
            u64::from(PAGE_LAYOUT_HEAD_B) * u64::from(PAGE_SIZE_V2),
            &layout_b.encode(),
        )?;
        let registry = WriterRegistry {
            leader_term: LEADER_TERM_M1,
            writer_pid: u64::from(std::process::id()),
            heartbeat_unix_ns: 0,
            writer_count: 0,
        };
        write_at(
            &file,
            u64::from(geometry.page_writer_reg()) * u64::from(PAGE_SIZE_V2),
            &registry.encode(),
        )?;
        let initial_a =
            AllocRecord::initial(PAGE_ALLOC_RECORD_A, u64::from(geometry.page_data_first()));
        let initial_b =
            AllocRecord::initial(PAGE_ALLOC_RECORD_B, u64::from(geometry.page_data_first()));
        write_at(
            &file,
            u64::from(PAGE_ALLOC_RECORD_A) * u64::from(PAGE_SIZE_V2),
            &initial_a.encode(),
        )?;
        write_at(
            &file,
            u64::from(PAGE_ALLOC_RECORD_B) * u64::from(PAGE_SIZE_V2),
            &initial_b.encode(),
        )?;
        retry_eintr(|| fdatasync(&file)).map_err(std::io::Error::from)?;
        sync_parent_dir(path)?;

        let heads = allocate_heads(geometry.max_zones())?;
        let zone_guard = allocate_u32(geometry.max_zones(), 0)?;
        let zone_state = allocate_u8(geometry.max_zones(), 0)?;
        let chain_depth = allocate_u32(geometry.max_zones(), CHAIN_UNKNOWN)?;
        let durable_versions = allocate_u64(geometry.max_zones(), 0)?;
        let pins = PinTable::new(geometry.reader_slots().min(READER_SLOTS_V2))?;
        let gc = GcState::new(geometry.max_zones())?;
        let leases = allocate_leases()?;
        let (raw_cache, node_cache) = make_caches(page_cache_entries);
        let dp = u64::from(geometry.page_data_first());
        let allocator = Allocator::new(dp, 2, geometry.page_count_max())?;
        let report = RecoveryReport {
            superblock_source: crate::parallel::error::CopySource::Both,
            torn_superblock: false,
            layout_source: crate::parallel::error::CopySource::Both,
            torn_layout: false,
            alloc_source: crate::parallel::error::CopySource::Both,
            torn_alloc: false,
            durable_page_limit: dp,
            durable_txn_limit: 1,
            next_txn: 2,
            max_root_page_limit: dp,
            max_root_version: 0,
            zones_with_roots: 0,
            torn_root_copies: 0,
            diverged_root_copies: 0,
            zone_issues: 0,
            fatal: None,
        };
        Ok(Self {
            path: path.to_path_buf(),
            file,
            _lock: Some(lock),
            geometry,
            superblock: superblock_a,
            layout: layout_a,
            allocator,
            alloc_durable: Mutex::new(AllocDurable {
                seq: ALLOC_RECORD_SEQ_FIRST,
                page_limit: dp,
                txn_limit: 1,
            }),
            durable_page_limit: AtomicU64::new(dp),
            durable_txn_limit: AtomicU64::new(1),
            published_txn: AtomicU64::new(0),
            durable_versions,
            file_mode: sync_mode,
            sticky_sync: AtomicBool::new(sync_mode == SyncModeV2::Sync),
            heads,
            zone_guard,
            zone_state,
            chain_depth,
            pins,
            gc,
            leases,
            raw_cache,
            node_cache,
            pools: allocate_pools()?,
            donation: Mutex::new(Vec::new()),
            fatal: Mutex::new(None),
            read_only: false,
            crash_hook: None,
            io_fault_hook: None,
            sync_delay_ns: AtomicU64::new(0),
            sync_delay_gate: Mutex::new(()),
            stats: StatsCounters::default(),
            report,
        })
    }

    /// Открывает существующий файл v2 и выполняет recovery.
    ///
    /// # Errors
    ///
    /// `Busy` — lock занят; `Corrupt`/`Unsupported`/`Io` — recovery не смог
    /// восстановить доверенную раскладку.
    pub fn open(path: &Path, config: OpenConfigV2) -> Result<Self, ParallelError> {
        let lock = if config.writer_lock && !config.read_only {
            Some(acquire_lock(path)?)
        } else {
            None
        };
        let flags = if config.read_only {
            OFlags::RDONLY
        } else {
            OFlags::RDWR
        };
        let file = open_existing(path, flags)?;
        let stat = fstat(&file).map_err(std::io::Error::from)?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            return Err(ParallelError::NotRegularFile);
        }
        let file_size = u64::try_from(stat.st_size).unwrap_or(0);
        let recovered = recover(&file, file_size)?;
        let geometry = recovered.geometry;
        let heads = allocate_heads(geometry.max_zones())?;
        for (index, head) in recovered.heads.iter().enumerate() {
            if let Some(entry) = head
                && let Some(block) = heads.get(index)
            {
                block.store(entry);
            }
        }
        let mut zone_state = allocate_u8(geometry.max_zones(), 0)?;
        for (zone, _field) in &recovered.zone_issues {
            if let Some(flag) = zone_state.get_mut(*zone as usize) {
                *flag = AtomicU8::new(ZONE_DEGRADED | ZONE_NEEDS_FSCK);
            }
        }
        // `fsck --repair` мог изолировать зону durable-флагом `NEEDS_FSCK`:
        // после перезапуска она снова read-only до ручного разбора.
        apply_root_flags(&mut zone_state, &recovered.heads);
        let zone_guard = allocate_u32(geometry.max_zones(), 0)?;
        let chain_depth = allocate_u32(geometry.max_zones(), CHAIN_UNKNOWN)?;
        let durable_versions = allocate_u64(geometry.max_zones(), 0)?;
        for (index, head) in recovered.heads.iter().enumerate() {
            if let Some(entry) = head
                && let Some(slot) = durable_versions.get(index)
            {
                slot.store(entry.version, Ordering::Release);
            }
        }
        let pins = PinTable::new(geometry.reader_slots().min(READER_SLOTS_V2))?;
        let gc = GcState::new(geometry.max_zones())?;
        let leases = allocate_leases()?;
        let (raw_cache, node_cache) = make_caches(config.page_cache_entries);
        let allocator = Allocator::new(
            recovered.durable_page_limit,
            recovered.next_txn,
            geometry.page_count_max(),
        )?;
        let published_txn = recovered.report.max_root_version;
        let fatal = recovered.report.fatal;
        let file_mode = recovered.superblock.sync_mode;
        let sticky = file_mode == SyncModeV2::Sync || recovered.durable_txn_limit > 1;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            _lock: lock,
            geometry,
            superblock: recovered.superblock,
            layout: recovered.layout,
            allocator,
            alloc_durable: Mutex::new(AllocDurable {
                seq: recovered.alloc_seq.max(ALLOC_RECORD_SEQ_FIRST),
                page_limit: recovered.durable_page_limit,
                txn_limit: recovered.durable_txn_limit,
            }),
            durable_page_limit: AtomicU64::new(recovered.durable_page_limit),
            durable_txn_limit: AtomicU64::new(recovered.durable_txn_limit),
            published_txn: AtomicU64::new(published_txn),
            durable_versions,
            file_mode,
            sticky_sync: AtomicBool::new(sticky),
            heads,
            zone_guard,
            zone_state,
            chain_depth,
            pins,
            gc,
            leases,
            raw_cache,
            node_cache,
            pools: allocate_pools()?,
            donation: Mutex::new(Vec::new()),
            fatal: Mutex::new(fatal),
            read_only: config.read_only,
            crash_hook: None,
            io_fault_hook: None,
            sync_delay_ns: AtomicU64::new(0),
            sync_delay_gate: Mutex::new(()),
            stats: StatsCounters::default(),
            report: recovered.report,
        })
    }

    /// Устанавливает crash-хук (только до публикации стора между потоками).
    pub fn set_crash_hook(&mut self, hook: Box<dyn CrashHook>) {
        self.crash_hook = Some(hook);
    }

    /// Устанавливает хук инъекции ошибок `fdatasync` (только тесты B2b).
    pub fn set_io_fault_hook(&mut self, hook: Box<dyn IoFaultHook>) {
        self.io_fault_hook = Some(hook);
    }

    /// Моделирует стоимость `fdatasync` (тесты/бенчи; production — 0).
    ///
    /// Позволяет измерить выигрыш group commit на устройстве, где fsync
    /// доминирует, независимо от скорости локальной ФС.
    pub fn set_sync_delay(&mut self, delay: std::time::Duration) {
        self.sync_delay_ns.store(
            u64::try_from(delay.as_nanos()).unwrap_or(u64::MAX),
            Ordering::Release,
        );
    }

    /// Путь файла.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Геометрия.
    #[must_use]
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Superblock.
    #[must_use]
    pub const fn superblock(&self) -> &SuperblockV2 {
        &self.superblock
    }

    /// `LayoutHead`.
    #[must_use]
    pub const fn layout(&self) -> &LayoutHead {
        &self.layout
    }

    /// Отчёт recovery.
    #[must_use]
    pub const fn recovery_report(&self) -> &RecoveryReport {
        &self.report
    }

    /// Durable `page_limit` (`DP`).
    #[must_use]
    pub fn durable_page_limit(&self) -> u64 {
        self.durable_page_limit.load(Ordering::Acquire)
    }

    /// Durable `txn_limit` (`DT`).
    #[must_use]
    pub fn durable_txn_limit(&self) -> u64 {
        self.durable_txn_limit.load(Ordering::Acquire)
    }

    /// Максимальный опубликованный `txn` (`e0` для пинов).
    #[must_use]
    pub fn published_txn(&self) -> u64 {
        self.published_txn.load(Ordering::Acquire)
    }

    /// Аллокатор.
    #[must_use]
    pub const fn allocator(&self) -> &Allocator {
        &self.allocator
    }

    /// Per-thread handle аллокатора.
    #[must_use]
    pub fn alloc_handle(&self) -> AllocHandle<'_> {
        self.allocator.handle()
    }

    /// Handle без локального кеша (короткоживущие writer'ы).
    #[must_use]
    pub fn alloc_handle_exact(&self) -> AllocHandle<'_> {
        self.allocator.handle_exact()
    }

    /// Резервирует ровно `pages` страниц.
    ///
    /// # Errors
    ///
    /// `MapFull` — лимит файла; `InvalidArgument` — `pages == 0`.
    pub fn reserve_pages(&self, pages: u32) -> Result<AllocTicket, ParallelError> {
        self.allocator.reserve_exact(pages)
    }

    /// Создаёт in-process читателя.
    ///
    /// # Errors
    ///
    /// `TooManyReaders` — все слоты заняты.
    pub fn reader(&self) -> Result<Reader<'_>, ParallelError> {
        Reader::register(&self.pins)
    }

    /// Текущая причина `write_locked`.
    #[must_use]
    pub fn fatal(&self) -> Option<FatalKind> {
        *lock_unpoison(&self.fatal)
    }

    /// Счётчики.
    #[must_use]
    pub fn stats(&self) -> StoreStats {
        let (page_cache_hits, page_cache_misses) =
            self.raw_cache.as_ref().map_or((0, 0), |cache| {
                let stats = cache.stats();
                (stats.hits, stats.misses)
            });
        StoreStats {
            alloc_cas_retries: self.allocator.cas_retries(),
            txn_cas_retries: self.allocator.txn_cas_retries(),
            reader_pin_overflow: self.pins.overflow_total(),
            publications: self.stats.publications.load(Ordering::Relaxed),
            chain_evictions: self.stats.chain_evictions.load(Ordering::Relaxed),
            reader_contended: self.stats.reader_contended.load(Ordering::Relaxed),
            zone_degraded: self.stats.zone_degraded.load(Ordering::Relaxed),
            reclaimed_pages: self.stats.reclaimed_pages.load(Ordering::Relaxed),
            chain_freed_pages: self.stats.chain_freed_pages.load(Ordering::Relaxed),
            donated_pages: self.stats.donated_pages.load(Ordering::Relaxed),
            page_cache_hits,
            page_cache_misses,
            group_commits: self.stats.group_commits.load(Ordering::Relaxed),
            group_members: self.stats.group_members.load(Ordering::Relaxed),
            group_fsyncs: self.stats.group_fsyncs.load(Ordering::Relaxed),
            group_max_members: self.stats.group_max_members.load(Ordering::Relaxed),
            group_aborted: self.stats.group_aborted.load(Ordering::Relaxed),
            aborted_pages_estimate: self
                .allocator
                .leaked_pages(self.durable_page_limit.load(Ordering::Acquire)),
        }
    }

    /// Режим durability файла (superblock `sync_mode`).
    #[must_use]
    pub const fn file_mode(&self) -> SyncModeV2 {
        self.file_mode
    }

    /// Эффективный режим с учётом липкого `Sync` (§7.2).
    #[must_use]
    pub fn effective_mode(&self) -> SyncModeV2 {
        if self.sticky_sync.load(Ordering::Acquire) {
            SyncModeV2::Sync
        } else {
            self.file_mode
        }
    }

    /// `D_z` — durable-версия зоны (двигается только `Sync`/`sync()`).
    #[must_use]
    pub fn durable_version(&self, zone: u32) -> u64 {
        self.durable_versions
            .get(zone as usize)
            .map_or(0, |value| value.load(Ordering::Acquire))
    }

    /// Включает липкий `Sync` (после durable-группы или `sync()`).
    fn promote_sticky(&self) {
        self.sticky_sync.store(true, Ordering::Release);
    }

    /// Проверяет, что `mode` не слабее эффективного режима файла.
    ///
    /// # Errors
    ///
    /// [`ParallelError::DurabilityBelowFileMode`].
    pub fn check_durability(&self, mode: SyncModeV2) -> Result<(), ParallelError> {
        let effective = self.effective_mode();
        if mode.durability_rank() < effective.durability_rank() {
            return Err(ParallelError::DurabilityBelowFileMode {
                requested: mode,
                effective,
            });
        }
        Ok(())
    }

    /// Метрики кеша валидированных страниц (v2).
    #[must_use]
    pub fn page_cache_stats(&self) -> PageCacheV2Stats {
        self.raw_cache
            .as_ref()
            .map_or(PageCacheV2Stats::default(), PageCacheV2::stats)
    }

    /// Метрики кеша узлов B+tree (v1 `PageCache`).
    #[must_use]
    pub fn node_cache_stats(&self) -> crate::cache::CacheStats {
        self.node_cache.as_ref().map_or(
            crate::cache::CacheStats {
                hits: 0,
                misses: 0,
                entries: 0,
                capacity: 0,
            },
            crate::cache::PageCache::stats,
        )
    }

    /// Кеш валидированных страниц v2 (для `ReaderIo`/`WriteIo`).
    pub(crate) const fn raw_page_cache(&self) -> Option<&PageCacheV2> {
        self.raw_cache.as_ref()
    }

    /// Кеш валидированных узлов (горячий read-path `ZoneReader`).
    #[must_use]
    pub const fn node_cache(&self) -> Option<&PageCache> {
        self.node_cache.as_ref()
    }

    /// Текущий `high_water` (первая невыданная страница).
    #[must_use]
    pub fn high_water(&self) -> u64 {
        self.allocator.cursor()
    }

    /// Число страниц данных, выданных аллокатором (без пролога геометрии).
    #[must_use]
    pub fn allocated_data_pages(&self) -> u64 {
        self.allocator
            .cursor()
            .saturating_sub(u64::from(self.geometry.page_data_first()))
    }

    /// Опубликованная голова зоны (включая tombstone).
    #[must_use]
    pub fn zone_head(&self, zone: u32) -> Option<RootEntry> {
        self.head_entry(zone)
    }

    /// Число активных in-process пинов (диагностика/метрики).
    #[must_use]
    pub fn active_pins(&self) -> usize {
        self.pins.snapshot_pins().len()
    }

    /// Число страниц в per-zone пулах (durable + in-memory).
    #[must_use]
    pub fn free_pool_pages(&self) -> u64 {
        let mut total = 0_u64;
        for shard in &self.pools {
            let guard = lock_unpoison(shard);
            for pool in guard.zones.values() {
                total = total.saturating_add(
                    u64::try_from(pool.chain.page_count().saturating_add(pool.immediate.len()))
                        .unwrap_or(u64::MAX),
                );
            }
        }
        total
    }

    /// Число страниц в donation-пуле.
    #[must_use]
    pub fn donation_pages(&self) -> u64 {
        let guard = lock_unpoison(&self.donation);
        u64::try_from(guard.len()).unwrap_or(u64::MAX)
    }

    fn pool_shard(&self, zone: u32) -> &Mutex<FreePoolShard> {
        let index = (zone as usize) % FREE_POOL_SHARDS;
        self.pools.get(index).unwrap_or(&FALLBACK_POOL)
    }

    fn load_zone_chain(&self, zone: u32) -> Result<FreeChain, ParallelError> {
        match self.head(zone) {
            Some(head) if head.free_head != 0 => {
                FreeChain::load(&self.file, &self.geometry, zone, &head)
            }
            _ => Ok(FreeChain::empty()),
        }
    }

    /// Берёт страницу из per-zone пула (или donation), если она выдаваема.
    ///
    /// `current_version` — версия планируемого коммита (`drop_txn < V`).
    ///
    /// # Errors
    ///
    /// `Corrupt` — битая durable-цепочка bucket'ов.
    pub(crate) fn take_pool_page(
        &self,
        zone: u32,
        current_version: u64,
    ) -> Result<Option<u32>, ParallelError> {
        let durable = self.durable_version(zone);
        let rv = self.gc.reclaim_version(zone, durable);
        {
            let mut shard = lock_unpoison(self.pool_shard(zone));
            let entry = shard.zones.entry(zone).or_default();
            if !entry.loaded {
                entry.chain = self.load_zone_chain(zone)?;
                entry.loaded = true;
            }
            if let Some(page) = entry.immediate.pop() {
                self.stats.reclaimed_pages.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(page));
            }
            if let Some(page) = entry.chain.take_eligible(durable, rv, current_version) {
                entry.dirty = true;
                self.stats.reclaimed_pages.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(page));
            }
        }
        Ok(self.take_donation_page())
    }

    /// Забирает eligible-страницы пула зоны под donation (без гейта выдачи).
    pub(crate) fn take_zone_pool_pages(
        &self,
        zone: u32,
        current_version: u64,
        max_pages: u32,
    ) -> Result<Vec<u32>, ParallelError> {
        let durable = self.durable_version(zone);
        let rv = self.gc.reclaim_version(zone, durable);
        let mut pages = Vec::new();
        let mut shard = lock_unpoison(self.pool_shard(zone));
        let entry = shard.zones.entry(zone).or_default();
        if !entry.loaded {
            entry.chain = self.load_zone_chain(zone)?;
            entry.loaded = true;
        }
        while u32::try_from(pages.len()).unwrap_or(u32::MAX) < max_pages {
            let page = entry
                .immediate
                .pop()
                .or_else(|| entry.chain.take_eligible(durable, rv, current_version));
            match page {
                Some(page) => pages.push(page),
                None => break,
            }
        }
        if !pages.is_empty() {
            entry.dirty = true;
        }
        Ok(pages)
    }

    /// Возвращает страницы в пул зоны как `NEVER_PUBLISHED`.
    pub(crate) fn return_pages(&self, zone: u32, pages: &[u32]) {
        if pages.is_empty() {
            return;
        }
        let mut shard = lock_unpoison(self.pool_shard(zone));
        let entry = shard.zones.entry(zone).or_default();
        entry.immediate.extend_from_slice(pages);
    }

    /// Переносит durable-освобождённые страницы в donation-пул.
    pub(crate) fn donate_pages(&self, pages: &[u32], donated_at: u64) {
        if pages.is_empty() {
            return;
        }
        let mut donation = lock_unpoison(&self.donation);
        donation.extend(pages.iter().map(|page| DonationEntry {
            page: *page,
            donated_at,
        }));
        self.stats.donated_pages.fetch_add(
            u64::try_from(pages.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn take_donation_page(&self) -> Option<u32> {
        let durable_txn = self.durable_txn_limit();
        let mut donation = lock_unpoison(&self.donation);
        let index = donation
            .iter()
            .position(|entry| entry.donated_at < durable_txn)?;
        let entry = donation.swap_remove(index);
        self.stats.reclaimed_pages.fetch_add(1, Ordering::Relaxed);
        Some(entry.page)
    }

    /// `MP(z)` (минимум пинов; `u64::MAX` — пинов не было).
    #[must_use]
    pub fn min_pinned(&self, zone: u32) -> u64 {
        self.gc.mp(zone)
    }

    /// `RV_z = min(D_z − 1, MP(z), freeze_epoch)`.
    #[must_use]
    pub fn reclaim_version(&self, zone: u32) -> u64 {
        self.gc.reclaim_version(zone, self.durable_version(zone))
    }

    /// Один GC-проход по грязным зонам (пересчёт `MP`).
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — внутренняя ошибка индекса.
    pub fn gc_pass(&self) -> Result<u32, ParallelError> {
        let zones = self.gc.dirty_zones();
        for zone in &zones {
            self.gc.refresh(*zone, &self.pins, &self.zone_guard)?;
            if !self.read_only
                && self.fatal().is_none()
                && *zone != 0
                && self.geometry.zone_slot(*zone).is_ok()
            {
                let _lease = lock_unpoison(self.lease(*zone));
                self.reclaim_chain_pages(*zone)?;
            }
        }
        u32::try_from(zones.len()).map_err(|_| ParallelError::InvalidArgument { field: "gc" })
    }

    /// Освобождает chain-страницы ниже `floor = min(MP, freeze)` (§4.4).
    ///
    /// Страницы попадают в bucket-группу `drop_txn = head.version` и выдаются
    /// не раньше, чем durable станет следующая версия (гейт `drop_txn < D_z`).
    fn reclaim_chain_pages(&self, zone: u32) -> Result<u32, ParallelError> {
        let Some(head) = self.head(zone) else {
            return Ok(0);
        };
        if head.prev_record == 0 {
            return Ok(0);
        }
        let guard_ref = self
            .zone_guard
            .get(zone as usize)
            .ok_or(ParallelError::InvalidArgument { field: "zone_seq" })?;
        let floor = {
            let _guard = EpochGuard::enter(guard_ref);
            self.gc.chain_floor(zone)
        };
        let ring = Ring::new(&self.file, &self.geometry);
        let mut page = head.prev_record;
        let mut upper = head.version;
        let mut hops = 0_u32;
        let mut collected = Vec::new();
        while page != 0 {
            hops = hops.saturating_add(1);
            if hops > MAX_ROOT_CHAIN_HOPS || page >= head.page_limit_at_commit {
                break;
            }
            let Some(chain) = ring.read_chain(page)? else {
                break;
            };
            if chain.owner_zone != zone || chain.entry.version >= upper {
                break;
            }
            upper = chain.entry.version;
            if chain.entry.version < head.version && chain.entry.version < floor {
                collected.push(page);
            }
            page = chain.entry.prev_record;
        }
        if collected.is_empty() {
            return Ok(0);
        }
        {
            let mut shard = lock_unpoison(self.pool_shard(zone));
            let entry = shard.zones.entry(zone).or_default();
            if !entry.loaded {
                entry.chain = self.load_zone_chain(zone)?;
                entry.loaded = true;
            }
            entry
                .chain
                .push_group(head.version, &collected, self.geometry.page_data_first())?;
            entry.dirty = true;
        }
        let freed = u32::try_from(collected.len()).unwrap_or(u32::MAX);
        self.stats
            .chain_freed_pages
            .fetch_add(u64::from(freed), Ordering::Relaxed);
        if let Some(depth) = self.chain_depth.get(zone as usize) {
            let current = depth.load(Ordering::Acquire);
            let value = if current == CHAIN_UNKNOWN {
                0
            } else {
                current.saturating_sub(freed)
            };
            depth.store(value, Ordering::Release);
        }
        Ok(freed)
    }

    /// Включает retention-барьер `freeze_epoch = published_txn`.
    ///
    /// # Errors
    ///
    /// `Busy` — freeze уже активен.
    pub fn freeze(&self) -> Result<FreezeGuard<'_>, ParallelError> {
        FreezeGuard::new(&self.gc, self.published_txn())
    }

    /// `freeze_epoch` (0 — freeze нет).
    #[must_use]
    pub fn freeze_epoch(&self) -> u64 {
        self.gc.freeze_epoch()
    }

    /// Глобальный durable-барьер `Sync`: двигает `DP` до курсора и `DT` до
    /// `published_txn`, пишет две копии `ALLOC_RECORD` и `fdatasync`.
    ///
    /// # Errors
    ///
    /// `ReadOnly` — файл `write_locked`; `Io` — ошибка записи/fsync.
    pub fn sync(&self) -> Result<(u64, u64), ParallelError> {
        self.ensure_writable()?;
        // Снимок голов ДО fsync: всё, что записано к этому моменту, попадёт в
        // fdatasync; более новые публикации останутся неdurable (консервативно).
        let mut durable_heads = Vec::new();
        for (index, block) in self.heads.iter().enumerate() {
            if let HeadRead::Stable(entry) = block.load()
                && let Ok(zone) = u32::try_from(index)
            {
                durable_heads.push((zone, entry.version));
            }
        }
        let mut durable = lock_unpoison(&self.alloc_durable);
        let page_limit = durable.page_limit.max(self.allocator.cursor());
        let txn_limit = durable.txn_limit.max(self.published_txn());
        let seq = durable.seq.saturating_add(1);
        self.write_alloc_record(seq, page_limit, txn_limit)?;
        self.fsync_data()?;
        durable.seq = seq;
        durable.page_limit = page_limit;
        durable.txn_limit = txn_limit;
        self.durable_page_limit.store(page_limit, Ordering::Release);
        self.durable_txn_limit.store(txn_limit, Ordering::Release);
        for (zone, version) in durable_heads {
            if let Some(slot) = self.durable_versions.get(zone as usize) {
                slot.store(version, Ordering::Release);
            }
        }
        self.promote_sticky();
        Ok((page_limit, txn_limit))
    }

    /// Публикует запись корня зоны (две фазы, два `fdatasync`).
    ///
    /// `page_limit_at_commit` пересчитывается: `max(переданного, chain+1,
    /// root_page+1, meta_root+1, free_head+1, prev_record+1)`.
    ///
    /// # Errors
    ///
    /// `ReadOnly` — `write_locked`; `ZoneDegraded` — зона деградирована;
    /// `ZoneWriterStalled` — лимит chain; `ReaderContended` — retryable гонка
    /// с пином (публикация не выполнена); `MapFull`/`Io`/`InvalidArgument`.
    #[allow(clippy::too_many_lines)]
    pub fn publish_root(&self, entry: RootEntry) -> Result<PublishOutcome, ParallelError> {
        let _lease = lock_unpoison(self.lease(entry.owner_zone));
        self.publish_root_locked(entry)
    }

    /// Публикация без захвата lease: вызывающий уже держит lease зоны.
    ///
    /// # Errors
    ///
    /// См. [`ParallelStore::publish_root`].
    pub(crate) fn publish_root_locked(
        &self,
        entry: RootEntry,
    ) -> Result<PublishOutcome, ParallelError> {
        self.publish_root_with_drops(entry, &[])
    }

    /// Публикует одну группу записей корней: **два** `fdatasync` на группу для
    /// [`SyncModeV2::Sync`] (§7.1).
    ///
    /// Все запросы должны иметь одинаковый режим durability. Записи готовятся
    /// последовательно, затем выполняются одной группой; `ReaderContended`
    /// возвращается только проигравшей зоне.
    ///
    /// # Errors
    ///
    /// Ошибки — в элементах результата (в порядке входа).
    pub fn commit_group(
        &self,
        requests: Vec<GroupCommitRequest>,
    ) -> Vec<Result<PublishOutcome, ParallelError>> {
        let count = requests.len();
        if count == 0 {
            return Vec::new();
        }
        let mode = requests
            .first()
            .map_or(SyncModeV2::Sync, |request| request.durability);
        if requests.iter().any(|request| request.durability != mode) {
            return (0..count)
                .map(|_| {
                    Err(ParallelError::InvalidArgument {
                        field: "group durability",
                    })
                })
                .collect();
        }
        let mut prepared = Vec::with_capacity(count);
        let mut slots: Vec<Option<Result<PublishOutcome, ParallelError>>> =
            (0..count).map(|_| None).collect();
        for (index, request) in requests.into_iter().enumerate() {
            let weight = u64::try_from(request.drops.len()).unwrap_or(u64::MAX) * 4;
            match self.prepare_publish(request.entry, &request.drops, weight) {
                Ok(member) => prepared.push((index, member)),
                Err(error) => {
                    if let Some(slot) = slots.get_mut(index) {
                        *slot = Some(Err(error));
                    }
                }
            }
        }
        let mut indices = Vec::with_capacity(prepared.len());
        let mut members = Vec::with_capacity(prepared.len());
        for (index, member) in prepared {
            indices.push(index);
            members.push(member);
        }
        let outcomes = self.execute_group(members, mode);
        for (index, outcome) in indices.into_iter().zip(outcomes) {
            if let Some(slot) = slots.get_mut(index) {
                *slot = Some(outcome);
            }
        }
        slots
            .into_iter()
            .map(|slot| slot.unwrap_or(Err(ParallelError::InvalidArgument { field: "group" })))
            .collect()
    }

    /// Публикация с явным набором страниц, освобождённых в этом коммите.
    ///
    /// `drops` попадают в bucket-группу `drop_txn = version` и пишутся в фазе 1
    /// вместе с данными и chain (§4.5, §6.3). Вызывающий уже держит lease зоны.
    /// Режим — `Sync` (низкоуровневый API фазы A); B2b-коммиты идут через
    /// [`ParallelStore::publish_root_with_drops_mode`].
    ///
    /// # Errors
    ///
    /// `ReadOnly` — `write_locked`; `ZoneDegraded` — зона деградирована;
    /// `ZoneWriterStalled` — лимит chain; `ReaderContended` — retryable гонка
    /// с пином (публикация не выполнена); `MapFull`/`Io`/`InvalidArgument`.
    pub(crate) fn publish_root_with_drops(
        &self,
        entry: RootEntry,
        drops: &[u32],
    ) -> Result<PublishOutcome, ParallelError> {
        self.publish_root_with_drops_mode(entry, drops, SyncModeV2::Sync)
    }

    /// Публикация с явным режимом durability (`Sync`/`Flush`/`Memory`).
    ///
    /// # Errors
    ///
    /// См. [`ParallelStore::publish_root_with_drops`] и
    /// [`ParallelError::DurabilityBelowFileMode`].
    pub(crate) fn publish_root_with_drops_mode(
        &self,
        entry: RootEntry,
        drops: &[u32],
        mode: SyncModeV2,
    ) -> Result<PublishOutcome, ParallelError> {
        self.check_durability(mode)?;
        let prepared = self.prepare_publish(entry, drops, 0)?;
        match self.execute_group(vec![prepared], mode).pop() {
            Some(outcome) => outcome,
            None => Err(ParallelError::InvalidArgument { field: "group" }),
        }
    }

    /// Проверяет и планирует коммит: версия, ring-ячейка, chain, bucket-образы.
    ///
    /// Ничего не пишет в файл: всё, что выделено, живёт в staging-копии пула и
    /// попадает на диск только в фазе 1. План можно выполнить одиночной
    /// публикацией или группой (§7.1).
    ///
    /// # Errors
    ///
    /// `ReadOnly`, `ZoneDegraded`, `ZoneWriterStalled`, `MapFull`,
    /// `InvalidArgument`, `Corrupt`.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn prepare_publish(
        &self,
        entry: RootEntry,
        drops: &[u32],
        weight: u64,
    ) -> Result<PreparedPublish, ParallelError> {
        self.ensure_writable()?;
        let zone = entry.owner_zone;
        let is_catalog = zone == 0;
        if !is_catalog {
            self.ensure_zone_writable(zone)?;
        }
        if entry.version < 2 {
            return Err(ParallelError::InvalidArgument { field: "version" });
        }
        if entry.state.to_disk() > 2
            || entry.ixfr_root != 0
            || entry.tree_level > MAX_TREE_DEPTH
            || entry.soa_serial > 0x7FFF_FFFF
            || RootFlags::from_bits(entry.flags.bits()).is_none()
        {
            return Err(ParallelError::InvalidArgument {
                field: "root entry",
            });
        }
        let head = self.head(zone);
        if let Some(current) = head
            && entry.version <= current.version
        {
            return Err(ParallelError::InvalidArgument { field: "version" });
        }
        let slot = self.geometry.head_slot(zone)?;
        let group = usize::try_from(entry.version % u64::from(ROOT_VERSIONS))
            .map_err(|_| ParallelError::InvalidArgument { field: "version" })?;
        let ring = Ring::new(&self.file, &self.geometry);
        let view = ring.read_slot_at(slot, zone)?;
        let old = view.cell(group);
        let mut max_allocated = self.allocator.cursor().saturating_sub(1);
        let mut needs_chain = None;
        if let Some(previous) = old {
            let mp = self.gc.mp(zone);
            if previous.version >= mp {
                let depth = self.chain_depth(zone)?;
                if depth >= self.geometry.max_root_chain_pages() {
                    return Err(ParallelError::ZoneWriterStalled { zone });
                }
                needs_chain = Some(previous);
            }
        }
        let reclaim = self.prepare_reclaim(
            zone,
            entry.version,
            drops,
            needs_chain.is_some(),
            &mut max_allocated,
        )?;
        let chain_write = match (needs_chain, reclaim.chain_page) {
            (Some(previous), Some(page)) => Some((page, previous, entry.version)),
            (Some(_), None) => {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::RootChain,
                    page: None,
                });
            }
            (None, _) => None,
        };
        let prev_record = chain_write.as_ref().map_or_else(
            || head.map_or(0, |current| current.prev_record),
            |(page, _, _)| *page,
        );
        let mut record = entry;
        record.prev_record = prev_record;
        record.free_head = reclaim.free_head;
        let minimum_limit = [
            record.page_limit_at_commit,
            head.map_or(0, |current| current.page_limit_at_commit),
            record.root_page.saturating_add(1),
            record.meta_root.saturating_add(1),
            record.free_head.saturating_add(1),
            record.prev_record.saturating_add(1),
            reclaim.max_page.saturating_add(1),
            self.geometry.page_data_first(),
        ]
        .into_iter()
        .max()
        .unwrap_or(self.geometry.page_data_first());
        if minimum_limit > self.geometry.page_count_max() {
            return Err(ParallelError::MapFull {
                high_water: u64::from(minimum_limit),
                page_count_max: self.geometry.page_count_max(),
            });
        }
        record.page_limit_at_commit = minimum_limit;
        record
            .check_fields(self.geometry.page_count_max())
            .map_err(|_| ParallelError::InvalidArgument {
                field: "root entry",
            })?;
        let weight = weight
            .saturating_add(reclaim.images.iter().fold(0_u64, |acc, (_, image)| {
                acc.saturating_add(u64::try_from(image.len()).unwrap_or(u64::MAX))
            }))
            .saturating_add(u64::try_from(drops.len()).unwrap_or(u64::MAX) * 4);
        Ok(PreparedPublish {
            zone,
            record,
            slot,
            chain_write,
            reclaim,
            minimum_limit: u64::from(minimum_limit),
            old,
            weight,
        })
    }

    /// Выполняет подготовленную группу: **ровно два** `fdatasync` для `Sync`
    /// (один для `Flush`, ни одного для `Memory`), публикация голов после
    /// durable-фазы и ack-семантика на уровне вызывающего.
    ///
    /// Ошибка ввода-вывода переводит файл в `CommitUncertain` (`write_locked`) и
    /// не публикует ни одной головы группы. `ReaderContended` — per-zone
    /// retryable: зона не публикуется, остальные участники — да.
    ///
    /// # Errors
    ///
    /// Каждый элемент результата — успех публикации или ошибка этой зоны.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_group(
        &self,
        members: Vec<PreparedPublish>,
        mode: SyncModeV2,
    ) -> Vec<Result<PublishOutcome, ParallelError>> {
        let count = members.len();
        if count == 0 {
            return Vec::new();
        }
        let mut results: Vec<Option<Result<PublishOutcome, ParallelError>>> =
            (0..count).map(|_| None).collect();
        if let Err(error) = self.ensure_writable() {
            let reason = match error {
                ParallelError::ReadOnly { reason } => reason,
                _ => FatalKind::CommitUncertain,
            };
            return (0..count)
                .map(|_| Err(ParallelError::ReadOnly { reason }))
                .collect();
        }
        if let Err(error) = self.check_durability(mode) {
            let (requested, effective) = match error {
                ParallelError::DurabilityBelowFileMode {
                    requested,
                    effective,
                } => (requested, effective),
                _ => (mode, self.effective_mode()),
            };
            return (0..count)
                .map(|_| {
                    Err(ParallelError::DurabilityBelowFileMode {
                        requested,
                        effective,
                    })
                })
                .collect();
        }
        self.stats.group_commits.fetch_add(1, Ordering::Relaxed);
        self.stats
            .group_members
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.stats
            .group_max_members
            .fetch_max(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
        let fsyncs = match mode {
            SyncModeV2::Sync => 2,
            SyncModeV2::Flush => 1,
            SyncModeV2::Memory => 0,
        };
        self.stats.group_fsyncs.fetch_add(fsyncs, Ordering::Relaxed);

        let page_limit = match self.phase1(&members, mode) {
            Ok(limit) => limit,
            Err(_error) => {
                // Исход группы не определён: ни одна голова не публикуется.
                self.mark_fatal(FatalKind::CommitUncertain);
                return (0..count)
                    .map(|_| {
                        Err(ParallelError::ReadOnly {
                            reason: FatalKind::CommitUncertain,
                        })
                    })
                    .collect();
            }
        };
        let mut pending: Vec<usize> = (0..count).collect();
        if let Err(error) = self.phase2(&members, mode, &mut results, &mut pending) {
            self.mark_fatal(FatalKind::CommitUncertain);
            let reason = if let ParallelError::ReadOnly { reason } = error {
                reason
            } else {
                FatalKind::CommitUncertain
            };
            return (0..count)
                .map(|_| Err(ParallelError::ReadOnly { reason }))
                .collect();
        }
        let aborted = count.saturating_sub(pending.len());
        self.stats.group_aborted.fetch_add(
            u64::try_from(aborted).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.publish_group(members, mode, page_limit, &pending, &mut results);
        results
            .into_iter()
            .map(|slot| {
                slot.unwrap_or(Err(ParallelError::ReadOnly {
                    reason: FatalKind::CommitUncertain,
                }))
            })
            .collect()
    }

    /// Фаза 1: `ALLOC_RECORD` (`Sync`) + chain/bucket-образы всех зон группы,
    /// затем один `fdatasync` (кроме `Memory`).
    fn phase1(&self, members: &[PreparedPublish], mode: SyncModeV2) -> Result<u64, ParallelError> {
        let mut candidate = self.durable_page_limit.load(Ordering::Acquire);
        for member in members {
            candidate = candidate
                .max(member.minimum_limit)
                .max(u64::from(member.reclaim.max_page.saturating_add(1)));
        }
        if mode == SyncModeV2::Memory {
            candidate = candidate.max(self.allocator.cursor());
            self.fire(CrashPoint::BeforeAllocRecord);
            self.write_group_metadata(members)?;
            self.fire(CrashPoint::AfterPhase1Writes);
            self.fire(CrashPoint::AfterPhase1Fsync);
            return Ok(candidate);
        }
        let mut durable = lock_unpoison(&self.alloc_durable);
        candidate = candidate
            .max(durable.page_limit)
            .max(self.allocator.cursor());
        if candidate > u64::from(self.geometry.page_count_max()) {
            return Err(ParallelError::MapFull {
                high_water: candidate,
                page_count_max: self.geometry.page_count_max(),
            });
        }
        let seq = durable.seq.saturating_add(1);
        let txn_limit = if mode == SyncModeV2::Sync {
            durable.txn_limit.max(
                members
                    .iter()
                    .map(|member| member.record.version)
                    .max()
                    .unwrap_or(0),
            )
        } else {
            durable.txn_limit
        };
        self.fire(CrashPoint::BeforeAllocRecord);
        if mode == SyncModeV2::Sync {
            self.write_alloc_record(seq, candidate, txn_limit)?;
        }
        self.write_group_metadata(members)?;
        self.fire(CrashPoint::AfterPhase1Writes);
        self.fsync_data()?;
        self.fire(CrashPoint::AfterPhase1Fsync);
        if mode == SyncModeV2::Sync {
            durable.seq = seq;
            durable.page_limit = candidate;
            durable.txn_limit = txn_limit;
            self.durable_page_limit.store(candidate, Ordering::Release);
            self.durable_txn_limit.store(txn_limit, Ordering::Release);
        }
        Ok(candidate)
    }

    fn write_group_metadata(&self, members: &[PreparedPublish]) -> Result<(), ParallelError> {
        let ring = Ring::new(&self.file, &self.geometry);
        for member in members {
            if let Some((page, previous, evicted_txn)) = member.chain_write {
                let chain = crate::parallel::layout::ChainPage {
                    page_no: page,
                    owner_zone: member.zone,
                    evicted_txn,
                    entry: previous,
                };
                ring.write_chain(&chain)?;
                if let Some(cache) = self.raw_cache.as_ref() {
                    cache.invalidate(page);
                }
            }
            for (page, image) in &member.reclaim.images {
                self.write_page_bytes(*page, image)?;
            }
        }
        Ok(())
    }

    /// Фаза 2: две копии записи каждой зоны под её `EpochGuard`; один
    /// `fdatasync` для `Sync`. `ReaderContended` уходит в `results` и в
    /// `pending` не попадает (зона не публикуется).
    fn phase2(
        &self,
        members: &[PreparedPublish],
        mode: SyncModeV2,
        results: &mut [Option<Result<PublishOutcome, ParallelError>>],
        pending: &mut Vec<usize>,
    ) -> Result<(), ParallelError> {
        let ring = Ring::new(&self.file, &self.geometry);
        pending.clear();
        for (index, member) in members.iter().enumerate() {
            let Some(guard_ref) = self.zone_guard.get(member.zone as usize) else {
                return Err(ParallelError::InvalidArgument { field: "zone_seq" });
            };
            let guard = EpochGuard::enter(guard_ref);
            if member.chain_write.is_none()
                && member
                    .old
                    .is_some_and(|previous| previous.version >= self.gc.mp(member.zone))
            {
                drop(guard);
                self.stats.reader_contended.fetch_add(1, Ordering::Relaxed);
                if let Some(slot) = results.get_mut(index) {
                    *slot = Some(Err(ParallelError::ReaderContended));
                }
                continue;
            }
            self.fire(CrashPoint::BeforeRootWrite);
            if let Err(error) = ring.write_cell(
                member.slot.page_a,
                member.slot.cell_offset(member.record.version),
                &member.record,
            ) {
                drop(guard);
                return Err(error);
            }
            self.fire(CrashPoint::AfterRootCopyA);
            let written = ring.write_cell(
                member.slot.page_b,
                member.slot.cell_offset(member.record.version),
                &member.record,
            );
            drop(guard);
            written?;
            self.fire(CrashPoint::AfterRootCopyB);
            pending.push(index);
        }
        if mode == SyncModeV2::Sync {
            self.fsync_data()?;
        }
        self.fire(CrashPoint::AfterPhase2Fsync);
        Ok(())
    }

    /// Публикация голов участников, чьи записи durable (или хотя бы записаны
    /// для `Flush`/`Memory`). Пулы фиксируются только здесь.
    fn publish_group(
        &self,
        mut members: Vec<PreparedPublish>,
        mode: SyncModeV2,
        page_limit: u64,
        pending: &[usize],
        results: &mut [Option<Result<PublishOutcome, ParallelError>>],
    ) {
        let mut published_txn = 0_u64;
        for &index in pending {
            let Some(member) = members.get_mut(index) else {
                continue;
            };
            if let Some(pool) = member.reclaim.pool.take() {
                self.commit_free_pool(member.zone, pool);
            }
            self.fire(CrashPoint::BeforeHeadPublish);
            if let Some(block) = self.heads.get(member.zone as usize) {
                block.store(&member.record);
            }
            if let Some(flags) = self.zone_state.get(member.zone as usize)
                && member.record.flags.contains(RootFlags::NEEDS_FSCK)
            {
                flags.fetch_or(ZONE_NEEDS_FSCK, Ordering::AcqRel);
            }
            if mode == SyncModeV2::Sync
                && let Some(slot) = self.durable_versions.get(member.zone as usize)
            {
                slot.store(member.record.version, Ordering::Release);
            }
            published_txn = published_txn.max(member.record.version);
            self.stats.publications.fetch_add(1, Ordering::Relaxed);
            let evicted_page = member.chain_write.map(|(page, _, _)| {
                self.stats.chain_evictions.fetch_add(1, Ordering::Relaxed);
                if let Some(depth) = self.chain_depth.get(member.zone as usize) {
                    let current = depth.load(Ordering::Acquire);
                    if current != CHAIN_UNKNOWN {
                        depth.store(current.saturating_add(1), Ordering::Release);
                    }
                }
                page
            });
            if let Some(slot) = results.get_mut(index) {
                *slot = Some(Ok(PublishOutcome {
                    zone: member.zone,
                    version: member.record.version,
                    page_limit,
                    prev_record: member.record.prev_record,
                    evicted_page,
                }));
            }
        }
        if published_txn != 0 {
            self.published_txn
                .fetch_max(published_txn, Ordering::Release);
        }
        if mode == SyncModeV2::Sync {
            self.promote_sticky();
        }
        self.fire(CrashPoint::AfterHeadPublish);
    }

    /// Готовит bucket-образы, `free_head` и (при необходимости) chain-страницу.
    ///
    /// Все страницы выдаются из staging-копии пула или bump-курсора; durable
    /// пул не меняется, пока коммит не опубликован. Поэтому retry после
    /// `ReaderContended` не удваивает `dropped(V)` и не теряет страницы.
    #[allow(clippy::too_many_lines)]
    fn prepare_reclaim(
        &self,
        zone: u32,
        version: u64,
        drops: &[u32],
        needs_chain: bool,
        max_allocated: &mut u64,
    ) -> Result<ReclaimPrep, ParallelError> {
        let durable = self.durable_version(zone);
        let rv = self.gc.reclaim_version(zone, durable);
        let data_first = self.geometry.page_data_first();
        let mut pool = {
            let mut shard = lock_unpoison(self.pool_shard(zone));
            let entry = shard.zones.entry(zone).or_default();
            if !entry.loaded {
                entry.chain = self.load_zone_chain(zone)?;
                entry.loaded = true;
            }
            if !needs_chain && !entry.dirty && drops.is_empty() && entry.immediate.is_empty() {
                let free_head = if entry.loaded {
                    entry.chain.head()
                } else {
                    self.head(zone).map_or(0, |head| head.free_head)
                };
                return Ok(ReclaimPrep {
                    pool: None,
                    free_head,
                    images: Vec::new(),
                    chain_page: None,
                    max_page: free_head,
                });
            }
            entry.clone()
        };

        let mut chain_page = None;
        if needs_chain {
            chain_page = Some(Self::allocate_from_pool(
                self,
                &mut pool.chain,
                durable,
                rv,
                version,
                max_allocated,
            )?);
        }
        let rebuild = pool.dirty || !drops.is_empty() || !pool.immediate.is_empty() || needs_chain;
        if !rebuild {
            let free_head = pool.chain.head();
            let max_page = Self::chain_max_page(&pool.chain);
            return Ok(ReclaimPrep {
                pool: Some(pool),
                free_head,
                images: Vec::new(),
                chain_page,
                max_page,
            });
        }

        let mut freed: Vec<u32> = Vec::new();
        let mut seen: HashSet<u32> = HashSet::new();
        let mut push = |page: u32| -> Result<(), ParallelError> {
            if page == 0 || !seen.insert(page) {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::WatermarkRegression,
                    page: Some(page),
                });
            }
            freed.push(page);
            Ok(())
        };
        for bucket in pool.chain.buckets() {
            // Страница 0 — группа, созданная GC и ещё не закодированная.
            if bucket.page != 0 {
                push(bucket.page)?;
            }
        }
        for page in drops {
            push(*page)?;
        }
        for page in std::mem::take(&mut pool.immediate) {
            push(page)?;
        }
        pool.chain.push_group(version, &freed, data_first)?;

        let mut pages: Vec<u32> = Vec::new();
        let mut assigned: HashSet<u32> = HashSet::new();
        let mut iterations = 0_u32;
        loop {
            let needed = pool.chain.needed_images();
            if pages.len() == needed {
                break;
            }
            iterations = iterations.saturating_add(1);
            if iterations > 4096 {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::WatermarkRegression,
                    page: None,
                });
            }
            if pages.len() < needed {
                let page = Self::allocate_from_pool(
                    self,
                    &mut pool.chain,
                    durable,
                    rv,
                    version,
                    max_allocated,
                )?;
                if !assigned.insert(page) || page == chain_page.unwrap_or(0) {
                    return Err(ParallelError::Corrupt {
                        kind: V2CorruptKind::WatermarkRegression,
                        page: Some(page),
                    });
                }
                pages.push(page);
            } else if let Some(extra) = pages.pop() {
                pool.chain.push_group(version, &[extra], data_first)?;
            }
        }
        let (free_head, images) = pool.chain.encode_images(zone, &pages)?;
        pool.dirty = false;
        let max_page = Self::chain_max_page(&pool.chain);
        Ok(ReclaimPrep {
            pool: Some(pool),
            free_head,
            images,
            chain_page,
            max_page,
        })
    }

    fn chain_max_page(chain: &FreeChain) -> u32 {
        let mut max_page = 0_u32;
        for bucket in chain.buckets() {
            max_page = max_page.max(bucket.page);
            for page in &bucket.pages {
                max_page = max_page.max(*page);
            }
        }
        max_page
    }

    fn allocate_from_pool(
        &self,
        chain: &mut FreeChain,
        durable: u64,
        rv: u64,
        version: u64,
        max_allocated: &mut u64,
    ) -> Result<u32, ParallelError> {
        if let Some(page) = chain.take_eligible(durable, rv, version) {
            return Ok(page);
        }
        let ticket = self.allocator.reserve_exact(1)?;
        *max_allocated = (*max_allocated).max(u64::from(ticket.first_page));
        Ok(ticket.first_page)
    }

    fn commit_free_pool(&self, zone: u32, pool: ZoneFreePool) {
        let mut shard = lock_unpoison(self.pool_shard(zone));
        shard.zones.insert(zone, pool);
    }

    fn mark_fatal(&self, kind: FatalKind) {
        let mut fatal = lock_unpoison(&self.fatal);
        merge_fatal(&mut fatal, Some(kind));
    }

    pub(crate) fn note_fatal(&self, kind: FatalKind) {
        self.mark_fatal(kind);
    }

    /// Читает durable-цепочку bucket'ов головы (для `fsck`).
    pub(crate) fn load_free_chain(
        &self,
        zone: u32,
        head: &RootEntry,
    ) -> Result<FreeChain, ParallelError> {
        if head.free_head == 0 {
            return Ok(FreeChain::empty());
        }
        FreeChain::load(&self.file, &self.geometry, zone, head)
    }

    fn write_page_bytes(&self, page: u32, data: &[u8]) -> Result<(), ParallelError> {
        if data.len() != PAGE_SIZE_V2 as usize {
            return Err(ParallelError::InvalidArgument {
                field: "page payload",
            });
        }
        let offset = self.geometry.page_offset(page)?;
        self.file.write_all_at(data, offset)?;
        if let Some(cache) = self.raw_cache.as_ref() {
            cache.invalidate(page);
        }
        Ok(())
    }

    /// Выбирает запись версии `≤ ceiling` (ring → chain).
    ///
    /// # Errors
    ///
    /// `NoZoneVersion` — зоны нет; `StaleRoot` — версия ниже истории;
    /// `Corrupt` — цикл/порядок chain; `ZoneDegraded`.
    pub fn select_root(&self, zone: u32, ceiling: u64) -> Result<RootEntry, ParallelError> {
        let Some(head) = self.head(zone) else {
            return Err(ParallelError::NoZoneVersion { zone });
        };
        self.ensure_zone_readable(zone)?;
        if ceiling >= head.version {
            return Ok(head);
        }
        let ring = Ring::new(&self.file, &self.geometry);
        let view = ring.read_slot(zone)?;
        let mut candidate: Option<RootEntry> = None;
        for cell in &view.cells {
            let Some(entry) = cell.best else { continue };
            if entry.version > ceiling {
                continue;
            }
            entry
                .check_fields(self.geometry.page_count_max())
                .map_err(|_| ParallelError::Corrupt {
                    kind: V2CorruptKind::RootEntry,
                    page: None,
                })?;
            if candidate.is_none_or(|current| entry.version > current.version) {
                candidate = Some(entry);
            }
        }
        if let Some(entry) = candidate {
            return Ok(entry);
        }
        self.walk_chain(zone, head, ceiling)
    }

    /// Берёт стабильный `ZoneSnapshot` с пином (PW-I12: `ceiling = ∞`).
    ///
    /// # Errors
    ///
    /// `NoZoneVersion` — зона отсутствует/tombstone; `ZoneDegraded` — зона
    /// read-only; `ReaderContended` — churn публикаций, retryable.
    pub fn zone_snapshot<'a>(
        &'a self,
        reader: &'a Reader<'a>,
        zone: u32,
    ) -> Result<ZoneSnapshot<'a>, ParallelError> {
        let e0 = self.published_txn.load(Ordering::Acquire);
        let mut stuck_odd: Option<(u32, std::time::Instant)> = None;
        for attempt in 0..PIN_ATTEMPTS {
            let head = match self.head_read(zone) {
                HeadRead::Stable(entry) => entry,
                HeadRead::Empty => return Err(ParallelError::NoZoneVersion { zone }),
                HeadRead::Unstable => {
                    if attempt + 1 == PIN_ATTEMPTS {
                        break;
                    }
                    backoff(attempt);
                    continue;
                }
            };
            if head.is_tombstone() {
                return Err(ParallelError::NoZoneVersion { zone });
            }
            self.ensure_zone_readable(zone)?;
            let pin = reader.pin(zone, head.version, e0);
            self.gc.note_pin(zone, head.version);
            fence(Ordering::SeqCst);
            let c1 = self.load_guard(zone);
            let e2 = self.published_txn.load(Ordering::Acquire);
            let c2 = self.load_guard(zone);
            let head2 = self.head_read(zone);
            let stable = c1 == c2
                && c1.is_multiple_of(2)
                && e2 == e0
                && matches!(head2, HeadRead::Stable(entry) if entry.version == head.version);
            if stable {
                return Ok(ZoneSnapshot {
                    root: head,
                    pin,
                    gc: &self.gc,
                    zone,
                    _not_send: std::marker::PhantomData,
                });
            }
            // Деградация — только если guard застрял надолго (F-11). Счётчик
            // попыток непригоден: писатель может быть вытеснен планировщиком
            // внутри короткой критической секции, и 8 попыток с backoff
            // складываются в единицы миллисекунд.
            if !c1.is_multiple_of(2) && c1 == c2 {
                let since = match stuck_odd {
                    Some((value, since)) if value == c1 => since,
                    _ => {
                        let now = std::time::Instant::now();
                        stuck_odd = Some((c1, now));
                        now
                    }
                };
                if since.elapsed() >= GUARD_STUCK_TIMEOUT {
                    self.degrade_zone(zone);
                    return Err(ParallelError::ZoneDegraded {
                        zone,
                        epoch: self.load_guard(zone),
                    });
                }
            } else {
                stuck_odd = None;
            }
            drop(pin);
            self.gc.mark_dirty(zone);
            self.stats.reader_contended.fetch_add(1, Ordering::Relaxed);
            backoff(attempt);
        }
        Err(ParallelError::ReaderContended)
    }

    /// Записывает низкоуровневую страницу данных (для тестов/фазы B).
    ///
    /// `data` дополняется нулями до размера страницы; запись не fsync'ится.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — страница вне data-региона/не зарезервирована;
    /// `ReadOnly`; `Io`.
    pub fn write_raw_page(&self, page: u32, data: &[u8]) -> Result<(), ParallelError> {
        self.ensure_writable()?;
        if page < self.geometry.page_data_first() || page >= self.geometry.page_count_max() {
            return Err(ParallelError::InvalidArgument { field: "page_id" });
        }
        if u64::from(page) >= self.allocator.cursor() {
            return Err(ParallelError::InvalidArgument { field: "page_id" });
        }
        if data.len() > PAGE_SIZE_V2 as usize {
            return Err(ParallelError::InvalidArgument { field: "payload" });
        }
        let mut page_buffer = vec![0_u8; PAGE_SIZE_V2 as usize];
        if let Some(span) = page_buffer.get_mut(..data.len()) {
            span.copy_from_slice(data);
        }
        self.write_page_bytes(page, &page_buffer)
    }

    /// Читает страницу данных.
    ///
    /// # Errors
    ///
    /// `InvalidArgument`/`Corrupt(Bounds)`/`Io`.
    pub fn read_raw_page(&self, page: u32) -> Result<Vec<u8>, ParallelError> {
        if page < self.geometry.page_data_first() {
            return Err(ParallelError::InvalidArgument { field: "page_id" });
        }
        let offset = self.geometry.page_offset(page)?;
        read_at(&self.file, offset, PAGE_SIZE_V2 as usize)
    }

    /// Запускает `fsck`-lite: проверка пролога, ring, chain и watermark.
    ///
    /// # Errors
    ///
    /// `Io` — ошибка чтения; `InvalidArgument` — внутренняя ошибка.
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    pub fn fsck_lite(&self) -> Result<FsckLiteReport, ParallelError> {
        let ring = Ring::new(&self.file, &self.geometry);
        let scan = scan_roots(&ring, &self.geometry)?;
        let mut fatal = self.fatal();
        merge_fatal(&mut fatal, scan.fatal);
        let mut issues: Vec<String> = scan
            .issues
            .iter()
            .map(|(zone, field)| format!("zone {zone}: {field}"))
            .collect();

        // `fsck` сверяет on-disk пролог с `LayoutHead` (PW-AT-6).
        let layout_a_raw = read_at(
            &self.file,
            u64::from(self.geometry.page_layout_head_a()) * u64::from(PAGE_SIZE_V2),
            LAYOUT_HEAD_RECORD_SIZE as usize,
        )?;
        let layout_b_raw = read_at(
            &self.file,
            u64::from(self.geometry.page_layout_head_b()) * u64::from(PAGE_SIZE_V2),
            LAYOUT_HEAD_RECORD_SIZE as usize,
        )?;
        let mut torn_layout_copy = false;
        match (
            LayoutHead::decode(&layout_a_raw),
            LayoutHead::decode(&layout_b_raw),
        ) {
            (Some(left), Some(right)) => {
                if !left.same_geometry(&right) || left.geometry != self.geometry {
                    merge_fatal(&mut fatal, Some(FatalKind::LayoutHead));
                    issues.push("LayoutHead A/B геометрия расходится".into());
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                torn_layout_copy = true;
            }
            (None, None) => {
                merge_fatal(&mut fatal, Some(FatalKind::LayoutHead));
                issues.push("LayoutHead: обе копии невалидны".into());
            }
        }

        // `ALLOC_RECORD` max-valid + монотонность относительно ring/памяти.
        let alloc_a_raw = read_at(
            &self.file,
            u64::from(self.geometry.page_alloc_record_a()) * u64::from(PAGE_SIZE_V2),
            ALLOC_RECORD_SIZE as usize,
        )?;
        let alloc_b_raw = read_at(
            &self.file,
            u64::from(self.geometry.page_alloc_record_b()) * u64::from(PAGE_SIZE_V2),
            ALLOC_RECORD_SIZE as usize,
        )?;
        let alloc_a = AllocRecord::decode(&alloc_a_raw, self.geometry.page_count_max());
        let alloc_b = AllocRecord::decode(&alloc_b_raw, self.geometry.page_count_max());
        let mut torn_alloc_copy = false;
        match (alloc_a, alloc_b) {
            (Some(left), Some(right)) => {
                let (chosen, other) = if left.seq >= right.seq {
                    (left, right)
                } else {
                    (right, left)
                };
                if chosen.page_limit < other.page_limit || chosen.txn_limit < other.txn_limit {
                    merge_fatal(&mut fatal, Some(FatalKind::AllocWatermarkRegression));
                    issues.push("ALLOC_RECORD: понижение watermark между копиями".into());
                }
                let strict = self.effective_mode() == SyncModeV2::Sync;
                if chosen.page_limit < u64::from(self.geometry.page_data_first()) {
                    merge_fatal(&mut fatal, Some(FatalKind::AllocWatermarkRegression));
                    issues.push("ALLOC_RECORD.page_limit ниже пролога".into());
                }
                if strict && chosen.page_limit < scan.max_page_limit {
                    merge_fatal(&mut fatal, Some(FatalKind::AllocWatermarkRegression));
                    issues.push("ALLOC_RECORD.page_limit ниже ring".into());
                }
                if strict && chosen.txn_limit < scan.max_version {
                    merge_fatal(&mut fatal, Some(FatalKind::RootWatermarkRegression));
                    issues.push("ALLOC_RECORD.txn_limit ниже version".into());
                }
                // Диск впереди памяти — незавершённая группа (фаза 1); диск
                // позади — регрессия watermark (только для `Sync`).
                if strict
                    && (chosen.page_limit < self.durable_page_limit()
                        || chosen.txn_limit < self.durable_txn_limit())
                {
                    merge_fatal(&mut fatal, Some(FatalKind::AllocWatermarkRegression));
                    issues.push("ALLOC_RECORD ниже in-memory DP/DT".into());
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                torn_alloc_copy = true;
            }
            (None, None) => {
                merge_fatal(&mut fatal, Some(FatalKind::AllocRecord));
                issues.push("ALLOC_RECORD: обе копии невалидны".into());
            }
        }
        let mut chain_pages = 0_u32;
        let mut chain_torn = 0_u32;
        let mut chain_max_depth = 0_u32;
        for (zone, head) in scan.heads.iter().enumerate() {
            let Some(head) = head else { continue };
            let Ok(zone) = u32::try_from(zone) else {
                continue;
            };
            let stats = Self::inspect_chain(zone, *head, &ring)?;
            chain_pages = chain_pages.saturating_add(stats.pages);
            chain_torn = chain_torn.saturating_add(stats.torn);
            chain_max_depth = chain_max_depth.max(stats.depth);
            issues.extend(stats.issues);
            if let Err(error) = self.load_free_chain(zone, head) {
                issues.push(format!("zone {zone}: free chain: {error}"));
            }
        }
        if self.effective_mode() == SyncModeV2::Sync {
            if self.durable_page_limit() < scan.max_page_limit {
                merge_fatal(&mut fatal, Some(FatalKind::AllocWatermarkRegression));
            }
            if self.durable_txn_limit() < scan.max_version {
                merge_fatal(&mut fatal, Some(FatalKind::RootWatermarkRegression));
            }
        }
        let leaked = self
            .allocator
            .cursor()
            .saturating_sub(self.durable_page_limit());
        if fatal.is_some() {
            let mut target = lock_unpoison(&self.fatal);
            merge_fatal(&mut target, fatal);
        }
        Ok(FsckLiteReport {
            ok: fatal.is_none() && issues.is_empty(),
            fatal,
            durable_page_limit: self.durable_page_limit(),
            durable_txn_limit: self.durable_txn_limit(),
            max_root_page_limit: scan.max_page_limit,
            max_root_version: scan.max_version,
            zones: scan.zones_with_roots,
            root_records: scan.root_records,
            torn_layout_copy,
            torn_alloc_copy,
            torn_root_copies: scan.torn_copies,
            diverged_root_copies: scan.diverged_copies,
            chain_pages,
            chain_torn,
            chain_max_depth,
            leaked_pages_estimate: leaked,
            issues,
        })
    }

    /// Структурный `fsck`: дерево/overflow/chain/пулы, пересечения и утечки.
    ///
    /// Пересечение множеств страниц помечается file-fatal
    /// ([`FatalKind::PageOverlap`]) и блокирует запись до offline `fsck`.
    ///
    /// # Errors
    ///
    /// `Io` — ошибка чтения; `Corrupt`/`Tree` — нечитаемая страница.
    pub fn fsck_graph(&self) -> Result<crate::parallel::verify::GraphReport, ParallelError> {
        let report = crate::parallel::verify::verify(self)?;
        if let Some(kind) = report.fatal {
            self.note_fatal(kind);
        }
        Ok(report)
    }

    /// Отчёт об утечках: `[data_first, DP)` вне дерева/chain/bucket/free,
    /// оценка aborted-страниц `[DP, cursor)` и порог [`MAX_LEAK_RATIO`].
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io` — структурная проверка не прошла.
    pub fn leak_report(&self) -> Result<LeakReport, ParallelError> {
        let graph = self.fsck_graph()?;
        Ok(Self::leak_report_from(&graph, self))
    }

    fn leak_report_from(graph: &crate::parallel::verify::GraphReport, store: &Self) -> LeakReport {
        let aborted = store
            .allocator
            .leaked_pages(store.durable_page_limit.load(Ordering::Acquire));
        let ratio = if graph.durable_pages == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            {
                graph.leaked_pages as f64 / graph.durable_pages as f64
            }
        };
        LeakReport {
            leaked_pages: graph.leaked_pages,
            leaked_page_ids: graph.leaked_page_ids.clone(),
            durable_pages: graph.durable_pages,
            aborted_pages: aborted,
            ratio,
            max_ratio: MAX_LEAK_RATIO,
            exceeds_max_ratio: ratio > MAX_LEAK_RATIO,
            fatal: graph.fatal,
            issues: graph.issues.clone(),
        }
    }

    /// Возвращает утёкшие страницы в durable free-пул (offline-операция,
    /// минимум §9.2/R4).
    ///
    /// Утечки `[data_first, DP)`, не достижимые ни из дерева, ни из chain, ни
    /// из bucket'ов, записываются как bucket-группа каталога (`owner_zone = 0`)
    /// `drop_txn = new_version` и переносятся в donation-пул. Пересечение
    /// множеств (file-fatal) — отказ до `fsck`-анализа: repair не «чинит»
    /// порчу.
    ///
    /// Вызывать только когда писателей нет (offline/`fsck --repair`).
    ///
    /// # Errors
    ///
    /// `Corrupt(PageOverlap)` — пересечение множеств; `ReadOnly`/`Io`/`MapFull`.
    pub fn repair_leaks(&self) -> Result<RepairReport, ParallelError> {
        let initial = crate::parallel::verify::verify(self)?;
        if let Some(kind) = initial.fatal {
            self.note_fatal(kind);
            return Err(ParallelError::Corrupt {
                kind: V2CorruptKind::PageOverlap,
                page: None,
            });
        }

        // 1. Карантин: повреждённые зоны получают `NEEDS_FSCK` в durable-голове.
        //    Пишутся только ячейки root directory; страницы данных не трогаются.
        let mut quarantined = Vec::new();
        let mut issues = initial.issues.clone();
        if !initial.damaged_zones.is_empty() {
            self.ensure_writable()?;
            for &zone in &initial.damaged_zones {
                let Some(head) = self.head_entry(zone) else {
                    continue;
                };
                match self.quarantine_zone(zone, &head) {
                    Ok(true) => quarantined.push(zone),
                    Ok(false) => {
                        issues.push(format!("zone {zone}: карантин не выставлен"));
                    }
                    Err(error) => {
                        issues.push(format!("zone {zone}: карантин не выставлен: {error}"));
                    }
                }
            }
        }

        // 2. Пересчёт после карантина: `sync()` мог сдвинуть `DP` до курсора.
        let graph = crate::parallel::verify::verify(self)?;
        if let Some(kind) = graph.fatal {
            self.note_fatal(kind);
            return Err(ParallelError::Corrupt {
                kind: V2CorruptKind::PageOverlap,
                page: None,
            });
        }

        // 3. Страницы ниже `page_limit_at_commit` повреждённой зоны могут
        //    принадлежать её недоступному дереву: их нельзя дарить пулу, пока
        //    зона в карантине. Безопасны только страницы выше всех таких лимитов.
        let floor = graph
            .damaged_zones
            .iter()
            .filter_map(|zone| self.head_entry(*zone))
            .map(|head| head.page_limit_at_commit)
            .max()
            .unwrap_or(0);
        let leaked: Vec<u32> = graph
            .leaked_page_ids
            .iter()
            .copied()
            .filter(|page| *page >= floor)
            .collect();
        let deferred = graph
            .leaked_pages
            .saturating_sub(u64::try_from(leaked.len()).unwrap_or(u64::MAX));
        if leaked.is_empty() {
            let ok = graph.damaged_zones.len() == quarantined.len();
            if !ok {
                issues.push(format!("не изолированы зоны: {:?}", graph.damaged_zones));
            }
            return Ok(RepairReport {
                repaired_pages: 0,
                remaining_leaks: graph.leaked_pages,
                deferred_leaks: deferred,
                quarantined_zones: quarantined,
                ok,
                issues,
            });
        }

        // 4. Утечки — bucket-группа каталога (`owner_zone = 0`).
        self.ensure_writable()?;
        let head = self.catalog_head();
        let version = self.allocator.next_txn_exact()?;
        let entry = RootEntry {
            owner_zone: 0,
            version,
            root_page: head.map_or(0, |current| current.root_page),
            tree_level: head.map_or(0, |current| current.tree_level),
            rrset_count: head.map_or(0, |current| current.rrset_count),
            soa_serial: head.map_or(0, |current| current.soa_serial),
            state: crate::parallel::root::RootState::Serving,
            flags: RootFlags::CATALOG,
            ..RootEntry::default()
        };
        // Страницы остаются durable-free в bucket-цепочке каталога: повторно
        // дарить их нельзя (double-free: bucket уже ссылается на них).
        let _outcome = self.publish_root_with_drops(entry, &leaked)?;
        let after = crate::parallel::verify::verify(self)?;
        let mut final_issues = after.issues.clone();
        final_issues.append(&mut issues);
        if after.leaked_pages != deferred {
            final_issues.push(format!(
                "после repair осталось {} утёкших страниц (ожидалось {deferred})",
                after.leaked_pages
            ));
        }
        let ok = after.fatal.is_none()
            && after.leaked_pages == deferred
            && graph.damaged_zones.len() == quarantined.len();
        Ok(RepairReport {
            repaired_pages: u64::try_from(leaked.len()).unwrap_or(u64::MAX),
            remaining_leaks: after.leaked_pages,
            deferred_leaks: deferred,
            quarantined_zones: quarantined,
            ok,
            issues: final_issues,
        })
    }

    /// Переводит зону в `NEEDS_FSCK` durable-записью корня.
    ///
    /// Пишутся только две копии `RootEntry`; дерево, overflow, chain и пулы
    /// не читаются и не изменяются. Это позволяет изолировать зону с
    /// zone-fatal повреждением, не усугубляя порчу.
    ///
    /// Возвращает `true`, если зона теперь помечена (или уже была помечена).
    fn quarantine_zone(&self, zone: u32, head: &RootEntry) -> Result<bool, ParallelError> {
        if zone == 0 {
            // Каталог — file-fatal класс; его нельзя «изолировать» частично.
            return Ok(false);
        }
        if head.flags.contains(RootFlags::NEEDS_FSCK) {
            if let Some(flags) = self.zone_state.get(zone as usize) {
                flags.fetch_or(ZONE_DEGRADED | ZONE_NEEDS_FSCK, Ordering::AcqRel);
            }
            return Ok(true);
        }
        self.ensure_writable()?;
        let version = self.allocator.next_txn_exact()?;
        let mut record = *head;
        record.version = version;
        record.flags = head.flags.union(RootFlags::NEEDS_FSCK);
        if record.prev_record >= record.page_limit_at_commit {
            record.prev_record = 0;
        }
        if record.free_head >= record.page_limit_at_commit {
            record.free_head = 0;
        }
        if record.meta_root >= record.page_limit_at_commit {
            record.meta_root = 0;
        }
        record
            .check_fields(self.geometry.page_count_max())
            .map_err(|_| ParallelError::InvalidArgument {
                field: "quarantine root",
            })?;
        let slot = self.geometry.head_slot(zone)?;
        let Some(guard_ref) = self.zone_guard.get(zone as usize) else {
            return Err(ParallelError::InvalidArgument { field: "zone_seq" });
        };
        let guard = EpochGuard::enter(guard_ref);
        let ring = Ring::new(&self.file, &self.geometry);
        let written = ring
            .write_cell(slot.page_a, slot.cell_offset(version), &record)
            .and_then(|()| ring.write_cell(slot.page_b, slot.cell_offset(version), &record));
        drop(guard);
        written?;
        self.fsync_data()?;
        if let Some(block) = self.heads.get(zone as usize) {
            block.store(&record);
        }
        if let Some(flags) = self.zone_state.get(zone as usize) {
            flags.fetch_or(ZONE_DEGRADED | ZONE_NEEDS_FSCK, Ordering::AcqRel);
        }
        self.published_txn.fetch_max(version, Ordering::Release);
        self.stats.publications.fetch_add(1, Ordering::Relaxed);
        // Durable `ALLOC_RECORD.txn_limit` должен покрывать новую версию.
        self.sync()?;
        Ok(true)
    }

    fn ensure_writable(&self) -> Result<(), ParallelError> {
        if self.read_only {
            return Err(ParallelError::ReadOnly {
                reason: FatalKind::ReadOnlyOpen,
            });
        }
        if let Some(reason) = self.fatal() {
            return Err(ParallelError::ReadOnly { reason });
        }
        Ok(())
    }

    fn ensure_zone_writable(&self, zone: u32) -> Result<(), ParallelError> {
        if zone == 0 || zone >= self.geometry.max_zones() {
            return Err(ParallelError::InvalidArgument { field: "zone_seq" });
        }
        let flags = self
            .zone_state
            .get(zone as usize)
            .map_or(0, |value| value.load(Ordering::Acquire));
        if flags & ZONE_DEGRADED != 0 {
            return Err(ParallelError::ZoneDegraded {
                zone,
                epoch: self.load_guard(zone),
            });
        }
        Ok(())
    }

    fn ensure_zone_readable(&self, zone: u32) -> Result<(), ParallelError> {
        if zone == 0 || zone >= self.geometry.max_zones() {
            return Err(ParallelError::NoZoneVersion { zone });
        }
        let flags = self
            .zone_state
            .get(zone as usize)
            .map_or(0, |value| value.load(Ordering::Acquire));
        if flags & ZONE_DEGRADED != 0 {
            return Err(ParallelError::ZoneDegraded {
                zone,
                epoch: self.load_guard(zone),
            });
        }
        Ok(())
    }

    fn degrade_zone(&self, zone: u32) {
        self.stats.zone_degraded.fetch_add(1, Ordering::Relaxed);
        if let Some(flags) = self.zone_state.get(zone as usize) {
            flags.fetch_or(ZONE_DEGRADED | ZONE_NEEDS_FSCK, Ordering::AcqRel);
        }
    }

    fn load_guard(&self, zone: u32) -> u32 {
        self.zone_guard
            .get(zone as usize)
            .map_or(0, |guard| guard.load(Ordering::Acquire))
    }

    fn head(&self, zone: u32) -> Option<RootEntry> {
        match self.heads.get(zone as usize) {
            Some(block) => match block.load() {
                HeadRead::Stable(entry) => Some(entry),
                HeadRead::Empty | HeadRead::Unstable => None,
            },
            None => None,
        }
    }

    fn head_read(&self, zone: u32) -> HeadRead {
        self.heads
            .get(zone as usize)
            .map_or(HeadRead::Empty, PublishedHead::load)
    }

    fn lease(&self, zone: u32) -> &Mutex<()> {
        let index = (zone as usize) % LEASE_SHARDS;
        match self.leases.get(index) {
            Some(lease) => lease,
            None => self.leases.first().unwrap_or(&FALLBACK_LEASE),
        }
    }

    /// Берёт writer-lease зоны (или каталога `0`).
    ///
    /// Разные зоны пишутся параллельно; коллизия шардов лишь сериализует
    /// открытие/коммит. Lease удерживается пока жив `MutexGuard`.
    pub(crate) fn lease_guard(&self, zone: u32) -> MutexGuard<'_, ()> {
        lock_unpoison(self.lease(zone))
    }

    /// Голова зоны без проверки читаемости (включая каталог `0`).
    #[must_use]
    pub(crate) fn head_entry(&self, zone: u32) -> Option<RootEntry> {
        self.head(zone)
    }

    /// Голова каталога зон (`owner_zone = 0`) из памяти.
    #[must_use]
    pub(crate) fn catalog_head(&self) -> Option<RootEntry> {
        self.head(0)
    }

    /// Сбрасывает in-memory состояние слота под переиспользование `zone_seq`
    /// (tombstone → новая зона): глубина chain неизвестна, деградация старой
    /// зоны к новому владельцу не относится.
    pub(crate) fn reset_zone_slot(&self, zone: u32) {
        if let Some(depth) = self.chain_depth.get(zone as usize) {
            depth.store(CHAIN_UNKNOWN, Ordering::Release);
        }
        if let Some(flags) = self.zone_state.get(zone as usize) {
            flags.store(0, Ordering::Release);
        }
    }

    /// Читает страницу данных в готовый буфер (zero-alloc read-path v2).
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — страница вне data-региона; `Io` — ошибка чтения.
    pub(crate) fn read_page_into(&self, page: u32, buffer: &mut [u8]) -> Result<(), ParallelError> {
        if page < self.geometry.page_data_first() || page >= self.geometry.page_count_max() {
            return Err(ParallelError::InvalidArgument { field: "page_id" });
        }
        if buffer.len() != PAGE_SIZE_V2 as usize {
            return Err(ParallelError::InvalidArgument {
                field: "page_buffer",
            });
        }
        let offset = self.geometry.page_offset(page)?;
        self.file.read_exact_at(buffer, offset)?;
        Ok(())
    }

    /// `fdatasync` с инъекцией ошибки (тестовый harness); любая ошибка —
    /// `Io`, вызывающий сам решает про `CommitUncertain`.
    fn fsync_data(&self) -> Result<(), ParallelError> {
        let delay = self.sync_delay_ns.load(Ordering::Acquire);
        if delay != 0 {
            // `fdatasync` одного inode сериализуется в ядре — модель это
            // учитывает, иначе замер не отражает устройство.
            let _gate = lock_unpoison(&self.sync_delay_gate);
            std::thread::sleep(std::time::Duration::from_nanos(delay));
        }
        if self
            .io_fault_hook
            .as_ref()
            .is_some_and(|hook| hook.fail_sync())
        {
            return Err(ParallelError::Io(std::io::Error::other(
                "injected fdatasync failure",
            )));
        }
        retry_eintr(|| fdatasync(&self.file))
            .map_err(|error| ParallelError::Io(std::io::Error::from(error)))
    }

    fn fire(&self, point: CrashPoint) {
        if let Some(hook) = self.crash_hook.as_ref() {
            hook.at(point);
        }
    }

    fn write_alloc_record(
        &self,
        seq: u64,
        page_limit: u64,
        txn_limit: u64,
    ) -> Result<(), ParallelError> {
        let record_a = AllocRecord {
            page_no: PAGE_ALLOC_RECORD_A,
            seq,
            page_limit,
            txn_limit,
            write_unix_ns: unix_now_ns(),
            leader_term: LEADER_TERM_M1,
            epoch_hint: self.gc.freeze_epoch(),
            writer_pid: u64::from(std::process::id()),
        };
        let record_b = AllocRecord {
            page_no: PAGE_ALLOC_RECORD_B,
            ..record_a
        };
        write_at(
            &self.file,
            u64::from(PAGE_ALLOC_RECORD_A) * u64::from(PAGE_SIZE_V2),
            &record_a.encode(),
        )?;
        write_at(
            &self.file,
            u64::from(PAGE_ALLOC_RECORD_B) * u64::from(PAGE_SIZE_V2),
            &record_b.encode(),
        )?;
        Ok(())
    }

    fn chain_depth(&self, zone: u32) -> Result<u32, ParallelError> {
        let Some(slot) = self.chain_depth.get(zone as usize) else {
            return Err(ParallelError::InvalidArgument { field: "zone_seq" });
        };
        let value = slot.load(Ordering::Acquire);
        if value != CHAIN_UNKNOWN {
            return Ok(value);
        }
        let Some(head) = self.head(zone) else {
            slot.store(0, Ordering::Release);
            return Ok(0);
        };
        let stats = Self::inspect_chain(zone, head, &Ring::new(&self.file, &self.geometry))?;
        slot.store(stats.depth, Ordering::Release);
        Ok(stats.depth)
    }

    fn walk_chain(
        &self,
        zone: u32,
        head: RootEntry,
        ceiling: u64,
    ) -> Result<RootEntry, ParallelError> {
        let ring = Ring::new(&self.file, &self.geometry);
        let mut page = head.prev_record;
        let mut upper = head.version;
        let mut oldest = 0_u64;
        let mut hops = 0_u32;
        while page != 0 {
            hops = hops.saturating_add(1);
            if hops > MAX_ROOT_CHAIN_HOPS {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::RootChain,
                    page: Some(page),
                });
            }
            if page >= head.page_limit_at_commit {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::RootChain,
                    page: Some(page),
                });
            }
            let Some(chain) = ring.read_chain(page)? else {
                break;
            };
            if chain.owner_zone != zone {
                // Освобождённый/переиспользованный хвост chain — конец истории,
                // а не порча (§4.4 п. 3).
                break;
            }
            if chain.entry.version >= upper {
                // Страница переиспользована после освобождения хвоста.
                break;
            }
            oldest = chain.entry.version;
            if chain.entry.version <= ceiling {
                return Ok(chain.entry);
            }
            upper = chain.entry.version;
            page = chain.entry.prev_record;
        }
        Err(ParallelError::StaleRoot {
            zone,
            requested: ceiling,
            oldest_retained: oldest,
        })
    }

    fn inspect_chain(
        zone: u32,
        head: RootEntry,
        ring: &Ring<'_>,
    ) -> Result<ChainStats, ParallelError> {
        let mut stats = ChainStats::default();
        let mut page = head.prev_record;
        let mut upper = head.version;
        while page != 0 {
            stats.pages = stats.pages.saturating_add(1);
            if stats.pages > MAX_ROOT_CHAIN_HOPS {
                stats
                    .issues
                    .push(format!("zone {zone}: chain hop limit exceeded"));
                return Ok(stats);
            }
            if page >= head.page_limit_at_commit {
                stats
                    .issues
                    .push(format!("zone {zone}: chain page {page} beyond head limit"));
                return Ok(stats);
            }
            let Some(chain) = ring.read_chain(page)? else {
                stats.torn = stats.torn.saturating_add(1);
                return Ok(stats);
            };
            if chain.owner_zone != zone {
                // Освобождённый хвост: конец chain, не ошибка (§4.4).
                return Ok(stats);
            }
            if chain.entry.version >= upper {
                // Хвост переиспользован после GC — конец chain.
                return Ok(stats);
            }
            upper = chain.entry.version;
            page = chain.entry.prev_record;
            stats.depth = stats.depth.saturating_add(1);
        }
        Ok(stats)
    }
}

/// `ZoneSnapshot`: стабильная версия зоны + RAII-пин.
pub struct ZoneSnapshot<'a> {
    root: RootEntry,
    pin: PinGuard<'a>,
    gc: &'a GcState,
    zone: u32,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl std::fmt::Debug for ZoneSnapshot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneSnapshot")
            .field("zone", &self.zone)
            .field("version", &self.root.version)
            .field("root_page", &self.root.root_page)
            .field("overflow", &self.pin.is_overflow())
            .finish()
    }
}

impl ZoneSnapshot<'_> {
    /// Запись корня.
    #[must_use]
    pub const fn root(&self) -> &RootEntry {
        &self.root
    }

    /// Версия (`txn`).
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.root.version
    }

    /// Зона.
    #[must_use]
    pub const fn zone(&self) -> u32 {
        self.zone
    }

    /// Версия пина (для диагностики).
    #[must_use]
    pub const fn pinned_version(&self) -> u64 {
        self.pin.version()
    }

    /// Использован EPOCH-overflow-пин.
    #[must_use]
    pub const fn is_overflow_pin(&self) -> bool {
        self.pin.is_overflow()
    }
}

impl Drop for ZoneSnapshot<'_> {
    fn drop(&mut self) {
        self.gc.mark_dirty(self.zone);
    }
}

#[derive(Default)]
struct ChainStats {
    pages: u32,
    torn: u32,
    depth: u32,
    issues: Vec<String>,
}

enum HeadRead {
    Empty,
    Stable(RootEntry),
    Unstable,
}

struct PublishedHead {
    nonce: AtomicU64,
    words: [AtomicU64; 8],
}

impl PublishedHead {
    fn new() -> Self {
        Self {
            nonce: AtomicU64::new(0),
            words: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn store(&self, entry: &RootEntry) {
        let raw = entry.encode();
        self.nonce.fetch_add(1, Ordering::AcqRel);
        for (index, word) in self.words.iter().enumerate() {
            let start = index * 8;
            let chunk: [u8; 8] = raw
                .get(start..start + 8)
                .and_then(|slice| slice.try_into().ok())
                .unwrap_or([0_u8; 8]);
            word.store(u64::from_le_bytes(chunk), Ordering::Release);
        }
        self.nonce.fetch_add(1, Ordering::Release);
    }

    fn load(&self) -> HeadRead {
        let first = self.nonce.load(Ordering::Acquire);
        if !first.is_multiple_of(2) {
            return HeadRead::Unstable;
        }
        let mut raw = [0_u8; ROOT_ENTRY_SIZE as usize];
        for (index, word) in self.words.iter().enumerate() {
            let value = word.load(Ordering::Acquire).to_le_bytes();
            let start = index * 8;
            if let Some(span) = raw.get_mut(start..start + 8) {
                span.copy_from_slice(&value);
            }
        }
        let second = self.nonce.load(Ordering::Acquire);
        if first != second || !second.is_multiple_of(2) {
            return HeadRead::Unstable;
        }
        match RootEntry::decode(&raw) {
            Some(entry) => HeadRead::Stable(entry),
            None => HeadRead::Empty,
        }
    }
}

fn allocate_heads(max_zones: u32) -> Result<Box<[PublishedHead]>, ParallelError> {
    let count = usize::try_from(max_zones)
        .map_err(|_| ParallelError::InvalidArgument { field: "max_zones" })?;
    let mut heads = Vec::new();
    heads
        .try_reserve_exact(count)
        .map_err(|_| ParallelError::MapFull {
            high_water: u64::from(max_zones),
            page_count_max: max_zones,
        })?;
    heads.resize_with(count, PublishedHead::new);
    Ok(heads.into_boxed_slice())
}

fn allocate_u32(max_zones: u32, initial: u32) -> Result<Box<[AtomicU32]>, ParallelError> {
    let count = usize::try_from(max_zones)
        .map_err(|_| ParallelError::InvalidArgument { field: "max_zones" })?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ParallelError::MapFull {
            high_water: u64::from(max_zones),
            page_count_max: max_zones,
        })?;
    values.resize_with(count, || AtomicU32::new(initial));
    Ok(values.into_boxed_slice())
}

fn allocate_u64(max_zones: u32, initial: u64) -> Result<Box<[AtomicU64]>, ParallelError> {
    let count = usize::try_from(max_zones)
        .map_err(|_| ParallelError::InvalidArgument { field: "max_zones" })?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ParallelError::MapFull {
            high_water: u64::from(max_zones),
            page_count_max: max_zones,
        })?;
    values.resize_with(count, || AtomicU64::new(initial));
    Ok(values.into_boxed_slice())
}

fn allocate_u8(max_zones: u32, initial: u8) -> Result<Box<[AtomicU8]>, ParallelError> {
    let count = usize::try_from(max_zones)
        .map_err(|_| ParallelError::InvalidArgument { field: "max_zones" })?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| ParallelError::MapFull {
            high_water: u64::from(max_zones),
            page_count_max: max_zones,
        })?;
    values.resize_with(count, || AtomicU8::new(initial));
    Ok(values.into_boxed_slice())
}

/// Помечает зоны с durable `NEEDS_FSCK` как degraded (write-locked).
fn apply_root_flags(zone_state: &mut [AtomicU8], heads: &[Option<RootEntry>]) {
    for (index, head) in heads.iter().enumerate() {
        if let Some(entry) = head
            && entry.flags.contains(RootFlags::NEEDS_FSCK)
            && let Some(flag) = zone_state.get_mut(index)
        {
            *flag = AtomicU8::new(ZONE_DEGRADED | ZONE_NEEDS_FSCK);
        }
    }
}

fn allocate_leases() -> Result<Box<[Mutex<()>]>, ParallelError> {
    let mut leases = Vec::new();
    leases
        .try_reserve_exact(LEASE_SHARDS)
        .map_err(|_| ParallelError::MapFull {
            high_water: LEASE_SHARDS as u64,
            page_count_max: u32::try_from(LEASE_SHARDS).unwrap_or(u32::MAX),
        })?;
    leases.resize_with(LEASE_SHARDS, || Mutex::new(()));
    Ok(leases.into_boxed_slice())
}

fn allocate_pools() -> Result<Box<[Mutex<FreePoolShard>]>, ParallelError> {
    let mut pools = Vec::new();
    pools
        .try_reserve_exact(FREE_POOL_SHARDS)
        .map_err(|_| ParallelError::MapFull {
            high_water: FREE_POOL_SHARDS as u64,
            page_count_max: u32::try_from(FREE_POOL_SHARDS).unwrap_or(u32::MAX),
        })?;
    pools.resize_with(FREE_POOL_SHARDS, || Mutex::new(FreePoolShard::default()));
    Ok(pools.into_boxed_slice())
}

fn make_caches(entries: usize) -> (Option<PageCacheV2>, Option<PageCache>) {
    if entries == 0 {
        return (None, None);
    }
    (
        Some(PageCacheV2::with_capacity(entries)),
        Some(PageCache::with_capacity(PAGE_SIZE_V2, entries)),
    )
}

fn lock_unpoison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn acquire_lock(path: &Path) -> Result<WriterLock, ParallelError> {
    match WriterLock::acquire(path) {
        Ok(Some(lock)) => Ok(lock),
        Err(crate::ZoneFileError::NotRegularFile) => Err(ParallelError::NotRegularFile),
        Err(crate::ZoneFileError::Io(error)) => Err(ParallelError::Io(error)),
        Ok(None) | Err(_) => Err(ParallelError::Busy),
    }
}

fn open_file(path: &Path, extra: OFlags) -> Result<File, ParallelError> {
    let flags = extra | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let fd = fs_open(path.as_os_str(), flags, Mode::RUSR | Mode::WUSR).map_err(|error| {
        if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::ISDIR {
            ParallelError::NotRegularFile
        } else {
            ParallelError::Io(std::io::Error::from(error))
        }
    })?;
    Ok(File::from(fd))
}

fn open_existing(path: &Path, access: OFlags) -> Result<File, ParallelError> {
    let fd = fs_open(
        path.as_os_str(),
        access | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::ISDIR {
            ParallelError::NotRegularFile
        } else {
            ParallelError::Io(std::io::Error::from(error))
        }
    })?;
    Ok(File::from(fd))
}

fn write_at(file: &File, offset: u64, data: &[u8]) -> Result<(), ParallelError> {
    file.write_all_at(data, offset)?;
    Ok(())
}

fn sync_parent_dir(path: &Path) -> Result<(), ParallelError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let fd = fs_open(
        parent.as_os_str(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    retry_eintr(|| fsync(&fd)).map_err(std::io::Error::from)?;
    Ok(())
}

fn retry_eintr(
    mut operation: impl FnMut() -> Result<(), rustix::io::Errno>,
) -> Result<(), rustix::io::Errno> {
    loop {
        match operation() {
            Err(rustix::io::Errno::INTR) => {}
            other => return other,
        }
    }
}

fn backoff(attempt: u32) {
    // 10 мкс — нормативный backoff §5.3; 100 мкс даёт запас на планировщик,
    // чтобы отличить «застрявший» guard (F-11) от обычной конкуренции.
    let micros = 10_u64.saturating_mul(u64::from(attempt.min(10)));
    let micros = micros.max(100);
    std::thread::sleep(std::time::Duration::from_micros(micros));
}

fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// Открывает файл только для `fsck` (без writer-блокировки).
///
/// # Errors
///
/// См. [`ParallelStore::open`].
pub fn open_read_only(path: &Path) -> Result<ParallelStore, ParallelError> {
    ParallelStore::open(
        path,
        OpenConfigV2 {
            read_only: true,
            writer_lock: false,
            page_cache_entries: DEFAULT_PAGE_CACHE_V2_ENTRIES,
        },
    )
}

/// Offline `fsck --repair`: открывает файл под `LOCK_EX`, возвращает утёкшие
/// страницы в durable free-пул и закрывает стор.
///
/// Пересечение множеств страниц (file-fatal) — отказ: такой файл чинится
/// только вручную/через `fsck --verify`. Функция идемпотентна: повторный
/// вызов на чистом файле возвращает `repaired_pages = 0`.
///
/// # Errors
///
/// `Busy` — файл занят другим writer'ом; `Corrupt`/`Io`/`ReadOnly`/`MapFull`.
pub fn fsck_repair(path: &Path) -> Result<RepairReport, ParallelError> {
    let store = ParallelStore::open(
        path,
        OpenConfigV2 {
            read_only: false,
            writer_lock: true,
            page_cache_entries: DEFAULT_PAGE_CACHE_V2_ENTRIES,
        },
    )?;
    store.repair_leaks()
}
