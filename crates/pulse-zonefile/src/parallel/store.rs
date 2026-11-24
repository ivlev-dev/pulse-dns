//! `ParallelStore` — фаза A параллельной записи v2.0.
//!
//! Стор владеет файлом, layout-геометрией, ring-головами в памяти, аллокатором,
//! in-process пинами и durable-барьером `ALLOC_RECORD`. Публикация корня — две
//! фазы (данные + `ALLOC_RECORD` + chain → `fdatasync`; две копии `RootEntry` →
//! `fdatasync`), затем публикация головы в памяти.
//!
//! B+tree, per-zone пулы, group commit и межпроцессная запись — фаза B.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering, fence};
use std::sync::{Mutex, MutexGuard};

use rustix::fs::{FileType, Mode, OFlags, fdatasync, fstat, fsync, ftruncate, open as fs_open};

use crate::consts::MAX_TREE_DEPTH;
use crate::lock::WriterLock;
use crate::parallel::alloc::{AllocHandle, AllocTicket, Allocator};
use crate::parallel::consts::{
    ALLOC_RECORD_SEQ_FIRST, ALLOC_RECORD_SIZE, DEFAULT_MAX_ZONES, DEFAULT_PAGE_COUNT_MAX,
    LAYOUT_HEAD_RECORD_SIZE, LEADER_TERM_M1, MAX_ROOT_CHAIN_HOPS, MAX_ROOT_CHAIN_PAGES,
    PAGE_ALLOC_RECORD_A, PAGE_ALLOC_RECORD_B, PAGE_LAYOUT_HEAD_A, PAGE_LAYOUT_HEAD_B, PAGE_SIZE_V2,
    PIN_ATTEMPTS, READER_SLOTS_V2, ROOT_ENTRY_SIZE, ROOT_VERSIONS,
};
use crate::parallel::error::{FatalKind, ParallelError, V2CorruptKind};
use crate::parallel::geometry::Geometry;
use crate::parallel::layout::{
    AllocRecord, LayoutHead, SuperblockV2, SyncModeV2, WriterRegistry, new_instance_uuid,
};
use crate::parallel::pins::{EpochGuard, FreezeGuard, GcState, PinGuard, PinTable, Reader};
use crate::parallel::recovery::{
    FsckLiteReport, OpenConfigV2, RecoveryReport, merge_fatal, read_at, recover, scan_roots,
};
use crate::parallel::ring::Ring;
use crate::parallel::root::{RootEntry, RootFlags};

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
    heads: Box<[PublishedHead]>,
    zone_guard: Box<[AtomicU32]>,
    zone_state: Box<[AtomicU8]>,
    chain_depth: Box<[AtomicU32]>,
    pins: PinTable,
    gc: GcState,
    leases: Box<[Mutex<()>]>,
    fatal: Mutex<Option<FatalKind>>,
    read_only: bool,
    crash_hook: Option<Box<dyn CrashHook>>,
    stats: StatsCounters,
    report: RecoveryReport,
}

struct AllocDurable {
    seq: u64,
    page_limit: u64,
    txn_limit: u64,
}

#[derive(Default)]
struct StatsCounters {
    publications: AtomicU64,
    chain_evictions: AtomicU64,
    reader_contended: AtomicU64,
    zone_degraded: AtomicU64,
}

const ZONE_DEGRADED: u8 = 1 << 0;
const ZONE_NEEDS_FSCK: u8 = 1 << 1;
const CHAIN_UNKNOWN: u32 = u32::MAX;
const LEASE_SHARDS: usize = 256;
static FALLBACK_LEASE: Mutex<()> = Mutex::new(());

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
        if config.sync_mode != SyncModeV2::Sync {
            return Err(ParallelError::Unsupported {
                what: "sync mode (phase A implements Sync only)",
            });
        }
        let geometry = Geometry::new(
            config.max_zones,
            config.page_count_max,
            config.max_root_chain_pages,
            config.reader_slots,
        )?;
        let lock = acquire_lock(path)?;
        let file = open_file(path, OFlags::CREATE | OFlags::EXCL)?;
        let lock_path = WriterLock::path_for(path);
        let result = Self::create_locked(path, geometry, file, lock);
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
    ) -> Result<Self, ParallelError> {
        ftruncate(&file, geometry.file_size()).map_err(std::io::Error::from)?;
        let uuid = new_instance_uuid();
        let superblock_a = SuperblockV2::for_geometry(geometry, 0, uuid, SyncModeV2::Sync);
        let superblock_b = SuperblockV2::for_geometry(geometry, 1, uuid, SyncModeV2::Sync);
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
        let pins = PinTable::new(geometry.reader_slots().min(READER_SLOTS_V2))?;
        let gc = GcState::new(geometry.max_zones())?;
        let leases = allocate_leases()?;
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
            heads,
            zone_guard,
            zone_state,
            chain_depth,
            pins,
            gc,
            leases,
            fatal: Mutex::new(None),
            read_only: false,
            crash_hook: None,
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
        let zone_guard = allocate_u32(geometry.max_zones(), 0)?;
        let chain_depth = allocate_u32(geometry.max_zones(), CHAIN_UNKNOWN)?;
        let pins = PinTable::new(geometry.reader_slots().min(READER_SLOTS_V2))?;
        let gc = GcState::new(geometry.max_zones())?;
        let leases = allocate_leases()?;
        let allocator = Allocator::new(
            recovered.durable_page_limit,
            recovered.next_txn,
            geometry.page_count_max(),
        )?;
        let published_txn = recovered.report.max_root_version;
        let fatal = recovered.report.fatal;
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
            heads,
            zone_guard,
            zone_state,
            chain_depth,
            pins,
            gc,
            leases,
            fatal: Mutex::new(fatal),
            read_only: config.read_only,
            crash_hook: None,
            stats: StatsCounters::default(),
            report: recovered.report,
        })
    }

    /// Устанавливает crash-хук (только до публикации стора между потоками).
    pub fn set_crash_hook(&mut self, hook: Box<dyn CrashHook>) {
        self.crash_hook = Some(hook);
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
        StoreStats {
            alloc_cas_retries: self.allocator.cas_retries(),
            txn_cas_retries: self.allocator.txn_cas_retries(),
            reader_pin_overflow: self.pins.overflow_total(),
            publications: self.stats.publications.load(Ordering::Relaxed),
            chain_evictions: self.stats.chain_evictions.load(Ordering::Relaxed),
            reader_contended: self.stats.reader_contended.load(Ordering::Relaxed),
            zone_degraded: self.stats.zone_degraded.load(Ordering::Relaxed),
        }
    }

    /// `MP(z)` (минимум пинов; `u64::MAX` — пинов не было).
    #[must_use]
    pub fn min_pinned(&self, zone: u32) -> u64 {
        self.gc.mp(zone)
    }

    /// `RV_z = min(D_z − 1, MP(z), freeze_epoch)`.
    #[must_use]
    pub fn reclaim_version(&self, zone: u32) -> u64 {
        let durable_version = self.head(zone).map_or(0, |entry| entry.version);
        self.gc.reclaim_version(zone, durable_version)
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
        }
        u32::try_from(zones.len()).map_err(|_| ParallelError::InvalidArgument { field: "gc" })
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
        let mut durable = lock_unpoison(&self.alloc_durable);
        let page_limit = durable.page_limit.max(self.allocator.cursor());
        let txn_limit = durable.txn_limit.max(self.published_txn());
        let seq = durable.seq.saturating_add(1);
        self.write_alloc_record(seq, page_limit, txn_limit)?;
        retry_eintr(|| fdatasync(&self.file)).map_err(std::io::Error::from)?;
        durable.seq = seq;
        durable.page_limit = page_limit;
        durable.txn_limit = txn_limit;
        self.durable_page_limit.store(page_limit, Ordering::Release);
        self.durable_txn_limit.store(txn_limit, Ordering::Release);
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
        self.ensure_writable()?;
        self.ensure_zone_writable(entry.owner_zone)?;
        let zone = entry.owner_zone;
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
        let _lease = lock_unpoison(self.lease(zone));
        let head = self.head(zone);
        if let Some(current) = head
            && entry.version <= current.version
        {
            return Err(ParallelError::InvalidArgument { field: "version" });
        }
        let slot = self.geometry.zone_slot(zone)?;
        let group = usize::try_from(entry.version % u64::from(ROOT_VERSIONS))
            .map_err(|_| ParallelError::InvalidArgument { field: "version" })?;
        let ring = Ring::new(&self.file, &self.geometry);
        let view = ring.read_slot(zone)?;
        let old = view.cell(group);
        let mut chain_write = None;
        let mut max_allocated = self.allocator.cursor().saturating_sub(1);
        if let Some(previous) = old {
            let mp = self.gc.mp(zone);
            let needs_chain = previous.version >= mp;
            if needs_chain {
                let depth = self.chain_depth(zone)?;
                if depth >= self.geometry.max_root_chain_pages() {
                    return Err(ParallelError::ZoneWriterStalled { zone });
                }
                let ticket = self.allocator.reserve_exact(1)?;
                max_allocated = max_allocated.max(u64::from(ticket.first_page));
                chain_write = Some((ticket.first_page, previous, entry.version));
            }
        }
        let prev_record = chain_write.as_ref().map_or_else(
            || head.map_or(0, |current| current.prev_record),
            |(page, _, _)| *page,
        );
        let mut record = entry;
        record.prev_record = prev_record;
        let minimum_limit = [
            record.page_limit_at_commit,
            record.root_page.saturating_add(1),
            record.meta_root.saturating_add(1),
            record.free_head.saturating_add(1),
            record.prev_record.saturating_add(1),
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

        // ФАЗА 1: ALLOC_RECORD + chain-страницы, затем fdatasync.
        let page_limit;
        {
            let mut durable = lock_unpoison(&self.alloc_durable);
            let seq = durable.seq.saturating_add(1);
            let candidate = durable
                .page_limit
                .max(u64::from(minimum_limit))
                .max(self.allocator.cursor())
                .max(max_allocated.saturating_add(1));
            if candidate > u64::from(self.geometry.page_count_max()) {
                return Err(ParallelError::MapFull {
                    high_water: candidate,
                    page_count_max: self.geometry.page_count_max(),
                });
            }
            let txn_limit = durable.txn_limit.max(record.version);
            self.fire(CrashPoint::BeforeAllocRecord);
            self.write_alloc_record(seq, candidate, txn_limit)?;
            if let Some((page, previous, evicted_txn)) = chain_write {
                let chain = crate::parallel::layout::ChainPage {
                    page_no: page,
                    owner_zone: zone,
                    evicted_txn,
                    entry: previous,
                };
                ring.write_chain(&chain)?;
            }
            self.fire(CrashPoint::AfterPhase1Writes);
            retry_eintr(|| fdatasync(&self.file)).map_err(std::io::Error::from)?;
            self.fire(CrashPoint::AfterPhase1Fsync);
            durable.seq = seq;
            durable.page_limit = candidate;
            durable.txn_limit = txn_limit;
            self.durable_page_limit.store(candidate, Ordering::Release);
            self.durable_txn_limit.store(txn_limit, Ordering::Release);
            page_limit = candidate;
        }

        // ФАЗА 2: две копии записи под EpochGuard, затем fdatasync.
        let guard = EpochGuard::enter(
            self.zone_guard
                .get(zone as usize)
                .ok_or(ParallelError::InvalidArgument { field: "zone_seq" })?,
        );
        if chain_write.is_none() && old.is_some_and(|previous| previous.version >= self.gc.mp(zone))
        {
            drop(guard);
            self.stats.reader_contended.fetch_add(1, Ordering::Relaxed);
            return Err(ParallelError::ReaderContended);
        }
        self.fire(CrashPoint::BeforeRootWrite);
        ring.write_cell(slot.page_a, slot.cell_offset(record.version), &record)?;
        self.fire(CrashPoint::AfterRootCopyA);
        ring.write_cell(slot.page_b, slot.cell_offset(record.version), &record)?;
        self.fire(CrashPoint::AfterRootCopyB);
        drop(guard);
        retry_eintr(|| fdatasync(&self.file)).map_err(std::io::Error::from)?;
        self.fire(CrashPoint::AfterPhase2Fsync);

        // Публикация в памяти после durable-фазы.
        self.fire(CrashPoint::BeforeHeadPublish);
        if let Some(block) = self.heads.get(zone as usize) {
            block.store(&record);
        }
        if let Some(flags) = self.zone_state.get(zone as usize)
            && record.flags.contains(RootFlags::NEEDS_FSCK)
        {
            flags.fetch_or(ZONE_NEEDS_FSCK, Ordering::AcqRel);
        }
        self.published_txn
            .fetch_max(record.version, Ordering::Release);
        self.stats.publications.fetch_add(1, Ordering::Relaxed);
        if let Some((page, _, _)) = chain_write {
            self.stats.chain_evictions.fetch_add(1, Ordering::Relaxed);
            if let Some(depth) = self.chain_depth.get(zone as usize) {
                let current = depth.load(Ordering::Acquire);
                if current != CHAIN_UNKNOWN {
                    depth.store(current.saturating_add(1), Ordering::Release);
                }
            }
            self.fire(CrashPoint::AfterHeadPublish);
            return Ok(PublishOutcome {
                zone,
                version: record.version,
                page_limit,
                prev_record,
                evicted_page: Some(page),
            });
        }
        self.fire(CrashPoint::AfterHeadPublish);
        Ok(PublishOutcome {
            zone,
            version: record.version,
            page_limit,
            prev_record,
            evicted_page: None,
        })
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
        let mut stuck_odd: Option<u32> = None;
        let mut stuck_attempts = 0_u32;
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
            if !c1.is_multiple_of(2) && c1 == c2 {
                if stuck_odd == Some(c1) {
                    stuck_attempts = stuck_attempts.saturating_add(1);
                } else {
                    stuck_odd = Some(c1);
                    stuck_attempts = 1;
                }
            } else {
                stuck_odd = None;
                stuck_attempts = 0;
            }
            drop(pin);
            self.gc.mark_dirty(zone);
            self.stats.reader_contended.fetch_add(1, Ordering::Relaxed);
            backoff(attempt);
        }
        if stuck_attempts >= PIN_ATTEMPTS {
            self.degrade_zone(zone);
            return Err(ParallelError::ZoneDegraded {
                zone,
                epoch: self.load_guard(zone),
            });
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
        let offset = self.geometry.page_offset(page)?;
        self.file.write_all_at(&page_buffer, offset)?;
        Ok(())
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
                if chosen.page_limit < scan.max_page_limit
                    || chosen.page_limit < u64::from(self.geometry.page_data_first())
                {
                    merge_fatal(&mut fatal, Some(FatalKind::AllocWatermarkRegression));
                    issues.push("ALLOC_RECORD.page_limit ниже ring/пролога".into());
                }
                if chosen.txn_limit < scan.max_version {
                    merge_fatal(&mut fatal, Some(FatalKind::RootWatermarkRegression));
                    issues.push("ALLOC_RECORD.txn_limit ниже version".into());
                }
                // Диск впереди памяти — незавершённая группа (фаза 1); диск
                // позади — регрессия watermark.
                if chosen.page_limit < self.durable_page_limit()
                    || chosen.txn_limit < self.durable_txn_limit()
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
        }
        if self.durable_page_limit() < scan.max_page_limit {
            merge_fatal(&mut fatal, Some(FatalKind::AllocWatermarkRegression));
        }
        if self.durable_txn_limit() < scan.max_version {
            merge_fatal(&mut fatal, Some(FatalKind::RootWatermarkRegression));
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
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::ForeignOwner,
                    page: Some(page),
                });
            }
            if chain.entry.version >= upper {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::RootChain,
                    page: Some(page),
                });
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
                stats
                    .issues
                    .push(format!("zone {zone}: chain page {page} foreign owner"));
                return Ok(stats);
            }
            if chain.entry.version >= upper {
                stats
                    .issues
                    .push(format!("zone {zone}: chain version not decreasing"));
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
        },
    )
}
