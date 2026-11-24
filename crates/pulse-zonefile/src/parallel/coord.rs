//! Межпроцессный координатор записи v2 (ADR 0007, M3).
//!
//! Один sidecar-файл `<file>.pulsecoord`, отображённый `MAP_SHARED`, хранит всё,
//! что обязано быть общим у N процессов, но не является форматом данных:
//!
//! * **аллокатор** — `reserve_cursor`/`reserve_txn` как выровненные
//!   `AtomicU64` (CAS между процессами); durable-барьер по-прежнему
//!   `ALLOC_RECORD` в файле данных под глобальной блокировкой коммита;
//! * **per-zone writer lease** — байтовый диапазон `fcntl`-блокировки на зону
//!   (ядро снимает её при закрытии/смерти процесса) + слот fencing-токена
//!   `(pid, starttime, generation)`;
//! * **per-zone seqlock публикации** (`zone_write_seq`) — протокол «пин →
//!   чтение ring» для читателей другого процесса;
//! * **file reader table** — 1024 слота по 128 Б (`pid`, `starttime`, пины
//!   зон/`EPOCH`) с seqlock на слот;
//! * **durable-водоразделы** `DP`/`DT`, `published_txn` и per-zone `D_z`.
//!
//! # Почему sidecar, а не второй writable-регион в файле данных
//!
//! SEC-ZF-014 (ADR-0004) фиксирует ровно один writable-регион файла зон —
//! reader table. Раскладка v2.0 заморожена (golden-фикстуры, §10.1), поэтому
//! координатор вынесен в отдельный sidecar: формат данных не меняется, v1 и
//! `pulsed` не затрагиваются, а sidecar можно безопасно пересоздать при
//! старте (он не содержит user data). Решение зафиксировано в ADR 0007 §3.
//!
//! # Почему `unsafe`
//!
//! Общая память — единственное место, где нужны атомики поверх `mmap` и
//! `fcntl(F_SETLK)` с байтовым диапазоном. `unsafe` локализован в этом модуле
//! (`#![allow(unsafe_code)]`), каждая операция снабжена SAFETY-комментарием.
//! `rustix` 1.x не предоставляет `F_SETLK` с диапазоном, поэтому используется
//! тонкая обёртка над `libc::fcntl`; `libc` уже есть в workspace.
//!
//! # Модель отказов
//!
//! Процесс может умереть в любой точке (`kill -9`): `fcntl`-locks снимаются
//! ядром, слоты reader table санитизируются по `(pid, starttime)`, курсор
//! откатывается к `DP` при следующем открытии без живых писателей. Слоты lease
//! не санитизируются: generation монотонен, новый владелец перезаписывает слот
//! после захвата блокировки.

#![allow(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};
use std::sync::{Arc, OnceLock};

use memmap2::{MmapMut, MmapOptions};
use rustix::fs::{FileType, Mode, OFlags, fchmod, fstat, ftruncate, open as fs_open};

use crate::parallel::error::ParallelError;
use crate::parallel::geometry::Geometry;

/// Магия sidecar-файла координатора.
pub(crate) const COORD_MAGIC: [u8; 8] = *b"PULSCD01";
/// Версия раскладки sidecar.
pub(crate) const COORD_VERSION: u16 = 1;
/// Суффикс sidecar-файла.
pub(crate) const COORD_FILE_SUFFIX: &str = ".pulsecoord";

const PAGE: usize = 4096;
const HDR_OFF_MAGIC: usize = 0;
const HDR_OFF_VERSION: usize = 8;
const HDR_OFF_FLAGS: usize = 10;
const HDR_OFF_MAX_ZONES: usize = 12;
const HDR_OFF_READER_SLOTS: usize = 16;
const HDR_OFF_UUID: usize = 24;
const HDR_OFF_PAGE_COUNT_MAX: usize = 40;
const HDR_OFF_PAGE_SIZE: usize = 44;

const SC_OFF_CURSOR: usize = PAGE;
const SC_OFF_TXN: usize = PAGE + 64;
const SC_OFF_DURABLE_PAGES: usize = PAGE + 128;
const SC_OFF_DURABLE_TXN: usize = PAGE + 192;
const SC_OFF_PUBLISHED: usize = PAGE + 256;
const SC_OFF_GENERATION: usize = PAGE + 320;
const SC_OFF_ALIVE_HINT: usize = PAGE + 384;
const ARRAYS_OFF: usize = 2 * PAGE;

/// Размер слота lease: `generation | state | pid | starttime`.
const LEASE_SLOT_SIZE: usize = 32;
const LEASE_OFF_GENERATION: usize = 0;
const LEASE_OFF_STATE: usize = 8;
const LEASE_OFF_PID: usize = 16;
const LEASE_OFF_STARTTIME: usize = 24;
const LEASE_STATE_FREE: u64 = 0;
const LEASE_STATE_BUSY: u64 = 1;

/// Смещения в слоте reader table (128 Б).
const RS_SIZE: usize = 128;
const RS_OFF_SEQ: usize = 0;
const RS_OFF_OWNER: usize = 8;
const RS_OFF_EPOCH: usize = 16;
const RS_OFF_STARTTIME: usize = 24;
const RS_OFF_PINS: usize = 32;
const RS_PIN_SIZE: usize = 16;
const RS_PINS: usize = 6;

/// Байтовые диапазоны `fcntl`-блокировок sidecar.
///
/// Диапазоны лежат в «дыре» за заголовком и не пересекаются с данными, хотя
/// `fcntl` разрешает блокировки и за EOF.
const LOCK_OFF_ALIVE: u64 = 1;
const LOCK_OFF_COMMIT: u64 = 2;
const LOCK_OFF_ZONE_BASE: u64 = 1 << 20;

const LOCK_SH: i16 = libc::F_RDLCK as i16;
const LOCK_EX: i16 = libc::F_WRLCK as i16;
const LOCK_UN: i16 = libc::F_UNLCK as i16;

#[cfg(target_os = "linux")]
const FCNTL_SETLK: i32 = libc::F_OFD_SETLK;
#[cfg(target_os = "linux")]
const FCNTL_SETLKW: i32 = libc::F_OFD_SETLKW;
#[cfg(not(target_os = "linux"))]
const FCNTL_SETLK: i32 = libc::F_SETLK;
#[cfg(not(target_os = "linux"))]
const FCNTL_SETLKW: i32 = libc::F_SETLKW;

/// Начальные значения общего состояния, вычисленные из recovery файла данных.
#[derive(Debug, Clone)]
pub(crate) struct CoordInit {
    /// Durable `page_limit` (`DP`).
    pub durable_pages: u64,
    /// Durable `txn_limit` (`DT`).
    pub durable_txn: u64,
    /// Следующий `txn` (`recovery`: `max(DT, max version) + 1`).
    pub next_txn: u64,
    /// Максимальная опубликованная версия (диагностика/`published_txn`).
    pub published: u64,
    /// Per-zone durable версии из ring (`D_z`).
    pub durable_versions: Vec<(u32, u64)>,
}

/// Идентичность процесса: `(pid, starttime)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessIdentity {
    /// PID.
    pub pid: u64,
    /// Время старта процесса (`/proc/<pid>/stat`, поле 22), в тиках.
    pub starttime: u64,
}

/// Идентичность текущего процесса (кэшируется: `/proc/self/stat` стабилен).
pub(crate) fn self_identity() -> ProcessIdentity {
    static SELF: OnceLock<ProcessIdentity> = OnceLock::new();
    *SELF.get_or_init(|| {
        let pid = u64::from(std::process::id());
        ProcessIdentity {
            pid,
            starttime: pid_start_time(pid).unwrap_or(0),
        }
    })
}

/// Время старта процесса `pid` (`/proc/<pid>/stat`, поле 22).
///
/// `None` — процесса нет (или `/proc` недоступен): слот считается мёртвым.
pub(crate) fn pid_start_time(pid: u64) -> Option<u64> {
    let Ok(pid32) = u32::try_from(pid) else {
        return None;
    };
    let raw = std::fs::read(format!("/proc/{pid32}/stat")).ok()?;
    // `comm` может содержать пробелы/скобки: поля ищем после последней ')'.
    let close = raw.iter().rposition(|byte| *byte == b')')?;
    let rest = std::str::from_utf8(raw.get(close + 1..)?).ok()?;
    // После ')' первый токен — поле 3 (`state`); `starttime` — поле 22.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Проверяет, что процесс с `(pid, starttime)` жив.
pub(crate) fn process_alive(pid: u64, starttime: u64) -> bool {
    if pid == 0 {
        return false;
    }
    if starttime == 0 {
        // Не смогли прочитать `/proc/self/stat` (например, контейнер без
        // procfs): не считаем живой чужой слот мёртвым по нулевому starttime —
        // это защита от ложного освобождения. Живость проверяется по pid.
        return pid_start_time(pid).is_some();
    }
    pid_start_time(pid) == Some(starttime)
}

/// RAII-держатель байтового диапазона `fcntl`.
///
/// Держит собственный дескриптор (`dup`): OFD-локи привязаны к
/// open-file-description, поэтому закрытие этого дескриптора не снимает чужие
/// блокировки процесса (в отличие от классических POSIX-локов). Linux-only
/// (`F_OFD_SETLK`); на других платформах используется `F_SETLK`, где закрытие
/// дескриптора снимает все локи процесса — это документированное ограничение.
#[derive(Debug)]
pub(crate) struct RangeLock {
    file: File,
    start: u64,
    len: u64,
}

impl RangeLock {
    fn release(&self) {
        let _ = set_lock(&self.file, FCNTL_SETLK, LOCK_UN, self.start, self.len);
    }
}

impl Drop for RangeLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Эксклюзивное владение координатором для maintenance (`fsck --repair`).
///
/// На время жизни вытесняет `LOCK_SH` процесса на `LOCK_EX` (других живых
/// процессов нет) и возвращает `LOCK_SH` в `Drop`.
#[derive(Debug)]
pub(crate) struct MaintenanceGuard<'a> {
    coord: &'a SharedCoord,
}

impl Drop for MaintenanceGuard<'_> {
    fn drop(&mut self) {
        // Возвращаем SH блокирующе: maintenance не должен «терять» ALIVE.
        let _ = set_lock(&self.coord.file, FCNTL_SETLKW, LOCK_SH, LOCK_OFF_ALIVE, 1);
    }
}

/// Общая разделяемая область координации.
pub(crate) struct SharedCoord {
    file: File,
    map: MmapMut,
    path: PathBuf,
    max_zones: u32,
    reader_slots: u32,
    leases_off: usize,
    zone_seq_off: usize,
    durable_off: usize,
    readers_off: usize,
    /// Держим `LOCK_SH` на `LOCK_OFF_ALIVE` всё время жизни.
    alive_lock: Option<RangeLock>,
}

impl std::fmt::Debug for SharedCoord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedCoord")
            .field("path", &self.path)
            .field("max_zones", &self.max_zones)
            .field("reader_slots", &self.reader_slots)
            .field("cursor", &self.cursor().load(Ordering::Relaxed))
            .field("txn", &self.txn().load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SharedCoord {
    /// Путь sidecar для файла зон `path`.
    pub(crate) fn path_for(path: &Path) -> PathBuf {
        let mut raw = path.as_os_str().to_os_string().into_vec();
        raw.extend_from_slice(COORD_FILE_SUFFIX.as_bytes());
        PathBuf::from(std::ffi::OsString::from_vec(raw))
    }

    /// Открывает/создаёт координатор и инициализирует его из recovery.
    ///
    /// # Errors
    ///
    /// `Busy` — sidecar несовместим, а другой процесс жив; `Io` — открытие/
    /// `mmap`/`ftruncate`; `NotRegularFile` — sidecar не regular-файл;
    /// `InvalidArgument`/`MapFull` — геометрия вне контракта.
    pub(crate) fn open(
        path: &Path,
        geometry: Geometry,
        instance_uuid: [u8; 16],
        init: &CoordInit,
    ) -> Result<Arc<Self>, ParallelError> {
        let coord_path = Self::path_for(path);
        let fd = match fs_open(
            &coord_path,
            OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::LOOP || error == rustix::io::Errno::ISDIR => {
                return Err(ParallelError::NotRegularFile);
            }
            Err(error) => return Err(ParallelError::Io(io::Error::from(error))),
        };
        let file = File::from(fd);
        let stat = fstat(&file).map_err(io::Error::from)?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            return Err(ParallelError::NotRegularFile);
        }
        fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(io::Error::from)?;

        let layout = Layout::new(geometry)?;
        let current_len = u64::try_from(stat.st_size).unwrap_or(0);
        if current_len < layout.len {
            ftruncate(&file, layout.len).map_err(io::Error::from)?;
        }
        // SAFETY: `map_mut` даёт `MAP_SHARED`-отображение всего файла; файл
        // открыт RDWR и не усечён после отображения. Доступ к областям —
        // только через выровненные атомики/байтовые срезы в границах layout.
        let map = unsafe {
            MmapOptions::new()
                .len(
                    usize::try_from(layout.len).map_err(|_| ParallelError::MapFull {
                        high_water: layout.len,
                        page_count_max: geometry.page_count_max(),
                    })?,
                )
                .map_mut(&file)?
        };

        let mut coord = Self {
            file,
            map,
            path: coord_path,
            max_zones: geometry.max_zones(),
            reader_slots: geometry.reader_slots(),
            leases_off: layout.leases_off,
            zone_seq_off: layout.zone_seq_off,
            durable_off: layout.durable_off,
            readers_off: layout.readers_off,
            alive_lock: None,
        };

        let header_matches = coord.header_matches(geometry, instance_uuid);
        // Если живых держателей нет — sidecar можно безопасно пересоздать
        // (курсор откатывается к `DP`, мёртвые слоты вычищаются).
        if coord.try_lock_exclusive(LOCK_OFF_ALIVE) {
            if header_matches {
                coord.reset_ephemeral(init);
            } else {
                coord.initialize(geometry, instance_uuid, init);
            }
            coord.downgrade_alive_to_shared()?;
        } else {
            // Кто-то жив: заголовок обязан совпадать, инициализировать нельзя.
            if !header_matches {
                return Err(ParallelError::Busy);
            }
            let alive = coord.lock_shared(LOCK_OFF_ALIVE)?;
            coord.alive_lock = Some(alive);
            coord.alive_hint().fetch_add(1, Ordering::AcqRel);
            coord.raise_watermarks(init);
        }
        Ok(Arc::new(coord))
    }

    /// Путь sidecar.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    // --- скалярные общие величины ---

    /// `reserve_cursor` (первая невыданная страница).
    #[must_use]
    pub(crate) fn cursor(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_CURSOR)
    }

    /// `reserve_txn` (следующий `txn`).
    #[must_use]
    pub(crate) fn txn(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_TXN)
    }

    /// Durable `page_limit` (`DP`).
    #[must_use]
    pub(crate) fn durable_pages(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_DURABLE_PAGES)
    }

    /// Durable `txn_limit` (`DT`).
    #[must_use]
    pub(crate) fn durable_txn(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_DURABLE_TXN)
    }

    /// Максимальная опубликованная версия.
    #[must_use]
    pub(crate) fn published(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_PUBLISHED)
    }

    /// Счётчик поколений lease (fencing).
    #[must_use]
    pub(crate) fn generation(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_GENERATION)
    }

    /// Подсказка «сколько процессов держат `LOCk_SH`» (диагностика).
    #[must_use]
    pub(crate) fn alive_hint(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_ALIVE_HINT)
    }

    /// `D_z` зоны (durable version), 0 — неизвестно.
    #[must_use]
    pub(crate) fn durable_version(&self, zone: u32) -> u64 {
        if zone >= self.max_zones {
            return 0;
        }
        self.atomic_u64(self.durable_off + zone as usize * 8)
            .load(Ordering::Acquire)
    }

    /// Публикует `D_z` зоны после durable-фазы 2.
    pub(crate) fn set_durable_version(&self, zone: u32, version: u64) {
        if zone < self.max_zones {
            self.atomic_u64(self.durable_off + zone as usize * 8)
                .fetch_max(version, Ordering::Release);
        }
    }

    /// Per-zone seqlock публикации (чётный — стабильно).
    #[must_use]
    pub(crate) fn zone_write_seq(&self, zone: u32) -> u64 {
        if zone >= self.max_zones {
            return 0;
        }
        self.atomic_u64(self.zone_seq_off + zone as usize * 8)
            .load(Ordering::SeqCst)
    }

    /// Входит в критическую секцию публикации зоны (нечётный seqlock).
    ///
    /// Возвращает `false`, если зона вне диапазона.
    pub(crate) fn zone_write_begin(&self, zone: u32) -> bool {
        if zone >= self.max_zones {
            return false;
        }
        self.atomic_u64(self.zone_seq_off + zone as usize * 8)
            .fetch_add(1, Ordering::SeqCst);
        fence(Ordering::SeqCst);
        true
    }

    /// Выходит из критической секции публикации зоны (чётный seqlock).
    pub(crate) fn zone_write_end(&self, zone: u32) {
        if zone < self.max_zones {
            self.atomic_u64(self.zone_seq_off + zone as usize * 8)
                .fetch_add(1, Ordering::SeqCst);
        }
    }

    // --- глобальные блокировки ---

    /// Блокировка коммита: эксклюзивна между процессами, ждёт освобождения.
    ///
    /// # Errors
    ///
    /// `Io` — ошибка `fcntl`.
    pub(crate) fn lock_commit(&self) -> Result<RangeLock, ParallelError> {
        set_lock(&self.file, FCNTL_SETLKW, LOCK_EX, LOCK_OFF_COMMIT, 1)
            .map_err(ParallelError::Io)?;
        let file = match self.file.try_clone() {
            Ok(file) => file,
            Err(error) => {
                let _ = set_lock(&self.file, FCNTL_SETLK, LOCK_UN, LOCK_OFF_COMMIT, 1);
                return Err(ParallelError::Io(error));
            }
        };
        Ok(RangeLock {
            file,
            start: LOCK_OFF_COMMIT,
            len: 1,
        })
    }

    /// Становится единственным живым держателем (maintenance/`fsck`).
    ///
    /// `None` — другие процессы живы. На время удержания `LOCK_SH` процесса
    /// заменяется на `LOCK_EX`; `Drop` возвращает `LOCK_SH`.
    #[must_use]
    pub(crate) fn try_maintenance(&self) -> Option<MaintenanceGuard<'_>> {
        if !self.try_lock_exclusive(LOCK_OFF_ALIVE) {
            return None;
        }
        Some(MaintenanceGuard { coord: self })
    }

    // --- writer lease ---

    /// Слот lease зоны.
    fn lease_slot(&self, zone: u32, field: usize) -> &AtomicU64 {
        self.atomic_u64(self.leases_off + zone as usize * LEASE_SLOT_SIZE + field)
    }

    /// Захватывает lease зоны (non-blocking).
    ///
    /// # Errors
    ///
    /// `ZoneBusy` — зона уже под lease другим writer'ом; `InvalidArgument` —
    /// зона вне геометрии; `Io` — ошибка `fcntl`.
    pub(crate) fn lease_acquire(
        &self,
        zone: u32,
        identity: ProcessIdentity,
    ) -> Result<u64, ParallelError> {
        if zone >= self.max_zones {
            return Err(ParallelError::InvalidArgument { field: "zone_seq" });
        }
        let start = LOCK_OFF_ZONE_BASE + u64::from(zone);
        match set_lock(&self.file, FCNTL_SETLK, LOCK_EX, start, 1) {
            Ok(()) => {}
            Err(error) if is_busy(&error) => {
                return Err(ParallelError::ZoneBusy { zone });
            }
            Err(error) => return Err(ParallelError::Io(error)),
        }
        let generation = self
            .generation()
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        self.lease_slot(zone, LEASE_OFF_GENERATION)
            .store(generation, Ordering::Release);
        self.lease_slot(zone, LEASE_OFF_PID)
            .store(identity.pid, Ordering::Release);
        self.lease_slot(zone, LEASE_OFF_STARTTIME)
            .store(identity.starttime, Ordering::Release);
        self.lease_slot(zone, LEASE_OFF_STATE)
            .store(LEASE_STATE_BUSY, Ordering::Release);
        Ok(generation)
    }

    /// Освобождает lease зоны.
    pub(crate) fn lease_release(&self, zone: u32, generation: u64) {
        if zone >= self.max_zones {
            return;
        }
        let slot_gen = self.lease_slot(zone, LEASE_OFF_GENERATION);
        if slot_gen.load(Ordering::Acquire) == generation {
            self.lease_slot(zone, LEASE_OFF_STATE)
                .store(LEASE_STATE_FREE, Ordering::Release);
        }
        let start = LOCK_OFF_ZONE_BASE + u64::from(zone);
        let _ = set_lock(&self.file, FCNTL_SETLK, LOCK_UN, start, 1);
    }

    /// Владеет ли зоной текущий процесс (по `pid`+`starttime`).
    #[must_use]
    pub(crate) fn lease_owned_by(&self, zone: u32, identity: ProcessIdentity) -> bool {
        if zone >= self.max_zones {
            return false;
        }
        self.lease_slot(zone, LEASE_OFF_STATE)
            .load(Ordering::Acquire)
            == LEASE_STATE_BUSY
            && self.lease_slot(zone, LEASE_OFF_PID).load(Ordering::Acquire) == identity.pid
            && self
                .lease_slot(zone, LEASE_OFF_STARTTIME)
                .load(Ordering::Acquire)
                == identity.starttime
    }

    /// Текущий владелец зоны (для диагностики `Busy`).
    #[must_use]
    pub(crate) fn lease_owner(&self, zone: u32) -> Option<ProcessIdentity> {
        if zone >= self.max_zones
            || self
                .lease_slot(zone, LEASE_OFF_STATE)
                .load(Ordering::Acquire)
                != LEASE_STATE_BUSY
        {
            return None;
        }
        Some(ProcessIdentity {
            pid: self.lease_slot(zone, LEASE_OFF_PID).load(Ordering::Acquire),
            starttime: self
                .lease_slot(zone, LEASE_OFF_STARTTIME)
                .load(Ordering::Acquire),
        })
    }

    /// Fencing-поколение зоны.
    #[must_use]
    pub(crate) fn lease_generation(&self, zone: u32) -> u64 {
        if zone >= self.max_zones {
            return 0;
        }
        self.lease_slot(zone, LEASE_OFF_GENERATION)
            .load(Ordering::Acquire)
    }

    // --- reader table ---

    fn reader_slot(&self, slot: usize, field: usize) -> &AtomicU64 {
        self.atomic_u64(self.readers_off + slot * RS_SIZE + field)
    }

    fn reader_pin_zone(&self, slot: usize, pin: usize) -> &AtomicU32 {
        self.atomic_u32(self.readers_off + slot * RS_SIZE + RS_OFF_PINS + pin * RS_PIN_SIZE)
    }

    fn reader_pin_version(&self, slot: usize, pin: usize) -> &AtomicU64 {
        self.atomic_u64(self.readers_off + slot * RS_SIZE + RS_OFF_PINS + pin * RS_PIN_SIZE + 8)
    }

    fn owner_token(identity: ProcessIdentity) -> u64 {
        let incarnation = (identity.starttime as u32) | 1;
        (identity.pid << 32) | u64::from(incarnation)
    }

    fn token_identity(token: u64) -> ProcessIdentity {
        ProcessIdentity {
            pid: token >> 32,
            starttime: token & 0xFFFF_FFFF,
        }
    }

    /// Регистрирует reader-слот процесса; `None` — таблица полна.
    pub(crate) fn reader_register(&self, identity: ProcessIdentity) -> Option<usize> {
        let token = Self::owner_token(identity);
        for slot in 0..self.reader_slots as usize {
            let owner = self.reader_slot(slot, RS_OFF_OWNER);
            if owner.load(Ordering::Acquire) != 0 {
                continue;
            }
            // `starttime` пишется до публикации токена: GC, увидев токен,
            // обязан увидеть и идентичность.
            self.reader_slot(slot, RS_OFF_STARTTIME)
                .store(identity.starttime, Ordering::Release);
            if owner
                .compare_exchange(0, token, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let seq = self.reader_slot(slot, RS_OFF_SEQ);
                seq.fetch_add(1, Ordering::SeqCst);
                self.reader_slot(slot, RS_OFF_EPOCH)
                    .store(0, Ordering::Release);
                for pin in 0..RS_PINS {
                    self.reader_pin_zone(slot, pin).store(0, Ordering::Release);
                    self.reader_pin_version(slot, pin)
                        .store(0, Ordering::Release);
                }
                seq.fetch_add(1, Ordering::SeqCst);
                return Some(slot);
            }
        }
        None
    }

    /// Снимает reader-слот (только свой токен).
    pub(crate) fn reader_unregister(&self, slot: usize, identity: ProcessIdentity) {
        if slot >= self.reader_slots as usize {
            return;
        }
        let token = Self::owner_token(identity);
        let owner = self.reader_slot(slot, RS_OFF_OWNER);
        if owner
            .compare_exchange(token, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let seq = self.reader_slot(slot, RS_OFF_SEQ);
        seq.fetch_add(1, Ordering::SeqCst);
        self.reader_slot(slot, RS_OFF_EPOCH)
            .store(0, Ordering::Release);
        for pin in 0..RS_PINS {
            self.reader_pin_zone(slot, pin).store(0, Ordering::Release);
            self.reader_pin_version(slot, pin)
                .store(0, Ordering::Release);
        }
        seq.fetch_add(1, Ordering::SeqCst);
    }

    /// Публикует пин зоны в слоте reader'а.
    ///
    /// Возвращает `Some(pin)` для зонного пина и `None` для EPOCH-overflow
    /// (удерживается до `reader_unregister` — консервативно).
    pub(crate) fn reader_pin(
        &self,
        slot: usize,
        zone: u32,
        version: u64,
        epoch: u64,
    ) -> Option<usize> {
        if slot >= self.reader_slots as usize {
            return None;
        }
        let seq = self.reader_slot(slot, RS_OFF_SEQ);
        seq.fetch_add(1, Ordering::SeqCst);
        let mut chosen = None;
        for pin in 0..RS_PINS {
            let cell = self.reader_pin_zone(slot, pin);
            if cell.load(Ordering::Acquire) == 0 {
                cell.store(zone, Ordering::Release);
                self.reader_pin_version(slot, pin)
                    .store(version, Ordering::SeqCst);
                chosen = Some(pin);
                break;
            }
        }
        if chosen.is_none() {
            let overflow = self.reader_slot(slot, RS_OFF_EPOCH);
            let bound = if epoch == 0 { version } else { epoch };
            let mut current = overflow.load(Ordering::Acquire);
            loop {
                let next = if current == 0 {
                    bound
                } else {
                    current.min(bound)
                };
                match overflow.compare_exchange_weak(
                    current,
                    next,
                    Ordering::SeqCst,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(observed) => current = observed,
                }
            }
        }
        seq.fetch_add(1, Ordering::SeqCst);
        // Полный барьер: пин опубликован до проверки ring/seqlock читателем.
        fence(Ordering::SeqCst);
        chosen
    }

    /// Снимает зонный пин.
    pub(crate) fn reader_unpin(&self, slot: usize, pin: usize) {
        if slot >= self.reader_slots as usize || pin >= RS_PINS {
            return;
        }
        let seq = self.reader_slot(slot, RS_OFF_SEQ);
        seq.fetch_add(1, Ordering::SeqCst);
        self.reader_pin_zone(slot, pin).store(0, Ordering::Release);
        self.reader_pin_version(slot, pin)
            .store(0, Ordering::Release);
        seq.fetch_add(1, Ordering::SeqCst);
    }

    /// Минимальный удерживаемый версион зоны во всех живых слотах.
    ///
    /// Мёртвые слоты (`pid`/`starttime` не совпали) вычищаются CAS-ом и не
    /// участвуют. `None` — пинов нет.
    #[must_use]
    pub(crate) fn oldest_pin(&self, zone: u32) -> Option<u64> {
        let mut oldest: Option<u64> = None;
        for slot in 0..self.reader_slots as usize {
            let owner = self.reader_slot(slot, RS_OFF_OWNER).load(Ordering::Acquire);
            if owner == 0 {
                continue;
            }
            let identity = Self::token_identity(owner);
            if !process_alive(
                identity.pid,
                self.reader_slot(slot, RS_OFF_STARTTIME)
                    .load(Ordering::Acquire),
            ) {
                // Санитизация мёртвого слота: мешает только этот слот.
                let _ = self.reader_slot(slot, RS_OFF_OWNER).compare_exchange(
                    owner,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                continue;
            }
            let Some(view) = self.read_slot(slot) else {
                continue;
            };
            for (pin_zone, version) in view.pins {
                if pin_zone == zone && version != 0 {
                    oldest = Some(oldest.map_or(version, |value| value.min(version)));
                }
            }
            if view.epoch != 0 {
                oldest = Some(oldest.map_or(view.epoch, |value| value.min(view.epoch)));
            }
        }
        oldest
    }

    /// Все живые пины (диагностика/тесты).
    #[must_use]
    pub(crate) fn snapshot_pins(&self) -> Vec<(u32, u64)> {
        let mut pins = Vec::new();
        for slot in 0..self.reader_slots as usize {
            if self.reader_slot(slot, RS_OFF_OWNER).load(Ordering::Acquire) == 0 {
                continue;
            }
            let Some(view) = self.read_slot(slot) else {
                continue;
            };
            for (zone, version) in view.pins {
                if zone != 0 && version != 0 {
                    pins.push((zone, version));
                }
            }
        }
        pins
    }

    /// Санитизирует мёртвые слоты reader table.
    #[must_use]
    pub(crate) fn sanitize_dead(&self) -> u32 {
        let mut cleared: u32 = 0;
        for slot in 0..self.reader_slots as usize {
            let owner = self.reader_slot(slot, RS_OFF_OWNER).load(Ordering::Acquire);
            if owner == 0 {
                continue;
            }
            let identity = Self::token_identity(owner);
            if !process_alive(
                identity.pid,
                self.reader_slot(slot, RS_OFF_STARTTIME)
                    .load(Ordering::Acquire),
            ) && self
                .reader_slot(slot, RS_OFF_OWNER)
                .compare_exchange(owner, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                cleared = cleared.saturating_add(1);
            }
        }
        cleared
    }

    fn read_slot(&self, slot: usize) -> Option<ReaderSlotView> {
        let seq = self.reader_slot(slot, RS_OFF_SEQ);
        let first = seq.load(Ordering::SeqCst);
        if first & 1 != 0 {
            return None;
        }
        let mut pins = [(0_u32, 0_u64); RS_PINS];
        for (index, pin) in pins.iter_mut().enumerate() {
            let zone = self.reader_pin_zone(slot, index).load(Ordering::SeqCst);
            let version = self.reader_pin_version(slot, index).load(Ordering::SeqCst);
            *pin = (zone, version);
        }
        let epoch = self.reader_slot(slot, RS_OFF_EPOCH).load(Ordering::SeqCst);
        let second = seq.load(Ordering::SeqCst);
        if first != second || second & 1 != 0 {
            return None;
        }
        Some(ReaderSlotView { pins, epoch })
    }

    // --- внутренняя инициализация ---

    fn header_matches(&self, geometry: Geometry, uuid: [u8; 16]) -> bool {
        let Some(magic) = self.map.get(HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8) else {
            return false;
        };
        if magic != COORD_MAGIC {
            return false;
        }
        self.header_u16(HDR_OFF_VERSION) == Some(COORD_VERSION)
            && self.header_u32(HDR_OFF_MAX_ZONES) == Some(geometry.max_zones())
            && self.header_u32(HDR_OFF_READER_SLOTS) == Some(geometry.reader_slots())
            && self.header_u32(HDR_OFF_PAGE_COUNT_MAX) == Some(geometry.page_count_max())
            && self.header_u32(HDR_OFF_PAGE_SIZE) == Some(geometry.page_size())
            && self.map.get(HDR_OFF_UUID..HDR_OFF_UUID + 16) == Some(uuid.as_slice())
    }

    fn header_u16(&self, offset: usize) -> Option<u16> {
        let bytes: [u8; 2] = self.map.get(offset..offset + 2)?.try_into().ok()?;
        Some(u16::from_le_bytes(bytes))
    }

    fn header_u32(&self, offset: usize) -> Option<u32> {
        let bytes: [u8; 4] = self.map.get(offset..offset + 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    fn initialize(&mut self, geometry: Geometry, uuid: [u8; 16], init: &CoordInit) {
        // SAFETY: обнуляем только области, вычисленные из геометрии, в границах
        // отображения; все адреса выровнены под атомики (offsets кратны 64/8).
        unsafe {
            let base = self.map.as_mut_ptr();
            std::ptr::write_bytes(base.add(2 * PAGE), 0, self.map.len() - 2 * PAGE);
        }
        let Some(header) = self.map.get_mut(..64) else {
            return;
        };
        let mut put = |offset: usize, value: &[u8]| {
            if let Some(span) = header.get_mut(offset..offset + value.len()) {
                span.copy_from_slice(value);
            }
        };
        put(HDR_OFF_MAGIC, &COORD_MAGIC);
        put(HDR_OFF_VERSION, &COORD_VERSION.to_le_bytes());
        put(HDR_OFF_FLAGS, &0_u16.to_le_bytes());
        put(HDR_OFF_MAX_ZONES, &geometry.max_zones().to_le_bytes());
        put(HDR_OFF_READER_SLOTS, &geometry.reader_slots().to_le_bytes());
        put(HDR_OFF_UUID, &uuid);
        put(
            HDR_OFF_PAGE_COUNT_MAX,
            &geometry.page_count_max().to_le_bytes(),
        );
        put(HDR_OFF_PAGE_SIZE, &geometry.page_size().to_le_bytes());
        self.reset_ephemeral(init);
    }

    fn reset_ephemeral(&mut self, init: &CoordInit) {
        let keep_txn = self.txn().load(Ordering::Acquire);
        self.cursor().store(init.durable_pages, Ordering::SeqCst);
        self.txn()
            .store(keep_txn.max(init.next_txn).max(2), Ordering::SeqCst);
        self.durable_pages()
            .store(init.durable_pages, Ordering::SeqCst);
        self.durable_txn()
            .store(init.durable_txn.max(1), Ordering::SeqCst);
        self.published().store(init.published, Ordering::SeqCst);
        self.generation().store(0, Ordering::SeqCst);
        self.alive_hint().store(0, Ordering::SeqCst);
        for zone in 0..self.max_zones {
            self.lease_slot(zone, LEASE_OFF_STATE)
                .store(LEASE_STATE_FREE, Ordering::SeqCst);
            self.atomic_u64(self.durable_off + zone as usize * 8)
                .store(0, Ordering::SeqCst);
            self.atomic_u64(self.zone_seq_off + zone as usize * 8)
                .store(0, Ordering::SeqCst);
        }
        for (zone, version) in &init.durable_versions {
            self.set_durable_version(*zone, *version);
        }
        for slot in 0..self.reader_slots as usize {
            self.reader_slot(slot, RS_OFF_OWNER)
                .store(0, Ordering::SeqCst);
            self.reader_slot(slot, RS_OFF_SEQ)
                .store(0, Ordering::SeqCst);
            self.reader_slot(slot, RS_OFF_EPOCH)
                .store(0, Ordering::SeqCst);
            for pin in 0..RS_PINS {
                self.reader_pin_zone(slot, pin).store(0, Ordering::SeqCst);
                self.reader_pin_version(slot, pin)
                    .store(0, Ordering::SeqCst);
            }
        }
    }

    fn raise_watermarks(&self, init: &CoordInit) {
        self.cursor()
            .fetch_max(init.durable_pages, Ordering::SeqCst);
        self.txn().fetch_max(init.next_txn.max(2), Ordering::SeqCst);
        self.durable_pages()
            .fetch_max(init.durable_pages, Ordering::SeqCst);
        self.durable_txn()
            .fetch_max(init.durable_txn.max(1), Ordering::SeqCst);
        self.published().fetch_max(init.published, Ordering::SeqCst);
        for (zone, version) in &init.durable_versions {
            self.set_durable_version(*zone, *version);
        }
    }

    fn lock_shared(&self, start: u64) -> Result<RangeLock, ParallelError> {
        // Блокирующий SH: если другой процесс сейчас в init-окне (EX), ждём
        // его перехода в SH, а не падаем с EAGAIN.
        set_lock(&self.file, FCNTL_SETLKW, LOCK_SH, start, 1).map_err(ParallelError::Io)?;
        let file = match self.file.try_clone() {
            Ok(file) => file,
            Err(error) => {
                let _ = set_lock(&self.file, FCNTL_SETLK, LOCK_UN, start, 1);
                return Err(ParallelError::Io(error));
            }
        };
        Ok(RangeLock {
            file,
            start,
            len: 1,
        })
    }

    fn try_lock_exclusive(&self, start: u64) -> bool {
        set_lock(&self.file, FCNTL_SETLK, LOCK_EX, start, 1).is_ok()
    }

    fn downgrade_alive_to_shared(&mut self) -> Result<(), ParallelError> {
        // Замена EX→SH на том же диапазоне атомарна для OFD-локов; классический
        // fcntl также меняет тип существующей блокировки процесса.
        let alive = self.lock_shared(LOCK_OFF_ALIVE)?;
        self.alive_hint().fetch_add(1, Ordering::AcqRel);
        self.alive_lock = Some(alive);
        Ok(())
    }

    #[allow(clippy::cast_ptr_alignment)] // offset выровнен под u64 (debug_assert)
    fn atomic_u64(&self, offset: usize) -> &AtomicU64 {
        debug_assert!(offset + 8 <= self.map.len());
        debug_assert_eq!(offset % 8, 0);
        // SAFETY: `offset` вычислен из геометрии, выровнен под `u64` и лежит в
        // границах `MAP_SHARED`-отображения; `AtomicU64` имеет тот же layout,
        // что и выровненный `u64`. Время жизни отображения ≥ времени жизни
        // ссылки (оба живут в `SharedCoord`).
        unsafe { &*self.map.as_ptr().add(offset).cast::<AtomicU64>() }
    }

    #[allow(clippy::cast_ptr_alignment)] // offset выровнен под u32 (debug_assert)
    fn atomic_u32(&self, offset: usize) -> &AtomicU32 {
        debug_assert!(offset + 4 <= self.map.len());
        debug_assert_eq!(offset % 4, 0);
        // SAFETY: см. `atomic_u64`.
        unsafe { &*self.map.as_ptr().add(offset).cast::<AtomicU32>() }
    }
}

impl Drop for SharedCoord {
    fn drop(&mut self) {
        let hint = self.alive_hint();
        let mut current = hint.load(Ordering::Acquire);
        loop {
            let next = current.saturating_sub(1);
            match hint.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }
}

/// Смещения областей sidecar для заданной геометрии.
#[derive(Debug, Clone, Copy)]
struct Layout {
    leases_off: usize,
    zone_seq_off: usize,
    durable_off: usize,
    readers_off: usize,
    len: u64,
}

impl Layout {
    fn new(geometry: Geometry) -> Result<Self, ParallelError> {
        let max_zones = usize::try_from(geometry.max_zones())
            .map_err(|_| ParallelError::InvalidArgument { field: "max_zones" })?;
        let slots = usize::try_from(geometry.reader_slots()).map_err(|_| {
            ParallelError::InvalidArgument {
                field: "reader_slots",
            }
        })?;
        let leases_off = ARRAYS_OFF;
        let zone_seq_off = align64(
            leases_off
                .checked_add(max_zones * LEASE_SLOT_SIZE)
                .ok_or(ParallelError::InvalidArgument { field: "max_zones" })?,
        );
        let durable_off = align64(
            zone_seq_off
                .checked_add(max_zones * 8)
                .ok_or(ParallelError::InvalidArgument { field: "max_zones" })?,
        );
        let readers_off = align64(
            durable_off
                .checked_add(max_zones * 8)
                .ok_or(ParallelError::InvalidArgument { field: "max_zones" })?,
        );
        let len =
            readers_off
                .checked_add(slots * RS_SIZE)
                .ok_or(ParallelError::InvalidArgument {
                    field: "reader_slots",
                })?;
        let len = align64(len);
        Ok(Self {
            leases_off,
            zone_seq_off,
            durable_off,
            readers_off,
            len: u64::try_from(len).map_err(|_| ParallelError::InvalidArgument {
                field: "coord_size",
            })?,
        })
    }
}

fn align64(value: usize) -> usize {
    value.saturating_add(63) & !63
}

struct ReaderSlotView {
    pins: [(u32, u64); RS_PINS],
    epoch: u64,
}

fn is_busy(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == libc::EACCES || code == libc::EAGAIN
    )
}

/// `fcntl(F_SETLK/F_SETLKW)` c байтовым диапазоном.
fn set_lock(file: &File, cmd: i32, typ: i16, start: u64, len: u64) -> io::Result<()> {
    let mut lock = libc::flock {
        l_type: typ,
        l_whence: libc::SEEK_SET as i16,
        l_start: start as libc::off_t,
        l_len: len as libc::off_t,
        l_pid: 0,
    };
    loop {
        // SAFETY: `lock` — корректно инициализированный `struct flock`;
        // дескриптор валиден (принадлежит открытому `File`), `cmd` — константа
        // `F_SETLK*`. `fcntl` не сохраняет указатель.
        let rc = unsafe { libc::fcntl(file.as_raw_fd(), cmd, &mut lock) };
        if rc == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(error);
    }
}
