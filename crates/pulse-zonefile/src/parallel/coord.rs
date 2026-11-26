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
///
/// v2 добавила очередь свободных `zone_seq` (`free_seqs`), которой
/// пользуется каталог при повторном создании зон (ADR 0007 §7.1). v3 добавила
/// общую таблицу `page_no → generation` (`page_gen`), по которой
/// `PageCacheV2`/node-cache инвалидируют переиспользованную страницу (ADR 0007
/// §7.4). v4 добавила межпроцессную очередь group commit: слоты клиентов с
/// готовыми `RootEntry`, счётчики групп/`fsync` и lease координирующего
/// процесса. v5 добавила общий `freeze_epoch` с TTL/fencing, счётчики
/// онлайн-sweep утечек и `pending_floor` каждого писателя (нижняя граница
/// зарезервированных, но ещё не закоммиченных страниц). Это не формат данных:
/// sidecar пересоздаётся при старте, а live-процессы старой версии получают
/// `Busy`, а не читают чужую раскладку.
pub(crate) const COORD_VERSION: u16 = 5;
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
/// Очередь переиспользуемых `zone_seq` (каталог): голова/хвост/флаг.
const SC_OFF_FREE_ZONE_HEAD: usize = PAGE + 448;
const SC_OFF_FREE_ZONE_TAIL: usize = PAGE + 512;
const SC_OFF_FREE_ZONE_READY: usize = PAGE + 576;
/// Счётчик постановок в общую очередь group commit (futex-слово лидера).
const SC_OFF_PENDING_SEQ: usize = PAGE + 640;
/// Выполненные межпроцессные группы.
const SC_OFF_GROUPS: usize = PAGE + 704;
/// `fdatasync` межпроцессных групп.
const SC_OFF_FSYNCS: usize = PAGE + 768;
/// Зона-коммиты межпроцессных групп.
const SC_OFF_GROUP_MEMBERS: usize = PAGE + 832;
/// Максимальный размер межпроцессной группы.
const SC_OFF_GROUP_MAX: usize = PAGE + 896;
/// Fencing-терм/идентичность координирующего процесса.
const SC_OFF_LEADER_TERM: usize = PAGE + 960;
const SC_OFF_LEADER_PID: usize = PAGE + 1024;
const SC_OFF_LEADER_STARTTIME: usize = PAGE + 1088;
/// Сколько групп отработал текущий лидер (диагностика/тесты).
const SC_OFF_LEADER_GROUPS: usize = PAGE + 1152;
/// Общий retention-барьер `freeze_epoch` (v5): активность, эпоха, владелец,
/// TTL, fencing-поколение.
const SC_OFF_FREEZE_ACTIVE: usize = PAGE + 1216;
const SC_OFF_FREEZE_EPOCH: usize = PAGE + 1280;
const SC_OFF_FREEZE_OWNER: usize = PAGE + 1344;
const SC_OFF_FREEZE_EXPIRES: usize = PAGE + 1408;
const SC_OFF_FREEZE_TTL: usize = PAGE + 1472;
const SC_OFF_FREEZE_GENERATION: usize = PAGE + 1536;
/// Диагностика онлайн-sweep утечек (`v2`): прогоны/просканировано/возвращено.
const SC_OFF_SWEEP_RUNS: usize = PAGE + 1600;
const SC_OFF_SWEEP_PAGES: usize = PAGE + 1664;
const SC_OFF_SWEEP_RECLAIMED: usize = PAGE + 1728;
/// Писатели без слота очереди: их `pending_floor` не виден, aborted-sweep
/// консервативно запрещён.
const SC_OFF_UNREGISTERED: usize = PAGE + 1792;
const ARRAYS_OFF: usize = 2 * PAGE;

/// Состояние общего freeze.
const FREEZE_INACTIVE: u64 = 0;
const FREEZE_ACTIVE: u64 = 1;

/// Слотов клиентов общей очереди group commit.
pub(crate) const CLIENT_SLOTS: usize = 256;
/// Максимум зон в одном запросе клиента (локальная группа больше — чанками).
pub(crate) const CLIENT_MAX_MEMBERS: usize = 32;
/// Размер слота клиента: заголовок 64 Б + члены 32×96 Б + результаты 32×16 Б.
pub(crate) const CLIENT_SLOT_SIZE: usize = 64 + CLIENT_MAX_MEMBERS * 96 + CLIENT_MAX_MEMBERS * 16;

/// `state = (ticket << 8) | phase`; CAS перехода `READY → DONE` — точка
/// линейности ack (старый координатор не может «подтвердить» новый запрос).
const CLIENT_OFF_STATE: usize = 0;
const CLIENT_OFF_OWNER: usize = 8;
const CLIENT_OFF_PID: usize = 16;
const CLIENT_OFF_STARTTIME: usize = 24;
const CLIENT_OFF_TICKET: usize = 32;
const CLIENT_OFF_NMEMBERS: usize = 40;
const CLIENT_OFF_MODE: usize = 44;
const CLIENT_OFF_PAGE_LIMIT: usize = 48;

const MEMBER_OFF_ZONE: usize = 0;
/// Страница chain-вытеснения (`0` — нет).
const MEMBER_OFF_CHAIN_PAGE: usize = 4;
const MEMBER_OFF_VERSION: usize = 8;
const MEMBER_OFF_BASE_VERSION: usize = 16;
const MEMBER_OFF_FENCE: usize = 24;
const MEMBER_OFF_RECORD: usize = 32;
const MEMBER_SIZE: usize = 96;

const RESULT_OFF_CODE: usize = 0;
const RESULT_OFF_PREV: usize = 4;
const RESULT_OFF_EVICTED: usize = 8;
const RESULT_SIZE: usize = 16;

const CLIENT_PHASE_IDLE: u64 = 0;
const CLIENT_PHASE_READY: u64 = 1;
const CLIENT_PHASE_DONE: u64 = 2;
const CLIENT_TICKET_SHIFT: u32 = 8;

/// Размер элемента таблицы генераций страниц (u32).
const PAGE_GEN_SIZE: usize = 4;

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
const LOCK_OFF_SWEEP: u64 = 3;
const LOCK_OFF_FREEZE: u64 = 4;
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

/// Участник межпроцессной группы: готовый `RootEntry` и его координаты.
///
/// Данные/bucket/chain к моменту публикации уже записаны процессом-писателем;
/// координатору остаётся `ALLOC_RECORD` + копии корня + два `fdatasync`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SharedRequestMember {
    /// Зона (`0` — каталог).
    pub zone: u32,
    /// Итоговая версия (`RootEntry.version`).
    pub version: u64,
    /// Версия головы на момент плана (защита от устаревшего плана).
    pub base_version: u64,
    /// Поколение lease на момент плана (`0` — без проверки владельца).
    pub fence: u64,
    /// Страница chain-вытеснения (`0` — вытеснения нет).
    pub chain_page: u32,
    /// 64-байтовая запись корня (CRC уже посчитан).
    pub record: [u8; 64],
}

/// Код результата зоны в ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SharedAckCode {
    /// Публикация durable.
    Ok,
    /// Гонка с пином: план устарел (retryable).
    ReaderContended,
    /// План устарел/зона под чужим lease.
    ZoneBusy,
    /// Ошибка ввода-вывода: исход группы не определён.
    Io,
}

impl SharedAckCode {
    const fn to_disk(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::ReaderContended => 1,
            Self::ZoneBusy => 2,
            Self::Io => 3,
        }
    }

    const fn from_disk(value: u32) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::ReaderContended,
            2 => Self::ZoneBusy,
            _ => Self::Io,
        }
    }
}

/// Результат одной зоны из ack координатора.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SharedMemberResult {
    /// Код.
    pub code: SharedAckCode,
    /// `prev_record` опубликованной записи.
    pub prev_record: u32,
    /// Вытесненная в chain страница (0 — нет).
    pub evicted_page: u32,
}

/// Готовый к обработке запрос клиента (снимок для координатора).
#[derive(Debug, Clone)]
pub(crate) struct SharedReadyBatch {
    /// Слот клиента.
    pub slot: usize,
    /// Билет запроса (ack обязан вернуть его же).
    pub ticket: u64,
    /// Токен владельца слота (защита от переиспользования).
    pub owner: u64,
    /// Идентичность владельца.
    pub identity: ProcessIdentity,
    /// Режим durability запроса.
    pub mode: crate::parallel::layout::SyncModeV2,
    /// Члены запроса.
    pub members: Vec<SharedRequestMember>,
}

/// Снимок счётчиков межпроцессного group commit (из sidecar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SharedGroupStats {
    /// Выполненных групп.
    pub groups: u64,
    /// `fdatasync` групп.
    pub fsyncs: u64,
    /// Зона-коммитов в группах.
    pub members: u64,
    /// Максимальный размер группы.
    pub max_members: u64,
}

/// Снимок общего `freeze_epoch` (sidecar v5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SharedFreezeStatus {
    /// Барьер активен (и не истёк по TTL).
    pub active: bool,
    /// Барьер истёк по TTL (запись ещё лежит, но не действует).
    pub expired: bool,
    /// Зафиксированная версия (`0` — барьера нет).
    pub epoch: u64,
    /// Владелец (`pid`).
    pub owner_pid: u64,
    /// Владелец (`starttime`).
    pub owner_starttime: u64,
    /// Абсолютное время истечения (unix ns).
    pub expires_ns: u64,
    /// TTL, с которым барьер выставлен.
    pub ttl_ns: u64,
    /// Fencing-поколение барьера.
    pub generation: u64,
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
    /// Массив переиспользуемых `zone_seq` (`max_zones` × `u32`).
    free_seqs_off: usize,
    /// Таблица `(page_no − page_data_first) → generation` (`u32`).
    page_gen_off: usize,
    page_gen_count: usize,
    /// Слоты общей очереди group commit (`CLIENT_SLOTS × CLIENT_SLOT_SIZE`).
    clients_off: usize,
    /// `pending_floor` каждого слота клиента.
    pending_off: usize,
    /// Слот этого процесса в очереди (только writable-стор).
    client: Option<usize>,
    page_data_first: u32,
    page_count_max: u32,
    /// Держим `LOCK_SH` на `LOCK_OFF_ALIVE` всё время жизни.
    alive_lock: Option<RangeLock>,
    /// Процесс не получил слот очереди (его `pending_floor` не опубликован).
    unregistered: bool,
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
        writable: bool,
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
            free_seqs_off: layout.free_seqs_off,
            page_gen_off: layout.page_gen_off,
            page_gen_count: layout.page_gen_count,
            clients_off: layout.clients_off,
            pending_off: layout.pending_off,
            client: None,
            page_data_first: geometry.page_data_first(),
            page_count_max: geometry.page_count_max(),
            alive_lock: None,
            unregistered: false,
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
        if writable {
            coord.client = coord.client_register(self_identity());
            if coord.client.is_none() {
                coord.unregistered = true;
                coord.note_unregistered(1);
            }
        }
        Ok(Arc::new(coord))
    }

    /// Слот этого процесса в общей очереди group commit.
    #[must_use]
    pub(crate) const fn client_slot(&self) -> Option<usize> {
        self.client
    }

    /// Есть ли у процесса слот очереди (иначе — локальный путь коммита).
    #[must_use]
    pub(crate) const fn has_client(&self) -> bool {
        self.client.is_some()
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

    /// Подсказка «сколько процессов держат `LOCK_SH`» (диагностика).
    #[must_use]
    pub(crate) fn alive_hint(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_ALIVE_HINT)
    }

    /// Сколько открытых writable/read-only сторов держат sidecar.
    ///
    /// Используется как дешёвый гейт: при единственном процессе общая очередь
    /// не нужна, и коммит идёт прежним локальным путём.
    #[must_use]
    pub(crate) fn alive_count(&self) -> u64 {
        self.alive_hint().load(Ordering::Acquire)
    }

    // --- общий freeze (v5) ---

    /// Захватывает общий retention-барьер.
    ///
    /// `epoch` — версия, ниже которой рекламация разрешена. Барьер живёт до
    /// `freeze_release`/`unfreeze` или до истечения `ttl` (crash-safe: TTL
    /// переживает `kill -9`, но не блокирует рекламацию навсегда).
    ///
    /// # Errors
    ///
    /// `Busy` — барьер активен и принадлежит другому процессу/поколению;
    /// `Io` — ошибка `fcntl`.
    pub(crate) fn freeze_acquire(
        &self,
        identity: ProcessIdentity,
        epoch: u64,
        ttl: std::time::Duration,
    ) -> Result<u64, ParallelError> {
        if epoch == 0 {
            return Err(ParallelError::InvalidArgument {
                field: "freeze_epoch",
            });
        }
        let _lock = self.lock_range_blocking(LOCK_OFF_FREEZE)?;
        let now = unix_now_ns();
        let owner_token = Self::owner_token(identity);
        let active = self
            .atomic_u64(SC_OFF_FREEZE_ACTIVE)
            .load(Ordering::Acquire);
        if active == FREEZE_ACTIVE {
            let owner = self.atomic_u64(SC_OFF_FREEZE_OWNER).load(Ordering::Acquire);
            let expires = self
                .atomic_u64(SC_OFF_FREEZE_EXPIRES)
                .load(Ordering::Acquire);
            if owner != owner_token && now < expires {
                return Err(ParallelError::Busy);
            }
        }
        let ttl_ns = u64::try_from(ttl.as_nanos()).unwrap_or(u64::MAX);
        let expires = now.saturating_add(ttl_ns.max(1));
        let generation = self
            .atomic_u64(SC_OFF_FREEZE_GENERATION)
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        self.atomic_u64(SC_OFF_FREEZE_EPOCH)
            .store(epoch, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_OWNER)
            .store(owner_token, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_TTL)
            .store(ttl_ns, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_EXPIRES)
            .store(expires, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_ACTIVE)
            .store(FREEZE_ACTIVE, Ordering::Release);
        // Публикуем `epoch` до активации: читатель видит согласованную пару.
        fence(Ordering::SeqCst);
        Ok(generation)
    }

    /// Снимает барьер, если его держит `identity` и поколение совпало.
    pub(crate) fn freeze_release(&self, identity: ProcessIdentity, generation: u64) -> bool {
        let Ok(_lock) = self.lock_range_blocking(LOCK_OFF_FREEZE) else {
            return false;
        };
        let owner_token = Self::owner_token(identity);
        let owner = self.atomic_u64(SC_OFF_FREEZE_OWNER).load(Ordering::Acquire);
        let current = self
            .atomic_u64(SC_OFF_FREEZE_GENERATION)
            .load(Ordering::Acquire);
        if owner != owner_token || (generation != 0 && current != generation) {
            return false;
        }
        self.atomic_u64(SC_OFF_FREEZE_ACTIVE)
            .store(FREEZE_INACTIVE, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_EPOCH)
            .store(0, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_OWNER)
            .store(0, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_EXPIRES)
            .store(0, Ordering::Release);
        true
    }

    /// Снимает барьер независимо от владельца (`unfreeze()` из любого
    /// процесса — административная операция).
    pub(crate) fn freeze_force_release(&self) -> bool {
        let Ok(_lock) = self.lock_range_blocking(LOCK_OFF_FREEZE) else {
            return false;
        };
        let was = self
            .atomic_u64(SC_OFF_FREEZE_ACTIVE)
            .load(Ordering::Acquire)
            == FREEZE_ACTIVE;
        self.atomic_u64(SC_OFF_FREEZE_ACTIVE)
            .store(FREEZE_INACTIVE, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_EPOCH)
            .store(0, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_OWNER)
            .store(0, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_EXPIRES)
            .store(0, Ordering::Release);
        was
    }

    /// Продлевает TTL барьера (только владелец/поколение).
    pub(crate) fn freeze_renew(
        &self,
        identity: ProcessIdentity,
        generation: u64,
        ttl: std::time::Duration,
    ) -> bool {
        let Ok(_lock) = self.lock_range_blocking(LOCK_OFF_FREEZE) else {
            return false;
        };
        let owner_token = Self::owner_token(identity);
        if self.atomic_u64(SC_OFF_FREEZE_OWNER).load(Ordering::Acquire) != owner_token
            || self
                .atomic_u64(SC_OFF_FREEZE_GENERATION)
                .load(Ordering::Acquire)
                != generation
        {
            return false;
        }
        let ttl_ns = u64::try_from(ttl.as_nanos()).unwrap_or(u64::MAX).max(1);
        let expires = unix_now_ns().saturating_add(ttl_ns);
        self.atomic_u64(SC_OFF_FREEZE_TTL)
            .store(ttl_ns, Ordering::Release);
        self.atomic_u64(SC_OFF_FREEZE_EXPIRES)
            .store(expires, Ordering::Release);
        true
    }

    /// Снимок общего барьера. Истёкший по TTL барьер возвращается как
    /// неактивный (`expired = true`), но запись не стирается: это позволяет
    /// диагностике увидеть «зависший» freeze умершего процесса.
    #[must_use]
    pub(crate) fn freeze_status(&self) -> SharedFreezeStatus {
        let active = self
            .atomic_u64(SC_OFF_FREEZE_ACTIVE)
            .load(Ordering::Acquire)
            == FREEZE_ACTIVE;
        if !active {
            return SharedFreezeStatus::default();
        }
        let epoch = self.atomic_u64(SC_OFF_FREEZE_EPOCH).load(Ordering::Acquire);
        let expires_ns = self
            .atomic_u64(SC_OFF_FREEZE_EXPIRES)
            .load(Ordering::Acquire);
        let ttl_ns = self.atomic_u64(SC_OFF_FREEZE_TTL).load(Ordering::Acquire);
        let owner =
            Self::token_identity(self.atomic_u64(SC_OFF_FREEZE_OWNER).load(Ordering::Acquire));
        let expired = unix_now_ns() >= expires_ns;
        SharedFreezeStatus {
            active: !expired,
            expired,
            epoch: if expired { 0 } else { epoch },
            owner_pid: owner.pid,
            owner_starttime: owner.starttime,
            expires_ns,
            ttl_ns,
            generation: self
                .atomic_u64(SC_OFF_FREEZE_GENERATION)
                .load(Ordering::Acquire),
        }
    }

    /// Действующий общий барьер (`0` — нет/истёк).
    #[must_use]
    pub(crate) fn effective_freeze_epoch(&self) -> u64 {
        self.freeze_status().epoch
    }

    // --- pending floor писателей (v5) ---

    fn pending_slot(&self, slot: usize) -> Option<&AtomicU64> {
        if slot >= CLIENT_SLOTS {
            return None;
        }
        Some(self.atomic_u64(self.pending_off + slot * 8))
    }

    /// Публикует нижнюю границу зарезервированных, но не закоммиченных страниц
    /// этого процесса (`u64::MAX` — таких нет).
    pub(crate) fn set_pending_floor(&self, slot: usize, floor: u64) {
        if let Some(cell) = self.pending_slot(slot) {
            cell.store(floor, Ordering::Release);
        }
    }

    /// Минимум `pending_floor` по живым писателям.
    ///
    /// `u64::MAX` — зарезервированных страниц нет (aborted-sweep безопасен).
    #[must_use]
    pub(crate) fn pending_floor(&self) -> u64 {
        let mut floor = u64::MAX;
        for slot in 0..CLIENT_SLOTS {
            let owner = self
                .client_word(slot, CLIENT_OFF_OWNER)
                .load(Ordering::Acquire);
            if owner == 0 {
                continue;
            }
            let identity = Self::token_identity(owner);
            if !process_alive(
                identity.pid,
                self.client_word(slot, CLIENT_OFF_STARTTIME)
                    .load(Ordering::Acquire),
            ) {
                continue;
            }
            if let Some(cell) = self.pending_slot(slot) {
                floor = floor.min(cell.load(Ordering::Acquire));
            }
        }
        floor
    }

    /// Зарегистрирован ли writable-процесс без слота очереди (его
    /// `pending_floor` не виден → aborted-sweep запрещён).
    pub(crate) fn note_unregistered(&self, delta: i64) {
        let cell = self.atomic_u64(SC_OFF_UNREGISTERED);
        if delta >= 0 {
            cell.fetch_add(delta.unsigned_abs(), Ordering::AcqRel);
        } else {
            let _ = cell.try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_sub(delta.unsigned_abs()))
            });
        }
    }

    /// Есть ли писатели без видимого `pending_floor`.
    #[must_use]
    pub(crate) fn unregistered_writers(&self) -> u64 {
        self.atomic_u64(SC_OFF_UNREGISTERED).load(Ordering::Acquire)
    }

    // --- онлайн-sweep (v5) ---

    /// Блокирующий эксклюзивный sweep-lease (публикация под commit-lock).
    pub(crate) fn lock_sweep_exclusive(&self) -> Result<RangeLock, ParallelError> {
        set_lock(&self.file, FCNTL_SETLKW, LOCK_EX, LOCK_OFF_SWEEP, 1)
            .map_err(ParallelError::Io)?;
        let file = match self.file.try_clone() {
            Ok(file) => file,
            Err(error) => {
                let _ = set_lock(&self.file, FCNTL_SETLK, LOCK_UN, LOCK_OFF_SWEEP, 1);
                return Err(ParallelError::Io(error));
            }
        };
        Ok(RangeLock {
            file,
            start: LOCK_OFF_SWEEP,
            len: 1,
        })
    }

    /// Блокирующий разделяемый sweep-lease: `return_pages` не пересекается с
    /// публикацией sweep другого процесса.
    pub(crate) fn lock_sweep_shared(&self) -> Result<RangeLock, ParallelError> {
        set_lock(&self.file, FCNTL_SETLKW, LOCK_SH, LOCK_OFF_SWEEP, 1)
            .map_err(ParallelError::Io)?;
        let file = self.file.try_clone().map_err(ParallelError::Io)?;
        Ok(RangeLock {
            file,
            start: LOCK_OFF_SWEEP,
            len: 1,
        })
    }

    /// Учитывает результаты sweep в общих счётчиках.
    pub(crate) fn note_sweep(&self, scanned: u64, reclaimed: u64) {
        self.atomic_u64(SC_OFF_SWEEP_RUNS)
            .fetch_add(1, Ordering::Relaxed);
        self.atomic_u64(SC_OFF_SWEEP_PAGES)
            .fetch_add(scanned, Ordering::Relaxed);
        self.atomic_u64(SC_OFF_SWEEP_RECLAIMED)
            .fetch_add(reclaimed, Ordering::Relaxed);
    }

    /// Счётчики sweep: `(runs, scanned_pages, reclaimed_pages)`.
    #[must_use]
    pub(crate) fn sweep_stats(&self) -> (u64, u64, u64) {
        (
            self.atomic_u64(SC_OFF_SWEEP_RUNS).load(Ordering::Relaxed),
            self.atomic_u64(SC_OFF_SWEEP_PAGES).load(Ordering::Relaxed),
            self.atomic_u64(SC_OFF_SWEEP_RECLAIMED)
                .load(Ordering::Relaxed),
        )
    }

    fn lock_range_blocking(&self, start: u64) -> Result<RangeLock, ParallelError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if self.try_lock_exclusive(start) {
                let file = self.file.try_clone().map_err(ParallelError::Io)?;
                return Ok(RangeLock {
                    file,
                    start,
                    len: 1,
                });
            }
            if std::time::Instant::now() >= deadline {
                return Err(ParallelError::Busy);
            }
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
    }

    // --- очередь переиспользуемых zone_seq (каталог, ADR 0007 §7.1) ---

    fn free_zone_head(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_FREE_ZONE_HEAD)
    }

    fn free_zone_tail(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_FREE_ZONE_TAIL)
    }

    fn free_zone_ready_atomic(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_FREE_ZONE_READY)
    }

    fn free_zone_slot(&self, index: u64) -> &AtomicU32 {
        let modulus = u64::from(self.max_zones.max(1));
        let slot = index % modulus;
        self.atomic_u32(self.free_seqs_off + usize::try_from(slot).unwrap_or(0) * 4)
    }

    /// Очередь свободных слотов уже восстановлена из durable tombstone'ов.
    #[must_use]
    pub(crate) fn free_zone_ready(&self) -> bool {
        self.free_zone_ready_atomic().load(Ordering::Acquire) != 0
    }

    /// Помечает очередь свободных слотов восстановленной.
    pub(crate) fn mark_free_zone_ready(&self) {
        self.free_zone_ready_atomic().store(1, Ordering::Release);
    }

    /// Кладёт `zone_seq` в очередь переиспользования.
    ///
    /// Вызывается только держателем lease каталога. `false` — очередь полна.
    pub(crate) fn push_free_zone_seq(&self, zone: u32) -> bool {
        if zone == 0 || zone >= self.max_zones {
            return false;
        }
        let head = self.free_zone_head().load(Ordering::Acquire);
        let tail = self.free_zone_tail().load(Ordering::Acquire);
        if tail.saturating_sub(head) >= u64::from(self.max_zones) {
            return false;
        }
        self.free_zone_slot(tail).store(zone, Ordering::Release);
        self.free_zone_tail()
            .store(tail.saturating_add(1), Ordering::Release);
        true
    }

    /// Забирает `zone_seq` из очереди (держатель lease каталога).
    #[must_use]
    pub(crate) fn pop_free_zone_seq(&self) -> Option<u32> {
        let head = self.free_zone_head().load(Ordering::Acquire);
        let tail = self.free_zone_tail().load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let zone = self.free_zone_slot(head).load(Ordering::Acquire);
        self.free_zone_head()
            .store(head.saturating_add(1), Ordering::Release);
        (zone != 0).then_some(zone)
    }

    /// Сбрасывает очередь свободных слотов (только при отсутствии живых).
    fn reset_free_zone_queue(&self) {
        self.free_zone_head().store(0, Ordering::SeqCst);
        self.free_zone_tail().store(0, Ordering::SeqCst);
        self.free_zone_ready_atomic().store(0, Ordering::SeqCst);
        for index in 0..u64::from(self.max_zones) {
            self.free_zone_slot(index).store(0, Ordering::SeqCst);
        }
    }

    // --- генерации страниц (ADR 0007 §7.4) ---

    fn page_gen_slot(&self, page: u32) -> Option<&AtomicU32> {
        if page < self.page_data_first || page >= self.page_count_max {
            return None;
        }
        let index = usize::try_from(page - self.page_data_first).ok()?;
        if index >= self.page_gen_count {
            return None;
        }
        Some(
            self.atomic_u32(
                self.page_gen_off
                    .checked_add(index.checked_mul(PAGE_GEN_SIZE)?)?,
            ),
        )
    }

    /// Текущая генерация страницы (0 — страница ещё не выдавалась).
    ///
    /// Пара `(page_no, generation)` — ключ кеша: при переиспользовании номера
    /// генерация возрастает, старый образ становится недостижим.
    #[must_use]
    pub(crate) fn page_generation(&self, page: u32) -> u32 {
        self.page_gen_slot(page)
            .map_or(0, |slot| slot.load(Ordering::Acquire))
    }

    /// Инкрементирует генерацию страницы (выдача/освобождение/перезапись).
    ///
    /// Монотонна до `u32::MAX`; на переполнении переходит в 1, а не в 0:
    /// 0 зарезервирован за «страница ещё не выдавалась». Теоретическая
    /// коллизия требует 2³² повторных переиспользований одной страницы и
    /// поэтому не влияет на практическую корректность (документировано в
    /// ADR 0007 §7.4).
    pub(crate) fn bump_page_generation(&self, page: u32) -> u32 {
        let Some(slot) = self.page_gen_slot(page) else {
            return 0;
        };
        let mut current = slot.load(Ordering::Acquire);
        loop {
            let next = next_page_generation(current);
            match slot.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return next,
                Err(observed) => current = observed,
            }
        }
    }

    /// Инкрементирует генерации диапазона `[first, first + pages)`.
    pub(crate) fn bump_page_generations(&self, first: u32, pages: u32) {
        let last = first.saturating_add(pages);
        for page in first..last {
            self.bump_page_generation(page);
        }
    }

    /// Сколько байт sidecar занимает таблица генераций (memory budget).
    #[must_use]
    pub(crate) fn page_generation_bytes(&self) -> usize {
        self.page_gen_count.saturating_mul(PAGE_GEN_SIZE)
    }

    fn reset_page_generations(&self) {
        // SAFETY: `page_gen_off`/`page_gen_count` вычислены из геометрии и
        // лежат в границах отображения. Сброс выполняется только при
        // эксклюзивном `LOCK_OFF_ALIVE` (живых процессов нет), поэтому гонок
        // с читателями/писателями нет. Область не пересекается с заголовком
        // и другими массивами.
        unsafe {
            std::ptr::write_bytes(
                self.map.as_ptr().add(self.page_gen_off).cast_mut(),
                0,
                self.page_gen_count.saturating_mul(PAGE_GEN_SIZE),
            );
        }
    }

    // --- общая очередь group commit (v4) ---

    fn client_base(&self, slot: usize) -> usize {
        self.clients_off + slot * CLIENT_SLOT_SIZE
    }

    fn client_word(&self, slot: usize, offset: usize) -> &AtomicU64 {
        self.atomic_u64(self.client_base(slot) + offset)
    }

    fn client_u32(&self, slot: usize, offset: usize) -> &AtomicU32 {
        self.atomic_u32(self.client_base(slot) + offset)
    }

    fn member_off(&self, slot: usize, index: usize) -> usize {
        self.client_base(slot) + 64 + index * MEMBER_SIZE
    }

    fn result_off(&self, slot: usize, index: usize) -> usize {
        self.client_base(slot) + 64 + CLIENT_MAX_MEMBERS * MEMBER_SIZE + index * RESULT_SIZE
    }

    fn reset_client_slot(&self, slot: usize, identity: ProcessIdentity) {
        self.client_word(slot, CLIENT_OFF_STATE)
            .store(CLIENT_PHASE_IDLE, Ordering::SeqCst);
        self.client_word(slot, CLIENT_OFF_TICKET)
            .store(0, Ordering::SeqCst);
        self.client_u32(slot, CLIENT_OFF_NMEMBERS)
            .store(0, Ordering::SeqCst);
        self.client_u32(slot, CLIENT_OFF_MODE)
            .store(0, Ordering::SeqCst);
        self.client_word(slot, CLIENT_OFF_PAGE_LIMIT)
            .store(0, Ordering::SeqCst);
        self.client_word(slot, CLIENT_OFF_PID)
            .store(identity.pid, Ordering::SeqCst);
        self.client_word(slot, CLIENT_OFF_STARTTIME)
            .store(identity.starttime, Ordering::SeqCst);
        if let Some(cell) = self.pending_slot(slot) {
            cell.store(u64::MAX, Ordering::SeqCst);
        }
    }

    /// Регистрирует слот клиента очереди; `None` — таблица полна.
    fn client_register(&self, identity: ProcessIdentity) -> Option<usize> {
        let token = Self::owner_token(identity);
        for slot in 0..CLIENT_SLOTS {
            let owner = self.client_word(slot, CLIENT_OFF_OWNER);
            let current = owner.load(Ordering::Acquire);
            if current == token {
                return Some(slot);
            }
            let reclaimable = current == 0 || {
                let dead = Self::token_identity(current);
                !process_alive(
                    dead.pid,
                    self.client_word(slot, CLIENT_OFF_STARTTIME)
                        .load(Ordering::Acquire),
                )
            };
            if !reclaimable {
                continue;
            }
            if owner
                .compare_exchange(current, token, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                self.reset_client_slot(slot, identity);
                return Some(slot);
            }
        }
        None
    }

    /// Публикует готовый запрос в свой слот. `None` — слота нет/таблица сброшена.
    pub(crate) fn client_publish(
        &self,
        slot: usize,
        members: &[SharedRequestMember],
        mode: crate::parallel::layout::SyncModeV2,
    ) -> Option<u64> {
        if slot >= CLIENT_SLOTS || members.is_empty() || members.len() > CLIENT_MAX_MEMBERS {
            return None;
        }
        let owner = self
            .client_word(slot, CLIENT_OFF_OWNER)
            .load(Ordering::Acquire);
        let identity = Self::token_identity(owner);
        if owner == 0 || identity.pid != self_identity().pid {
            return None;
        }
        for (index, member) in members.iter().enumerate() {
            let base = self.member_off(slot, index);
            self.atomic_u32(base + MEMBER_OFF_ZONE)
                .store(member.zone, Ordering::Relaxed);
            self.atomic_u32(base + MEMBER_OFF_CHAIN_PAGE)
                .store(member.chain_page, Ordering::Relaxed);
            self.atomic_u64(base + MEMBER_OFF_VERSION)
                .store(member.version, Ordering::Relaxed);
            self.atomic_u64(base + MEMBER_OFF_BASE_VERSION)
                .store(member.base_version, Ordering::Relaxed);
            self.atomic_u64(base + MEMBER_OFF_FENCE)
                .store(member.fence, Ordering::Relaxed);
            for (chunk, bytes) in member.record.as_chunks::<8>().0.iter().enumerate() {
                self.atomic_u64(base + MEMBER_OFF_RECORD + chunk * 8)
                    .store(u64::from_le_bytes(*bytes), Ordering::Relaxed);
            }
            // Результат по умолчанию — «не обработан».
            let result = self.result_off(slot, index);
            self.atomic_u32(result + RESULT_OFF_CODE)
                .store(SharedAckCode::Io.to_disk(), Ordering::Relaxed);
            self.atomic_u32(result + RESULT_OFF_PREV)
                .store(0, Ordering::Relaxed);
            self.atomic_u32(result + RESULT_OFF_EVICTED)
                .store(0, Ordering::Relaxed);
        }
        self.client_u32(slot, CLIENT_OFF_NMEMBERS).store(
            u32::try_from(members.len()).unwrap_or(u32::MAX),
            Ordering::Relaxed,
        );
        self.client_u32(slot, CLIENT_OFF_MODE)
            .store(u32::from(mode.to_disk()), Ordering::Relaxed);
        self.client_word(slot, CLIENT_OFF_PAGE_LIMIT)
            .store(0, Ordering::Relaxed);
        let ticket = self
            .client_word(slot, CLIENT_OFF_TICKET)
            .load(Ordering::Relaxed)
            .saturating_add(1);
        self.client_word(slot, CLIENT_OFF_TICKET)
            .store(ticket, Ordering::Relaxed);
        // Публикация запроса: Release после записи payload.
        self.client_word(slot, CLIENT_OFF_STATE).store(
            (ticket << CLIENT_TICKET_SHIFT) | CLIENT_PHASE_READY,
            Ordering::Release,
        );
        self.pending_seq().fetch_add(1, Ordering::Release);
        futex_wake(self.pending_seq(), i32::MAX);
        Some(ticket)
    }

    /// Ждёт ack запроса `ticket`; `None` — таймаут.
    pub(crate) fn client_wait(&self, slot: usize, ticket: u64, timeout: std::time::Duration) {
        if slot >= CLIENT_SLOTS {
            return;
        }
        let state = self.client_word(slot, CLIENT_OFF_STATE);
        let current = state.load(Ordering::Acquire);
        if (current >> CLIENT_TICKET_SHIFT) != ticket {
            return;
        }
        // Ровно одно ожидание: по таймауту управление возвращается в
        // `wait_shared_ack`, и участник пробует сам стать лидером (иначе смерть
        // координатора оставила бы всех в вечном futex-ожидании).
        futex_wait_u64(state, current, timeout);
    }

    /// Результат запроса, если координатор уже подтвердил его.
    pub(crate) fn client_ack(
        &self,
        slot: usize,
        ticket: u64,
    ) -> Option<(u64, Vec<SharedMemberResult>)> {
        if slot >= CLIENT_SLOTS {
            return None;
        }
        let expected = (ticket << CLIENT_TICKET_SHIFT) | CLIENT_PHASE_DONE;
        if self
            .client_word(slot, CLIENT_OFF_STATE)
            .load(Ordering::Acquire)
            != expected
        {
            return None;
        }
        // Acquire уже выполнен загрузкой state; результаты записаны до CAS.
        let count = self
            .client_u32(slot, CLIENT_OFF_NMEMBERS)
            .load(Ordering::Acquire) as usize;
        let page_limit = self
            .client_word(slot, CLIENT_OFF_PAGE_LIMIT)
            .load(Ordering::Acquire);
        let mut results = Vec::with_capacity(count.min(CLIENT_MAX_MEMBERS));
        for index in 0..count.min(CLIENT_MAX_MEMBERS) {
            let base = self.result_off(slot, index);
            results.push(SharedMemberResult {
                code: SharedAckCode::from_disk(
                    self.atomic_u32(base + RESULT_OFF_CODE)
                        .load(Ordering::Acquire),
                ),
                prev_record: self
                    .atomic_u32(base + RESULT_OFF_PREV)
                    .load(Ordering::Acquire),
                evicted_page: self
                    .atomic_u32(base + RESULT_OFF_EVICTED)
                    .load(Ordering::Acquire),
            });
        }
        Some((page_limit, results))
    }

    /// Снимок готовых запросов (без `READY` — пусто).
    pub(crate) fn ready_batches(&self) -> Vec<SharedReadyBatch> {
        let mut batches = Vec::new();
        for slot in 0..CLIENT_SLOTS {
            let state = self
                .client_word(slot, CLIENT_OFF_STATE)
                .load(Ordering::Acquire);
            if state & 0xFF != CLIENT_PHASE_READY {
                continue;
            }
            let ticket = state >> CLIENT_TICKET_SHIFT;
            let owner = self
                .client_word(slot, CLIENT_OFF_OWNER)
                .load(Ordering::Acquire);
            if owner == 0 {
                continue;
            }
            // Полная идентичность: токен упаковывает лишь младшие 32 бита
            // `starttime`, а `process_alive` сравнивает полное значение.
            let identity = ProcessIdentity {
                pid: self
                    .client_word(slot, CLIENT_OFF_PID)
                    .load(Ordering::Acquire),
                starttime: self
                    .client_word(slot, CLIENT_OFF_STARTTIME)
                    .load(Ordering::Acquire),
            };
            let count = self
                .client_u32(slot, CLIENT_OFF_NMEMBERS)
                .load(Ordering::Acquire) as usize;
            let mode = crate::parallel::layout::SyncModeV2::from_disk(
                u8::try_from(
                    self.client_u32(slot, CLIENT_OFF_MODE)
                        .load(Ordering::Acquire),
                )
                .unwrap_or(0),
            )
            .unwrap_or(crate::parallel::layout::SyncModeV2::Sync);
            let mut members = Vec::with_capacity(count.min(CLIENT_MAX_MEMBERS));
            for index in 0..count.min(CLIENT_MAX_MEMBERS) {
                let base = self.member_off(slot, index);
                let mut record = [0_u8; 64];
                for (chunk, bytes) in record.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                    let word = self
                        .atomic_u64(base + MEMBER_OFF_RECORD + chunk * 8)
                        .load(Ordering::Acquire);
                    *bytes = word.to_le_bytes();
                }
                members.push(SharedRequestMember {
                    zone: self
                        .atomic_u32(base + MEMBER_OFF_ZONE)
                        .load(Ordering::Acquire),
                    version: self
                        .atomic_u64(base + MEMBER_OFF_VERSION)
                        .load(Ordering::Acquire),
                    base_version: self
                        .atomic_u64(base + MEMBER_OFF_BASE_VERSION)
                        .load(Ordering::Acquire),
                    fence: self
                        .atomic_u64(base + MEMBER_OFF_FENCE)
                        .load(Ordering::Acquire),
                    chain_page: self
                        .atomic_u32(base + MEMBER_OFF_CHAIN_PAGE)
                        .load(Ordering::Acquire),
                    record,
                });
            }
            batches.push(SharedReadyBatch {
                slot,
                ticket,
                owner,
                identity,
                mode,
                members,
            });
        }
        batches
    }

    /// Подтверждает запрос: пишет результаты и переводит `READY → DONE`.
    ///
    /// `false` — слот переиспользован/состояние изменилось (ack не доставлен;
    /// новый владелец обработает свой запрос сам).
    pub(crate) fn client_complete(
        &self,
        batch: &SharedReadyBatch,
        page_limit: u64,
        results: &[SharedMemberResult],
    ) -> bool {
        if batch.slot >= CLIENT_SLOTS {
            return false;
        }
        if self
            .client_word(batch.slot, CLIENT_OFF_OWNER)
            .load(Ordering::Acquire)
            != batch.owner
        {
            return false;
        }
        for (index, result) in results.iter().enumerate() {
            let base = self.result_off(batch.slot, index);
            self.atomic_u32(base + RESULT_OFF_PREV)
                .store(result.prev_record, Ordering::Relaxed);
            self.atomic_u32(base + RESULT_OFF_EVICTED)
                .store(result.evicted_page, Ordering::Relaxed);
            self.atomic_u32(base + RESULT_OFF_CODE)
                .store(result.code.to_disk(), Ordering::Relaxed);
        }
        self.client_word(batch.slot, CLIENT_OFF_PAGE_LIMIT)
            .store(page_limit, Ordering::Relaxed);
        let expected = (batch.ticket << CLIENT_TICKET_SHIFT) | CLIENT_PHASE_READY;
        let done = (batch.ticket << CLIENT_TICKET_SHIFT) | CLIENT_PHASE_DONE;
        let state = self.client_word(batch.slot, CLIENT_OFF_STATE);
        if state
            .compare_exchange(expected, done, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        futex_wake(state, i32::MAX);
        true
    }

    fn pending_seq(&self) -> &AtomicU64 {
        self.atomic_u64(SC_OFF_PENDING_SEQ)
    }

    /// Счётчик постановок в очередь (для settle-окна лидера).
    #[must_use]
    pub(crate) fn pending_sequence(&self) -> u64 {
        self.pending_seq().load(Ordering::Acquire)
    }

    /// Ждёт появления новых запросов до `timeout`.
    pub(crate) fn wait_pending(&self, expected: u64, timeout: std::time::Duration) {
        futex_wait_u64(self.pending_seq(), expected, timeout);
    }

    fn group_counter(&self, offset: usize) -> &AtomicU64 {
        self.atomic_u64(offset)
    }

    /// Учитывает выполненную группу.
    pub(crate) fn note_group(&self, members: u64, fsyncs: u64) {
        self.group_counter(SC_OFF_GROUPS)
            .fetch_add(1, Ordering::Relaxed);
        self.group_counter(SC_OFF_FSYNCS)
            .fetch_add(fsyncs, Ordering::Relaxed);
        self.group_counter(SC_OFF_GROUP_MEMBERS)
            .fetch_add(members, Ordering::Relaxed);
        self.group_counter(SC_OFF_GROUP_MAX)
            .fetch_max(members, Ordering::Relaxed);
    }

    /// Счётчики межпроцессного group commit.
    #[must_use]
    pub(crate) fn group_stats(&self) -> SharedGroupStats {
        SharedGroupStats {
            groups: self.group_counter(SC_OFF_GROUPS).load(Ordering::Acquire),
            fsyncs: self.group_counter(SC_OFF_FSYNCS).load(Ordering::Acquire),
            members: self
                .group_counter(SC_OFF_GROUP_MEMBERS)
                .load(Ordering::Acquire),
            max_members: self.group_counter(SC_OFF_GROUP_MAX).load(Ordering::Acquire),
        }
    }

    /// Отмечает начало группы под lease: терм + идентичность лидера.
    pub(crate) fn leader_begin(&self, identity: ProcessIdentity) -> u64 {
        let term = self
            .group_counter(SC_OFF_LEADER_TERM)
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        self.group_counter(SC_OFF_LEADER_PID)
            .store(identity.pid, Ordering::Release);
        self.group_counter(SC_OFF_LEADER_STARTTIME)
            .store(identity.starttime, Ordering::Release);
        self.group_counter(SC_OFF_LEADER_GROUPS)
            .fetch_add(1, Ordering::Relaxed);
        term
    }

    /// Текущий лидер (для диагностики/тестов).
    #[must_use]
    pub(crate) fn leader(&self) -> (u64, ProcessIdentity) {
        (
            self.group_counter(SC_OFF_LEADER_TERM)
                .load(Ordering::Acquire),
            ProcessIdentity {
                pid: self
                    .group_counter(SC_OFF_LEADER_PID)
                    .load(Ordering::Acquire),
                starttime: self
                    .group_counter(SC_OFF_LEADER_STARTTIME)
                    .load(Ordering::Acquire),
            },
        )
    }

    /// Пробует стать координатором группы (non-blocking lease).
    ///
    /// # Errors
    ///
    /// `Io` — ошибка `fcntl` (не `EAGAIN`).
    pub(crate) fn try_lock_commit(&self) -> Result<Option<RangeLock>, ParallelError> {
        match set_lock(&self.file, FCNTL_SETLK, LOCK_EX, LOCK_OFF_COMMIT, 1) {
            Ok(()) => {}
            Err(error) if is_busy(&error) => return Ok(None),
            Err(error) => return Err(ParallelError::Io(error)),
        }
        let file = match self.file.try_clone() {
            Ok(file) => file,
            Err(error) => {
                let _ = set_lock(&self.file, FCNTL_SETLK, LOCK_UN, LOCK_OFF_COMMIT, 1);
                return Err(ParallelError::Io(error));
            }
        };
        Ok(Some(RangeLock {
            file,
            start: LOCK_OFF_COMMIT,
            len: 1,
        }))
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
        self.reset_free_zone_queue();
        self.reset_page_generations();
        for offset in [
            SC_OFF_PENDING_SEQ,
            SC_OFF_GROUPS,
            SC_OFF_FSYNCS,
            SC_OFF_GROUP_MEMBERS,
            SC_OFF_GROUP_MAX,
            SC_OFF_LEADER_TERM,
            SC_OFF_LEADER_PID,
            SC_OFF_LEADER_STARTTIME,
            SC_OFF_LEADER_GROUPS,
            SC_OFF_FREEZE_ACTIVE,
            SC_OFF_FREEZE_EPOCH,
            SC_OFF_FREEZE_OWNER,
            SC_OFF_FREEZE_EXPIRES,
            SC_OFF_FREEZE_TTL,
            SC_OFF_FREEZE_GENERATION,
            SC_OFF_SWEEP_RUNS,
            SC_OFF_SWEEP_PAGES,
            SC_OFF_SWEEP_RECLAIMED,
            SC_OFF_UNREGISTERED,
        ] {
            self.atomic_u64(offset).store(0, Ordering::SeqCst);
        }
        for slot in 0..CLIENT_SLOTS {
            if let Some(cell) = self.pending_slot(slot) {
                cell.store(u64::MAX, Ordering::SeqCst);
            }
        }
        for slot in 0..CLIENT_SLOTS {
            self.client_word(slot, CLIENT_OFF_STATE)
                .store(0, Ordering::SeqCst);
            self.client_word(slot, CLIENT_OFF_OWNER)
                .store(0, Ordering::SeqCst);
            self.client_word(slot, CLIENT_OFF_TICKET)
                .store(0, Ordering::SeqCst);
            self.client_u32(slot, CLIENT_OFF_NMEMBERS)
                .store(0, Ordering::SeqCst);
            self.client_u32(slot, CLIENT_OFF_MODE)
                .store(0, Ordering::SeqCst);
            self.client_word(slot, CLIENT_OFF_PAGE_LIMIT)
                .store(0, Ordering::SeqCst);
            self.client_word(slot, CLIENT_OFF_PID)
                .store(0, Ordering::SeqCst);
            self.client_word(slot, CLIENT_OFF_STARTTIME)
                .store(0, Ordering::SeqCst);
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
        if self.unregistered {
            self.note_unregistered(-1);
        }
        if let Some(slot) = self.client {
            let token = Self::owner_token(self_identity());
            let owner = self.client_word(slot, CLIENT_OFF_OWNER);
            if owner.load(Ordering::Acquire) == token {
                self.client_word(slot, CLIENT_OFF_STATE)
                    .store(0, Ordering::SeqCst);
                let _ = owner.compare_exchange(token, 0, Ordering::AcqRel, Ordering::Acquire);
            }
        }
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
    free_seqs_off: usize,
    page_gen_off: usize,
    page_gen_count: usize,
    clients_off: usize,
    /// `pending_floor` каждого слота клиента (`CLIENT_SLOTS × u64`).
    pending_off: usize,
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
        let free_seqs_off = align64(readers_off.checked_add(slots * RS_SIZE).ok_or(
            ParallelError::InvalidArgument {
                field: "reader_slots",
            },
        )?);
        let page_gen_off = align64(
            free_seqs_off
                .checked_add(max_zones * 4)
                .ok_or(ParallelError::InvalidArgument { field: "max_zones" })?,
        );
        let data_first = usize::try_from(geometry.page_data_first()).map_err(|_| {
            ParallelError::InvalidArgument {
                field: "page_data_first",
            }
        })?;
        let page_count = usize::try_from(geometry.page_count_max()).map_err(|_| {
            ParallelError::InvalidArgument {
                field: "page_count_max",
            }
        })?;
        let page_gen_count = page_count.saturating_sub(data_first);
        let page_gen_bytes =
            page_gen_count
                .checked_mul(PAGE_GEN_SIZE)
                .ok_or(ParallelError::InvalidArgument {
                    field: "page_count_max",
                })?;
        let clients_off = align64(page_gen_off.checked_add(page_gen_bytes).ok_or(
            ParallelError::InvalidArgument {
                field: "page_count_max",
            },
        )?);
        let len = clients_off
            .checked_add(CLIENT_SLOTS * CLIENT_SLOT_SIZE)
            .ok_or(ParallelError::InvalidArgument {
                field: "coord_size",
            })?;
        let pending_off = align64(len);
        let len =
            pending_off
                .checked_add(CLIENT_SLOTS * 8)
                .ok_or(ParallelError::InvalidArgument {
                    field: "coord_size",
                })?;
        let len = align64(len);
        Ok(Self {
            leases_off,
            zone_seq_off,
            durable_off,
            readers_off,
            free_seqs_off,
            page_gen_off,
            page_gen_count,
            clients_off,
            pending_off,
            len: u64::try_from(len).map_err(|_| ParallelError::InvalidArgument {
                field: "coord_size",
            })?,
        })
    }
}

fn align64(value: usize) -> usize {
    value.saturating_add(63) & !63
}

fn unix_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// Следующая генерация страницы: 0 и `u32::MAX` переходят в 1.
///
/// 0 означает «страница ещё не выдавалась», поэтому переполнение не должно
/// возвращать 0 (иначе свежая страница совпала бы с legacy-ключом).
pub(crate) const fn next_page_generation(current: u32) -> u32 {
    let next = current.wrapping_add(1);
    if next == 0 { 1 } else { next }
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

/// `FUTEX_WAIT` по младшему 32-битному слову `AtomicU64` (межпроцессный).
///
/// Ожидание ограничено `timeout`: участник периодически пробует сам стать
/// лидером (если координатор умер, его `fcntl`-lease уже снят ядром).
fn futex_wait_u64(word: &AtomicU64, expected: u64, timeout: std::time::Duration) {
    let nanos = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
    let timespec = libc::timespec {
        tv_sec: libc::time_t::try_from(nanos / 1_000_000_000).unwrap_or(libc::time_t::MAX),
        tv_nsec: libc::c_long::try_from(nanos % 1_000_000_000).unwrap_or(999_999_999),
    };
    // SAFETY: `word` — выровненный `AtomicU64` в `MAP_SHARED`; futex читает
    // только младшее 32-битное слово по валидному адресу, `timespec` живёт на
    // стеке до возврата syscall. Указатели на uaddr2/mask нулевые — как
    // требует `FUTEX_WAIT`.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word.as_ptr().cast::<u32>(),
            libc::FUTEX_WAIT,
            u32::try_from(expected & 0xFFFF_FFFF).unwrap_or(u32::MAX),
            &timespec,
            std::ptr::null::<u32>(),
            0,
        );
    }
}

/// `FUTEX_WAKE` по младшему 32-битному слову `AtomicU64`.
fn futex_wake(word: &AtomicU64, count: i32) {
    // SAFETY: тот же выровненный адрес; `FUTEX_WAKE` не разыменовывает
    // остальные аргументы (нулевые).
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            word.as_ptr().cast::<u32>(),
            libc::FUTEX_WAKE,
            count,
            std::ptr::null::<u32>(),
            std::ptr::null::<u32>(),
            0,
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parallel::geometry::Geometry;

    #[test]
    fn generation_wraps_to_one_not_zero() {
        assert_eq!(next_page_generation(0), 1);
        assert_eq!(next_page_generation(1), 2);
        assert_eq!(next_page_generation(u32::MAX - 1), u32::MAX);
        // Переполнение не возвращает 0: 0 — «страница ещё не выдавалась».
        assert_eq!(next_page_generation(u32::MAX), 1);
    }

    fn test_geometry() -> Geometry {
        Geometry::new(8, 1 << 12, 64, 8).expect("geometry")
    }

    fn init_for(geometry: Geometry) -> CoordInit {
        CoordInit {
            durable_pages: u64::from(geometry.page_data_first()),
            durable_txn: 1,
            next_txn: 2,
            published: 0,
            durable_versions: Vec::new(),
        }
    }

    #[test]
    fn sidecar_v3_has_page_generation_table_and_migrates_v2() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("coord.v2");
        let geometry = test_geometry();
        let init = init_for(geometry);
        let coord = SharedCoord::open(&path, geometry, [7; 16], &init, true).expect("open");
        let coord_path = coord.path().to_path_buf();
        let page = geometry.page_data_first();
        assert!(coord.page_generation_bytes() > 0);
        assert_eq!(coord.page_generation(page), 0);
        assert_eq!(coord.bump_page_generation(page), 1);
        assert_eq!(coord.page_generation(page), 1);
        drop(coord);

        // Эмулируем sidecar предыдущей версии: при отсутствии живых процессов
        // координатор обязан пересоздать раскладку, а не читать чужую.
        {
            use std::os::unix::fs::FileExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&coord_path)
                .expect("open sidecar");
            file.write_at(&2_u16.to_le_bytes(), HDR_OFF_VERSION as u64)
                .expect("downgrade version");
        }
        let coord = SharedCoord::open(&path, geometry, [7; 16], &init, true).expect("reopen");
        assert_eq!(coord.page_generation(page), 0, "таблица не сброшена");
        assert_eq!(coord.bump_page_generation(page), 1);
        drop(coord);
    }
}
