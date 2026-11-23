//! Создание, монтирование и открытие файла (спецификация §3, §4, §13.1).

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{Mode, OFlags, Stat, fdatasync, fstat, fsync, ftruncate, open as fs_open};
use rustix::io::Errno;

use crate::consts::{
    DEFAULT_MAP_SIZE, META_OFF_TXNID, PAGE_META_A, PAGE_META_B, PAGE_READER_TABLE,
    PAGE_SIZE_ALLOWED, PAGE_SUPERBLOCK_A, PAGE_SUPERBLOCK_B, PAGE_TYPE_READER_TABLE,
    RTP_OFF_CRC32C, RTP_OFF_PAGE_FLAGS, RTP_OFF_PAGE_NO, RTP_OFF_PAGE_TYPE, RTP_OFF_SLOTS_USED,
    RTP_OFF_VERSION, SUPERBLOCK_RECORD_SIZE,
};
use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::lock::WriterLock;
use crate::map::{FileMap, ReaderRegion};
use crate::meta::Meta;
use crate::readers::{self, ProcProcessProbe, ReaderTable};
use crate::recovery;
use crate::superblock::{self, CreateConfig, Superblock};
use crate::wire;

/// Открытая, но ещё не обёрнутая в `ZoneFile` конфигурация файла.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct OpenedFile {
    pub(crate) file: Arc<File>,
    pub(crate) map: FileMap,
    pub(crate) superblock: Superblock,
    pub(crate) meta: Meta,
    pub(crate) readers: ReaderTable,
    pub(crate) recovered_unsynced: bool,
    pub(crate) torn_meta: bool,
    pub(crate) write_locked: bool,
    pub(crate) memory_tail_discarded: bool,
    pub(crate) durable_watermark: u64,
}

/// Режим блокировки при открытии (спецификация §6.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LockMode {
    /// Читатель: `flock` не берётся.
    #[default]
    Reader,
    /// Writer: `<zonefile>.lock` с `LOCK_EX | LOCK_NB`.
    Writer,
}

/// Конфигурация открытия файла.
///
/// Несколько независимых логических флагов соответствуют контракту §20.3.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenConfig {
    /// Режим «только чтение»: запрещает writer-блокировку.
    ///
    /// Регион reader table всё равно отображается writable (этого требует §6.1),
    /// поэтому `read_only` не запрещает `reader()`. Файл открывается `O_RDWR`
    /// в соответствии с §13.1/§21.4.
    pub read_only: bool,
    /// Зарезервировано: размер карты задаётся при создании файла.
    pub map_size: u64,
    /// Режим блокировки.
    pub lock_mode: LockMode,
    /// Строгие проверки прав владельца и режима файла.
    ///
    /// `false` учитывается только в тестовых сборках (`cfg(test)`); production
    /// всегда работает со strict=true. Поле сохранено для совместимости API.
    pub strict: bool,
    /// Разрешить старт после отката к initial meta (§13.7, шаг 10).
    pub allow_rollback_to_initial: bool,
    /// Разрешить старт, если в режиме `Memory` (`NoSync`) выбрана meta новее
    /// `durable_txn` (meta могла пережить данные).
    pub allow_unsynced_memory_recovery: bool,
}

impl Default for OpenConfig {
    fn default() -> Self {
        Self {
            read_only: false,
            map_size: DEFAULT_MAP_SIZE,
            lock_mode: LockMode::Reader,
            strict: true,
            allow_rollback_to_initial: false,
            allow_unsynced_memory_recovery: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Identity {
    dev: u64,
    ino: u64,
    size: u64,
}

/// Точки отказа, используемые только тестами очистки (§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum CreateFailPoint {
    AfterSuperblocks,
    AfterMeta,
    AfterReaderPages,
    BeforeSync,
}

struct CreateCleanup {
    data: Option<PathBuf>,
    lock: Option<WriterLock>,
    lock_path: PathBuf,
    armed: bool,
}

impl Drop for CreateCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(data) = self.data.as_ref() {
            let _ = std::fs::remove_file(data);
        }
        // Сначала отпускаем flock, только потом удаляем lock-файл: иначе между
        // `unlink` и `flock(UN)` другой writer мог бы создать новый lock-файл.
        drop(self.lock.take());
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

/// Создаёт новый файл зон строго по последовательности §4.
///
/// # Errors
///
/// `AlreadyExists` — файл уже существует; `Busy` — lock занят другим writer'ом;
/// `MapAllocFailed` — `ftruncate`/`mmap` не удались; `Io` — ошибка записи.
pub(crate) fn create(
    path: &Path,
    cfg: CreateConfig,
) -> Result<(OpenedFile, WriterLock), ZoneFileError> {
    create_impl(path, cfg, None)
}

#[cfg(test)]
fn create_failing(
    path: &Path,
    cfg: CreateConfig,
    fail: CreateFailPoint,
) -> Result<(OpenedFile, WriterLock), ZoneFileError> {
    create_impl(path, cfg, Some(fail))
}

#[allow(clippy::too_many_lines)]
fn create_impl(
    path: &Path,
    cfg: CreateConfig,
    fail: Option<CreateFailPoint>,
) -> Result<(OpenedFile, WriterLock), ZoneFileError> {
    let created_unix_ns = recovery::now_unix_ns();
    let instance_uuid = superblock::new_instance_uuid();
    let superblock = Superblock::for_new(cfg, instance_uuid, created_unix_ns)?;
    let geometry = superblock.reader_geometry().ok_or_else(|| {
        ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::BadReaderRegion)
    })?;

    match std::fs::symlink_metadata(path) {
        Ok(_) => return Err(ZoneFileError::AlreadyExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(ZoneFileError::Io(error)),
    }

    let lock = WriterLock::acquire(path)?.ok_or(ZoneFileError::Busy)?;
    let mut cleanup = CreateCleanup {
        data: None,
        lock: Some(lock),
        lock_path: PathBuf::from(WriterLock::path_for(path)),
        armed: true,
    };

    let fd = match fs_open(
        path,
        OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR,
    ) {
        Ok(fd) => fd,
        Err(Errno::EXIST) => return Err(ZoneFileError::AlreadyExists),
        Err(error) => return Err(ZoneFileError::Io(io::Error::from(error))),
    };
    let file = File::from(fd);
    cleanup.data = Some(path.to_path_buf());

    rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(io::Error::from)?;
    ftruncate(&file, superblock.map_size()).map_err(|error| ZoneFileError::MapAllocFailed {
        size: superblock.map_size(),
        errno: error.raw_os_error(),
        hint: "ftruncate failed; the filesystem may not support sparse files or a quota is exhausted",
    })?;

    let identity = identity_of(&file)?;
    verify_identity(&file, &identity, superblock.map_size())?;
    let map = FileMap::map_read(&file, superblock.map_size())?;

    let superblock_a = superblock.encode();
    let superblock_b = superblock.as_copy_b().encode();
    let meta = Meta::initial(
        PAGE_META_A,
        superblock.page_size,
        superblock.page_data_first,
        u32::try_from(superblock.reader_region_off).map_err(|_| {
            ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::BadReaderRegion)
        })?,
        u32::try_from(superblock.reader_region_len).map_err(|_| {
            ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::BadReaderRegion)
        })?,
        created_unix_ns,
    );
    let meta_page = meta.encode();

    write_runs(
        &file,
        &[
            (
                u64::from(PAGE_SUPERBLOCK_A) * u64::from(superblock.page_size),
                superblock_a.as_slice(),
            ),
            (
                u64::from(PAGE_SUPERBLOCK_B) * u64::from(superblock.page_size),
                superblock_b.as_slice(),
            ),
            (
                u64::from(PAGE_META_A) * u64::from(superblock.page_size),
                meta_page.as_slice(),
            ),
        ],
    )?;
    fail_if(fail, CreateFailPoint::AfterSuperblocks)?;
    fail_if(fail, CreateFailPoint::AfterMeta)?;

    let reader_pages = encode_reader_pages(geometry.pages, superblock.page_size);
    let reader_parts: Vec<&[u8]> = reader_pages.iter().map(Vec::as_slice).collect();
    // Батч `pwritev` по до 64 подряд идущих страниц reader table.
    write_pages(&file, superblock.reader_region_off, &reader_parts)?;
    fail_if(fail, CreateFailPoint::AfterReaderPages)?;
    fail_if(fail, CreateFailPoint::BeforeSync)?;

    sync_data(&file)?;
    fsync_directory(path)?;

    verify_identity(&file, &identity, superblock.map_size())?;
    let region = ReaderRegion::map(
        &file,
        superblock.reader_region_off,
        superblock.reader_region_len,
        superblock.page_size,
        geometry.pages,
        geometry.slots_per_page,
    )?;
    readers::validate_pages(&region, geometry.pages, geometry.slots_per_page)?;
    let readers = ReaderTable::new(region)?;

    cleanup.armed = false;
    let lock = cleanup.lock.take().ok_or_else(|| {
        ZoneFileError::Io(io::Error::from_raw_os_error(Errno::INVAL.raw_os_error()))
    })?;
    Ok((
        OpenedFile {
            file: Arc::new(file),
            map,
            superblock,
            meta,
            readers,
            recovered_unsynced: false,
            torn_meta: false,
            write_locked: false,
            memory_tail_discarded: false,
            durable_watermark: meta.durable_txn,
        },
        lock,
    ))
}

/// Открывает существующий файл и выбирает активную meta.
///
/// # Errors
///
/// `TruncatedFile` — файл короче `page_count_max * page_size`;
/// `CorruptNoValidMeta` — обе meta невалидны; `Busy` — writer-блокировка занята;
/// `RolledBackToInitial` — откат к initial meta без подтверждения;
/// `UnsupportedVersion`/`Corrupt` — несовместимый или повреждённый файл.
pub(crate) fn open(
    path: &Path,
    cfg: OpenConfig,
) -> Result<(OpenedFile, Option<WriterLock>), ZoneFileError> {
    if cfg.read_only && cfg.lock_mode == LockMode::Writer {
        return Err(ZoneFileError::ReadOnly);
    }
    let fd = match fs_open(
        path,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        // `O_NOFOLLOW` на symlink даёт ELOOP, `O_RDWR` на каталоге — EISDIR.
        Err(error) if error == Errno::LOOP || error == Errno::ISDIR => {
            return Err(ZoneFileError::NotRegularFile);
        }
        Err(error) => return Err(ZoneFileError::Io(io::Error::from(error))),
    };
    let file = File::from(fd);
    let stat = fstat(&file).map_err(io::Error::from)?;
    // В production strict всегда включён; ослабление допускается только тестами.
    validate_file_identity(&stat, !cfg!(test) || cfg.strict)?;
    let identity = identity_from_stat(&stat)?;
    let file_size = identity.size;

    let superblock = read_superblocks(&file, file_size)?;
    let geometry = superblock.validate_layout(file_size)?;

    let lock = if cfg.lock_mode == LockMode::Writer {
        Some(WriterLock::acquire(path)?.ok_or(ZoneFileError::Busy)?)
    } else {
        None
    };

    verify_identity(&file, &identity, file_size)?;
    let map = FileMap::map_read(&file, file_size)?;

    verify_identity(&file, &identity, file_size)?;
    let region = ReaderRegion::map(
        &file,
        superblock.reader_region_off,
        superblock.reader_region_len,
        superblock.page_size,
        geometry.pages,
        geometry.slots_per_page,
    )?;
    verify_identity(&file, &identity, file_size)?;
    readers::validate_pages(&region, geometry.pages, geometry.slots_per_page)?;

    let page_a = read_meta(&file, PAGE_META_A, &superblock)?;
    let page_b = read_meta(&file, PAGE_META_B, &superblock)?;
    let empty_slot = matches!(page_a, MetaPage::Empty) || matches!(page_b, MetaPage::Empty);
    let slot_a = prepare_candidate(page_a, &superblock)?;
    let slot_b = prepare_candidate(page_b, &superblock)?;
    // Пустой слот — норма только для initial-файла (active.txnid = 1);
    // решение принимает `select` по выбранной meta (§13.7 шаг 5).
    let recovered = recovery::select(
        slot_a,
        slot_b,
        empty_slot,
        superblock.sync_mode,
        cfg.allow_unsynced_memory_recovery,
    )?;
    let mut meta = validate_meta_against_superblock(recovered.meta, &superblock)?;
    check_high_water(&meta, &superblock)?;
    meta = recovery::apply_rollback_policy(
        meta,
        superblock.instance_uuid,
        superblock.created_unix_ns,
        recovery::now_unix_ns(),
        cfg.allow_rollback_to_initial,
    )?;
    let readers = ReaderTable::new(region)?;
    if readers.sanitize(meta.txnid, &ProcProcessProbe)? {
        meta.set_needs_fsck();
    }
    // `reclaim_txn` из файла — advisory (§5): пересчитываем от единого
    // durable-watermark по актуальному reader table, не повышая `durable_txn`
    // и не записывая meta.
    let oldest_reader_txn = readers.oldest_reader_txn(meta.txnid);
    meta.refresh_reclaim_txn(recovered.durable_watermark, oldest_reader_txn);

    Ok((
        OpenedFile {
            file: Arc::new(file),
            map,
            superblock,
            meta,
            readers,
            recovered_unsynced: recovered.unsynced,
            torn_meta: recovered.torn_meta,
            write_locked: recovered.write_locked,
            memory_tail_discarded: recovered.memory_tail_discarded,
            durable_watermark: recovered.durable_watermark,
        },
        lock,
    ))
}

#[allow(clippy::verbose_bit_mask)]
fn validate_file_identity(stat: &Stat, strict: bool) -> Result<(), ZoneFileError> {
    let mode = rustix::fs::FileType::from_raw_mode(stat.st_mode);
    if !mode.is_file() {
        return Err(ZoneFileError::NotRegularFile);
    }
    if strict {
        let owner_ok = stat.st_uid == rustix::process::geteuid().as_raw();
        let mode_ok = stat.st_mode & 0o077 == 0;
        if !owner_ok || !mode_ok {
            return Err(ZoneFileError::Io(io::Error::from_raw_os_error(
                Errno::ACCESS.raw_os_error(),
            )));
        }
    }
    Ok(())
}

fn identity_of(file: &File) -> Result<Identity, ZoneFileError> {
    let stat = fstat(file).map_err(io::Error::from)?;
    identity_from_stat(&stat)
}

fn identity_from_stat(stat: &Stat) -> Result<Identity, ZoneFileError> {
    let size = u64::try_from(stat.st_size).map_err(|_| ZoneFileError::TruncatedFile)?;
    Ok(Identity {
        dev: stat.st_dev,
        ino: stat.st_ino,
        size,
    })
}

fn verify_identity(
    file: &File,
    identity: &Identity,
    expected_size: u64,
) -> Result<(), ZoneFileError> {
    let stat = fstat(file).map_err(io::Error::from)?;
    let current = identity_from_stat(&stat)?;
    if current.dev != identity.dev || current.ino != identity.ino {
        return Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            None,
            CorruptDetail::OffsetOutOfRange,
        ));
    }
    if current.size < expected_size {
        return Err(ZoneFileError::TruncatedFile);
    }
    if current.size > expected_size {
        return Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            None,
            CorruptDetail::OffsetOutOfRange,
        ));
    }
    Ok(())
}

fn read_exact_at(file: &File, offset: u64, len: usize) -> Result<Vec<u8>, ZoneFileError> {
    let mut buffer = vec![0_u8; len];
    file.read_exact_at(&mut buffer, offset).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            ZoneFileError::TruncatedFile
        } else {
            ZoneFileError::Io(error)
        }
    })?;
    Ok(buffer)
}

fn is_unsupported(error: &ZoneFileError) -> bool {
    matches!(error, ZoneFileError::UnsupportedVersion { .. })
}

/// Повреждение, при котором копию можно считать отсутствующей/нечитаемой.
fn is_absent_copy_error(error: &ZoneFileError) -> bool {
    matches!(
        error,
        ZoneFileError::Corrupt {
            detail: CorruptDetail::Checksum | CorruptDetail::BadMagic | CorruptDetail::Truncated,
            ..
        }
    )
}

#[cfg(test)]
fn decode_copy(
    record: &[u8],
    expected_copy: u8,
    page_no: u32,
) -> Result<Superblock, ZoneFileError> {
    let candidate = Superblock::decode(record)?;
    if candidate.superblock_copy != expected_copy {
        return Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(page_no),
            CorruptDetail::OffsetOutOfRange,
        ));
    }
    Ok(candidate)
}

fn same_superblock_config(a: &Superblock, b: &Superblock) -> bool {
    a.version_major == b.version_major
        && a.version_minor == b.version_minor
        && a.page_size == b.page_size
        && a.page_count_max == b.page_count_max
        && a.feature_flags_required == b.feature_flags_required
        && a.feature_flags_optional == b.feature_flags_optional
        && a.instance_uuid == b.instance_uuid
        && a.created_unix_ns == b.created_unix_ns
        && a.reader_region_off == b.reader_region_off
        && a.reader_region_len == b.reader_region_len
        && a.reader_region_align == b.reader_region_align
        && a.page_meta_a == b.page_meta_a
        && a.page_meta_b == b.page_meta_b
        && a.page_data_first == b.page_data_first
        && a.page_reader_table == b.page_reader_table
        && a.page_reader_table_count == b.page_reader_table_count
        && a.section_count == b.section_count
        && a.sections == b.sections
        && a.sync_mode == b.sync_mode
        && a.sync_mode_version == b.sync_mode_version
}

fn read_superblocks(file: &File, file_size: u64) -> Result<Superblock, ZoneFileError> {
    const RECORD: u64 = SUPERBLOCK_RECORD_SIZE as u64;
    if file_size < RECORD {
        return Err(ZoneFileError::TruncatedFile);
    }
    let first = read_exact_at(file, 0, SUPERBLOCK_RECORD_SIZE as usize)?;
    let mut a_error = None;
    let decoded_a = match Superblock::decode(&first) {
        Ok(superblock) if superblock.superblock_copy == 0 => Some(superblock),
        Ok(_) => {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(PAGE_SUPERBLOCK_A),
                CorruptDetail::OffsetOutOfRange,
            ));
        }
        Err(error) if is_unsupported(&error) => {
            // Structurally valid copy with an unsupported version/layout:
            // fallback to B is forbidden (fail-closed).
            return Err(error);
        }
        Err(error) if is_absent_copy_error(&error) => {
            a_error = Some(error);
            None
        }
        Err(error) => return Err(error),
    };

    let mut decoded_b: Option<Superblock> = None;
    if let Some(candidate) = &decoded_a {
        let offset = u64::from(candidate.page_size);
        if offset.saturating_add(RECORD) <= file_size {
            let record = read_exact_at(file, offset, SUPERBLOCK_RECORD_SIZE as usize)?;
            match Superblock::decode(&record) {
                Ok(copy) => {
                    if copy.superblock_copy != 1 || u64::from(copy.page_size) != offset {
                        return Err(ZoneFileError::corrupt(
                            CorruptKind::Bounds,
                            Some(PAGE_SUPERBLOCK_B),
                            CorruptDetail::OffsetOutOfRange,
                        ));
                    }
                    decoded_b = Some(copy);
                }
                Err(error) if is_unsupported(&error) => return Err(error),
                Err(error) if is_absent_copy_error(&error) => {
                    // A валидна; отсутствующая/CRC-битая B допустима.
                }
                Err(error) => return Err(error),
            }
        }
    } else {
        for offset in PAGE_SIZE_ALLOWED.map(u64::from) {
            if offset.saturating_add(RECORD) > file_size {
                continue;
            }
            let record = read_exact_at(file, offset, SUPERBLOCK_RECORD_SIZE as usize)?;
            match Superblock::decode(&record) {
                Ok(copy) => {
                    if u64::from(copy.page_size) == offset {
                        if copy.superblock_copy != 1 {
                            return Err(ZoneFileError::corrupt(
                                CorruptKind::Bounds,
                                Some(PAGE_SUPERBLOCK_B),
                                CorruptDetail::OffsetOutOfRange,
                            ));
                        }
                        decoded_b = Some(copy);
                        break;
                    }
                }
                Err(error) if is_unsupported(&error) => {
                    // Структурно валидная B с несовместимой версией: fail-closed.
                    return Err(error);
                }
                Err(error) if !is_absent_copy_error(&error) => return Err(error),
                Err(_) => {}
            }
        }
    }

    match (decoded_a, decoded_b) {
        (Some(a), Some(b)) => {
            if !same_superblock_config(&a, &b) {
                return Err(ZoneFileError::corrupt(
                    CorruptKind::Bounds,
                    Some(PAGE_SUPERBLOCK_B),
                    CorruptDetail::OffsetOutOfRange,
                ));
            }
            Ok(a)
        }
        (Some(a), None) => Ok(a),
        (None, Some(b)) => Ok(b),
        (None, None) => Err(a_error.unwrap_or(ZoneFileError::CorruptNoValidMeta)),
    }
}

#[derive(Debug, Clone, Copy)]
enum MetaPage {
    Valid(Meta),
    /// Слот никогда не использовался (страница целиком нулевая, §4 шаг 8).
    Empty,
    /// Страница содержит данные, но структурно невалидна (CRC/поля).
    Invalid {
        /// `txnid` из поля `+16`, если он читается (CRC не проверен).
        readable_txnid: Option<u64>,
    },
}

fn read_meta(
    file: &File,
    page_no: u32,
    superblock: &Superblock,
) -> Result<MetaPage, ZoneFileError> {
    let offset = u64::from(page_no) * u64::from(superblock.page_size);
    let page = read_exact_at(
        file,
        offset,
        usize::try_from(superblock.page_size).map_err(|_| ZoneFileError::TruncatedFile)?,
    )?;
    classify_meta(
        Meta::decode(
            &page,
            page_no,
            superblock.page_size,
            superblock.page_count_max,
        ),
        &page,
    )
}

fn classify_meta(
    decoded: Result<Meta, ZoneFileError>,
    page: &[u8],
) -> Result<MetaPage, ZoneFileError> {
    match decoded {
        Ok(meta) => Ok(MetaPage::Valid(meta)),
        // Пустой второй слот — нормальное initial-состояние, а не откат.
        Err(ZoneFileError::Corrupt { .. }) if page.iter().all(|&byte| byte == 0) => {
            Ok(MetaPage::Empty)
        }
        // Структурно непригодная/CRC-битая страница: допустим откат на вторую meta.
        // `txnid` читается без доверия к CRC — только чтобы отличить torn-write
        // (штатный крах) от слота, который мог быть новее выбранного.
        Err(ZoneFileError::Corrupt { .. }) => Ok(MetaPage::Invalid {
            readable_txnid: readable_txnid(page),
        }),
        // I/O, неподдерживаемая версия и прочие ошибки — fail-closed, без отката.
        Err(error) => Err(error),
    }
}

/// `txnid` из поля meta `+16` без проверки CRC.
///
/// `None` для нулевого/нечитаемого поля: такой torn-слот не даёт оснований
/// считать, что он был новее активной meta.
fn readable_txnid(page: &[u8]) -> Option<u64> {
    wire::read_u64(page, META_OFF_TXNID).filter(|&txnid| txnid != 0)
}

fn prepare_candidate(
    page: MetaPage,
    superblock: &Superblock,
) -> Result<recovery::MetaSlot, ZoneFileError> {
    match page {
        MetaPage::Empty => Ok(recovery::MetaSlot::NotPersisted),
        MetaPage::Invalid { readable_txnid } => Ok(recovery::MetaSlot::Torn { readable_txnid }),
        MetaPage::Valid(meta) => match validate_meta_against_superblock(meta, superblock) {
            Ok(meta) => Ok(recovery::MetaSlot::Valid(meta)),
            Err(error) if is_unsupported(&error) => Err(error),
            Err(_) => Ok(recovery::MetaSlot::Torn {
                readable_txnid: Some(meta.txnid),
            }),
        },
    }
}

fn check_high_water(meta: &Meta, superblock: &Superblock) -> Result<(), ZoneFileError> {
    if meta.page_count_high_water > superblock.page_count_max {
        return Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(meta.page_no),
            CorruptDetail::ChildRange,
        ));
    }
    let high_water_bytes = u64::from(meta.page_count_high_water)
        .checked_mul(u64::from(superblock.page_size))
        .ok_or_else(|| {
            ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(meta.page_no),
                CorruptDetail::OffsetOutOfRange,
            )
        })?;
    if high_water_bytes > superblock.map_size() {
        return Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(meta.page_no),
            CorruptDetail::ChildRange,
        ));
    }
    Ok(())
}

fn validate_meta_against_superblock(
    meta: Meta,
    superblock: &Superblock,
) -> Result<Meta, ZoneFileError> {
    let off = u32::try_from(superblock.reader_region_off).map_err(|_| {
        ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(meta.page_no),
            CorruptDetail::BadReaderRegion,
        )
    })?;
    let len = u32::try_from(superblock.reader_region_len).map_err(|_| {
        ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(meta.page_no),
            CorruptDetail::BadReaderRegion,
        )
    })?;
    if meta.reader_region_off != off
        || meta.reader_region_len != len
        || meta.page_count_high_water < superblock.page_data_first
    {
        return Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(meta.page_no),
            CorruptDetail::BadReaderRegion,
        ));
    }
    Ok(meta)
}

fn fail_if(fail: Option<CreateFailPoint>, point: CreateFailPoint) -> Result<(), ZoneFileError> {
    if fail == Some(point) {
        return Err(ZoneFileError::Io(io::Error::from_raw_os_error(
            Errno::IO.raw_os_error(),
        )));
    }
    Ok(())
}

fn retry_eintr<T>(mut operation: impl FnMut() -> Result<T, Errno>) -> Result<T, Errno> {
    loop {
        match operation() {
            Err(Errno::INTR) => {}
            other => return other,
        }
    }
}

fn sync_data(file: &File) -> Result<(), ZoneFileError> {
    retry_eintr(|| fdatasync(file)).map_err(io::Error::from)?;
    Ok(())
}

fn sync_directory_fd(fd: &impl std::os::fd::AsFd) -> Result<(), ZoneFileError> {
    retry_eintr(|| fsync(fd)).map_err(io::Error::from)?;
    Ok(())
}

fn encode_reader_pages(count: u32, page_size: u32) -> Vec<Vec<u8>> {
    (0..count)
        .map(|index| {
            let mut page = vec![0_u8; usize::try_from(page_size).unwrap_or(0)];
            let page_no = PAGE_READER_TABLE.saturating_add(index);
            wire::write_u32(&mut page, RTP_OFF_PAGE_TYPE, PAGE_TYPE_READER_TABLE);
            wire::write_u16(&mut page, RTP_OFF_VERSION, 1);
            wire::write_u16(&mut page, RTP_OFF_PAGE_FLAGS, 0);
            wire::write_u32(&mut page, RTP_OFF_PAGE_NO, page_no);
            wire::write_u32(&mut page, RTP_OFF_SLOTS_USED, 0);
            wire::write_u32(&mut page, RTP_OFF_CRC32C, 0);
            page
        })
        .collect()
}

fn write_runs(file: &File, runs: &[(u64, &[u8])]) -> Result<(), ZoneFileError> {
    for (offset, data) in runs {
        writev_at(file, *offset, &[*data])?;
    }
    Ok(())
}

fn write_pages(file: &File, offset: u64, pages: &[&[u8]]) -> Result<(), ZoneFileError> {
    const MAX_BATCH: usize = 64;
    let mut base = offset;
    for batch in pages.chunks(MAX_BATCH) {
        writev_at(file, base, batch)?;
        for page in batch {
            base = base.saturating_add(u64::try_from(page.len()).unwrap_or(0));
        }
    }
    Ok(())
}

fn writev_at(file: &File, offset: u64, bufs: &[&[u8]]) -> Result<(), ZoneFileError> {
    writev_at_with(
        |slices, offset| retry_eintr(|| rustix::io::pwritev(file, slices, offset)),
        offset,
        bufs,
    )
}

fn writev_at_with<W>(mut write: W, mut offset: u64, bufs: &[&[u8]]) -> Result<(), ZoneFileError>
where
    W: FnMut(&[io::IoSlice<'_>], u64) -> Result<usize, Errno>,
{
    let mut remaining: Vec<&[u8]> = bufs.to_vec();
    while !remaining.is_empty() {
        let slices: Vec<io::IoSlice<'_>> =
            remaining.iter().map(|buf| io::IoSlice::new(buf)).collect();
        let written = write(&slices, offset).map_err(io::Error::from)?;
        if written == 0 {
            return Err(ZoneFileError::Io(io::Error::from(io::ErrorKind::WriteZero)));
        }
        offset = offset.saturating_add(
            u64::try_from(written)
                .map_err(|_| ZoneFileError::Io(io::Error::from(io::ErrorKind::InvalidData)))?,
        );
        let mut consumed = written;
        let mut index = 0;
        while index < remaining.len() {
            let Some(buf) = remaining.get(index) else {
                break;
            };
            if consumed >= buf.len() {
                consumed -= buf.len();
                index += 1;
            } else {
                break;
            }
        }
        if index >= remaining.len() {
            break;
        }
        if consumed > 0
            && let Some(buf) = remaining.get_mut(index)
        {
            *buf = buf.get(consumed..).unwrap_or(&[]);
        }
        remaining.drain(..index);
    }
    Ok(())
}

fn fsync_directory(path: &Path) -> Result<(), ZoneFileError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let fd = fs_open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    sync_directory_fd(&fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::PAGE_SUPERBLOCK_A;

    fn test_superblock() -> Superblock {
        Superblock::for_new(
            CreateConfig {
                map_size: 64 * 1024 * 1024,
                ..CreateConfig::default()
            },
            [3; 16],
            42,
        )
        .unwrap()
    }

    #[test]
    fn create_failure_removes_data_and_lock_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zones.zonefile");
        let result = create_failing(
            &path,
            CreateConfig {
                map_size: 64 * 1024 * 1024,
                ..CreateConfig::default()
            },
            CreateFailPoint::AfterReaderPages,
        );
        assert!(matches!(result, Err(ZoneFileError::Io(_))));
        assert!(!path.exists());
        let lock = PathBuf::from(WriterLock::path_for(&path));
        assert!(!lock.exists());
    }

    #[test]
    fn read_meta_propagates_io_errors() {
        let dir = tempfile::tempdir().unwrap();
        let directory = File::open(dir.path()).unwrap();
        let superblock = test_superblock();
        let result = read_meta(&directory, PAGE_META_A, &superblock);
        assert!(matches!(result, Err(ZoneFileError::Io(_))));
    }

    #[test]
    fn classify_meta_distinguishes_structural_errors() {
        let io_error = ZoneFileError::Io(io::Error::from_raw_os_error(5));
        assert!(matches!(
            classify_meta(Err(io_error), &[1, 2, 3]),
            Err(ZoneFileError::Io(_))
        ));
        let version = ZoneFileError::UnsupportedVersion {
            found: crate::Version { major: 2, minor: 0 },
            supported: crate::Version { major: 1, minor: 0 },
            required_flags: 0,
        };
        assert!(matches!(
            classify_meta(Err(version), &[1, 2, 3]),
            Err(ZoneFileError::UnsupportedVersion { .. })
        ));
        assert!(matches!(
            classify_meta(
                Err(ZoneFileError::corrupt(
                    CorruptKind::PageChecksum,
                    Some(PAGE_META_A),
                    CorruptDetail::Checksum,
                )),
                &[1, 2, 3]
            ),
            Ok(MetaPage::Invalid { .. })
        ));
        assert!(matches!(
            classify_meta(
                Err(ZoneFileError::corrupt(
                    CorruptKind::PageChecksum,
                    Some(PAGE_META_A),
                    CorruptDetail::Checksum,
                )),
                &[0, 0, 0]
            ),
            Ok(MetaPage::Empty)
        ));
    }

    #[test]
    fn retry_eintr_retries_until_success() {
        let mut calls = 0;
        let result = retry_eintr(|| {
            calls += 1;
            if calls < 3 {
                Err(Errno::INTR)
            } else {
                Ok(7_u32)
            }
        });
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls, 3);
    }

    #[test]
    fn writev_handles_partial_writes_and_offsets() {
        let first = [1_u8, 2, 3];
        let second = [4_u8, 5, 6, 7];
        let mut output = Vec::new();
        let mut offsets = Vec::new();
        writev_at_with(
            |slices, offset| {
                offsets.push(offset);
                let mut budget = 3_usize;
                for slice in slices {
                    if budget == 0 {
                        break;
                    }
                    let take = slice.len().min(budget);
                    output.extend_from_slice(slice.get(..take).unwrap_or(&[]));
                    budget -= take;
                }
                let written = 3.min(slices.iter().map(|slice| slice.len()).sum::<usize>());
                Ok(written)
            },
            100,
            &[first.as_slice(), second.as_slice()],
        )
        .unwrap();
        assert_eq!(output, vec![1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(offsets, vec![100, 103, 106]);
    }

    #[test]
    fn strict_mode_rejects_foreign_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.zonefile");
        let file = File::create(&path).unwrap();
        rustix::fs::fchmod(&file, Mode::RUSR | Mode::WUSR).unwrap();
        let mut stat = fstat(&file).unwrap();
        assert!(validate_file_identity(&stat, true).is_ok());
        stat.st_uid = stat.st_uid.wrapping_add(1);
        assert!(validate_file_identity(&stat, true).is_err());
        assert!(validate_file_identity(&stat, false).is_ok());
    }

    #[test]
    fn permissive_strict_is_test_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("permissive.zonefile");
        let (opened, lock) = create(
            &path,
            CreateConfig {
                map_size: 64 * 1024 * 1024,
                ..CreateConfig::default()
            },
        )
        .unwrap();
        drop(opened);
        drop(lock);
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .unwrap();
        // Внутри cfg(test) permissive разрешён.
        assert!(
            open(
                &path,
                OpenConfig {
                    strict: false,
                    ..OpenConfig::default()
                }
            )
            .is_ok()
        );
        // А strict=true по-прежнему отвергает.
        assert!(open(&path, OpenConfig::default()).is_err());
    }

    #[test]
    fn superblock_copy_flag_expected_for_each_page() {
        let superblock = test_superblock();
        let record = superblock.encode();
        assert!(decode_copy(&record, 0, PAGE_SUPERBLOCK_A).is_ok());
        assert!(decode_copy(&record, 1, PAGE_SUPERBLOCK_A).is_err());
    }
}
