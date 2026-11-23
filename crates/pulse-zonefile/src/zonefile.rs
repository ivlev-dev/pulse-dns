//! Публичный корень формата: экземпляр открытого файла зон.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::lock::WriterLock;
use crate::map::FileMap;
use crate::meta::Meta;
use crate::page::PageHeader;
use crate::pager::{self, LockMode, OpenConfig};
use crate::readers::{ActiveTxn, Reader, ReaderTable, Snapshot};
use crate::superblock::{CreateConfig, Superblock, SyncMode};

/// Открытый файл зон.
///
/// Экземпляр держит маппинги (`PROT_READ` на файл и единственный writable —
/// на регион reader table) и, для writer'а, эксклюзивную блокировку.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct ZoneFile {
    _file: Arc<File>,
    map: FileMap,
    superblock: Superblock,
    meta: Meta,
    readers: Arc<ReaderTable>,
    active: ActiveTxn,
    recovered_unsynced: bool,
    torn_meta: bool,
    write_locked: bool,
    memory_tail_discarded: bool,
    durable_watermark: u64,
    lock: Option<WriterLock>,
}

impl ZoneFile {
    /// Создаёт новый файл зон строго по последовательности §4.
    ///
    /// Файл создаётся `O_CREAT|O_EXCL` с правами `0600`, расширяется до
    /// `map_size` и инициализируется superblock A/B, начальной meta
    /// (`txnid = 1`, `durable_txn = 1`) и страницами reader table; в конце
    /// выполняется `fdatasync` и `fsync` каталога. Lock-файл writer'а берётся
    /// до создания данных.
    ///
    /// # Errors
    ///
    /// `AlreadyExists` — путь уже существует; `Busy` — lock занят;
    /// `MapAllocFailed` — `ftruncate`/`mmap` не удались; `Io` — ошибка записи.
    pub fn create(path: &Path, cfg: CreateConfig) -> Result<Self, ZoneFileError> {
        let (opened, lock) = pager::create(path, cfg)?;
        let active = ActiveTxn::new(opened.meta.txnid);
        Ok(Self {
            _file: opened.file,
            map: opened.map,
            superblock: opened.superblock,
            meta: opened.meta,
            readers: Arc::new(opened.readers),
            active,
            recovered_unsynced: false,
            torn_meta: false,
            write_locked: false,
            memory_tail_discarded: false,
            durable_watermark: opened.meta.durable_txn,
            lock: Some(lock),
        })
    }

    /// Открывает существующий файл и выбирает активную meta по §13.7.
    ///
    /// Выбирается max-valid meta; один torn-слот при валидном втором —
    /// штатный крах ([`ZoneFile::torn_meta`]). `Memory`-файл сначала чисто
    /// откатывается на подтверждённую meta `txnid <= durable_txn`
    /// ([`ZoneFile::memory_tail_discarded`]); если такой нет — нужен
    /// `allow_unsynced_memory_recovery`, и тогда файл write-locked до offline
    /// `fsck` ([`ZoneFile::is_write_locked`]).
    ///
    /// Читатель не берёт `flock`; writer берёт `<zonefile>.lock`
    /// (`LOCK_EX | LOCK_NB`) и получает `Busy` при втором писателе.
    ///
    /// # Errors
    ///
    /// `TruncatedFile` — файл короче `page_count_max * page_size`;
    /// `CorruptNoValidMeta` — обе meta невалидны; `Busy` — writer уже открыт;
    /// `UnsyncedMemoryRecovery` — `Memory` без подтверждённой meta и без
    /// `allow_unsynced_memory_recovery`;
    /// `RolledBackToInitial` — откат к initial meta без `allow_rollback_to_initial`;
    /// `UnsupportedVersion`/`Corrupt` — несовместимый или повреждённый файл.
    pub fn open(path: &Path, cfg: OpenConfig) -> Result<Self, ZoneFileError> {
        let (opened, lock) = pager::open(path, cfg)?;
        let active = ActiveTxn::new(opened.meta.txnid);
        Ok(Self {
            _file: opened.file,
            map: opened.map,
            superblock: opened.superblock,
            meta: opened.meta,
            readers: Arc::new(opened.readers),
            active,
            recovered_unsynced: opened.recovered_unsynced,
            torn_meta: opened.torn_meta,
            write_locked: opened.write_locked,
            memory_tail_discarded: opened.memory_tail_discarded,
            durable_watermark: opened.durable_watermark,
            lock,
        })
    }

    /// Superblock файла.
    #[must_use]
    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// Активная meta.
    #[must_use]
    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// Таблица читателей.
    #[must_use]
    pub fn reader_table(&self) -> &ReaderTable {
        &self.readers
    }

    /// Возвращает поток-локальный вход читателя.
    ///
    /// `open()` слоты не занимает; слот занимается при [`Reader::snapshot`]
    /// (§13.1 шаг 11). Снапшот держит пин и освобождает его при `Drop`.
    #[must_use]
    pub fn reader(&self) -> Reader<'_> {
        Reader::new(
            Arc::clone(&self.readers),
            &self.active,
            self.superblock.instance_uuid,
        )
    }

    /// Текущий опубликованный `txnid`.
    #[must_use]
    pub fn txnid(&self) -> u64 {
        self.active.load()
    }

    /// Была ли выбрана meta новее `durable_watermark` (диагностика recovery).
    #[must_use]
    pub fn recovered_unsynced(&self) -> bool {
        self.recovered_unsynced
    }

    /// Обнаружен ли при открытии torn-слот meta (§13.7).
    ///
    /// `true` — один из слотов повреждён, второй валиден; это штатный крах
    /// (torn write), а не повод для `NEEDS_FSCK`. Если такой слот мог быть
    /// новее выбранного, `meta().needs_fsck()` выставлен отдельно.
    #[must_use]
    pub fn torn_meta(&self) -> bool {
        self.torn_meta
    }

    /// `Memory`: recovery чистым откатом отбросил неподтверждённый хвост
    /// (§13.7 шаг 7a). Выбранная meta имеет `txnid <= durable_txn`; запись
    /// разрешена, `NEEDS_FSCK` не выставлен.
    #[must_use]
    pub fn memory_tail_discarded(&self) -> bool {
        self.memory_tail_discarded
    }

    /// Запрещена ли запись до offline `fsck` (§13.7).
    ///
    /// `true` только для `Memory`-файла, принятого через
    /// `allow_unsynced_memory_recovery`: max-valid meta может ссылаться на
    /// потерянные данные. Чтение разрешено, но проходит ленивые проверки
    /// [`ZoneFile::page_header`]; коммиты обязаны отклоняться. Пока freelist
    /// не реализован, это только флаг; выдача из freelist в этом состоянии
    /// запрещена — он может указывать на потерянные bucket-страницы.
    #[must_use]
    pub fn is_write_locked(&self) -> bool {
        self.write_locked
    }

    /// Единый durable-watermark файла (§4.1, §14).
    ///
    /// Максимум `min(durable_txn, txnid)` по валидным метам, известный recovery.
    /// Runtime-проверки используют именно его, а не `meta.durable_txn`
    /// выбранной meta: при регрессии durable (W-10) meta может быть ниже
    /// watermark, и это не должно ослаблять режим/границу переиспользования.
    #[must_use]
    pub fn durable_watermark(&self) -> u64 {
        self.durable_watermark
    }

    /// Эффективный режим durability (§4.1).
    ///
    /// Пока `durable_watermark == 1`, это `superblock.sync_mode`; после первого
    /// durable-водораздела (`durable_watermark > 1`, то есть `Sync`-коммита или
    /// `sync()`) режим **липко** становится `Sync`: коммит слабее эффективного
    /// отклоняется [`InvariantViolation(DurabilityBelowFileMode)`](crate::InvariantId::DurabilityBelowFileMode).
    #[must_use]
    pub fn effective_mode(&self) -> SyncMode {
        self.superblock
            .sync_mode
            .effective_mode(self.durable_watermark)
    }

    /// Проверяет режим будущего коммита (контракт фазы 3).
    ///
    /// # Errors
    ///
    /// `ReadOnly` — файл write-locked до offline `fsck`;
    /// `InvariantViolation(DurabilityBelowFileMode)` — запрошенный режим слабее
    /// [`ZoneFile::effective_mode`].
    pub fn check_commit_mode(&self, requested: SyncMode) -> Result<(), ZoneFileError> {
        if self.write_locked {
            return Err(ZoneFileError::ReadOnly);
        }
        self.superblock
            .sync_mode
            .check_commit(self.durable_watermark, requested)
    }

    /// Заголовок страницы данных под пином снапшота, с ленивыми проверками (§7).
    ///
    /// Единственный публичный путь чтения страницы: сырые байты наружу не
    /// отдаются (типизированное чтение появится в фазе 2). Требует [`Snapshot`]:
    /// пин удерживает `oldest_reader_txn` на `snapshot.txnid`, поэтому writer не
    /// может переиспользовать страницы, достижимые из снапшота, пока он жив
    /// (§6.3, §14). Снапшот обязан принадлежать этому файлу (`instance_uuid`),
    /// иначе — [`ZoneFileError::SnapshotFromDifferentFile`]: чужой пин не
    /// защищает страницы от переиспользования.
    ///
    /// Проверяет `page.txn <= snapshot.txnid`, CRC, `page_no`/`page_type`,
    /// reserved-поля, `payload_len` и границы `[page_data_first, high_water)`.
    /// Для write-locked `Memory`-файла это обязательный путь чтения до offline
    /// `fsck`; ошибка означает, что страница не могла быть прочитана на момент
    /// снапшота.
    ///
    /// Чтение без снапшота невозможно:
    ///
    /// ```compile_fail
    /// fn unguarded(zonefile: &pulse_zonefile::ZoneFile) {
    ///     let _ = zonefile.page_header(2, 1);
    /// }
    /// ```
    ///
    /// Снапшот должен быть жив на момент вызова:
    ///
    /// ```compile_fail
    /// fn after_drop(zonefile: &pulse_zonefile::ZoneFile) {
    ///     let reader = zonefile.reader();
    ///     let snapshot = reader.snapshot().unwrap();
    ///     drop(snapshot);
    ///     let _ = zonefile.page_header(&snapshot, 2);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница вне диапазона данных или невалидна (включая
    /// `page.txn > snapshot.txnid`); `SnapshotFromDifferentFile` — снапшот
    /// создан другим `ZoneFile`.
    pub fn page_header(
        &self,
        snapshot: &Snapshot,
        page_no: u32,
    ) -> Result<PageHeader, ZoneFileError> {
        if snapshot.instance_uuid() != self.superblock.instance_uuid {
            return Err(ZoneFileError::SnapshotFromDifferentFile);
        }
        if page_no < self.superblock.page_data_first || page_no >= self.meta.page_count_high_water {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(page_no),
                CorruptDetail::ChildRange,
            ));
        }
        let page = self
            .map
            .page(page_no, self.superblock.page_size)
            .ok_or_else(|| {
                ZoneFileError::corrupt(
                    CorruptKind::Bounds,
                    Some(page_no),
                    CorruptDetail::ChildRange,
                )
            })?;
        PageHeader::decode(page, page_no, snapshot.txnid(), self.superblock.page_size)
    }

    /// Взят ли эксклюзивный lock writer'а.
    #[must_use]
    pub fn is_writer(&self) -> bool {
        self.lock.is_some()
    }

    /// Режим блокировки, с которым открыт экземпляр.
    #[must_use]
    pub fn lock_mode(&self) -> LockMode {
        if self.lock.is_some() {
            LockMode::Writer
        } else {
            LockMode::Reader
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CreateConfig;

    #[test]
    fn snapshot_keeps_txn_and_releases_on_last_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zones.zonefile");
        let zonefile = ZoneFile::create(
            &path,
            CreateConfig {
                map_size: 64 * 1024 * 1024,
                ..CreateConfig::default()
            },
        )
        .unwrap();
        let reader = zonefile.reader();
        let snapshot = reader.snapshot().unwrap();
        assert_eq!(snapshot.txnid(), 1);
        assert_eq!(zonefile.reader_table().registered_slots(), 1);

        zonefile.active.publish(2);
        assert_eq!(zonefile.txnid(), 2);
        assert_eq!(snapshot.txnid(), 1);
        assert_eq!(zonefile.reader_table().oldest_reader_txn(99), 1);
        let second = reader.snapshot().unwrap();
        assert_eq!(second.txnid(), 2);

        let cloned = snapshot.clone();
        drop(snapshot);
        assert_eq!(zonefile.reader_table().oldest_reader_txn(99), 1);
        drop(cloned);
        assert_eq!(zonefile.reader_table().oldest_reader_txn(99), 2);
        drop(second);
        assert_eq!(zonefile.reader_table().oldest_reader_txn(99), 99);
        assert_eq!(zonefile.reader_table().registered_slots(), 0);
    }
}
