//! Публичный корень формата: открытый файл зон, writer-транзакции и fsck.
//!
//! [`ZoneFile`] держит маппинги и активную meta. Запись идёт через
//! [`ZoneFile::write`]: [`ZoneWriter`] собирает COW-страницы в памяти, а
//! `commit` записывает данные, bucket'ы freelist и новую meta в порядке
//! §13.6 (данные → `fdatasync` → meta → публикация).

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;

use rustix::fs::fdatasync;

use crate::cache::PageCache;
use crate::consts::{
    MAX_RECLAIM_PAGES_PER_COMMIT, MAX_RECLAIM_ZONES_PER_COMMIT, PAGE_META_A, PAGE_META_B,
};
use crate::errors::{CorruptDetail, CorruptKind, InvariantId, ZoneFileError};
use crate::key::{Key, NameRle, T_ZONE_ENTRY, ZoneEntryKey};
use crate::lock::WriterLock;
use crate::map::FileMap;
use crate::meta::Meta;
use crate::node::{
    DecodedBranch, DecodedLeaf, DecodedValue, ItemValue, LeafItem, LeafValue, ValueKind,
};
use crate::overflow::{self, OverflowRrset};
use crate::page::PageHeader;
use crate::pager::{self, LockMode, OpenConfig};
use crate::readers::{ActiveTxn, Reader, ReaderTable, Snapshot};
use crate::store::TxnPages;
use crate::superblock::{CreateConfig, Superblock, SyncMode};
use crate::tree::{BTree, Cursor, PageIo, RrsetData, UpsertOutcome, ZoneTree};
use crate::wire;
use crate::zone_index::{ZoneIndex, ZoneLocation};
use crate::zone_meta::{ZoneEntry, ZoneMetaBlock, ZoneState};

const META_HISTORY_LEN: usize = 32;

/// Просмотренный `RRset` (копия RDATA для прикладного API).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsetView {
    /// TTL набора.
    pub ttl: u32,
    /// Флаги набора.
    pub flags: u16,
    /// RDATA каждого RR в каноническом порядке.
    pub rdata: Vec<Vec<u8>>,
}

/// Итог коммита.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOutcome {
    /// Опубликованный `txnid`.
    pub txnid: u64,
    /// Достигнут ли durable-водораздел этим коммитом.
    pub durable: bool,
    /// Записано страниц (данные + bucket-образы).
    pub pages_written: u32,
    /// Страниц в freelist после коммита.
    pub freed_pages: u64,
    /// Число bucket-страниц freelist.
    pub bucket_pages: u32,
    /// Режим durability коммита.
    pub sync_mode: SyncMode,
}

/// Значение элемента зоны при обходе ([`ZoneFile::zone_items`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneItemValue {
    /// `T_NODE`-маркер имени (включая apex и ENT).
    Node {
        /// Флаги `T_NODE` (`RR_FLAG_*`).
        flags: u16,
    },
    /// `RRset` с TTL, флагами и RDATA.
    Rrset(RrsetView),
}

/// Один элемент дерева зоны в каноническом порядке.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneItem {
    /// Имя-владелец.
    pub name: NameRle,
    /// Тип записи (`T_NODE` = 0).
    pub rr_type: u16,
    /// Класс (`0` для `T_NODE`).
    pub class: u16,
    /// Подтип (`RRSIG` covered type).
    pub subtype: u16,
    /// Значение.
    pub value: ZoneItemValue,
}

/// Итератор элементов зоны, включая apex, ENT и `T_NODE`.
///
/// Элементы выдаются в каноническом порядке ключей; каждый `next()` может
/// вернуть `Corrupt`, если встретилась повреждённая страница.
pub struct ZoneItems<'a> {
    zonefile: &'a ZoneFile,
    cursor: Cursor<'a, ZoneFile>,
    txnid: u64,
    finished: bool,
}

impl Iterator for ZoneItems<'_> {
    type Item = Result<ZoneItem, ZoneFileError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let key = match self.cursor.key() {
            Ok(Some(key)) => key,
            Ok(None) => {
                self.finished = true;
                return None;
            }
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        };
        let name = match key.owner() {
            Ok(name) => name,
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        };
        let value = match self.cursor.value() {
            Ok(Some(value)) => value,
            Ok(None) => {
                self.finished = true;
                return None;
            }
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        };
        let item = match value {
            DecodedValue::ZoneEntry(_) => Err(ZoneFileError::corrupt(
                CorruptKind::BadZoneMeta,
                None,
                CorruptDetail::ZoneMetaField,
            )),
            DecodedValue::Rrset { value, payload } => {
                if value.kind == ValueKind::Node {
                    Ok(ZoneItem {
                        name,
                        rr_type: key.rr_type(),
                        class: key.class(),
                        subtype: key.subtype(),
                        value: ZoneItemValue::Node { flags: value.flags },
                    })
                } else {
                    match self
                        .zonefile
                        .rrset_view_from_value(self.txnid, value, payload)
                    {
                        Ok(view) => Ok(ZoneItem {
                            name,
                            rr_type: key.rr_type(),
                            class: key.class(),
                            subtype: key.subtype(),
                            value: ZoneItemValue::Rrset(view),
                        }),
                        Err(error) => Err(error),
                    }
                }
            }
        };
        match self.cursor.advance() {
            Ok(true) => {}
            Ok(false) => self.finished = true,
            Err(error) => {
                self.finished = true;
                return Some(Err(error));
            }
        }
        Some(item)
    }
}

/// Отчёт `fsck`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FsckReport {
    /// Достижимых страниц графа (каталог, зоны, overflow, zone-meta).
    pub reachable_pages: u64,
    /// Страниц в freelist.
    pub freelist_pages: u64,
    /// Bucket-страниц.
    pub bucket_pages: u64,
    /// `page_count_high_water`.
    pub high_water: u32,
    /// `page_count_max`.
    pub page_count_max: u32,
    /// Живых зон.
    pub zone_count: u32,
    /// `RRset` по счётчикам.
    pub rrset_count: u64,
    /// RR по счётчикам.
    pub rr_count: u64,
    /// Найденные утечки/несогласованности (не фатальные).
    pub problems: Vec<String>,
}

impl FsckReport {
    /// Истина, если проблем не найдено.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Открытый файл зон.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct ZoneFile {
    file: Arc<File>,
    map: Arc<FileMap>,
    superblock: Superblock,
    meta: Meta,
    readers: Arc<ReaderTable>,
    active: ActiveTxn,
    recovered_unsynced: bool,
    torn_meta: bool,
    write_locked: bool,
    memory_tail_discarded: bool,
    durable_watermark: u64,
    page_cache: Arc<PageCache>,
    zone_index: ZoneIndex,
    meta_history: VecDeque<Meta>,
    lock: Option<WriterLock>,
}

impl ZoneFile {
    /// Создаёт новый файл зон строго по последовательности §4.
    ///
    /// # Errors
    ///
    /// `AlreadyExists`, `Busy`, `MapAllocFailed`, `Io`.
    pub fn create(path: &Path, cfg: CreateConfig) -> Result<Self, ZoneFileError> {
        let (opened, lock) = pager::create(path, cfg)?;
        let active = ActiveTxn::new(opened.meta.txnid);
        let page_cache = Arc::new(PageCache::new(opened.superblock.page_size));
        let mut meta_history = VecDeque::with_capacity(META_HISTORY_LEN);
        meta_history.push_back(opened.meta);
        Ok(Self {
            file: opened.file,
            map: Arc::new(opened.map),
            superblock: opened.superblock,
            meta: opened.meta,
            readers: Arc::new(opened.readers),
            active,
            recovered_unsynced: false,
            torn_meta: false,
            write_locked: false,
            memory_tail_discarded: false,
            durable_watermark: opened.meta.durable_txn,
            page_cache,
            zone_index: ZoneIndex::new(),
            meta_history,
            lock: Some(lock),
        })
    }

    /// Открывает существующий файл и выбирает активную meta по §13.7.
    ///
    /// # Errors
    ///
    /// `TruncatedFile`, `CorruptNoValidMeta`, `Busy`, `UnsyncedMemoryRecovery`,
    /// `RolledBackToInitial`, `UnsupportedVersion`, `Corrupt`.
    pub fn open(path: &Path, cfg: OpenConfig) -> Result<Self, ZoneFileError> {
        let (opened, lock) = pager::open(path, cfg)?;
        let active = ActiveTxn::new(opened.meta.txnid);
        let page_cache = Arc::new(PageCache::new(opened.superblock.page_size));
        let mut meta_history = VecDeque::with_capacity(META_HISTORY_LEN);
        meta_history.push_back(opened.meta);
        Ok(Self {
            file: opened.file,
            map: Arc::new(opened.map),
            superblock: opened.superblock,
            meta: opened.meta,
            readers: Arc::new(opened.readers),
            active,
            recovered_unsynced: opened.recovered_unsynced,
            torn_meta: opened.torn_meta,
            write_locked: opened.write_locked,
            memory_tail_discarded: opened.memory_tail_discarded,
            durable_watermark: opened.durable_watermark,
            page_cache,
            zone_index: ZoneIndex::new(),
            meta_history,
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

    /// Была ли выбрана meta новее `durable_watermark`.
    #[must_use]
    pub fn recovered_unsynced(&self) -> bool {
        self.recovered_unsynced
    }

    /// Обнаружен ли при открытии torn-слот meta.
    #[must_use]
    pub fn torn_meta(&self) -> bool {
        self.torn_meta
    }

    /// `Memory`: recovery отбросил неподтверждённый хвост.
    #[must_use]
    pub fn memory_tail_discarded(&self) -> bool {
        self.memory_tail_discarded
    }

    /// Запрещена ли запись до offline `fsck`.
    #[must_use]
    pub fn is_write_locked(&self) -> bool {
        self.write_locked
    }

    /// Единый durable-watermark файла.
    #[must_use]
    pub fn durable_watermark(&self) -> u64 {
        self.durable_watermark
    }

    /// Эффективный режим durability.
    #[must_use]
    pub fn effective_mode(&self) -> SyncMode {
        self.superblock
            .sync_mode
            .effective_mode(self.durable_watermark)
    }

    /// Проверяет режим будущего коммита.
    ///
    /// # Errors
    ///
    /// `ReadOnly`, `InvariantViolation(DurabilityBelowFileMode)`.
    pub fn check_commit_mode(&self, requested: SyncMode) -> Result<(), ZoneFileError> {
        if self.write_locked {
            return Err(ZoneFileError::ReadOnly);
        }
        self.superblock
            .sync_mode
            .check_commit(self.durable_watermark, requested)
    }

    /// Страница под пином снапшота с ленивыми проверками.
    ///
    /// # Errors
    ///
    /// `Corrupt`, `SnapshotFromDifferentFile`.
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

    /// Режим блокировки.
    #[must_use]
    pub fn lock_mode(&self) -> LockMode {
        if self.lock.is_some() {
            LockMode::Writer
        } else {
            LockMode::Reader
        }
    }

    /// Кеш валидированных страниц (чтение).
    #[must_use]
    pub fn page_cache(&self) -> &PageCache {
        &self.page_cache
    }

    /// Индекс зон в памяти.
    #[must_use]
    pub fn zone_index(&self) -> &ZoneIndex {
        &self.zone_index
    }

    /// Открывает writer-транзакцию.
    ///
    /// # Errors
    ///
    /// `ReadOnly` — экземпляр не writer или файл write-locked до `fsck`;
    /// `Corrupt` — повреждённый freelist/каталог; `MapFull`/`NoSpace`.
    pub fn write(&mut self) -> Result<ZoneWriter<'_>, ZoneFileError> {
        if self.lock.is_none() || self.write_locked {
            return Err(ZoneFileError::ReadOnly);
        }
        let oldest = self.readers.oldest_reader_txn(self.meta.txnid);
        let reclaim = self.durable_watermark.saturating_sub(1).min(oldest);
        let pages = TxnPages::new(
            Arc::clone(&self.map),
            self.superblock.page_size,
            self.superblock.page_count_max,
            self.meta.txnid,
            self.meta.page_count_high_water,
            reclaim,
            self.meta.freelist_head,
            self.meta.freelist_tail,
            self.meta.freelist_buckets,
            self.meta.freelist_entries,
        )?;
        let catalog = BTree::new(self.meta.zone_dir_root, self.meta.zone_dir_level)?;
        let zone_count = self.meta.zone_count;
        let next_zone_seq = self.meta.next_zone_seq;
        let total_rrsets = self.meta.total_rrsets;
        let total_rrs = self.meta.total_rrs;
        Ok(ZoneWriter {
            file: self,
            pages: Some(pages),
            catalog,
            zone_count,
            next_zone_seq,
            total_rrsets,
            total_rrs,
            catalog_changed: false,
        })
    }

    fn snapshot_meta(&self, txnid: u64) -> &Meta {
        self.meta_history
            .iter()
            .rev()
            .find(|meta| meta.txnid <= txnid)
            .unwrap_or(&self.meta)
    }

    fn catalog_entry_at(
        &self,
        meta: &Meta,
        apex: &NameRle,
    ) -> Result<Option<ZoneEntry>, ZoneFileError> {
        let catalog = BTree::new(meta.zone_dir_root, meta.zone_dir_level)?;
        let key = ZoneEntryKey::new(apex)?;
        match catalog.lookup_cached(self, &self.page_cache, meta.txnid, key.key())? {
            Some(entry) => match entry.value {
                DecodedValue::ZoneEntry(bytes) => Ok(Some(ZoneEntry::decode(bytes)?)),
                DecodedValue::Rrset { .. } => Err(ZoneFileError::corrupt(
                    CorruptKind::BadZoneMeta,
                    None,
                    CorruptDetail::ZoneMetaField,
                )),
            },
            None => Ok(None),
        }
    }

    /// Запись каталога по apex (включая tombstone).
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённый каталог/запись.
    pub fn zone_entry(&self, apex: &NameRle) -> Result<Option<ZoneEntry>, ZoneFileError> {
        self.catalog_entry_at(&self.meta, apex)
    }

    /// Ищет зону по точному apex; tombstone невидим.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённый каталог.
    pub fn find_zone(&self, apex: &NameRle) -> Result<Option<ZoneEntry>, ZoneFileError> {
        if let Some(location) = self.zone_index.get(apex)
            && location.state == ZoneState::Tombstone.as_u8()
        {
            return Ok(None);
        }
        let Some(entry) = self.catalog_entry_at(&self.meta, apex)? else {
            return Ok(None);
        };
        if !entry.is_live() {
            return Ok(None);
        }
        self.zone_index.insert(
            *apex,
            ZoneLocation {
                root: entry.tree_root,
                level: entry.tree_level,
                meta_root: entry.meta_root,
                zone_seq: entry.zone_seq,
                state: entry.state.as_u8(),
            },
        );
        Ok(Some(entry))
    }

    /// Longest-suffix поиск зоны по QNAME.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённый каталог.
    pub fn find_zone_suffix(
        &self,
        qname: &NameRle,
    ) -> Result<Option<(NameRle, ZoneEntry)>, ZoneFileError> {
        let mut current = Some(*qname);
        while let Some(name) = current {
            if self.find_zone(&name)?.is_some() {
                let entry = self.catalog_entry_at(&self.meta, &name)?.ok_or_else(|| {
                    ZoneFileError::corrupt(
                        CorruptKind::BadZoneMeta,
                        None,
                        CorruptDetail::ZoneMetaField,
                    )
                })?;
                return Ok(Some((name, entry)));
            }
            current = name.parent();
        }
        Ok(None)
    }

    /// Все живые зоны.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённый каталог.
    pub fn zones(&self) -> Result<Vec<(NameRle, ZoneEntry)>, ZoneFileError> {
        let catalog = BTree::new(self.meta.zone_dir_root, self.meta.zone_dir_level)?;
        let mut cursor = catalog.cursor(self, self.meta.txnid);
        let mut out = Vec::new();
        if !cursor.seek_first()? {
            return Ok(out);
        }
        while let Some(key) = cursor.key()? {
            if key.rr_type() == T_ZONE_ENTRY {
                let apex = key.owner()?;
                if let Some(DecodedValue::ZoneEntry(bytes)) = cursor.value()? {
                    let entry = ZoneEntry::decode(bytes)?;
                    if entry.is_live() {
                        out.push((apex, entry));
                    }
                }
            }
            if !cursor.advance()? {
                break;
            }
        }
        Ok(out)
    }

    /// Живая зона по точному origin (apex).
    ///
    /// В отличие от [`ZoneFile::zone_entry`], tombstone не возвращается.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённый каталог.
    pub fn zone_by_origin(&self, origin: &NameRle) -> Result<Option<ZoneEntry>, ZoneFileError> {
        self.find_zone(origin)
    }

    /// Итератор всех элементов живой зоны: `T_NODE` (apex/ENT), `RRset`,
    /// включая `RRSIG`-подтипы, в каноническом порядке.
    ///
    /// Пустая зона или tombstone дают пустой итератор.
    ///
    /// # Errors
    ///
    /// `Corrupt` — повреждённый каталог/дерево; `Corrupt(Bounds)` —
    /// несогласованные `tree_root`/`tree_level`.
    pub fn zone_items<'a>(&'a self, apex: &NameRle) -> Result<ZoneItems<'a>, ZoneFileError> {
        let txnid = self.meta.txnid;
        let Some(entry) = self.catalog_entry_at(&self.meta, apex)? else {
            return Ok(self.empty_zone_items());
        };
        if !entry.is_live() || entry.tree_root == 0 {
            return Ok(self.empty_zone_items());
        }
        let tree = ZoneTree::new(*apex, entry.tree_root, entry.tree_level)?;
        let mut cursor = tree.btree().cursor(self, txnid);
        let started = cursor.seek_first()?;
        Ok(ZoneItems {
            zonefile: self,
            cursor,
            txnid,
            finished: !started,
        })
    }

    fn empty_zone_items(&self) -> ZoneItems<'_> {
        let cursor = BTree::empty().cursor(self, self.meta.txnid);
        ZoneItems {
            zonefile: self,
            cursor,
            txnid: self.meta.txnid,
            finished: true,
        }
    }

    fn rrset_view_from_value(
        &self,
        txnid: u64,
        value: LeafValue,
        payload: &[u8],
    ) -> Result<RrsetView, ZoneFileError> {
        let rdata = if value.kind == ValueKind::Overflow {
            let chain =
                OverflowRrset::decode(self, txnid, value.val_u32, value.rdlen, value.rr_count)?;
            let mut rdata = Vec::with_capacity(usize::from(value.rr_count));
            for index in 0..value.rr_count {
                let Some(rr) = chain.rr(index)? else {
                    break;
                };
                let mut buf = vec![0_u8; rr.len()];
                let written = rr.copy_into(&mut buf).map_err(|_| {
                    ZoneFileError::corrupt(CorruptKind::BadRdata, None, CorruptDetail::RdataSum)
                })?;
                buf.truncate(written);
                rdata.push(buf);
            }
            rdata
        } else {
            split_inline_payload(payload, value.rr_count)?
        };
        Ok(RrsetView {
            ttl: value.ttl,
            flags: value.flags,
            rdata,
        })
    }

    /// Точный поиск `RRset` в текущей meta.
    ///
    /// # Errors
    ///
    /// `WrongAccessor` для `RRSIG` с `subtype = 0`; `Corrupt`.
    pub fn lookup_rrset(
        &self,
        apex: &NameRle,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
    ) -> Result<Option<RrsetView>, ZoneFileError> {
        self.lookup_rrset_at(self.meta.txnid, apex, name, rr_type, subtype)
    }

    /// Поиск `RRset`, видимый в снапшоте.
    ///
    /// # Errors
    ///
    /// `WrongAccessor`/`Corrupt`.
    pub fn lookup_rrset_at(
        &self,
        txnid: u64,
        apex: &NameRle,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
    ) -> Result<Option<RrsetView>, ZoneFileError> {
        let meta = self.snapshot_meta(txnid);
        let Some(entry) = self.catalog_entry_at(meta, apex)? else {
            return Ok(None);
        };
        if !entry.is_live() || entry.tree_root == 0 {
            return Ok(None);
        }
        let tree = ZoneTree::new(*apex, entry.tree_root, entry.tree_level)?;
        let Some(stored) =
            tree.lookup_cached(self, &self.page_cache, meta.txnid, name, rr_type, subtype)?
        else {
            return Ok(None);
        };
        let DecodedValue::Rrset { value, payload } = stored.value else {
            return Ok(None);
        };
        Ok(Some(
            self.rrset_view_from_value(meta.txnid, value, payload)?,
        ))
    }

    /// Явный `fdatasync` + чекпойнт meta (`sync()`, §13.6).
    ///
    /// Поднимает `durable_watermark` и делает режим липко-`Sync`.
    ///
    /// # Errors
    ///
    /// `ReadOnly`, `MapFull`, `Io`.
    pub fn sync(&mut self) -> Result<u64, ZoneFileError> {
        if self.lock.is_none() || self.write_locked {
            return Err(ZoneFileError::ReadOnly);
        }
        let file = Arc::clone(&self.file);
        sync_fd(&file)?;
        let new_txn = self
            .meta
            .txnid
            .checked_add(1)
            .ok_or(ZoneFileError::IdSpaceExhausted)?;
        let oldest = self.readers.oldest_reader_txn(new_txn);
        let mut meta = self.meta;
        meta.page_no = inactive_meta_page(meta.page_no);
        meta.txnid = new_txn;
        meta.durable_txn = new_txn;
        meta.reclaim_txn = new_txn.saturating_sub(1).min(oldest);
        meta.oldest_reader_txn = oldest;
        meta.commit_unix_ns = now_ns();
        meta.validate(self.superblock.page_count_max)?;
        write_meta_page(&file, &meta, self.superblock.page_size)?;
        crash_point("sync_meta_written");
        sync_fd(&file)?;
        self.meta = meta;
        self.durable_watermark = new_txn;
        self.active.publish(new_txn);
        self.page_cache.clear();
        self.zone_index.invalidate();
        self.push_meta_history(meta);
        Ok(new_txn)
    }

    fn push_meta_history(&mut self, meta: Meta) {
        if self.meta_history.len() >= META_HISTORY_LEN {
            self.meta_history.pop_front();
        }
        self.meta_history.push_back(meta);
    }

    /// Offline `fsck`: достижимость, freelist, лимиты, счётчики.
    ///
    /// # Errors
    ///
    /// `Corrupt` — структурное повреждение графа/страницы.
    pub fn fsck(&self) -> Result<FsckReport, ZoneFileError> {
        crate::fsck::verify(self)
    }

    pub(crate) fn page_count_max(&self) -> u32 {
        self.superblock.page_count_max
    }

    pub(crate) fn map_ref(&self) -> &FileMap {
        &self.map
    }
}

impl PageIo for ZoneFile {
    fn page_size(&self) -> u32 {
        self.superblock.page_size
    }

    fn alloc_page(&mut self) -> Result<u32, ZoneFileError> {
        Err(ZoneFileError::ReadOnly)
    }

    fn read_page(&self, page_no: u32) -> Result<&[u8], ZoneFileError> {
        if page_no < self.superblock.page_data_first || page_no >= self.meta.page_count_high_water {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(page_no),
                CorruptDetail::ChildRange,
            ));
        }
        self.map
            .page(page_no, self.superblock.page_size)
            .ok_or_else(|| {
                ZoneFileError::corrupt(CorruptKind::Bounds, Some(page_no), CorruptDetail::Truncated)
            })
    }

    fn write_page(&mut self, page_no: u32, _page: &[u8]) -> Result<(), ZoneFileError> {
        let _ = page_no;
        Err(ZoneFileError::ReadOnly)
    }

    fn free_page(&mut self, _page_no: u32) -> Result<(), ZoneFileError> {
        Err(ZoneFileError::ReadOnly)
    }
}

/// Открытая writer-транзакция.
#[derive(Debug)]
pub struct ZoneWriter<'a> {
    file: &'a mut ZoneFile,
    pages: Option<TxnPages>,
    catalog: BTree,
    zone_count: u32,
    next_zone_seq: u32,
    total_rrsets: u64,
    total_rrs: u64,
    catalog_changed: bool,
}

impl ZoneWriter<'_> {
    fn pages(&self) -> Result<&TxnPages, ZoneFileError> {
        self.pages.as_ref().ok_or(ZoneFileError::ReadOnly)
    }

    fn pages_mut(&mut self) -> Result<&mut TxnPages, ZoneFileError> {
        self.pages.as_mut().ok_or(ZoneFileError::ReadOnly)
    }

    fn txn(&self) -> Result<u64, ZoneFileError> {
        Ok(self.pages()?.txn())
    }

    fn load_entry(&self, apex: &NameRle) -> Result<Option<ZoneEntry>, ZoneFileError> {
        let pages = self.pages()?;
        let key = ZoneEntryKey::new(apex)?;
        match self.catalog.lookup(pages, pages.txn(), key.key())? {
            Some(entry) => match entry.value {
                DecodedValue::ZoneEntry(bytes) => Ok(Some(ZoneEntry::decode(bytes)?)),
                DecodedValue::Rrset { .. } => Err(ZoneFileError::corrupt(
                    CorruptKind::BadZoneMeta,
                    None,
                    CorruptDetail::ZoneMetaField,
                )),
            },
            None => Ok(None),
        }
    }

    fn store_entry(&mut self, apex: &NameRle, entry: ZoneEntry) -> Result<(), ZoneFileError> {
        let txn = self
            .pages
            .as_ref()
            .map_or(Err(ZoneFileError::ReadOnly), |pages| Ok(pages.txn()))?;
        let key = ZoneEntryKey::new(apex)?;
        let pages = self.pages.as_mut().ok_or(ZoneFileError::ReadOnly)?;
        self.catalog.insert_or_replace(
            pages,
            txn,
            &LeafItem::new(*key.key(), ItemValue::ZoneEntry(entry.encode())),
        )?;
        self.catalog_changed = true;
        Ok(())
    }

    /// Создаёт зону.
    ///
    /// # Errors
    ///
    /// `AlreadyExists` — живая зона уже есть; `IdSpaceExhausted`;
    /// `InvariantViolation` — зарезервированные флаги; `Corrupt`/`Io`.
    pub fn create_zone(&mut self, apex: &NameRle, flags: u16) -> Result<ZoneEntry, ZoneFileError> {
        if flags
            & !(crate::zone_meta::ZONE_FLAG_SECONDARY
                | crate::zone_meta::ZONE_FLAG_FORWARD
                | crate::zone_meta::ZONE_FLAG_DYNAMIC
                | crate::zone_meta::ZONE_FLAG_FROZEN)
            != 0
        {
            return Err(ZoneFileError::InvariantViolation(InvariantId::KeyOrder));
        }
        if self.load_entry(apex)?.is_some_and(ZoneEntry::is_live) {
            return Err(ZoneFileError::AlreadyExists);
        }
        if self.zone_count >= crate::consts::MAX_ZONES {
            return Err(ZoneFileError::ZoneTooLarge);
        }
        let txn = self.txn()?;
        // Повторное создание после tombstone: старое дерево и блок настроек
        // освобождаются в этой транзакции (старая meta их ещё видит, но
        // выданные в этом txn страницы не переиспользуются).
        if let Some(old) = self.load_entry(apex)? {
            free_zone_pages(self.pages_mut()?, txn, &old)?;
        }
        let seq = self.next_zone_seq;
        if seq == u32::MAX {
            return Err(ZoneFileError::IdSpaceExhausted);
        }
        self.next_zone_seq = seq.saturating_add(1);
        let meta_page = self.pages_mut()?.alloc_page()?;
        let block = ZoneMetaBlock {
            txn,
            ..ZoneMetaBlock::default()
        };
        let image = block.encode(meta_page, self.file.superblock.page_size, txn)?;
        self.pages_mut()?.write_page(meta_page, &image)?;
        let mut entry = ZoneEntry::new(seq, meta_page, apex.len(), txn, now_ns());
        entry.flags = flags;
        self.store_entry(apex, entry)?;
        self.zone_count = self.zone_count.saturating_add(1);
        Ok(entry)
    }

    /// Upsert `RRset`'а (`§13.3`).
    ///
    /// # Errors
    ///
    /// `NameOutsideZone`, `RrsetTooLarge`, `WrongAccessor`, `Corrupt`/`Io`.
    pub fn upsert_rrset(
        &mut self,
        apex: &NameRle,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
        data: &RrsetData,
    ) -> Result<UpsertOutcome, ZoneFileError> {
        let mut entry = self.load_entry(apex)?.ok_or_else(|| {
            ZoneFileError::corrupt(CorruptKind::BadZoneMeta, None, CorruptDetail::ZoneMetaField)
        })?;
        if !entry.is_live() {
            return Err(ZoneFileError::ReadOnly);
        }
        let txn = self.txn()?;
        let mut tree = ZoneTree::new(*apex, entry.tree_root, entry.tree_level)?;
        let old_rr_count = {
            let pages = self.pages()?;
            match tree.lookup(pages, txn, name, rr_type, subtype)? {
                Some(stored) => match stored.value {
                    DecodedValue::Rrset { value, .. } => Some(u32::from(value.rr_count)),
                    DecodedValue::ZoneEntry(_) => None,
                },
                None => None,
            }
        };
        let outcome = tree.upsert_rrset(self.pages_mut()?, txn, name, rr_type, subtype, data)?;
        if outcome.changed {
            let new_rr_count = u32::from(data.rr_count()?);
            if let Some(old) = old_rr_count {
                entry.rr_count = entry
                    .rr_count
                    .saturating_sub(old)
                    .saturating_add(new_rr_count);
                self.total_rrs = self
                    .total_rrs
                    .saturating_sub(u64::from(old))
                    .saturating_add(u64::from(new_rr_count));
            } else {
                entry.rrset_count = entry.rrset_count.saturating_add(1);
                entry.rr_count = entry.rr_count.saturating_add(new_rr_count);
                self.total_rrsets = self.total_rrsets.saturating_add(1);
                self.total_rrs = self.total_rrs.saturating_add(u64::from(new_rr_count));
            }
            entry.tree_root = tree.root();
            entry.tree_level = tree.level();
            entry.last_commit_txn = txn;
            entry.last_change_unix_ns = now_ns();
            if entry.state == ZoneState::Initializing && self.zone_is_serving(apex, &tree)? {
                entry.state = ZoneState::Serving;
            }
            self.store_entry(apex, entry)?;
        }
        Ok(outcome)
    }

    fn zone_is_serving(&self, apex: &NameRle, tree: &ZoneTree) -> Result<bool, ZoneFileError> {
        let pages = self.pages()?;
        let txn = pages.txn();
        let has_soa = tree.lookup(pages, txn, apex, 6, 0)?.is_some();
        let has_ns = tree.lookup(pages, txn, apex, 2, 0)?.is_some();
        Ok(has_soa && has_ns)
    }

    /// Удаляет `RRset` и обновляет `T_NODE`/счётчики.
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`.
    pub fn delete_rrset(
        &mut self,
        apex: &NameRle,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
    ) -> Result<bool, ZoneFileError> {
        let Some(mut entry) = self.load_entry(apex)? else {
            return Ok(false);
        };
        if !entry.is_live() {
            return Ok(false);
        }
        let txn = self.txn()?;
        let mut tree = ZoneTree::new(*apex, entry.tree_root, entry.tree_level)?;
        let old_rr_count = {
            let pages = self.pages()?;
            match tree.lookup(pages, txn, name, rr_type, subtype)? {
                Some(stored) => match stored.value {
                    DecodedValue::Rrset { value, .. } => Some(u32::from(value.rr_count)),
                    DecodedValue::ZoneEntry(_) => None,
                },
                None => None,
            }
        };
        if !tree.delete_rrset(self.pages_mut()?, txn, name, rr_type, subtype)? {
            return Ok(false);
        }
        entry.tree_root = tree.root();
        entry.tree_level = tree.level();
        entry.rrset_count = entry.rrset_count.saturating_sub(1);
        if let Some(count) = old_rr_count {
            entry.rr_count = entry.rr_count.saturating_sub(count);
            self.total_rrs = self.total_rrs.saturating_sub(u64::from(count));
        }
        self.total_rrsets = self.total_rrsets.saturating_sub(1);
        entry.last_commit_txn = txn;
        entry.last_change_unix_ns = now_ns();
        self.store_entry(apex, entry)?;
        Ok(true)
    }

    /// Удаляет все `RRset` имени.
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`.
    pub fn delete_name(&mut self, apex: &NameRle, name: &NameRle) -> Result<bool, ZoneFileError> {
        let Some(mut entry) = self.load_entry(apex)? else {
            return Ok(false);
        };
        if !entry.is_live() {
            return Ok(false);
        }
        let txn = self.txn()?;
        let mut tree = ZoneTree::new(*apex, entry.tree_root, entry.tree_level)?;
        let (rrsets, rr_count) = {
            let pages = self.pages()?;
            count_owner(&tree, pages, txn, name)?
        };
        if !tree.delete_name(self.pages_mut()?, txn, name)? {
            return Ok(false);
        }
        entry.tree_root = tree.root();
        entry.tree_level = tree.level();
        entry.rrset_count = entry.rrset_count.saturating_sub(rrsets);
        entry.rr_count = entry.rr_count.saturating_sub(rr_count);
        self.total_rrsets = self.total_rrsets.saturating_sub(u64::from(rrsets));
        self.total_rrs = self.total_rrs.saturating_sub(u64::from(rr_count));
        entry.last_commit_txn = txn;
        entry.last_change_unix_ns = now_ns();
        self.store_entry(apex, entry)?;
        Ok(true)
    }

    /// Удаляет имя со всем поддеревом.
    ///
    /// # Errors
    ///
    /// `InvariantViolation(CutSubtreeTooLarge)`, `Corrupt`/`Io`.
    pub fn delete_subtree(
        &mut self,
        apex: &NameRle,
        name: &NameRle,
    ) -> Result<bool, ZoneFileError> {
        let Some(mut entry) = self.load_entry(apex)? else {
            return Ok(false);
        };
        if !entry.is_live() {
            return Ok(false);
        }
        let txn = self.txn()?;
        let mut tree = ZoneTree::new(*apex, entry.tree_root, entry.tree_level)?;
        let (rrsets, rr_count) = {
            let pages = self.pages()?;
            count_subtree(&tree, pages, txn, name)?
        };
        if !tree.delete_subtree(self.pages_mut()?, txn, name)? {
            return Ok(false);
        }
        entry.tree_root = tree.root();
        entry.tree_level = tree.level();
        entry.rrset_count = entry.rrset_count.saturating_sub(rrsets);
        entry.rr_count = entry.rr_count.saturating_sub(rr_count);
        self.total_rrsets = self.total_rrsets.saturating_sub(u64::from(rrsets));
        self.total_rrs = self.total_rrs.saturating_sub(u64::from(rr_count));
        entry.last_commit_txn = txn;
        entry.last_change_unix_ns = now_ns();
        self.store_entry(apex, entry)?;
        Ok(true)
    }

    /// Tombstone-удаление зоны (§12.3). Страницы не освобождаются.
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`.
    pub fn delete_zone(&mut self, apex: &NameRle) -> Result<bool, ZoneFileError> {
        let Some(mut entry) = self.load_entry(apex)? else {
            return Ok(false);
        };
        if !entry.is_live() {
            return Ok(false);
        }
        let txn = self.txn()?;
        self.total_rrsets = self
            .total_rrsets
            .saturating_sub(u64::from(entry.rrset_count));
        self.total_rrs = self.total_rrs.saturating_sub(u64::from(entry.rr_count));
        entry.state = ZoneState::Tombstone;
        entry.deleted_txn = txn;
        entry.last_commit_txn = txn;
        entry.last_change_unix_ns = now_ns();
        self.store_entry(apex, entry)?;
        self.zone_count = self.zone_count.saturating_sub(1);
        Ok(true)
    }

    /// Перезаписывает дерево зоны в свежие страницы (`compact_zone`).
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`, `MapFull`/`NoSpace`.
    pub fn compact_zone(&mut self, apex: &NameRle) -> Result<bool, ZoneFileError> {
        let Some(mut entry) = self.load_entry(apex)? else {
            return Ok(false);
        };
        if !entry.is_live() {
            return Ok(false);
        }
        let txn = self.txn()?;
        let tree = ZoneTree::new(*apex, entry.tree_root, entry.tree_level)?;
        let items = {
            let pages = self.pages()?;
            tree.collect_items(pages, txn)?
        };
        let old_root = entry.tree_root;
        let old_level = entry.tree_level;
        let new_tree = BTree::bulk_load(self.pages_mut()?, txn, items)?;
        if old_root != 0 {
            // Overflow-цепочки переиспользуются новым деревом: освобождаем
            // только страницы узлов.
            free_tree_pages(
                self.pages_mut()?,
                txn,
                old_root,
                old_level.saturating_sub(1),
                false,
            )?;
        }
        entry.tree_root = new_tree.root();
        entry.tree_level = new_tree.level();
        entry.last_commit_txn = txn;
        entry.last_change_unix_ns = now_ns();
        self.store_entry(apex, entry)?;
        Ok(true)
    }

    fn gc_tombstones(&mut self) -> Result<u64, ZoneFileError> {
        let reclaim = self.pages()?.reclaim_txn();
        if reclaim == 0 {
            return Ok(0);
        }
        let candidates = {
            let pages = self.pages()?;
            let txn = pages.txn();
            let mut cursor = self.catalog.cursor(pages, txn);
            let mut out: Vec<(Key, ZoneEntry)> = Vec::new();
            if !cursor.seek_first()? {
                return Ok(0);
            }
            while let Some(key) = cursor.key()? {
                if key.rr_type() == T_ZONE_ENTRY
                    && let Some(DecodedValue::ZoneEntry(bytes)) = cursor.value()?
                {
                    let entry = ZoneEntry::decode(bytes)?;
                    if entry.state == ZoneState::Tombstone && entry.deleted_txn <= reclaim {
                        out.push((key, entry));
                    }
                }
                if !cursor.advance()? {
                    break;
                }
            }
            out
        };
        let mut pages_freed = 0_u64;
        for (zone_index, (key, entry)) in candidates.into_iter().enumerate() {
            if u32::try_from(zone_index).unwrap_or(u32::MAX) >= MAX_RECLAIM_ZONES_PER_COMMIT
                || pages_freed >= u64::from(MAX_RECLAIM_PAGES_PER_COMMIT)
            {
                break;
            }
            let freed_before = self.pages()?.freed_count();
            let txn = self.txn()?;
            free_zone_pages(
                self.pages.as_mut().ok_or(ZoneFileError::ReadOnly)?,
                txn,
                &entry,
            )?;
            let pages = self.pages.as_mut().ok_or(ZoneFileError::ReadOnly)?;
            let _ = self.catalog.delete(pages, txn, &key)?;
            let freed_after = self.pages()?.freed_count();
            pages_freed = pages_freed.saturating_add(
                u64::try_from(freed_after.saturating_sub(freed_before)).unwrap_or(0),
            );
            self.catalog_changed = true;
        }
        Ok(pages_freed)
    }

    /// Фиксирует транзакцию: страницы → bucket'ы → meta (§13.6).
    ///
    /// # Errors
    ///
    /// `InvariantViolation(DurabilityBelowFileMode)`, `NoSpace`, `MapFull`,
    /// `Io`, `Corrupt`.
    pub fn commit(mut self, mode: SyncMode) -> Result<CommitOutcome, ZoneFileError> {
        self.file.check_commit_mode(mode)?;
        self.gc_tombstones()?;
        let mut pages = self.pages.take().ok_or(ZoneFileError::ReadOnly)?;
        let free = pages.finalize_freelist()?;
        let new_txn = pages.txn();
        let oldest = self.file.readers.oldest_reader_txn(new_txn);
        let durable_watermark = if mode == SyncMode::Sync {
            new_txn
        } else {
            self.file.durable_watermark
        };
        let mut meta = self.file.meta;
        meta.page_no = inactive_meta_page(meta.page_no);
        meta.txnid = new_txn;
        meta.durable_txn = durable_watermark;
        meta.page_count_high_water = pages.high_water();
        meta.free_page_count = free.entries;
        meta.freelist_head = free.head;
        meta.freelist_tail = free.tail;
        meta.freelist_buckets = free.buckets;
        meta.freelist_entries = free.entries;
        meta.zone_dir_root = self.catalog.root();
        meta.zone_dir_level = self.catalog.level();
        meta.zone_count = self.zone_count;
        meta.next_zone_seq = self.next_zone_seq;
        meta.total_rrsets = self.total_rrsets;
        meta.total_rrs = self.total_rrs;
        meta.commit_unix_ns = now_ns();
        meta.reclaim_txn = durable_watermark.saturating_sub(1).min(oldest);
        meta.oldest_reader_txn = oldest;
        meta.validate(self.file.superblock.page_count_max)?;

        let stats = write_transaction(
            self.file.file.as_ref(),
            pages.dirty_pages(),
            &meta,
            self.file.superblock.page_size,
            mode,
        )?;
        crash_point("commit_published");
        self.file.meta = meta;
        self.file.durable_watermark = durable_watermark;
        self.file.active.publish(new_txn);
        self.file.page_cache.clear();
        self.file.zone_index.invalidate();
        self.file.push_meta_history(meta);
        Ok(CommitOutcome {
            txnid: new_txn,
            durable: mode == SyncMode::Sync,
            pages_written: stats,
            freed_pages: u64::from(free.entries),
            bucket_pages: free.buckets,
            sync_mode: mode,
        })
    }
}

fn count_owner<P: PageIo + ?Sized>(
    tree: &ZoneTree,
    io: &P,
    txn: u64,
    name: &NameRle,
) -> Result<(u32, u32), ZoneFileError> {
    let mut cursor = tree.btree().cursor(io, txn);
    let start = Key::new(name, 0, 0, 0)?;
    if !cursor.seek(&start)? {
        return Ok((0, 0));
    }
    let mut rrsets = 0_u32;
    let mut rr_count = 0_u32;
    while let Some(key) = cursor.key()? {
        if key.owner_bytes() != name.as_rle() {
            break;
        }
        if key.rr_type() != 0 && key.rr_type() != T_ZONE_ENTRY {
            rrsets = rrsets.saturating_add(1);
            if let Some(DecodedValue::Rrset { value, .. }) = cursor.value()? {
                rr_count = rr_count.saturating_add(u32::from(value.rr_count));
            }
        }
        if !cursor.advance()? {
            break;
        }
    }
    Ok((rrsets, rr_count))
}

fn count_subtree<P: PageIo + ?Sized>(
    tree: &ZoneTree,
    io: &P,
    txn: u64,
    name: &NameRle,
) -> Result<(u32, u32), ZoneFileError> {
    let mut cursor = tree.btree().cursor(io, txn);
    let start = Key::new(name, 0, 0, 0)?;
    if !cursor.seek(&start)? {
        return Ok((0, 0));
    }
    let mut rrsets = 0_u32;
    let mut rr_count = 0_u32;
    while let Some(key) = cursor.key()? {
        let owner = key.owner()?;
        if owner != *name && !crate::tree::is_descendant(&owner, name) {
            break;
        }
        if key.rr_type() != 0 && key.rr_type() != T_ZONE_ENTRY {
            rrsets = rrsets.saturating_add(1);
            if let Some(DecodedValue::Rrset { value, .. }) = cursor.value()? {
                rr_count = rr_count.saturating_add(u32::from(value.rr_count));
            }
        }
        if !cursor.advance()? {
            break;
        }
    }
    Ok((rrsets, rr_count))
}

fn split_inline_payload(payload: &[u8], rr_count: u16) -> Result<Vec<Vec<u8>>, ZoneFileError> {
    let mut out = Vec::with_capacity(usize::from(rr_count));
    let mut offset = 0_usize;
    for _ in 0..rr_count {
        let length = usize::from(wire::read_u16_be(payload, offset).ok_or_else(|| {
            ZoneFileError::corrupt(CorruptKind::BadRdata, None, CorruptDetail::RdataSum)
        })?);
        offset = offset.checked_add(2).ok_or_else(|| {
            ZoneFileError::corrupt(CorruptKind::BadRdata, None, CorruptDetail::RdataSum)
        })?;
        let end = offset
            .checked_add(length)
            .filter(|&end| end <= payload.len())
            .ok_or_else(|| {
                ZoneFileError::corrupt(CorruptKind::BadRdata, None, CorruptDetail::RdataSum)
            })?;
        out.push(
            payload
                .get(offset..end)
                .ok_or_else(|| {
                    ZoneFileError::corrupt(CorruptKind::BadRdata, None, CorruptDetail::RdataSum)
                })?
                .to_vec(),
        );
        offset = end;
    }
    Ok(out)
}

fn free_tree_pages<P: PageIo + ?Sized>(
    io: &mut P,
    txn: u64,
    page_no: u32,
    level: u16,
    free_overflow: bool,
) -> Result<u64, ZoneFileError> {
    if page_no == 0 {
        return Ok(0);
    }
    let page_size = io.page_size();
    let mut freed = 0_u64;
    if level == 0 {
        let mut chains = Vec::new();
        {
            let page = io.read_page(page_no)?;
            let leaf = DecodedLeaf::decode(page, page_no, txn, page_size)?;
            for index in 0..leaf.len() {
                if let Some(value) = leaf.leaf_value(index)?
                    && value.kind == ValueKind::Overflow
                    && value.val_u32 != 0
                {
                    chains.push(value.val_u32);
                }
            }
        }
        if free_overflow {
            for chain in chains {
                overflow::free_chain(io, chain)?;
                freed = freed.saturating_add(1);
            }
        }
        io.free_page(page_no)?;
        return Ok(freed.saturating_add(1));
    }
    let children = {
        let page = io.read_page(page_no)?;
        let branch = DecodedBranch::decode(page, page_no, txn, page_size)?;
        if branch.level() != level {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(page_no),
                CorruptDetail::PageType,
            ));
        }
        let mut children = Vec::with_capacity(branch.len());
        for index in 0..branch.len() {
            children.push(branch.child(index)?);
        }
        children
    };
    for child in children {
        freed = freed.saturating_add(free_tree_pages(io, txn, child, level - 1, free_overflow)?);
    }
    io.free_page(page_no)?;
    Ok(freed.saturating_add(1))
}

fn free_zone_pages<P: PageIo + ?Sized>(
    io: &mut P,
    txn: u64,
    entry: &ZoneEntry,
) -> Result<(), ZoneFileError> {
    if entry.tree_root != 0 {
        free_tree_pages(
            io,
            txn,
            entry.tree_root,
            entry.tree_level.saturating_sub(1),
            true,
        )?;
    }
    if entry.meta_root != 0 {
        // v1 не использует overflow-цепочку блока настроек.
        io.free_page(entry.meta_root)?;
    }
    Ok(())
}

fn inactive_meta_page(current: u32) -> u32 {
    if current == PAGE_META_A {
        PAGE_META_B
    } else {
        PAGE_META_A
    }
}

fn now_ns() -> u64 {
    crate::recovery::now_unix_ns()
}

fn sync_fd(file: &File) -> Result<(), ZoneFileError> {
    loop {
        match fdatasync(file) {
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => return Err(ZoneFileError::Io(std::io::Error::from(error))),
            Ok(()) => return Ok(()),
        }
    }
}

fn write_meta_page(file: &File, meta: &Meta, page_size: u32) -> Result<(), ZoneFileError> {
    let offset = u64::from(meta.page_no) * u64::from(page_size);
    let image = meta.encode();
    write_page_at(file, offset, &image)
}

fn write_page_at(file: &File, offset: u64, bytes: &[u8]) -> Result<(), ZoneFileError> {
    file.write_all_at(bytes, offset).map_err(ZoneFileError::Io)
}

fn write_transaction(
    file: &File,
    dirty: &BTreeMap<u32, Vec<u8>>,
    meta: &Meta,
    page_size: u32,
    mode: SyncMode,
) -> Result<u32, ZoneFileError> {
    let mut written = 0_u32;
    for (page_no, page) in dirty {
        let offset = u64::from(*page_no) * u64::from(page_size);
        write_page_at(file, offset, page)?;
        written = written.saturating_add(1);
        if written == 1 {
            crash_point("commit_data_mid");
        }
    }
    crash_point("commit_data_written");
    if mode != SyncMode::NoSync {
        sync_fd(file)?;
        crash_point("commit_data_synced");
    }
    crash_point("commit_before_meta");
    if crash_phase() == Some("torn_meta") {
        let offset = u64::from(meta.page_no) * u64::from(page_size);
        let image = meta.encode();
        let half = image.len() / 2;
        if let Some(part) = image.get(..half) {
            write_page_at(file, offset, part)?;
        }
        crash_now();
    }
    write_meta_page(file, meta, page_size)?;
    crash_point("commit_meta_written");
    if mode == SyncMode::Sync {
        sync_fd(file)?;
        crash_point("commit_meta_synced");
    }
    Ok(written)
}

#[cfg(test)]
fn crash_phase() -> Option<&'static str> {
    // Значение читается один раз; тестовый harness передаёт его дочернему
    // процессу через окружение.
    static PHASE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    PHASE
        .get_or_init(|| std::env::var("PULSE_ZF_CRASH_PHASE").ok())
        .as_deref()
}

#[cfg(not(test))]
fn crash_phase() -> Option<&'static str> {
    None
}

fn crash_point(phase: &str) {
    if crash_phase() == Some(phase) {
        crash_now();
    }
}

fn crash_now() {
    #[cfg(test)]
    {
        let _ =
            rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::KILL);
    }
    std::process::abort();
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
