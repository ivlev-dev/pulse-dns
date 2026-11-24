//! B+tree-зоны v2 поверх [`ParallelStore`]: writer, commit и read snapshots.
//!
//! Слой B1 (`docs/spec/parallel-writes-v2.md` §4.5, §5.1–5.3) переиспользует
//! v1-дерево ([`crate::tree::ZoneTree`]) через v2-страничный I/O
//! (внутренний `pageio`):
//!
//! * [`ParallelZones`] — минимальный каталог `origin → zone_seq`. Каталог
//!   хранится B+tree в слоте `0` root directory под `RootEntry.owner_zone = 0`
//!   (флаг [`RootFlags::CATALOG`]); ключ — `RLE(origin) || T_ZONE_ENTRY`, значение
//!   — 72 Б `{ magic, zone_seq, soa_serial, origin_len, created_txn }`.
//! * [`ParallelZone`] — writer одной зоны: lease зоны удерживается всё время
//!   жизни, правки идут в COW-страницы в памяти, [`ParallelZone::commit`]
//!   пишет их пачкой и публикует `RootEntry` (два `fdatasync` внутри
//!   [`ParallelStore::publish_root`]).
//! * [`ZoneReader`] — read snapshot: [`crate::parallel::ZoneSnapshot`] держит
//!   пин, дерево читается по версии головы; writer его не блокирует.
//!
//! `Durability::Sync` — единственный режим B1; `Flush`/`Memory` возвращают
//! [`ParallelError::Unsupported`] (B2).

use std::collections::HashMap;
use std::sync::MutexGuard;

use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::key::{Key, NameRle, T_ZONE_ENTRY};
use crate::node::{DecodedValue, ItemValue, LeafItem, LeafValue, ValueKind};
use crate::parallel::error::ParallelError;
use crate::parallel::layout::SyncModeV2;
use crate::parallel::pageio::{ReaderIo, WriteIo};
use crate::parallel::pins::Reader;
use crate::parallel::root::{RootEntry, RootFlags, RootState};
use crate::parallel::store::{ParallelStore, ZoneSnapshot};
use crate::tree::{BTree, NodeInfo, PageIo, RrsetData, UpsertOutcome, ZoneTree};
use crate::wire;

/// Сколько раз коммит повторяет публикацию при `ReaderContended` (retryable:
/// между планом и фазой 2 появился пин). Данные и `ALLOC_RECORD` уже durable,
/// повторяется только запись корня/chain.
const PUBLISH_RETRIES: u32 = 64;

/// Значение каталога (72 Б, как `ZoneEntry` v1, но собственная раскладка B1).
const CATALOG_VALUE_BYTES: usize = 72;
const CATALOG_MAGIC: [u8; 4] = *b"ZC01";
const CATALOG_OFF_MAGIC: usize = 0;
const CATALOG_OFF_SEQ: usize = 4;
const CATALOG_OFF_SERIAL: usize = 8;
const CATALOG_OFF_ORIGIN_LEN: usize = 12;
const CATALOG_OFF_CREATED_TXN: usize = 16;

/// Метаданные создания зоны (B1: только SOA serial; блок `ZoneMeta` — B2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZoneCreateMeta {
    /// SOA serial зоны (RFC 1982, ≤ `0x7FFF_FFFF`).
    pub soa_serial: u32,
}

/// Информация о зоне из каталога и головы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneInfo {
    /// Origin зоны.
    pub origin: NameRle,
    /// `zone_seq` (слот в root directory).
    pub zone_seq: u32,
    /// Опубликованная версия (`txn`).
    pub version: u64,
    /// SOA serial.
    pub soa_serial: u32,
    /// Число `RRset` без `T_NODE`.
    pub rrset_count: u32,
    /// Состояние зоны.
    pub state: RootState,
    /// Корень B+tree (`0` — пусто).
    pub root_page: u32,
    /// Уровень корня.
    pub tree_level: u16,
}

/// Итог коммита зоны.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOutcome {
    /// Зона.
    pub zone: u32,
    /// Опубликованная версия (`txn`); для пустого коммита — текущая.
    pub version: u64,
    /// Корень дерева.
    pub root_page: u32,
    /// Уровень корня.
    pub tree_level: u16,
    /// Число `RRset` без `T_NODE`.
    pub rrset_count: u32,
    /// Сколько страниц реально записано в этом коммите.
    pub dirty_pages: u32,
    /// Durable `page_limit` после фазы 1.
    pub page_limit: u32,
    /// Коммит изменил зону.
    pub changed: bool,
}

/// Материализованный `RRset` (владеющая копия, включая overflow).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsetRecord {
    /// Владелец.
    pub name: NameRle,
    /// Тип RR.
    pub rr_type: u16,
    /// Подтип (`RRSIG` — type covered).
    pub subtype: u16,
    /// TTL.
    pub ttl: u32,
    /// Флаги `RR_FLAG_*`.
    pub flags: u16,
    /// RDATA всех RR в каноническом порядке.
    pub rdata: Vec<Vec<u8>>,
}

/// Zero-copy `RRset` из inline-значения (см. [`ZoneReader::lookup_ref`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrsetRef<'a> {
    /// Владелец.
    pub name: NameRle,
    /// Тип RR.
    pub rr_type: u16,
    /// Подтип.
    pub subtype: u16,
    /// TTL.
    pub ttl: u32,
    /// Флаги.
    pub flags: u16,
    /// `LeafValue` (для `OVERFLOW` payload пуст, `val_u32` — цепочка).
    pub value: LeafValue,
    /// Встроенный payload (`kind == INLINE`).
    pub payload: &'a [u8],
}

/// Значение каталога.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CatalogValue {
    zone_seq: u32,
    soa_serial: u32,
    origin_len: u32,
    created_txn: u64,
}

impl CatalogValue {
    fn encode(self) -> [u8; CATALOG_VALUE_BYTES] {
        let mut raw = [0_u8; CATALOG_VALUE_BYTES];
        let _ = wire::write_bytes(&mut raw, CATALOG_OFF_MAGIC, &CATALOG_MAGIC);
        let _ = wire::write_u32(&mut raw, CATALOG_OFF_SEQ, self.zone_seq);
        let _ = wire::write_u32(&mut raw, CATALOG_OFF_SERIAL, self.soa_serial);
        let _ = wire::write_u32(&mut raw, CATALOG_OFF_ORIGIN_LEN, self.origin_len);
        let _ = wire::write_u64(&mut raw, CATALOG_OFF_CREATED_TXN, self.created_txn);
        raw
    }

    fn decode(raw: &[u8], origin: &NameRle) -> Option<Self> {
        let magic: [u8; 4] = raw.get(..4)?.try_into().ok()?;
        if magic != CATALOG_MAGIC {
            return None;
        }
        let value = Self {
            zone_seq: wire::read_u32(raw, CATALOG_OFF_SEQ)?,
            soa_serial: wire::read_u32(raw, CATALOG_OFF_SERIAL)?,
            origin_len: wire::read_u32(raw, CATALOG_OFF_ORIGIN_LEN)?,
            created_txn: wire::read_u64(raw, CATALOG_OFF_CREATED_TXN)?,
        };
        if value.zone_seq == 0
            || value.soa_serial > 0x7FFF_FFFF
            || usize::try_from(value.origin_len).ok()? != origin.as_rle().len()
        {
            return None;
        }
        Some(value)
    }
}

fn tree_error(io: &ReaderIo<'_>, error: ZoneFileError) -> ParallelError {
    io.take_error().unwrap_or(ParallelError::Tree(error))
}

fn writer_error(io: &WriteIo<'_>, error: ZoneFileError) -> ParallelError {
    io.take_error().unwrap_or(ParallelError::Tree(error))
}

/// Каталог зон: `origin → zone_seq` (B+tree в слоте `0`).
#[derive(Debug, Clone)]
pub struct ParallelZones<'a> {
    store: &'a ParallelStore,
    tree: BTree,
    version: u64,
    next_seq: u32,
    entries: HashMap<NameRle, CatalogValue>,
    origins: HashMap<u32, NameRle>,
}

impl<'a> ParallelZones<'a> {
    /// Загружает каталог из головы `owner_zone = 0` (пустой стор — пустой).
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io` — каталог не читается; `Tree` — повреждён B+tree.
    #[allow(clippy::too_many_lines)]
    pub fn open(store: &'a ParallelStore) -> Result<Self, ParallelError> {
        let mut zones = Self {
            store,
            tree: BTree::empty(),
            version: 0,
            next_seq: 1,
            entries: HashMap::new(),
            origins: HashMap::new(),
        };
        let Some(head) = store.catalog_head() else {
            return Ok(zones);
        };
        zones.version = head.version;
        zones.tree = BTree::new(head.root_page, head.tree_level)?;
        if zones.tree.is_empty() {
            return Ok(zones);
        }
        let io = ReaderIo::new(store, 0, head.version);
        let mut cursor = zones.tree.cursor(&io, head.version);
        let found = cursor
            .seek_first()
            .map_err(|error| tree_error(&io, error))?;
        if !found {
            return Ok(zones);
        }
        while let Some(item) = cursor.item().map_err(|error| tree_error(&io, error))? {
            if let ItemValue::ZoneEntry(raw) = item.value {
                let origin = item.key.owner().map_err(|error| tree_error(&io, error))?;
                let value = CatalogValue::decode(&raw, &origin).ok_or(ParallelError::Corrupt {
                    kind: crate::parallel::error::V2CorruptKind::RootEntry,
                    page: None,
                })?;
                zones.next_seq = zones.next_seq.max(value.zone_seq.saturating_add(1));
                zones.origins.insert(value.zone_seq, origin);
                zones.entries.insert(origin, value);
            }
            if !cursor.advance().map_err(|error| tree_error(&io, error))? {
                break;
            }
        }
        Ok(zones)
    }

    /// Стор.
    #[must_use]
    pub const fn store(&self) -> &'a ParallelStore {
        self.store
    }

    /// Версия каталога (0 — каталог пуст).
    #[must_use]
    pub const fn catalog_version(&self) -> u64 {
        self.version
    }

    /// `zone_seq` по origin (включая tombstone).
    #[must_use]
    pub fn zone_seq(&self, origin: &NameRle) -> Option<u32> {
        self.entries.get(origin).map(|value| value.zone_seq)
    }

    /// Origin по `zone_seq`.
    #[must_use]
    pub fn origin(&self, zone: u32) -> Option<NameRle> {
        self.origins.get(&zone).copied()
    }

    /// Живые зоны (голова есть, не tombstone).
    #[must_use]
    pub fn zones(&self) -> Vec<ZoneInfo> {
        let mut zones = Vec::with_capacity(self.entries.len());
        for (origin, value) in &self.entries {
            let Some(head) = self.store.head_entry(value.zone_seq) else {
                continue;
            };
            if head.is_tombstone() {
                continue;
            }
            zones.push(ZoneInfo {
                origin: *origin,
                zone_seq: value.zone_seq,
                version: head.version,
                soa_serial: head.soa_serial,
                rrset_count: head.rrset_count,
                state: head.state,
                root_page: head.root_page,
                tree_level: head.tree_level,
            });
        }
        zones
    }

    /// Создаёт зону: `RootEntry` зоны (пустое дерево), затем запись каталога.
    ///
    /// Порядок: сначала durable-голова зоны, затем каталог. Крах между ними
    /// оставляет недостижимую зону (PW-L7), но не порчу; повторный
    /// `create_zone` выдаст новый `zone_seq`.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — origin уже в каталоге/слоты кончились;
    /// `Unsupported` — SOA serial вне диапазона; `Io`/`MapFull` — запись.
    #[allow(clippy::too_many_lines)]
    pub fn create_zone(
        &mut self,
        origin: &NameRle,
        meta: ZoneCreateMeta,
    ) -> Result<u32, ParallelError> {
        if self.entries.contains_key(origin) {
            return Err(ParallelError::InvalidArgument { field: "origin" });
        }
        if meta.soa_serial > 0x7FFF_FFFF {
            return Err(ParallelError::Unsupported {
                what: "soa_serial (max 0x7fff_ffff)",
            });
        }
        let max_zones = self.store.geometry().max_zones();
        let mut zone_seq = self.next_seq;
        // Пропускаем «осиротевшие» головы от краха между коммитом зоны и
        // каталогом (PW-L7): слот занят, но в каталоге его нет.
        while zone_seq < max_zones && self.store.head_entry(zone_seq).is_some() {
            zone_seq = zone_seq.saturating_add(1);
        }
        if zone_seq >= max_zones {
            return Err(ParallelError::InvalidArgument { field: "max_zones" });
        }
        self.next_seq = zone_seq.saturating_add(1);
        let mut zone = ParallelZone::open_new(self.store, *origin, zone_seq, meta.soa_serial)?;
        let outcome = zone.commit()?;
        let value = CatalogValue {
            zone_seq,
            soa_serial: meta.soa_serial,
            origin_len: u32::try_from(origin.as_rle().len()).unwrap_or(u32::MAX),
            created_txn: outcome.version,
        };
        self.write_catalog_entry(origin, value, true)?;
        self.origins.insert(zone_seq, *origin);
        self.entries.insert(*origin, value);
        Ok(zone_seq)
    }

    /// Помечает зону tombstone (`delete_zone`), каталог не меняется.
    ///
    /// # Errors
    ///
    /// `NoZoneVersion` — зоны нет; `Busy`/`Io` — lease/запись.
    pub fn delete_zone(&mut self, origin: &NameRle) -> Result<CommitOutcome, ParallelError> {
        let mut zone = self.writer(origin)?;
        zone.commit_tombstone()
    }

    /// Открывает writer зоны по origin (lease удерживается до `Drop`).
    ///
    /// # Errors
    ///
    /// `NoZoneVersion` — зоны нет/tombstone; `Corrupt`/`Io` — голова/дерево.
    pub fn writer(&self, origin: &NameRle) -> Result<ParallelZone<'a>, ParallelError> {
        let zone = self
            .zone_seq(origin)
            .ok_or(ParallelError::InvalidArgument { field: "origin" })?;
        self.writer_by_seq(zone)
    }

    /// Открывает writer по `zone_seq` (origin берётся из каталога).
    ///
    /// # Errors
    ///
    /// `NoZoneVersion` — зоны/каталога нет; `Corrupt`/`Io`.
    pub fn writer_by_seq(&self, zone: u32) -> Result<ParallelZone<'a>, ParallelError> {
        let origin = self
            .origin(zone)
            .ok_or(ParallelError::NoZoneVersion { zone })?;
        ParallelZone::open(self.store, origin, zone)
    }

    /// Открывает read snapshot зоны (пин + версия головы).
    ///
    /// # Errors
    ///
    /// `NoZoneVersion`, `ZoneDegraded`, `ReaderContended`, `Corrupt`.
    pub fn read<'r>(
        &'r self,
        reader: &'r Reader<'r>,
        origin: &NameRle,
    ) -> Result<ZoneReader<'r>, ParallelError>
    where
        'a: 'r,
    {
        let zone = self
            .zone_seq(origin)
            .ok_or(ParallelError::InvalidArgument { field: "origin" })?;
        let snapshot = self.store.zone_snapshot(reader, zone)?;
        let root = *snapshot.root();
        let tree = ZoneTree::new(*origin, root.root_page, root.tree_level)?;
        let io = ReaderIo::new(self.store, zone, snapshot.version());
        Ok(ZoneReader {
            snapshot,
            tree,
            io,
            origin: *origin,
        })
    }

    fn write_catalog_entry(
        &mut self,
        origin: &NameRle,
        value: CatalogValue,
        inserted: bool,
    ) -> Result<(), ParallelError> {
        let _lease = self.store.lease_guard(0);
        let mut io = WriteIo::new(self.store, 0, self.version);
        io.clear_cache();
        let txn = io.next_txn()?;
        io.set_version(txn);
        let key = Key::new(origin, T_ZONE_ENTRY, 0, 0)?;
        let raw = value.encode();
        let item = LeafItem::new(key, ItemValue::zone_entry(&raw)?);
        let old_root = self.tree.root();
        let old_level = self.tree.level();
        if let Err(error) = self.tree.insert_or_replace(&mut io, txn, &item) {
            self.tree = BTree::new(old_root, old_level)?;
            return Err(writer_error(&io, error));
        }
        let dirty = io.take_dirty();
        for (page, bytes) in dirty {
            if let Err(error) = self.store.write_raw_page(page, &bytes) {
                self.tree = BTree::new(old_root, old_level)?;
                io.clear();
                return Err(error);
            }
        }
        let entries = self.entries.len();
        let rrset_count = if inserted {
            u32::try_from(entries.saturating_add(1)).unwrap_or(u32::MAX)
        } else {
            u32::try_from(entries).unwrap_or(u32::MAX)
        };
        let entry = RootEntry {
            owner_zone: 0,
            version: txn,
            root_page: self.tree.root(),
            tree_level: self.tree.level(),
            rrset_count,
            state: RootState::Serving,
            flags: RootFlags::CATALOG,
            ..RootEntry::default()
        };
        let mut attempt = 0_u32;
        loop {
            match self.store.publish_root_locked(entry) {
                Ok(_) => {
                    self.version = txn;
                    io.clear_cache();
                    return Ok(());
                }
                Err(ParallelError::ReaderContended) if attempt < PUBLISH_RETRIES => {
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => {
                    self.tree = BTree::new(old_root, old_level)?;
                    io.clear();
                    return Err(error);
                }
            }
        }
    }
}

/// Writer одной зоны; lease удерживается на всё время жизни.
///
/// `!Send`: `MutexGuard` и `AllocHandle` принадлежат потоку, открывшему
/// writer. Разные зоны (и разные потоки) пишутся параллельно.
pub struct ParallelZone<'a> {
    store: &'a ParallelStore,
    origin: NameRle,
    zone: u32,
    tree: ZoneTree,
    io: WriteIo<'a>,
    _lease: MutexGuard<'a, ()>,
    base_version: u64,
    txn: Option<u64>,
    rrset_count: u32,
    soa_serial: u32,
}

impl std::fmt::Debug for ParallelZone<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParallelZone")
            .field("origin", &self.origin)
            .field("zone", &self.zone)
            .field("version", &self.base_version)
            .field("rrset_count", &self.rrset_count)
            .finish_non_exhaustive()
    }
}

impl<'a> ParallelZone<'a> {
    fn open(store: &'a ParallelStore, origin: NameRle, zone: u32) -> Result<Self, ParallelError> {
        let lease = store.lease_guard(zone);
        let head = store
            .head_entry(zone)
            .ok_or(ParallelError::NoZoneVersion { zone })?;
        if head.is_tombstone() {
            return Err(ParallelError::NoZoneVersion { zone });
        }
        let tree = ZoneTree::new(origin, head.root_page, head.tree_level)?;
        let io = WriteIo::new(store, zone, head.version);
        Ok(Self {
            store,
            origin,
            zone,
            tree,
            io,
            _lease: lease,
            base_version: head.version,
            txn: None,
            rrset_count: head.rrset_count,
            soa_serial: head.soa_serial,
        })
    }

    fn open_new(
        store: &'a ParallelStore,
        origin: NameRle,
        zone: u32,
        soa_serial: u32,
    ) -> Result<Self, ParallelError> {
        let lease = store.lease_guard(zone);
        if store.head_entry(zone).is_some() {
            return Err(ParallelError::InvalidArgument { field: "zone_seq" });
        }
        let tree = ZoneTree::empty(origin);
        let io = WriteIo::new(store, zone, 0);
        Ok(Self {
            store,
            origin,
            zone,
            tree,
            io,
            _lease: lease,
            base_version: 0,
            txn: None,
            rrset_count: 0,
            soa_serial,
        })
    }

    /// Origin зоны.
    #[must_use]
    pub const fn origin(&self) -> &NameRle {
        &self.origin
    }

    /// `zone_seq`.
    #[must_use]
    pub const fn zone(&self) -> u32 {
        self.zone
    }

    /// Последняя опубликованная версия (до незакоммиченных правок).
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.base_version
    }

    /// `txn` незакоммиченной транзакции (если есть правки).
    #[must_use]
    pub const fn pending_txn(&self) -> Option<u64> {
        self.txn
    }

    /// Текущее число `RRset` (с учётом незакоммиченных правок).
    #[must_use]
    pub const fn rrset_count(&self) -> u32 {
        self.rrset_count
    }

    /// SOA serial зоны.
    #[must_use]
    pub const fn soa_serial(&self) -> u32 {
        self.soa_serial
    }

    /// Страниц в незакоммиченном dirty-наборе.
    #[must_use]
    pub fn dirty_pages(&self) -> usize {
        self.io.dirty_pages()
    }

    /// Страниц, прочитанных/закэшированных writer'ом.
    #[must_use]
    pub fn cached_pages(&self) -> usize {
        self.io.cached_pages()
    }

    fn ensure_txn(&mut self) -> Result<u64, ParallelError> {
        if let Some(txn) = self.txn {
            return Ok(txn);
        }
        let txn = self.io.next_txn()?;
        self.io.set_version(txn);
        self.txn = Some(txn);
        Ok(txn)
    }

    fn version_for_reads(&self) -> u64 {
        self.txn.unwrap_or(self.base_version)
    }

    fn rollback(&mut self) {
        if let Some(head) = self.store.head_entry(self.zone)
            && !head.is_tombstone()
            && let Ok(tree) = ZoneTree::new(self.origin, head.root_page, head.tree_level)
        {
            self.tree = tree;
            self.rrset_count = head.rrset_count;
            self.soa_serial = head.soa_serial;
            self.base_version = head.version;
            self.io.set_version(head.version);
        }
        self.txn = None;
        self.io.clear();
    }

    /// Upsert `RRset` (COW; `T_NODE`/ENT материализуются деревом v1).
    ///
    /// # Errors
    ///
    /// `Tree`/`Corrupt` — ключ/дерево; `MapFull` — страницы; `Io`.
    pub fn upsert_rrset(
        &mut self,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
        data: &RrsetData,
    ) -> Result<UpsertOutcome, ParallelError> {
        self.ensure_txn()?;
        let txn = self.txn.unwrap_or(self.base_version);
        match self
            .tree
            .upsert_rrset(&mut self.io, txn, name, rr_type, subtype, data)
        {
            Ok(outcome) => {
                if outcome.inserted {
                    self.rrset_count = self.rrset_count.saturating_add(1);
                }
                Ok(outcome)
            }
            Err(error) => {
                let error = writer_error(&self.io, error);
                self.rollback();
                Err(error)
            }
        }
    }

    /// Удаляет один `RRset`.
    ///
    /// # Errors
    ///
    /// `Tree`/`Corrupt`/`Io`.
    pub fn delete_rrset(
        &mut self,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
    ) -> Result<bool, ParallelError> {
        self.ensure_txn()?;
        let txn = self.txn.unwrap_or(self.base_version);
        match self
            .tree
            .delete_rrset(&mut self.io, txn, name, rr_type, subtype)
        {
            Ok(true) => {
                self.rrset_count = self.rrset_count.saturating_sub(1);
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(error) => {
                let error = writer_error(&self.io, error);
                self.rollback();
                Err(error)
            }
        }
    }

    /// Удаляет все `RRset` имени (не поддерево).
    ///
    /// # Errors
    ///
    /// `Tree`/`Corrupt`/`Io`.
    pub fn delete_name(&mut self, name: &NameRle) -> Result<bool, ParallelError> {
        self.ensure_txn()?;
        let txn = self.txn.unwrap_or(self.base_version);
        let removed = match self.tree.owner_rrset_count(&self.io, txn, name) {
            Ok(count) => count,
            Err(error) => {
                let error = writer_error(&self.io, error);
                self.rollback();
                return Err(error);
            }
        };
        match self.tree.delete_name(&mut self.io, txn, name) {
            Ok(true) => {
                self.rrset_count = self.rrset_count.saturating_sub(removed);
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(error) => {
                let error = writer_error(&self.io, error);
                self.rollback();
                Err(error)
            }
        }
    }

    /// Точный `lookup` в незакоммиченном дереве (read-your-writes).
    ///
    /// # Errors
    ///
    /// `Tree`/`Corrupt`/`Io`.
    pub fn lookup(
        &self,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
    ) -> Result<Option<RrsetRecord>, ParallelError> {
        let version = self.version_for_reads();
        let entry = self
            .tree
            .lookup(&self.io, version, name, rr_type, subtype)
            .map_err(|error| writer_error(&self.io, error))?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        record_from_value(&self.tree, &self.io, version, &entry.key, entry.value)
            .map_err(|error| self.io.take_error().unwrap_or(error))
    }

    /// Состояние имени (`T_NODE`, ENT/cut, флаги).
    ///
    /// # Errors
    ///
    /// `Tree`/`Corrupt`/`Io`.
    pub fn node(&self, name: &NameRle) -> Result<NodeInfo, ParallelError> {
        let version = self.version_for_reads();
        self.tree
            .node(&self.io, version, name)
            .map_err(|error| writer_error(&self.io, error))
    }

    /// Все `RRset` дерева (в каноническом порядке ключей).
    ///
    /// # Errors
    ///
    /// `Tree`/`Corrupt`/`Io`.
    pub fn records(&self) -> Result<Vec<RrsetRecord>, ParallelError> {
        let version = self.version_for_reads();
        collect_records(&self.tree, &self.io, version)
            .map_err(|error| self.io.take_error().unwrap_or(error))
    }

    /// Коммит в режиме `Durability::Sync`.
    ///
    /// # Errors
    ///
    /// `Unsupported` — не `Sync`; `Io`/`MapFull`/`ReaderContended`.
    pub fn commit(&mut self) -> Result<CommitOutcome, ParallelError> {
        self.commit_with(SyncModeV2::Sync)
    }

    /// Коммит с явным режимом durability (`Flush`/`Memory` — B2).
    ///
    /// # Errors
    ///
    /// `Unsupported` — не `Sync`; `Io`/`MapFull`/`ReaderContended`.
    #[allow(clippy::too_many_lines)]
    pub fn commit_with(&mut self, durability: SyncModeV2) -> Result<CommitOutcome, ParallelError> {
        if durability != SyncModeV2::Sync {
            return Err(ParallelError::Unsupported {
                what: "durability mode (phase B1 implements Sync only)",
            });
        }
        let txn = match self.txn {
            Some(txn) => txn,
            None if self.base_version == 0 => self.ensure_txn()?,
            None => {
                return Ok(CommitOutcome {
                    zone: self.zone,
                    version: self.base_version,
                    root_page: self.tree.root(),
                    tree_level: self.tree.level(),
                    rrset_count: self.rrset_count,
                    dirty_pages: 0,
                    page_limit: u32::try_from(self.store.durable_page_limit()).unwrap_or(u32::MAX),
                    changed: false,
                });
            }
        };
        let dirty = self.io.take_dirty();
        let dirty_pages = u32::try_from(dirty.len()).unwrap_or(u32::MAX);
        for (page, bytes) in dirty {
            if let Err(error) = self.store.write_raw_page(page, &bytes) {
                self.rollback();
                return Err(error);
            }
        }
        let entry = RootEntry {
            owner_zone: self.zone,
            version: txn,
            root_page: self.tree.root(),
            tree_level: self.tree.level(),
            rrset_count: self.rrset_count,
            soa_serial: self.soa_serial,
            state: RootState::Serving,
            ..RootEntry::default()
        };
        let mut attempt = 0_u32;
        loop {
            match self.store.publish_root_locked(entry) {
                Ok(outcome) => {
                    self.base_version = txn;
                    self.txn = None;
                    self.io.clear_cache();
                    return Ok(CommitOutcome {
                        zone: self.zone,
                        version: txn,
                        root_page: entry.root_page,
                        tree_level: entry.tree_level,
                        rrset_count: self.rrset_count,
                        dirty_pages,
                        page_limit: u32::try_from(outcome.page_limit).unwrap_or(u32::MAX),
                        changed: true,
                    });
                }
                Err(ParallelError::ReaderContended) if attempt < PUBLISH_RETRIES => {
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => {
                    self.rollback();
                    return Err(error);
                }
            }
        }
    }

    fn commit_tombstone(&mut self) -> Result<CommitOutcome, ParallelError> {
        let txn = self.ensure_txn()?;
        self.io.clear();
        let entry = RootEntry {
            owner_zone: self.zone,
            version: txn,
            root_page: 0,
            tree_level: 0,
            rrset_count: 0,
            soa_serial: self.soa_serial,
            deleted_txn: txn,
            state: RootState::Tombstone,
            ..RootEntry::default()
        };
        let mut attempt = 0_u32;
        loop {
            match self.store.publish_root_locked(entry) {
                Ok(outcome) => {
                    self.base_version = txn;
                    self.txn = None;
                    self.rrset_count = 0;
                    self.tree = ZoneTree::empty(self.origin);
                    return Ok(CommitOutcome {
                        zone: self.zone,
                        version: txn,
                        root_page: 0,
                        tree_level: 0,
                        rrset_count: 0,
                        dirty_pages: 0,
                        page_limit: u32::try_from(outcome.page_limit).unwrap_or(u32::MAX),
                        changed: true,
                    });
                }
                Err(ParallelError::ReaderContended) if attempt < PUBLISH_RETRIES => {
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => {
                    self.rollback();
                    return Err(error);
                }
            }
        }
    }
}

fn split_payload(payload: &[u8]) -> Result<Vec<Vec<u8>>, ParallelError> {
    let mut rdata = Vec::new();
    let mut offset = 0_usize;
    while offset < payload.len() {
        let length = wire::read_u16_be(payload, offset).ok_or_else(|| {
            ParallelError::Tree(ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                None,
                CorruptDetail::Truncated,
            ))
        })? as usize;
        let start = offset.saturating_add(2);
        let end = start.saturating_add(length);
        let bytes = payload.get(start..end).ok_or_else(|| {
            ParallelError::Tree(ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                None,
                CorruptDetail::RdataSum,
            ))
        })?;
        rdata.push(bytes.to_vec());
        offset = end;
    }
    Ok(rdata)
}

fn overflow_rdata<P: PageIo + ?Sized>(
    tree: &ZoneTree,
    io: &P,
    version: u64,
    value: &LeafValue,
) -> Result<Vec<Vec<u8>>, ParallelError> {
    let chain = tree
        .read_overflow(io, version, value)
        .map_err(ParallelError::Tree)?;
    let Some(chain) = chain else {
        return Ok(Vec::new());
    };
    let mut rdata = Vec::with_capacity(chain.len());
    for index in 0..chain.len() {
        let index = u16::try_from(index).unwrap_or(u16::MAX);
        let Some(rr) = chain.rr(index).map_err(ParallelError::Tree)? else {
            break;
        };
        let length = rr.len();
        let mut buffer = vec![0_u8; length];
        rr.copy_into(&mut buffer).map_err(|_| {
            ParallelError::Tree(ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                None,
                CorruptDetail::OverflowChain,
            ))
        })?;
        rdata.push(buffer);
    }
    Ok(rdata)
}

fn record_from_value<P: PageIo + ?Sized>(
    tree: &ZoneTree,
    io: &P,
    version: u64,
    key: &Key,
    value: DecodedValue<'_>,
) -> Result<Option<RrsetRecord>, ParallelError> {
    let DecodedValue::Rrset {
        value: leaf,
        payload,
    } = value
    else {
        return Ok(None);
    };
    if leaf.kind == ValueKind::Node {
        return Ok(None);
    }
    let rdata = match leaf.kind {
        ValueKind::Inline => split_payload(payload)?,
        ValueKind::Overflow => overflow_rdata(tree, io, version, &leaf)?,
        ValueKind::Node => return Ok(None),
    };
    Ok(Some(RrsetRecord {
        name: key.owner()?,
        rr_type: key.rr_type(),
        subtype: key.subtype(),
        ttl: leaf.ttl,
        flags: leaf.flags,
        rdata,
    }))
}

fn collect_records<P: PageIo + ?Sized>(
    tree: &ZoneTree,
    io: &P,
    version: u64,
) -> Result<Vec<RrsetRecord>, ParallelError> {
    let mut cursor = tree.btree().cursor(io, version);
    let mut records = Vec::new();
    if !cursor.seek_first().map_err(ParallelError::Tree)? {
        return Ok(records);
    }
    while let Some(item) = cursor.item().map_err(ParallelError::Tree)? {
        if let ItemValue::Leaf { value, payload } = item.value
            && value.kind != ValueKind::Node
        {
            let rdata = match value.kind {
                ValueKind::Inline => split_payload(&payload)?,
                ValueKind::Overflow => overflow_rdata(tree, io, version, &value)?,
                ValueKind::Node => Vec::new(),
            };
            records.push(RrsetRecord {
                name: item.key.owner()?,
                rr_type: item.key.rr_type(),
                subtype: item.key.subtype(),
                ttl: value.ttl,
                flags: value.flags,
                rdata,
            });
        }
        if !cursor.advance().map_err(ParallelError::Tree)? {
            break;
        }
    }
    Ok(records)
}

/// Read snapshot зоны: держит пин и читает B+tree по версии головы.
pub struct ZoneReader<'a> {
    snapshot: ZoneSnapshot<'a>,
    tree: ZoneTree,
    io: ReaderIo<'a>,
    origin: NameRle,
}

impl std::fmt::Debug for ZoneReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneReader")
            .field("origin", &self.origin)
            .field("version", &self.snapshot.version())
            .finish_non_exhaustive()
    }
}

impl ZoneReader<'_> {
    /// Origin.
    #[must_use]
    pub const fn origin(&self) -> &NameRle {
        &self.origin
    }

    /// Зона.
    #[must_use]
    pub const fn zone(&self) -> u32 {
        self.snapshot.zone()
    }

    /// Версия снапшота.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.snapshot.version()
    }

    /// Запись головы.
    #[must_use]
    pub const fn root(&self) -> &RootEntry {
        self.snapshot.root()
    }

    /// Число прочитанных/закэшированных страниц (диагностика).
    #[must_use]
    pub fn cached_pages(&self) -> usize {
        self.io.cached_pages()
    }

    /// Точный `lookup` с материализацией overflow.
    ///
    /// # Errors
    ///
    /// `Corrupt` — чужая страница/`txn`/дерево; `Io`.
    pub fn lookup(
        &self,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
    ) -> Result<Option<RrsetRecord>, ParallelError> {
        let Some(entry) = self
            .tree
            .lookup(&self.io, self.version(), name, rr_type, subtype)
            .map_err(|error| tree_error(&self.io, error))?
        else {
            return Ok(None);
        };
        record_from_value(
            &self.tree,
            &self.io,
            self.version(),
            &entry.key,
            entry.value,
        )
        .map_err(|error| self.io.take_error().unwrap_or(error))
    }

    /// Zero-copy `lookup` inline-значения (без аллокаций payload).
    ///
    /// Для `OVERFLOW` возвращает `value.kind == Overflow` и `payload = &[]`;
    /// полный набор даёт [`ZoneReader::lookup`].
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`.
    pub fn lookup_ref(
        &self,
        name: &NameRle,
        rr_type: u16,
        subtype: u16,
    ) -> Result<Option<RrsetRef<'_>>, ParallelError> {
        let Some(entry) = self
            .tree
            .lookup(&self.io, self.version(), name, rr_type, subtype)
            .map_err(|error| tree_error(&self.io, error))?
        else {
            return Ok(None);
        };
        let DecodedValue::Rrset { value, payload } = entry.value else {
            return Ok(None);
        };
        if value.kind == ValueKind::Node {
            return Ok(None);
        }
        Ok(Some(RrsetRef {
            name: entry.key.owner()?,
            rr_type: entry.key.rr_type(),
            subtype: entry.key.subtype(),
            ttl: value.ttl,
            flags: value.flags,
            value,
            payload,
        }))
    }

    /// Все `RRset` имени/типа (по возрастанию `subtype`).
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`.
    pub fn lookup_all(
        &self,
        name: &NameRle,
        rr_type: u16,
    ) -> Result<Vec<RrsetRecord>, ParallelError> {
        let items = self
            .tree
            .lookup_all(&self.io, self.version(), name, rr_type)
            .map_err(|error| tree_error(&self.io, error))?;
        let mut records = Vec::with_capacity(items.len());
        for item in items {
            if let ItemValue::Leaf { value, payload } = item.value
                && value.kind != ValueKind::Node
            {
                let rdata = match value.kind {
                    ValueKind::Inline => split_payload(&payload)?,
                    ValueKind::Overflow => {
                        overflow_rdata(&self.tree, &self.io, self.version(), &value)?
                    }
                    ValueKind::Node => Vec::new(),
                };
                records.push(RrsetRecord {
                    name: item.key.owner()?,
                    rr_type: item.key.rr_type(),
                    subtype: item.key.subtype(),
                    ttl: value.ttl,
                    flags: value.flags,
                    rdata,
                });
            }
        }
        Ok(records)
    }

    /// Состояние имени (`T_NODE`, ENT/cut, флаги).
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`.
    pub fn node(&self, name: &NameRle) -> Result<NodeInfo, ParallelError> {
        self.tree
            .node(&self.io, self.version(), name)
            .map_err(|error| tree_error(&self.io, error))
    }

    /// Следующее имя в каноническом порядке.
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`.
    pub fn next_name(&self, after: Option<&NameRle>) -> Result<Option<NameRle>, ParallelError> {
        self.tree
            .next_name(&self.io, self.version(), after)
            .map_err(|error| tree_error(&self.io, error))
    }

    /// Все `RRset` зоны (канонический порядок).
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`.
    pub fn records(&self) -> Result<Vec<RrsetRecord>, ParallelError> {
        collect_records(&self.tree, &self.io, self.version())
    }
}
