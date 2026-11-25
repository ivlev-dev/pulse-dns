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

use std::collections::{HashMap, HashSet};

use crate::consts::{MAX_OVERFLOW_PAGES, PAGE_TYPE_OVERFLOW};
use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::key::{Key, NameRle, T_ZONE_ENTRY};
use crate::node::{
    DecodedBranch, DecodedLeaf, DecodedValue, ItemValue, LeafItem, LeafValue, ValueKind,
};
use crate::page::PageHeader;
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
// B3: пользовательские метаданные зоны в хвосте значения каталога. Старые
// файлы имеют нули в этих байтах, поэтому раскладка обратно совместима.
const CATALOG_OFF_KIND_FLAGS: usize = 20;
const CATALOG_OFF_DEFAULT_TTL: usize = 24;
const CATALOG_OFF_DENIAL: usize = 28;
const CATALOG_OFF_CREATED_NS: usize = 32;
const CATALOG_OFF_UPDATED_NS: usize = 40;

/// Флаги вида зоны (`ZONE_FLAG_*` из v1 `zone_meta`).
pub const ZONE_KIND_FLAG_SECONDARY: u16 = 1;
/// Зона получена трансфером (forward-зона).
pub const ZONE_KIND_FLAG_FORWARD: u16 = 2;
const ZONE_KIND_FLAGS_KNOWN: u16 = ZONE_KIND_FLAG_SECONDARY | ZONE_KIND_FLAG_FORWARD;

/// Метаданные создания зоны (B1: только SOA serial; блок `ZoneMeta` — B2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZoneCreateMeta {
    /// SOA serial зоны (RFC 1982, ≤ `0x7FFF_FFFF`).
    pub soa_serial: u32,
}

/// Пользовательские метаданные зоны, хранимые в записи каталога (B3).
///
/// Значения по умолчанию (`0`) означают «не задано»: адаптеры подставляют
/// собственные значения по умолчанию. Все поля входят в durable запись
/// каталога, поэтому смена настроек зоны — отдельный коммит каталога.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZoneMetaV2 {
    /// Флаги вида зоны ([`ZONE_KIND_FLAG_SECONDARY`], [`ZONE_KIND_FLAG_FORWARD`]).
    pub kind_flags: u16,
    /// TTL по умолчанию (`0` — не задано).
    pub default_ttl: u32,
    /// Denial: `0` — NSEC, `1` — NSEC3 (`2+` — не задано).
    pub denial: u8,
    /// Время создания зоны (unix ns, `0` — не задано).
    pub created_unix_ns: u64,
    /// Время последнего изменения (unix ns, `0` — не задано).
    pub updated_unix_ns: u64,
}

impl ZoneMetaV2 {
    /// Проверяет диапазоны полей.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — зарезервированные флаги/TTL/denial.
    pub fn validate(&self) -> Result<(), ParallelError> {
        if self.kind_flags & !ZONE_KIND_FLAGS_KNOWN != 0
            || self.default_ttl > 0x7FFF_FFFF
            || self.denial > 1
        {
            return Err(ParallelError::InvalidArgument { field: "zone_meta" });
        }
        Ok(())
    }
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
    /// Пользовательские метаданные из каталога.
    pub meta: ZoneMetaV2,
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

/// Подготовленный коммит зоны (dirty-страницы уже записаны, txn закреплён).
struct StagedCommit {
    txn: u64,
    dirty_pages: u32,
    drops: Vec<u32>,
    entry: RootEntry,
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
    meta: ZoneMetaV2,
}

impl CatalogValue {
    fn encode(self) -> [u8; CATALOG_VALUE_BYTES] {
        let mut raw = [0_u8; CATALOG_VALUE_BYTES];
        let _ = wire::write_bytes(&mut raw, CATALOG_OFF_MAGIC, &CATALOG_MAGIC);
        let _ = wire::write_u32(&mut raw, CATALOG_OFF_SEQ, self.zone_seq);
        let _ = wire::write_u32(&mut raw, CATALOG_OFF_SERIAL, self.soa_serial);
        let _ = wire::write_u32(&mut raw, CATALOG_OFF_ORIGIN_LEN, self.origin_len);
        let _ = wire::write_u64(&mut raw, CATALOG_OFF_CREATED_TXN, self.created_txn);
        let _ = wire::write_u32(
            &mut raw,
            CATALOG_OFF_KIND_FLAGS,
            u32::from(self.meta.kind_flags),
        );
        let _ = wire::write_u32(&mut raw, CATALOG_OFF_DEFAULT_TTL, self.meta.default_ttl);
        let _ = wire::write_u32(&mut raw, CATALOG_OFF_DENIAL, u32::from(self.meta.denial));
        let _ = wire::write_u64(&mut raw, CATALOG_OFF_CREATED_NS, self.meta.created_unix_ns);
        let _ = wire::write_u64(&mut raw, CATALOG_OFF_UPDATED_NS, self.meta.updated_unix_ns);
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
            meta: ZoneMetaV2 {
                kind_flags: u16::try_from(wire::read_u32(raw, CATALOG_OFF_KIND_FLAGS)?).ok()?,
                default_ttl: wire::read_u32(raw, CATALOG_OFF_DEFAULT_TTL)?,
                denial: u8::try_from(wire::read_u32(raw, CATALOG_OFF_DENIAL)?).ok()?,
                created_unix_ns: wire::read_u64(raw, CATALOG_OFF_CREATED_NS)?,
                updated_unix_ns: wire::read_u64(raw, CATALOG_OFF_UPDATED_NS)?,
            },
        };
        if value.zone_seq == 0
            || value.soa_serial > 0x7FFF_FFFF
            || usize::try_from(value.origin_len).ok()? != origin.as_rle().len()
            || value.meta.kind_flags & !ZONE_KIND_FLAGS_KNOWN != 0
            || value.meta.default_ttl > 0x7FFF_FFFF
            || value.meta.denial > 1
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
        // `next_seq` восстанавливается и по головам (включая tombstone), иначе
        // после удаления всех зон каталог пуст и свободные слоты терялись бы.
        zones.next_seq = Self::scan_next_seq(store);
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

    fn scan_next_seq(store: &ParallelStore) -> u32 {
        let mut next = 1_u32;
        for seq in 1..store.geometry().max_zones() {
            if store.head_entry(seq).is_some() {
                next = next.max(seq.saturating_add(1));
            }
        }
        next
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

    /// Пользовательские метаданные зоны из каталога.
    #[must_use]
    pub fn zone_meta(&self, origin: &NameRle) -> Option<ZoneMetaV2> {
        self.entries.get(origin).map(|value| value.meta)
    }

    /// Пользовательские метаданные по `zone_seq`.
    #[must_use]
    pub fn zone_meta_by_seq(&self, zone: u32) -> Option<ZoneMetaV2> {
        self.origin(zone)
            .and_then(|origin| self.entries.get(&origin))
            .map(|value| value.meta)
    }

    /// Заменяет пользовательские метаданные зоны (отдельный коммит каталога).
    ///
    /// Возвращает `true`, если запись изменилась (идемпотентный вызов с теми
    /// же полями не пишет каталог).
    ///
    /// # Errors
    ///
    /// `InvalidArgument` — зоны нет/метаданные вне диапазонов;
    /// `Io`/`Corrupt`/`MapFull` — коммит каталога.
    pub fn set_zone_meta(
        &mut self,
        origin: &NameRle,
        meta: ZoneMetaV2,
    ) -> Result<bool, ParallelError> {
        meta.validate()?;
        let Some(mut value) = self.entries.get(origin).copied() else {
            return Err(ParallelError::InvalidArgument { field: "origin" });
        };
        if value.meta == meta {
            return Ok(false);
        }
        value.meta = meta;
        self.write_catalog_edit(CatalogEdit::Upsert(origin, value))?;
        self.entries.insert(*origin, value);
        Ok(true)
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
                meta: value.meta,
            });
        }
        zones
    }

    /// Создаёт зону: `RootEntry` зоны (пустое дерево), затем запись каталога.
    ///
    /// Сначала переиспользуется свободный слот удалённой зоны (tombstone
    /// durable, каталог уже очищен `gc_catalog`), иначе выдаётся новый
    /// `zone_seq`. Крах между коммитом зоны и каталогом оставляет недостижимую
    /// зону (PW-L7), но не порчу.
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
        self.create_zone_with_meta(origin, meta, ZoneMetaV2::default())
    }

    /// Создаёт зону вместе с пользовательскими метаданными каталога.
    ///
    /// Пользовательские поля (вид зоны, TTL по умолчанию, denial) пишутся в ту
    /// же запись каталога, что и `origin → zone_seq`, поэтому зона и её
    /// настройки появляются атомарно.
    ///
    /// # Errors
    ///
    /// См. [`ParallelZones::create_zone`]; `InvalidArgument` — метаданные вне
    /// допустимых диапазонов.
    #[allow(clippy::too_many_lines)]
    pub fn create_zone_with_meta(
        &mut self,
        origin: &NameRle,
        meta: ZoneCreateMeta,
        zone_meta: ZoneMetaV2,
    ) -> Result<u32, ParallelError> {
        zone_meta.validate()?;
        if self.entries.contains_key(origin) {
            return Err(ParallelError::InvalidArgument { field: "origin" });
        }
        if meta.soa_serial > 0x7FFF_FFFF {
            return Err(ParallelError::Unsupported {
                what: "soa_serial (max 0x7fff_ffff)",
            });
        }
        let max_zones = self.store.geometry().max_zones();
        let mut zone_seq = self.reusable_slot();
        if zone_seq.is_none() {
            let mut candidate = self.next_seq;
            // Пропускаем «осиротевшие» головы от краха между коммитом зоны и
            // каталогом (PW-L7): слот занят, но в каталоге его нет.
            while candidate < max_zones && self.store.head_entry(candidate).is_some() {
                candidate = candidate.saturating_add(1);
            }
            zone_seq = Some(candidate);
        }
        let zone_seq = zone_seq.ok_or(ParallelError::InvalidArgument { field: "max_zones" })?;
        if zone_seq >= max_zones {
            return Err(ParallelError::InvalidArgument { field: "max_zones" });
        }
        self.next_seq = self.next_seq.max(zone_seq.saturating_add(1));
        self.store.reset_zone_slot(zone_seq);
        let mut zone = ParallelZone::open_new(self.store, *origin, zone_seq, meta.soa_serial)?;
        let outcome = zone.commit_with(self.store.effective_mode())?;
        // Порядок локов (ADR 0007 §8): lease зоны не удерживается при правке
        // каталога. Каталог живёт в выделенном шарде (`CATALOG_LEASE_SHARD`),
        // поэтому зоны 256/512/… не делят с ним нереентерабельный mutex.
        drop(zone);
        let value = CatalogValue {
            zone_seq,
            soa_serial: meta.soa_serial,
            origin_len: u32::try_from(origin.as_rle().len()).unwrap_or(u32::MAX),
            created_txn: outcome.version,
            meta: zone_meta,
        };
        self.write_catalog_edit(CatalogEdit::Upsert(origin, value))?;
        self.origins.insert(zone_seq, *origin);
        self.entries.insert(*origin, value);
        Ok(zone_seq)
    }

    /// Durable tombstone-слот без записи в каталоге, который можно
    /// переиспользовать (`zone_seq` не расходуется бесконечно).
    fn reusable_slot(&self) -> Option<u32> {
        for seq in 1..self.next_seq {
            if self.origins.contains_key(&seq) {
                continue;
            }
            let Some(head) = self.store.head_entry(seq) else {
                continue;
            };
            if head.is_tombstone()
                && head.deleted_txn != 0
                && self.store.durable_version(seq) >= head.deleted_txn
            {
                return Some(seq);
            }
        }
        None
    }

    /// Удаляет из каталога зоны, чей tombstone уже durable (§5.6, §6.5).
    ///
    /// Каталог-запись уходит после durable-удаления, поэтому крах на любой
    /// стадии оставляет либо живую зону, либо tombstone, но не «висячую»
    /// запись каталога на удалённую зону. Возвращает удалённые origin'ы; слот
    /// `zone_seq` становится доступен [`ParallelZones::create_zone`] после
    /// durable-коммита каталога.
    ///
    /// # Errors
    ///
    /// `Io`/`Corrupt`/`MapFull` — коммит каталога.
    pub fn gc_catalog(&mut self) -> Result<Vec<NameRle>, ParallelError> {
        let mut candidates = Vec::new();
        for (origin, value) in &self.entries {
            let Some(head) = self.store.head_entry(value.zone_seq) else {
                continue;
            };
            if !head.is_tombstone() || head.deleted_txn == 0 {
                continue;
            }
            if self.store.durable_version(value.zone_seq) < head.deleted_txn {
                continue;
            }
            candidates.push((*origin, value.zone_seq));
        }
        candidates.sort_by_key(|(_, zone)| *zone);
        let mut removed = Vec::new();
        for (origin, zone) in candidates {
            if self.write_catalog_edit(CatalogEdit::Remove(&origin))? {
                self.entries.remove(&origin);
                self.origins.remove(&zone);
                removed.push(origin);
            }
        }
        Ok(removed)
    }

    /// Помечает зону tombstone (`delete_zone`), каталог не меняется.
    ///
    /// Каталог-запись удаляется отдельно через [`ParallelZones::gc_catalog`]
    /// после durable tombstone.
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
            store: self.store,
            snapshot,
            tree,
            io,
            origin: *origin,
        })
    }

    fn write_catalog_edit(&mut self, edit: CatalogEdit<'_>) -> Result<bool, ParallelError> {
        let _lease = self.store.lease_guard(0)?;
        // Правка каталога короткоживущая: локальный батч `WriteIo::new`
        // (64 страницы) терялся бы на каждом коммите каталога, раздувая файл
        // на ~64 страницы на зону. Каталог резервирует страницы точно.
        let mut io = WriteIo::new_exact(self.store, 0, self.version);
        io.clear_cache();
        let txn = io.next_txn()?;
        io.set_version(txn);
        let old_root = self.tree.root();
        let old_level = self.tree.level();
        let changed = match edit {
            CatalogEdit::Upsert(origin, value) => {
                let key = Key::new(origin, T_ZONE_ENTRY, 0, 0)?;
                let raw = value.encode();
                let item = LeafItem::new(key, ItemValue::zone_entry(&raw)?);
                match self.tree.insert_or_replace(&mut io, txn, &item) {
                    Ok(_) => true,
                    Err(error) => {
                        self.tree = BTree::new(old_root, old_level)?;
                        return Err(writer_error(&io, error));
                    }
                }
            }
            CatalogEdit::Remove(origin) => {
                let key = Key::new(origin, T_ZONE_ENTRY, 0, 0)?;
                match self.tree.delete(&mut io, txn, &key) {
                    Ok(value) => value.is_some(),
                    Err(error) => {
                        self.tree = BTree::new(old_root, old_level)?;
                        return Err(writer_error(&io, error));
                    }
                }
            }
        };
        if !changed {
            io.clear();
            return Ok(false);
        }
        let dirty = io.take_dirty();
        for (page, bytes) in dirty {
            if let Err(error) = self.store.write_raw_page(page, &bytes) {
                self.tree = BTree::new(old_root, old_level)?;
                io.clear();
                return Err(error);
            }
        }
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        let rrset_count = match edit {
            CatalogEdit::Upsert(..) => count.saturating_add(1),
            CatalogEdit::Remove(..) => count.saturating_sub(1),
        };
        let drops = io.take_freed();
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
            match self.store.publish_root_with_drops_mode(
                entry,
                &drops,
                self.store.effective_mode(),
            ) {
                Ok(_) => {
                    self.version = txn;
                    io.finish_commit();
                    return Ok(true);
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

/// Правка каталога зон.
#[derive(Debug, Clone, Copy)]
enum CatalogEdit<'a> {
    /// Вставить/заменить запись зоны.
    Upsert(&'a NameRle, CatalogValue),
    /// Удалить запись зоны.
    Remove(&'a NameRle),
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
    _lease: crate::parallel::store::ZoneLease<'a>,
    base_version: u64,
    txn: Option<u64>,
    /// Новой/переиспользованной зоне нужен первый durable `RootEntry`.
    needs_root: bool,
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
    /// Открывает writer зоны по `zone_seq` (lease удерживается до `Drop`).
    ///
    /// Позволяет писать зону без загрузки каталога: `origin`/`zone_seq` берутся
    /// из кэша вызывающего. Между открытием writer'а и коммитом другой процесс
    /// писать не может (writer-лок), а другой поток этого процесса ждёт lease.
    ///
    /// # Errors
    ///
    /// `NoZoneVersion` — зоны нет/tombstone; `Corrupt`/`Io` — голова/дерево;
    /// `Busy` — файл занят другим writer'ом.
    pub fn open(
        store: &'a ParallelStore,
        origin: NameRle,
        zone: u32,
    ) -> Result<Self, ParallelError> {
        Self::open_impl(store, origin, zone, true)
    }

    /// Открывает writer без per-handle кеша страниц (`REST`/короткие правки).
    ///
    /// Обычный [`ParallelZone::open`] резервирует батч из 64 страниц на handle;
    /// короткоживущий writer не успевает его использовать, поэтому такой режим
    /// тратил бы место файла. Семантика lease/коммита идентична.
    ///
    /// # Errors
    ///
    /// См. [`ParallelZone::open`].
    pub fn open_uncached(
        store: &'a ParallelStore,
        origin: NameRle,
        zone: u32,
    ) -> Result<Self, ParallelError> {
        Self::open_impl(store, origin, zone, false)
    }

    fn open_impl(
        store: &'a ParallelStore,
        origin: NameRle,
        zone: u32,
        cached: bool,
    ) -> Result<Self, ParallelError> {
        let lease = store.lease_guard(zone)?;
        let head = store
            .head_entry(zone)
            .ok_or(ParallelError::NoZoneVersion { zone })?;
        if head.is_tombstone() {
            return Err(ParallelError::NoZoneVersion { zone });
        }
        let tree = ZoneTree::new(origin, head.root_page, head.tree_level)?;
        let io = if cached {
            WriteIo::new(store, zone, head.version)
        } else {
            WriteIo::new_exact(store, zone, head.version)
        };
        Ok(Self {
            store,
            origin,
            zone,
            tree,
            io,
            _lease: lease,
            base_version: head.version,
            txn: None,
            needs_root: false,
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
        let lease = store.lease_guard(zone)?;
        let base_version = match store.head_entry(zone) {
            None => 0,
            Some(head) if head.is_tombstone() => head.version,
            Some(_) => return Err(ParallelError::InvalidArgument { field: "zone_seq" }),
        };
        let tree = ZoneTree::empty(origin);
        let io = WriteIo::new_exact(store, zone, base_version);
        Ok(Self {
            store,
            origin,
            zone,
            tree,
            io,
            _lease: lease,
            base_version,
            txn: None,
            needs_root: true,
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

    /// Создаёт пустой `T_NODE` имени (ENT) в незакоммиченном дереве.
    ///
    /// Нужен, чтобы после удаления последнего `RRset` имя продолжало
    /// существовать (NODATA вместо NXDOMAIN).
    ///
    /// # Errors
    ///
    /// `Tree`/`Corrupt`/`Io`; `NameOutsideZone` — имя вне зоны.
    pub fn ensure_empty_node(&mut self, name: &NameRle) -> Result<bool, ParallelError> {
        self.ensure_txn()?;
        let txn = self.txn.unwrap_or(self.base_version);
        match self.tree.ensure_empty_node(&mut self.io, txn, name) {
            Ok(changed) => Ok(changed),
            Err(error) => {
                let error = writer_error(&self.io, error);
                self.rollback();
                Err(error)
            }
        }
    }

    /// Задаёт SOA serial, публикуемый в голове зоны.
    ///
    /// Значение хранится в `RootEntry.soa_serial` (≤ `0x7FFF_FFFF`); старший
    /// бит отбрасывается, полный serial всегда доступен в самом `SOA` `RRset`.
    ///
    /// # Errors
    ///
    /// Нет: значение маскируется до допустимого диапазона.
    pub fn set_soa_serial(&mut self, serial: u32) {
        self.soa_serial = serial & 0x7FFF_FFFF;
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
    /// `DurabilityBelowFileMode` — липкий/файловый `Sync`; `Io`/`MapFull`/
    /// `ReaderContended`.
    pub fn commit(&mut self) -> Result<CommitOutcome, ParallelError> {
        self.commit_with(SyncModeV2::Sync)
    }

    /// Коммит с явным режимом durability: `Sync`/`Flush`/`Memory` (§7.2).
    ///
    /// `Flush` синхронизирует данные (фаза 1) и не синхронизирует корни;
    /// `Memory` не делает `fdatasync` вовсе. Проверка липкого `Sync` —
    /// [`ParallelError::DurabilityBelowFileMode`].
    ///
    /// # Errors
    ///
    /// `Unsupported` — режим не поддержан файлом; `DurabilityBelowFileMode`;
    /// `Io`/`MapFull`/`ReaderContended`.
    pub fn commit_with(&mut self, durability: SyncModeV2) -> Result<CommitOutcome, ParallelError> {
        let Some(staged) = self.stage_commit(durability)? else {
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
        };
        let mut attempt = 0_u32;
        loop {
            match self
                .store
                .publish_root_with_drops_mode(staged.entry, &staged.drops, durability)
            {
                Ok(outcome) => return Ok(self.complete_commit(&staged, outcome)),
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

    /// Коммит через координатор group commit (§7.1): запрос батчится с другими
    /// зонами, ack приходит после публикации головы.
    ///
    /// # Errors
    ///
    /// [`ParallelError::GroupClosed`] — координатор остановлен;
    /// `DurabilityBelowFileMode`; `Io`/`MapFull`/`ReaderContended`/`Unsupported`.
    pub fn commit_via(
        &mut self,
        committer: &crate::parallel::group::GroupCommitter,
    ) -> Result<CommitOutcome, ParallelError> {
        let durability = SyncModeV2::Sync;
        let Some(staged) = self.stage_commit(durability)? else {
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
        };
        let weight = u64::from(staged.dirty_pages) * 4096;
        let mut attempt = 0_u32;
        loop {
            match committer.commit(staged.entry, &staged.drops, weight) {
                Ok(outcome) => return Ok(self.complete_commit(&staged, outcome)),
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

    /// Коммит через координатор с явным режимом durability.
    ///
    /// # Errors
    ///
    /// См. [`ParallelZone::commit_via`] и
    /// [`ParallelError::DurabilityBelowFileMode`].
    pub fn commit_via_with(
        &mut self,
        committer: &crate::parallel::group::GroupCommitter,
        durability: SyncModeV2,
    ) -> Result<CommitOutcome, ParallelError> {
        let Some(staged) = self.stage_commit(durability)? else {
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
        };
        let weight = u64::from(staged.dirty_pages) * 4096;
        let mut attempt = 0_u32;
        loop {
            match committer.commit_with(staged.entry, &staged.drops, weight, durability) {
                Ok(outcome) => return Ok(self.complete_commit(&staged, outcome)),
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

    /// Готовит коммит: проверяет режим, пишет dirty-страницы, собирает
    /// `RootEntry` и `drops`. `None` — нечего публиковать (пустой коммит).
    fn stage_commit(
        &mut self,
        durability: SyncModeV2,
    ) -> Result<Option<StagedCommit>, ParallelError> {
        self.store.check_durability(durability)?;
        let txn = match self.txn {
            Some(txn) => txn,
            None if self.base_version == 0 || self.needs_root => self.ensure_txn()?,
            None => return Ok(None),
        };
        let dirty = self.io.take_dirty();
        let dirty_pages = u32::try_from(dirty.len()).unwrap_or(u32::MAX);
        for (page, bytes) in dirty {
            if let Err(error) = self.store.write_raw_page(page, &bytes) {
                self.rollback();
                return Err(error);
            }
        }
        let drops = self.io.take_freed();
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
        Ok(Some(StagedCommit {
            txn,
            dirty_pages,
            drops,
            entry,
        }))
    }

    fn complete_commit(
        &mut self,
        staged: &StagedCommit,
        outcome: crate::parallel::store::PublishOutcome,
    ) -> CommitOutcome {
        self.base_version = staged.txn;
        self.txn = None;
        self.needs_root = false;
        self.io.finish_commit();
        CommitOutcome {
            zone: self.zone,
            version: staged.txn,
            root_page: staged.entry.root_page,
            tree_level: staged.entry.tree_level,
            rrset_count: self.rrset_count,
            dirty_pages: staged.dirty_pages,
            page_limit: u32::try_from(outcome.page_limit).unwrap_or(u32::MAX),
            changed: true,
        }
    }

    fn commit_tombstone(&mut self) -> Result<CommitOutcome, ParallelError> {
        let durability = self.store.effective_mode();
        self.store.check_durability(durability)?;
        let txn = self.ensure_txn()?;
        // Страницы удаляемой зоны становятся недостижимыми: собираем их в
        // bucket `drop_txn = V`, чтобы GC вернул место.
        let old_root = self.tree.root();
        let old_level = self.tree.level();
        let mut pages = Vec::new();
        if old_root != 0 {
            let io = ReaderIo::new(self.store, self.zone, self.base_version);
            pages = collect_zone_pages(&io, old_root, old_level, self.base_version)
                .map_err(|error| io.take_error().unwrap_or(error))?;
        }
        self.io.clear();
        for page in pages {
            self.io
                .free_page(page)
                .map_err(|error| self.io.take_error().unwrap_or(ParallelError::Tree(error)))?;
        }
        let drops = self.io.take_freed();
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
            match self.store.publish_root_with_drops_mode(
                entry,
                &drops,
                self.store.effective_mode(),
            ) {
                Ok(outcome) => {
                    self.base_version = txn;
                    self.txn = None;
                    self.rrset_count = 0;
                    self.tree = ZoneTree::empty(self.origin);
                    self.io.finish_commit();
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

    /// Передаёт eligible-страницы пула зоны в donation-пул (§6.4).
    ///
    /// Сначала durable-коммит с уменьшенным `free_head`, затем перенос в
    /// donation: только после fsync страницы считаются свободными для других
    /// зон. Возвращает число страниц.
    ///
    /// # Errors
    ///
    /// `NoZoneVersion` — зоны нет; `MapFull`/`Io` — коммит; `ZoneDegraded`.
    pub fn donate(&mut self, max_pages: u32) -> Result<u32, ParallelError> {
        if max_pages == 0 {
            return Ok(0);
        }
        let version = self.ensure_txn()?;
        let pages = self
            .store
            .take_zone_pool_pages(self.zone, version, max_pages)?;
        if pages.is_empty() {
            self.txn = None;
            return Ok(0);
        }
        let entry = RootEntry {
            owner_zone: self.zone,
            version,
            root_page: self.tree.root(),
            tree_level: self.tree.level(),
            rrset_count: self.rrset_count,
            soa_serial: self.soa_serial,
            state: RootState::Serving,
            ..RootEntry::default()
        };
        let mut attempt = 0_u32;
        loop {
            match self
                .store
                .publish_root_with_drops_mode(entry, &[], self.store.effective_mode())
            {
                Ok(outcome) => {
                    self.base_version = version;
                    self.txn = None;
                    self.io.finish_commit();
                    self.store.donate_pages(&pages, outcome.version);
                    return Ok(u32::try_from(pages.len()).unwrap_or(u32::MAX));
                }
                Err(ParallelError::ReaderContended) if attempt < PUBLISH_RETRIES => {
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => {
                    self.store.return_pages(self.zone, &pages);
                    self.rollback();
                    return Err(error);
                }
            }
        }
    }
}

impl Drop for ParallelZone<'_> {
    fn drop(&mut self) {
        // Незакоммиченные страницы не достижимы ни из одной durable-головы:
        // возвращаем их в пул (NEVER_PUBLISHED), чтобы не терять место.
        self.io.clear();
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
    let name = NameRle::from_validated(key.owner_bytes()).ok_or(ParallelError::Corrupt {
        kind: crate::parallel::error::V2CorruptKind::Bounds,
        page: None,
    })?;
    Ok(Some(RrsetRecord {
        name,
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

/// Собирает все страницы дерева зоны (включая overflow-цепочки) для tombstone.
///
/// Читает через [`ReaderIo`], поэтому каждая страница уже проверена на
/// `owner_zone`, `txn ≤ version` и CRC. Повтор/цикл — `Corrupt`.
fn collect_zone_pages(
    io: &ReaderIo<'_>,
    root: u32,
    level: u16,
    version: u64,
) -> Result<Vec<u32>, ParallelError> {
    let mut pages = Vec::new();
    let mut seen = HashSet::new();
    let node_level = level.checked_sub(1).ok_or_else(|| {
        ParallelError::Tree(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(root),
            CorruptDetail::DepthExceeded,
        ))
    })?;
    collect_node_pages(io, root, node_level, version, &mut pages, &mut seen)
        .map_err(ParallelError::Tree)?;
    Ok(pages)
}

fn collect_node_pages(
    io: &ReaderIo<'_>,
    page_no: u32,
    level: u16,
    version: u64,
    pages: &mut Vec<u32>,
    seen: &mut HashSet<u32>,
) -> Result<(), ZoneFileError> {
    if !seen.insert(page_no) {
        return Err(ZoneFileError::corrupt(
            CorruptKind::FreelistCycle,
            Some(page_no),
            CorruptDetail::Cycle,
        ));
    }
    pages.push(page_no);
    let raw = io.read_page(page_no)?;
    let page_size = io.page_size();
    if level == 0 {
        let leaf = DecodedLeaf::decode(raw, page_no, version, page_size)?;
        for index in 0..leaf.len() {
            if let DecodedValue::Rrset { value, .. } = leaf.value(index)?
                && value.kind == ValueKind::Overflow
            {
                collect_overflow_pages(io, value.val_u32, version, pages, seen)?;
            }
        }
        return Ok(());
    }
    let branch = DecodedBranch::decode(raw, page_no, version, page_size)?;
    if branch.level() != level {
        return Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(page_no),
            CorruptDetail::PageType,
        ));
    }
    for index in 0..branch.len() {
        collect_node_pages(io, branch.child(index)?, level - 1, version, pages, seen)?;
    }
    Ok(())
}

fn collect_overflow_pages(
    io: &ReaderIo<'_>,
    first: u32,
    version: u64,
    pages: &mut Vec<u32>,
    seen: &mut HashSet<u32>,
) -> Result<(), ZoneFileError> {
    let mut page_no = first;
    let mut hops = 0_u32;
    while page_no != 0 {
        hops = hops.saturating_add(1);
        if hops > MAX_OVERFLOW_PAGES || !seen.insert(page_no) {
            return Err(ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                Some(page_no),
                CorruptDetail::Cycle,
            ));
        }
        pages.push(page_no);
        let raw = io.read_page(page_no)?;
        let header = PageHeader::decode(raw, page_no, version, io.page_size())?;
        if header.page_type != PAGE_TYPE_OVERFLOW {
            return Err(ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                Some(page_no),
                CorruptDetail::PageType,
            ));
        }
        page_no = wire::read_u32(raw, 40).ok_or_else(|| {
            ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                Some(page_no),
                CorruptDetail::Truncated,
            )
        })?;
    }
    Ok(())
}

/// Read snapshot зоны: держит пин и читает B+tree по версии головы.
pub struct ZoneReader<'a> {
    store: &'a ParallelStore,
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

impl<'a> ZoneReader<'a> {
    /// Открывает read snapshot зоны по `zone_seq` без загрузки каталога.
    ///
    /// `reader` должен жить не меньше снапшота; пин снимается при `Drop`.
    ///
    /// # Errors
    ///
    /// `NoZoneVersion`, `ZoneDegraded`, `ReaderContended`, `Corrupt`.
    pub fn open(
        store: &'a ParallelStore,
        reader: &'a Reader<'a>,
        origin: NameRle,
        zone: u32,
    ) -> Result<Self, ParallelError> {
        let snapshot = store.zone_snapshot(reader, zone)?;
        let root = *snapshot.root();
        let tree = ZoneTree::new(origin, root.root_page, root.tree_level)?;
        let io = ReaderIo::new(store, zone, snapshot.version());
        Ok(Self {
            store,
            snapshot,
            tree,
            io,
            origin,
        })
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
        let entry = match self.store.node_cache() {
            Some(cache) => {
                self.tree
                    .lookup_cached(&self.io, cache, self.version(), name, rr_type, subtype)
            }
            None => self
                .tree
                .lookup(&self.io, self.version(), name, rr_type, subtype),
        }
        .map_err(|error| tree_error(&self.io, error))?;
        let Some(entry) = entry else {
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
        let entry = match self.store.node_cache() {
            Some(cache) => {
                self.tree
                    .lookup_cached(&self.io, cache, self.version(), name, rr_type, subtype)
            }
            None => self
                .tree
                .lookup(&self.io, self.version(), name, rr_type, subtype),
        }
        .map_err(|error| tree_error(&self.io, error))?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        let DecodedValue::Rrset { value, payload } = entry.value else {
            return Ok(None);
        };
        if value.kind == ValueKind::Node {
            return Ok(None);
        }
        // Имя/тип уже провалидированы при разборе ключа страницы.
        let name =
            NameRle::from_validated(entry.key.owner_bytes()).ok_or(ParallelError::Corrupt {
                kind: crate::parallel::error::V2CorruptKind::Bounds,
                page: None,
            })?;
        Ok(Some(RrsetRef {
            name,
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

    /// Предыдущее имя (`predecessor`) в каноническом порядке до `before`
    /// (`None` — последнее имя зоны).
    ///
    /// Спуск по B+tree, без обхода зоны.
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`.
    pub fn prev_name(&self, before: Option<&NameRle>) -> Result<Option<NameRle>, ParallelError> {
        self.tree
            .prev_name(&self.io, self.version(), before)
            .map_err(|error| tree_error(&self.io, error))
    }

    /// Обходит владельцев записей заданного типа в каноническом порядке.
    ///
    /// Ключи читаются курсором (без материализации RDATA/overflow). Для
    /// `RRSIG` обратный вызов срабатывает на каждый `subtype`; `NSEC`/`NSEC3`
    /// имеют один ключ на владельца.
    ///
    /// # Errors
    ///
    /// `Corrupt`/`Io`.
    pub fn for_each_owner(
        &self,
        rr_type: u16,
        mut visit: impl FnMut(&NameRle),
    ) -> Result<(), ParallelError> {
        self.tree
            .for_each_owner(&self.io, self.version(), rr_type, &mut visit)
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
