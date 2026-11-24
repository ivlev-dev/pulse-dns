//! Доступ к `pulse-zonefile` v2 (`ParallelStore`) как к единственному
//! источнику истины.
//!
//! DNS-ответы читаются из mmap через [`ZoneReader`]: на каждый логический
//! запрос открывается пин читателя, поиск идёт по B+tree без материализации
//! зоны. Мутации выполняются per-zone writer'ом ([`ParallelZone`]): lease зоны
//! удерживается на время правки, разные зоны коммитятся параллельно.
//!
//! Метаданные зон (вид, TTL по умолчанию, denial) хранятся в записи каталога
//! v2 ([`ZoneMetaV2`]), поэтому настройки зоны durable вместе с `origin →
//! zone_seq`. Кэш каталога в памяти обновляется при create/delete и читает
//! версию головы зоны при каждом обращении.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pulse_api::{Denial, ZoneFileMetrics, ZoneKind};
use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Ttl};
use pulse_server::{LookupOutcome, ZoneState as ServerZoneState, ZoneView};
use pulse_transfer::ZoneSnapshot;
use pulse_zonefile::RrsetView as StoredRrsetView;
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    CommitOutcome, GroupCommitter, OpenConfigV2, ParallelError, ParallelStore, ParallelZone,
    ParallelZones, RootState, RrsetData, RrsetRecord, StoreConfig, SyncModeV2,
    ZONE_KIND_FLAG_FORWARD, ZONE_KIND_FLAG_SECONDARY, ZoneCreateMeta, ZoneMetaV2, ZoneReader,
};
use pulse_zonefile::tree::NodeInfo;
use thiserror::Error;

use crate::config::CommitMode;

/// Сигнатура v1-файла; такой файл нельзя открыть v2-стором.
const V1_MAGIC: &[u8; 8] = b"PULSEZF1";
/// Сколько раз повторяется стабильный пин при `ReaderContended`.
const READ_RETRIES: u32 = 64;
/// Попытки стабильного чтения головы (публикация использует seqlock).
const HEAD_RETRIES: u32 = 128;
/// Максимум зон в v2-файле `pulsed` (пролог не раздувается под 65k слотов).
const MAX_ZONES: u32 = 4096;

/// Ошибка доступа к zonefile.
#[derive(Debug, Error)]
#[error("{0}")]
pub(crate) struct ZoneFileSourceError(String);

impl ZoneFileSourceError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Атомарные счётчики пути чтения/записи zonefile.
#[derive(Debug, Default)]
pub(crate) struct ZoneFileStats {
    snapshot_pins: AtomicU64,
    lookups: AtomicU64,
    commits: AtomicU64,
    commit_errors: AtomicU64,
}

impl ZoneFileStats {
    pub(crate) fn metrics(&self, store: Option<&ParallelStore>) -> ZoneFileMetrics {
        let store_stats = store.map(ParallelStore::stats);
        let page_cache = store.map(ParallelStore::page_cache_stats);
        let node_cache = store.map(ParallelStore::node_cache_stats);
        ZoneFileMetrics {
            snapshot_pins: self.snapshot_pins.load(Ordering::Relaxed),
            lookups: self.lookups.load(Ordering::Relaxed),
            commits: self.commits.load(Ordering::Relaxed),
            commit_errors: self.commit_errors.load(Ordering::Relaxed),
            v2_alloc_pages: store.map_or(0, ParallelStore::allocated_data_pages),
            v2_alloc_cas_retries: store_stats.map_or(0, |stats| stats.alloc_cas_retries),
            v2_page_cache_hits: page_cache.map_or(0, |stats| stats.hits),
            v2_page_cache_misses: page_cache.map_or(0, |stats| stats.misses),
            v2_node_cache_hits: node_cache.map_or(0, |stats| stats.hits),
            v2_node_cache_misses: node_cache.map_or(0, |stats| stats.misses),
            v2_reclaimed_pages: store_stats.map_or(0, |stats| stats.reclaimed_pages),
            v2_group_commits: store_stats.map_or(0, |stats| stats.group_commits),
            v2_group_fsyncs: store_stats.map_or(0, |stats| stats.group_fsyncs),
            v2_pins: store.map_or(0, |store| {
                u64::try_from(store.active_pins()).unwrap_or(u64::MAX)
            }),
        }
    }

    pub(crate) fn commit_ok(&self) {
        self.commits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn commit_failed(&self) {
        self.commit_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn lookup(&self) {
        self.lookups.fetch_add(1, Ordering::Relaxed);
    }

    fn pin(&self) {
        self.snapshot_pins.fetch_add(1, Ordering::Relaxed);
    }
}

/// Запись зоны, прочитанная из каталога + головы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZoneEntry {
    /// Origin.
    pub origin: Name,
    /// Origin в RLE-форме.
    pub apex: NameRle,
    /// Слот зоны.
    pub zone_seq: u32,
    /// Опубликованная версия (`txn`).
    pub version: u64,
    /// SOA serial из головы.
    pub soa_serial: u32,
    /// Число `RRset`.
    pub rrset_count: u32,
    /// Состояние.
    pub state: RootState,
    /// Флаги вида зоны (`ZONE_KIND_FLAG_*`).
    pub flags: u16,
    /// TTL по умолчанию (`0` — не задан).
    pub default_ttl: u32,
    /// Denial (`0` — NSEC).
    pub denial: u8,
    /// Время создания (unix ns).
    pub created_unix_ns: u64,
    /// Время последнего изменения (unix ns).
    pub updated_unix_ns: u64,
}

/// Зона в кэше каталога (без головы; версия читается при обращении).
#[derive(Debug, Clone)]
struct CatalogEntry {
    origin: Name,
    apex: NameRle,
    zone_seq: u32,
    meta: ZoneMetaV2,
}

/// Кэш каталога: `origin → zone_seq` и пользовательские метаданные.
#[derive(Debug, Default)]
struct CatalogCache {
    entries: HashMap<Name, CatalogEntry>,
}

/// Открытый v2-стор: единственный writer-лок процесса.
pub(crate) struct ZoneStore {
    store: Arc<ParallelStore>,
    stats: Arc<ZoneFileStats>,
    requested: SyncModeV2,
    commit_mode: CommitMode,
    committer: Option<GroupCommitter>,
    catalog: Mutex<CatalogCache>,
    path: PathBuf,
    /// Сериализует выбор durability с `sync()`: `sync()` делает режим липким
    /// `Sync`, и коммит, выбравший `Flush` до этого, иначе получил бы
    /// `DurabilityBelowFileMode` уже после правок.
    durability_gate: Arc<Mutex<()>>,
    maintenance_stop: Arc<AtomicBool>,
    maintenance: Mutex<Option<JoinHandle<()>>>,
}

impl ZoneStore {
    /// Открывает существующий v2-файл или создаёт новый.
    ///
    /// Пустой файл трактуется как «создать» (совместимо с `pulsed import`).
    /// v1-файл отвергается с подсказкой про `pulsed convert`.
    pub(crate) fn open_or_create(
        path: &Path,
        map_size: u64,
        requested: SyncModeV2,
        commit_mode: CommitMode,
    ) -> Result<Self, ZoneFileSourceError> {
        let existed = match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_file() && meta.len() == 0 {
                    std::fs::remove_file(path).map_err(|error| {
                        ZoneFileSourceError::new(format!(
                            "cannot initialise empty zone file {}: {error}",
                            path.display()
                        ))
                    })?;
                    false
                } else {
                    true
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(ZoneFileSourceError::new(format!(
                    "cannot stat zone file {}: {error}",
                    path.display()
                )));
            }
        };
        if existed && is_v1_file(path)? {
            return Err(ZoneFileSourceError::new(format!(
                "zone file {} uses the v1 format; run `pulsed convert --from {} --to <v2-file>` first",
                path.display(),
                path.display()
            )));
        }
        let store = if existed {
            ParallelStore::open(path, OpenConfigV2::default())
        } else {
            ParallelStore::create(
                path,
                StoreConfig {
                    page_count_max: page_count(map_size),
                    max_zones: MAX_ZONES,
                    sync_mode: requested,
                    ..StoreConfig::default()
                },
            )
        }
        .map_err(|error| file_error(path, "open", &error))?;
        let store = Arc::new(store);
        let mut cache = CatalogCache::default();
        Self::load_catalog_into(&store, &mut cache)
            .map_err(|error| file_error(path, "load catalog", &error))?;
        let committer = if commit_mode == CommitMode::Group {
            Some(
                GroupCommitter::new(Arc::clone(&store))
                    .map_err(|error| file_error(path, "start group committer", &error))?,
            )
        } else {
            None
        };
        let durability_gate = Arc::new(Mutex::new(()));
        let maintenance_stop = Arc::new(AtomicBool::new(false));
        let maintenance = {
            let stop = Arc::clone(&maintenance_stop);
            let worker = Arc::clone(&store);
            let gate = Arc::clone(&durability_gate);
            let worker_path = path.to_path_buf();
            thread::Builder::new()
                .name("pulse-zonefile-gc".to_owned())
                .spawn(move || maintenance_loop(&worker, &worker_path, &stop, &gate))
                .map_err(|error| {
                    ZoneFileSourceError::new(format!(
                        "cannot start zonefile GC worker for {}: {error}",
                        path.display()
                    ))
                })?
        };
        Ok(Self {
            store,
            stats: Arc::new(ZoneFileStats::default()),
            requested,
            commit_mode,
            committer,
            catalog: Mutex::new(cache),
            path: path.to_path_buf(),
            durability_gate,
            maintenance_stop,
            maintenance: Mutex::new(Some(maintenance)),
        })
    }

    fn load_catalog_into(
        store: &ParallelStore,
        cache: &mut CatalogCache,
    ) -> Result<(), ParallelError> {
        let zones = ParallelZones::open(store)?;
        let mut entries = HashMap::new();
        for info in zones.zones() {
            let origin =
                name_from_rle(&info.origin).map_err(|_| ParallelError::InvalidArgument {
                    field: "catalog origin",
                })?;
            entries.insert(
                origin.clone(),
                CatalogEntry {
                    origin,
                    apex: info.origin,
                    zone_seq: info.zone_seq,
                    meta: info.meta,
                },
            );
        }
        cache.entries = entries;
        Ok(())
    }

    pub(crate) fn stats(&self) -> Arc<ZoneFileStats> {
        Arc::clone(&self.stats)
    }

    /// Режим коммита с учётом липкого `Sync` файла.
    pub(crate) fn effective_requested(&self) -> SyncModeV2 {
        let effective = self.store.effective_mode();
        if self.requested.durability_rank() < effective.durability_rank() {
            effective
        } else {
            self.requested
        }
    }

    /// Явный `sync()` файла.
    pub(crate) fn sync(&self) -> Result<(), ZoneFileSourceError> {
        let _gate = self
            .durability_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.store
            .sync()
            .map(|_| ())
            .map_err(|error| file_error(&self.path, "sync", &error))
    }

    /// Счётчики v2 для `/metrics`.
    pub(crate) fn metrics(&self) -> ZoneFileMetrics {
        self.stats.metrics(Some(&self.store))
    }

    /// Метаданные всех зон (голова читается live).
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn list_zones(&self) -> Result<Vec<ZoneEntry>, String> {
        let entries: Vec<CatalogEntry> = {
            let cache = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
            cache.entries.values().cloned().collect()
        };
        let mut zones = Vec::with_capacity(entries.len());
        for entry in entries {
            if let Some(zone) = self.head_entry(entry) {
                zones.push(zone);
            }
        }
        zones.sort_by_key(|zone| zone.zone_seq);
        Ok(zones)
    }

    /// Читает голову зоны, пережидая окно публикации (`PublishedHead` seqlock).
    ///
    /// `zone_head` возвращает `None` и для пустого слота, и для нестабильного
    /// чтения; для зоны из каталога второе — кратковременная гонка с коммитом.
    fn stable_head(&self, zone: u32) -> Option<pulse_zonefile::parallel::RootEntry> {
        for attempt in 0..HEAD_RETRIES {
            if let Some(head) = self.store.zone_head(zone) {
                return Some(head);
            }
            if attempt < 8 {
                std::thread::yield_now();
            } else {
                std::thread::sleep(Duration::from_micros(50));
            }
        }
        None
    }

    /// Метаданные зоны по origin.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn zone_entry(&self, origin: &Name) -> Result<Option<ZoneEntry>, String> {
        let entry = {
            let cache = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
            cache.entries.get(origin).cloned()
        };
        let Some(entry) = entry else {
            return Ok(None);
        };
        Ok(self.head_entry(entry))
    }

    fn head_entry(&self, entry: CatalogEntry) -> Option<ZoneEntry> {
        let head = self.stable_head(entry.zone_seq)?;
        if head.is_tombstone() {
            return None;
        }
        Some(ZoneEntry {
            origin: entry.origin,
            apex: entry.apex,
            zone_seq: entry.zone_seq,
            version: head.version,
            soa_serial: head.soa_serial,
            rrset_count: head.rrset_count,
            state: head.state,
            flags: entry.meta.kind_flags,
            default_ttl: entry.meta.default_ttl,
            denial: entry.meta.denial,
            created_unix_ns: entry.meta.created_unix_ns,
            updated_unix_ns: entry.meta.updated_unix_ns,
        })
    }

    fn zone_seq(&self, origin: &Name) -> Option<(NameRle, u32)> {
        let cache = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        cache
            .entries
            .get(origin)
            .map(|entry| (entry.apex, entry.zone_seq))
    }

    /// Открывает writer зоны (lease удерживается до `Drop`).
    pub(crate) fn open_writer(&self, origin: &Name) -> Result<ParallelZone<'_>, String> {
        let (apex, zone_seq) = self
            .zone_seq(origin)
            .ok_or_else(|| format!("zone {origin}: not found"))?;
        ParallelZone::open_uncached(&self.store, apex, zone_seq)
            .map_err(|error| self.error("open writer", &error))
    }

    /// Коммитит writer в настроенном режиме (`per-zone` или `group`).
    pub(crate) fn commit_writer(
        &self,
        writer: &mut ParallelZone<'_>,
    ) -> Result<CommitOutcome, String> {
        let _gate = self
            .durability_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let durability = self.effective_requested();
        let outcome = match self.commit_mode {
            CommitMode::PerZone => writer.commit_with(durability),
            CommitMode::Group => {
                let committer = self.committer.as_ref().ok_or_else(|| {
                    "group commit mode is enabled but the coordinator is stopped".to_owned()
                })?;
                writer.commit_via_with(committer, durability)
            }
        };
        match outcome {
            Ok(outcome) => {
                self.stats.commit_ok();
                Ok(outcome)
            }
            Err(error) => {
                self.stats.commit_failed();
                Err(self.error("commit", &error))
            }
        }
    }

    /// Создаёт зону с метаданными; `origin` не должен существовать.
    pub(crate) fn create_zone(
        &self,
        origin: &Name,
        kind: ZoneKind,
        default_ttl: Ttl,
        denial: Denial,
    ) -> Result<ZoneEntry, String> {
        let apex = name_to_rle(origin).map_err(|error| error.to_string())?;
        let mut cache = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        let mut zones =
            ParallelZones::open(&self.store).map_err(|error| self.error("open catalog", &error))?;
        if zones.zone_seq(&apex).is_some() {
            return Err(format!("zone {origin} already exists"));
        }
        let now = now_unix_ns();
        let meta = ZoneMetaV2 {
            kind_flags: kind_flags(kind),
            default_ttl: default_ttl.as_u32(),
            denial: denial_to_u8(denial),
            created_unix_ns: now,
            updated_unix_ns: now,
        };
        let zone_seq = zones
            .create_zone_with_meta(&apex, ZoneCreateMeta { soa_serial: 1 }, meta)
            .map_err(|error| self.error("create zone", &error))?;
        let entry = CatalogEntry {
            origin: origin.clone(),
            apex,
            zone_seq,
            meta,
        };
        cache.entries.insert(origin.clone(), entry.clone());
        self.head_entry(entry)
            .ok_or_else(|| format!("created zone {origin} has no published head"))
    }

    /// Обновляет вид/TTL/denial зоны (коммит каталога).
    pub(crate) fn update_zone_meta(
        &self,
        origin: &Name,
        kind: ZoneKind,
        default_ttl: Ttl,
        denial: Denial,
    ) -> Result<(), String> {
        let apex = name_to_rle(origin).map_err(|error| error.to_string())?;
        let mut cache = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        let mut zones =
            ParallelZones::open(&self.store).map_err(|error| self.error("open catalog", &error))?;
        let Some(mut meta) = zones.zone_meta(&apex) else {
            return Err(format!("zone {origin}: not found"));
        };
        meta.kind_flags = kind_flags(kind);
        meta.default_ttl = default_ttl.as_u32();
        meta.denial = denial_to_u8(denial);
        meta.updated_unix_ns = now_unix_ns();
        zones
            .set_zone_meta(&apex, meta)
            .map_err(|error| self.error("update zone metadata", &error))?;
        if let Some(entry) = cache.entries.get_mut(origin) {
            entry.meta = meta;
        }
        Ok(())
    }

    /// Удаляет зону: durable tombstone и очистка каталога.
    pub(crate) fn delete_zone(&self, origin: &Name) -> Result<(), String> {
        let apex = name_to_rle(origin).map_err(|error| error.to_string())?;
        let mut cache = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        let mut zones =
            ParallelZones::open(&self.store).map_err(|error| self.error("open catalog", &error))?;
        if zones.zone_seq(&apex).is_none() {
            return Err(format!("zone {origin}: not found"));
        }
        zones
            .delete_zone(&apex)
            .map_err(|error| self.error("delete zone", &error))?;
        // Tombstone должен стать durable до очистки каталога (§5.6): иначе
        // `gc_catalog` не имеет права удалять запись, и повторное создание
        // origin упирается в занятый слот.
        self.sync().map_err(|error| error.to_string())?;
        zones
            .gc_catalog()
            .map_err(|error| self.error("gc catalog", &error))?;
        cache.entries.remove(origin);
        Ok(())
    }

    /// Полностью заменяет содержимое зоны (import/sign/secondary).
    ///
    /// Если зоны нет — создаёт её с переданными метаданными. Существующая зона
    /// сохраняет `zone_seq` и tombstone не создаёт: все имена удаляются и
    /// записываются заново в одной транзакции.
    pub(crate) fn replace_zone(
        &self,
        origin: &Name,
        kind: ZoneKind,
        default_ttl: Ttl,
        denial: Denial,
        rrsets: &[Rrset],
        nodes: &[Name],
    ) -> Result<(), String> {
        let exists = self.zone_entry(origin)?.is_some();
        if exists {
            self.update_zone_meta(origin, kind, default_ttl, denial)?;
        } else {
            self.create_zone(origin, kind, default_ttl, denial)?;
        }
        let soa_serial = rrsets
            .iter()
            .find(|rrset| rrset.rr_type() == Rtype::SOA)
            .and_then(|rrset| match rrset.rdatas().first() {
                Some(Rdata::Soa(soa)) => Some(soa.serial.as_u32()),
                _ => None,
            });
        let mut writer = self.open_writer(origin)?;
        let existing = writer
            .records()
            .map_err(|error| self.error("read zone", &error))?;
        let mut owners = Vec::new();
        for record in &existing {
            if !owners.contains(&record.name) {
                owners.push(record.name);
            }
        }
        for owner in owners {
            writer
                .delete_name(&owner)
                .map_err(|error| self.error("clear zone", &error))?;
        }
        for rrset in rrsets {
            write_rrset(&mut writer, rrset)?;
        }
        let mut written: Vec<NameRle> = rrsets
            .iter()
            .filter_map(|r| name_to_rle(r.owner()).ok())
            .collect();
        for node in nodes {
            if rrsets.iter().any(|rrset| rrset.owner() == node) {
                continue;
            }
            let node_rle = name_to_rle(node).map_err(|error| error.to_string())?;
            if written.contains(&node_rle) {
                continue;
            }
            writer
                .ensure_empty_node(&node_rle)
                .map_err(|error| self.error("write empty node", &error))?;
            written.push(node_rle);
        }
        if let Some(serial) = soa_serial {
            writer.set_soa_serial(serial);
        }
        let _ = self.commit_writer(&mut writer)?;
        Ok(())
    }

    /// Снимок зоны для transfer/secondary (материализуется только здесь).
    pub(crate) fn zone_snapshot(&self, origin: &Name) -> Result<Option<ZoneSnapshot>, String> {
        let Some(entry) = self.zone_entry(origin)? else {
            return Ok(None);
        };
        let records = self.zone_records(&entry)?;
        let mut zone_records = Vec::with_capacity(records.len());
        let mut has_soa = false;
        for record in records {
            has_soa |= record.rr_type() == Rtype::SOA;
            for rdata in record.rdatas() {
                zone_records.push(
                    pulse_dns::Record::new(
                        record.owner().clone(),
                        record.rr_type(),
                        Rclass::IN,
                        record.ttl(),
                        rdata.clone(),
                    )
                    .map_err(|error| format!("zone {origin}: bad record: {error}"))?,
                );
            }
        }
        if !has_soa {
            return Ok(None);
        }
        ZoneSnapshot::new(origin.clone(), zone_records)
            .map(Some)
            .map_err(|error| format!("zone {origin}: cannot build transfer snapshot: {error}"))
    }

    /// Все RRset зоны в каноническом порядке.
    pub(crate) fn zone_rrsets(&self, origin: &Name) -> Result<Vec<Rrset>, String> {
        let Some(entry) = self.zone_entry(origin)? else {
            return Err(format!("zone {origin}: not found"));
        };
        self.zone_records(&entry)
    }

    fn zone_records(&self, entry: &ZoneEntry) -> Result<Vec<Rrset>, String> {
        let records = self.read_records(entry)?;
        group_records(&entry.origin, records)
    }

    fn read_records(&self, entry: &ZoneEntry) -> Result<Vec<RrsetRecord>, String> {
        self.with_reader(entry, |reader| {
            reader
                .records()
                .map_err(|error| self.error("read zone records", &error))
        })
    }

    /// Точечный `lookup` RRset (RRSIG — все/заданный subtype).
    pub(crate) fn lookup(
        &self,
        origin: &Name,
        name: &Name,
        rr_type: Rtype,
    ) -> Result<Option<StoredRrsetView>, String> {
        let Some(entry) = self.zone_entry(origin)? else {
            return Err(format!("zone {origin}: not found"));
        };
        let owner = name_to_rle(name).map_err(|error| error.to_string())?;
        self.stats.lookup();
        self.with_reader(&entry, |reader| {
            let mut records = Vec::new();
            if rr_type == Rtype::RRSIG {
                records = reader
                    .lookup_all(&owner, rr_type.as_u16())
                    .map_err(|error| self.error("lookup RRSIG", &error))?;
            } else if let Some(record) = reader
                .lookup(&owner, rr_type.as_u16(), 0)
                .map_err(|error| self.error("lookup RRset", &error))?
            {
                records.push(record);
            }
            Ok(merge_stored(records))
        })
    }

    /// `RRSIG` имени, покрывающий `covered`.
    pub(crate) fn lookup_rrsig(
        &self,
        origin: &Name,
        name: &Name,
        covered: Rtype,
    ) -> Result<Option<StoredRrsetView>, String> {
        let Some(entry) = self.zone_entry(origin)? else {
            return Err(format!("zone {origin}: not found"));
        };
        let owner = name_to_rle(name).map_err(|error| error.to_string())?;
        self.stats.lookup();
        self.with_reader(&entry, |reader| {
            let records = reader
                .lookup_all(&owner, Rtype::RRSIG.as_u16())
                .map_err(|error| self.error("lookup RRSIG", &error))?;
            let filtered: Vec<RrsetRecord> = records
                .into_iter()
                .filter(|record| record.subtype == covered.as_u16())
                .collect();
            Ok(merge_stored(filtered))
        })
    }

    /// Состояние имени (`T_NODE`, ENT/cut).
    pub(crate) fn node(&self, origin: &Name, name: &Name) -> Result<Option<NodeInfo>, String> {
        let Some(entry) = self.zone_entry(origin)? else {
            return Ok(None);
        };
        let owner = name_to_rle(name).map_err(|error| error.to_string())?;
        self.with_reader(&entry, |reader| {
            reader
                .node(&owner)
                .map(Some)
                .map_err(|error| self.error("read node", &error))
        })
    }

    /// Типы RRset имени (для проверки CNAME/DNAME-конфликтов).
    pub(crate) fn owner_types(&self, origin: &Name, owner: &Name) -> Result<Vec<Rtype>, String> {
        let Some(entry) = self.zone_entry(origin)? else {
            return Ok(Vec::new());
        };
        let owner_rle = name_to_rle(owner).map_err(|error| error.to_string())?;
        let records = self.read_records(&entry)?;
        let mut types = BTreeMap::new();
        for record in records {
            if record.name == owner_rle && record.rr_type != 0 {
                types.insert(record.rr_type, Rtype::from_u16(record.rr_type));
            }
        }
        Ok(types.into_values().collect())
    }

    /// NSEC-записи зоны (для denial-of-existence).
    pub(crate) fn nsec_records(&self, origin: &Name) -> Result<Vec<Rrset>, String> {
        let Some(entry) = self.zone_entry(origin)? else {
            return Ok(Vec::new());
        };
        let records = self.read_records(&entry)?;
        let rrsets = group_records(&entry.origin, records)?;
        Ok(rrsets
            .into_iter()
            .filter(|rrset| rrset.rr_type() == Rtype::NSEC)
            .collect())
    }

    /// Выполняет чтение под стабильным пином зоны.
    fn with_reader<T>(
        &self,
        entry: &ZoneEntry,
        f: impl FnOnce(&ZoneReader<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        self.stats.pin();
        // Слоты читателей ограничены (1024). Под пиком параллельных запросов
        // слот освобождается за микросекунды — короткий retry вместо отказа.
        let mut reader_attempts = 0_u32;
        let reader = loop {
            match self.store.reader() {
                Ok(reader) => break reader,
                Err(ParallelError::TooManyReaders) if reader_attempts < READ_RETRIES => {
                    reader_attempts = reader_attempts.saturating_add(1);
                    thread::sleep(Duration::from_micros(50));
                }
                Err(error) => return Err(self.error("reader", &error)),
            }
        };
        let mut attempt = 0_u32;
        loop {
            match ZoneReader::open(&self.store, &reader, entry.apex, entry.zone_seq) {
                Ok(zone) => return f(&zone),
                Err(ParallelError::ReaderContended) if attempt < READ_RETRIES => {
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => return Err(self.error("zone snapshot", &error)),
            }
        }
    }

    /// Ошибка стора с путём.
    pub(crate) fn error(&self, action: &str, error: &ParallelError) -> String {
        format!("zone file {}: {action}: {error}", self.path.display())
    }

    /// Конвертирует v1-файл в текущий v2-стор.
    ///
    /// Читает все зоны v1 (дерево, `T_NODE`/ENT и метаданные), создаёт зоны
    /// v2 и коммитит их с `Sync`. `dst` должен быть новым/пустым файлом.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn convert_from_v1(
        from: &Path,
        to: &Path,
        map_size: u64,
        durability: SyncModeV2,
    ) -> Result<(usize, usize), ZoneFileSourceError> {
        if !is_v1_file(from)? {
            return Err(ZoneFileSourceError::new(format!(
                "{} is not a pulse-zonefile v1 file",
                from.display()
            )));
        }
        if let Ok(meta) = std::fs::metadata(to) {
            if meta.len() != 0 {
                return Err(ZoneFileSourceError::new(format!(
                    "destination {} already exists and is not empty",
                    to.display()
                )));
            }
            std::fs::remove_file(to).map_err(|error| {
                ZoneFileSourceError::new(format!(
                    "cannot initialise empty destination {}: {error}",
                    to.display()
                ))
            })?;
        }
        let source = pulse_zonefile::ZoneFile::open(
            from,
            pulse_zonefile::OpenConfig {
                lock_mode: pulse_zonefile::LockMode::Reader,
                ..pulse_zonefile::OpenConfig::default()
            },
        )
        .map_err(|error| {
            ZoneFileSourceError::new(format!(
                "cannot open v1 zone file {}: {error}",
                from.display()
            ))
        })?;
        let txnid = source.txnid();
        let zones_v1 = source.zones_at(txnid).map_err(|error| {
            ZoneFileSourceError::new(format!(
                "cannot enumerate v1 zones in {}: {error}",
                from.display()
            ))
        })?;
        let store = ParallelStore::create(
            to,
            StoreConfig {
                page_count_max: page_count(map_size),
                max_zones: MAX_ZONES,
                sync_mode: durability,
                ..StoreConfig::default()
            },
        )
        .map_err(|error| file_error(to, "create", &error))?;
        let mut zones =
            ParallelZones::open(&store).map_err(|error| file_error(to, "open catalog", &error))?;
        let mut zone_count = 0_usize;
        let mut record_count = 0_usize;
        for (apex, entry) in zones_v1 {
            let meta = source
                .zone_meta_at(txnid, &apex)
                .map_err(|error| {
                    ZoneFileSourceError::new(format!(
                        "cannot read v1 zone metadata for {}: {error}",
                        display_name(&apex)
                    ))
                })?
                .unwrap_or_default();
            zones
                .create_zone_with_meta(
                    &apex,
                    ZoneCreateMeta {
                        soa_serial: entry.soa_serial & 0x7FFF_FFFF,
                    },
                    ZoneMetaV2 {
                        kind_flags: entry.flags
                            & (ZONE_KIND_FLAG_FORWARD | ZONE_KIND_FLAG_SECONDARY),
                        default_ttl: meta.default_ttl,
                        denial: meta.denial,
                        created_unix_ns: entry.last_change_unix_ns,
                        updated_unix_ns: entry.last_change_unix_ns,
                    },
                )
                .map_err(|error| file_error(to, "create zone", &error))?;
            let zone_seq = zones.zone_seq(&apex).ok_or_else(|| {
                ZoneFileSourceError::new(format!(
                    "created zone {} is missing from the catalog",
                    display_name(&apex)
                ))
            })?;
            let mut writer =
                ParallelZone::open_uncached(&store, apex, zone_seq).map_err(|error| {
                    ZoneFileSourceError::new(format!(
                        "cannot open v2 writer for {}: {error}",
                        display_name(&apex)
                    ))
                })?;
            let items = source.zone_items_at(txnid, &apex).map_err(|error| {
                ZoneFileSourceError::new(format!(
                    "cannot read v1 zone {}: {error}",
                    display_name(&apex)
                ))
            })?;
            let mut nodes = Vec::new();
            for item in items {
                let item = item.map_err(|error| {
                    ZoneFileSourceError::new(format!(
                        "cannot read v1 zone item in {}: {error}",
                        display_name(&apex)
                    ))
                })?;
                match item.value {
                    pulse_zonefile::ZoneItemValue::Node { .. } => nodes.push(item.name),
                    pulse_zonefile::ZoneItemValue::Rrset(view) => {
                        let data =
                            RrsetData::new(view.ttl, view.flags, view.rdata).map_err(|error| {
                                ZoneFileSourceError::new(format!(
                                    "cannot encode RRset {}: {error}",
                                    display_name(&item.name)
                                ))
                            })?;
                        writer
                            .upsert_rrset(&item.name, item.rr_type, item.subtype, &data)
                            .map_err(|error| {
                                ZoneFileSourceError::new(format!(
                                    "cannot write RRset {}: {error}",
                                    display_name(&item.name)
                                ))
                            })?;
                        record_count = record_count.saturating_add(1);
                    }
                }
            }
            for node in nodes {
                writer.ensure_empty_node(&node).map_err(|error| {
                    ZoneFileSourceError::new(format!(
                        "cannot write empty node {}: {error}",
                        display_name(&node)
                    ))
                })?;
            }
            writer.set_soa_serial(entry.soa_serial);
            writer.commit_with(SyncModeV2::Sync).map_err(|error| {
                ZoneFileSourceError::new(format!(
                    "cannot commit zone {}: {error}",
                    display_name(&apex)
                ))
            })?;
            zone_count = zone_count.saturating_add(1);
        }
        store
            .sync()
            .map_err(|error| file_error(to, "sync", &error))?;
        Ok((zone_count, record_count))
    }
}

impl Drop for ZoneStore {
    fn drop(&mut self) {
        self.maintenance_stop.store(true, Ordering::Release);
        if let Some(handle) = self
            .maintenance
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = handle.join();
        }
    }
}

/// Фоновый GC: пересчитывает `MP`, освобождает chain-страницы и делает
/// `sync()` при заполнении файла наполовину.
///
/// `sync()` нужен, потому что страницы, освобождённые в `Flush`/`Memory`,
/// переиспользуются только после роста durable-версии зоны (§7.2). При низком
/// давлении лишних `fdatasync` нет: GC только пересчитывает пины.
fn maintenance_loop(
    store: &Arc<ParallelStore>,
    path: &Path,
    stop: &AtomicBool,
    durability_gate: &Mutex<()>,
) {
    let limit = u64::from(store.geometry().page_count_max()).max(1);
    while !stop.load(Ordering::Acquire) {
        let _ = store.gc_pass();
        let high_water = store.high_water();
        if store.fatal().is_none() && high_water.saturating_mul(8) >= limit {
            let _gate = durability_gate
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Err(error) = store.sync() {
                crate::logging::warn(
                    "zonefile",
                    &format!(
                        "zone file {}: background sync failed: {error}",
                        path.display()
                    ),
                );
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// `true`, если файл начинается с сигнатуры v1.
fn is_v1_file(path: &Path) -> Result<bool, ZoneFileSourceError> {
    let mut file = std::fs::File::open(path).map_err(|error| {
        ZoneFileSourceError::new(format!("cannot read zone file {}: {error}", path.display()))
    })?;
    let mut magic = [0_u8; 8];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(&magic == V1_MAGIC),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(ZoneFileSourceError::new(format!(
            "cannot read zone file {}: {error}",
            path.display()
        ))),
    }
}

fn page_count(map_size: u64) -> u32 {
    let pages = map_size / u64::from(pulse_zonefile::parallel::V2_PAGE_BYTES);
    u32::try_from(pages).unwrap_or(u32::MAX).max(1024)
}

fn display_name(name: &NameRle) -> String {
    name_from_rle(name).map_or_else(|_| "<invalid>".to_owned(), |name| name.to_string())
}

fn merge_stored(records: Vec<RrsetRecord>) -> Option<StoredRrsetView> {
    let mut iter = records.into_iter();
    let first = iter.next()?;
    let mut ttl = first.ttl;
    let mut flags = first.flags;
    let mut rdata = first.rdata;
    for record in iter {
        ttl = ttl.min(record.ttl);
        flags |= record.flags;
        rdata.extend(record.rdata);
    }
    Some(StoredRrsetView { ttl, flags, rdata })
}

fn group_records(origin: &Name, records: Vec<RrsetRecord>) -> Result<Vec<Rrset>, String> {
    let mut groups: BTreeMap<(String, u16), (Name, u32, Vec<Rdata>)> = BTreeMap::new();
    for record in records {
        let owner = name_from_rle(&record.name).map_err(|error| error.to_string())?;
        let rr_type = Rtype::from_u16(record.rr_type);
        let key = (owner.to_string(), rr_type.as_u16());
        let entry = groups
            .entry(key)
            .or_insert_with(|| (owner, record.ttl, Vec::new()));
        if rr_type == Rtype::RRSIG {
            entry.1 = entry.1.min(record.ttl);
        } else if entry.1 != record.ttl {
            return Err(format!(
                "zone {origin}: TTL mismatch for {} {rr_type}",
                entry.0
            ));
        }
        for bytes in record.rdata {
            entry
                .2
                .push(Rdata::from_wire(rr_type, &bytes).map_err(|error| {
                    format!(
                        "zone {origin}: {} {rr_type}: invalid stored rdata: {error}",
                        entry.0
                    )
                })?);
        }
    }
    let mut out = Vec::with_capacity(groups.len());
    for ((_owner, rr_type), (owner, ttl, rdata)) in groups {
        let rr_type = Rtype::from_u16(rr_type);
        let ttl = Ttl::new(ttl).map_err(|error| format!("zone {origin}: {owner}: {error}"))?;
        out.push(
            Rrset::new(owner.clone(), rr_type, Rclass::IN, ttl, rdata)
                .map_err(|error| format!("zone {origin}: {owner} {rr_type}: {error}"))?,
        );
    }
    Ok(out)
}

/// Добавляет RRset в v2-writer (RRSIG раскладывается по subtype).
pub(crate) fn write_rrset(writer: &mut ParallelZone<'_>, rrset: &Rrset) -> Result<(), String> {
    let owner = name_to_rle(rrset.owner()).map_err(|error| error.to_string())?;
    let ttl = rrset.ttl().as_u32();
    let mut groups: BTreeMap<u16, Vec<Vec<u8>>> = BTreeMap::new();
    for rdata in rrset.rdatas() {
        let subtype = if rrset.rr_type() == Rtype::RRSIG {
            match rdata {
                Rdata::Rrsig(signature) => signature.type_covered().as_u16(),
                _ => 0,
            }
        } else {
            0
        };
        groups
            .entry(subtype)
            .or_default()
            .push(rdata.to_canonical_wire());
    }
    for (subtype, rdata) in groups {
        let data = RrsetData::new(ttl, 0, rdata).map_err(|error| {
            format!(
                "cannot encode RRset {} {}: {error}",
                rrset.owner(),
                rrset.rr_type()
            )
        })?;
        writer
            .upsert_rrset(&owner, rrset.rr_type().as_u16(), subtype, &data)
            .map_err(|error| {
                format!(
                    "cannot write RRset {} {}: {error}",
                    rrset.owner(),
                    rrset.rr_type()
                )
            })?;
    }
    Ok(())
}

/// `ZoneView` поверх v2: точечные чтения, ноль материализации зоны.
pub(crate) struct FileZoneView {
    store: Arc<ZoneStore>,
    origin: Name,
    soa: Option<Rrset>,
    ns: Option<Rrset>,
    state: ServerZoneState,
}

impl FileZoneView {
    /// Строит view зоны, читая apex SOA/NS и состояние.
    pub(crate) fn new(
        store: Arc<ZoneStore>,
        entry: &ZoneEntry,
        state: ServerZoneState,
    ) -> Result<Self, String> {
        let soa = store
            .lookup(&entry.origin, &entry.origin, Rtype::SOA)?
            .map(|view| rrset_from_stored(&entry.origin, Rtype::SOA, &view))
            .transpose()
            .map_err(|error| error.to_string())?;
        let ns = store
            .lookup(&entry.origin, &entry.origin, Rtype::NS)?
            .map(|view| rrset_from_stored(&entry.origin, Rtype::NS, &view))
            .transpose()
            .map_err(|error| error.to_string())?;
        // Как и v1 (`zone_is_serving`), зона обслуживается только при наличии
        // apex SOA и NS; пустая/недособранная зона остаётся `Initializing`.
        let state = if state == ServerZoneState::Serving && (soa.is_none() || ns.is_none()) {
            ServerZoneState::Initializing
        } else {
            state
        };
        Ok(Self {
            store,
            origin: entry.origin.clone(),
            soa,
            ns,
            state,
        })
    }

    fn lookup_stored(&self, name: &Name, rr_type: Rtype) -> Option<Rrset> {
        let stored = self
            .store
            .lookup(&self.origin, name, rr_type)
            .ok()
            .flatten()?;
        rrset_from_stored(name, rr_type, &stored).ok()
    }

    fn node(&self, name: &Name) -> Option<NodeInfo> {
        self.store.node(&self.origin, name).ok().flatten()
    }

    fn rrsig(&self, name: &Name, covered: Rtype) -> Option<Rrset> {
        let stored = self
            .store
            .lookup_rrsig(&self.origin, name, covered)
            .ok()
            .flatten()?;
        rrset_from_stored(name, Rtype::RRSIG, &stored).ok()
    }

    fn delegation_of(&self, name: &Name) -> Option<Name> {
        let mut current = Some(name.clone());
        while let Some(candidate) = current {
            if candidate == self.origin {
                return None;
            }
            if !candidate.is_subdomain_of(&self.origin) {
                return None;
            }
            if self.is_delegation(&candidate) {
                return Some(candidate);
            }
            current = candidate.parent();
        }
        None
    }
}

impl ZoneView for FileZoneView {
    fn origin(&self) -> &Name {
        &self.origin
    }

    fn apex(&self) -> &Name {
        &self.origin
    }

    fn soa(&self) -> Option<&Rrset> {
        self.soa.as_ref()
    }

    fn ns(&self) -> Option<&Rrset> {
        self.ns.as_ref()
    }

    fn class(&self) -> Rclass {
        Rclass::IN
    }

    fn state(&self) -> ServerZoneState {
        self.state
    }

    fn lookup(&self, name: &Name, rr_type: Rtype) -> LookupOutcome {
        if !name.is_subdomain_of(&self.origin) {
            return LookupOutcome::ZoneNotFound;
        }
        if let Some(cut) = self.delegation_of(name) {
            if &cut == name {
                if rr_type == Rtype::DS {
                    return self
                        .lookup_stored(name, Rtype::DS)
                        .map_or(LookupOutcome::NoData, LookupOutcome::Answer);
                }
                let Some(ns) = self.lookup_stored(name, Rtype::NS) else {
                    return LookupOutcome::NoData;
                };
                return LookupOutcome::Delegation {
                    ns,
                    ds: self.lookup_stored(name, Rtype::DS),
                };
            }
            return LookupOutcome::Referral;
        }
        if let Some(rrset) = self.lookup_stored(name, rr_type) {
            return LookupOutcome::Answer(rrset);
        }
        if rr_type != Rtype::CNAME
            && let Some(cname) = self.lookup_stored(name, Rtype::CNAME)
        {
            let target = cname.rdatas().iter().find_map(|rdata| match rdata {
                Rdata::Cname(target) => Some(target.clone()),
                _ => None,
            });
            if let Some(target) = target {
                return LookupOutcome::Cname(cname, target);
            }
        }
        if self.node(name).is_some_and(|node| node.exists) {
            LookupOutcome::NoData
        } else {
            LookupOutcome::NxDomain
        }
    }

    fn lookup_all_rrsig(&self, name: &Name, covered: Rtype) -> Vec<Rrset> {
        if !name.is_subdomain_of(&self.origin) {
            return Vec::new();
        }
        self.rrsig(name, covered).into_iter().collect()
    }

    fn nsec_at(&self, name: &Name) -> Option<Rrset> {
        if !name.is_subdomain_of(&self.origin) {
            return None;
        }
        self.lookup_stored(name, Rtype::NSEC)
    }

    fn nsec_cover(&self, name: &Name) -> Option<Rrset> {
        if !name.is_subdomain_of(&self.origin) {
            return None;
        }
        let _ = self.lookup_stored(&self.origin, Rtype::NSEC)?;
        for rrset in self.store.nsec_records(&self.origin).ok()? {
            let owner = rrset.owner();
            let Some(next) = rrset.rdatas().iter().find_map(|rdata| match rdata {
                Rdata::Nsec(nsec) => Some(nsec.next_domain().clone()),
                _ => None,
            }) else {
                continue;
            };
            if nsec_covers(owner, &next, name) {
                return Some(rrset);
            }
        }
        None
    }

    fn is_delegation(&self, name: &Name) -> bool {
        if name == &self.origin || !name.is_subdomain_of(&self.origin) {
            return false;
        }
        self.lookup_stored(name, Rtype::NS).is_some()
            && self.lookup_stored(name, Rtype::SOA).is_none()
    }

    fn glue(&self, name: &Name) -> Vec<Rrset> {
        if !name.is_subdomain_of(&self.origin) {
            return Vec::new();
        }
        [Rtype::A, Rtype::AAAA]
            .into_iter()
            .filter_map(|rr_type| self.lookup_stored(name, rr_type))
            .collect()
    }

    fn node_exists(&self, name: &Name) -> bool {
        name.is_subdomain_of(&self.origin) && self.node(name).is_some_and(|node| node.exists)
    }
}

fn nsec_covers(owner: &Name, next: &Name, name: &Name) -> bool {
    use std::cmp::Ordering;
    if name == owner {
        return false;
    }
    match owner.cmp_canonical(next) {
        Ordering::Less => {
            owner.cmp_canonical(name) == Ordering::Less
                && name.cmp_canonical(next) == Ordering::Less
        }
        Ordering::Greater | Ordering::Equal => {
            owner.cmp_canonical(name) == Ordering::Less
                || name.cmp_canonical(next) == Ordering::Less
        }
    }
}

/// Конвертирует сохранённый RRset (RDATA bytes) в доменный `Rrset`.
pub(crate) fn rrset_from_stored(
    owner: &Name,
    rr_type: Rtype,
    view: &StoredRrsetView,
) -> Result<Rrset, ZoneFileSourceError> {
    let ttl = Ttl::new(view.ttl).map_err(|error| {
        ZoneFileSourceError::new(format!("{owner} {rr_type}: invalid stored ttl: {error}"))
    })?;
    let mut rdata = Vec::with_capacity(view.rdata.len());
    for bytes in &view.rdata {
        rdata.push(Rdata::from_wire(rr_type, bytes).map_err(|error| {
            ZoneFileSourceError::new(format!("{owner} {rr_type}: invalid stored rdata: {error}"))
        })?);
    }
    Rrset::new(owner.clone(), rr_type, Rclass::IN, ttl, rdata).map_err(|error| {
        ZoneFileSourceError::new(format!("{owner} {rr_type}: invalid stored RRset: {error}"))
    })
}

pub(crate) fn name_to_rle(name: &Name) -> Result<NameRle, ZoneFileSourceError> {
    NameRle::from_wire(name.as_wire())
        .map_err(|error| ZoneFileSourceError::new(format!("invalid DNS name {name}: {error}")))
}

pub(crate) fn name_from_rle(rle: &NameRle) -> Result<Name, ZoneFileSourceError> {
    let mut buffer = [0_u8; 255];
    let len = rle
        .write_wire(&mut buffer)
        .map_err(|error| ZoneFileSourceError::new(format!("cannot encode stored name: {error}")))?;
    Name::from_wire(&buffer[..len])
        .map_err(|error| ZoneFileSourceError::new(format!("invalid stored DNS name: {error}")))
}

pub(crate) fn denial_to_u8(denial: Denial) -> u8 {
    match denial {
        Denial::Nsec => 0,
        Denial::Nsec3 => 1,
    }
}

pub(crate) fn denial_from_u8(value: u8) -> Option<Denial> {
    match value {
        0 => Some(Denial::Nsec),
        1 => Some(Denial::Nsec3),
        _ => None,
    }
}

pub(crate) fn kind_flags(kind: ZoneKind) -> u16 {
    match kind {
        ZoneKind::Primary => 0,
        ZoneKind::Secondary => ZONE_KIND_FLAG_SECONDARY,
        ZoneKind::Forward => ZONE_KIND_FLAG_FORWARD,
    }
}

pub(crate) fn kind_from_flags(flags: u16) -> ZoneKind {
    if flags & ZONE_KIND_FLAG_FORWARD != 0 {
        ZoneKind::Forward
    } else if flags & ZONE_KIND_FLAG_SECONDARY != 0 {
        ZoneKind::Secondary
    } else {
        ZoneKind::Primary
    }
}

pub(crate) fn system_time_from_unix_ns(ns: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_nanos(ns))
        .unwrap_or(UNIX_EPOCH)
}

/// Текущее время unix ns.
pub(crate) fn now_unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        })
}

pub(crate) fn file_error(path: &Path, action: &str, error: &ParallelError) -> ZoneFileSourceError {
    ZoneFileSourceError::new(format!("zone file {}: {action}: {error}", path.display()))
}
