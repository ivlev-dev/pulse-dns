//! Доступ к `pulse-zonefile` как к единственному источнику истины.
//!
//! DNS-ответы читаются через [`FileZoneView`]: каждый движок держит один
//! пиновый [`Snapshot`] и выполняет точечные поиски в mmap, не материализуя
//! зону в памяти. REST-мутации пишут в тот же файл и коммитят транзакцию;
//! после коммита движок пересобирается (метаданные зон, не данные).

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pulse_api::ZoneFileMetrics;
use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Ttl};
use pulse_server::{LookupOutcome, ZoneState as ServerZoneState, ZoneView};
use pulse_transfer::ZoneSnapshot;
use pulse_zonefile::key::NameRle;
use pulse_zonefile::tree::NodeInfo;
use pulse_zonefile::{
    CreateConfig, LockMode, OpenConfig, RrsetData, RrsetView as StoredRrsetView, Snapshot,
    SyncMode, ZoneEntry, ZoneFile, ZoneFileError, ZoneItem, ZoneItemValue, ZoneMetaBlock,
    ZoneState as FileZoneState,
};
use thiserror::Error;

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
    pub(crate) fn metrics(&self) -> ZoneFileMetrics {
        ZoneFileMetrics {
            snapshot_pins: self.snapshot_pins.load(Ordering::Relaxed),
            lookups: self.lookups.load(Ordering::Relaxed),
            commits: self.commits.load(Ordering::Relaxed),
            commit_errors: self.commit_errors.load(Ordering::Relaxed),
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

/// Открытый zonefile: единственный writer-лок процесса.
pub(crate) struct ZoneStore {
    file: RwLock<ZoneFile>,
    stats: Arc<ZoneFileStats>,
    requested: SyncMode,
    path: std::path::PathBuf,
}

impl ZoneStore {
    /// Открывает существующий файл или создаёт новый.
    pub(crate) fn open_or_create(
        path: &Path,
        map_size: u64,
        requested: SyncMode,
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
        let file = if existed {
            ZoneFile::open(
                path,
                OpenConfig {
                    lock_mode: LockMode::Writer,
                    ..OpenConfig::default()
                },
            )
        } else {
            ZoneFile::create(
                path,
                CreateConfig {
                    map_size,
                    sync_mode: requested,
                    ..CreateConfig::default()
                },
            )
        }
        .map_err(|error| file_error(path, "open", &error))?;
        Ok(Self {
            file: RwLock::new(file),
            stats: Arc::new(ZoneFileStats::default()),
            requested,
            path: path.to_path_buf(),
        })
    }

    pub(crate) fn stats(&self) -> Arc<ZoneFileStats> {
        Arc::clone(&self.stats)
    }

    /// Режим коммита с учётом липкого режима файла.
    pub(crate) fn commit_mode(&self) -> SyncMode {
        let file = self.file.read().unwrap_or_else(PoisonError::into_inner);
        let effective = file.effective_mode();
        if self.requested.durability_rank() < effective.durability_rank() {
            effective
        } else {
            self.requested
        }
    }

    /// Явный `sync()` файла.
    pub(crate) fn sync(&self) -> Result<(), ZoneFileSourceError> {
        let mut file = self.file.write().unwrap_or_else(PoisonError::into_inner);
        file.sync()
            .map(|_| ())
            .map_err(|error| file_error(&self.path, "sync", &error))
    }

    /// Собирает источник чтения: один пин снапшота + метаданные всех зон.
    pub(crate) fn source(self: &Arc<Self>) -> Result<Arc<ZoneSource>, ZoneFileSourceError> {
        let file = self.file.read().unwrap_or_else(PoisonError::into_inner);
        let snapshot = file
            .reader()
            .snapshot()
            .map_err(|error| file_error(&self.path, "snapshot", &error))?;
        self.stats.pin();
        let txnid = snapshot.txnid();
        let entries = file
            .zones_at(txnid)
            .map_err(|error| file_error(&self.path, "enumerate zones", &error))?;
        let mut zones = Vec::with_capacity(entries.len());
        for (apex, entry) in entries {
            let origin = name_from_rle(&apex).map_err(|error| {
                ZoneFileSourceError::new(format!("cannot decode origin in zonefile: {error}"))
            })?;
            let soa = file
                .lookup_rrset_at(txnid, &apex, &apex, Rtype::SOA.as_u16(), 0)
                .map_err(|error| file_error(&self.path, "read SOA", &error))?
                .map(|view| rrset_from_stored(&origin, Rtype::SOA, &view))
                .transpose()?;
            let ns = file
                .lookup_rrset_at(txnid, &apex, &apex, Rtype::NS.as_u16(), 0)
                .map_err(|error| file_error(&self.path, "read NS", &error))?
                .map(|view| rrset_from_stored(&origin, Rtype::NS, &view))
                .transpose()?;
            zones.push(ZoneMeta {
                origin,
                apex,
                entry,
                soa,
                ns,
            });
        }
        Ok(Arc::new(ZoneSource {
            store: Arc::clone(self),
            snapshot,
            zones,
        }))
    }

    /// Снимок одной зоны для secondary/IXFR. Материализует зону только на
    /// время операции записи/трансфера, не на пути DNS-ответа.
    pub(crate) fn zone_snapshot(&self, origin: &Name) -> Result<Option<ZoneSnapshot>, String> {
        let file = self.file.read().unwrap_or_else(PoisonError::into_inner);
        let txnid = file.txnid();
        let apex = name_to_rle(origin).map_err(|error| error.to_string())?;
        let Some(entry) = file
            .zone_entry_at(txnid, &apex)
            .map_err(|error| file_error(&self.path, "read zone", &error).to_string())?
        else {
            return Ok(None);
        };
        if !entry.is_live() {
            return Ok(None);
        }
        let items = file
            .zone_items_at(txnid, &apex)
            .map_err(|error| file_error(&self.path, "read zone tree", &error).to_string())?;
        let mut records = Vec::new();
        let mut has_soa = false;
        for item in items {
            let item =
                item.map_err(|error| file_error(&self.path, "read zone item", &error).to_string())?;
            let ZoneItemValue::Rrset(view) = item.value else {
                continue;
            };
            let owner = name_from_rle(&item.name).map_err(|error| error.to_string())?;
            let rr_type = Rtype::from_u16(item.rr_type);
            has_soa |= rr_type == Rtype::SOA && item.class == Rclass::IN.as_u16();
            let ttl = Ttl::new(view.ttl).map_err(|error| error.to_string())?;
            for bytes in view.rdata {
                let rdata = Rdata::from_wire(rr_type, &bytes)
                    .map_err(|error| format!("zone {origin}: bad stored rdata: {error}"))?;
                records.push(
                    pulse_dns::Record::new(owner.clone(), rr_type, Rclass::IN, ttl, rdata)
                        .map_err(|error| format!("zone {origin}: bad record: {error}"))?,
                );
            }
        }
        if !has_soa {
            return Ok(None);
        }
        ZoneSnapshot::new(origin.clone(), records)
            .map(Some)
            .map_err(|error| format!("zone {origin}: cannot build transfer snapshot: {error}"))
    }

    /// Все зоны: origin, тип и serial (дёшево, без обхода деревьев).
    pub(crate) fn zone_list(&self) -> Result<Vec<(Name, ZoneEntry)>, String> {
        let file = self.file.read().unwrap_or_else(PoisonError::into_inner);
        let txnid = file.txnid();
        let entries = file
            .zones_at(txnid)
            .map_err(|error| file_error(&self.path, "enumerate zones", &error).to_string())?;
        let mut out = Vec::with_capacity(entries.len());
        for (apex, entry) in entries {
            let origin = name_from_rle(&apex).map_err(|error| error.to_string())?;
            out.push((origin, entry));
        }
        Ok(out)
    }

    /// Метаданные зоны.
    pub(crate) fn zone_entry(&self, origin: &Name) -> Result<Option<(NameRle, ZoneEntry)>, String> {
        let file = self.file.read().unwrap_or_else(PoisonError::into_inner);
        let apex = name_to_rle(origin).map_err(|error| error.to_string())?;
        let entry = file
            .zone_entry_at(file.txnid(), &apex)
            .map_err(|error| file_error(&self.path, "read zone", &error).to_string())?;
        Ok(entry
            .filter(|entry| entry.is_live())
            .map(|entry| (apex, entry)))
    }

    /// Настройки зоны и запись каталога.
    pub(crate) fn zone_meta_block(
        &self,
        origin: &Name,
    ) -> Result<Option<(NameRle, ZoneEntry, ZoneMetaBlock)>, String> {
        let file = self.file.read().unwrap_or_else(PoisonError::into_inner);
        let txnid = file.txnid();
        let apex = name_to_rle(origin).map_err(|error| error.to_string())?;
        let Some(entry) = file
            .zone_entry_at(txnid, &apex)
            .map_err(|error| file_error(&self.path, "read zone", &error).to_string())?
            .filter(|entry| entry.is_live())
        else {
            return Ok(None);
        };
        let meta = file
            .zone_meta_at(txnid, &apex)
            .map_err(|error| file_error(&self.path, "read zone metadata", &error).to_string())?
            .unwrap_or_default();
        Ok(Some((apex, entry, meta)))
    }

    /// Читает RRset в текущем снапшоте.
    pub(crate) fn lookup(
        &self,
        origin: &Name,
        name: &Name,
        rr_type: Rtype,
    ) -> Result<Option<StoredRrsetView>, String> {
        let file = self.file.read().unwrap_or_else(PoisonError::into_inner);
        let txnid = file.txnid();
        let apex = name_to_rle(origin).map_err(|error| error.to_string())?;
        let owner = name_to_rle(name).map_err(|error| error.to_string())?;
        if rr_type == Rtype::RRSIG {
            let views = file
                .lookup_all_rrset_at(txnid, &apex, &owner, Rtype::RRSIG.as_u16())
                .map_err(|error| file_error(&self.path, "lookup RRSIG", &error).to_string())?;
            if views.is_empty() {
                return Ok(None);
            }
            let mut ttl = views.first().map_or(0, |view| view.ttl);
            let mut flags = 0;
            let mut rdata = Vec::new();
            for view in views {
                ttl = ttl.min(view.ttl);
                flags |= view.flags;
                rdata.extend(view.rdata);
            }
            return Ok(Some(StoredRrsetView { ttl, flags, rdata }));
        }
        file.lookup_rrset_at(txnid, &apex, &owner, rr_type.as_u16(), 0)
            .map_err(|error| file_error(&self.path, "lookup RRset", &error).to_string())
    }

    /// Все RRset зоны в каноническом порядке (для REST list/sign).
    pub(crate) fn zone_rrsets(&self, origin: &Name) -> Result<Vec<Rrset>, String> {
        let file = self.file.read().unwrap_or_else(PoisonError::into_inner);
        let txnid = file.txnid();
        let apex = name_to_rle(origin).map_err(|error| error.to_string())?;
        let items = file
            .zone_items_at(txnid, &apex)
            .map_err(|error| file_error(&self.path, "read zone tree", &error).to_string())?;
        collect_rrsets(origin, items, &self.path)
    }

    /// Итератор элементов зоны под текущей meta (для REST-листинга).
    pub(crate) fn with_zone_items<T>(
        &self,
        origin: &Name,
        f: impl FnOnce(&ZoneFile, u64, &NameRle, pulse_zonefile::ZoneItems<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let file = self.file.read().unwrap_or_else(PoisonError::into_inner);
        let txnid = file.txnid();
        let apex = name_to_rle(origin).map_err(|error| error.to_string())?;
        let items = file
            .zone_items_at(txnid, &apex)
            .map_err(|error| file_error(&self.path, "read zone tree", &error).to_string())?;
        f(&file, txnid, &apex, items)
    }

    /// Доступ к открытому файлу (блокировки берёт вызывающий).
    pub(crate) fn file(&self) -> &RwLock<ZoneFile> {
        &self.file
    }

    /// Ошибка файла с путём.
    pub(crate) fn error(&self, action: &str, error: &ZoneFileError) -> String {
        file_error(&self.path, action, error).to_string()
    }
}

/// Метаданные зоны, прочитанные из снапшота.
#[derive(Debug, Clone)]
pub(crate) struct ZoneMeta {
    pub(crate) origin: Name,
    pub(crate) apex: NameRle,
    pub(crate) entry: ZoneEntry,
    pub(crate) soa: Option<Rrset>,
    pub(crate) ns: Option<Rrset>,
}

/// Пин снапшота + метаданные всех видимых зон.
pub(crate) struct ZoneSource {
    store: Arc<ZoneStore>,
    snapshot: Snapshot,
    zones: Vec<ZoneMeta>,
}

impl ZoneSource {
    pub(crate) fn txnid(&self) -> u64 {
        self.snapshot.txnid()
    }

    pub(crate) fn zones(&self) -> &[ZoneMeta] {
        &self.zones
    }

    /// Строит `QueryEngine`-совместимые views (по одной на зону).
    pub(crate) fn views(self: &Arc<Self>, expired: &HashSet<Name>) -> Vec<Arc<dyn ZoneView>> {
        self.zones
            .iter()
            .map(|meta| {
                let state = match meta.entry.state {
                    FileZoneState::Serving => {
                        if expired.contains(&meta.origin) {
                            ServerZoneState::Expired
                        } else {
                            ServerZoneState::Serving
                        }
                    }
                    FileZoneState::Initializing => ServerZoneState::Initializing,
                    FileZoneState::Tombstone => ServerZoneState::Tombstone,
                };
                Arc::new(FileZoneView {
                    source: Arc::clone(self),
                    origin: meta.origin.clone(),
                    apex: meta.apex,
                    soa: meta.soa.clone(),
                    ns: meta.ns.clone(),
                    state,
                }) as Arc<dyn ZoneView>
            })
            .collect()
    }
}

/// `ZoneView` поверх mmap: точечные чтения, ноль материализации зоны.
pub(crate) struct FileZoneView {
    source: Arc<ZoneSource>,
    origin: Name,
    apex: NameRle,
    soa: Option<Rrset>,
    ns: Option<Rrset>,
    state: ServerZoneState,
}

impl FileZoneView {
    fn txnid(&self) -> u64 {
        self.source.txnid()
    }

    fn lookup_stored(&self, name: &Name, rr_type: Rtype) -> Option<Rrset> {
        self.source.store.stats.lookup();
        let stored = self
            .source
            .store
            .lookup_at(self.txnid(), &self.apex, name, rr_type)
            .ok()
            .flatten()?;
        rrset_from_stored(name, rr_type, &stored).ok()
    }

    fn node(&self, name: &Name) -> Option<NodeInfo> {
        let owner = name_to_rle(name).ok()?;
        let file = self
            .source
            .store
            .file
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        file.node_at(self.txnid(), &self.apex, &owner)
            .ok()
            .flatten()
    }

    fn rrsig(&self, name: &Name, covered: Rtype) -> Option<Rrset> {
        self.source.store.stats.lookup();
        let owner = name_to_rle(name).ok()?;
        let file = self
            .source
            .store
            .file
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let view = file
            .lookup_rrset_at(
                self.txnid(),
                &self.apex,
                &owner,
                Rtype::RRSIG.as_u16(),
                covered.as_u16(),
            )
            .ok()
            .flatten()?;
        rrset_from_stored(name, Rtype::RRSIG, &view).ok()
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
        let file = self
            .source
            .store
            .file
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let items = file.zone_items_at(self.txnid(), &self.apex).ok()?;
        for item in items.flatten() {
            if item.rr_type != Rtype::NSEC.as_u16() {
                continue;
            }
            let ZoneItemValue::Rrset(view) = item.value else {
                continue;
            };
            let owner = name_from_rle(&item.name).ok()?;
            let Ok(rrset) = rrset_from_stored(&owner, Rtype::NSEC, &view) else {
                continue;
            };
            let Some(next) = rrset.rdatas().iter().find_map(|rdata| match rdata {
                Rdata::Nsec(nsec) => Some(nsec.next_domain().clone()),
                _ => None,
            }) else {
                continue;
            };
            if nsec_covers(&owner, &next, name) {
                return Some(rrset);
            }
        }
        None
    }

    fn is_delegation(&self, name: &Name) -> bool {
        if name == &self.origin || !name.is_subdomain_of(&self.origin) {
            return false;
        }
        // Флаги cut в v1 не материализуются деревом зоны: delegation
        // определяется наличием NS при отсутствии SOA.
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

impl ZoneStore {
    fn lookup_at(
        &self,
        txnid: u64,
        apex: &NameRle,
        name: &Name,
        rr_type: Rtype,
    ) -> Result<Option<StoredRrsetView>, ZoneFileError> {
        let file = self.file.read().unwrap_or_else(PoisonError::into_inner);
        let owner = name_to_rle_lossy(name)?;
        if rr_type == Rtype::RRSIG {
            let views = file.lookup_all_rrset_at(txnid, apex, &owner, Rtype::RRSIG.as_u16())?;
            if views.is_empty() {
                return Ok(None);
            }
            let mut ttl = views.first().map_or(0, |view| view.ttl);
            let mut flags = 0;
            let mut rdata = Vec::new();
            for view in views {
                ttl = ttl.min(view.ttl);
                flags |= view.flags;
                rdata.extend(view.rdata);
            }
            return Ok(Some(StoredRrsetView { ttl, flags, rdata }));
        }
        file.lookup_rrset_at(txnid, apex, &owner, rr_type.as_u16(), 0)
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

fn name_to_rle_lossy(name: &Name) -> Result<NameRle, ZoneFileError> {
    NameRle::from_wire(name.as_wire()).map_err(|_| ZoneFileError::Corrupt {
        kind: pulse_zonefile::CorruptKind::Bounds,
        page: None,
        detail: pulse_zonefile::CorruptDetail::OffsetOutOfRange,
    })
}

pub(crate) fn name_from_rle(rle: &NameRle) -> Result<Name, ZoneFileSourceError> {
    let mut buffer = [0_u8; 255];
    let len = rle
        .write_wire(&mut buffer)
        .map_err(|error| ZoneFileSourceError::new(format!("cannot encode stored name: {error}")))?;
    Name::from_wire(&buffer[..len])
        .map_err(|error| ZoneFileSourceError::new(format!("invalid stored DNS name: {error}")))
}

/// Группирует элементы дерева в RRset'ы, включая подтипы RRSIG.
pub(crate) fn collect_rrsets(
    origin: &Name,
    items: impl Iterator<Item = Result<ZoneItem, ZoneFileError>>,
    path: &Path,
) -> Result<Vec<Rrset>, String> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<(String, u16), (u32, Vec<Rdata>)> = BTreeMap::new();
    for item in items {
        let item = item.map_err(|error| file_error(path, "read zone item", &error).to_string())?;
        let ZoneItemValue::Rrset(view) = item.value else {
            continue;
        };
        let owner = name_from_rle(&item.name).map_err(|error| error.to_string())?;
        if item.class != Rclass::IN.as_u16() {
            return Err(format!("zone {origin}: unsupported class {}", item.class));
        }
        let rr_type = Rtype::from_u16(item.rr_type);
        let key = (owner.to_string(), rr_type.as_u16());
        let entry = groups.entry(key).or_insert_with(|| (view.ttl, Vec::new()));
        if entry.0 != view.ttl {
            return Err(format!("zone {origin}: TTL mismatch for {owner} {rr_type}"));
        }
        for bytes in view.rdata {
            entry
                .1
                .push(Rdata::from_wire(rr_type, &bytes).map_err(|error| {
                    format!("zone {origin}: {owner} {rr_type}: invalid stored rdata: {error}")
                })?);
        }
    }
    let mut out = Vec::with_capacity(groups.len());
    for ((owner, rr_type), (ttl, rdata)) in groups {
        let owner = Name::parse(&owner).map_err(|error| error.to_string())?;
        let rr_type = Rtype::from_u16(rr_type);
        let ttl = Ttl::new(ttl).map_err(|error| error.to_string())?;
        out.push(
            Rrset::new(owner.clone(), rr_type, Rclass::IN, ttl, rdata)
                .map_err(|error| format!("zone {origin}: {owner} {rr_type}: {error}"))?,
        );
    }
    Ok(out)
}

/// Добавляет RRset в транзакцию (RRSIG раскладывается по subtype).
pub(crate) fn write_rrset(
    writer: &mut pulse_zonefile::ZoneWriter<'_>,
    apex: &NameRle,
    rrset: &Rrset,
) -> Result<(), String> {
    use std::collections::BTreeMap;
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
            .upsert_rrset(apex, &owner, rrset.rr_type().as_u16(), subtype, &data)
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

pub(crate) fn denial_to_u8(denial: pulse_api::Denial) -> u8 {
    match denial {
        pulse_api::Denial::Nsec => 0,
        pulse_api::Denial::Nsec3 => 1,
    }
}

pub(crate) fn denial_from_u8(value: u8) -> Option<pulse_api::Denial> {
    match value {
        0 => Some(pulse_api::Denial::Nsec),
        1 => Some(pulse_api::Denial::Nsec3),
        _ => None,
    }
}

pub(crate) fn kind_flags(kind: pulse_api::ZoneKind) -> u16 {
    match kind {
        pulse_api::ZoneKind::Primary => 0,
        pulse_api::ZoneKind::Secondary => pulse_zonefile::zone_meta::ZONE_FLAG_SECONDARY,
        pulse_api::ZoneKind::Forward => pulse_zonefile::zone_meta::ZONE_FLAG_FORWARD,
    }
}

pub(crate) fn kind_from_flags(flags: u16) -> pulse_api::ZoneKind {
    if flags & pulse_zonefile::zone_meta::ZONE_FLAG_FORWARD != 0 {
        pulse_api::ZoneKind::Forward
    } else if flags & pulse_zonefile::zone_meta::ZONE_FLAG_SECONDARY != 0 {
        pulse_api::ZoneKind::Secondary
    } else {
        pulse_api::ZoneKind::Primary
    }
}

pub(crate) fn system_time_from_unix_ns(ns: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_nanos(ns))
        .unwrap_or(UNIX_EPOCH)
}

pub(crate) fn file_error(path: &Path, action: &str, error: &ZoneFileError) -> ZoneFileSourceError {
    ZoneFileSourceError::new(format!("zone file {}: {action}: {error}", path.display()))
}
