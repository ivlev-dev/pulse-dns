//! Адаптер `pulse-api::ZoneAdmin` и `pulse-server::ZoneView` поверх
//! `pulse-zonefile` v2 (`ParallelStore`).
//!
//! Единственный источник истины — mmap-файл зон. DNS-ответы читают его через
//! [`FileZoneView`]; REST-мутации открывают per-zone writer, применяют правку и
//! коммитят. Разные зоны пишутся параллельно (lease у зоны один), а view зоны
//! после коммита перечитывает apex SOA/NS; полной in-memory копии зон нет.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Instant, SystemTime};

use pulse_api::{
    AdminError, Conflict, Denial, ListRrsets, ListZones, Precondition, Preconditions, RrsetInput,
    RrsetPatch, RrsetPatchOutcome, RrsetView, WriteOutcome, ZoneAdmin, ZoneAllow, ZoneFileMetrics,
    ZoneKind, ZoneMetaInput, ZonePage, ZoneSettings, ZoneSettingsPatch, ZoneSettingsView,
};
use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Serial, Ttl};
use pulse_server::{QueryEngine, QueryStats, ZoneState as ServerZoneState, ZoneView};
use pulse_transfer::ZoneSnapshot;
use pulse_zonefile::parallel::{ParallelZone, RootState};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::Config;
use crate::dnssec::{self, DnssecSigners};
use crate::logging;
use crate::secondary::{SecondaryError, SecondaryManager, SecondaryUpdate, rrsets_from_snapshot};
use crate::transfer::{NotifyDispatcher, TransferState};
use crate::zonefile::{
    FileZoneView, ZoneEntry, ZoneFileStats, ZoneStore, denial_from_u8, kind_from_flags,
    name_from_rle, name_to_rle, system_time_from_unix_ns, write_rrset,
};

/// Ошибка начального построения DNS-снапшота.
#[derive(Debug, Error)]
#[error("zone snapshot cannot be served: {0}")]
pub(crate) struct StoreError(String);

/// Общий администратор: zonefile, DNS-движок, transfer и secondary.
pub(crate) struct SharedZoneAdmin {
    store: Option<Arc<ZoneStore>>,
    /// `origin → view`; движок собирается из этих view.
    views: RwLock<HashMap<Name, Arc<FileZoneView>>>,
    engine: RwLock<Arc<QueryEngine>>,
    query_stats: Arc<QueryStats>,
    file_stats: Arc<ZoneFileStats>,
    /// Сериализует операции с каталогом (create/delete/replace), не RRset-правки.
    catalog: Mutex<()>,
    dnssec: DnssecSigners,
    transfer: TransferState,
    secondary: SecondaryManager,
}

impl SharedZoneAdmin {
    pub(crate) fn new(
        store: Option<Arc<ZoneStore>>,
        dnssec: DnssecSigners,
        config: &Config,
        notify: Option<Arc<NotifyDispatcher>>,
    ) -> Result<Self, StoreError> {
        let query_stats = Arc::new(QueryStats::new());
        let file_stats = store
            .as_ref()
            .map_or_else(|| Arc::new(ZoneFileStats::default()), |store| store.stats());
        let zones = match &store {
            Some(store) => store.list_zones().map_err(StoreError)?,
            None => Vec::new(),
        };
        let zones_meta = zones
            .iter()
            .map(|zone| {
                (
                    zone.origin.clone(),
                    kind_from_flags(zone.flags),
                    (zone.soa_serial != 0).then(|| Serial::new(zone.soa_serial)),
                )
            })
            .collect();
        let transfer = TransferState::from_config(
            &config.transfer,
            &config.tsig_keys,
            &config.secondary_zones,
            zones_meta,
            store.clone(),
            notify,
        )
        .map_err(|error| StoreError(format!("cannot initialise transfer: {error}")))?;
        let existing_secondary: HashSet<Name> = zones
            .iter()
            .filter(|zone| kind_from_flags(zone.flags) == ZoneKind::Secondary)
            .map(|zone| zone.origin.clone())
            .collect();
        let secondary = SecondaryManager::from_config(
            config,
            &existing_secondary,
            |name| transfer.key(name),
            Instant::now(),
        )
        .map_err(|error| StoreError(format!("cannot initialise secondary zones: {error}")))?;
        let expired = secondary.expired_origins();
        let mut views = HashMap::with_capacity(zones.len());
        for entry in &zones {
            let Some(store) = &store else {
                continue;
            };
            let view = FileZoneView::new(Arc::clone(store), entry, server_state(entry, &expired))
                .map_err(StoreError)?;
            views.insert(entry.origin.clone(), Arc::new(view));
        }
        let engine = build_engine(&views, &query_stats);
        Ok(Self {
            store,
            views: RwLock::new(views),
            engine: RwLock::new(engine),
            query_stats,
            file_stats,
            catalog: Mutex::new(()),
            dnssec,
            transfer,
            secondary,
        })
    }

    /// Текущий движок. Read-lock удерживается только на клонирование `Arc`.
    pub(crate) fn engine(&self) -> Arc<QueryEngine> {
        Arc::clone(&self.engine.read().unwrap_or_else(PoisonError::into_inner))
    }

    pub(crate) fn query_stats(&self) -> Arc<QueryStats> {
        Arc::clone(&self.query_stats)
    }

    pub(crate) fn transfer(&self) -> &TransferState {
        &self.transfer
    }

    pub(crate) fn pending_updates(&self) -> Vec<Name> {
        self.transfer.pending_updates()
    }

    pub(crate) fn has_secondary_zones(&self) -> bool {
        !self.secondary.is_empty()
    }

    pub(crate) fn secondary_last_error(&self, origin: &Name) -> Option<String> {
        self.secondary.last_error(origin)
    }

    pub(crate) fn wake_secondary(&self, origin: &Name, now: Instant) {
        self.secondary.wake(origin, now);
    }

    pub(crate) fn secondary_tick(&self, now: Instant) {
        if self.secondary.expire_due(now)
            && let Err(error) = self.rebuild_all_views()
        {
            logging::error(
                "secondary",
                &format!("cannot rebuild engine after expire: {error:?}"),
            );
        }
        for origin in self.secondary.due(now) {
            self.secondary_refresh(&origin, now);
        }
    }

    fn secondary_refresh(&self, origin: &Name, now: Instant) {
        let Some(zone) = self.secondary.get(origin) else {
            return;
        };
        let Some(_lease) = zone.try_lease() else {
            logging::debug(
                "secondary",
                &format!("zone {origin}: transfer already in progress"),
            );
            return;
        };
        let forced = zone.take_force();
        let local = self
            .store
            .as_ref()
            .and_then(|store| store.zone_snapshot(origin).ok().flatten());
        if local.is_none() && !zone.bootstrap() && !forced {
            zone.note_skip(now);
            return;
        }
        let result = zone.fetch(local.as_ref(), self.transfer.limits());
        match result {
            Ok(update @ SecondaryUpdate::UpToDate { .. }) => {
                let was_expired = zone.note_success(update.soa(), now);
                if was_expired && let Err(error) = self.rebuild_all_views() {
                    logging::error(
                        "secondary",
                        &format!("zone {origin}: cannot rebuild engine: {error:?}"),
                    );
                }
            }
            Ok(update @ SecondaryUpdate::Zone(_)) => {
                match self.apply_secondary_update(origin, &update, local.as_ref()) {
                    Ok(()) => {
                        let was_expired = zone.note_success(update.soa(), now);
                        if was_expired {
                            logging::info(
                                "secondary",
                                &format!("zone {origin}: recovered from expired state"),
                            );
                        }
                    }
                    Err(error) => {
                        logging::error(
                            "secondary",
                            &format!("zone {origin}: cannot apply transfer: {error}"),
                        );
                        let was_expired = zone.note_failure(error.to_string(), now);
                        if was_expired && let Err(error) = self.rebuild_all_views() {
                            logging::error(
                                "secondary",
                                &format!("zone {origin}: cannot rebuild engine: {error:?}"),
                            );
                        }
                    }
                }
            }
            Err(error) => {
                logging::warn(
                    "secondary",
                    &format!("zone {origin}: refresh failed: {error}"),
                );
                let was_expired = zone.note_failure(error.to_string(), now);
                if was_expired && let Err(error) = self.rebuild_all_views() {
                    logging::error(
                        "secondary",
                        &format!("zone {origin}: cannot rebuild engine: {error:?}"),
                    );
                }
            }
        }
    }

    fn apply_secondary_update(
        &self,
        origin: &Name,
        update: &SecondaryUpdate,
        previous: Option<&ZoneSnapshot>,
    ) -> Result<(), SecondaryError> {
        let SecondaryUpdate::Zone(snapshot) = update else {
            return Ok(());
        };
        let Some(store) = &self.store else {
            return Err(SecondaryError::Store(
                "secondary zones require --data <zonefile>".to_owned(),
            ));
        };
        let existing = store.zone_entry(origin).map_err(SecondaryError::Store)?;
        if let Some(entry) = &existing
            && kind_from_flags(entry.flags) != ZoneKind::Secondary
        {
            return Err(SecondaryError::Store(format!(
                "zone {origin} exists and is not secondary"
            )));
        }
        let rrsets = rrsets_from_snapshot(snapshot)?;
        let default_ttl = existing
            .as_ref()
            .and_then(|entry| Ttl::new(entry.default_ttl).ok())
            .unwrap_or_else(|| soa_default_ttl(snapshot));
        replace_zone_in_file(
            store,
            origin,
            ZoneKind::Secondary,
            default_ttl,
            Denial::Nsec,
            &rrsets,
            &[],
        )
        .map_err(SecondaryError::Store)?;
        self.after_commit(origin, previous);
        Ok(())
    }

    /// Перечитывает view одной зоны и публикует новый движок.
    fn after_commit(&self, origin: &Name, previous: Option<&ZoneSnapshot>) {
        let current = if self.transfer.needs_snapshot() {
            self.store
                .as_ref()
                .and_then(|store| store.zone_snapshot(origin).ok().flatten())
        } else {
            None
        };
        if self.transfer.needs_snapshot() {
            let notify = self
                .store
                .as_ref()
                .and_then(|store| store.zone_entry(origin).ok().flatten())
                .is_some_and(|entry| kind_from_flags(entry.flags) == ZoneKind::Primary);
            self.transfer
                .record_change(origin, previous, current.as_ref(), notify);
        }
        if let Err(error) = self.refresh_view(origin) {
            logging::error(
                "zone_store",
                &format!("cannot refresh DNS view after commit: {error:?}"),
            );
        }
    }

    fn refresh_view(&self, origin: &Name) -> Result<(), AdminError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let entry = store.zone_entry(origin).map_err(AdminError::Storage)?;
        let expired = self.secondary.expired_origins();
        let mut views = self.views.write().unwrap_or_else(PoisonError::into_inner);
        match entry {
            Some(entry) => {
                let view =
                    FileZoneView::new(Arc::clone(store), &entry, server_state(&entry, &expired))
                        .map_err(|error| {
                            logging::error("zone_store", &error);
                            AdminError::Internal
                        })?;
                views.insert(origin.clone(), Arc::new(view));
            }
            None => {
                views.remove(origin);
            }
        }
        let engine = build_engine(&views, &self.query_stats);
        *self.engine.write().unwrap_or_else(PoisonError::into_inner) = engine;
        Ok(())
    }

    fn rebuild_all_views(&self) -> Result<(), AdminError> {
        let Some(store) = &self.store else {
            let empty = QueryEngine::with_stats(Vec::new(), Arc::clone(&self.query_stats));
            *self.engine.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(empty);
            return Ok(());
        };
        let zones = store.list_zones().map_err(AdminError::Storage)?;
        let expired = self.secondary.expired_origins();
        let mut views = HashMap::with_capacity(zones.len());
        for entry in &zones {
            let view = FileZoneView::new(Arc::clone(store), entry, server_state(entry, &expired))
                .map_err(|error| {
                logging::error("zone_store", &error);
                AdminError::Internal
            })?;
            views.insert(entry.origin.clone(), Arc::new(view));
        }
        let engine = build_engine(&views, &self.query_stats);
        *self.views.write().unwrap_or_else(PoisonError::into_inner) = views;
        *self.engine.write().unwrap_or_else(PoisonError::into_inner) = engine;
        Ok(())
    }

    pub(crate) fn shutdown(&self) -> Result<(), String> {
        let result = self.sync_persistence();
        self.transfer.shutdown_notify();
        result
    }

    pub(crate) fn sync_persistence(&self) -> Result<(), String> {
        if let Some(store) = &self.store {
            store.sync().map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    fn require_store(&self) -> Result<&Arc<ZoneStore>, AdminError> {
        self.store.as_ref().ok_or_else(|| {
            AdminError::Storage("zonefile is not configured (use --data)".to_owned())
        })
    }

    fn previous_snapshot(&self, origin: &Name, store: &ZoneStore) -> Option<ZoneSnapshot> {
        if !self.transfer.needs_snapshot() {
            return None;
        }
        store.zone_snapshot(origin).ok().flatten()
    }
}

fn build_engine(
    views: &HashMap<Name, Arc<FileZoneView>>,
    query_stats: &Arc<QueryStats>,
) -> Arc<QueryEngine> {
    let views: Vec<Arc<dyn ZoneView>> = views
        .values()
        .map(|view| Arc::clone(view) as Arc<dyn ZoneView>)
        .collect();
    Arc::new(QueryEngine::with_stats(views, Arc::clone(query_stats)))
}

fn server_state(entry: &ZoneEntry, expired: &HashSet<Name>) -> ServerZoneState {
    match entry.state {
        RootState::Serving => {
            if expired.contains(&entry.origin) {
                ServerZoneState::Expired
            } else {
                ServerZoneState::Serving
            }
        }
        RootState::Init => ServerZoneState::Initializing,
        RootState::Tombstone => ServerZoneState::Tombstone,
    }
}

/// Подписывает зоны, для которых настроены DNSSEC-ключи, и коммитит результат
/// в zonefile. Запускается при старте и в `/sign`.
pub(crate) fn sign_configured_zones(
    store: &ZoneStore,
    dnssec: &DnssecSigners,
) -> Result<usize, String> {
    let mut signed_count = 0_usize;
    for origin in dnssec.origins() {
        let Some(entry) = store.zone_entry(origin)? else {
            return Err(format!(
                "DNSSEC is configured for zone {origin}, but the zone is not loaded"
            ));
        };
        let signer = dnssec
            .signer(origin)
            .ok_or_else(|| format!("DNSSEC signer for zone {origin} disappeared"))?;
        let rrsets = store.zone_rrsets(origin)?;
        let signed_zone = signer
            .sign_zone(origin, &rrsets, dnssec::now_unix())
            .map_err(|error| format!("cannot sign zone {origin}: {error}"))?;
        let kind = kind_from_flags(entry.flags);
        let default_ttl = Ttl::new(entry.default_ttl).unwrap_or(Ttl::from_wire(3600));
        let denial = denial_from_u8(entry.denial).unwrap_or(Denial::Nsec);
        replace_zone_in_file(
            store,
            origin,
            kind,
            default_ttl,
            denial,
            &signed_zone.rrsets,
            &[],
        )?;
        signed_count = signed_count.saturating_add(1);
        logging::info(
            "dnssec",
            &format!(
                "zone {origin} signed into zonefile: keys={} key_tags={:?} rrsets={} rrsigs={}",
                signed_zone.dnskeys.len(),
                signed_zone.key_tags,
                signed_zone.rrsets.len(),
                signed_zone.rrsig_count
            ),
        );
    }
    Ok(signed_count)
}

fn soa_default_ttl(snapshot: &ZoneSnapshot) -> Ttl {
    let minimum = match snapshot.soa().rdata() {
        Rdata::Soa(soa) => soa.minimum,
        _ => 3600,
    };
    Ttl::new(minimum.max(1)).unwrap_or_else(|_| Ttl::from_wire(3600))
}

fn soa_serial(soa: Option<&Rrset>) -> Option<Serial> {
    soa.and_then(|rrset| match rrset.rdatas().first() {
        Some(Rdata::Soa(soa)) => Some(soa.serial),
        _ => None,
    })
}

/// Импортирует master-файл в zonefile (`pulsed import`).
pub(crate) fn import_loaded_zone(
    store: &ZoneStore,
    loaded: &crate::master::LoadedZone,
    replace: bool,
    dnssec: &DnssecSigners,
) -> Result<(), String> {
    let exists = store.zone_entry(&loaded.origin)?.is_some();
    if exists && !replace {
        return Err(format!(
            "zone {} already exists; pass --replace to overwrite it",
            loaded.origin
        ));
    }
    let rrsets = if let Some(signer) = dnssec.signer(&loaded.origin) {
        signer
            .sign_zone(&loaded.origin, &loaded.rrsets, dnssec::now_unix())
            .map_err(|error| format!("cannot sign zone {}: {error}", loaded.origin))?
            .rrsets
    } else {
        loaded.rrsets.clone()
    };
    replace_zone_in_file(
        store,
        &loaded.origin,
        ZoneKind::Primary,
        loaded.default_ttl,
        Denial::Nsec,
        &rrsets,
        &[],
    )?;
    store.sync().map_err(|error| error.to_string())
}

/// Полностью перезаписывает зону в одной транзакции.
pub(crate) fn replace_zone_in_file(
    store: &ZoneStore,
    origin: &Name,
    kind: ZoneKind,
    default_ttl: Ttl,
    denial: Denial,
    rrsets: &[Rrset],
    nodes: &[Name],
) -> Result<(), String> {
    store.replace_zone(origin, kind, default_ttl, denial, rrsets, nodes)
}

fn zone_view(store: &ZoneStore, origin: &Name) -> Result<pulse_api::ZoneView, AdminError> {
    let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
        return Err(AdminError::zone_not_found());
    };
    let soa = store
        .lookup(origin, origin, Rtype::SOA)
        .map_err(AdminError::Storage)?
        .map(|view| {
            crate::zonefile::rrset_from_stored(origin, Rtype::SOA, &view)
                .map_err(|error| AdminError::Storage(error.to_string()))
        })
        .transpose()?;
    let serial = soa_serial(soa.as_ref()).unwrap_or_else(|| Serial::new(entry.soa_serial.max(1)));
    let version = entry.version.max(1);
    let txn = entry.version;
    Ok(pulse_api::ZoneView {
        id: pulse_api::ZoneId::new(entry.zone_seq),
        origin: origin.clone(),
        kind: kind_from_flags(entry.flags),
        serial,
        version,
        txn,
        default_ttl: Ttl::new(entry.default_ttl).unwrap_or(Ttl::from_wire(3600)),
        denial: denial_from_u8(entry.denial).unwrap_or(Denial::Nsec),
        rrset_count: entry.rrset_count,
        etag: zone_etag(entry.zone_seq, version, txn),
        created_at: system_time_from_unix_ns(entry.created_unix_ns),
        updated_at: system_time_from_unix_ns(entry.updated_unix_ns),
    })
}

fn zone_etag(id: u32, version: u64, txn: u64) -> String {
    format!("\"z{id}-v{version}-t{txn}\"")
}

fn rrset_etag(rrset: &Rrset) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rrset.owner().as_wire());
    hasher.update(rrset.rr_type().as_u16().to_be_bytes());
    hasher.update(rrset.class().as_u16().to_be_bytes());
    hasher.update(rrset.ttl().as_u32().to_be_bytes());
    for rdata in rrset.rdatas() {
        hasher.update(rdata.to_canonical_wire());
    }
    let digest = hasher.finalize();
    let prefix = digest.get(..6).unwrap_or(&digest);
    format!("\"rr_{}\"", hex::encode(prefix))
}

fn rrset_view(origin: &Name, rrset: &Rrset) -> RrsetView {
    RrsetView {
        zone: origin.clone(),
        owner: rrset.owner().clone(),
        rr_type: rrset.rr_type(),
        ttl: rrset.ttl(),
        rdata: rrset.rdatas().iter().cloned().collect(),
        etag: rrset_etag(rrset),
        updated_at: SystemTime::now(),
    }
}

fn tags_equal(left: &str, right: &str) -> bool {
    fn normalize(value: &str) -> &str {
        let trimmed = value.trim();
        let weak = trimmed.strip_prefix("W/").unwrap_or(trimmed);
        weak.strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(weak)
    }
    normalize(left) == normalize(right)
}

fn condition_matches(condition: &Precondition, current: &str) -> bool {
    match condition {
        Precondition::Any => true,
        Precondition::Tag(tag) => tags_equal(tag, current),
        Precondition::Tags(tags) => tags.iter().any(|tag| tags_equal(tag, current)),
    }
}

fn check_existing(
    preconditions: &Preconditions,
    current_etag: &str,
    version: u64,
) -> Result<(), AdminError> {
    if let Some(condition) = &preconditions.if_none_match
        && condition_matches(condition, current_etag)
    {
        return Err(AdminError::PreconditionFailed {
            current_etag: Some(current_etag.to_owned()),
            current_version: Some(version),
        });
    }
    match &preconditions.if_match {
        Some(condition) if condition_matches(condition, current_etag) => Ok(()),
        Some(_) => Err(AdminError::PreconditionFailed {
            current_etag: Some(current_etag.to_owned()),
            current_version: Some(version),
        }),
        None => Err(AdminError::PreconditionRequired),
    }
}

fn check_create(preconditions: &Preconditions) -> Result<(), AdminError> {
    if preconditions.if_match.is_some() {
        return Err(AdminError::PreconditionFailed {
            current_etag: None,
            current_version: None,
        });
    }
    Ok(())
}

fn map_rrset_error(error: &pulse_dns::RrsetError) -> AdminError {
    AdminError::invariant("/records", "invalid-rrset", error.to_string())
}

fn is_managed_type(rr_type: Rtype) -> bool {
    matches!(
        rr_type,
        Rtype::RRSIG | Rtype::NSEC | Rtype::NSEC3 | Rtype::NSEC3PARAM | Rtype::DNSKEY
    )
}

fn validate_type(origin: &Name, owner: &Name, rr_type: Rtype) -> Result<(), AdminError> {
    if !owner.is_subdomain_of(origin) {
        return Err(AdminError::invariant(
            "/owner",
            "owner-out-of-zone",
            "record owner must be inside the zone",
        ));
    }
    if rr_type == Rtype::SOA && owner != origin {
        return Err(AdminError::invariant(
            "/type",
            "soa-apex-only",
            "SOA is allowed only at the zone apex",
        ));
    }
    if is_managed_type(rr_type) {
        return Err(AdminError::invariant(
            "/type",
            "managed-by-signer",
            "DNSSEC records are managed by the signer",
        ));
    }
    if matches!(
        rr_type,
        Rtype::OPT | Rtype::AXFR | Rtype::IXFR | Rtype::ANY | Rtype::TKEY | Rtype::TSIG
    ) {
        return Err(AdminError::invariant(
            "/type",
            "invalid-type",
            "this record type cannot be stored in a zone",
        ));
    }
    Ok(())
}

fn bumped_soa(writer: &ParallelZone<'_>, kind: ZoneKind) -> Result<Option<Rrset>, AdminError> {
    if kind != ZoneKind::Primary {
        return Ok(None);
    }
    let origin = *writer.origin();
    let origin_name =
        name_from_rle(&origin).map_err(|error| AdminError::Storage(error.to_string()))?;
    let Some(soa) = writer
        .lookup(&origin, Rtype::SOA.as_u16(), 0)
        .map_err(|error| AdminError::Storage(error.to_string()))?
    else {
        return Ok(None);
    };
    let view = pulse_zonefile::RrsetView {
        ttl: soa.ttl,
        flags: soa.flags,
        rdata: soa.rdata,
    };
    let mut rrset = crate::zonefile::rrset_from_stored(&origin_name, Rtype::SOA, &view)
        .map_err(|error| AdminError::Storage(error.to_string()))?;
    let Some(Rdata::Soa(mut data)) = rrset.rdatas().first().cloned() else {
        return Ok(None);
    };
    data.serial = data.serial.succ();
    rrset = Rrset::new(
        origin_name,
        Rtype::SOA,
        Rclass::IN,
        rrset.ttl(),
        [Rdata::Soa(data)],
    )
    .map_err(|error| map_rrset_error(&error))?;
    Ok(Some(rrset))
}

fn soa_serial_of(rrset: &Rrset) -> Option<u32> {
    match rrset.rdatas().first() {
        Some(Rdata::Soa(soa)) => Some(soa.serial.as_u32()),
        _ => None,
    }
}

fn check_owner_conflicts(
    store: &ZoneStore,
    origin: &Name,
    owner: &Name,
    rr_type: Rtype,
) -> Result<(), AdminError> {
    let types = store
        .owner_types(origin, owner)
        .map_err(AdminError::Storage)?;
    let has_cname = types.contains(&Rtype::CNAME);
    let has_other = types
        .iter()
        .any(|kind| *kind != rr_type && *kind != Rtype::CNAME);
    if rr_type == Rtype::CNAME {
        if owner == origin {
            return Err(AdminError::invariant(
                "/owner",
                "cname-conflict",
                "CNAME is not allowed at the zone apex",
            ));
        }
        if has_other {
            return Err(AdminError::invariant(
                "/owner",
                "cname-conflict",
                "CNAME cannot coexist with other types at the same owner",
            ));
        }
    }
    if rr_type == Rtype::DNAME {
        if owner == origin {
            return Err(AdminError::invariant(
                "/owner",
                "dname-conflict",
                "DNAME is not allowed at the zone apex",
            ));
        }
        if has_cname {
            return Err(AdminError::invariant(
                "/owner",
                "dname-conflict",
                "DNAME cannot coexist with CNAME at the same owner",
            ));
        }
    }
    if has_cname && rr_type != Rtype::CNAME {
        return Err(AdminError::invariant(
            "/owner",
            "cname-conflict",
            "owner with CNAME cannot have other types",
        ));
    }
    Ok(())
}

impl ZoneAdmin for SharedZoneAdmin {
    fn ready(&self) -> bool {
        self.store.is_some()
    }

    fn zonefile_metrics(&self) -> Option<ZoneFileMetrics> {
        Some(match &self.store {
            Some(store) => store.metrics(),
            None => self.file_stats.metrics(None),
        })
    }

    fn list_zones(&self, query: &ListZones, allow: &dyn ZoneAllow) -> Result<ZonePage, AdminError> {
        let Some(store) = &self.store else {
            return Ok(ZonePage {
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
            });
        };
        let limit = if query.limit == 0 {
            50
        } else {
            query.limit.min(500)
        } as usize;
        let cursor = query
            .cursor
            .as_deref()
            .map(decode_zone_cursor)
            .transpose()?;
        let zones = store.list_zones().map_err(AdminError::Storage)?;
        let mut items = Vec::new();
        let mut has_more = false;
        for entry in zones {
            if cursor.is_some_and(|cursor| entry.zone_seq <= cursor) {
                continue;
            }
            if !allow.allows(&entry.origin) {
                continue;
            }
            let kind = kind_from_flags(entry.flags);
            if query.kind.is_some_and(|wanted| wanted != kind) {
                continue;
            }
            if items.len() >= limit {
                has_more = true;
                break;
            }
            items.push(zone_view(store, &entry.origin)?);
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|zone| encode_zone_cursor(zone.id.as_u32()))
        } else {
            None
        };
        Ok(ZonePage {
            items,
            next_cursor,
            has_more,
        })
    }

    fn get_zone(&self, origin: &Name) -> Result<pulse_api::ZoneView, AdminError> {
        zone_view(self.require_store()?, origin)
    }

    fn put_zone(
        &self,
        origin: &Name,
        meta: &ZoneMetaInput,
        preconditions: &Preconditions,
    ) -> Result<WriteOutcome<pulse_api::ZoneView>, AdminError> {
        if origin == &Name::root() || origin.labels().any(|label| label == b"*") {
            return Err(AdminError::invariant(
                "/origin",
                "invalid-origin",
                "zone origin must be a non-root name without wildcards",
            ));
        }
        let store = self.require_store()?;
        let _guard = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        let existing = store.zone_entry(origin).map_err(AdminError::Storage)?;
        let created = if let Some(entry) = &existing {
            let view = zone_view(store, origin)?;
            check_existing(preconditions, &view.etag, view.version)?;
            let current_kind = kind_from_flags(entry.flags);
            if current_kind != meta.kind && entry.rrset_count != 0 {
                return Err(AdminError::invariant(
                    "/kind",
                    "zone-not-empty",
                    "zone must be empty before changing kind",
                ));
            }
            store
                .update_zone_meta(origin, meta.kind, meta.default_ttl, meta.denial)
                .map_err(AdminError::Storage)?;
            false
        } else {
            check_create(preconditions)?;
            store
                .create_zone(origin, meta.kind, meta.default_ttl, meta.denial)
                .map_err(AdminError::Storage)?;
            true
        };
        self.after_commit(origin, None);
        let view = zone_view(store, origin)?;
        Ok(if created {
            WriteOutcome::Created(view)
        } else {
            WriteOutcome::Updated(view)
        })
    }

    fn delete_zone(&self, origin: &Name, preconditions: &Preconditions) -> Result<(), AdminError> {
        let store = self.require_store()?;
        let _guard = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        let view = zone_view(store, origin)?;
        check_existing(preconditions, &view.etag, view.version)?;
        let previous = self.previous_snapshot(origin, store);
        store.delete_zone(origin).map_err(AdminError::Storage)?;
        self.after_commit(origin, previous.as_ref());
        Ok(())
    }

    fn list_rrsets(
        &self,
        origin: &Name,
        query: &ListRrsets,
    ) -> Result<pulse_api::RrsetPage, AdminError> {
        let store = self.require_store()?;
        let _ = zone_view(store, origin)?;
        let limit = if query.limit == 0 {
            50
        } else {
            query.limit.min(500)
        } as usize;
        let cursor = query
            .cursor
            .as_deref()
            .map(decode_rrset_cursor)
            .transpose()?;
        let rrsets = store.zone_rrsets(origin).map_err(AdminError::Storage)?;
        let mut items = Vec::new();
        let mut has_more = false;
        for rrset in rrsets {
            let owner = rrset.owner();
            if query.owner.as_ref().is_some_and(|wanted| wanted != owner) {
                continue;
            }
            if query
                .owner_suffix
                .as_ref()
                .is_some_and(|suffix| !owner.is_subdomain_of(suffix))
            {
                continue;
            }
            if !query.types.is_empty() && !query.types.contains(&rrset.rr_type()) {
                continue;
            }
            if let Some((cursor_owner, cursor_type)) = &cursor {
                let key_owner = owner.to_string();
                if key_owner.as_str() < cursor_owner.as_str()
                    || (key_owner.as_str() == cursor_owner.as_str()
                        && rrset.rr_type().as_u16() <= *cursor_type)
                {
                    continue;
                }
            }
            if items.len() >= limit {
                has_more = true;
                break;
            }
            items.push(rrset_view(origin, &rrset));
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|rrset| encode_rrset_cursor(&rrset.owner, rrset.rr_type))
        } else {
            None
        };
        Ok(pulse_api::RrsetPage {
            items,
            next_cursor,
            has_more,
        })
    }

    fn get_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
    ) -> Result<RrsetView, AdminError> {
        let store = self.require_store()?;
        let _ = zone_view(store, origin)?;
        let stored = store
            .lookup(origin, owner, rr_type)
            .map_err(AdminError::Storage)?
            .ok_or_else(AdminError::rrset_not_found)?;
        let rrset = crate::zonefile::rrset_from_stored(owner, rr_type, &stored)
            .map_err(|error| AdminError::Storage(error.to_string()))?;
        Ok(rrset_view(origin, &rrset))
    }

    fn put_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        input: &RrsetInput,
        preconditions: &Preconditions,
    ) -> Result<WriteOutcome<RrsetView>, AdminError> {
        let store = self.require_store()?;
        let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
            return Err(AdminError::zone_not_found());
        };
        let kind = kind_from_flags(entry.flags);
        if !kind.is_writable() {
            return Err(AdminError::Conflict(Conflict::ZoneReadOnly));
        }
        validate_type(origin, owner, rr_type)?;
        let owner_rle =
            name_to_rle(owner).map_err(|error| AdminError::Storage(error.to_string()))?;
        // Lease зоны сериализует писателей одной зоны; разные зоны пишут
        // параллельно. Предыдущий снапшот читается под lease, иначе IXFR-дельта
        // считалась бы от устаревшей версии.
        let mut writer = store.open_writer(origin).map_err(AdminError::Storage)?;
        let previous = self.previous_snapshot(origin, store);
        let current = writer
            .lookup(&owner_rle, rr_type.as_u16(), 0)
            .map_err(|error| AdminError::Storage(error.to_string()))?;
        let existed = if let Some(record) = current {
            let view = pulse_zonefile::RrsetView {
                ttl: record.ttl,
                flags: record.flags,
                rdata: record.rdata,
            };
            let rrset = crate::zonefile::rrset_from_stored(owner, rr_type, &view)
                .map_err(|error| AdminError::Storage(error.to_string()))?;
            check_existing(preconditions, &rrset_etag(&rrset), writer.version().max(1))?;
            true
        } else {
            check_create(preconditions)?;
            false
        };
        check_owner_conflicts(store, origin, owner, rr_type)?;
        let rrset = Rrset::new(
            owner.clone(),
            rr_type,
            Rclass::IN,
            input.ttl,
            input.rdata.iter().cloned(),
        )
        .map_err(|error| map_rrset_error(&error))?;
        if rr_type == Rtype::SOA && rrset.len() != 1 {
            return Err(AdminError::invariant(
                "/records",
                "soa-single",
                "apex SOA must contain exactly one record",
            ));
        }
        let soa = if rr_type == Rtype::SOA {
            None
        } else {
            bumped_soa(&writer, kind)?
        };
        write_rrset(&mut writer, &rrset).map_err(AdminError::Storage)?;
        if let Some(soa) = &soa {
            write_rrset(&mut writer, soa).map_err(AdminError::Storage)?;
        }
        if let Some(serial) = soa
            .as_ref()
            .and_then(soa_serial_of)
            .or_else(|| soa_serial_of(&rrset))
        {
            writer.set_soa_serial(serial);
        }
        store
            .commit_writer(&mut writer)
            .map_err(AdminError::Storage)?;
        // Lease удерживается до конца after_commit: IXFR-история и view
        // обновляются в порядке коммитов одной зоны.
        self.after_commit(origin, previous.as_ref());
        drop(writer);
        let stored = rrset;
        let view = rrset_view(origin, &stored);
        Ok(if existed {
            WriteOutcome::Updated(view)
        } else {
            WriteOutcome::Created(view)
        })
    }

    #[allow(clippy::too_many_lines)]
    fn patch_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        patch: &RrsetPatch,
        preconditions: &Preconditions,
    ) -> Result<RrsetPatchOutcome, AdminError> {
        let store = self.require_store()?;
        let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
            return Err(AdminError::zone_not_found());
        };
        let kind = kind_from_flags(entry.flags);
        if !kind.is_writable() {
            return Err(AdminError::Conflict(Conflict::ZoneReadOnly));
        }
        let owner_rle =
            name_to_rle(owner).map_err(|error| AdminError::Storage(error.to_string()))?;
        let mut writer = store.open_writer(origin).map_err(AdminError::Storage)?;
        let previous = self.previous_snapshot(origin, store);
        let current = writer
            .lookup(&owner_rle, rr_type.as_u16(), 0)
            .map_err(|error| AdminError::Storage(error.to_string()))?
            .ok_or_else(AdminError::rrset_not_found)?;
        let current_view = pulse_zonefile::RrsetView {
            ttl: current.ttl,
            flags: current.flags,
            rdata: current.rdata,
        };
        let current = crate::zonefile::rrset_from_stored(owner, rr_type, &current_view)
            .map_err(|error| AdminError::Storage(error.to_string()))?;
        check_existing(
            preconditions,
            &rrset_etag(&current),
            writer.version().max(1),
        )?;
        let ttl = patch.ttl.unwrap_or(current.ttl());
        let current_set: BTreeSet<Rdata> = current.rdatas().iter().cloned().collect();
        let remove_set: BTreeSet<Rdata> = patch.remove.iter().cloned().collect();
        let add_set: BTreeSet<Rdata> = patch.add.iter().cloned().collect();
        let mut next_set = current_set.clone();
        for record in &remove_set {
            next_set.remove(record);
        }
        let removed = current_set
            .iter()
            .filter(|record| remove_set.contains(*record))
            .count();
        let added = add_set
            .iter()
            .filter(|record| !current_set.contains(*record))
            .count();
        for record in &add_set {
            next_set.insert(record.clone());
        }
        let soa = if rr_type == Rtype::SOA {
            None
        } else {
            bumped_soa(&writer, kind)?
        };
        if next_set.is_empty() {
            writer
                .delete_rrset(&owner_rle, rr_type.as_u16(), 0)
                .map_err(|error| AdminError::Storage(error.to_string()))?;
            writer
                .ensure_empty_node(&owner_rle)
                .map_err(|error| AdminError::Storage(error.to_string()))?;
            if let Some(soa) = &soa {
                write_rrset(&mut writer, soa).map_err(AdminError::Storage)?;
                if let Some(serial) = soa_serial_of(soa) {
                    writer.set_soa_serial(serial);
                }
            }
            store
                .commit_writer(&mut writer)
                .map_err(AdminError::Storage)?;
            self.after_commit(origin, previous.as_ref());
            drop(writer);
            return Ok(RrsetPatchOutcome::Deleted {
                removed: u32::try_from(removed).unwrap_or(u32::MAX),
            });
        }
        let rrset = Rrset::new(owner.clone(), rr_type, Rclass::IN, ttl, next_set)
            .map_err(|error| map_rrset_error(&error))?;
        if rr_type == Rtype::SOA && rrset.len() != 1 {
            return Err(AdminError::invariant(
                "/records",
                "soa-single",
                "apex SOA must contain exactly one record",
            ));
        }
        write_rrset(&mut writer, &rrset).map_err(AdminError::Storage)?;
        if let Some(soa) = &soa {
            write_rrset(&mut writer, soa).map_err(AdminError::Storage)?;
            if let Some(serial) = soa_serial_of(soa) {
                writer.set_soa_serial(serial);
            }
        } else if let Some(serial) = soa_serial_of(&rrset) {
            writer.set_soa_serial(serial);
        }
        store
            .commit_writer(&mut writer)
            .map_err(AdminError::Storage)?;
        self.after_commit(origin, previous.as_ref());
        drop(writer);
        Ok(RrsetPatchOutcome::Updated {
            rrset: rrset_view(origin, &rrset),
            added: u32::try_from(added).unwrap_or(u32::MAX),
            removed: u32::try_from(removed).unwrap_or(u32::MAX),
        })
    }

    fn delete_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        preconditions: &Preconditions,
    ) -> Result<(), AdminError> {
        let store = self.require_store()?;
        let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
            return Err(AdminError::zone_not_found());
        };
        let kind = kind_from_flags(entry.flags);
        if !kind.is_writable() {
            return Err(AdminError::Conflict(Conflict::ZoneReadOnly));
        }
        let owner_rle =
            name_to_rle(owner).map_err(|error| AdminError::Storage(error.to_string()))?;
        let mut writer = store.open_writer(origin).map_err(AdminError::Storage)?;
        let previous = self.previous_snapshot(origin, store);
        let current = writer
            .lookup(&owner_rle, rr_type.as_u16(), 0)
            .map_err(|error| AdminError::Storage(error.to_string()))?
            .ok_or_else(AdminError::rrset_not_found)?;
        let current_view = pulse_zonefile::RrsetView {
            ttl: current.ttl,
            flags: current.flags,
            rdata: current.rdata,
        };
        let current = crate::zonefile::rrset_from_stored(owner, rr_type, &current_view)
            .map_err(|error| AdminError::Storage(error.to_string()))?;
        check_existing(
            preconditions,
            &rrset_etag(&current),
            writer.version().max(1),
        )?;
        let soa = bumped_soa(&writer, kind)?;
        writer
            .delete_rrset(&owner_rle, rr_type.as_u16(), 0)
            .map_err(|error| AdminError::Storage(error.to_string()))?;
        writer
            .ensure_empty_node(&owner_rle)
            .map_err(|error| AdminError::Storage(error.to_string()))?;
        if let Some(soa) = &soa {
            write_rrset(&mut writer, soa).map_err(AdminError::Storage)?;
            if let Some(serial) = soa_serial_of(soa) {
                writer.set_soa_serial(serial);
            }
        }
        store
            .commit_writer(&mut writer)
            .map_err(AdminError::Storage)?;
        self.after_commit(origin, previous.as_ref());
        drop(writer);
        Ok(())
    }

    fn get_settings(&self, origin: &Name) -> Result<ZoneSettingsView, AdminError> {
        let store = self.require_store()?;
        let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
            return Err(AdminError::zone_not_found());
        };
        let version = entry.version.max(1);
        Ok(ZoneSettingsView {
            zone: origin.clone(),
            settings: ZoneSettings {
                default_ttl: Ttl::new(entry.default_ttl).unwrap_or(Ttl::from_wire(3600)),
                denial: denial_from_u8(entry.denial).unwrap_or(Denial::Nsec),
            },
            version,
            etag: zone_etag(entry.zone_seq, version, entry.version),
            updated_at: system_time_from_unix_ns(entry.updated_unix_ns),
        })
    }

    fn patch_settings(
        &self,
        origin: &Name,
        patch: &ZoneSettingsPatch,
        preconditions: &Preconditions,
    ) -> Result<ZoneSettingsView, AdminError> {
        if patch.is_empty() {
            return Err(AdminError::invariant(
                "/",
                "validation-failed",
                "at least one setting must be provided",
            ));
        }
        let store = self.require_store()?;
        let _guard = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
            return Err(AdminError::zone_not_found());
        };
        let version = entry.version.max(1);
        check_existing(
            preconditions,
            &zone_etag(entry.zone_seq, version, entry.version),
            version,
        )?;
        let kind = kind_from_flags(entry.flags);
        let default_ttl = patch
            .default_ttl
            .unwrap_or_else(|| Ttl::new(entry.default_ttl).unwrap_or(Ttl::from_wire(3600)));
        let denial = patch
            .denial
            .unwrap_or_else(|| denial_from_u8(entry.denial).unwrap_or(Denial::Nsec));
        store
            .update_zone_meta(origin, kind, default_ttl, denial)
            .map_err(AdminError::Storage)?;
        self.after_commit(origin, None);
        self.get_settings(origin)
    }

    fn sign_zone(&self, origin: &Name) -> Result<pulse_api::ZoneView, AdminError> {
        let store = self.require_store()?;
        let signer = self.dnssec.signer(origin).ok_or_else(|| {
            AdminError::invariant(
                "/zone",
                "dnssec-not-configured",
                "zone has no DNSSEC keys configured",
            )
        })?;
        let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
            return Err(AdminError::zone_not_found());
        };
        let _guard = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        let rrsets = store.zone_rrsets(origin).map_err(AdminError::Storage)?;
        let previous = self.previous_snapshot(origin, store);
        let signed_zone = signer
            .sign_zone(origin, &rrsets, dnssec::now_unix())
            .map_err(|error| {
                logging::error(
                    "dnssec_sign",
                    &format!("zone {origin}: cannot sign: {error}"),
                );
                AdminError::Internal
            })?;
        let kind = kind_from_flags(entry.flags);
        let default_ttl = Ttl::new(entry.default_ttl).unwrap_or(Ttl::from_wire(3600));
        replace_zone_in_file(
            store,
            origin,
            kind,
            default_ttl,
            Denial::Nsec,
            &signed_zone.rrsets,
            &[],
        )
        .map_err(AdminError::Storage)?;
        self.after_commit(origin, previous.as_ref());
        zone_view(store, origin)
    }
}

fn encode_zone_cursor(id: u32) -> String {
    id.to_string()
}

fn decode_zone_cursor(cursor: &str) -> Result<u32, AdminError> {
    cursor.parse::<u32>().map_err(|_| AdminError::InvalidCursor)
}

fn encode_rrset_cursor(owner: &Name, rr_type: Rtype) -> String {
    format!("{}\u{0}{}", owner, rr_type.as_u16())
}

fn decode_rrset_cursor(cursor: &str) -> Result<(String, u16), AdminError> {
    let (owner, rr_type) = cursor
        .split_once('\u{0}')
        .ok_or(AdminError::InvalidCursor)?;
    Ok((
        owner.to_owned(),
        rr_type
            .parse::<u16>()
            .map_err(|_| AdminError::InvalidCursor)?,
    ))
}
