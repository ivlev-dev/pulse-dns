//! Адаптер `pulse-api::ZoneAdmin` и `pulse-server::ZoneView` поверх
//! `pulse-zonefile`.
//!
//! Единственный источник истины — mmap-файл зон. DNS-ответы читают его через
//! [`crate::zonefile::FileZoneView`]; REST-мутации выполняют writer-транзакцию
//! и коммит, после чего движок пересобирается. Полной in-memory копии зон нет.

use std::collections::{BTreeSet, HashSet};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Instant, SystemTime};

use pulse_api::{
    AdminError, Conflict, Denial, ListRrsets, ListZones, Precondition, Preconditions, RrsetInput,
    RrsetPatch, RrsetPatchOutcome, RrsetView, WriteOutcome, ZoneAdmin, ZoneAllow, ZoneFileMetrics,
    ZoneKind, ZoneMetaInput, ZonePage, ZoneSettings, ZoneSettingsPatch, ZoneSettingsView,
};
use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Serial, Ttl};
use pulse_server::{QueryEngine, QueryStats};
use pulse_transfer::ZoneSnapshot;
use pulse_zonefile::{ZoneMetaBlock, ZoneWriter};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::Config;
use crate::dnssec::{self, DnssecSigners};
use crate::logging;
use crate::secondary::{SecondaryError, SecondaryManager, SecondaryUpdate, rrsets_from_snapshot};
use crate::transfer::{NotifyDispatcher, TransferState};
use crate::zonefile::{
    ZoneFileStats, ZoneStore, denial_from_u8, denial_to_u8, kind_flags, kind_from_flags,
    name_from_rle, name_to_rle, system_time_from_unix_ns, write_rrset,
};

/// Ошибка начального построения DNS-снапшота.
#[derive(Debug, Error)]
#[error("zone snapshot cannot be served: {0}")]
pub(crate) struct StoreError(String);

/// Общий администратор: zonefile, DNS-движок, transfer и secondary.
pub(crate) struct SharedZoneAdmin {
    store: Option<Arc<ZoneStore>>,
    engine: RwLock<Arc<QueryEngine>>,
    query_stats: Arc<QueryStats>,
    file_stats: Arc<ZoneFileStats>,
    mutation: Mutex<()>,
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
        let source = match &store {
            Some(store) => Some(
                store
                    .source()
                    .map_err(|error| StoreError(error.to_string()))?,
            ),
            None => None,
        };
        let zones_meta = source
            .as_ref()
            .map(|source| {
                source
                    .zones()
                    .iter()
                    .map(|zone| {
                        (
                            zone.origin.clone(),
                            kind_from_flags(zone.entry.flags),
                            soa_serial(zone.soa.as_ref()),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let transfer = TransferState::from_config(
            &config.transfer,
            &config.tsig_keys,
            &config.secondary_zones,
            zones_meta,
            store.clone(),
            notify,
        )
        .map_err(|error| StoreError(format!("cannot initialise transfer: {error}")))?;
        let existing_secondary: HashSet<Name> = source
            .as_ref()
            .map(|source| {
                source
                    .zones()
                    .iter()
                    .filter(|zone| kind_from_flags(zone.entry.flags) == ZoneKind::Secondary)
                    .map(|zone| zone.origin.clone())
                    .collect()
            })
            .unwrap_or_default();
        let secondary = SecondaryManager::from_config(
            config,
            &existing_secondary,
            |name| transfer.key(name),
            Instant::now(),
        )
        .map_err(|error| StoreError(format!("cannot initialise secondary zones: {error}")))?;
        let expired = secondary.expired_origins();
        let views = source
            .as_ref()
            .map(|source| source.views(&expired))
            .unwrap_or_default();
        let engine = QueryEngine::with_stats(views, Arc::clone(&query_stats));
        Ok(Self {
            store,
            engine: RwLock::new(Arc::new(engine)),
            query_stats,
            file_stats,
            mutation: Mutex::new(()),
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
            && let Err(error) = self.rebuild_engine()
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
                if was_expired && let Err(error) = self.rebuild_engine() {
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
                        if was_expired && let Err(error) = self.rebuild_engine() {
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
                if was_expired && let Err(error) = self.rebuild_engine() {
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
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let existing = store
            .zone_meta_block(origin)
            .map_err(SecondaryError::Store)?;
        if let Some((_apex, entry, _meta)) = &existing
            && kind_from_flags(entry.flags) != ZoneKind::Secondary
        {
            return Err(SecondaryError::Store(format!(
                "zone {origin} exists and is not secondary"
            )));
        }
        let rrsets = rrsets_from_snapshot(snapshot)?;
        let default_ttl = existing
            .as_ref()
            .and_then(|(_apex, _entry, meta)| Ttl::new(meta.default_ttl).ok())
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
        self.file_stats.commit_ok();
        self.after_commit(origin, previous);
        Ok(())
    }

    fn after_commit(&self, origin: &Name, previous: Option<&ZoneSnapshot>) {
        let current = self
            .store
            .as_ref()
            .and_then(|store| store.zone_snapshot(origin).ok().flatten());
        let notify = self
            .store
            .as_ref()
            .and_then(|store| store.zone_entry(origin).ok().flatten())
            .is_some_and(|(_apex, entry)| kind_from_flags(entry.flags) == ZoneKind::Primary);
        self.transfer
            .record_change(origin, previous, current.as_ref(), notify);
        if let Err(error) = self.rebuild_engine() {
            logging::error(
                "zone_store",
                &format!("cannot rebuild DNS engine after commit: {error:?}"),
            );
        }
    }

    fn rebuild_engine(&self) -> Result<(), AdminError> {
        let Some(store) = &self.store else {
            let empty = QueryEngine::with_stats(Vec::new(), Arc::clone(&self.query_stats));
            *self.engine.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(empty);
            return Ok(());
        };
        let store = Arc::clone(store);
        // Снапшот строится на отдельном потоке: reader-table ограничивает
        // число пинов на поток, а старые движки могут ещё обслуживать запросы.
        let built = std::thread::spawn(move || store.source())
            .join()
            .map_err(|_| AdminError::Internal)?;
        let source = built.map_err(|error| {
            logging::error("zone_store", &error.to_string());
            AdminError::Internal
        })?;
        let expired = self.secondary.expired_origins();
        let views = source.views(&expired);
        let engine = QueryEngine::with_stats(views, Arc::clone(&self.query_stats));
        *self.engine.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(engine);
        Ok(())
    }

    pub(crate) fn shutdown(&self) -> Result<(), String> {
        let result = self.sync_persistence();
        self.transfer.shutdown_notify();
        result
    }

    pub(crate) fn sync_persistence(&self) -> Result<(), String> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
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
}

/// Подписывает зоны, для которых настроены DNSSEC-ключи, и коммитит результат
/// в zonefile. Запускается при старте и в `/sign`.
pub(crate) fn sign_configured_zones(
    store: &ZoneStore,
    dnssec: &DnssecSigners,
) -> Result<usize, String> {
    let mut signed_count = 0_usize;
    for origin in dnssec.origins() {
        let Some((_apex, entry, meta)) = store.zone_meta_block(origin)? else {
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
        let default_ttl = Ttl::new(meta.default_ttl).unwrap_or(Ttl::from_wire(3600));
        let denial = denial_from_u8(meta.denial).unwrap_or(Denial::Nsec);
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

/// Выполняет действие внутри транзакции и коммитит.
fn commit_action<T>(
    store: &ZoneStore,
    action: impl FnOnce(&mut ZoneWriter<'_>) -> Result<T, String>,
) -> Result<T, String> {
    let mode = store.commit_mode();
    let mut file = store.file().write().unwrap_or_else(PoisonError::into_inner);
    let mut writer = file.write().map_err(|error| {
        store.stats().commit_failed();
        store.error("begin transaction", &error)
    })?;
    let value = action(&mut writer)?;
    match writer.commit(mode) {
        Ok(_) => {
            store.stats().commit_ok();
            Ok(value)
        }
        Err(error) => {
            store.stats().commit_failed();
            Err(store.error("commit", &error))
        }
    }
}

/// Импортирует master-файл в zonefile (`pulsed import`).
pub(crate) fn import_loaded_zone(
    store: &ZoneStore,
    loaded: &crate::master::LoadedZone,
    replace: bool,
    dnssec: &DnssecSigners,
) -> Result<(), String> {
    let exists = store.zone_meta_block(&loaded.origin)?.is_some();
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
    let apex = name_to_rle(origin).map_err(|error| error.to_string())?;
    let meta = ZoneMetaBlock {
        default_ttl: default_ttl.as_u32(),
        denial: denial_to_u8(denial),
        ..ZoneMetaBlock::default()
    };
    commit_action(store, move |writer| {
        writer
            .delete_zone(&apex)
            .map_err(|error| format!("replace: tombstone old zone: {error}"))?;
        writer
            .create_zone_with_meta(&apex, kind_flags(kind), &meta)
            .map_err(|error| format!("replace: create zone: {error}"))?;
        for rrset in rrsets {
            write_rrset(writer, &apex, rrset)?;
        }
        let owners: HashSet<&Name> = rrsets.iter().map(Rrset::owner).collect();
        for node in nodes {
            if owners.contains(node) {
                continue;
            }
            let node_rle = name_to_rle(node).map_err(|error| error.to_string())?;
            writer
                .ensure_empty_node(&apex, &node_rle)
                .map_err(|error| format!("replace: write empty node: {error}"))?;
        }
        Ok(())
    })
}

fn zone_view(store: &ZoneStore, origin: &Name) -> Result<pulse_api::ZoneView, AdminError> {
    let Some((_apex, entry, meta)) = store.zone_meta_block(origin).map_err(AdminError::Storage)?
    else {
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
    let version = entry.last_commit_txn.max(1);
    let txn = entry.last_commit_txn;
    Ok(pulse_api::ZoneView {
        id: pulse_api::ZoneId::new(entry.zone_seq),
        origin: origin.clone(),
        kind: kind_from_flags(entry.flags),
        serial,
        version,
        txn,
        default_ttl: Ttl::new(meta.default_ttl).unwrap_or(Ttl::from_wire(3600)),
        denial: denial_from_u8(meta.denial).unwrap_or(Denial::Nsec),
        rrset_count: entry.rrset_count,
        etag: zone_etag(entry.zone_seq, version, txn),
        created_at: system_time_from_unix_ns(entry.last_change_unix_ns),
        updated_at: system_time_from_unix_ns(entry.last_change_unix_ns),
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

fn bumped_soa(
    store: &ZoneStore,
    origin: &Name,
    kind: ZoneKind,
) -> Result<Option<Rrset>, AdminError> {
    if kind != ZoneKind::Primary {
        return Ok(None);
    }
    let Some(soa) = store
        .lookup(origin, origin, Rtype::SOA)
        .map_err(AdminError::Storage)?
    else {
        return Ok(None);
    };
    let mut rrset = crate::zonefile::rrset_from_stored(origin, Rtype::SOA, &soa)
        .map_err(|error| AdminError::Storage(error.to_string()))?;
    let Some(Rdata::Soa(mut data)) = rrset.rdatas().first().cloned() else {
        return Ok(None);
    };
    data.serial = data.serial.succ();
    rrset = Rrset::new(
        origin.clone(),
        Rtype::SOA,
        Rclass::IN,
        rrset.ttl(),
        [Rdata::Soa(data)],
    )
    .map_err(|error| map_rrset_error(&error))?;
    Ok(Some(rrset))
}

fn owner_types(store: &ZoneStore, origin: &Name, owner: &Name) -> Result<Vec<Rtype>, String> {
    let mut types = BTreeSet::new();
    store.with_zone_items(origin, |_file, _txn, _apex, items| {
        for item in items {
            let item = item.map_err(|error| error.to_string())?;
            let item_owner = name_from_rle(&item.name).map_err(|error| error.to_string())?;
            if &item_owner == owner && item.rr_type != 0 {
                types.insert(Rtype::from_u16(item.rr_type));
            }
        }
        Ok(())
    })?;
    Ok(types.into_iter().collect())
}

impl ZoneAdmin for SharedZoneAdmin {
    fn ready(&self) -> bool {
        self.store.is_some()
    }

    fn zonefile_metrics(&self) -> Option<ZoneFileMetrics> {
        Some(self.file_stats.metrics())
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
        let mut zones = store.zone_list().map_err(AdminError::Storage)?;
        zones.sort_by_key(|(_origin, entry)| entry.zone_seq);
        let mut items = Vec::new();
        let mut has_more = false;
        for (origin, entry) in zones {
            if cursor.is_some_and(|cursor| entry.zone_seq <= cursor) {
                continue;
            }
            if !allow.allows(&origin) {
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
            items.push(zone_view(store, &origin)?);
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
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let existing = store.zone_meta_block(origin).map_err(AdminError::Storage)?;
        let (created, old_snapshot) = if let Some((_apex, entry, old_meta)) = &existing {
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
            let apex =
                name_to_rle(origin).map_err(|error| AdminError::Storage(error.to_string()))?;
            let block = ZoneMetaBlock {
                default_ttl: meta.default_ttl.as_u32(),
                denial: denial_to_u8(meta.denial),
                ..*old_meta
            };
            let old = store.zone_snapshot(origin).map_err(AdminError::Storage)?;
            commit_action(store, move |writer| {
                writer
                    .set_zone_flags(&apex, kind_flags(meta.kind))
                    .map_err(|error| format!("update zone flags: {error}"))?;
                writer
                    .update_zone_meta(&apex, &block)
                    .map_err(|error| format!("update zone metadata: {error}"))?;
                Ok(())
            })
            .map_err(AdminError::Storage)?;
            (false, old)
        } else {
            check_create(preconditions)?;
            let apex =
                name_to_rle(origin).map_err(|error| AdminError::Storage(error.to_string()))?;
            let block = ZoneMetaBlock {
                default_ttl: meta.default_ttl.as_u32(),
                denial: denial_to_u8(meta.denial),
                ..ZoneMetaBlock::default()
            };
            commit_action(store, move |writer| {
                writer
                    .create_zone_with_meta(&apex, kind_flags(meta.kind), &block)
                    .map_err(|error| format!("create zone: {error}"))?;
                Ok(())
            })
            .map_err(AdminError::Storage)?;
            (true, None)
        };
        self.after_commit(origin, old_snapshot.as_ref());
        let view = zone_view(store, origin)?;
        Ok(if created {
            WriteOutcome::Created(view)
        } else {
            WriteOutcome::Updated(view)
        })
    }

    fn delete_zone(&self, origin: &Name, preconditions: &Preconditions) -> Result<(), AdminError> {
        let store = self.require_store()?;
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let view = zone_view(store, origin)?;
        check_existing(preconditions, &view.etag, view.version)?;
        let apex = name_to_rle(origin).map_err(|error| AdminError::Storage(error.to_string()))?;
        let old = store.zone_snapshot(origin).map_err(AdminError::Storage)?;
        commit_action(store, move |writer| {
            writer
                .delete_zone(&apex)
                .map_err(|error| format!("delete zone: {error}"))?;
            Ok(())
        })
        .map_err(AdminError::Storage)?;
        self.after_commit(origin, old.as_ref());
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
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((_apex, entry, _meta)) =
            store.zone_meta_block(origin).map_err(AdminError::Storage)?
        else {
            return Err(AdminError::zone_not_found());
        };
        let kind = kind_from_flags(entry.flags);
        if !kind.is_writable() {
            return Err(AdminError::Conflict(Conflict::ZoneReadOnly));
        }
        validate_type(origin, owner, rr_type)?;
        let current = store
            .lookup(origin, owner, rr_type)
            .map_err(AdminError::Storage)?;
        let existed = if let Some(view) = current {
            let rrset = crate::zonefile::rrset_from_stored(owner, rr_type, &view)
                .map_err(|error| AdminError::Storage(error.to_string()))?;
            check_existing(
                preconditions,
                &rrset_etag(&rrset),
                entry.last_commit_txn.max(1),
            )?;
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
        let apex = name_to_rle(origin).map_err(|error| AdminError::Storage(error.to_string()))?;
        let soa = if rr_type == Rtype::SOA {
            None
        } else {
            bumped_soa(store, origin, kind)?
        };
        let old = store.zone_snapshot(origin).map_err(AdminError::Storage)?;
        let stored = rrset.clone();
        commit_action(store, move |writer| {
            write_rrset(writer, &apex, &rrset)?;
            if let Some(soa) = &soa {
                write_rrset(writer, &apex, soa)?;
            }
            Ok(())
        })
        .map_err(AdminError::Storage)?;
        self.after_commit(origin, old.as_ref());
        let view = rrset_view(origin, &stored);
        Ok(if existed {
            WriteOutcome::Updated(view)
        } else {
            WriteOutcome::Created(view)
        })
    }

    fn patch_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        patch: &RrsetPatch,
        preconditions: &Preconditions,
    ) -> Result<RrsetPatchOutcome, AdminError> {
        let store = self.require_store()?;
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((_apex, entry, _meta)) =
            store.zone_meta_block(origin).map_err(AdminError::Storage)?
        else {
            return Err(AdminError::zone_not_found());
        };
        let kind = kind_from_flags(entry.flags);
        if !kind.is_writable() {
            return Err(AdminError::Conflict(Conflict::ZoneReadOnly));
        }
        let current = store
            .lookup(origin, owner, rr_type)
            .map_err(AdminError::Storage)?
            .ok_or_else(AdminError::rrset_not_found)?;
        let current = crate::zonefile::rrset_from_stored(owner, rr_type, &current)
            .map_err(|error| AdminError::Storage(error.to_string()))?;
        check_existing(
            preconditions,
            &rrset_etag(&current),
            entry.last_commit_txn.max(1),
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
        let apex = name_to_rle(origin).map_err(|error| AdminError::Storage(error.to_string()))?;
        let owner_rle =
            name_to_rle(owner).map_err(|error| AdminError::Storage(error.to_string()))?;
        let soa = if rr_type == Rtype::SOA {
            None
        } else {
            bumped_soa(store, origin, kind)?
        };
        let old = store.zone_snapshot(origin).map_err(AdminError::Storage)?;
        if next_set.is_empty() {
            commit_action(store, move |writer| {
                writer
                    .delete_rrset(&apex, &owner_rle, rr_type.as_u16(), 0)
                    .map_err(|error| format!("delete RRset: {error}"))?;
                writer
                    .ensure_empty_node(&apex, &owner_rle)
                    .map_err(|error| format!("preserve empty node: {error}"))?;
                if let Some(soa) = &soa {
                    write_rrset(writer, &apex, soa)?;
                }
                Ok(())
            })
            .map_err(AdminError::Storage)?;
            self.after_commit(origin, old.as_ref());
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
        let stored = rrset.clone();
        commit_action(store, move |writer| {
            write_rrset(writer, &apex, &rrset)?;
            if let Some(soa) = &soa {
                write_rrset(writer, &apex, soa)?;
            }
            Ok(())
        })
        .map_err(AdminError::Storage)?;
        self.after_commit(origin, old.as_ref());
        Ok(RrsetPatchOutcome::Updated {
            rrset: rrset_view(origin, &stored),
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
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((_apex, entry, _meta)) =
            store.zone_meta_block(origin).map_err(AdminError::Storage)?
        else {
            return Err(AdminError::zone_not_found());
        };
        let kind = kind_from_flags(entry.flags);
        if !kind.is_writable() {
            return Err(AdminError::Conflict(Conflict::ZoneReadOnly));
        }
        let current = store
            .lookup(origin, owner, rr_type)
            .map_err(AdminError::Storage)?
            .ok_or_else(AdminError::rrset_not_found)?;
        let current = crate::zonefile::rrset_from_stored(owner, rr_type, &current)
            .map_err(|error| AdminError::Storage(error.to_string()))?;
        check_existing(
            preconditions,
            &rrset_etag(&current),
            entry.last_commit_txn.max(1),
        )?;
        let apex = name_to_rle(origin).map_err(|error| AdminError::Storage(error.to_string()))?;
        let owner_rle =
            name_to_rle(owner).map_err(|error| AdminError::Storage(error.to_string()))?;
        let soa = bumped_soa(store, origin, kind)?;
        let old = store.zone_snapshot(origin).map_err(AdminError::Storage)?;
        commit_action(store, move |writer| {
            writer
                .delete_rrset(&apex, &owner_rle, rr_type.as_u16(), 0)
                .map_err(|error| format!("delete RRset: {error}"))?;
            writer
                .ensure_empty_node(&apex, &owner_rle)
                .map_err(|error| format!("preserve empty node: {error}"))?;
            if let Some(soa) = &soa {
                write_rrset(writer, &apex, soa)?;
            }
            Ok(())
        })
        .map_err(AdminError::Storage)?;
        self.after_commit(origin, old.as_ref());
        Ok(())
    }

    fn get_settings(&self, origin: &Name) -> Result<ZoneSettingsView, AdminError> {
        let store = self.require_store()?;
        let Some((_apex, entry, meta)) =
            store.zone_meta_block(origin).map_err(AdminError::Storage)?
        else {
            return Err(AdminError::zone_not_found());
        };
        let version = entry.last_commit_txn.max(1);
        Ok(ZoneSettingsView {
            zone: origin.clone(),
            settings: ZoneSettings {
                default_ttl: Ttl::new(meta.default_ttl).unwrap_or(Ttl::from_wire(3600)),
                denial: denial_from_u8(meta.denial).unwrap_or(Denial::Nsec),
            },
            version,
            etag: zone_etag(entry.zone_seq, version, entry.last_commit_txn),
            updated_at: system_time_from_unix_ns(entry.last_change_unix_ns),
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
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let Some((apex, entry, meta)) =
            store.zone_meta_block(origin).map_err(AdminError::Storage)?
        else {
            return Err(AdminError::zone_not_found());
        };
        let version = entry.last_commit_txn.max(1);
        check_existing(
            preconditions,
            &zone_etag(entry.zone_seq, version, entry.last_commit_txn),
            version,
        )?;
        let block = ZoneMetaBlock {
            default_ttl: patch.default_ttl.map_or(meta.default_ttl, Ttl::as_u32),
            denial: patch.denial.map_or(meta.denial, denial_to_u8),
            ..meta
        };
        commit_action(store, move |writer| {
            writer
                .update_zone_meta(&apex, &block)
                .map_err(|error| format!("update zone metadata: {error}"))?;
            Ok(())
        })
        .map_err(AdminError::Storage)?;
        self.get_settings(origin)
    }

    fn sign_zone(&self, origin: &Name) -> Result<pulse_api::ZoneView, AdminError> {
        let store = self.require_store()?;
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let signer = self.dnssec.signer(origin).ok_or_else(|| {
            AdminError::invariant(
                "/zone",
                "dnssec-not-configured",
                "zone has no DNSSEC keys configured",
            )
        })?;
        let Some((_apex, entry, meta)) =
            store.zone_meta_block(origin).map_err(AdminError::Storage)?
        else {
            return Err(AdminError::zone_not_found());
        };
        let rrsets = store.zone_rrsets(origin).map_err(AdminError::Storage)?;
        let old = store.zone_snapshot(origin).map_err(AdminError::Storage)?;
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
        let default_ttl = Ttl::new(meta.default_ttl).unwrap_or(Ttl::from_wire(3600));
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
        self.after_commit(origin, old.as_ref());
        zone_view(store, origin)
    }
}

fn check_owner_conflicts(
    store: &ZoneStore,
    origin: &Name,
    owner: &Name,
    rr_type: Rtype,
) -> Result<(), AdminError> {
    let types = owner_types(store, origin, owner).map_err(AdminError::Storage)?;
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
