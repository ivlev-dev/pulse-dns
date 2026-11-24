//! Адаптер `pulse-api::ZoneAdmin` → `pulse-server::QueryEngine`.
//!
//! In-memory store — источник истины. После каждой успешной мутации адаптер
//! строит новый снапшот всех зон и атомарно подменяет `Arc<QueryEngine>`.
//! DNS-запрос берёт `Arc` под коротким read-lock и отвечает уже без блокировок
//! store; таким образом write-lock никогда не удерживается на время запроса.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use pulse_api::{
    AdminError, Denial, InMemoryZoneAdmin, ListRrsets, ListZones, Preconditions, RrsetInput,
    RrsetPatch, RrsetPatchOutcome, RrsetView, StoreSnapshot, WriteOutcome, ZoneAdmin, ZoneAllow,
    ZoneKind, ZoneMetaInput, ZonePage, ZoneSettingsPatch, ZoneSettingsView,
};
use pulse_dns::{Name, Rtype};
use pulse_server::testkit::InMemoryZone;
use pulse_server::{QueryEngine, QueryStats, ZoneState};
use thiserror::Error;

use crate::config::Config;
use crate::dnssec::{self, DnssecSigners};
use crate::logging;
use crate::master;
use crate::persist::{PersistenceError, ZonePersistence};
use crate::zone::{self, LoadedZone};

/// Ошибка начального построения DNS-снапшота.
#[derive(Debug, Error)]
#[error("zone snapshot cannot be served: {0}")]
pub(crate) struct StoreError(String);

/// Store с актуальным `QueryEngine` и сериализацией перестроений.
pub(crate) struct SharedZoneAdmin {
    store: Arc<InMemoryZoneAdmin>,
    engine: RwLock<Arc<QueryEngine>>,
    query_stats: Arc<QueryStats>,
    revision: AtomicU64,
    rebuild: Mutex<()>,
    mutation: Mutex<()>,
    persistence: Option<Mutex<ZonePersistence>>,
    dnssec: DnssecSigners,
}

impl SharedZoneAdmin {
    pub(crate) fn new(
        store: Arc<InMemoryZoneAdmin>,
        dnssec: DnssecSigners,
        persistence: Option<ZonePersistence>,
    ) -> Result<Self, StoreError> {
        let query_stats = Arc::new(QueryStats::new());
        let snapshot = store.snapshot();
        let engine = build_engine(&snapshot, Arc::clone(&query_stats)).map_err(StoreError)?;
        Ok(Self {
            store,
            engine: RwLock::new(Arc::new(engine)),
            query_stats,
            revision: AtomicU64::new(snapshot.revision),
            rebuild: Mutex::new(()),
            mutation: Mutex::new(()),
            persistence: persistence.map(Mutex::new),
            dnssec,
        })
    }

    /// Текущий движок. Read-lock удерживается только на клонирование `Arc`.
    pub(crate) fn engine(&self) -> Arc<QueryEngine> {
        Arc::clone(&self.engine.read().unwrap_or_else(PoisonError::into_inner))
    }

    pub(crate) fn query_stats(&self) -> Arc<QueryStats> {
        Arc::clone(&self.query_stats)
    }

    fn refresh(&self) -> Result<(), AdminError> {
        let _guard = self.rebuild.lock().unwrap_or_else(PoisonError::into_inner);
        let snapshot = self.store.snapshot();
        if snapshot.revision == self.revision.load(Ordering::Acquire) {
            return Ok(());
        }
        let engine = build_engine(&snapshot, Arc::clone(&self.query_stats)).map_err(|error| {
            logging::error("zone_store", &error);
            AdminError::Internal
        })?;
        *self.engine.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(engine);
        self.revision.store(snapshot.revision, Ordering::Release);
        Ok(())
    }

    fn persist(
        &self,
        action: impl FnOnce(&mut ZonePersistence) -> Result<(), PersistenceError>,
    ) -> Result<(), AdminError> {
        if let Some(persistence) = &self.persistence {
            let mut guard = persistence.lock().unwrap_or_else(PoisonError::into_inner);
            action(&mut guard).map_err(|error| {
                logging::error("zone_store", &format!("persistence: {error}"));
                AdminError::Storage(error.to_string())
            })?;
        }
        Ok(())
    }

    fn finish_mutation(
        &self,
        action: impl FnOnce(&mut ZonePersistence) -> Result<(), PersistenceError>,
    ) -> Result<(), AdminError> {
        let persisted = self.persist(action);
        let refreshed = self.refresh();
        persisted?;
        refreshed
    }

    fn owner_has_rrsets(&self, origin: &Name, owner: &Name) -> bool {
        self.store
            .snapshot()
            .zones
            .iter()
            .find(|zone| &zone.origin == origin)
            .is_some_and(|zone| zone.rrsets.iter().any(|rrset| rrset.owner() == owner))
    }

    /// `sync()` persistence при graceful shutdown.
    pub(crate) fn sync_persistence(&self) -> Result<(), String> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(persistence) = &self.persistence {
            let mut guard = persistence.lock().unwrap_or_else(PoisonError::into_inner);
            guard.sync().map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

/// Загружает JSON-зоны и master-файлы в один store.
///
/// Конфликт origin между любыми источниками (JSON, `zones_files`, CLI
/// `--zone`) обнаруживается **до** импорта и завершает запуск. Импорт
/// допускает DNSSEC-записи из файлов, которые HTTP RRset API намеренно не
/// принимает.
pub(crate) fn load_config(
    store: &InMemoryZoneAdmin,
    config: &Config,
    dnssec: &DnssecSigners,
) -> Result<(), String> {
    let mut zones: Vec<(String, LoadedZone)> = Vec::new();
    let json_zones =
        zone::load_zones(&config.zones).map_err(|error| format!("JSON zones: {error}"))?;
    for (index, zone) in json_zones.into_iter().enumerate() {
        zones.push((format!("config.zones[{index}]"), zone));
    }
    for (index, file) in config.zones_files.iter().enumerate() {
        let loaded = master::load_zone_file(file)
            .map_err(|error| format!("zones_files[{index}] ({}): {error}", file.path.display()))?;
        zones.push((
            format!("zone file {} (zones_files[{index}])", file.path.display()),
            loaded,
        ));
    }

    let mut origins: HashMap<Name, String> = HashMap::with_capacity(zones.len());
    for (source, zone) in &zones {
        if let Some(first) = origins.insert(zone.origin.clone(), source.clone()) {
            return Err(format!(
                "zone {} is declared more than once: {first} and {source}",
                zone.origin
            ));
        }
    }

    let mut signed_origins: HashSet<Name> = HashSet::with_capacity(dnssec.len());
    for (source, mut zone) in zones {
        if let Some(signer) = dnssec.signer(&zone.origin) {
            let signed = signer
                .sign_zone(&zone.origin, &zone.rrsets, dnssec::now_unix())
                .map_err(|error| format!("{source}: cannot sign zone {}: {error}", zone.origin))?;
            logging::info(
                "dnssec",
                &format!(
                    "zone {} signed: keys={} key_tags={:?} rrsets={} rrsigs={}",
                    zone.origin,
                    signed.dnskeys.len(),
                    signed.key_tags,
                    signed.rrsets.len(),
                    signed.rrsig_count
                ),
            );
            zone.rrsets = signed.rrsets;
            signed_origins.insert(zone.origin.clone());
        }
        let meta = ZoneMetaInput {
            kind: ZoneKind::Primary,
            default_ttl: zone.default_ttl,
            denial: Denial::Nsec,
        };
        store
            .import_zone(&zone.origin, &meta, zone.rrsets)
            .map_err(|error| format!("{source}: cannot import zone {}: {error}", zone.origin))?;
    }
    for origin in dnssec.origins() {
        if !signed_origins.contains(origin) {
            return Err(format!(
                "DNSSEC is configured for zone {origin}, but the zone is not loaded"
            ));
        }
    }
    Ok(())
}

fn build_engine(snapshot: &StoreSnapshot, stats: Arc<QueryStats>) -> Result<QueryEngine, String> {
    let mut views: Vec<Arc<dyn pulse_server::ZoneView>> = Vec::with_capacity(snapshot.zones.len());
    for zone in &snapshot.zones {
        let has_soa = zone.rrsets.iter().any(|rrset| {
            rrset.owner() == &zone.origin && rrset.rr_type() == Rtype::SOA && rrset.len() == 1
        });
        let has_ns = zone.rrsets.iter().any(|rrset| {
            rrset.owner() == &zone.origin && rrset.rr_type() == Rtype::NS && !rrset.is_empty()
        });
        // Secondary/Forward пока не обслуживаются авторитетно; отсутствие
        // apex SOA/NS означает незавершённую зону. В обоих случаях QueryEngine
        // отвечает REFUSED, а не NXDOMAIN.
        let zone_state = if zone.kind == ZoneKind::Primary && has_soa && has_ns {
            ZoneState::Serving
        } else {
            ZoneState::Initializing
        };
        let mut view = InMemoryZone::new(zone.origin.clone()).with_state(zone_state);
        for rrset in &zone.rrsets {
            view.insert(rrset.clone())
                .map_err(|error| format!("zone {}: {error}", zone.origin))?;
        }
        for node in &zone.nodes {
            view.insert_node(node.clone())
                .map_err(|error| format!("zone {}: {error}", zone.origin))?;
        }
        views.push(Arc::new(view));
    }
    Ok(QueryEngine::with_stats(views, stats))
}

impl ZoneAdmin for SharedZoneAdmin {
    fn ready(&self) -> bool {
        self.store.ready()
    }

    fn list_zones(&self, query: &ListZones, allow: &dyn ZoneAllow) -> Result<ZonePage, AdminError> {
        self.store.list_zones(query, allow)
    }

    fn get_zone(&self, origin: &Name) -> Result<pulse_api::ZoneView, AdminError> {
        self.store.get_zone(origin)
    }

    fn put_zone(
        &self,
        origin: &Name,
        meta: &ZoneMetaInput,
        preconditions: &Preconditions,
    ) -> Result<WriteOutcome<pulse_api::ZoneView>, AdminError> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = self.store.put_zone(origin, meta, preconditions)?;
        let view = outcome.value().clone();
        let created = outcome.is_created();
        self.finish_mutation(|persistence| persistence.put_zone(&view, created))?;
        Ok(outcome)
    }

    fn delete_zone(&self, origin: &Name, preconditions: &Preconditions) -> Result<(), AdminError> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        self.store.delete_zone(origin, preconditions)?;
        self.finish_mutation(|persistence| persistence.delete_zone(origin))
    }

    fn list_rrsets(
        &self,
        origin: &Name,
        query: &ListRrsets,
    ) -> Result<pulse_api::RrsetPage, AdminError> {
        self.store.list_rrsets(origin, query)
    }

    fn get_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
    ) -> Result<RrsetView, AdminError> {
        self.store.get_rrset(origin, owner, rr_type)
    }

    fn put_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        input: &RrsetInput,
        preconditions: &Preconditions,
    ) -> Result<WriteOutcome<RrsetView>, AdminError> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = self
            .store
            .put_rrset(origin, owner, rr_type, input, preconditions)?;
        let view = outcome.value().clone();
        self.finish_mutation(|persistence| persistence.put_rrset(&view))?;
        Ok(outcome)
    }

    fn patch_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        patch: &RrsetPatch,
        preconditions: &Preconditions,
    ) -> Result<RrsetPatchOutcome, AdminError> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = self
            .store
            .patch_rrset(origin, owner, rr_type, patch, preconditions)?;
        match &outcome {
            RrsetPatchOutcome::Updated { rrset, .. } => {
                let rrset = rrset.clone();
                self.finish_mutation(|persistence| persistence.put_rrset(&rrset))?;
            }
            RrsetPatchOutcome::Deleted { .. } => {
                let keep_empty_node = !self.owner_has_rrsets(origin, owner);
                self.finish_mutation(|persistence| {
                    persistence.delete_rrset(origin, owner, rr_type, keep_empty_node)
                })?;
            }
        }
        Ok(outcome)
    }

    fn delete_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        preconditions: &Preconditions,
    ) -> Result<(), AdminError> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        self.store
            .delete_rrset(origin, owner, rr_type, preconditions)?;
        let keep_empty_node = !self.owner_has_rrsets(origin, owner);
        self.finish_mutation(|persistence| {
            persistence.delete_rrset(origin, owner, rr_type, keep_empty_node)
        })
    }

    fn get_settings(&self, origin: &Name) -> Result<ZoneSettingsView, AdminError> {
        self.store.get_settings(origin)
    }

    fn patch_settings(
        &self,
        origin: &Name,
        patch: &ZoneSettingsPatch,
        preconditions: &Preconditions,
    ) -> Result<ZoneSettingsView, AdminError> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let view = self.store.patch_settings(origin, patch, preconditions)?;
        let persisted = view.clone();
        self.finish_mutation(|persistence| persistence.patch_settings(&persisted))?;
        Ok(view)
    }

    fn sign_zone(&self, origin: &Name) -> Result<pulse_api::ZoneView, AdminError> {
        let _guard = self.mutation.lock().unwrap_or_else(PoisonError::into_inner);
        let signer = self.dnssec.signer(origin).ok_or_else(|| {
            AdminError::invariant(
                "/zone",
                "dnssec-not-configured",
                "zone has no DNSSEC keys configured",
            )
        })?;
        let snapshot = self.store.snapshot();
        let zone = snapshot
            .zones
            .iter()
            .find(|zone| &zone.origin == origin)
            .ok_or_else(AdminError::zone_not_found)?;
        let signed_zone = signer
            .sign_zone(origin, &zone.rrsets, dnssec::now_unix())
            .map_err(|error| {
                logging::error(
                    "dnssec_sign",
                    &format!("zone {origin}: cannot sign: {error}"),
                );
                AdminError::Internal
            })?;
        self.store
            .replace_zone_rrsets(origin, signed_zone.rrsets)
            .map_err(|error| {
                logging::error(
                    "dnssec_sign",
                    &format!("zone {origin}: cannot store signed zone: {error}"),
                );
                AdminError::Internal
            })?;
        let signed_snapshot = self
            .store
            .snapshot()
            .zones
            .into_iter()
            .find(|zone| &zone.origin == origin)
            .ok_or(AdminError::Internal)?;
        self.finish_mutation(|persistence| persistence.replace_zone(&signed_snapshot))?;
        self.store.get_zone(origin)
    }
}
