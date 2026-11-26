//! Адаптер `pulse-api::ZoneAdmin` и `pulse-server::ZoneView` поверх
//! `pulse-zonefile` v2 (`ParallelStore`).
//!
//! Единственный источник истины — mmap-файл зон. DNS-ответы читают его через
//! [`FileZoneView`]; REST-мутации открывают per-zone writer, применяют правку и
//! коммитят. Разные зоны пишутся параллельно (lease у зоны один), а view зоны
//! после коммита перечитывает apex SOA/NS; полной in-memory копии зон нет.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime};

use pulse_api::{
    AdminError, Conflict, Denial, ImportMode, ImportReport, KeyRotationKeyView, KeyRotationView,
    ListRrsets, ListZones, Precondition, Preconditions, RolloverRequest, RrsetInput, RrsetPatch,
    RrsetPatchOutcome, RrsetView, SerialState, SerialUpdate, SerialUpdateResult, TransferRequest,
    TransferResult, WriteOutcome, ZoneAdmin, ZoneAllow, ZoneFileMetrics, ZoneKind, ZoneMetaInput,
    ZonePage, ZoneSettings, ZoneSettingsPatch, ZoneSettingsView, next_serial,
};
use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Serial, Ttl, UpdateError, UpdateRequest};
use pulse_server::dnssec_incremental::{SignNode, UpdateChanges, ZoneEdit};
use pulse_server::update::{UpdateOutcome, UpdateTarget};
use pulse_server::{
    DenialKind, QueryEngine, QueryStats, ResponseCache, ResponseCacheMetrics,
    ZoneState as ServerZoneState, ZoneView,
};
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

/// Состояние зоны для политики DNS UPDATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UpdateZoneState {
    /// Вид зоны.
    pub kind: ZoneKind,
    /// Класс зоны.
    pub class: Rclass,
    /// Зона отдаётся авторитетно (не expired/tombstone).
    pub serving: bool,
}

/// Общий администратор: zonefile, DNS-движок, transfer и secondary.
pub(crate) struct SharedZoneAdmin {
    store: Option<Arc<ZoneStore>>,
    /// `origin → view`; движок собирается из этих view.
    views: RwLock<HashMap<Name, Arc<FileZoneView>>>,
    /// Версия головы, из которой построена view (для poll роли `dns`).
    view_versions: RwLock<HashMap<Name, u64>>,
    engine: RwLock<Arc<QueryEngine>>,
    query_stats: Arc<QueryStats>,
    /// Кеш готовых ответов, общий для всех поколений движка.
    response_cache: Arc<ResponseCache>,
    file_stats: Arc<ZoneFileStats>,
    /// Сериализует операции с каталогом (create/delete/replace), не RRset-правки.
    catalog: Mutex<()>,
    dnssec: DnssecSigners,
    transfer: TransferState,
    secondary: SecondaryManager,
    update: crate::update::UpdateService,
    tsig_keys: Arc<crate::tsigkeys::TsigKeyStore>,
}

impl SharedZoneAdmin {
    pub(crate) fn new(
        store: Option<Arc<ZoneStore>>,
        dnssec: DnssecSigners,
        config: &Config,
        notify: Option<Arc<NotifyDispatcher>>,
    ) -> Result<Self, StoreError> {
        let query_stats = Arc::new(QueryStats::new());
        let response_cache = Arc::new(ResponseCache::new(config.response_cache.to_engine_config()));
        let file_stats = store
            .as_ref()
            .map_or_else(|| Arc::new(ZoneFileStats::default()), |store| store.stats());
        let tsig_keys = Arc::new(
            crate::tsigkeys::TsigKeyStore::load(&config.tsig_keys, config.tsig_state_file.clone())
                .map_err(|error| StoreError(format!("cannot load TSIG keys: {error}")))?,
        );
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
            Arc::clone(&tsig_keys),
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
        let mut versions = HashMap::with_capacity(zones.len());
        for entry in &zones {
            let Some(store) = &store else {
                continue;
            };
            let view = FileZoneView::new(Arc::clone(store), entry, server_state(entry, &expired))
                .map_err(StoreError)?;
            views.insert(entry.origin.clone(), Arc::new(view));
            versions.insert(entry.origin.clone(), entry.version);
        }
        let engine = build_engine(&views, &query_stats, &response_cache);
        let update = crate::update::UpdateService::new(config, Arc::clone(&tsig_keys))
            .map_err(StoreError)?;
        Ok(Self {
            store,
            views: RwLock::new(views),
            view_versions: RwLock::new(versions),
            engine: RwLock::new(engine),
            query_stats,
            response_cache,
            file_stats,
            catalog: Mutex::new(()),
            dnssec,
            transfer,
            secondary,
            update,
            tsig_keys,
        })
    }

    /// Обрабатывает пакет UPDATE, если opcode совпадает.
    ///
    /// `None` — это не UPDATE; иначе готовый wire-ответ (включая TSIG).
    pub(crate) fn handle_dns_update(
        &self,
        raw: &[u8],
        source: std::net::IpAddr,
        now: u64,
    ) -> Option<Vec<u8>> {
        self.update.handle(self, raw, source, now)
    }

    pub(crate) fn update_metrics(&self) -> Arc<crate::update::UpdateMetrics> {
        self.update.metrics()
    }

    /// Перечитывает state-файл управляемых ключей.
    pub(crate) fn reload_tsig_keys(&self) -> Result<usize, String> {
        self.tsig_keys.reload().map_err(|error| error.to_string())
    }

    /// Текущий движок. Read-lock удерживается только на клонирование `Arc`.
    pub(crate) fn engine(&self) -> Arc<QueryEngine> {
        Arc::clone(&self.engine.read().unwrap_or_else(PoisonError::into_inner))
    }

    pub(crate) fn query_stats(&self) -> Arc<QueryStats> {
        Arc::clone(&self.query_stats)
    }

    /// Снимок метрик кеша готовых ответов.
    pub(crate) fn response_cache_metrics(&self) -> ResponseCacheMetrics {
        self.response_cache.metrics()
    }

    /// Интервал фоновой ротации ключей, если она настроена.
    pub(crate) fn rotation_tick(&self) -> Option<Duration> {
        self.dnssec.rotation_tick()
    }

    /// Продвигает ротацию и переподписывает изменившиеся зоны.
    pub(crate) fn advance_rotations(&self) -> usize {
        let changed = self.dnssec.advance_all(dnssec::now_unix());
        let mut resigned = 0_usize;
        for origin in changed {
            match ZoneAdmin::sign_zone(self, &origin) {
                Ok(_) => {
                    resigned = resigned.saturating_add(1);
                    logging::info(
                        "dnssec_rotation",
                        &format!("zone {origin} re-signed after key rotation"),
                    );
                }
                Err(error) => logging::error(
                    "dnssec_rotation",
                    &format!("zone {origin}: cannot re-sign after rotation: {error}"),
                ),
            }
        }
        resigned
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

    pub(crate) fn run_transfer(
        &self,
        origin: &Name,
        request: &TransferRequest,
    ) -> Result<TransferResult, AdminError> {
        let store = self.require_store()?;
        let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
            return Err(AdminError::zone_not_found());
        };
        let kind = kind_from_flags(entry.flags);
        let view = zone_view(store, origin)?;
        match kind {
            ZoneKind::Primary => {
                if let Some(from_serial) = request.from_serial
                    && Serial::new(from_serial).is_newer_than(view.serial) != Some(false)
                {
                    return Err(AdminError::invariant(
                        "/from_serial",
                        "serial-not-older",
                        "from_serial must be older than the current serial",
                    ));
                }
                logging::info(
                    "transfer",
                    &format!(
                        "{origin}: outgoing {} requested via API",
                        request.kind.as_str()
                    ),
                );
                Ok(TransferResult {
                    zone: origin.clone(),
                    kind: request.kind,
                    mode_used: request.kind,
                    serial: Some(view.serial),
                    rrsets: Some(view.rrset_count),
                    bytes: None,
                    peer: request.peer.clone(),
                    outgoing: true,
                })
            }
            ZoneKind::Secondary => {
                if let Some(from_serial) = request.from_serial
                    && Serial::new(from_serial).is_newer_than(view.serial) != Some(false)
                {
                    return Err(AdminError::invariant(
                        "/from_serial",
                        "serial-not-older",
                        "from_serial must be older than the current serial",
                    ));
                }
                let Some(zone) = self.secondary.get(origin) else {
                    return Err(AdminError::Conflict(Conflict::InvalidZoneState));
                };
                let Some(_lease) = zone.try_lease() else {
                    return Err(AdminError::Conflict(Conflict::TransferInProgress));
                };
                let local = store.zone_snapshot(origin).ok().flatten();
                let update =
                    zone.fetch(local.as_ref(), self.transfer.limits())
                        .map_err(|error| {
                            logging::warn(
                                "transfer",
                                &format!("zone {origin}: incoming transfer failed: {error}"),
                            );
                            AdminError::Storage("incoming transfer failed".to_owned())
                        })?;
                let serial = match update.soa().rdata() {
                    Rdata::Soa(soa) => Some(soa.serial),
                    _ => None,
                };
                if let SecondaryUpdate::Zone(_) = &update {
                    self.apply_secondary_update(origin, &update, local.as_ref())
                        .map_err(|error| {
                            logging::error(
                                "transfer",
                                &format!("zone {origin}: cannot apply transfer: {error}"),
                            );
                            AdminError::Storage("cannot apply incoming transfer".to_owned())
                        })?;
                }
                zone.note_success(update.soa(), Instant::now());
                let refreshed = zone_view(store, origin)?;
                Ok(TransferResult {
                    zone: origin.clone(),
                    kind: request.kind,
                    mode_used: request.kind,
                    serial,
                    rrsets: Some(refreshed.rrset_count),
                    bytes: None,
                    peer: request.peer.clone(),
                    outgoing: false,
                })
            }
            ZoneKind::Forward => Err(AdminError::Conflict(Conflict::InvalidZoneState)),
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
        let mut versions = self
            .view_versions
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let invalidated = entry.as_ref().map_or_else(
            || views.get(origin).map(|view| u64::from(view.zone_seq())),
            |entry| Some(u64::from(entry.zone_seq)),
        );
        if let Some(entry) = entry {
            let view = FileZoneView::new(Arc::clone(store), &entry, server_state(&entry, &expired))
                .map_err(|error| {
                    logging::error("zone_store", &error);
                    AdminError::Internal
                })?;
            views.insert(origin.clone(), Arc::new(view));
            versions.insert(origin.clone(), entry.version);
        } else {
            views.remove(origin);
            versions.remove(origin);
        }
        let engine = build_engine(&views, &self.query_stats, &self.response_cache);
        *self.engine.write().unwrap_or_else(PoisonError::into_inner) = engine;
        if let Some(seq) = invalidated {
            self.response_cache.invalidate_zone(seq);
        }
        Ok(())
    }

    /// Подхватывает внешние изменения zonefile (multi-process роль `dns`).
    ///
    /// Перечитывает каталог, сравнивает версии голов и перестраивает только
    /// изменившиеся view; данные зон не копируются — точечные чтения идут из
    /// mmap по текущей голове. Возвращает число обновлённых/удалённых зон.
    pub(crate) fn poll_zonefile(&self) -> Result<usize, String> {
        let Some(store) = &self.store else {
            return Ok(0);
        };
        if store.refresh_catalog()? {
            // Изменился набор зон или метаданные каталога (create/delete/
            // settings): перестраиваем view целиком, это редкое событие.
            let count = store.list_zones()?.len();
            self.rebuild_all_views().map_err(|error| match error {
                AdminError::Storage(error) => error,
                _ => "cannot rebuild DNS views after catalog change".to_owned(),
            })?;
            return Ok(count.max(1));
        }
        let zones = store.list_zones()?;
        let expired = self.secondary.expired_origins();
        let mut changed = 0_usize;
        let mut invalidated = Vec::new();
        {
            let mut views = self.views.write().unwrap_or_else(PoisonError::into_inner);
            let mut versions = self
                .view_versions
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            let known: HashSet<Name> = versions.keys().cloned().collect();
            for entry in &zones {
                let same = versions.get(&entry.origin) == Some(&entry.version);
                if same {
                    continue;
                }
                let view =
                    FileZoneView::new(Arc::clone(store), entry, server_state(entry, &expired))
                        .map_err(|error| format!("zone {}: {error}", entry.origin))?;
                views.insert(entry.origin.clone(), Arc::new(view));
                versions.insert(entry.origin.clone(), entry.version);
                invalidated.push(u64::from(entry.zone_seq));
                changed = changed.saturating_add(1);
            }
            let present: HashSet<Name> = zones.iter().map(|entry| entry.origin.clone()).collect();
            for origin in known.difference(&present) {
                // `list_zones` пропускает зону с нестабильной головой на время
                // публикации; не удаляем view, пока каталог её ещё содержит.
                if store.zone_entry(origin).ok().flatten().is_some() {
                    continue;
                }
                if let Some(view) = views.remove(origin) {
                    invalidated.push(u64::from(view.zone_seq()));
                }
                versions.remove(origin);
                changed = changed.saturating_add(1);
            }
        }
        for seq in invalidated {
            self.response_cache.invalidate_zone(seq);
        }
        if changed > 0 {
            let views = self.views.read().unwrap_or_else(PoisonError::into_inner);
            let engine = build_engine(&views, &self.query_stats, &self.response_cache);
            *self.engine.write().unwrap_or_else(PoisonError::into_inner) = engine;
        }
        Ok(changed)
    }

    fn rebuild_all_views(&self) -> Result<(), AdminError> {
        let Some(store) = &self.store else {
            let empty = QueryEngine::with_stats(Vec::new(), Arc::clone(&self.query_stats));
            *self.engine.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(empty);
            self.response_cache.invalidate_all();
            return Ok(());
        };
        let zones = store.list_zones().map_err(AdminError::Storage)?;
        let expired = self.secondary.expired_origins();
        let mut views = HashMap::with_capacity(zones.len());
        let mut versions = HashMap::with_capacity(zones.len());
        for entry in &zones {
            let view = FileZoneView::new(Arc::clone(store), entry, server_state(entry, &expired))
                .map_err(|error| {
                logging::error("zone_store", &error);
                AdminError::Internal
            })?;
            views.insert(entry.origin.clone(), Arc::new(view));
            versions.insert(entry.origin.clone(), entry.version);
        }
        let engine = build_engine(&views, &self.query_stats, &self.response_cache);
        *self.views.write().unwrap_or_else(PoisonError::into_inner) = views;
        *self
            .view_versions
            .write()
            .unwrap_or_else(PoisonError::into_inner) = versions;
        *self.engine.write().unwrap_or_else(PoisonError::into_inner) = engine;
        self.response_cache.invalidate_all();
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

    /// Состояние зоны для политики UPDATE.
    ///
    /// # Errors
    ///
    /// Строка с ошибкой чтения каталога/головы зоны.
    pub(crate) fn update_zone_state(
        &self,
        origin: &Name,
    ) -> Result<Option<UpdateZoneState>, String> {
        let Some(store) = &self.store else {
            return Ok(None);
        };
        let Some(entry) = store.zone_entry(origin)? else {
            return Ok(None);
        };
        let expired = self.secondary.expired_origins();
        Ok(Some(UpdateZoneState {
            kind: kind_from_flags(entry.flags),
            class: Rclass::IN,
            serving: server_state(&entry, &expired) == ServerZoneState::Serving,
        }))
    }

    /// Применяет разобранный UPDATE одной транзакцией writer'а.
    ///
    /// Prerequisites проверяются движком на незакоммиченном дереве до первой
    /// записи; любая ошибка оставляет writer без commit, поэтому частичных
    /// изменений нет. После коммита обновляются IXFR-история/NOTIFY и view
    /// движка.
    ///
    /// # Errors
    ///
    /// [`UpdateError`] с кодом RFC 2136; ошибки хранилища маппятся в
    /// `SERVFAIL`.
    pub(crate) fn apply_zone_update(
        &self,
        request: &UpdateRequest,
    ) -> Result<UpdateOutcome, UpdateError> {
        let store = self.store.as_ref().ok_or(UpdateError::Refused {
            reason: "zonefile is not configured",
        })?;
        let Some(entry) = store.zone_entry(request.zone()).map_err(servfail)? else {
            return Err(UpdateError::NotAuthoritative {
                zone: request.zone().to_string(),
            });
        };
        if kind_from_flags(entry.flags) != ZoneKind::Primary {
            return Err(UpdateError::Refused {
                reason: "only primary zones accept UPDATE",
            });
        }
        let expired = self.secondary.expired_origins();
        if server_state(&entry, &expired) != ServerZoneState::Serving {
            return Err(UpdateError::Refused {
                reason: "zone is not serving",
            });
        }
        let previous = {
            let mut writer = store.open_writer(request.zone()).map_err(servfail)?;
            let base_version = writer.version();
            let previous = self.previous_snapshot(request.zone(), store);
            let (outcome, changes) = {
                let mut target = StoreUpdateTarget {
                    writer: &mut writer,
                    origin: request.zone().clone(),
                    class: Rclass::IN,
                    initial: HashMap::new(),
                    cut_before: HashMap::new(),
                };
                let outcome = pulse_server::update::apply_update(&mut target, request)?;
                let changes = target.finish()?;
                (outcome, changes)
            };
            writer.set_soa_serial(outcome.serial.as_u32());

            // Переподпись идёт в той же незакоммиченной транзакции: ошибка
            // ключа/подписи оставляет writer без commit, читатель не видит
            // зону с устаревшими RRSIG/NSEC.
            let mut zone_update = self.dnssec.zone_update(request.zone());
            if let Some(update) = zone_update.as_mut() {
                let mut edit = WriterEdit {
                    writer: &mut writer,
                    origin: request.zone().clone(),
                };
                update
                    .resign(&mut edit, &changes, base_version, crate::dnssec::now_unix())
                    .map_err(servfail)?;
            }
            let committed = store.commit_writer(&mut writer).map_err(servfail)?;
            if let Some(update) = zone_update.as_mut() {
                update.committed(committed.version);
            }
            (outcome, previous)
        };
        self.after_commit(request.zone(), previous.1.as_ref());
        Ok(previous.0)
    }
}

fn servfail(error: impl std::fmt::Display) -> UpdateError {
    UpdateError::ServFail {
        reason: error.to_string(),
    }
}

/// Адаптер [`UpdateTarget`] поверх незакоммиченного `ParallelZone`.
struct StoreUpdateTarget<'a, 'z> {
    writer: &'a mut ParallelZone<'z>,
    origin: Name,
    class: Rclass,
    /// Значение RRset до первой правки: по нему считается фактический diff.
    initial: HashMap<(Name, Rtype), Option<Rrset>>,
    /// Статус zone cut до первой правки NS.
    cut_before: HashMap<Name, bool>,
}

impl StoreUpdateTarget<'_, '_> {
    fn read_rrset(
        writer: &ParallelZone<'_>,
        name: &Name,
        rr_type: Rtype,
    ) -> Result<Option<Rrset>, UpdateError> {
        let owner = name_to_rle(name).map_err(servfail)?;
        let Some(record) = writer
            .lookup(&owner, rr_type.as_u16(), 0)
            .map_err(servfail)?
        else {
            return Ok(None);
        };
        let view = pulse_zonefile::RrsetView {
            ttl: record.ttl,
            flags: record.flags,
            rdata: record.rdata,
        };
        crate::zonefile::rrset_from_stored(name, rr_type, &view)
            .map(Some)
            .map_err(servfail)
    }

    fn record_initial(&mut self, name: &Name, rr_type: Rtype) -> Result<(), UpdateError> {
        let key = (name.clone(), rr_type);
        if self.initial.contains_key(&key) {
            return Ok(());
        }
        let before = Self::read_rrset(self.writer, name, rr_type)?;
        self.initial.insert(key, before);
        Ok(())
    }

    fn record_cut(&mut self, name: &Name) -> Result<(), UpdateError> {
        if self.cut_before.contains_key(name) {
            return Ok(());
        }
        let owner = name_to_rle(name).map_err(servfail)?;
        let cut = self
            .writer
            .node(&owner)
            .map(|node| node.is_zone_cut)
            .map_err(servfail)?;
        self.cut_before.insert(name.clone(), cut);
        Ok(())
    }

    fn finish(&mut self) -> Result<UpdateChanges, UpdateError> {
        let mut rrsets = Vec::new();
        for ((name, rr_type), before) in &self.initial {
            let after = Self::read_rrset(self.writer, name, *rr_type)?;
            if after.as_ref() != before.as_ref() {
                rrsets.push((name.clone(), *rr_type));
            }
        }
        rrsets.sort_by(|left, right| {
            left.0
                .cmp_canonical(&right.0)
                .then_with(|| left.1.as_u16().cmp(&right.1.as_u16()))
        });
        let mut cut_changes = Vec::new();
        for (name, before) in &self.cut_before {
            let owner = name_to_rle(name).map_err(servfail)?;
            let after = self
                .writer
                .node(&owner)
                .map(|node| node.is_zone_cut)
                .map_err(servfail)?;
            if after != *before {
                cut_changes.push(name.clone());
            }
        }
        cut_changes.sort_by(Name::cmp_canonical);
        Ok(UpdateChanges {
            rrsets,
            cut_changes,
        })
    }
}

impl UpdateTarget for StoreUpdateTarget<'_, '_> {
    fn origin(&self) -> &Name {
        &self.origin
    }

    fn zone_class(&self) -> Rclass {
        self.class
    }

    fn rrset(&mut self, name: &Name, rr_type: Rtype) -> Result<Option<Rrset>, UpdateError> {
        Self::read_rrset(self.writer, name, rr_type)
    }

    fn types_at(&mut self, name: &Name) -> Result<Vec<Rtype>, UpdateError> {
        let owner = name_to_rle(name).map_err(servfail)?;
        let records = self.writer.owner_rrsets(&owner).map_err(servfail)?;
        let mut types: Vec<Rtype> = records
            .iter()
            .map(|record| Rtype::from_u16(record.rr_type))
            .collect();
        types.sort();
        types.dedup();
        Ok(types)
    }

    fn put_rrset(&mut self, rrset: &Rrset) -> Result<(), UpdateError> {
        self.record_initial(rrset.owner(), rrset.rr_type())?;
        if rrset.rr_type() == Rtype::NS {
            self.record_cut(rrset.owner())?;
        }
        write_rrset(self.writer, rrset).map_err(servfail)
    }

    fn delete_rrset(&mut self, name: &Name, rr_type: Rtype) -> Result<(), UpdateError> {
        self.record_initial(name, rr_type)?;
        if rr_type == Rtype::NS {
            self.record_cut(name)?;
        }
        let owner = name_to_rle(name).map_err(servfail)?;
        self.writer
            .delete_rrset(&owner, rr_type.as_u16(), 0)
            .map(|_| ())
            .map_err(servfail)
    }
}

/// Адаптер [`ZoneEdit`] поверх незакоммиченного writer'а.
struct WriterEdit<'a, 'z> {
    writer: &'a mut ParallelZone<'z>,
    origin: Name,
}

impl WriterEdit<'_, '_> {
    fn error(&self, error: impl std::fmt::Display) -> pulse_server::dnssec::SignZoneError {
        pulse_server::dnssec::SignZoneError::Edit {
            zone: self.origin.clone(),
            reason: error.to_string(),
        }
    }

    fn owners_of(
        &mut self,
        rr_type: Rtype,
    ) -> Result<Vec<Name>, pulse_server::dnssec::SignZoneError> {
        let mut owners = Vec::new();
        let origin = self.origin.clone();
        self.writer
            .for_each_owner(rr_type.as_u16(), |owner| owners.push(*owner))
            .map_err(|error| pulse_server::dnssec::SignZoneError::Edit {
                zone: origin,
                reason: error.to_string(),
            })?;
        owners
            .into_iter()
            .map(|owner| name_from_rle(&owner).map_err(|error| self.error(error)))
            .collect()
    }
}

impl ZoneEdit for WriterEdit<'_, '_> {
    fn rrset(
        &mut self,
        name: &Name,
        rr_type: Rtype,
    ) -> Result<Option<Rrset>, pulse_server::dnssec::SignZoneError> {
        StoreUpdateTarget::read_rrset(self.writer, name, rr_type).map_err(|error| self.error(error))
    }

    fn node(&mut self, name: &Name) -> Result<SignNode, pulse_server::dnssec::SignZoneError> {
        let owner = name_to_rle(name).map_err(|error| self.error(error))?;
        let node = self
            .writer
            .node(&owner)
            .map_err(|error| self.error(error))?;
        Ok(SignNode {
            exists: node.exists,
            is_zone_cut: node.is_zone_cut,
            has_children: node.has_children,
        })
    }

    fn owner_types(
        &mut self,
        name: &Name,
    ) -> Result<Vec<Rtype>, pulse_server::dnssec::SignZoneError> {
        let owner = name_to_rle(name).map_err(|error| self.error(error))?;
        let records = self
            .writer
            .owner_rrsets(&owner)
            .map_err(|error| self.error(error))?;
        let mut types: Vec<Rtype> = records
            .iter()
            .map(|record| Rtype::from_u16(record.rr_type))
            .collect();
        types.sort();
        types.dedup();
        Ok(types)
    }

    fn rrsig_subtypes(
        &mut self,
        name: &Name,
    ) -> Result<Vec<Rtype>, pulse_server::dnssec::SignZoneError> {
        let owner = name_to_rle(name).map_err(|error| self.error(error))?;
        let records = self
            .writer
            .owner_rrsets(&owner)
            .map_err(|error| self.error(error))?;
        let mut covered: Vec<Rtype> = records
            .iter()
            .filter(|record| record.rr_type == Rtype::RRSIG.as_u16())
            .map(|record| Rtype::from_u16(record.subtype))
            .collect();
        covered.sort();
        covered.dedup();
        Ok(covered)
    }

    fn put_rrset(&mut self, rrset: &Rrset) -> Result<(), pulse_server::dnssec::SignZoneError> {
        write_rrset(self.writer, rrset).map_err(|error| self.error(error))
    }

    fn delete_rrset(
        &mut self,
        name: &Name,
        rr_type: Rtype,
    ) -> Result<(), pulse_server::dnssec::SignZoneError> {
        let owner = name_to_rle(name).map_err(|error| self.error(error))?;
        self.writer
            .delete_rrset(&owner, rr_type.as_u16(), 0)
            .map(|_| ())
            .map_err(|error| self.error(error))
    }

    fn delete_rrsig(
        &mut self,
        name: &Name,
        covered: Rtype,
    ) -> Result<(), pulse_server::dnssec::SignZoneError> {
        let owner = name_to_rle(name).map_err(|error| self.error(error))?;
        self.writer
            .delete_rrset(&owner, Rtype::RRSIG.as_u16(), covered.as_u16())
            .map(|_| ())
            .map_err(|error| self.error(error))
    }

    fn nsec_owners(&mut self) -> Result<Vec<Name>, pulse_server::dnssec::SignZoneError> {
        self.owners_of(Rtype::NSEC)
    }

    fn nsec3_owners(&mut self) -> Result<Vec<Name>, pulse_server::dnssec::SignZoneError> {
        self.owners_of(Rtype::NSEC3)
    }

    fn next_name(
        &mut self,
        after: Option<&Name>,
    ) -> Result<Option<Name>, pulse_server::dnssec::SignZoneError> {
        let after = after
            .map(name_to_rle)
            .transpose()
            .map_err(|error| self.error(error))?;
        let next = self
            .writer
            .next_name(after.as_ref())
            .map_err(|error| self.error(error))?;
        next.map(|name| name_from_rle(&name).map_err(|error| self.error(error)))
            .transpose()
    }
}

fn build_engine(
    views: &HashMap<Name, Arc<FileZoneView>>,
    query_stats: &Arc<QueryStats>,
    response_cache: &Arc<ResponseCache>,
) -> Arc<QueryEngine> {
    let views: Vec<Arc<dyn ZoneView>> = views
        .values()
        .map(|view| Arc::clone(view) as Arc<dyn ZoneView>)
        .collect();
    Arc::new(QueryEngine::with_cache(
        views,
        Arc::clone(query_stats),
        pulse_server::EngineConfig::default(),
        Arc::clone(response_cache),
    ))
}

fn denial_from_kind(kind: DenialKind) -> Denial {
    match kind {
        DenialKind::Nsec => Denial::Nsec,
        DenialKind::Nsec3 => Denial::Nsec3,
    }
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
        let rrsets = store.zone_rrsets(origin)?;
        let signed_zone = dnssec
            .sign(origin, &rrsets, dnssec::now_unix())
            .map_err(|error| format!("cannot sign zone {origin}: {error}"))?;
        let kind = kind_from_flags(entry.flags);
        let default_ttl = Ttl::new(entry.default_ttl).unwrap_or(Ttl::from_wire(3600));
        let denial = denial_from_kind(signed_zone.denial);
        replace_zone_in_file(
            store,
            origin,
            kind,
            default_ttl,
            denial,
            &signed_zone.rrsets,
            &[],
        )?;
        if let Some(entry) = store.zone_entry(origin)? {
            dnssec.set_denial_index(origin, entry.version, &signed_zone.rrsets);
        }
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
    let (rrsets, denial, signed) = if dnssec.is_configured(&loaded.origin) {
        let signed_zone = dnssec
            .sign(&loaded.origin, &loaded.rrsets, dnssec::now_unix())
            .map_err(|error| format!("cannot sign zone {}: {error}", loaded.origin))?;
        let denial = denial_from_kind(signed_zone.denial);
        (signed_zone.rrsets, denial, true)
    } else {
        (loaded.rrsets.clone(), Denial::Nsec, false)
    };
    replace_zone_in_file(
        store,
        &loaded.origin,
        ZoneKind::Primary,
        loaded.default_ttl,
        denial,
        &rrsets,
        &[],
    )?;
    if signed && let Some(entry) = store.zone_entry(&loaded.origin)? {
        dnssec.set_denial_index(&loaded.origin, entry.version, &rrsets);
    }
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

fn check_optional_existing(
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
    if let Some(condition) = &preconditions.if_match
        && !condition_matches(condition, current_etag)
    {
        return Err(AdminError::PreconditionFailed {
            current_etag: Some(current_etag.to_owned()),
            current_version: Some(version),
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

    fn create_zone(
        &self,
        origin: &Name,
        meta: &ZoneMetaInput,
    ) -> Result<pulse_api::ZoneView, AdminError> {
        if origin == &Name::root() || origin.labels().any(|label| label == b"*") {
            return Err(AdminError::invariant(
                "/origin",
                "invalid-origin",
                "zone origin must be a non-root name without wildcards",
            ));
        }
        let store = self.require_store()?;
        let _guard = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        if store
            .zone_entry(origin)
            .map_err(AdminError::Storage)?
            .is_some()
        {
            return Err(AdminError::Conflict(Conflict::ZoneExists));
        }
        store
            .create_zone(origin, meta.kind, meta.default_ttl, meta.denial)
            .map_err(AdminError::Storage)?;
        self.after_commit(origin, None);
        zone_view(store, origin)
    }

    fn get_serial(&self, origin: &Name) -> Result<SerialState, AdminError> {
        let view = zone_view(self.require_store()?, origin)?;
        Ok(SerialState {
            zone: view.origin,
            serial: view.serial,
            version: view.version,
            etag: view.etag,
            updated_at: view.updated_at,
        })
    }

    fn update_serial(
        &self,
        origin: &Name,
        update: SerialUpdate,
        preconditions: &Preconditions,
    ) -> Result<SerialUpdateResult, AdminError> {
        let store = self.require_store()?;
        let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
            return Err(AdminError::zone_not_found());
        };
        if !kind_from_flags(entry.flags).is_writable() {
            return Err(AdminError::Conflict(Conflict::ZoneReadOnly));
        }
        let origin_rle =
            name_to_rle(origin).map_err(|error| AdminError::Storage(error.to_string()))?;
        let mut writer = store.open_writer(origin).map_err(AdminError::Storage)?;
        let base = writer.version().max(1);
        check_optional_existing(preconditions, &zone_etag(entry.zone_seq, base, base), base)?;
        let current = writer
            .lookup(&origin_rle, Rtype::SOA.as_u16(), 0)
            .map_err(|error| AdminError::Storage(error.to_string()))?;
        let current_serial = match &current {
            Some(record) => {
                let view = pulse_zonefile::RrsetView {
                    ttl: record.ttl,
                    flags: record.flags,
                    rdata: record.rdata.clone(),
                };
                let rrset = crate::zonefile::rrset_from_stored(origin, Rtype::SOA, &view)
                    .map_err(|error| AdminError::Storage(error.to_string()))?;
                soa_serial(Some(&rrset)).unwrap_or_else(|| Serial::new(writer.soa_serial()))
            }
            None => Serial::new(writer.soa_serial()),
        };
        let new_serial = next_serial(current_serial, update)?;
        if current.is_some() {
            let view = pulse_zonefile::RrsetView {
                ttl: current.as_ref().map_or(0, |record| record.ttl),
                flags: current.as_ref().map_or(0, |record| record.flags),
                rdata: current
                    .as_ref()
                    .map_or_else(Vec::new, |record| record.rdata.clone()),
            };
            let mut rrset = crate::zonefile::rrset_from_stored(origin, Rtype::SOA, &view)
                .map_err(|error| AdminError::Storage(error.to_string()))?;
            let Some(Rdata::Soa(mut soa)) = rrset.rdatas().first().cloned() else {
                return Err(AdminError::Internal);
            };
            soa.serial = new_serial;
            rrset = Rrset::new(
                origin.clone(),
                Rtype::SOA,
                Rclass::IN,
                rrset.ttl(),
                [Rdata::Soa(soa)],
            )
            .map_err(|error| map_rrset_error(&error))?;
            write_rrset(&mut writer, &rrset).map_err(AdminError::Storage)?;
        }
        writer.set_soa_serial(new_serial.as_u32());
        let previous = self.previous_snapshot(origin, store);
        store
            .commit_writer(&mut writer)
            .map_err(AdminError::Storage)?;
        self.after_commit(origin, previous.as_ref());
        drop(writer);
        let view = zone_view(store, origin)?;
        Ok(SerialUpdateResult {
            zone: origin.clone(),
            old_serial: current_serial,
            new_serial,
            version: view.version,
            etag: view.etag,
            updated_at: view.updated_at,
        })
    }

    fn trigger_transfer(
        &self,
        origin: &Name,
        request: &TransferRequest,
    ) -> Result<TransferResult, AdminError> {
        self.run_transfer(origin, request)
    }

    fn import_zone(
        &self,
        origin: &Name,
        text: &str,
        mode: ImportMode,
    ) -> Result<ImportReport, AdminError> {
        let store = self.require_store()?;
        let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
            return Err(AdminError::zone_not_found());
        };
        let kind = kind_from_flags(entry.flags);
        if kind != ZoneKind::Primary {
            return Err(AdminError::Conflict(Conflict::ZoneReadOnly));
        }
        let loaded = crate::master::load_zone_text(&origin.to_string(), text, "api-import")
            .map_err(|error| AdminError::invariant("/body", "invalid-zonefile", error))?;
        let mut rrsets = if mode == ImportMode::Merge {
            store.zone_rrsets(origin).map_err(AdminError::Storage)?
        } else {
            Vec::new()
        };
        for rrset in loaded.rrsets {
            let same = |existing: &Rrset| {
                existing.owner() == rrset.owner() && existing.rr_type() == rrset.rr_type()
            };
            rrsets.retain(|existing| !same(existing));
            rrsets.push(rrset);
        }
        let (rrsets, denial) = if self.dnssec.is_configured(origin) {
            let signed_zone = self
                .dnssec
                .sign(origin, &rrsets, dnssec::now_unix())
                .map_err(|error| {
                    logging::error(
                        "zone_import",
                        &format!("zone {origin}: cannot sign after import: {error}"),
                    );
                    AdminError::Internal
                })?;
            (signed_zone.rrsets, denial_from_kind(signed_zone.denial))
        } else {
            (rrsets, Denial::Nsec)
        };
        let serial = rrsets
            .iter()
            .find(|rrset| rrset.rr_type() == Rtype::SOA)
            .and_then(|rrset| soa_serial(Some(rrset)));
        let count = u32::try_from(rrsets.len()).unwrap_or(u32::MAX);
        let warnings = loaded.warnings.clone();
        if mode == ImportMode::Check {
            return Ok(ImportReport {
                zone: origin.clone(),
                mode,
                rrsets: count,
                serial,
                warnings,
                applied: false,
            });
        }
        let default_ttl = loaded.default_ttl;
        replace_zone_in_file(store, origin, kind, default_ttl, denial, &rrsets, &[])
            .map_err(AdminError::Storage)?;
        if self.dnssec.is_configured(origin)
            && let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)?
        {
            self.dnssec.set_denial_index(origin, entry.version, &rrsets);
        }
        self.after_commit(origin, None);
        Ok(ImportReport {
            zone: origin.clone(),
            mode,
            rrsets: count,
            serial,
            warnings,
            applied: true,
        })
    }

    fn rollover_keys(
        &self,
        origin: &Name,
        request: &RolloverRequest,
    ) -> Result<KeyRotationView, AdminError> {
        let _ = self.require_store()?;
        let role = pulse_server::dnssec::KeyRole::parse(&request.role).ok_or_else(|| {
            AdminError::invariant("/role", "invalid-role", "role must be ksk or zsk")
        })?;
        if !matches!(
            role,
            pulse_server::dnssec::KeyRole::Ksk | pulse_server::dnssec::KeyRole::Zsk
        ) {
            return Err(AdminError::invariant(
                "/role",
                "invalid-role",
                "role must be ksk or zsk",
            ));
        }
        let status = self
            .dnssec
            .rollover(origin, role, request.overlap, request.retire_after)
            .map_err(|error| {
                logging::error(
                    "dnssec_rotation",
                    &format!("zone {origin}: rollover failed: {error}"),
                );
                match error.as_ref() {
                    crate::dnssec::DnssecError::InvalidRotation { .. } => AdminError::invariant(
                        "/zone",
                        "rotation-not-configured",
                        "key rotation is not configured for this zone",
                    ),
                    crate::dnssec::DnssecError::Rotation { source, .. }
                        if matches!(
                            source.as_ref(),
                            crate::rotation::RotationError::RolloverInProgress { .. }
                        ) =>
                    {
                        AdminError::Conflict(Conflict::ZoneBusy)
                    }
                    _ => AdminError::Internal,
                }
            })?;
        Ok(KeyRotationView {
            next_event_at: status.next_event_at,
            keys: status
                .keys
                .into_iter()
                .map(|key| KeyRotationKeyView {
                    key_tag: key.key_tag,
                    role: key.role,
                    state: key.stage.as_str().to_owned(),
                    created_at: key.created_at,
                    next_transition: key.next_transition,
                })
                .collect(),
        })
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
        if !self.dnssec.is_configured(origin) {
            return Err(AdminError::invariant(
                "/zone",
                "dnssec-not-configured",
                "zone has no DNSSEC keys configured",
            ));
        }
        let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? else {
            return Err(AdminError::zone_not_found());
        };
        let _guard = self.catalog.lock().unwrap_or_else(PoisonError::into_inner);
        let rrsets = store.zone_rrsets(origin).map_err(AdminError::Storage)?;
        let previous = self.previous_snapshot(origin, store);
        let signed_zone = self
            .dnssec
            .sign(origin, &rrsets, dnssec::now_unix())
            .map_err(|error| {
                logging::error(
                    "dnssec_sign",
                    &format!("zone {origin}: cannot sign: {error}"),
                );
                AdminError::Internal
            })?;
        let kind = kind_from_flags(entry.flags);
        let default_ttl = Ttl::new(entry.default_ttl).unwrap_or(Ttl::from_wire(3600));
        let denial = denial_from_kind(signed_zone.denial);
        replace_zone_in_file(
            store,
            origin,
            kind,
            default_ttl,
            denial,
            &signed_zone.rrsets,
            &[],
        )
        .map_err(AdminError::Storage)?;
        if let Some(entry) = store.zone_entry(origin).map_err(AdminError::Storage)? {
            self.dnssec
                .set_denial_index(origin, entry.version, &signed_zone.rrsets);
        }
        self.after_commit(origin, previous.as_ref());
        zone_view(store, origin)
    }

    fn key_rotation(&self, origin: &Name) -> Result<Option<KeyRotationView>, AdminError> {
        Ok(self
            .dnssec
            .rotation_status(origin)
            .map(|status| KeyRotationView {
                next_event_at: status.next_event_at,
                keys: status
                    .keys
                    .into_iter()
                    .map(|key| KeyRotationKeyView {
                        key_tag: key.key_tag,
                        role: key.role,
                        state: key.stage.as_str().to_owned(),
                        created_at: key.created_at,
                        next_transition: key.next_transition,
                    })
                    .collect(),
            }))
    }

    fn list_tsig_keys(&self) -> Result<Vec<pulse_api::TsigKeyView>, AdminError> {
        Ok(self
            .tsig_keys
            .list()
            .into_iter()
            .map(|view| pulse_api::TsigKeyView {
                name: view.name,
                algorithm: view.algorithm,
                created_at: view.created_at,
                last_used: view.last_used,
                configured: view.configured,
            })
            .collect())
    }

    fn create_tsig_key(
        &self,
        input: &pulse_api::TsigKeyInput,
    ) -> Result<pulse_api::TsigKeyView, AdminError> {
        self.tsig_keys
            .create(&input.name.to_string(), &input.algorithm, &input.secret)
            .map(|view| pulse_api::TsigKeyView {
                name: view.name,
                algorithm: view.algorithm,
                created_at: view.created_at,
                last_used: view.last_used,
                configured: view.configured,
            })
            .map_err(tsig_store_error)
    }

    fn delete_tsig_key(&self, name: &Name) -> Result<(), AdminError> {
        self.tsig_keys.delete(name).map_err(tsig_store_error)
    }

    fn reload_tsig_keys(&self) -> Result<usize, AdminError> {
        self.tsig_keys
            .reload()
            .map_err(|error| AdminError::Storage(error.to_string()))
    }
}

fn tsig_store_error(error: crate::tsigkeys::TsigKeyStoreError) -> AdminError {
    use crate::tsigkeys::TsigKeyStoreError;
    match error {
        TsigKeyStoreError::Exists { .. } => AdminError::Conflict(Conflict::TsigKeyExists),
        TsigKeyStoreError::NotFound { .. } => AdminError::NotFound(pulse_api::NotFound::TsigKey),
        TsigKeyStoreError::Immutable { .. } => AdminError::Conflict(Conflict::TsigKeyImmutable),
        TsigKeyStoreError::Invalid { reason } => {
            AdminError::invariant("/", "invalid-tsig-key", reason)
        }
        TsigKeyStoreError::State { reason, .. } => AdminError::Storage(reason),
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
