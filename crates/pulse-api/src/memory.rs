//! In-memory реализация [`ZoneAdmin`] для тестов и `pulsed`.
//!
//! Модель конкурентности: каталог зон защищён `RwLock`, каждая зона — своим
//! `Mutex` (аренда). Мутации одной зоны сериализуются, разные зоны пишутся
//! параллельно. Проверка `If-Match` выполняется внутри аренды, поэтому
//! конкурентные записи с одним ETag дают ровно одну победу.
//!
//! Порядок взятия блокировок всегда «каталог → зона»; обратный порядок
//! запрещён (иначе возможен deadlock с удалением зоны).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard};

use pulse_dns::{Name, Rclass, Rdata, Rrset, RrsetError, Rtype, Serial, Ttl};

use crate::base64url;
use crate::error::{AdminError, InvariantViolation};
use crate::etag::{normalize_tag, rrset_etag, zone_etag};
use crate::port::{
    Denial, ImportMode, ImportReport, KeyRotationKeyView, KeyRotationView, ListRrsets, ListZones,
    Precondition, Preconditions, RolloverRequest, RrsetInput, RrsetPage, RrsetPatch,
    RrsetPatchOutcome, RrsetView, SerialState, SerialUpdate, SerialUpdateResult, TransferRequest,
    TransferResult, WriteOutcome, ZoneAdmin, ZoneAllow, ZoneId, ZoneKind, ZoneMetaInput, ZonePage,
    ZoneSettings, ZoneSettingsPatch, ZoneSettingsView, ZoneView, next_serial,
};
use crate::rdata_text::is_managed_type;

type RrsetKey = (String, u16);

#[derive(Clone)]
struct RrsetRecord {
    rrset: Rrset,
    etag: String,
    updated_at: std::time::SystemTime,
}

struct ZoneData {
    id: ZoneId,
    origin: Name,
    kind: ZoneKind,
    serial: Serial,
    version: u64,
    txn: u64,
    default_ttl: Ttl,
    denial: Denial,
    rrsets: BTreeMap<RrsetKey, RrsetRecord>,
    /// Существующие имена, включая узлы без RRset после удаления.
    nodes: HashSet<Name>,
    created_at: std::time::SystemTime,
    updated_at: std::time::SystemTime,
}

impl ZoneData {
    fn etag(&self) -> String {
        zone_etag(self.id.as_u32(), self.version, self.txn)
    }

    fn view(&self) -> ZoneView {
        ZoneView {
            id: self.id,
            origin: self.origin.clone(),
            kind: self.kind,
            serial: self.serial,
            version: self.version,
            txn: self.txn,
            default_ttl: self.default_ttl,
            denial: self.denial,
            rrset_count: u32::try_from(self.rrsets.len()).unwrap_or(u32::MAX),
            etag: self.etag(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    fn settings_view(&self) -> ZoneSettingsView {
        ZoneSettingsView {
            zone: self.origin.clone(),
            settings: ZoneSettings {
                default_ttl: self.default_ttl,
                denial: self.denial,
            },
            version: self.version,
            etag: self.etag(),
            updated_at: self.updated_at,
        }
    }

    fn snapshot(&self) -> ZoneSnapshot {
        let mut nodes: Vec<Name> = self.nodes.iter().cloned().collect();
        nodes.sort_by(|left, right| left.cmp_canonical(right));
        ZoneSnapshot {
            origin: self.origin.clone(),
            kind: self.kind,
            serial: self.serial,
            version: self.version,
            txn: self.txn,
            default_ttl: self.default_ttl,
            denial: self.denial,
            rrsets: self
                .rrsets
                .values()
                .map(|record| record.rrset.clone())
                .collect(),
            nodes,
        }
    }
}

/// Снимок одной зоны для DNS-адаптера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSnapshot {
    /// Origin зоны.
    pub origin: Name,
    /// Тип зоны.
    pub kind: ZoneKind,
    /// Serial метаданных зоны.
    pub serial: Serial,
    /// Версия зоны.
    pub version: u64,
    /// Номер последнего коммита.
    pub txn: u64,
    /// TTL по умолчанию.
    pub default_ttl: Ttl,
    /// Политика denial-of-existence.
    pub denial: Denial,
    /// Все RRset зоны в детерминированном порядке.
    pub rrsets: Vec<Rrset>,
    /// Существующие имена, включая empty nodes.
    pub nodes: Vec<Name>,
}

/// Атомарный снимок каталога зон.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSnapshot {
    /// Номер последнего коммита store.
    pub revision: u64,
    /// Зоны в каноническом порядке origin.
    pub zones: Vec<ZoneSnapshot>,
}

/// In-memory store зон.
pub struct InMemoryZoneAdmin {
    catalog: RwLock<BTreeMap<String, Arc<Mutex<ZoneData>>>>,
    next_id: AtomicU32,
    next_txn: AtomicU64,
    ready: AtomicBool,
    /// Синтетическое состояние ротации ключей для тестов/`pulsed` без DNSSEC.
    rotation: Mutex<HashMap<String, KeyRotationView>>,
}

impl InMemoryZoneAdmin {
    /// Создаёт пустой store.
    pub fn new() -> Self {
        Self {
            catalog: RwLock::new(BTreeMap::new()),
            next_id: AtomicU32::new(1),
            next_txn: AtomicU64::new(1),
            ready: AtomicBool::new(true),
            rotation: Mutex::new(HashMap::new()),
        }
    }

    /// Помечает store как готовый/неготовый (для `/readyz`).
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    /// Возвращает согласованный по зонам снимок каталога.
    ///
    /// Блокировка каталога удерживается на чтение, каждой зоны — на время
    /// клонирования её RRset. DNS-адаптер строит `ZoneView` по этому снимку,
    /// поэтому запросы не держат блокировки store.
    pub fn snapshot(&self) -> StoreSnapshot {
        // Ревизия читается до копирования зон: если мутация попадёт в снимок
        // или произойдёт во время копирования, её собственный `refresh()`
        // увидит revision больше сохранённой и перестроит движок ещё раз.
        let revision = self.revision();
        let catalog = self.catalog.read().unwrap_or_else(PoisonError::into_inner);
        let mut zones: Vec<ZoneSnapshot> = Vec::with_capacity(catalog.len());
        for zone in catalog.values() {
            let data = lock_zone(zone);
            zones.push(data.snapshot());
        }
        zones.sort_by(|left, right| left.origin.cmp_canonical(&right.origin));
        StoreSnapshot { revision, zones }
    }

    /// Номер последнего коммита store.
    pub fn revision(&self) -> u64 {
        self.next_txn.load(Ordering::Acquire).saturating_sub(1)
    }

    /// Атомарно импортирует готовую зону (bootstrap из JSON-конфига).
    ///
    /// В отличие от HTTP RRset API, импорт допускает DNSSEC-записи
    /// (`RRSIG`/`NSEC`/`NSEC3`): они приходят из проверенного конфигурационного
    /// файла и не редактируются через control plane. Store-инварианты
    /// (owner в зоне, единственный apex SOA, CNAME-эксклюзивность) проверяются.
    ///
    /// # Errors
    ///
    /// [`AdminError::Conflict`], если зона уже существует,
    /// [`AdminError::InvariantViolation`] при нарушении инвариантов.
    pub fn import_zone(
        &self,
        origin: &Name,
        meta: &ZoneMetaInput,
        rrsets: Vec<Rrset>,
    ) -> Result<ZoneView, AdminError> {
        if origin == &Name::root() || origin.labels().any(|label| label == b"*") {
            return Err(AdminError::invariant(
                "/origin",
                "invalid-origin",
                "zone origin must be a non-root name without wildcards",
            ));
        }
        let now = std::time::SystemTime::now();
        let (records, nodes, serial) = build_zone_records(origin, rrsets, now)?;

        let mut catalog = self.catalog.write().unwrap_or_else(PoisonError::into_inner);
        if catalog.contains_key(&Self::zone_key(origin)) {
            return Err(AdminError::Conflict(crate::error::Conflict::ZoneExists));
        }
        let id = ZoneId::new(self.next_id.fetch_add(1, Ordering::SeqCst));
        let txn = self.next_txn();
        let data = ZoneData {
            id,
            origin: origin.clone(),
            kind: meta.kind,
            serial,
            version: 1,
            txn,
            default_ttl: meta.default_ttl,
            denial: meta.denial,
            rrsets: records,
            nodes,
            created_at: now,
            updated_at: now,
        };
        let view = data.view();
        catalog.insert(Self::zone_key(origin), Arc::new(Mutex::new(data)));
        Ok(view)
    }

    /// Импорт зоны с явными empty nodes/ENT из persistence-файла.
    ///
    /// # Errors
    ///
    /// См. [`InMemoryZoneAdmin::import_zone`]; дополнительно каждый узел
    /// обязан находиться внутри origin.
    pub fn import_zone_with_nodes(
        &self,
        origin: &Name,
        meta: &ZoneMetaInput,
        rrsets: Vec<Rrset>,
        extra_nodes: Vec<Name>,
    ) -> Result<ZoneView, AdminError> {
        if origin == &Name::root() || origin.labels().any(|label| label == b"*") {
            return Err(AdminError::invariant(
                "/origin",
                "invalid-origin",
                "zone origin must be a non-root name without wildcards",
            ));
        }
        let now = std::time::SystemTime::now();
        let (records, mut nodes, serial) = build_zone_records(origin, rrsets, now)?;
        for node in extra_nodes {
            if !node.is_subdomain_of(origin) {
                return Err(AdminError::invariant(
                    "/nodes",
                    "node-out-of-zone",
                    "empty node must be inside the zone",
                ));
            }
            nodes.insert(node);
        }
        let mut catalog = self.catalog.write().unwrap_or_else(PoisonError::into_inner);
        if catalog.contains_key(&Self::zone_key(origin)) {
            return Err(AdminError::Conflict(crate::error::Conflict::ZoneExists));
        }
        let id = ZoneId::new(self.next_id.fetch_add(1, Ordering::SeqCst));
        let txn = self.next_txn();
        let data = ZoneData {
            id,
            origin: origin.clone(),
            kind: meta.kind,
            serial,
            version: 1,
            txn,
            default_ttl: meta.default_ttl,
            denial: meta.denial,
            rrsets: records,
            nodes,
            created_at: now,
            updated_at: now,
        };
        let view = data.view();
        catalog.insert(Self::zone_key(origin), Arc::new(Mutex::new(data)));
        Ok(view)
    }

    /// Атомарно заменяет все RRset зоны (например, после DNSSEC-подписи).
    ///
    /// Метаданные зоны (`kind`, `default_ttl`, `denial`) сохраняются; serial
    /// берётся из нового apex `SOA`. Версия и `txn` продвигаются, поэтому
    /// DNS-адаптер перестраивает снапшот.
    ///
    /// # Errors
    ///
    /// [`AdminError::NotFound`], если зоны нет, [`AdminError::Conflict`] для
    /// read-only зоны, [`AdminError::InvariantViolation`] при нарушении
    /// инвариантов набора.
    pub fn replace_zone_rrsets(
        &self,
        origin: &Name,
        rrsets: Vec<Rrset>,
    ) -> Result<ZoneView, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let mut data = lock_zone(&zone);
        if !data.kind.is_writable() {
            return Err(AdminError::Conflict(crate::error::Conflict::ZoneReadOnly));
        }
        let now = std::time::SystemTime::now();
        let (records, nodes, serial) = build_zone_records(origin, rrsets, now)?;
        data.rrsets = records;
        data.nodes = nodes;
        data.serial = serial;
        data.version = data.version.saturating_add(1);
        data.txn = self.next_txn();
        data.updated_at = now;
        Ok(data.view())
    }

    /// Заменяет RRset вторичной зоны данными, полученными трансфером.
    ///
    /// В отличие от [`InMemoryZoneAdmin::replace_zone_rrsets`], операция
    /// разрешена для `ZoneKind::Secondary`: данные secondary управляются
    /// только AXFR/IXFR, а не HTTP API.
    ///
    /// # Errors
    ///
    /// [`AdminError::NotFound`], если зоны нет, [`AdminError::Conflict`] для
    /// не-secondary зоны, [`AdminError::InvariantViolation`] при нарушении
    /// инвариантов набора.
    pub fn replace_secondary_zone_rrsets(
        &self,
        origin: &Name,
        rrsets: Vec<Rrset>,
    ) -> Result<ZoneView, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let mut data = lock_zone(&zone);
        if data.kind != ZoneKind::Secondary {
            return Err(AdminError::Conflict(crate::error::Conflict::ZoneReadOnly));
        }
        let now = std::time::SystemTime::now();
        let (records, nodes, serial) = build_zone_records(origin, rrsets, now)?;
        data.rrsets = records;
        data.nodes = nodes;
        data.serial = serial;
        data.version = data.version.saturating_add(1);
        data.txn = self.next_txn();
        data.updated_at = now;
        Ok(data.view())
    }

    /// Инкрементирует apex `SOA` serial первичной зоны.
    ///
    /// Нужен `pulsed`, чтобы изменение данных primary через REST/RRset API
    /// автоматически давало новый serial для IXFR/NOTIFY. Для secondary и
    /// зон без apex `SOA` возвращает `None`.
    ///
    /// # Errors
    ///
    /// [`AdminError::Internal`] при нарушении инвариантов RRset.
    pub fn bump_soa_serial(&self, origin: &Name) -> Result<Option<Serial>, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let mut data = lock_zone(&zone);
        if !data.kind.is_writable() {
            return Ok(None);
        }
        let key = Self::rrset_key(origin, Rtype::SOA);
        let Some(record) = data.rrsets.get(&key) else {
            return Ok(None);
        };
        let Some(Rdata::Soa(soa)) = record.rrset.rdatas().first() else {
            return Ok(None);
        };
        let serial = soa.serial.succ();
        let mut next_soa = soa.clone();
        next_soa.serial = serial;
        let rrset = Rrset::new(
            origin.clone(),
            Rtype::SOA,
            Rclass::IN,
            record.rrset.ttl(),
            [Rdata::Soa(next_soa)],
        )
        .map_err(map_rrset_error)?;
        let etag = rrset_etag(&rrset);
        let now = std::time::SystemTime::now();
        data.rrsets.insert(
            key,
            RrsetRecord {
                rrset,
                etag,
                updated_at: now,
            },
        );
        data.serial = serial;
        data.version = data.version.saturating_add(1);
        data.txn = self.next_txn();
        data.updated_at = now;
        Ok(Some(serial))
    }

    fn next_txn(&self) -> u64 {
        self.next_txn.fetch_add(1, Ordering::SeqCst)
    }
    fn zone_key(origin: &Name) -> String {
        origin.to_string()
    }

    fn rrset_key(owner: &Name, rr_type: Rtype) -> RrsetKey {
        (owner.to_string(), rr_type.as_u16())
    }

    fn zone_handle<'a>(
        &'a self,
        origin: &Name,
    ) -> Result<
        (
            RwLockReadGuard<'a, BTreeMap<String, Arc<Mutex<ZoneData>>>>,
            Arc<Mutex<ZoneData>>,
        ),
        AdminError,
    > {
        let catalog = self.catalog.read().unwrap_or_else(PoisonError::into_inner);
        let key = Self::zone_key(origin);
        let zone = catalog
            .get(&key)
            .cloned()
            .ok_or_else(AdminError::zone_not_found)?;
        Ok((catalog, zone))
    }

    fn replace_zone(
        &self,
        zone: &mut ZoneData,
        meta: &ZoneMetaInput,
        preconditions: &Preconditions,
    ) -> Result<ZoneView, AdminError> {
        check_existing(preconditions, &zone.etag(), zone.version)?;
        if meta.kind != zone.kind && !zone.rrsets.is_empty() {
            return Err(AdminError::invariant(
                "/kind",
                "zone-not-empty",
                "zone must be empty before changing kind",
            ));
        }
        zone.kind = meta.kind;
        zone.default_ttl = meta.default_ttl;
        zone.denial = meta.denial;
        zone.version = zone.version.saturating_add(1);
        zone.txn = self.next_txn();
        zone.updated_at = std::time::SystemTime::now();
        Ok(zone.view())
    }

    fn check_writable(&self, zone: &ZoneData) -> Result<(), AdminError> {
        if zone.kind.is_writable() {
            Ok(())
        } else {
            Err(AdminError::Conflict(crate::error::Conflict::ZoneReadOnly))
        }
    }

    fn validate_type(
        &self,
        zone: &ZoneData,
        owner: &Name,
        rr_type: Rtype,
    ) -> Result<(), AdminError> {
        if !owner.is_subdomain_of(&zone.origin) {
            return Err(AdminError::invariant(
                "/owner",
                "owner-out-of-zone",
                "record owner must be inside the zone",
            ));
        }
        if rr_type == Rtype::SOA {
            if owner != &zone.origin {
                return Err(AdminError::invariant(
                    "/type",
                    "soa-apex-only",
                    "SOA is allowed only at the zone apex",
                ));
            }
            return Ok(());
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

    fn check_owner_conflicts(
        &self,
        zone: &ZoneData,
        owner: &Name,
        rr_type: Rtype,
    ) -> Result<(), AdminError> {
        let owner_text = owner.to_string();
        let has_cname = zone
            .rrsets
            .iter()
            .any(|((name, kind), _)| name == &owner_text && *kind == Rtype::CNAME.as_u16());
        let has_other = zone.rrsets.iter().any(|((name, kind), _)| {
            name == &owner_text && *kind != rr_type.as_u16() && *kind != Rtype::CNAME.as_u16()
        });
        if rr_type == Rtype::CNAME {
            if owner == &zone.origin {
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
            if owner == &zone.origin {
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
}

impl Default for InMemoryZoneAdmin {
    fn default() -> Self {
        Self::new()
    }
}

fn build_zone_records(
    origin: &Name,
    rrsets: Vec<Rrset>,
    now: std::time::SystemTime,
) -> Result<(BTreeMap<RrsetKey, RrsetRecord>, HashSet<Name>, Serial), AdminError> {
    let mut records: BTreeMap<RrsetKey, RrsetRecord> = BTreeMap::new();
    let mut by_owner: HashMap<Name, Vec<Rtype>> = HashMap::new();
    let mut nodes = HashSet::from([origin.clone()]);
    let mut serial = Serial::new(1);
    for rrset in rrsets {
        let owner = rrset.owner();
        if !owner.is_subdomain_of(origin) {
            return Err(AdminError::invariant(
                "/owner",
                "owner-out-of-zone",
                "record owner must be inside the zone",
            ));
        }
        if rrset.rr_type() == Rtype::SOA {
            if owner != origin {
                return Err(AdminError::invariant(
                    "/type",
                    "soa-apex-only",
                    "SOA is allowed only at the zone apex",
                ));
            }
            if rrset.len() != 1 {
                return Err(AdminError::invariant(
                    "/records",
                    "soa-single",
                    "apex SOA must contain exactly one record",
                ));
            }
            if let Some(Rdata::Soa(data)) = rrset.rdatas().iter().next() {
                serial = data.serial;
            }
        }
        if rrset.rr_type() == Rtype::CNAME && rrset.len() != 1 {
            return Err(AdminError::invariant(
                "/records",
                "cname-single",
                "CNAME must contain exactly one target",
            ));
        }
        let key = InMemoryZoneAdmin::rrset_key(owner, rrset.rr_type());
        if records.contains_key(&key) {
            return Err(AdminError::invariant(
                "/records",
                "duplicate-rrset",
                "zone import contains duplicate owner/type",
            ));
        }
        by_owner
            .entry(owner.clone())
            .or_default()
            .push(rrset.rr_type());
        register_nodes_into(&mut nodes, origin, owner);
        let etag = rrset_etag(&rrset);
        records.insert(
            key,
            RrsetRecord {
                rrset,
                etag,
                updated_at: now,
            },
        );
    }
    for (owner, types) in &by_owner {
        if !types.contains(&Rtype::CNAME) {
            continue;
        }
        if owner == origin
            || types
                .iter()
                .any(|rr_type| *rr_type != Rtype::CNAME && !is_dnssec_adjacent(*rr_type))
        {
            return Err(AdminError::invariant(
                "/owner",
                "cname-conflict",
                "CNAME cannot coexist with other data at the same owner",
            ));
        }
    }
    Ok((records, nodes, serial))
}

fn lock_zone(zone: &Mutex<ZoneData>) -> MutexGuard<'_, ZoneData> {
    zone.lock().unwrap_or_else(PoisonError::into_inner)
}

fn register_nodes(zone: &mut ZoneData, owner: &Name) {
    register_nodes_into(&mut zone.nodes, &zone.origin, owner);
}

fn register_nodes_into(nodes: &mut HashSet<Name>, origin: &Name, owner: &Name) {
    let mut current = Some(owner.clone());
    while let Some(name) = current {
        let is_origin = &name == origin;
        nodes.insert(name.clone());
        if is_origin {
            break;
        }
        current = name.parent();
    }
}

fn is_dnssec_adjacent(rr_type: Rtype) -> bool {
    matches!(rr_type, Rtype::RRSIG | Rtype::NSEC | Rtype::NSEC3)
}

fn tags_equal(left: &str, right: &str) -> bool {
    match (normalize_tag(left), normalize_tag(right)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn condition_matches(condition: &Precondition, current_etag: &str) -> bool {
    match condition {
        Precondition::Any => true,
        Precondition::Tag(tag) => tags_equal(tag, current_etag),
        Precondition::Tags(tags) => tags.iter().any(|tag| tags_equal(tag, current_etag)),
    }
}

fn precondition_failed(etag: &str, version: u64) -> AdminError {
    AdminError::PreconditionFailed {
        current_etag: Some(etag.to_owned()),
        current_version: Some(version),
    }
}

fn check_existing(
    preconditions: &Preconditions,
    current_etag: &str,
    current_version: u64,
) -> Result<(), AdminError> {
    if let Some(condition) = &preconditions.if_none_match {
        if condition_matches(condition, current_etag) {
            return Err(precondition_failed(current_etag, current_version));
        }
    }
    match &preconditions.if_match {
        Some(condition) => {
            if condition_matches(condition, current_etag) {
                Ok(())
            } else {
                Err(precondition_failed(current_etag, current_version))
            }
        }
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

fn map_rrset_error(error: RrsetError) -> AdminError {
    match error {
        RrsetError::Empty => {
            AdminError::invariant("/records", "empty-rrset", "rrset must not be empty")
        }
        RrsetError::TtlMismatch { .. } => AdminError::invariant(
            "/ttl",
            "ttl-mismatch",
            "all records in an rrset must share one ttl",
        ),
        RrsetError::OwnerMismatch { .. } | RrsetError::Owner(_) => {
            AdminError::invariant("/owner", "owner-invalid", "invalid record owner")
        }
        RrsetError::TypeMismatch { .. } | RrsetError::RdataTypeMismatch { .. } => {
            AdminError::invariant(
                "/records",
                "rdata-type-mismatch",
                "record data does not match the rrset type",
            )
        }
        RrsetError::ClassMismatch { .. } | RrsetError::UnsupportedClass { .. } => {
            AdminError::invariant("/class", "unsupported-class", "only class IN is supported")
        }
        RrsetError::TooManyRecords { .. } => AdminError::invariant(
            "/records",
            "too-many-records",
            "rrset exceeds the record limit",
        ),
        RrsetError::Rdata(_) | RrsetError::RdataTooLong { .. } => {
            AdminError::invariant("/records", "invalid-rdata", "invalid record data")
        }
    }
}

fn rrset_view(zone: &ZoneData, record: &RrsetRecord) -> RrsetView {
    RrsetView {
        zone: zone.origin.clone(),
        owner: record.rrset.owner().clone(),
        rr_type: record.rrset.rr_type(),
        ttl: record.rrset.ttl(),
        rdata: record.rrset.rdatas().iter().cloned().collect(),
        etag: record.etag.clone(),
        updated_at: record.updated_at,
    }
}

impl ZoneAdmin for InMemoryZoneAdmin {
    fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    fn list_zones(&self, query: &ListZones, allow: &dyn ZoneAllow) -> Result<ZonePage, AdminError> {
        let limit = if query.limit == 0 {
            50
        } else {
            query.limit.min(500)
        };
        let cursor = match query.cursor.as_deref() {
            Some(cursor) => Some(decode_zone_cursor(cursor)?),
            None => None,
        };
        let catalog = self.catalog.read().unwrap_or_else(PoisonError::into_inner);
        let mut zones: Vec<(ZoneId, Arc<Mutex<ZoneData>>)> = catalog
            .values()
            .map(|zone| {
                let data = lock_zone(zone);
                (data.id, Arc::clone(zone))
            })
            .collect();
        zones.sort_by_key(|(id, _)| *id);
        let mut items = Vec::new();
        let mut has_more = false;
        for (id, zone) in zones {
            if cursor.is_some_and(|cursor| id.as_u32() <= cursor) {
                continue;
            }
            let data = lock_zone(&zone);
            if !allow.allows(&data.origin) {
                continue;
            }
            if query.kind.is_some_and(|kind| kind != data.kind) {
                continue;
            }
            if items.len() >= limit as usize {
                has_more = true;
                break;
            }
            items.push(data.view());
        }
        let next_cursor = if has_more {
            items.last().map(|zone| encode_zone_cursor(zone.id))
        } else {
            None
        };
        Ok(ZonePage {
            items,
            next_cursor,
            has_more,
        })
    }

    fn get_zone(&self, origin: &Name) -> Result<ZoneView, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let data = lock_zone(&zone);
        Ok(data.view())
    }

    fn create_zone(&self, origin: &Name, meta: &ZoneMetaInput) -> Result<ZoneView, AdminError> {
        if origin == &Name::root() || origin.labels().any(|label| label == b"*") {
            return Err(AdminError::invariant(
                "/origin",
                "invalid-origin",
                "zone origin must be a non-root name without wildcards",
            ));
        }
        let key = Self::zone_key(origin);
        let mut catalog = self.catalog.write().unwrap_or_else(PoisonError::into_inner);
        if catalog.contains_key(&key) {
            return Err(AdminError::Conflict(crate::error::Conflict::ZoneExists));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let txn = self.next_txn();
        let now = std::time::SystemTime::now();
        let data = ZoneData {
            id: ZoneId::new(id),
            origin: origin.clone(),
            kind: meta.kind,
            serial: Serial::new(1),
            version: 1,
            txn,
            default_ttl: meta.default_ttl,
            denial: meta.denial,
            rrsets: BTreeMap::new(),
            nodes: HashSet::from([origin.clone()]),
            created_at: now,
            updated_at: now,
        };
        let view = data.view();
        catalog.insert(key, Arc::new(Mutex::new(data)));
        Ok(view)
    }

    fn get_serial(&self, origin: &Name) -> Result<SerialState, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let data = lock_zone(&zone);
        Ok(SerialState {
            zone: origin.clone(),
            serial: zone_serial(&data),
            version: data.version,
            etag: data.etag(),
            updated_at: data.updated_at,
        })
    }

    fn update_serial(
        &self,
        origin: &Name,
        update: SerialUpdate,
        preconditions: &Preconditions,
    ) -> Result<SerialUpdateResult, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let mut data = lock_zone(&zone);
        self.check_writable(&data)?;
        check_optional_existing(preconditions, &data.etag(), data.version)?;
        let old_serial = zone_serial(&data);
        let new_serial = next_serial(old_serial, update)?;
        if let Some(record) = data
            .rrsets
            .get(&Self::rrset_key(origin, Rtype::SOA))
            .cloned()
            && let Some(Rdata::Soa(soa)) = record.rrset.rdatas().first()
        {
            let mut next_soa = soa.clone();
            next_soa.serial = new_serial;
            let rrset = Rrset::new(
                origin.clone(),
                Rtype::SOA,
                Rclass::IN,
                record.rrset.ttl(),
                [Rdata::Soa(next_soa)],
            )
            .map_err(map_rrset_error)?;
            let etag = rrset_etag(&rrset);
            data.rrsets.insert(
                Self::rrset_key(origin, Rtype::SOA),
                RrsetRecord {
                    rrset,
                    etag,
                    updated_at: std::time::SystemTime::now(),
                },
            );
        }
        data.serial = new_serial;
        data.version = data.version.saturating_add(1);
        data.txn = self.next_txn();
        data.updated_at = std::time::SystemTime::now();
        Ok(SerialUpdateResult {
            zone: origin.clone(),
            old_serial,
            new_serial,
            version: data.version,
            etag: data.etag(),
            updated_at: data.updated_at,
        })
    }

    fn trigger_transfer(
        &self,
        origin: &Name,
        request: &TransferRequest,
    ) -> Result<TransferResult, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let data = lock_zone(&zone);
        match data.kind {
            ZoneKind::Primary => Ok(TransferResult {
                zone: origin.clone(),
                kind: request.kind,
                mode_used: request.kind,
                serial: Some(zone_serial(&data)),
                rrsets: Some(u32::try_from(data.rrsets.len()).unwrap_or(u32::MAX)),
                bytes: None,
                peer: request.peer.clone(),
                outgoing: true,
            }),
            ZoneKind::Secondary => {
                if let Some(from_serial) = request.from_serial
                    && Serial::new(from_serial).is_newer_than(zone_serial(&data)) != Some(false)
                {
                    return Err(AdminError::invariant(
                        "/from_serial",
                        "serial-not-older",
                        "from_serial must be older than the current serial",
                    ));
                }
                Ok(TransferResult {
                    zone: origin.clone(),
                    kind: request.kind,
                    mode_used: request.kind,
                    serial: Some(zone_serial(&data)),
                    rrsets: Some(u32::try_from(data.rrsets.len()).unwrap_or(u32::MAX)),
                    bytes: Some(0),
                    peer: request.peer.clone(),
                    outgoing: false,
                })
            }
            ZoneKind::Forward => Err(AdminError::Conflict(
                crate::error::Conflict::InvalidZoneState,
            )),
        }
    }

    fn import_zone(
        &self,
        origin: &Name,
        text: &str,
        mode: ImportMode,
    ) -> Result<ImportReport, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let mut data = lock_zone(&zone);
        self.check_writable(&data)?;
        let parsed = pulse_master::parse_zone(origin.clone(), text).map_err(|error| {
            AdminError::invariant("/body", "invalid-zonefile", error.to_string())
        })?;
        let warnings: Vec<String> = parsed
            .warnings
            .iter()
            .map(|warning| warning.kind.to_string())
            .collect();
        let imported = rrsets_from_parsed(&parsed)?;
        let mut rrsets = if mode == ImportMode::Merge {
            data.rrsets
                .values()
                .map(|record| record.rrset.clone())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        for rrset in imported {
            let key = (rrset.owner().to_string(), rrset.rr_type().as_u16());
            rrsets.retain(|existing| {
                (existing.owner().to_string(), existing.rr_type().as_u16()) != key
            });
            rrsets.push(rrset);
        }
        let (records, nodes, serial) =
            build_zone_records(origin, rrsets, std::time::SystemTime::now())?;
        let count = u32::try_from(records.len()).unwrap_or(u32::MAX);
        if mode == ImportMode::Check {
            return Ok(ImportReport {
                zone: origin.clone(),
                mode,
                rrsets: count,
                serial: Some(serial),
                warnings,
                applied: false,
            });
        }
        data.rrsets = records;
        data.nodes = nodes;
        data.serial = serial;
        data.version = data.version.saturating_add(1);
        data.txn = self.next_txn();
        data.updated_at = std::time::SystemTime::now();
        Ok(ImportReport {
            zone: origin.clone(),
            mode,
            rrsets: count,
            serial: Some(serial),
            warnings,
            applied: true,
        })
    }

    fn rollover_keys(
        &self,
        origin: &Name,
        request: &RolloverRequest,
    ) -> Result<KeyRotationView, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let _data = lock_zone(&zone);
        let role = match request.role.as_str() {
            "ksk" => "ksk",
            "zsk" => "zsk",
            _ => {
                return Err(AdminError::invariant(
                    "/role",
                    "invalid-role",
                    "role must be ksk or zsk",
                ));
            }
        };
        let now = unix_now();
        let mut rotation = self.rotation.lock().unwrap_or_else(PoisonError::into_inner);
        let view = rotation
            .entry(Self::zone_key(origin))
            .or_insert_with(|| KeyRotationView {
                keys: vec![
                    KeyRotationKeyView {
                        key_tag: 1,
                        role: "ksk".to_owned(),
                        state: "active".to_owned(),
                        created_at: now,
                        next_transition: None,
                    },
                    KeyRotationKeyView {
                        key_tag: 2,
                        role: "zsk".to_owned(),
                        state: "active".to_owned(),
                        created_at: now,
                        next_transition: None,
                    },
                ],
                next_event_at: None,
            });
        if view.keys.iter().any(|key| {
            key.role == role && matches!(key.state.as_str(), "pre_publish" | "double_sign")
        }) {
            return Err(AdminError::Conflict(crate::error::Conflict::ZoneBusy));
        }
        let next_transition = now.saturating_add(request.overlap.max(1));
        let key_tag = u16::try_from(view.keys.len().saturating_add(3)).unwrap_or(3);
        view.keys.push(KeyRotationKeyView {
            key_tag,
            role: role.to_owned(),
            state: "pre_publish".to_owned(),
            created_at: now,
            next_transition: Some(next_transition),
        });
        view.next_event_at = view.keys.iter().filter_map(|key| key.next_transition).min();
        Ok(view.clone())
    }

    fn key_rotation(&self, origin: &Name) -> Result<Option<KeyRotationView>, AdminError> {
        let rotation = self.rotation.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(rotation.get(&Self::zone_key(origin)).cloned())
    }

    fn put_zone(
        &self,
        origin: &Name,
        meta: &ZoneMetaInput,
        preconditions: &Preconditions,
    ) -> Result<WriteOutcome<ZoneView>, AdminError> {
        if origin == &Name::root() || origin.labels().any(|label| label == b"*") {
            return Err(AdminError::invariant(
                "/origin",
                "invalid-origin",
                "zone origin must be a non-root name without wildcards",
            ));
        }
        let key = Self::zone_key(origin);
        {
            let catalog = self.catalog.read().unwrap_or_else(PoisonError::into_inner);
            if let Some(zone) = catalog.get(&key) {
                let mut data = lock_zone(zone);
                let view = self.replace_zone(&mut data, meta, preconditions)?;
                return Ok(WriteOutcome::Updated(view));
            }
        }
        check_create(preconditions)?;
        let mut catalog = self.catalog.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(zone) = catalog.get(&key) {
            let mut data = lock_zone(zone);
            let view = self.replace_zone(&mut data, meta, preconditions)?;
            return Ok(WriteOutcome::Updated(view));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let txn = self.next_txn();
        let now = std::time::SystemTime::now();
        let data = ZoneData {
            id: ZoneId::new(id),
            origin: origin.clone(),
            kind: meta.kind,
            serial: Serial::new(1),
            version: 1,
            txn,
            default_ttl: meta.default_ttl,
            denial: meta.denial,
            rrsets: BTreeMap::new(),
            nodes: HashSet::from([origin.clone()]),
            created_at: now,
            updated_at: now,
        };
        let view = data.view();
        catalog.insert(key, Arc::new(Mutex::new(data)));
        Ok(WriteOutcome::Created(view))
    }

    fn delete_zone(&self, origin: &Name, preconditions: &Preconditions) -> Result<(), AdminError> {
        let key = Self::zone_key(origin);
        let mut catalog = self.catalog.write().unwrap_or_else(PoisonError::into_inner);
        let zone = catalog
            .get(&key)
            .cloned()
            .ok_or_else(AdminError::zone_not_found)?;
        {
            let data = lock_zone(&zone);
            check_existing(preconditions, &data.etag(), data.version)?;
        }
        catalog.remove(&key);
        // Удаление зоны не меняет ни одной ZoneData, поэтому глобальную
        // ревизию нужно продвинуть явно: DNS-адаптеры перестраивают снапшот
        // по `revision`.
        let _ = self.next_txn();
        Ok(())
    }

    fn list_rrsets(&self, origin: &Name, query: &ListRrsets) -> Result<RrsetPage, AdminError> {
        let limit = if query.limit == 0 {
            50
        } else {
            query.limit.min(500)
        };
        let cursor = match query.cursor.as_deref() {
            Some(cursor) => Some(decode_rrset_cursor(cursor)?),
            None => None,
        };
        let (_catalog, zone) = self.zone_handle(origin)?;
        let data = lock_zone(&zone);
        let mut items = Vec::new();
        let mut has_more = false;
        for (key, record) in &data.rrsets {
            let owner = record.rrset.owner();
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
            if !query.types.is_empty() && !query.types.contains(&record.rrset.rr_type()) {
                continue;
            }
            if let Some((cursor_owner, cursor_type)) = &cursor {
                let key_owner = key.0.as_str();
                if key_owner < cursor_owner.as_str()
                    || (key_owner == cursor_owner.as_str() && key.1 <= *cursor_type)
                {
                    continue;
                }
            }
            if items.len() >= limit as usize {
                has_more = true;
                break;
            }
            items.push(rrset_view(&data, record));
        }
        let next_cursor = if has_more {
            items
                .last()
                .map(|rrset| encode_rrset_cursor(&rrset.owner, rrset.rr_type))
        } else {
            None
        };
        Ok(RrsetPage {
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
        let (_catalog, zone) = self.zone_handle(origin)?;
        let data = lock_zone(&zone);
        let key = Self::rrset_key(owner, rr_type);
        let record = data
            .rrsets
            .get(&key)
            .ok_or_else(AdminError::rrset_not_found)?;
        Ok(rrset_view(&data, record))
    }

    fn put_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        input: &RrsetInput,
        preconditions: &Preconditions,
    ) -> Result<WriteOutcome<RrsetView>, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let mut data = lock_zone(&zone);
        self.check_writable(&data)?;
        self.validate_type(&data, owner, rr_type)?;
        self.check_owner_conflicts(&data, owner, rr_type)?;
        let rrset = Rrset::new(
            owner.clone(),
            rr_type,
            Rclass::IN,
            input.ttl,
            input.rdata.iter().cloned(),
        )
        .map_err(map_rrset_error)?;
        if rr_type == Rtype::SOA && rrset.len() != 1 {
            return Err(AdminError::invariant(
                "/records",
                "soa-single",
                "apex SOA must contain exactly one record",
            ));
        }
        let key = Self::rrset_key(owner, rr_type);
        let existed = data.rrsets.contains_key(&key);
        if let Some(current) = data.rrsets.get(&key) {
            check_existing(preconditions, &current.etag, data.version)?;
        } else {
            check_create(preconditions)?;
        }
        let now = std::time::SystemTime::now();
        let etag = rrset_etag(&rrset);
        data.rrsets.insert(
            key,
            RrsetRecord {
                rrset,
                etag,
                updated_at: now,
            },
        );
        register_nodes(&mut data, owner);
        data.serial = data.serial.succ();
        data.version = data.version.saturating_add(1);
        data.txn = self.next_txn();
        data.updated_at = now;
        let record = data
            .rrsets
            .get(&Self::rrset_key(owner, rr_type))
            .ok_or(AdminError::Internal)?;
        let view = rrset_view(&data, record);
        if existed {
            Ok(WriteOutcome::Updated(view))
        } else {
            Ok(WriteOutcome::Created(view))
        }
    }

    fn patch_rrset(
        &self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        patch: &RrsetPatch,
        preconditions: &Preconditions,
    ) -> Result<RrsetPatchOutcome, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let mut data = lock_zone(&zone);
        self.check_writable(&data)?;
        let key = Self::rrset_key(owner, rr_type);
        let current = data
            .rrsets
            .get(&key)
            .ok_or_else(AdminError::rrset_not_found)?;
        check_existing(preconditions, &current.etag, data.version)?;
        let ttl = patch.ttl.unwrap_or(current.rrset.ttl());
        let current_set: BTreeSet<Rdata> = current.rrset.rdatas().iter().cloned().collect();
        let remove_set: BTreeSet<Rdata> = patch.remove.iter().cloned().collect();
        let add_set: BTreeSet<Rdata> = patch.add.iter().cloned().collect();
        let mut next_set = current_set.clone();
        for record in &remove_set {
            next_set.remove(record);
        }
        let removed = current_set.len().saturating_sub(
            current_set
                .iter()
                .filter(|record| !remove_set.contains(*record))
                .count(),
        );
        let added = add_set
            .iter()
            .filter(|record| !current_set.contains(*record))
            .count();
        for record in &add_set {
            next_set.insert(record.clone());
        }
        let now = std::time::SystemTime::now();
        if next_set.is_empty() {
            data.rrsets.remove(&key);
            data.serial = data.serial.succ();
            data.version = data.version.saturating_add(1);
            data.txn = self.next_txn();
            data.updated_at = now;
            return Ok(RrsetPatchOutcome::Deleted {
                removed: u32::try_from(removed).unwrap_or(u32::MAX),
            });
        }
        let rrset = Rrset::new(owner.clone(), rr_type, Rclass::IN, ttl, next_set)
            .map_err(map_rrset_error)?;
        if rr_type == Rtype::SOA && rrset.len() != 1 {
            return Err(AdminError::invariant(
                "/records",
                "soa-single",
                "apex SOA must contain exactly one record",
            ));
        }
        let etag = rrset_etag(&rrset);
        data.rrsets.insert(
            key,
            RrsetRecord {
                rrset,
                etag,
                updated_at: now,
            },
        );
        register_nodes(&mut data, owner);
        data.serial = data.serial.succ();
        data.version = data.version.saturating_add(1);
        data.txn = self.next_txn();
        data.updated_at = now;
        let record = data
            .rrsets
            .get(&Self::rrset_key(owner, rr_type))
            .ok_or(AdminError::Internal)?;
        Ok(RrsetPatchOutcome::Updated {
            rrset: rrset_view(&data, record),
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
        let (_catalog, zone) = self.zone_handle(origin)?;
        let mut data = lock_zone(&zone);
        self.check_writable(&data)?;
        let key = Self::rrset_key(owner, rr_type);
        let current = data
            .rrsets
            .get(&key)
            .ok_or_else(AdminError::rrset_not_found)?;
        check_existing(preconditions, &current.etag, data.version)?;
        data.rrsets.remove(&key);
        data.serial = data.serial.succ();
        data.version = data.version.saturating_add(1);
        data.txn = self.next_txn();
        data.updated_at = std::time::SystemTime::now();
        Ok(())
    }

    fn get_settings(&self, origin: &Name) -> Result<ZoneSettingsView, AdminError> {
        let (_catalog, zone) = self.zone_handle(origin)?;
        let data = lock_zone(&zone);
        Ok(data.settings_view())
    }

    fn patch_settings(
        &self,
        origin: &Name,
        patch: &ZoneSettingsPatch,
        preconditions: &Preconditions,
    ) -> Result<ZoneSettingsView, AdminError> {
        if patch.is_empty() {
            return Err(AdminError::InvariantViolation(InvariantViolation::single(
                "/",
                "validation-failed",
                "at least one setting must be provided",
            )));
        }
        let (_catalog, zone) = self.zone_handle(origin)?;
        let mut data = lock_zone(&zone);
        check_existing(preconditions, &data.etag(), data.version)?;
        if let Some(default_ttl) = patch.default_ttl {
            data.default_ttl = default_ttl;
        }
        if let Some(denial) = patch.denial {
            data.denial = denial;
        }
        data.version = data.version.saturating_add(1);
        data.txn = self.next_txn();
        data.updated_at = std::time::SystemTime::now();
        Ok(data.settings_view())
    }
}

fn encode_zone_cursor(id: ZoneId) -> String {
    base64url::encode(id.as_u32().to_string().as_bytes())
}

fn decode_zone_cursor(cursor: &str) -> Result<u32, AdminError> {
    let bytes = base64url::decode(cursor).ok_or(AdminError::InvalidCursor)?;
    let text = String::from_utf8(bytes).map_err(|_| AdminError::InvalidCursor)?;
    text.parse::<u32>().map_err(|_| AdminError::InvalidCursor)
}

fn encode_rrset_cursor(owner: &Name, rr_type: Rtype) -> String {
    let payload = format!("{}\u{0}{}", owner, rr_type.as_u16());
    base64url::encode(payload.as_bytes())
}

fn decode_rrset_cursor(cursor: &str) -> Result<(String, u16), AdminError> {
    let bytes = base64url::decode(cursor).ok_or(AdminError::InvalidCursor)?;
    let text = String::from_utf8(bytes).map_err(|_| AdminError::InvalidCursor)?;
    let (owner, rr_type) = text.split_once('\u{0}').ok_or(AdminError::InvalidCursor)?;
    let rr_type = rr_type
        .parse::<u16>()
        .map_err(|_| AdminError::InvalidCursor)?;
    Ok((owner.to_owned(), rr_type))
}

fn zone_serial(data: &ZoneData) -> Serial {
    data.rrsets
        .get(&(data.origin.to_string(), Rtype::SOA.as_u16()))
        .and_then(|record| match record.rrset.rdatas().first() {
            Some(Rdata::Soa(soa)) => Some(soa.serial),
            _ => None,
        })
        .unwrap_or(data.serial)
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

fn rrsets_from_parsed(parsed: &pulse_master::ParsedZone) -> Result<Vec<Rrset>, AdminError> {
    let mut groups: HashMap<(Name, Rtype), (Ttl, Vec<Rdata>)> = HashMap::new();
    for record in &parsed.records {
        let key = (record.owner().clone(), record.rr_type());
        match groups.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get().0 != record.ttl() {
                    return Err(AdminError::invariant(
                        "/body",
                        "ttl-mismatch",
                        "records of one RRset must share the TTL",
                    ));
                }
                entry.get_mut().1.push(record.rdata().clone());
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert((record.ttl(), vec![record.rdata().clone()]));
            }
        }
    }
    let mut entries: Vec<((Name, Rtype), (Ttl, Vec<Rdata>))> = groups.into_iter().collect();
    entries.sort_by(|(left, _), (right, _)| {
        left.0
            .to_string()
            .cmp(&right.0.to_string())
            .then_with(|| left.1.as_u16().cmp(&right.1.as_u16()))
    });
    entries
        .into_iter()
        .map(|((owner, rr_type), (ttl, rdata))| {
            Rrset::new(owner, rr_type, Rclass::IN, ttl, rdata)
                .map_err(|error| AdminError::invariant("/body", "invalid-rrset", error.to_string()))
        })
        .collect()
}

fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u32::try_from(duration.as_secs()).unwrap_or(u32::MAX)
        })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use pulse_dns::{Name, Rdata, Rtype, Serial, SoaData, Ttl};

    use super::*;
    use crate::port::AllowAll;

    fn origin() -> Name {
        Name::parse("example.com.").unwrap()
    }

    fn meta() -> ZoneMetaInput {
        ZoneMetaInput {
            kind: ZoneKind::Primary,
            default_ttl: Ttl::new(3600).unwrap(),
            denial: Denial::Nsec,
        }
    }

    fn store_with_zone() -> (InMemoryZoneAdmin, String) {
        let store = InMemoryZoneAdmin::new();
        let created = store
            .put_zone(&origin(), &meta(), &Preconditions::none())
            .unwrap();
        let etag = created.value().etag.clone();
        (store, etag)
    }

    fn a_record(address: &str) -> Rdata {
        Rdata::A(address.parse().unwrap())
    }

    fn soa_record(serial: u32) -> Rdata {
        Rdata::Soa(SoaData::new(
            Name::parse("ns1.example.com.").unwrap(),
            Name::parse("hostmaster.example.com.").unwrap(),
            Serial::new(serial),
            3600,
            600,
            604_800,
            300,
        ))
    }

    #[test]
    fn zone_lifecycle() {
        let (store, etag) = store_with_zone();
        assert!(store.get_zone(&origin()).is_ok());
        assert!(matches!(
            store.put_zone(&origin(), &meta(), &Preconditions::none()),
            Err(AdminError::PreconditionRequired)
        ));
        let replaced = store
            .put_zone(&origin(), &meta(), &Preconditions::if_match(&etag))
            .unwrap();
        assert!(!replaced.is_created());
        let new_etag = replaced.value().etag.clone();
        store
            .delete_zone(&origin(), &Preconditions::if_match(&new_etag))
            .unwrap();
        assert!(matches!(
            store.get_zone(&origin()),
            Err(AdminError::NotFound(_))
        ));
    }

    #[test]
    fn rrset_crud_and_patch() {
        let (store, zone_etag) = store_with_zone();
        let owner = Name::parse("www.example.com.").unwrap();
        let input = RrsetInput {
            ttl: Ttl::new(300).unwrap(),
            rdata: vec![a_record("192.0.2.10")],
        };
        let created = store
            .put_rrset(&origin(), &owner, Rtype::A, &input, &Preconditions::none())
            .unwrap();
        let etag = created.value().etag.clone();
        let updated = store
            .put_rrset(
                &origin(),
                &owner,
                Rtype::A,
                &RrsetInput {
                    ttl: Ttl::new(300).unwrap(),
                    rdata: vec![a_record("192.0.2.10"), a_record("192.0.2.11")],
                },
                &Preconditions::if_match(&etag),
            )
            .unwrap();
        assert_eq!(updated.value().rdata.len(), 2);
        let etag = updated.value().etag.clone();
        let patched = store
            .patch_rrset(
                &origin(),
                &owner,
                Rtype::A,
                &RrsetPatch {
                    ttl: Some(Ttl::new(600).unwrap()),
                    add: vec![a_record("192.0.2.12")],
                    remove: vec![a_record("192.0.2.10")],
                },
                &Preconditions::if_match(&etag),
            )
            .unwrap();
        let RrsetPatchOutcome::Updated {
            rrset,
            added,
            removed,
        } = patched
        else {
            panic!("expected updated");
        };
        assert_eq!(added, 1);
        assert_eq!(removed, 1);
        assert_eq!(rrset.ttl, Ttl::new(600).unwrap());
        assert_eq!(rrset.rdata.len(), 2);
        let etag = rrset.etag.clone();
        let outcome = store
            .patch_rrset(
                &origin(),
                &owner,
                Rtype::A,
                &RrsetPatch {
                    ttl: None,
                    add: Vec::new(),
                    remove: rrset.rdata.clone(),
                },
                &Preconditions::if_match(&etag),
            )
            .unwrap();
        assert!(matches!(outcome, RrsetPatchOutcome::Deleted { removed: 2 }));
        assert!(matches!(
            store.get_rrset(&origin(), &owner, Rtype::A),
            Err(AdminError::NotFound(_))
        ));
        let _ = zone_etag;
    }

    #[test]
    fn conditional_write_is_atomic() {
        let (store, _) = store_with_zone();
        let owner = Name::parse("www.example.com.").unwrap();
        let input = RrsetInput {
            ttl: Ttl::new(300).unwrap(),
            rdata: vec![a_record("192.0.2.10")],
        };
        let created = store
            .put_rrset(&origin(), &owner, Rtype::A, &input, &Preconditions::none())
            .unwrap();
        let etag = created.value().etag.clone();
        let store = Arc::new(store);
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for address in ["192.0.2.20", "192.0.2.21"] {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let etag = etag.clone();
            let owner = owner.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                store.put_rrset(
                    &origin(),
                    &owner,
                    Rtype::A,
                    &RrsetInput {
                        ttl: Ttl::new(300).unwrap(),
                        rdata: vec![a_record(address)],
                    },
                    &Preconditions::if_match(&etag),
                )
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let ok = results.iter().filter(|result| result.is_ok()).count();
        let failed = results
            .iter()
            .filter(|result| matches!(result, Err(AdminError::PreconditionFailed { .. })))
            .count();
        assert_eq!((ok, failed), (1, 1));
    }

    #[test]
    fn pagination_and_allowlist() {
        let store = InMemoryZoneAdmin::new();
        for name in ["a.example.", "b.example.", "c.example."] {
            store
                .put_zone(&Name::parse(name).unwrap(), &meta(), &Preconditions::none())
                .unwrap();
        }
        let scope = crate::auth::ZoneScope::parse(&["*.example.".to_owned()]).unwrap();
        let first = store
            .list_zones(
                &ListZones {
                    limit: 2,
                    cursor: None,
                    kind: None,
                },
                &scope,
            )
            .unwrap();
        assert_eq!(first.items.len(), 2);
        assert!(first.has_more);
        let second = store
            .list_zones(
                &ListZones {
                    limit: 2,
                    cursor: first.next_cursor.clone(),
                    kind: None,
                },
                &scope,
            )
            .unwrap();
        assert_eq!(second.items.len(), 1);
        assert!(!second.has_more);
        let all = store
            .list_zones(
                &ListZones {
                    limit: 10,
                    cursor: None,
                    kind: None,
                },
                &AllowAll,
            )
            .unwrap();
        assert_eq!(all.items.len(), 3);
    }

    #[test]
    fn cname_conflict_rejected() {
        let (store, _) = store_with_zone();
        let owner = Name::parse("alias.example.com.").unwrap();
        let cname = RrsetInput {
            ttl: Ttl::new(300).unwrap(),
            rdata: vec![Rdata::Cname(Name::parse("target.example.com.").unwrap())],
        };
        store
            .put_rrset(
                &origin(),
                &owner,
                Rtype::CNAME,
                &cname,
                &Preconditions::none(),
            )
            .unwrap();
        let error = store
            .put_rrset(
                &origin(),
                &owner,
                Rtype::A,
                &RrsetInput {
                    ttl: Ttl::new(300).unwrap(),
                    rdata: vec![a_record("192.0.2.1")],
                },
                &Preconditions::none(),
            )
            .unwrap_err();
        assert!(matches!(error, AdminError::InvariantViolation(_)));
    }

    #[test]
    fn snapshot_exposes_rrsets_and_preserves_empty_nodes() {
        let (store, _) = store_with_zone();
        let owner = Name::parse("www.example.com.").unwrap();
        let created = store
            .put_rrset(
                &origin(),
                &owner,
                Rtype::A,
                &RrsetInput {
                    ttl: Ttl::new(300).unwrap(),
                    rdata: vec![a_record("192.0.2.10")],
                },
                &Preconditions::none(),
            )
            .unwrap();
        let snapshot = store.snapshot();
        assert_eq!(snapshot.zones.len(), 1);
        assert_eq!(snapshot.revision, snapshot.zones[0].txn);
        assert_eq!(snapshot.zones[0].rrsets.len(), 1);
        assert!(snapshot.zones[0].nodes.contains(&owner));

        let etag = created.value().etag.clone();
        store
            .delete_rrset(&origin(), &owner, Rtype::A, &Preconditions::if_match(etag))
            .unwrap();
        let snapshot = store.snapshot();
        assert_eq!(snapshot.zones[0].rrsets.len(), 0);
        assert!(snapshot.zones[0].nodes.contains(&owner));
    }

    #[test]
    fn import_zone_is_atomic_and_uses_soa_serial() {
        let store = InMemoryZoneAdmin::new();
        let origin = origin();
        let owner = Name::parse("www.example.com.").unwrap();
        let rrsets = vec![
            Rrset::new(
                origin.clone(),
                Rtype::SOA,
                Rclass::IN,
                Ttl::new(3600).unwrap(),
                [soa_record(7)],
            )
            .unwrap(),
            Rrset::new(
                origin.clone(),
                Rtype::NS,
                Rclass::IN,
                Ttl::new(3600).unwrap(),
                [Rdata::Ns(Name::parse("ns1.example.com.").unwrap())],
            )
            .unwrap(),
            Rrset::new(
                owner.clone(),
                Rtype::A,
                Rclass::IN,
                Ttl::new(300).unwrap(),
                [a_record("192.0.2.10")],
            )
            .unwrap(),
        ];
        let view = store.import_zone(&origin, &meta(), rrsets).unwrap();
        assert_eq!(view.serial, Serial::new(7));
        let snapshot = store.snapshot();
        assert_eq!(snapshot.zones[0].rrsets.len(), 3);
        assert!(snapshot.zones[0].nodes.contains(&owner));
        assert!(matches!(
            store.import_zone(&origin, &meta(), Vec::new()),
            Err(AdminError::Conflict(_))
        ));
    }

    #[test]
    fn soa_is_editable_at_apex_only_and_single() {
        let (store, _) = store_with_zone();
        let created = store
            .put_rrset(
                &origin(),
                &origin(),
                Rtype::SOA,
                &RrsetInput {
                    ttl: Ttl::new(3600).unwrap(),
                    rdata: vec![soa_record(1)],
                },
                &Preconditions::none(),
            )
            .unwrap();
        assert_eq!(created.value().rr_type, Rtype::SOA);

        let non_apex = Name::parse("sub.example.com.").unwrap();
        let error = store
            .put_rrset(
                &origin(),
                &non_apex,
                Rtype::SOA,
                &RrsetInput {
                    ttl: Ttl::new(3600).unwrap(),
                    rdata: vec![soa_record(2)],
                },
                &Preconditions::none(),
            )
            .unwrap_err();
        assert!(matches!(error, AdminError::InvariantViolation(_)));

        let etag = created.value().etag.clone();
        let error = store
            .put_rrset(
                &origin(),
                &origin(),
                Rtype::SOA,
                &RrsetInput {
                    ttl: Ttl::new(3600).unwrap(),
                    rdata: vec![soa_record(3), soa_record(4)],
                },
                &Preconditions::if_match(etag),
            )
            .unwrap_err();
        assert!(matches!(error, AdminError::InvariantViolation(_)));
    }

    #[test]
    fn delete_last_removes_rrset_and_etag_isolated() {
        let (store, _) = store_with_zone();
        let first = Name::parse("a.example.com.").unwrap();
        let second = Name::parse("b.example.com.").unwrap();
        let input = |address: &str| RrsetInput {
            ttl: Ttl::new(300).unwrap(),
            rdata: vec![a_record(address)],
        };
        store
            .put_rrset(
                &origin(),
                &first,
                Rtype::A,
                &input("192.0.2.1"),
                &Preconditions::none(),
            )
            .unwrap();
        let second_view = store
            .put_rrset(
                &origin(),
                &second,
                Rtype::A,
                &input("192.0.2.2"),
                &Preconditions::none(),
            )
            .unwrap();
        let second_etag = second_view.value().etag.clone();
        assert_eq!(
            store.get_rrset(&origin(), &second, Rtype::A).unwrap().etag,
            second_etag
        );
        store
            .put_rrset(
                &origin(),
                &first,
                Rtype::A,
                &input("192.0.2.3"),
                &Preconditions::if_match(
                    &store.get_rrset(&origin(), &first, Rtype::A).unwrap().etag,
                ),
            )
            .unwrap();
        assert_eq!(
            store.get_rrset(&origin(), &second, Rtype::A).unwrap().etag,
            second_etag
        );
    }
}
