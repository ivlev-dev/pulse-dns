//! Write-through persistence в `pulse-zonefile`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use pulse_api::{Denial, InMemoryZoneAdmin, StoreSnapshot, ZoneKind, ZoneMetaInput, ZoneSnapshot};
use pulse_dns::{Name, Rclass, Rdata, Rrset, Rtype, Ttl};
use pulse_zonefile::key::NameRle;
use pulse_zonefile::{
    CreateConfig, LockMode, OpenConfig, RrsetData, SyncMode, ZoneEntry, ZoneFile, ZoneFileError,
    ZoneItemValue, ZoneMetaBlock, ZoneWriter,
};
use thiserror::Error;

/// Ошибка persistence-слоя.
#[derive(Debug, Error)]
#[error("{0}")]
pub(crate) struct PersistenceError(String);

impl PersistenceError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

type RrsetKey = (Name, Rtype);
type PendingRrset = (u32, Vec<Rdata>);

/// Зона, прочитанная из zonefile.
pub(crate) struct PersistedZone {
    pub(crate) origin: Name,
    pub(crate) kind: ZoneKind,
    pub(crate) default_ttl: Ttl,
    pub(crate) denial: Denial,
    pub(crate) rrsets: Vec<Rrset>,
    pub(crate) nodes: Vec<Name>,
}

/// Открытый zonefile (единственный writer-лок на процесс).
pub(crate) struct ZonePersistence {
    zonefile: ZoneFile,
    requested: SyncMode,
    path: PathBuf,
}

impl ZonePersistence {
    /// Открывает существующий файл или создаёт новый.
    ///
    /// Существующий пустой regular-файл трактуется как «ещё не
    /// инициализирован»: он удаляется и создаётся заново (bootstrap).
    pub(crate) fn open_or_create(
        path: &Path,
        map_size: u64,
        requested: SyncMode,
    ) -> Result<(Self, Vec<PersistedZone>, bool), PersistenceError> {
        let existed = match std::fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_file() && meta.len() == 0 {
                    std::fs::remove_file(path).map_err(|error| {
                        PersistenceError::new(format!(
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
                return Err(PersistenceError::new(format!(
                    "cannot stat zone file {}: {error}",
                    path.display()
                )));
            }
        };
        let zonefile = if existed {
            ZoneFile::open(
                path,
                OpenConfig {
                    lock_mode: LockMode::Writer,
                    ..OpenConfig::default()
                },
            )
            .map_err(|error| file_error(path, "open", &error))?
        } else {
            ZoneFile::create(
                path,
                CreateConfig {
                    map_size,
                    sync_mode: requested,
                    ..CreateConfig::default()
                },
            )
            .map_err(|error| file_error(path, "create", &error))?
        };
        let persistence = Self {
            zonefile,
            requested,
            path: path.to_path_buf(),
        };
        let zones = persistence.load_all()?;
        Ok((persistence, zones, !existed))
    }

    /// Все живые зоны и их RRset/узлы.
    pub(crate) fn load_all(&self) -> Result<Vec<PersistedZone>, PersistenceError> {
        let entries = self
            .zonefile
            .zones()
            .map_err(|error| self.file_error("enumerate zones", &error))?;
        let mut zones = Vec::with_capacity(entries.len());
        for (apex, entry) in entries {
            zones.push(self.load_zone(&apex, &entry)?);
        }
        Ok(zones)
    }

    #[allow(clippy::too_many_lines)] // Один проход по зоне: metadata + nodes + RRset.
    fn load_zone(
        &self,
        apex: &NameRle,
        entry: &ZoneEntry,
    ) -> Result<PersistedZone, PersistenceError> {
        let origin = name_from_rle(apex).map_err(|error| {
            PersistenceError::new(format!("cannot decode origin in zonefile: {error}"))
        })?;
        let meta = self
            .zonefile
            .zone_meta(apex)
            .map_err(|error| self.file_error("read zone metadata", &error))?
            .ok_or_else(|| {
                PersistenceError::new(format!("zone {origin}: missing metadata block"))
            })?;
        let kind = kind_from_flags(entry.flags);
        let default_ttl = Ttl::new(meta.default_ttl).map_err(|error| {
            PersistenceError::new(format!("zone {origin}: invalid default ttl: {error}"))
        })?;
        let denial = denial_from_u8(meta.denial).ok_or_else(|| {
            PersistenceError::new(format!("zone {origin}: invalid denial {}", meta.denial))
        })?;

        let mut nodes = Vec::new();
        let mut groups: HashMap<RrsetKey, PendingRrset> = HashMap::new();
        let items = self
            .zonefile
            .zone_items(apex)
            .map_err(|error| self.file_error("read zone tree", &error))?;
        for item in items {
            let item = item.map_err(|error| self.file_error("read zone item", &error))?;
            match item.value {
                ZoneItemValue::Node { .. } => {
                    nodes.push(name_from_rle(&item.name).map_err(|error| {
                        PersistenceError::new(format!("zone {origin}: bad node name: {error}"))
                    })?);
                }
                ZoneItemValue::Rrset(view) => {
                    if item.class != 1 {
                        return Err(PersistenceError::new(format!(
                            "zone {origin}: {} {} has unsupported class {}",
                            item.name, item.rr_type, item.class
                        )));
                    }
                    let owner = name_from_rle(&item.name).map_err(|error| {
                        PersistenceError::new(format!(
                            "zone {origin}: bad owner name in rrset: {error}"
                        ))
                    })?;
                    let rr_type = Rtype::from_u16(item.rr_type);
                    let key = (owner.clone(), rr_type);
                    let entry = groups.entry(key).or_insert_with(|| (view.ttl, Vec::new()));
                    if entry.0 != view.ttl {
                        return Err(PersistenceError::new(format!(
                            "zone {origin}: TTL mismatch for {owner} {rr_type}: {} and {}",
                            entry.0, view.ttl
                        )));
                    }
                    for bytes in view.rdata {
                        let rdata = Rdata::from_wire(rr_type, &bytes).map_err(|error| {
                            PersistenceError::new(format!(
                                "zone {origin}: invalid stored rdata for {owner} {rr_type}: {error}"
                            ))
                        })?;
                        if rr_type == Rtype::RRSIG
                            && let Rdata::Rrsig(signature) = &rdata
                            && signature.type_covered().as_u16() != item.subtype
                        {
                            return Err(PersistenceError::new(format!(
                                "zone {origin}: RRSIG subtype {} does not match covered type {} at {owner}",
                                item.subtype,
                                signature.type_covered()
                            )));
                        }
                        entry.1.push(rdata);
                    }
                }
            }
        }

        let mut rrsets = Vec::with_capacity(groups.len());
        let mut entries: Vec<(RrsetKey, PendingRrset)> = groups.into_iter().collect();
        entries.sort_by(|(left, _), (right, _)| {
            left.0
                .to_string()
                .cmp(&right.0.to_string())
                .then_with(|| left.1.as_u16().cmp(&right.1.as_u16()))
        });
        for ((owner, rr_type), (ttl, rdata)) in entries {
            let ttl = Ttl::new(ttl).map_err(|error| {
                PersistenceError::new(format!(
                    "zone {origin}: invalid ttl for {owner} {rr_type}: {error}"
                ))
            })?;
            let rrset =
                Rrset::new(owner.clone(), rr_type, Rclass::IN, ttl, rdata).map_err(|error| {
                    PersistenceError::new(format!(
                        "zone {origin}: invalid stored RRset {owner} {rr_type}: {error}"
                    ))
                })?;
            rrsets.push(rrset);
        }

        Ok(PersistedZone {
            origin,
            kind,
            default_ttl,
            denial,
            rrsets,
            nodes,
        })
    }

    /// Записывает текущий store в пустой zonefile (bootstrap).
    pub(crate) fn bootstrap(&mut self, snapshot: &StoreSnapshot) -> Result<(), PersistenceError> {
        let path = self.path.clone();
        let mode = self.commit_mode();
        let mut writer = self
            .zonefile
            .write()
            .map_err(|error| file_error(&path, "begin bootstrap", &error))?;
        for zone in &snapshot.zones {
            let apex = name_to_rle(&zone.origin)
                .map_err(|error| PersistenceError::new(format!("zone {}: {error}", zone.origin)))?;
            let meta = ZoneMetaBlock {
                default_ttl: zone.default_ttl.as_u32(),
                denial: denial_to_u8(zone.denial),
                ..ZoneMetaBlock::default()
            };
            writer
                .create_zone_with_meta(&apex, kind_flags(zone.kind), &meta)
                .map_err(|error| file_error(&path, "create zone in bootstrap", &error))?;
            for rrset in &zone.rrsets {
                write_rrset(&mut writer, &apex, rrset)?;
            }
            let owners: HashSet<&Name> = zone.rrsets.iter().map(Rrset::owner).collect();
            for node in &zone.nodes {
                if owners.contains(node) {
                    continue;
                }
                let node_rle = name_to_rle(node).map_err(|error| {
                    PersistenceError::new(format!(
                        "zone {}: empty node {node}: {error}",
                        zone.origin
                    ))
                })?;
                writer
                    .ensure_empty_node(&apex, &node_rle)
                    .map_err(|error| file_error(&path, "write empty node", &error))?;
            }
        }
        writer
            .commit(mode)
            .map_err(|error| file_error(&path, "bootstrap commit", &error))?;
        Ok(())
    }

    /// Persist создание/замену зоны.
    pub(crate) fn put_zone(
        &mut self,
        zone: &pulse_api::ZoneView,
        created: bool,
    ) -> Result<(), PersistenceError> {
        let apex = name_to_rle(&zone.origin)
            .map_err(|error| PersistenceError::new(format!("zone {}: {error}", zone.origin)))?;
        let current_meta = self
            .zonefile
            .zone_meta(&apex)
            .map_err(|error| self.file_error("read zone metadata", &error))?;
        let mut meta = current_meta.unwrap_or_default();
        meta.default_ttl = zone.default_ttl.as_u32();
        meta.denial = denial_to_u8(zone.denial);
        let path = self.path.clone();
        let mode = self.commit_mode();
        let mut writer = self
            .zonefile
            .write()
            .map_err(|error| file_error(&path, "begin zone persist", &error))?;
        if created {
            writer
                .create_zone_with_meta(&apex, kind_flags(zone.kind), &meta)
                .map_err(|error| file_error(&path, "create zone", &error))?;
        } else {
            writer
                .set_zone_flags(&apex, kind_flags(zone.kind))
                .map_err(|error| file_error(&path, "update zone flags", &error))?;
            writer
                .update_zone_meta(&apex, &meta)
                .map_err(|error| file_error(&path, "update zone metadata", &error))?;
        }
        writer
            .commit(mode)
            .map_err(|error| file_error(&path, "zone commit", &error))?;
        Ok(())
    }

    /// Полностью перезаписывает зону (например, после DNSSEC-подписи).
    pub(crate) fn replace_zone(&mut self, zone: &ZoneSnapshot) -> Result<(), PersistenceError> {
        let apex = name_to_rle(&zone.origin)
            .map_err(|error| PersistenceError::new(format!("zone {}: {error}", zone.origin)))?;
        let mut meta = self
            .zonefile
            .zone_meta(&apex)
            .map_err(|error| self.file_error("read zone metadata", &error))?
            .unwrap_or_default();
        meta.default_ttl = zone.default_ttl.as_u32();
        meta.denial = denial_to_u8(zone.denial);
        let path = self.path.clone();
        let mode = self.commit_mode();
        let mut writer = self
            .zonefile
            .write()
            .map_err(|error| file_error(&path, "begin zone replace", &error))?;
        writer
            .delete_zone(&apex)
            .map_err(|error| file_error(&path, "replace: tombstone old zone", &error))?;
        writer
            .create_zone_with_meta(&apex, kind_flags(zone.kind), &meta)
            .map_err(|error| file_error(&path, "replace: create zone", &error))?;
        for rrset in &zone.rrsets {
            write_rrset(&mut writer, &apex, rrset)?;
        }
        let owners: HashSet<&Name> = zone.rrsets.iter().map(Rrset::owner).collect();
        for node in &zone.nodes {
            if owners.contains(node) {
                continue;
            }
            let node_rle = name_to_rle(node).map_err(|error| {
                PersistenceError::new(format!("zone {}: empty node {node}: {error}", zone.origin))
            })?;
            writer
                .ensure_empty_node(&apex, &node_rle)
                .map_err(|error| file_error(&path, "replace: write empty node", &error))?;
        }
        writer
            .commit(mode)
            .map_err(|error| file_error(&path, "zone replace commit", &error))?;
        Ok(())
    }

    /// Persist удаление зоны.
    pub(crate) fn delete_zone(&mut self, origin: &Name) -> Result<(), PersistenceError> {
        let apex = name_to_rle(origin)
            .map_err(|error| PersistenceError::new(format!("zone {origin}: {error}")))?;
        let path = self.path.clone();
        let mode = self.commit_mode();
        let mut writer = self
            .zonefile
            .write()
            .map_err(|error| file_error(&path, "begin zone delete", &error))?;
        writer
            .delete_zone(&apex)
            .map_err(|error| file_error(&path, "delete zone", &error))?;
        writer
            .commit(mode)
            .map_err(|error| file_error(&path, "zone delete commit", &error))?;
        Ok(())
    }

    /// Persist полную замену RRset.
    pub(crate) fn put_rrset(
        &mut self,
        view: &pulse_api::RrsetView,
    ) -> Result<(), PersistenceError> {
        let rrset = Rrset::new(
            view.owner.clone(),
            view.rr_type,
            Rclass::IN,
            view.ttl,
            view.rdata.iter().cloned(),
        )
        .map_err(|error| {
            PersistenceError::new(format!(
                "zone {}: cannot persist RRset {} {}: {error}",
                view.zone, view.owner, view.rr_type
            ))
        })?;
        let apex = name_to_rle(&view.zone)
            .map_err(|error| PersistenceError::new(format!("zone {}: {error}", view.zone)))?;
        let owner_rle = name_to_rle(&view.owner)?;
        let old_subtypes = self.rrsig_subtypes(&apex, &view.owner, view.rr_type)?;
        let new_subtypes = rrset_subtypes(&rrset);
        let path = self.path.clone();
        let mode = self.commit_mode();
        let mut writer = self
            .zonefile
            .write()
            .map_err(|error| file_error(&path, "begin RRset put", &error))?;
        write_rrset(&mut writer, &apex, &rrset)?;
        if view.rr_type == Rtype::RRSIG {
            for subtype in old_subtypes {
                if !new_subtypes.contains(&subtype) {
                    writer
                        .delete_rrset(&apex, &owner_rle, 46, subtype)
                        .map_err(|error| file_error(&path, "delete stale RRSIG subtype", &error))?;
                }
            }
        }
        writer
            .commit(mode)
            .map_err(|error| file_error(&path, "RRset put commit", &error))?;
        Ok(())
    }

    /// Persist удаление RRset (всех RRSIG-подтипов).
    pub(crate) fn delete_rrset(
        &mut self,
        origin: &Name,
        owner: &Name,
        rr_type: Rtype,
        keep_empty_node: bool,
    ) -> Result<(), PersistenceError> {
        let apex = name_to_rle(origin)
            .map_err(|error| PersistenceError::new(format!("zone {origin}: {error}")))?;
        let owner_rle = name_to_rle(owner).map_err(|error| {
            PersistenceError::new(format!("zone {origin}, owner {owner}: {error}"))
        })?;
        let subtypes = if rr_type == Rtype::RRSIG {
            self.rrsig_subtypes(&apex, owner, rr_type)?
        } else {
            vec![0]
        };
        let path = self.path.clone();
        let mode = self.commit_mode();
        let mut writer = self
            .zonefile
            .write()
            .map_err(|error| file_error(&path, "begin RRset delete", &error))?;
        for subtype in subtypes {
            writer
                .delete_rrset(&apex, &owner_rle, rr_type.as_u16(), subtype)
                .map_err(|error| file_error(&path, "delete RRset", &error))?;
        }
        if keep_empty_node {
            writer
                .ensure_empty_node(&apex, &owner_rle)
                .map_err(|error| file_error(&path, "preserve empty node", &error))?;
        }
        writer
            .commit(mode)
            .map_err(|error| file_error(&path, "RRset delete commit", &error))?;
        Ok(())
    }

    /// Persist изменение настроек зоны.
    pub(crate) fn patch_settings(
        &mut self,
        view: &pulse_api::ZoneSettingsView,
    ) -> Result<(), PersistenceError> {
        let apex = name_to_rle(&view.zone)
            .map_err(|error| PersistenceError::new(format!("zone {}: {error}", view.zone)))?;
        let mut meta = self
            .zonefile
            .zone_meta(&apex)
            .map_err(|error| self.file_error("read zone metadata", &error))?
            .unwrap_or_default();
        meta.default_ttl = view.settings.default_ttl.as_u32();
        meta.denial = denial_to_u8(view.settings.denial);
        let path = self.path.clone();
        let mode = self.commit_mode();
        let mut writer = self
            .zonefile
            .write()
            .map_err(|error| file_error(&path, "begin settings persist", &error))?;
        writer
            .update_zone_meta(&apex, &meta)
            .map_err(|error| file_error(&path, "update zone metadata", &error))?;
        writer
            .commit(mode)
            .map_err(|error| file_error(&path, "settings commit", &error))?;
        Ok(())
    }

    /// Явный `sync()` при graceful shutdown.
    pub(crate) fn sync(&mut self) -> Result<(), PersistenceError> {
        self.zonefile
            .sync()
            .map(|_| ())
            .map_err(|error| self.file_error("sync", &error))
    }

    fn rrsig_subtypes(
        &self,
        apex: &NameRle,
        owner: &Name,
        rr_type: Rtype,
    ) -> Result<Vec<u16>, PersistenceError> {
        if rr_type != Rtype::RRSIG {
            return Ok(Vec::new());
        }
        let owner_rle = name_to_rle(owner)?;
        let mut subtypes = HashSet::new();
        let items = self
            .zonefile
            .zone_items(apex)
            .map_err(|error| self.file_error("read RRSIG subtypes", &error))?;
        for item in items {
            let item = item.map_err(|error| self.file_error("read RRSIG subtype", &error))?;
            if item.name == owner_rle && item.rr_type == Rtype::RRSIG.as_u16() {
                subtypes.insert(item.subtype);
            }
        }
        let mut out: Vec<u16> = subtypes.into_iter().collect();
        out.sort_unstable();
        Ok(out)
    }

    fn commit_mode(&self) -> SyncMode {
        let effective = self.zonefile.effective_mode();
        if self.requested.durability_rank() < effective.durability_rank() {
            effective
        } else {
            self.requested
        }
    }

    fn file_error(&self, action: &str, error: &ZoneFileError) -> PersistenceError {
        file_error(&self.path, action, error)
    }
}

/// Импорт прочитанных зон в общий store.
pub(crate) fn load_into_store(
    store: &InMemoryZoneAdmin,
    zones: Vec<PersistedZone>,
) -> Result<(), String> {
    for zone in zones {
        let meta = ZoneMetaInput {
            kind: zone.kind,
            default_ttl: zone.default_ttl,
            denial: zone.denial,
        };
        store
            .import_zone_with_nodes(&zone.origin, &meta, zone.rrsets, zone.nodes)
            .map_err(|error| format!("cannot import persisted zone {}: {error}", zone.origin))?;
    }
    Ok(())
}

fn write_rrset(
    writer: &mut ZoneWriter<'_>,
    apex: &NameRle,
    rrset: &Rrset,
) -> Result<(), PersistenceError> {
    let owner = name_to_rle(rrset.owner())?;
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
            PersistenceError::new(format!(
                "cannot encode RRset {} {}: {error}",
                rrset.owner(),
                rrset.rr_type()
            ))
        })?;
        writer
            .upsert_rrset(apex, &owner, rrset.rr_type().as_u16(), subtype, &data)
            .map_err(|error| {
                PersistenceError::new(format!(
                    "cannot write RRset {} {}: {error}",
                    rrset.owner(),
                    rrset.rr_type()
                ))
            })?;
    }
    Ok(())
}

fn rrset_subtypes(rrset: &Rrset) -> HashSet<u16> {
    let mut subtypes = HashSet::new();
    if rrset.rr_type() == Rtype::RRSIG {
        for rdata in rrset.rdatas() {
            if let Rdata::Rrsig(signature) = rdata {
                subtypes.insert(signature.type_covered().as_u16());
            }
        }
    } else {
        subtypes.insert(0);
    }
    subtypes
}

fn kind_flags(kind: ZoneKind) -> u16 {
    match kind {
        ZoneKind::Primary => 0,
        ZoneKind::Secondary => pulse_zonefile::zone_meta::ZONE_FLAG_SECONDARY,
        ZoneKind::Forward => pulse_zonefile::zone_meta::ZONE_FLAG_FORWARD,
    }
}

fn kind_from_flags(flags: u16) -> ZoneKind {
    if flags & pulse_zonefile::zone_meta::ZONE_FLAG_FORWARD != 0 {
        ZoneKind::Forward
    } else if flags & pulse_zonefile::zone_meta::ZONE_FLAG_SECONDARY != 0 {
        ZoneKind::Secondary
    } else {
        ZoneKind::Primary
    }
}

fn denial_to_u8(denial: Denial) -> u8 {
    match denial {
        Denial::Nsec => 0,
        Denial::Nsec3 => 1,
    }
}

fn denial_from_u8(value: u8) -> Option<Denial> {
    match value {
        0 => Some(Denial::Nsec),
        1 => Some(Denial::Nsec3),
        _ => None,
    }
}

fn name_to_rle(name: &Name) -> Result<NameRle, PersistenceError> {
    NameRle::from_wire(name.as_wire())
        .map_err(|error| PersistenceError::new(format!("invalid DNS name {name}: {error}")))
}

fn name_from_rle(rle: &NameRle) -> Result<Name, PersistenceError> {
    let mut buffer = [0_u8; 255];
    let len = rle
        .write_wire(&mut buffer)
        .map_err(|error| PersistenceError::new(format!("cannot encode stored name: {error}")))?;
    Name::from_wire(&buffer[..len])
        .map_err(|error| PersistenceError::new(format!("invalid stored DNS name: {error}")))
}

fn file_error(path: &Path, action: &str, error: &ZoneFileError) -> PersistenceError {
    PersistenceError::new(format!("zone file {}: {action}: {error}", path.display()))
}
