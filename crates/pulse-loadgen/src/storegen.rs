//! Генератор v2-zonefile: `zones × rrsets_per_zone` с apex SOA/NS/A и
//! записями A/AAAA/MX/TXT (тип циклится по индексу).
//!
//! Используется и для baseline-стенда, и для memory-сценариев. Файл
//! создаётся в режиме `Memory` (без `fdatasync` на каждый коммит) — для
//! измерения чтения это не влияет, а генерация 1M RRset остаётся быстрой.
//! Для тестов durability используйте `pulsed bench zone_writes`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Instant;

use pulse_dns::{Name, Rdata, SoaData, TxtData};
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, SyncModeV2, ZoneCreateMeta,
};

/// Параметры генерации.
#[derive(Debug, Clone)]
pub struct GenSpec {
    /// Путь к zonefile.
    pub path: PathBuf,
    /// Число зон.
    pub zones: u32,
    /// RRset на зону (не считая apex SOA/NS/A).
    pub rrsets_per_zone: u32,
    /// Лимит страниц (файл = `page_count_max × 4096`, sparse).
    pub page_count_max: u32,
    /// Durability при создании/коммитах.
    pub sync_mode: SyncModeV2,
    /// Продолжить существующий store (зона 0), начиная с текущего `rrset_count`.
    pub resume: bool,
}

impl Default for GenSpec {
    fn default() -> Self {
        Self {
            path: PathBuf::from("bench.v2"),
            zones: 1,
            rrsets_per_zone: 1_000,
            page_count_max: 1 << 18,
            sync_mode: SyncModeV2::Memory,
            resume: false,
        }
    }
}

impl GenSpec {
    /// Оценка `page_count_max` по числу RRset (sparse-файл, запас 4×).
    #[must_use]
    pub fn pages_for(zones: u32, rrsets_per_zone: u32) -> u32 {
        let total = u64::from(zones).saturating_mul(u64::from(rrsets_per_zone));
        // Текущий writer аллоцирует ~6 COW-страниц на RRset (страницы потом
        // уходят в free pool, но allocator cursor/`page_count_max` растёт).
        // Файл sparse, поэтому запас 7 страниц/RRset почти не стоит диска.
        let estimate = total.saturating_mul(7) + 65_536;
        u32::try_from(estimate.min(u64::from(1_u32 << 27))).unwrap_or(1 << 27)
    }
}

/// Сведения о существующем store.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoreInfo {
    /// Зон в каталоге.
    pub zones: u32,
    /// Сумма `rrset_count`.
    pub rrsets: u64,
    /// Размер файла (logical), байт.
    pub file_bytes: u64,
    /// Занято на диске, байт.
    pub disk_bytes: u64,
}

/// Читает каталог store без writer-lock.
///
/// # Errors
///
/// Ошибка открытия/чтения каталога.
pub fn info(path: &std::path::Path) -> Result<StoreInfo, String> {
    let store = pulse_zonefile::parallel::open_read_only(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let catalog = ParallelZones::open(&store).map_err(|error| format!("catalog: {error}"))?;
    let zones = catalog.zones();
    let rrsets: u64 = zones.iter().map(|zone| u64::from(zone.rrset_count)).sum();
    #[cfg(unix)]
    let disk_bytes = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).map_or(0, |meta| meta.blocks().saturating_mul(512))
    };
    #[cfg(not(unix))]
    let disk_bytes = 0;
    Ok(StoreInfo {
        zones: u32::try_from(zones.len()).unwrap_or(u32::MAX),
        rrsets,
        file_bytes: std::fs::metadata(path).map_or(0, |meta| meta.len()),
        disk_bytes,
    })
}

/// Итог генерации.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenReport {
    /// Путь.
    pub path: String,
    /// Зон.
    pub zones: u32,
    /// RRset (сумма по каталогу, включая apex).
    pub rrsets: u64,
    /// Размер файла, байт.
    pub file_bytes: u64,
    /// Время генерации, мс.
    pub elapsed_ms: u64,
    /// RRset на зону (запрошено).
    pub rrsets_per_zone: u32,
}

/// Генерирует зоны и возвращает отчёт.
///
/// # Errors
///
/// Ошибки создания store/зон/записи.
#[allow(clippy::too_many_lines)]
pub fn generate(spec: &GenSpec) -> Result<GenReport, String> {
    if spec.zones == 0 {
        return Err("zones must be > 0".to_owned());
    }
    if let Some(parent) = spec.path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("create dir: {error}"))?;
    }
    if spec.path.exists() {
        if !spec.resume {
            std::fs::remove_file(&spec.path)
                .map_err(|error| format!("remove old store: {error}"))?;
            let _ = std::fs::remove_file(format!("{}.lock", spec.path.display()));
            let _ = std::fs::remove_file(format!("{}.pulsecoord", spec.path.display()));
        }
    } else if spec.resume {
        return Err(format!("resume: {} does not exist", spec.path.display()));
    }
    let started = Instant::now();
    let store = if spec.resume {
        ParallelStore::open(
            &spec.path,
            pulse_zonefile::parallel::OpenConfigV2::default(),
        )
        .map_err(|error| format!("open store for resume: {error}"))?
    } else {
        ParallelStore::create(
            &spec.path,
            StoreConfig {
                page_count_max: spec.page_count_max,
                max_zones: spec.zones.saturating_add(16).max(32),
                max_root_chain_pages: 64,
                reader_slots: 8,
                page_cache_entries: 1024,
                sync_mode: spec.sync_mode,
                multi_process: false,
            },
        )
        .map_err(|error| format!("create store: {error}"))?
    };
    let mut catalog = ParallelZones::open(&store).map_err(|error| format!("catalog: {error}"))?;
    let resume_start = if spec.resume {
        let zones = catalog.zones();
        if zones.len() != 1 {
            return Err(format!(
                "resume: expected exactly 1 zone, found {}",
                zones.len()
            ));
        }
        zones[0].rrset_count.saturating_sub(3)
    } else {
        0
    };
    for zone in 0..spec.zones {
        let origin_text = origin(zone);
        let apex = NameRle::from_ascii(&origin_text).map_err(|error| format!("apex: {error}"))?;
        if !spec.resume {
            catalog
                .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
                .map_err(|error| format!("create zone {origin_text}: {error}"))?;
        }
        let mut writer = catalog
            .writer(&apex)
            .map_err(|error| format!("writer {origin_text}: {error}"))?;
        if !spec.resume {
            write_apex(&mut writer, &origin_text)?;
        }
        let start = if zone == 0 { resume_start } else { 0 };
        let batch = 8_192_u32;
        let mut inserted = 0_u32;
        for index in start..spec.rrsets_per_zone {
            let record = record_name(index, zone);
            let name =
                NameRle::from_ascii(&record).map_err(|error| format!("record name: {error}"))?;
            let (rr_type, data) = record_rdata(index, &origin_text);
            writer
                .upsert_rrset(&name, rr_type, 0, &data)
                .map_err(|error| format!("upsert {record}: {error}"))?;
            inserted = inserted.saturating_add(1);
            if (index + 1) % batch == 0 {
                writer
                    .commit_with(spec.sync_mode)
                    .map_err(|error| format!("commit {origin_text} at {index}: {error}"))?;
            }
        }
        if inserted > 0 {
            writer
                .commit_with(spec.sync_mode)
                .map_err(|error| format!("commit {origin_text}: {error}"))?;
        }
    }
    let zones_info = catalog.zones();
    let rrsets: u64 = zones_info
        .iter()
        .map(|zone| u64::from(zone.rrset_count))
        .sum();
    drop(catalog);
    let file_bytes = std::fs::metadata(&spec.path).map_or(0, |meta| meta.len());
    drop(store);
    Ok(GenReport {
        path: spec.path.display().to_string(),
        zones: u32::try_from(zones_info.len()).unwrap_or(spec.zones),
        rrsets,
        file_bytes,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        rrsets_per_zone: spec.rrsets_per_zone,
    })
}

fn write_apex(
    writer: &mut pulse_zonefile::parallel::ParallelZone<'_>,
    origin_text: &str,
) -> Result<(), String> {
    let apex = NameRle::from_ascii(origin_text).map_err(|error| format!("apex: {error}"))?;
    let soa = Rdata::Soa(SoaData::new(
        Name::parse(&format!("ns1.{origin_text}"))
            .map_err(|error| format!("soa mname: {error}"))?,
        Name::parse(&format!("hostmaster.{origin_text}"))
            .map_err(|error| format!("soa rname: {error}"))?,
        pulse_dns::Serial::new(1),
        3_600,
        600,
        604_800,
        60,
    ));
    let soa_data = RrsetData::from_slices(60, 0, &[&soa.to_canonical_wire()])
        .map_err(|error| format!("soa rrset: {error}"))?;
    writer
        .upsert_rrset(&apex, pulse_dns::Rtype::SOA.as_u16(), 0, &soa_data)
        .map_err(|error| format!("upsert soa: {error}"))?;
    let ns = Rdata::Ns(
        Name::parse(&format!("ns1.{origin_text}")).map_err(|error| format!("ns: {error}"))?,
    );
    let ns_data = RrsetData::from_slices(60, 0, &[&ns.to_canonical_wire()])
        .map_err(|error| format!("ns rrset: {error}"))?;
    writer
        .upsert_rrset(&apex, pulse_dns::Rtype::NS.as_u16(), 0, &ns_data)
        .map_err(|error| format!("upsert ns: {error}"))?;
    let ns_name = NameRle::from_ascii(&format!("ns1.{origin_text}"))
        .map_err(|error| format!("ns name: {error}"))?;
    let glue = RrsetData::from_slices(60, 0, &[&[127, 0, 0, 1]])
        .map_err(|error| format!("glue: {error}"))?;
    writer
        .upsert_rrset(&ns_name, pulse_dns::Rtype::A.as_u16(), 0, &glue)
        .map_err(|error| format!("upsert glue: {error}"))?;
    Ok(())
}

fn record_rdata(index: u32, origin_text: &str) -> (u16, RrsetData) {
    let octets = index.to_be_bytes();
    match index % 4 {
        0 => (
            pulse_dns::Rtype::A.as_u16(),
            RrsetData::from_slices(60, 0, &[&[10, octets[2], octets[3], 1]]).expect("A rrset"),
        ),
        1 => {
            let address = Ipv6Addr::new(
                0x2001,
                0x0db8,
                0,
                0,
                0,
                0,
                u16::from_be_bytes([octets[2], octets[3]]),
                1,
            );
            (
                pulse_dns::Rtype::AAAA.as_u16(),
                RrsetData::from_slices(60, 0, &[&address.octets()]).expect("AAAA rrset"),
            )
        }
        2 => {
            let exchange =
                Name::parse(&format!("mail.{origin_text}")).expect("exchange name parses");
            let mut wire = Vec::with_capacity(2 + exchange.as_wire().len());
            wire.extend_from_slice(&10_u16.to_be_bytes());
            wire.extend_from_slice(exchange.as_wire());
            (
                pulse_dns::Rtype::MX.as_u16(),
                RrsetData::from_slices(60, 0, &[&wire]).expect("MX rrset"),
            )
        }
        _ => {
            let text =
                TxtData::new(vec![b"pulse-dns benchmark txt record".to_vec()]).expect("TXT data");
            let wire = Rdata::Txt(text).to_canonical_wire();
            (
                pulse_dns::Rtype::TXT.as_u16(),
                RrsetData::from_slices(60, 0, &[&wire]).expect("TXT rrset"),
            )
        }
    }
}

/// Origin зоны.
#[must_use]
pub fn origin(zone: u32) -> String {
    format!("z{zone}.bench.test.")
}

/// Имя RRset.
#[must_use]
pub fn record_name(index: u32, zone: u32) -> String {
    format!("r{index}.z{zone}.bench.test.")
}

/// Apex A (для запросов к origin, при необходимости).
#[must_use]
pub fn apex_a() -> Ipv4Addr {
    Ipv4Addr::LOCALHOST
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pages_are_bounded() {
        assert_eq!(GenSpec::pages_for(1, 1_000), 72_536);
        assert!(GenSpec::pages_for(1, 1_000_000) <= 1 << 27);
        assert!(GenSpec::pages_for(1_000, 1_000) >= 16_384);
    }

    #[test]
    fn record_types_cycle() {
        for index in 0..8 {
            let (rr_type, data) = record_rdata(index, "z0.bench.test.");
            assert!(data.rr_count().is_ok());
            assert!(matches!(rr_type, 1 | 15 | 16 | 28));
        }
    }

    #[test]
    fn generate_small_store() {
        let dir = std::env::temp_dir().join(format!(
            "pulse-loadgen-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |value| value.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let spec = GenSpec {
            path: dir.join("small.v2"),
            zones: 2,
            rrsets_per_zone: 16,
            page_count_max: 16_384,
            sync_mode: SyncModeV2::Memory,
            resume: false,
        };
        let report = generate(&spec).expect("generate");
        assert_eq!(report.zones, 2);
        assert!(report.rrsets >= 32);
        let _ = std::fs::remove_dir_all(dir);
    }
}
