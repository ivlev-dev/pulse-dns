//! Recovery и `fsck`-lite фазы A (§3.5, §9).
//!
//! Открытие выбирает валидные копии `superblock`/`LayoutHead`/`ALLOC_RECORD`,
//! восстанавливает `DP`/`DT`/`next_txn` и ring-головы, обнаруживает torn и
//! регрессии watermark. Любая file-fatal находка переводит стор в режим
//! `write_locked` (чтение продолжает работать) — fail-closed.

use std::fs::File;

use crate::parallel::consts::{
    LAYOUT_HEAD_RECORD_SIZE, PAGE_LAYOUT_HEAD_A, PAGE_LAYOUT_HEAD_B, PAGE_SIZE_V2, ROOT_ENTRY_SIZE,
    ROOT_VERSIONS, ZONES_PER_DIR_PAGE,
};
use crate::parallel::error::{CopySource, FatalKind, ParallelError, V2CorruptKind};
use crate::parallel::geometry::Geometry;
use crate::parallel::layout::{AllocRecord, LayoutHead, SuperblockV2, WriterRegistry};
use crate::parallel::ring::{Ring, record_matches_slot};
use crate::parallel::root::{RootEntry, RootFieldError};

/// Конфигурация открытия v2-стора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenConfigV2 {
    /// Только чтение/`fsck`: writer-блокировка не берётся, запись запрещена.
    pub read_only: bool,
    /// Брать `LOCK_EX` на lock-файл (M1: обязателен для writer'а).
    pub writer_lock: bool,
}

impl Default for OpenConfigV2 {
    fn default() -> Self {
        Self {
            read_only: false,
            writer_lock: true,
        }
    }
}

/// Итог recovery.
#[derive(Debug, Clone)]
pub struct RecoveryReport {
    /// Выбранная копия superblock.
    pub superblock_source: CopySource,
    /// Одна из копий superblock была torn.
    pub torn_superblock: bool,
    /// Выбранная копия `LayoutHead`.
    pub layout_source: CopySource,
    /// Одна из копий `LayoutHead` была torn.
    pub torn_layout: bool,
    /// Выбранная копия `ALLOC_RECORD`.
    pub alloc_source: CopySource,
    /// Одна из копий `ALLOC_RECORD` была torn.
    pub torn_alloc: bool,
    /// Восстановленный `DP`.
    pub durable_page_limit: u64,
    /// Восстановленный `DT`.
    pub durable_txn_limit: u64,
    /// Следующий `txn` после recovery.
    pub next_txn: u64,
    /// Максимальный `page_limit_at_commit` среди ring-записей.
    pub max_root_page_limit: u64,
    /// Максимальный `version` среди ring-записей.
    pub max_root_version: u64,
    /// Число зон с валидной головой.
    pub zones_with_roots: u32,
    /// Число torn-копий ring.
    pub torn_root_copies: u64,
    /// Число разошедшихся копий A/B (нормальное окно краха).
    pub diverged_root_copies: u64,
    /// Число зон с zone-fatal проблемами.
    pub zone_issues: u32,
    /// Причина `write_locked`, если найдена.
    pub fatal: Option<FatalKind>,
}

/// Итог `fsck`-lite.
#[derive(Debug, Clone)]
pub struct FsckLiteReport {
    /// Файл консистентен (нет file-fatal/zone-проблем).
    pub ok: bool,
    /// Причина `write_locked`.
    pub fatal: Option<FatalKind>,
    /// Durable `page_limit`.
    pub durable_page_limit: u64,
    /// Durable `txn_limit`.
    pub durable_txn_limit: u64,
    /// Максимальный `page_limit_at_commit` ring.
    pub max_root_page_limit: u64,
    /// Максимальный `version` ring.
    pub max_root_version: u64,
    /// Число зон с головой.
    pub zones: u32,
    /// Число валидных записей корней.
    pub root_records: u32,
    /// Одна из копий `LayoutHead` torn (восстановимо, не ошибка).
    pub torn_layout_copy: bool,
    /// Одна из копий `ALLOC_RECORD` torn (восстановимо, не ошибка).
    pub torn_alloc_copy: bool,
    /// Torn-копии ring.
    pub torn_root_copies: u64,
    /// Разошедшиеся копии A/B.
    pub diverged_root_copies: u64,
    /// Прочитанные chain-страницы.
    pub chain_pages: u32,
    /// Torn/оборванные chain-страницы (ожидаемый хвост).
    pub chain_torn: u32,
    /// Максимальная глубина chain.
    pub chain_max_depth: u32,
    /// `cursor − DP`: «выделено, но не опубликовано».
    pub leaked_pages_estimate: u64,
    /// Диагностические сообщения (зона/поле).
    pub issues: Vec<String>,
}

/// Внутренний результат recovery.
pub(crate) struct Recovered {
    pub(crate) geometry: Geometry,
    pub(crate) superblock: SuperblockV2,
    pub(crate) layout: LayoutHead,
    pub(crate) heads: Vec<Option<RootEntry>>,
    pub(crate) durable_page_limit: u64,
    pub(crate) durable_txn_limit: u64,
    pub(crate) alloc_seq: u64,
    pub(crate) next_txn: u64,
    pub(crate) report: RecoveryReport,
    pub(crate) zone_issues: Vec<(u32, &'static str)>,
}

pub(crate) struct RootScan {
    pub(crate) heads: Vec<Option<RootEntry>>,
    pub(crate) max_page_limit: u64,
    pub(crate) max_version: u64,
    pub(crate) torn_copies: u64,
    pub(crate) diverged_copies: u64,
    pub(crate) zones_with_roots: u32,
    pub(crate) root_records: u32,
    pub(crate) issues: Vec<(u32, &'static str)>,
    pub(crate) fatal: Option<FatalKind>,
}

/// Выполняет recovery файла v2.
///
/// # Errors
///
/// `Corrupt` — нет валидной копии superblock/`LayoutHead`; `Io` — ошибка чтения;
/// `Unsupported` — версия/размер страницы.
pub(crate) fn recover(file: &File, file_size: u64) -> Result<Recovered, ParallelError> {
    let (superblock, superblock_source, torn_superblock) = read_superblock(file, file_size)?;
    let geometry = Geometry::new(
        superblock.max_zones,
        superblock.page_count_max,
        superblock.max_root_chain_pages,
        superblock.reader_slots,
    )?;
    let (layout, layout_source, torn_layout) = read_layout(file, geometry)?;
    if layout.geometry != geometry {
        return Err(ParallelError::Corrupt {
            kind: V2CorruptKind::LayoutHead,
            page: Some(PAGE_LAYOUT_HEAD_A),
        });
    }
    let mut fatal = read_writer_registry(file, geometry)?;
    let (alloc, alloc_source, torn_alloc) = read_alloc_records(file, geometry, &mut fatal)?;

    let ring = Ring::new(file, &geometry);
    let scan = scan_roots(&ring, &geometry)?;
    merge_fatal(&mut fatal, scan.fatal);

    let mut max_root_page_limit = scan.max_page_limit;
    let mut max_root_version = scan.max_version;
    let alloc_page_limit = alloc.map(|record| record.page_limit);
    let alloc_txn_limit = alloc.map(|record| record.txn_limit);
    let durable_page_limit = alloc_page_limit.unwrap_or(0);
    let durable_txn_limit = alloc_txn_limit.unwrap_or(0);

    if durable_page_limit < max_root_page_limit {
        merge_fatal(&mut fatal, Some(FatalKind::AllocWatermarkRegression));
    }
    if alloc.is_some() && durable_page_limit < u64::from(geometry.page_data_first()) {
        merge_fatal(&mut fatal, Some(FatalKind::AllocWatermarkRegression));
    }
    if durable_txn_limit < max_root_version {
        merge_fatal(&mut fatal, Some(FatalKind::RootWatermarkRegression));
    }

    let dp = durable_page_limit
        .max(max_root_page_limit)
        .max(u64::from(geometry.page_data_first()));
    if dp > u64::from(geometry.page_count_max()) {
        merge_fatal(&mut fatal, Some(FatalKind::AllocWatermarkRegression));
    }
    let dt = durable_txn_limit.max(max_root_version).max(1);
    let next_txn = dt
        .checked_add(1)
        .ok_or(ParallelError::InvalidArgument { field: "txn" })?;
    max_root_page_limit = max_root_page_limit.min(dp);
    max_root_version = max_root_version.min(dt);

    let report = RecoveryReport {
        superblock_source,
        torn_superblock,
        layout_source,
        torn_layout,
        alloc_source,
        torn_alloc,
        durable_page_limit: dp,
        durable_txn_limit: dt,
        next_txn,
        max_root_page_limit,
        max_root_version,
        zones_with_roots: scan.zones_with_roots,
        torn_root_copies: scan.torn_copies,
        diverged_root_copies: scan.diverged_copies,
        zone_issues: u32::try_from(scan.issues.len()).unwrap_or(u32::MAX),
        fatal,
    };
    Ok(Recovered {
        geometry,
        superblock,
        layout,
        heads: scan.heads,
        durable_page_limit: dp,
        durable_txn_limit: dt,
        alloc_seq: alloc.map_or(0, |record| record.seq),
        next_txn,
        report,
        zone_issues: scan.issues,
    })
}

fn read_superblock(
    file: &File,
    file_size: u64,
) -> Result<(SuperblockV2, CopySource, bool), ParallelError> {
    let a_raw = read_at(file, 0, PAGE_SIZE_V2 as usize)?;
    let b_raw = read_at(file, u64::from(PAGE_SIZE_V2), PAGE_SIZE_V2 as usize)?;
    let a = SuperblockV2::decode(&a_raw);
    let b = SuperblockV2::decode(&b_raw);
    let (chosen, source, torn) = match (a, b) {
        (Some(left), Some(right)) => {
            if left.page_count_max != right.page_count_max
                || left.page_size != right.page_size
                || left.instance_uuid != right.instance_uuid
                || left.max_zones != right.max_zones
                || left.page_data_first != right.page_data_first
                || left.version_major != right.version_major
                || left.version_minor != right.version_minor
            {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::Superblock,
                    page: None,
                });
            }
            let chosen = if left.copy == 0 { left } else { right };
            (chosen, CopySource::Both, false)
        }
        (Some(left), None) => (left, CopySource::A, true),
        (None, Some(right)) => (right, CopySource::B, true),
        (None, None) => {
            return Err(ParallelError::Corrupt {
                kind: V2CorruptKind::Superblock,
                page: Some(0),
            });
        }
    };
    let geometry = Geometry::new(
        chosen.max_zones,
        chosen.page_count_max,
        chosen.max_root_chain_pages,
        chosen.reader_slots,
    )?;
    chosen.verify(&geometry, file_size)?;
    Ok((chosen, source, torn))
}

fn read_layout(
    file: &File,
    geometry: Geometry,
) -> Result<(LayoutHead, CopySource, bool), ParallelError> {
    let a_raw = read_at(
        file,
        u64::from(PAGE_LAYOUT_HEAD_A) * u64::from(PAGE_SIZE_V2),
        LAYOUT_HEAD_RECORD_SIZE as usize,
    )?;
    let b_raw = read_at(
        file,
        u64::from(PAGE_LAYOUT_HEAD_B) * u64::from(PAGE_SIZE_V2),
        LAYOUT_HEAD_RECORD_SIZE as usize,
    )?;
    let a = LayoutHead::decode(&a_raw);
    let b = LayoutHead::decode(&b_raw);
    match (a, b) {
        (Some(left), Some(right)) => {
            if !left.same_geometry(&right) {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::LayoutHead,
                    page: Some(PAGE_LAYOUT_HEAD_B),
                });
            }
            if left.geometry != geometry {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::LayoutHead,
                    page: Some(PAGE_LAYOUT_HEAD_A),
                });
            }
            let (chosen, source) = if left.layout_seq >= right.layout_seq {
                (left, CopySource::Both)
            } else {
                (right, CopySource::Both)
            };
            Ok((chosen, source, false))
        }
        (Some(left), None) => {
            if left.geometry != geometry {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::LayoutHead,
                    page: Some(PAGE_LAYOUT_HEAD_A),
                });
            }
            Ok((left, CopySource::A, true))
        }
        (None, Some(right)) => {
            if right.geometry != geometry {
                return Err(ParallelError::Corrupt {
                    kind: V2CorruptKind::LayoutHead,
                    page: Some(PAGE_LAYOUT_HEAD_B),
                });
            }
            Ok((right, CopySource::B, true))
        }
        (None, None) => Err(ParallelError::Corrupt {
            kind: V2CorruptKind::LayoutHead,
            page: Some(PAGE_LAYOUT_HEAD_A),
        }),
    }
}

fn read_writer_registry(
    file: &File,
    geometry: Geometry,
) -> Result<Option<FatalKind>, ParallelError> {
    let raw = read_at(
        file,
        u64::from(geometry.page_writer_reg()) * u64::from(PAGE_SIZE_V2),
        PAGE_SIZE_V2 as usize,
    )?;
    let Some(registry) = WriterRegistry::decode(&raw) else {
        return Ok(Some(FatalKind::ForeignLeader));
    };
    if registry.leader_term != crate::parallel::consts::LEADER_TERM_M1 || registry.writer_count != 0
    {
        return Ok(Some(FatalKind::ForeignLeader));
    }
    Ok(None)
}

fn read_alloc_records(
    file: &File,
    geometry: Geometry,
    fatal: &mut Option<FatalKind>,
) -> Result<(Option<AllocRecord>, CopySource, bool), ParallelError> {
    let a_raw = read_at(
        file,
        u64::from(geometry.page_alloc_record_a()) * u64::from(PAGE_SIZE_V2),
        crate::parallel::consts::ALLOC_RECORD_SIZE as usize,
    )?;
    let b_raw = read_at(
        file,
        u64::from(geometry.page_alloc_record_b()) * u64::from(PAGE_SIZE_V2),
        crate::parallel::consts::ALLOC_RECORD_SIZE as usize,
    )?;
    let a = AllocRecord::decode(&a_raw, geometry.page_count_max());
    let b = AllocRecord::decode(&b_raw, geometry.page_count_max());
    match (a, b) {
        (Some(left), Some(right)) => {
            if left.seq == right.seq
                && (left.page_limit != right.page_limit || left.txn_limit != right.txn_limit)
            {
                merge_fatal(fatal, Some(FatalKind::AllocRecord));
                return Ok((Some(left), CopySource::A, false));
            }
            let (chosen, source) = if left.seq >= right.seq {
                (left, CopySource::A)
            } else {
                (right, CopySource::B)
            };
            let other = if chosen.page_no == left.page_no {
                right
            } else {
                left
            };
            if chosen.page_limit < other.page_limit || chosen.txn_limit < other.txn_limit {
                merge_fatal(fatal, Some(FatalKind::AllocWatermarkRegression));
            }
            let both_same = chosen.seq == other.seq
                && chosen.page_limit == other.page_limit
                && chosen.txn_limit == other.txn_limit;
            let source = if both_same { CopySource::Both } else { source };
            Ok((Some(chosen), source, false))
        }
        (Some(left), None) => Ok((Some(left), CopySource::A, true)),
        (None, Some(right)) => Ok((Some(right), CopySource::B, true)),
        (None, None) => {
            merge_fatal(fatal, Some(FatalKind::AllocRecord));
            Ok((None, CopySource::None, true))
        }
    }
}

/// Сканирует root directory и выбирает max-valid голову каждой зоны.
pub(crate) fn scan_roots(ring: &Ring<'_>, geometry: &Geometry) -> Result<RootScan, ParallelError> {
    let max_zones = geometry.max_zones();
    let mut heads = vec![None; max_zones as usize];
    let mut max_page_limit = 0_u64;
    let mut max_version = 0_u64;
    let mut torn_copies = 0_u64;
    let mut diverged_copies = 0_u64;
    let mut zones_with_roots = 0_u32;
    let mut root_records = 0_u32;
    let mut issues = Vec::new();
    let mut fatal = None;

    for page_index in 0..geometry.root_dir_pages() {
        let page_a = ring.read_dir_page(geometry.page_root_dir_a_first() + page_index)?;
        let page_b = ring.read_dir_page(geometry.page_root_dir_b_first() + page_index)?;
        for index_in_page in 0..ZONES_PER_DIR_PAGE {
            let zone = page_index * ZONES_PER_DIR_PAGE + index_in_page;
            if zone == 0 || zone >= max_zones {
                continue;
            }
            let block = (index_in_page * crate::parallel::consts::ROOT_BLOCK_SIZE) as usize;
            let mut best: Option<RootEntry> = None;
            let mut zone_issue: Option<RootFieldError> = None;
            for group in 0..ROOT_VERSIONS as usize {
                let offset = block + group * ROOT_ENTRY_SIZE as usize;
                let a_raw = page_a.get(offset..offset + ROOT_ENTRY_SIZE as usize);
                let b_raw = page_b.get(offset..offset + ROOT_ENTRY_SIZE as usize);
                let a = a_raw.and_then(RootEntry::decode);
                let b = b_raw.and_then(RootEntry::decode);
                for record in [a, b].into_iter().flatten() {
                    root_records = root_records.saturating_add(1);
                    max_page_limit = max_page_limit.max(u64::from(record.page_limit_at_commit));
                    max_version = max_version.max(record.version);
                    if let Err(issue) = record.check_fields(geometry.page_count_max()) {
                        zone_issue.get_or_insert(issue);
                        continue;
                    }
                    if !record_matches_slot(&record, zone, group) {
                        if record.owner_zone == zone {
                            return Err(ParallelError::Corrupt {
                                kind: V2CorruptKind::RingSlotMismatch,
                                page: None,
                            });
                        }
                        merge_fatal(&mut fatal, Some(FatalKind::ForeignOwner));
                        continue;
                    }
                    if best.is_none_or(|current| record.version > current.version) {
                        best = Some(record);
                    }
                }
                match (a, b) {
                    (Some(left), Some(right)) => {
                        if left.version != right.version {
                            diverged_copies = diverged_copies.saturating_add(1);
                        }
                    }
                    (Some(_), None) | (None, Some(_)) => {
                        if raw_nonzero(a_raw.unwrap_or(&[])) && raw_nonzero(b_raw.unwrap_or(&[])) {
                            torn_copies = torn_copies.saturating_add(1);
                        }
                    }
                    (None, None) => {}
                }
            }
            if let Some(issue) = zone_issue {
                issues.push((zone, field_name(issue)));
            }
            if let Some(entry) = best {
                if let Some(slot) = heads.get_mut(zone as usize) {
                    *slot = Some(entry);
                }
                zones_with_roots = zones_with_roots.saturating_add(1);
            }
        }
    }
    Ok(RootScan {
        heads,
        max_page_limit,
        max_version,
        torn_copies,
        diverged_copies,
        zones_with_roots,
        root_records,
        issues,
        fatal,
    })
}

/// Имя нарушенного поля `RootEntry`.
fn field_name(error: RootFieldError) -> &'static str {
    match error {
        RootFieldError::Version => "version",
        RootFieldError::State => "state",
        RootFieldError::DeletedTxn => "deleted_txn",
        RootFieldError::Serial => "soa_serial",
        RootFieldError::Flags => "flags",
        RootFieldError::TreeLevel => "tree_level",
        RootFieldError::IxfrRoot => "ixfr_root",
        RootFieldError::PointerBeyondLimit => "pointer_beyond_limit",
        RootFieldError::PageLimit => "page_limit_at_commit",
    }
}

pub(crate) fn merge_fatal(target: &mut Option<FatalKind>, value: Option<FatalKind>) {
    if target.is_none() {
        *target = value;
    }
}

fn raw_nonzero(data: &[u8]) -> bool {
    data.iter().any(|byte| *byte != 0)
}

pub(crate) fn read_at(file: &File, offset: u64, len: usize) -> Result<Vec<u8>, ParallelError> {
    use std::os::unix::fs::FileExt;
    let mut buffer = vec![0_u8; len];
    file.read_exact_at(&mut buffer, offset)?;
    Ok(buffer)
}
