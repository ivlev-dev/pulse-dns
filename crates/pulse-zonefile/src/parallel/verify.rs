//! Структурный `fsck` v2: достижимость, пулы и утечки (фаза B2a).
//!
//! Проверяет инварианты рекламации поверх durable-голов:
//!
//! * дерево каждой зоны (leaf/branch/overflow) не пересекается с другими
//!   зонами, bucket-страницами и свободными страницами;
//! * bucket-цепочка валидна (`FreeChain::load`), свободные страницы не
//!   дублируются и не пересекаются с деревом;
//! * страница chain может одновременно быть в пуле — это освобождённый хвост
//!   истории (§4.4), не ошибка;
//! * `DP = reachable ∪ pools ∪ leaked` — утечки считаются, но не являются
//!   ошибкой (крах/`NEVER_PUBLISHED` допустимы, §3.3).
//!
//! `fsck_lite` намеренно не обходит деревья (фаза A разрешает произвольный
//! `root_page` в тестах); структурная проверка — [`crate::parallel::ParallelStore::fsck_graph`].

use std::collections::HashSet;

use crate::consts::{MAX_OVERFLOW_PAGES, PAGE_TYPE_OVERFLOW};
use crate::node::{DecodedBranch, DecodedLeaf, DecodedValue, ValueKind};
use crate::page::PageHeader;
use crate::parallel::consts::MAX_ROOT_CHAIN_HOPS;
use crate::parallel::error::{FatalKind, ParallelError, V2CorruptKind};
use crate::parallel::layout::ChainPage;
use crate::parallel::pageio::ReaderIo;
use crate::parallel::root::RootEntry;
use crate::parallel::store::ParallelStore;
use crate::tree::PageIo;
use crate::wire;

/// Итог структурного `fsck`.
#[derive(Debug, Clone, Default)]
pub struct GraphReport {
    /// Нет ошибок/пересечений.
    pub ok: bool,
    /// Достижимые страницы деревьев.
    pub reachable_pages: u64,
    /// Достижимые chain-страницы.
    pub chain_pages: u64,
    /// Bucket-страницы.
    pub bucket_pages: u64,
    /// Свободные страницы в пулах.
    pub free_pages: u64,
    /// Страницы `[data_first, DP)`, не попавшие ни в один набор.
    pub leaked_pages: u64,
    /// Диагностические сообщения.
    pub issues: Vec<String>,
    /// File-fatal причина (пересечение множеств).
    pub fatal: Option<FatalKind>,
}

#[derive(Default)]
struct Sets {
    tree: HashSet<u32>,
    chain: HashSet<u32>,
    buckets: HashSet<u32>,
    free: HashSet<u32>,
}

impl Sets {
    fn overlap(&mut self, page: u32, set: Kind, report: &mut GraphReport) -> bool {
        let duplicate = match set {
            Kind::Tree => !self.tree.insert(page),
            Kind::Chain => !self.chain.insert(page),
            Kind::Bucket => !self.buckets.insert(page),
            Kind::Free => !self.free.insert(page),
        };
        if duplicate {
            report
                .issues
                .push(format!("page {page} дублируется в {set:?}"));
            report.fatal.get_or_insert(FatalKind::PageOverlap);
        }
        !duplicate
    }

    fn contains_tree(&self, page: u32) -> bool {
        self.tree.contains(&page)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tree,
    Chain,
    Bucket,
    Free,
}

pub(crate) fn verify(store: &ParallelStore) -> Result<GraphReport, ParallelError> {
    let mut report = GraphReport::default();
    let mut sets = Sets::default();
    let geometry = store.geometry();
    let max_zones = geometry.max_zones();
    for zone in 0..max_zones {
        let Some(head) = store.head_entry(zone) else {
            continue;
        };
        if head.root_page != 0 {
            let io = ReaderIo::new(store, zone, head.version);
            walk_tree(
                &io,
                head.root_page,
                head.tree_level,
                head.version,
                zone,
                &mut sets,
                &mut report,
            )?;
        }
        walk_chain(store, zone, head, &mut sets, &mut report)?;
        let chain = store.load_free_chain(zone, &head)?;
        for bucket in chain.buckets() {
            if sets.contains_tree(bucket.page) || sets.chain.contains(&bucket.page) {
                report
                    .issues
                    .push(format!("bucket page {} зоны {zone} достижима", bucket.page));
                report.fatal.get_or_insert(FatalKind::PageOverlap);
            }
            sets.overlap(bucket.page, Kind::Bucket, &mut report);
            for freed in &bucket.pages {
                if sets.contains_tree(*freed) {
                    report
                        .issues
                        .push(format!("free page {freed} зоны {zone} достижима из дерева"));
                    report.fatal.get_or_insert(FatalKind::PageOverlap);
                }
                if sets.buckets.contains(freed) {
                    report
                        .issues
                        .push(format!("free page {freed} зоны {zone} совпадает с bucket"));
                    report.fatal.get_or_insert(FatalKind::PageOverlap);
                }
                // Свободная chain-страница (освобождённый хвост) допустима.
                sets.overlap(*freed, Kind::Free, &mut report);
            }
        }
    }
    let durable = u32::try_from(store.durable_page_limit()).unwrap_or(u32::MAX);
    for page in geometry.page_data_first()..durable {
        if !sets.tree.contains(&page)
            && !sets.chain.contains(&page)
            && !sets.buckets.contains(&page)
            && !sets.free.contains(&page)
        {
            report.leaked_pages = report.leaked_pages.saturating_add(1);
        }
    }
    report.reachable_pages = u64::try_from(sets.tree.len()).unwrap_or(u64::MAX);
    report.chain_pages = u64::try_from(sets.chain.len()).unwrap_or(u64::MAX);
    report.bucket_pages = u64::try_from(sets.buckets.len()).unwrap_or(u64::MAX);
    report.free_pages = u64::try_from(sets.free.len()).unwrap_or(u64::MAX);
    report.ok = report.fatal.is_none() && report.issues.is_empty();
    Ok(report)
}

fn walk_tree(
    io: &ReaderIo<'_>,
    page_no: u32,
    level: u16,
    version: u64,
    zone: u32,
    sets: &mut Sets,
    report: &mut GraphReport,
) -> Result<(), ParallelError> {
    if level == 0 {
        report.issues.push(format!(
            "zone {zone}: root_page {page_no} при tree_level = 0"
        ));
        return Ok(());
    }
    if !sets.overlap(page_no, Kind::Tree, report) {
        return Ok(());
    }
    let raw = io
        .read_page(page_no)
        .map_err(|error| io.take_error().unwrap_or(ParallelError::Tree(error)))?;
    let page_size = io.page_size();
    if level <= 1 {
        let leaf =
            DecodedLeaf::decode(raw, page_no, version, page_size).map_err(ParallelError::Tree)?;
        for index in 0..leaf.len() {
            if let DecodedValue::Rrset { value, .. } =
                leaf.value(index).map_err(ParallelError::Tree)?
                && value.kind == ValueKind::Overflow
            {
                walk_overflow(io, value.val_u32, version, sets, report)?;
            }
        }
        return Ok(());
    }
    let branch =
        DecodedBranch::decode(raw, page_no, version, page_size).map_err(ParallelError::Tree)?;
    if branch.level() != level - 1 {
        report
            .issues
            .push(format!("zone {zone}: страница {page_no} уровень не совпал"));
        return Ok(());
    }
    for index in 0..branch.len() {
        let child = branch.child(index).map_err(ParallelError::Tree)?;
        walk_tree(io, child, level - 1, version, zone, sets, report)?;
    }
    Ok(())
}

fn walk_overflow(
    io: &ReaderIo<'_>,
    first: u32,
    version: u64,
    sets: &mut Sets,
    report: &mut GraphReport,
) -> Result<(), ParallelError> {
    let mut page_no = first;
    let mut hops = 0_u32;
    while page_no != 0 {
        hops = hops.saturating_add(1);
        if hops > MAX_OVERFLOW_PAGES {
            report
                .issues
                .push(format!("overflow chain page {first}: цикл"));
            return Ok(());
        }
        if !sets.overlap(page_no, Kind::Tree, report) {
            return Ok(());
        }
        let raw = io
            .read_page(page_no)
            .map_err(|error| io.take_error().unwrap_or(ParallelError::Tree(error)))?;
        let header = PageHeader::decode(raw, page_no, version, io.page_size())
            .map_err(ParallelError::Tree)?;
        if header.page_type != PAGE_TYPE_OVERFLOW {
            report
                .issues
                .push(format!("overflow page {page_no}: неверный тип"));
            return Ok(());
        }
        page_no = wire::read_u32(raw, 40).ok_or(ParallelError::Corrupt {
            kind: V2CorruptKind::Truncated,
            page: Some(page_no),
        })?;
    }
    Ok(())
}

fn walk_chain(
    store: &ParallelStore,
    zone: u32,
    head: RootEntry,
    sets: &mut Sets,
    report: &mut GraphReport,
) -> Result<(), ParallelError> {
    let mut page = head.prev_record;
    let mut upper = head.version;
    let mut hops = 0_u32;
    while page != 0 {
        hops = hops.saturating_add(1);
        if hops > MAX_ROOT_CHAIN_HOPS || page >= head.page_limit_at_commit {
            report
                .issues
                .push(format!("zone {zone}: chain hop limit at {page}"));
            return Ok(());
        }
        let raw = store.read_raw_page(page)?;
        let Some(chain) = ChainPage::decode(&raw, page) else {
            // Освобождённый/переиспользованный хвост — ожидаемо.
            return Ok(());
        };
        if chain.owner_zone != zone || chain.entry.version >= upper {
            return Ok(());
        }
        upper = chain.entry.version;
        sets.overlap(page, Kind::Chain, report);
        page = chain.entry.prev_record;
    }
    Ok(())
}
