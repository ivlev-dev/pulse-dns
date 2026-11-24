//! Структурный `fsck` v2: достижимость, пулы, утечки и карантин зон.
//!
//! Проверяет инварианты рекламации поверх durable-голов:
//!
//! * дерево каждой зоны (leaf/branch/overflow) не пересекается с другими
//!   зонами, bucket-страницами и свободными страницами;
//! * `page.txn ≤ version` и `owner_zone` каждой достижимой страницы;
//! * `root_page`/`meta_root`/`free_head`/`prev_record` лежат внутри
//!   `page_limit_at_commit`, а сам лимит — внутри `DP`;
//! * bucket-цепочка валидна (`FreeChain::load`), свободные страницы не
//!   дублируются и не пересекаются с деревом;
//! * страница chain может одновременно быть в пуле — это освобождённый хвост
//!   истории (§4.4), не ошибка;
//! * `DP = reachable ∪ pools ∪ leaked` — утечки считаются, но не являются
//!   ошибкой (крах/`NEVER_PUBLISHED` допустимы, §3.3).
//!
//! Множества страниц хранятся битсетом (`DP / 8` байт на набор): проверка
//! больших файлов не раздувает RSS и остаётся O(`DP`).
//!
//! Зоны, у которых дерево/chain/пул не читаются (zone-fatal), попадают в
//! [`GraphReport::damaged_zones`]; file-fatal признаки (`owner_zone` чужой
//! зоны, `page.txn > version`, пересечение множеств) по-прежнему возвращаются
//! ошибкой [`ParallelError`].

use crate::consts::{MAX_OVERFLOW_PAGES, PAGE_OFF_TXN, PAGE_TYPE_OVERFLOW};
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
    /// Нет ошибок/пересечений и все зоны читаемы.
    pub ok: bool,
    /// Достижимые страницы деревьев (включая overflow).
    pub reachable_pages: u64,
    /// Достижимые chain-страницы.
    pub chain_pages: u64,
    /// Bucket-страницы.
    pub bucket_pages: u64,
    /// Свободные страницы в пулах.
    pub free_pages: u64,
    /// Страницы `[data_first, DP)`, не попавшие ни в один набор.
    pub leaked_pages: u64,
    /// Номера утёкших страниц (для `fsck --repair`).
    pub leaked_page_ids: Vec<u32>,
    /// Ёмкость проверенной области `[data_first, DP)`.
    pub durable_pages: u64,
    /// Число голов, обойдённых `fsck`.
    pub zones_checked: u32,
    /// Максимальный `page.txn` среди достижимых страниц.
    pub max_page_txn: u64,
    /// Зоны с zone-fatal повреждением (карантин, данные не трогаются).
    pub damaged_zones: Vec<u32>,
    /// Диагностические сообщения.
    pub issues: Vec<String>,
    /// File-fatal причина (пересечение множеств/чужой владелец).
    pub fatal: Option<FatalKind>,
}

/// Результат вставки страницы в множество.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InsertResult {
    /// Страница добавлена впервые.
    Inserted,
    /// Страница уже была в этом множестве (цикл/двойная ссылка).
    Duplicate,
    /// Номер страницы вне `[data_first, DP)`.
    OutOfRange,
}

/// Битсет страниц `[0, capacity)`.
#[derive(Debug, Default)]
struct PageSet {
    words: Vec<u64>,
    len: u64,
    capacity: u32,
}

impl PageSet {
    fn new(capacity: u32) -> Self {
        let words = usize::try_from(capacity).unwrap_or(0).div_ceil(64);
        Self {
            words: vec![0; words],
            len: 0,
            capacity,
        }
    }

    fn insert(&mut self, page: u32) -> InsertResult {
        if page >= self.capacity {
            return InsertResult::OutOfRange;
        }
        let index = usize::try_from(page / 64).unwrap_or(usize::MAX);
        let bit = 1_u64 << (page % 64);
        let Some(word) = self.words.get_mut(index) else {
            return InsertResult::OutOfRange;
        };
        if *word & bit != 0 {
            InsertResult::Duplicate
        } else {
            *word |= bit;
            self.len = self.len.saturating_add(1);
            InsertResult::Inserted
        }
    }

    fn contains(&self, page: u32) -> bool {
        if page >= self.capacity {
            return false;
        }
        let index = usize::try_from(page / 64).unwrap_or(usize::MAX);
        let bit = 1_u64 << (page % 64);
        self.words.get(index).is_some_and(|word| *word & bit != 0)
    }

    fn len(&self) -> u64 {
        self.len
    }
}

#[derive(Debug)]
struct Sets {
    tree: PageSet,
    chain: PageSet,
    buckets: PageSet,
    free: PageSet,
    capacity: u32,
}

impl Sets {
    fn new(capacity: u32) -> Self {
        Self {
            tree: PageSet::new(capacity),
            chain: PageSet::new(capacity),
            buckets: PageSet::new(capacity),
            free: PageSet::new(capacity),
            capacity,
        }
    }

    fn set_mut(&mut self, kind: Kind) -> &mut PageSet {
        match kind {
            Kind::Tree => &mut self.tree,
            Kind::Chain => &mut self.chain,
            Kind::Bucket => &mut self.buckets,
            Kind::Free => &mut self.free,
        }
    }

    fn overlap(&mut self, page: u32, kind: Kind, report: &mut GraphReport) -> InsertResult {
        let result = self.set_mut(kind).insert(page);
        match result {
            InsertResult::Inserted => {}
            InsertResult::Duplicate => {
                report
                    .issues
                    .push(format!("page {page} дублируется в {kind:?}"));
                report.fatal.get_or_insert(FatalKind::PageOverlap);
            }
            InsertResult::OutOfRange => {
                report
                    .issues
                    .push(format!("page {page} вне [{}, {})", 0, self.capacity));
            }
        }
        result
    }

    fn contains_tree(&self, page: u32) -> bool {
        self.tree.contains(page)
    }

    fn contains_chain(&self, page: u32) -> bool {
        self.chain.contains(page)
    }

    fn contains_bucket(&self, page: u32) -> bool {
        self.buckets.contains(page)
    }

    fn contains_free(&self, page: u32) -> bool {
        self.free.contains(page)
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
    let geometry = store.geometry();
    let durable = u32::try_from(store.durable_page_limit()).unwrap_or(u32::MAX);
    let capacity = durable.max(geometry.page_data_first());
    let mut sets = Sets::new(capacity);
    let mut damaged = Vec::new();

    for zone in 0..geometry.max_zones() {
        let Some(head) = store.head_entry(zone) else {
            continue;
        };
        report.zones_checked = report.zones_checked.saturating_add(1);
        if head.owner_zone != zone {
            report.issues.push(format!(
                "zone {zone}: owner_zone головы {}",
                head.owner_zone
            ));
            report.fatal.get_or_insert(FatalKind::ForeignOwner);
            continue;
        }
        if u64::from(head.page_limit_at_commit) > store.durable_page_limit() {
            report.issues.push(format!(
                "zone {zone}: page_limit {} выше DP {}",
                head.page_limit_at_commit,
                store.durable_page_limit()
            ));
            report.fatal.get_or_insert(FatalKind::HeadBeyondLimit);
        }
        if let Err(field) = head.check_fields(geometry.page_count_max()) {
            report
                .issues
                .push(format!("zone {zone}: head field {field:?}"));
            damaged.push(zone);
            continue;
        }
        if head.page_limit_at_commit < geometry.page_data_first() {
            report.issues.push(format!(
                "zone {zone}: page_limit {} ниже data_first {}",
                head.page_limit_at_commit,
                geometry.page_data_first()
            ));
            damaged.push(zone);
            continue;
        }
        match verify_zone(store, zone, &head, capacity, &mut sets, &mut report) {
            Ok(()) => {}
            // File-fatal (§9.2): запись запрещена до offline `fsck`; отчёт не
            // продолжаем, чтобы не маскировать порчу «частичным» результатом.
            Err(error) if is_file_fatal(&error) => return Err(error),
            Err(error) => {
                report.issues.push(format!("zone {zone}: {error}"));
                damaged.push(zone);
            }
        }
    }

    let durable = u32::try_from(store.durable_page_limit()).unwrap_or(u32::MAX);
    for page in geometry.page_data_first()..durable {
        if !sets.contains_tree(page)
            && !sets.contains_chain(page)
            && !sets.contains_bucket(page)
            && !sets.contains_free(page)
        {
            report.leaked_pages = report.leaked_pages.saturating_add(1);
            report.leaked_page_ids.push(page);
        }
    }
    report.durable_pages = u64::from(durable.saturating_sub(geometry.page_data_first()));
    report.reachable_pages = sets.tree.len();
    report.chain_pages = sets.chain.len();
    report.bucket_pages = sets.buckets.len();
    report.free_pages = sets.free.len();
    damaged.sort_unstable();
    damaged.dedup();
    report.damaged_zones = damaged;
    report.ok = report.fatal.is_none() && report.issues.is_empty();
    Ok(report)
}

fn verify_zone(
    store: &ParallelStore,
    zone: u32,
    head: &RootEntry,
    capacity: u32,
    sets: &mut Sets,
    report: &mut GraphReport,
) -> Result<(), ParallelError> {
    let limit = head.page_limit_at_commit;
    if head.root_page != 0 {
        if head.tree_level == 0 {
            return Err(zone_corrupt(head.root_page, V2CorruptKind::TreeLevel));
        }
        let io = ReaderIo::new(store, zone, head.version);
        let ctx = WalkCtx {
            io: &io,
            version: head.version,
            limit,
            capacity,
        };
        walk_tree(&ctx, head.root_page, head.tree_level, sets, report)?;
    }
    walk_chain(store, zone, head, capacity, sets, report)?;
    let chain = store
        .load_free_chain(zone, head)
        .map_err(|error| match error {
            // Цикл/порядок/дубли bucket-цепочки — zone-fatal, а не регрессия
            // глобальных watermark'ов (`WatermarkRegression` у `ALLOC_RECORD`).
            ParallelError::Corrupt {
                kind: V2CorruptKind::WatermarkRegression,
                page,
            } => ParallelError::Corrupt {
                kind: V2CorruptKind::RootChain,
                page,
            },
            other => other,
        })?;
    for bucket in chain.buckets() {
        if sets.contains_tree(bucket.page) || sets.contains_chain(bucket.page) {
            report
                .issues
                .push(format!("bucket page {} зоны {zone} достижима", bucket.page));
            report.fatal.get_or_insert(FatalKind::PageOverlap);
        }
        if sets.contains_bucket(bucket.page) {
            report.issues.push(format!(
                "bucket page {} зоны {zone} дублируется",
                bucket.page
            ));
            report.fatal.get_or_insert(FatalKind::PageOverlap);
        }
        match sets.overlap(bucket.page, Kind::Bucket, report) {
            InsertResult::Inserted => {}
            _ => continue,
        }
        for freed in &bucket.pages {
            if sets.contains_tree(*freed) {
                report
                    .issues
                    .push(format!("free page {freed} зоны {zone} достижима из дерева"));
                report.fatal.get_or_insert(FatalKind::PageOverlap);
            }
            if sets.contains_bucket(*freed) {
                report
                    .issues
                    .push(format!("free page {freed} зоны {zone} совпадает с bucket"));
                report.fatal.get_or_insert(FatalKind::PageOverlap);
            }
            // Свободная chain-страница (освобождённый хвост) допустима.
            let _ = sets.overlap(*freed, Kind::Free, report);
        }
    }
    Ok(())
}

/// Контекст обхода дерева одной зоны.
struct WalkCtx<'a, 'store> {
    io: &'a ReaderIo<'store>,
    version: u64,
    limit: u32,
    capacity: u32,
}

impl WalkCtx<'_, '_> {
    fn read(&self, page_no: u32) -> Result<&[u8], ParallelError> {
        self.io
            .read_page(page_no)
            .map_err(|error| self.io.take_error().unwrap_or(ParallelError::Tree(error)))
    }
}

fn walk_tree(
    ctx: &WalkCtx<'_, '_>,
    page_no: u32,
    level: u16,
    sets: &mut Sets,
    report: &mut GraphReport,
) -> Result<(), ParallelError> {
    if level == 0 {
        return Err(zone_corrupt(page_no, V2CorruptKind::TreeLevel));
    }
    check_page(page_no, ctx.limit, ctx.capacity)?;
    match sets.overlap(page_no, Kind::Tree, report) {
        InsertResult::Inserted => {}
        InsertResult::Duplicate => return Ok(()),
        InsertResult::OutOfRange => {
            return Err(zone_corrupt(page_no, V2CorruptKind::Bounds));
        }
    }
    let raw = ctx.read(page_no)?;
    note_txn(raw, report)?;
    let page_size = ctx.io.page_size();
    if level <= 1 {
        let leaf = DecodedLeaf::decode(raw, page_no, ctx.version, page_size)
            .map_err(ParallelError::Tree)?;
        for index in 0..leaf.len() {
            if let DecodedValue::Rrset { value, .. } =
                leaf.value(index).map_err(ParallelError::Tree)?
                && value.kind == ValueKind::Overflow
            {
                walk_overflow(ctx, value.val_u32, sets, report)?;
            }
        }
        return Ok(());
    }
    let branch =
        DecodedBranch::decode(raw, page_no, ctx.version, page_size).map_err(ParallelError::Tree)?;
    if branch.level() != level - 1 {
        return Err(zone_corrupt(page_no, V2CorruptKind::TreeLevel));
    }
    for index in 0..branch.len() {
        let child = branch.child(index).map_err(ParallelError::Tree)?;
        walk_tree(ctx, child, level - 1, sets, report)?;
    }
    Ok(())
}

fn walk_overflow(
    ctx: &WalkCtx<'_, '_>,
    first: u32,
    sets: &mut Sets,
    report: &mut GraphReport,
) -> Result<(), ParallelError> {
    let mut page_no = first;
    let mut hops = 0_u32;
    while page_no != 0 {
        hops = hops.saturating_add(1);
        if hops > MAX_OVERFLOW_PAGES {
            return Err(zone_corrupt(first, V2CorruptKind::TreeLevel));
        }
        check_page(page_no, ctx.limit, ctx.capacity)?;
        match sets.overlap(page_no, Kind::Tree, report) {
            InsertResult::Inserted => {}
            InsertResult::Duplicate => return Ok(()),
            InsertResult::OutOfRange => {
                return Err(zone_corrupt(page_no, V2CorruptKind::Bounds));
            }
        }
        let raw = ctx.read(page_no)?;
        note_txn(raw, report)?;
        let header = PageHeader::decode(raw, page_no, ctx.version, ctx.io.page_size())
            .map_err(ParallelError::Tree)?;
        if header.page_type != PAGE_TYPE_OVERFLOW {
            return Err(zone_corrupt(page_no, V2CorruptKind::TreeLevel));
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
    head: &RootEntry,
    capacity: u32,
    sets: &mut Sets,
    report: &mut GraphReport,
) -> Result<(), ParallelError> {
    let mut page = head.prev_record;
    let mut upper = head.version;
    let mut hops = 0_u32;
    while page != 0 {
        hops = hops.saturating_add(1);
        if hops > MAX_ROOT_CHAIN_HOPS {
            return Err(zone_corrupt(page, V2CorruptKind::RootChain));
        }
        if page >= head.page_limit_at_commit || page >= capacity {
            return Err(zone_corrupt(page, V2CorruptKind::PageLimit));
        }
        let raw = store.read_raw_page(page)?;
        let Some(chain) = ChainPage::decode(&raw, page) else {
            // Освобождённый/переиспользованный хвост — ожидаемо.
            return Ok(());
        };
        if chain.owner_zone != zone {
            return Err(ParallelError::Corrupt {
                kind: V2CorruptKind::ForeignOwner,
                page: Some(page),
            });
        }
        if u64::from(chain.entry.page_limit_at_commit) > store.durable_page_limit() {
            return Err(ParallelError::Corrupt {
                kind: V2CorruptKind::WatermarkRegression,
                page: Some(page),
            });
        }
        if chain.entry.page_limit_at_commit > head.page_limit_at_commit
            || chain.entry.version >= upper
        {
            return Err(zone_corrupt(page, V2CorruptKind::RootChain));
        }
        upper = chain.entry.version;
        match sets.overlap(page, Kind::Chain, report) {
            InsertResult::Inserted => {}
            InsertResult::Duplicate => return Ok(()),
            InsertResult::OutOfRange => {
                return Err(zone_corrupt(page, V2CorruptKind::Bounds));
            }
        }
        page = chain.entry.prev_record;
    }
    Ok(())
}

fn check_page(page: u32, limit: u32, capacity: u32) -> Result<(), ParallelError> {
    if page >= limit {
        return Err(zone_corrupt(page, V2CorruptKind::PageLimit));
    }
    if page >= capacity {
        return Err(zone_corrupt(page, V2CorruptKind::Bounds));
    }
    Ok(())
}

fn note_txn(raw: &[u8], report: &mut GraphReport) -> Result<(), ParallelError> {
    let txn = wire::read_u64(raw, PAGE_OFF_TXN).ok_or(ParallelError::Corrupt {
        kind: V2CorruptKind::Bounds,
        page: None,
    })?;
    report.max_page_txn = report.max_page_txn.max(txn);
    Ok(())
}

fn zone_corrupt(page: u32, kind: V2CorruptKind) -> ParallelError {
    // `PageLimit`/`TreeLevel`/`Bounds` — zone-fatal класс (не `is_file_fatal`):
    // зона уходит в карантин, остальные зоны и файл остаются доступны.
    ParallelError::Corrupt {
        kind,
        page: Some(page),
    }
}

fn is_file_fatal(error: &ParallelError) -> bool {
    match error {
        ParallelError::Corrupt { kind, .. } => kind.is_file_fatal(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{GraphReport, InsertResult, Kind, PageSet, Sets};

    #[test]
    fn bitset_reports_duplicates_and_out_of_range() {
        let mut set = PageSet::new(128);
        assert_eq!(set.insert(42), InsertResult::Inserted);
        assert_eq!(set.insert(42), InsertResult::Duplicate);
        assert_eq!(set.insert(128), InsertResult::OutOfRange);
        assert!(set.contains(42));
        assert!(!set.contains(43));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn duplicate_page_is_reported_as_overlap() {
        let mut sets = Sets::new(1024);
        let mut report = GraphReport::default();
        assert_eq!(
            sets.overlap(42, Kind::Tree, &mut report),
            InsertResult::Inserted
        );
        assert_eq!(
            sets.overlap(42, Kind::Tree, &mut report),
            InsertResult::Duplicate
        );
        assert_eq!(
            report.fatal,
            Some(crate::parallel::error::FatalKind::PageOverlap)
        );
        assert_eq!(report.issues.len(), 1);
    }

    #[test]
    fn disjoint_pages_stay_ok() {
        let mut sets = Sets::new(1024);
        let mut report = GraphReport::default();
        for (page, kind) in [
            (1, Kind::Tree),
            (2, Kind::Chain),
            (3, Kind::Bucket),
            (4, Kind::Free),
        ] {
            assert_eq!(
                sets.overlap(page, kind, &mut report),
                InsertResult::Inserted
            );
        }
        assert!(report.fatal.is_none());
        assert_eq!(report.issues.len(), 0);
    }
}
