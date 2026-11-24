//! Offline `fsck` (`zonefile-v1.md` §13.9).
//!
//! Проверяет достижимость графа, отсутствие пересечений с freelist,
//! `high_water`/`page_limit`, контракт значений и счётчики каталога.

use std::collections::HashSet;

use crate::consts::{MAX_OVERFLOW_PAGES, PAGE_TYPE_ZONE_META};
use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::freelist::Freelist;
use crate::key::{Key, T_NODE, T_ZONE_ENTRY, compare_validated};
use crate::node::{DecodedBranch, DecodedLeaf, DecodedValue, ValueKind, ZONE_ENTRY_BYTES};
use crate::page::PageHeader;
use crate::tree::{BTree, PageIo, ZoneTree};
use crate::wire;
use crate::zone_meta::{ZoneEntry, ZoneMetaBlock};
use crate::zonefile::{FsckReport, ZoneFile};

/// Проверяет открытый файл.
///
/// # Errors
///
/// `Corrupt` — структурное повреждение страницы/графа.
pub(crate) fn verify(zonefile: &ZoneFile) -> Result<FsckReport, ZoneFileError> {
    let meta = *zonefile.meta();
    let page_size = zonefile.superblock().page_size;
    let mut report = FsckReport {
        high_water: meta.page_count_high_water,
        page_count_max: zonefile.page_count_max(),
        zone_count: meta.zone_count,
        ..FsckReport::default()
    };
    if meta.page_count_high_water > zonefile.page_count_max() {
        report
            .problems
            .push("high_water exceeds page_count_max".to_string());
    }
    let mut visited = HashSet::new();

    let catalog = BTree::new(meta.zone_dir_root, meta.zone_dir_level)?;
    let mut previous: Option<Key> = None;
    let mut totals = Totals::default();
    walk_catalog(
        zonefile,
        catalog,
        meta.txnid,
        &mut visited,
        &mut previous,
        &mut totals,
        &mut report,
    )?;

    let freelist = Freelist::load(
        zonefile.map_ref(),
        page_size,
        meta.txnid,
        meta.page_count_high_water,
        meta.freelist_head,
        meta.freelist_buckets,
        meta.freelist_entries,
        meta.freelist_tail,
    )?;
    let mut free_pages = HashSet::new();
    for bucket in freelist.buckets() {
        if visited.contains(&bucket.page) {
            report
                .problems
                .push(format!("bucket page {} is reachable", bucket.page));
        }
        if !free_pages.insert(bucket.page) {
            report
                .problems
                .push(format!("duplicate bucket page {}", bucket.page));
        }
        for &page in &bucket.pages {
            if visited.contains(&page) {
                report
                    .problems
                    .push(format!("free page {page} is reachable"));
            }
            if !free_pages.insert(page) {
                report.problems.push(format!("duplicate free page {page}"));
            }
        }
    }
    report.reachable_pages = u64::try_from(visited.len()).unwrap_or(u64::MAX);
    report.bucket_pages = u64::from(freelist.bucket_count());
    report.freelist_pages = u64::from(freelist.entry_count());
    report.rrset_count = totals.rrsets;
    report.rr_count = totals.rrs;

    if totals.zones != meta.zone_count {
        report.problems.push(format!(
            "zone_count mismatch: catalog {}, meta {}",
            totals.zones, meta.zone_count
        ));
    }
    if totals.rrsets != meta.total_rrsets {
        report.problems.push(format!(
            "total_rrsets mismatch: catalog {}, meta {}",
            totals.rrsets, meta.total_rrsets
        ));
    }
    if totals.rrs != meta.total_rrs {
        report.problems.push(format!(
            "total_rrs mismatch: catalog {}, meta {}",
            totals.rrs, meta.total_rrs
        ));
    }

    let mut allocated = visited.clone();
    allocated.extend(free_pages.iter().copied());
    for page in zonefile.superblock().page_data_first..meta.page_count_high_water {
        if !allocated.contains(&page) {
            report.problems.push(format!("leaked page {page}"));
        }
    }
    Ok(report)
}

#[derive(Default)]
struct Totals {
    zones: u32,
    rrsets: u64,
    rrs: u64,
}

#[allow(clippy::too_many_arguments)]
fn walk_catalog(
    zonefile: &ZoneFile,
    catalog: BTree,
    txn: u64,
    visited: &mut HashSet<u32>,
    previous: &mut Option<Key>,
    totals: &mut Totals,
    report: &mut FsckReport,
) -> Result<(), ZoneFileError> {
    if catalog.is_empty() {
        return Ok(());
    }
    walk_catalog_page(
        zonefile,
        catalog.root(),
        catalog.level() - 1,
        txn,
        visited,
        previous,
        totals,
        report,
    )
}

#[allow(clippy::too_many_arguments)]
fn walk_catalog_page(
    zonefile: &ZoneFile,
    page_no: u32,
    level: u16,
    txn: u64,
    visited: &mut HashSet<u32>,
    previous: &mut Option<Key>,
    totals: &mut Totals,
    report: &mut FsckReport,
) -> Result<(), ZoneFileError> {
    mark_visited(visited, page_no)?;
    let page_size = zonefile.superblock().page_size;
    let page = zonefile.read_page(page_no)?;
    if level == 0 {
        let leaf = DecodedLeaf::decode(page, page_no, txn, page_size)?;
        for index in 0..leaf.len() {
            let key = leaf.key(index)?;
            if let Some(prev) = previous
                && compare_validated(prev, &key) != std::cmp::Ordering::Less
            {
                return Err(ZoneFileError::corrupt(
                    CorruptKind::TreeOrder,
                    Some(page_no),
                    CorruptDetail::KeyOrder,
                ));
            }
            *previous = Some(key);
            let value = leaf.value(index)?;
            let DecodedValue::ZoneEntry(bytes) = value else {
                return Err(ZoneFileError::corrupt(
                    CorruptKind::BadZoneMeta,
                    Some(page_no),
                    CorruptDetail::ZoneMetaField,
                ));
            };
            if key.rr_type() != T_ZONE_ENTRY || bytes.len() != ZONE_ENTRY_BYTES {
                return Err(ZoneFileError::corrupt(
                    CorruptKind::BadZoneMeta,
                    Some(page_no),
                    CorruptDetail::ZoneMetaField,
                ));
            }
            let apex = key.owner()?;
            let entry = ZoneEntry::decode(bytes)?;
            if entry.zone_origin_len as usize != apex.len() {
                report
                    .problems
                    .push(format!("zone {} origin_len mismatch", apex.as_rle().len()));
            }
            stats_zone_meta(zonefile, &entry, txn, visited)?;
            let (rrsets, rrs) = walk_zone_tree(
                zonefile,
                &apex,
                entry.tree_root,
                entry.tree_level,
                txn,
                visited,
            )?;
            if entry.is_live() {
                totals.zones = totals.zones.saturating_add(1);
                if entry.rrset_count != rrsets {
                    report.problems.push(format!(
                        "zone {apex:?} rrset_count: entry {}, tree {}",
                        entry.rrset_count, rrsets
                    ));
                }
                if entry.rr_count != rrs {
                    report.problems.push(format!(
                        "zone {apex:?} rr_count: entry {}, tree {}",
                        entry.rr_count, rrs
                    ));
                }
                totals.rrsets = totals.rrsets.saturating_add(u64::from(rrsets));
                totals.rrs = totals.rrs.saturating_add(u64::from(rrs));
            }
        }
        return Ok(());
    }
    let branch = DecodedBranch::decode(page, page_no, txn, page_size)?;
    if branch.level() != level {
        return Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(page_no),
            CorruptDetail::PageType,
        ));
    }
    for index in 0..branch.len() {
        let child = branch.child(index)?;
        let separator = branch.separator(index)?;
        let first = first_key_of_page(zonefile, child, level - 1, txn)?;
        if compare_validated(&separator, &first) != std::cmp::Ordering::Equal {
            return Err(ZoneFileError::corrupt(
                CorruptKind::TreeOrder,
                Some(page_no),
                CorruptDetail::SeparatorMismatch,
            ));
        }
        walk_catalog_page(
            zonefile,
            child,
            level - 1,
            txn,
            visited,
            previous,
            totals,
            report,
        )?;
    }
    Ok(())
}

fn stats_zone_meta(
    zonefile: &ZoneFile,
    entry: &ZoneEntry,
    txn: u64,
    visited: &mut HashSet<u32>,
) -> Result<(), ZoneFileError> {
    if entry.meta_root == 0 {
        return Ok(());
    }
    let page_size = zonefile.superblock().page_size;
    mark_visited(visited, entry.meta_root)?;
    let page = zonefile.read_page(entry.meta_root)?;
    let header = PageHeader::decode(page, entry.meta_root, txn, page_size)?;
    if header.page_type != PAGE_TYPE_ZONE_META {
        return Err(ZoneFileError::corrupt(
            CorruptKind::BadZoneMeta,
            Some(entry.meta_root),
            CorruptDetail::PageType,
        ));
    }
    let block = ZoneMetaBlock::decode(page, entry.meta_root, txn, page_size)?;
    block.validate()?;
    Ok(())
}

fn walk_zone_tree(
    zonefile: &ZoneFile,
    apex: &crate::key::NameRle,
    root: u32,
    level: u16,
    txn: u64,
    visited: &mut HashSet<u32>,
) -> Result<(u32, u32), ZoneFileError> {
    if root == 0 {
        return Ok((0, 0));
    }
    let tree = ZoneTree::new(*apex, root, level)?;
    let mut rrsets = 0_u32;
    let mut rrs = 0_u32;
    walk_zone_page(
        zonefile,
        tree.root(),
        tree.level() - 1,
        txn,
        visited,
        &mut rrsets,
        &mut rrs,
    )?;
    Ok((rrsets, rrs))
}

fn walk_zone_page(
    zonefile: &ZoneFile,
    page_no: u32,
    level: u16,
    txn: u64,
    visited: &mut HashSet<u32>,
    rrsets: &mut u32,
    rrs: &mut u32,
) -> Result<(), ZoneFileError> {
    mark_visited(visited, page_no)?;
    let page_size = zonefile.superblock().page_size;
    let page = zonefile.read_page(page_no)?;
    if level == 0 {
        let leaf = DecodedLeaf::decode(page, page_no, txn, page_size)?;
        for index in 0..leaf.len() {
            let key = leaf.key(index)?;
            match leaf.value(index)? {
                DecodedValue::ZoneEntry(_) => {
                    return Err(ZoneFileError::corrupt(
                        CorruptKind::BadZoneMeta,
                        Some(page_no),
                        CorruptDetail::ZoneMetaField,
                    ));
                }
                DecodedValue::Rrset { value, payload } => {
                    if key.rr_type() == T_NODE {
                        if value.kind != ValueKind::Node || value.rr_count != 0 {
                            return Err(ZoneFileError::corrupt(
                                CorruptKind::TreeOrder,
                                Some(page_no),
                                CorruptDetail::KeyOrder,
                            ));
                        }
                        continue;
                    }
                    if value.kind == ValueKind::Node {
                        return Err(ZoneFileError::corrupt(
                            CorruptKind::TreeOrder,
                            Some(page_no),
                            CorruptDetail::KeyOrder,
                        ));
                    }
                    *rrsets = rrsets.saturating_add(1);
                    *rrs = rrs.saturating_add(u32::from(value.rr_count));
                    if value.kind == ValueKind::Overflow {
                        walk_overflow_chain(
                            zonefile,
                            value.val_u32,
                            txn,
                            visited,
                            value.payload_bytes()?,
                        )?;
                    } else if payload.len()
                        != usize::try_from(value.payload_bytes()?).unwrap_or(usize::MAX)
                    {
                        return Err(ZoneFileError::corrupt(
                            CorruptKind::BadRdata,
                            Some(page_no),
                            CorruptDetail::RdataSum,
                        ));
                    }
                }
            }
        }
        return Ok(());
    }
    let branch = DecodedBranch::decode(page, page_no, txn, page_size)?;
    if branch.level() != level {
        return Err(ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(page_no),
            CorruptDetail::PageType,
        ));
    }
    for index in 0..branch.len() {
        let child = branch.child(index)?;
        let separator = branch.separator(index)?;
        let first = first_key_of_page(zonefile, child, level - 1, txn)?;
        if compare_validated(&separator, &first) != std::cmp::Ordering::Equal {
            return Err(ZoneFileError::corrupt(
                CorruptKind::TreeOrder,
                Some(page_no),
                CorruptDetail::SeparatorMismatch,
            ));
        }
        walk_zone_page(zonefile, child, level - 1, txn, visited, rrsets, rrs)?;
    }
    Ok(())
}

fn walk_overflow_chain(
    zonefile: &ZoneFile,
    first: u32,
    txn: u64,
    visited: &mut HashSet<u32>,
    expected: u32,
) -> Result<(), ZoneFileError> {
    let page_size = zonefile.superblock().page_size;
    let mut page_no = first;
    let mut total = 0_u32;
    let mut hops = 0_u32;
    while page_no != 0 {
        hops = hops.saturating_add(1);
        if hops > MAX_OVERFLOW_PAGES {
            return Err(ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                Some(page_no),
                CorruptDetail::Cycle,
            ));
        }
        mark_visited(visited, page_no)?;
        let page = zonefile.read_page(page_no)?;
        let header = PageHeader::decode(page, page_no, txn, page_size)?;
        if header.page_type != crate::consts::PAGE_TYPE_OVERFLOW {
            return Err(ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                Some(page_no),
                CorruptDetail::PageType,
            ));
        }
        let data_len = wire::read_u32(page, 44).ok_or_else(|| {
            ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                Some(page_no),
                CorruptDetail::Truncated,
            )
        })?;
        total = total.checked_add(data_len).ok_or_else(|| {
            ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                Some(page_no),
                CorruptDetail::RdataSum,
            )
        })?;
        let payload_start = usize::try_from(crate::consts::OVERFLOW_HEADER_SIZE).unwrap_or(48);
        let payload_end = payload_start
            .checked_add(usize::try_from(data_len).unwrap_or(usize::MAX))
            .filter(|&end| end <= page.len())
            .ok_or_else(|| {
                ZoneFileError::corrupt(
                    CorruptKind::BadRdata,
                    Some(page_no),
                    CorruptDetail::OverflowChain,
                )
            })?;
        let _ = payload_end;
        page_no = wire::read_u32(page, 40).ok_or_else(|| {
            ZoneFileError::corrupt(
                CorruptKind::BadRdata,
                Some(page_no),
                CorruptDetail::Truncated,
            )
        })?;
    }
    if total != expected {
        return Err(ZoneFileError::corrupt(
            CorruptKind::BadRdata,
            Some(first),
            CorruptDetail::RdataSum,
        ));
    }
    Ok(())
}

fn first_key_of_page(
    zonefile: &ZoneFile,
    page_no: u32,
    level: u16,
    txn: u64,
) -> Result<Key, ZoneFileError> {
    let page_size = zonefile.superblock().page_size;
    let page = zonefile.read_page(page_no)?;
    if level == 0 {
        DecodedLeaf::decode(page, page_no, txn, page_size)?.first_key()
    } else {
        let branch = DecodedBranch::decode(page, page_no, txn, page_size)?;
        if branch.level() != level {
            return Err(ZoneFileError::corrupt(
                CorruptKind::Bounds,
                Some(page_no),
                CorruptDetail::PageType,
            ));
        }
        first_key_of_page(zonefile, branch.child(0)?, level - 1, txn)
    }
}

fn mark_visited(visited: &mut HashSet<u32>, page_no: u32) -> Result<(), ZoneFileError> {
    if !visited.insert(page_no) {
        return Err(ZoneFileError::corrupt(
            CorruptKind::FreelistCycle,
            Some(page_no),
            CorruptDetail::Overlap,
        ));
    }
    Ok(())
}
