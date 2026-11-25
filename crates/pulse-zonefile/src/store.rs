//! Транзакционный слой страниц: COW-оверлей поверх `mmap` (`zonefile-v1.md` §13.6).
//!
//! Все записи транзакции копятся в памяти ([`TxnPages::dirty`]); на диск они
//! попадают только на коммите, после чего публикуется новая meta. Чтение
//! сначала смотрит в оверлей, затем в `MAP_SHARED`-отображение файла: запись
//! `pwrite` видна через маппинг, поэтому после коммита отдельная
//! ре-синхронизация не нужна.
//!
//! Freelist здесь же: выдача страниц, учёт освобождённых и пересборка цепочки
//! bucket'ов на коммите.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use crate::consts::{MAX_FILE_PAGES, PAGE_DATA_FIRST};
use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::freelist::{self, Freelist};
use crate::map::FileMap;
use crate::tree::PageIo;

/// Итог финализации freelist'а.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeMeta {
    /// Голова цепочки.
    pub head: u32,
    /// Хвост цепочки.
    pub tail: u32,
    /// Число bucket-страниц.
    pub buckets: u32,
    /// Число свободных страниц.
    pub entries: u32,
}

fn push_group(groups: &mut Vec<(u64, Vec<u32>)>, free_txn: u64, pages: Vec<u32>) {
    if let Some((last_txn, last_pages)) = groups.last_mut()
        && *last_txn == free_txn
    {
        last_pages.extend(pages);
    } else {
        groups.push((free_txn, pages));
    }
}

/// Транзакционное хранилище страниц.
#[derive(Debug)]
pub struct TxnPages {
    map: Arc<FileMap>,
    page_size: u32,
    txn: u64,
    high_water: u32,
    page_count_max: u32,
    reclaim_txn: u64,
    dirty: BTreeMap<u32, Vec<u8>>,
    freed: Vec<u32>,
    freed_set: HashSet<u32>,
    freelist: Freelist,
}

impl TxnPages {
    /// Открывает транзакцию поверх активной meta.
    ///
    /// # Errors
    ///
    /// `Corrupt` — цепочка freelist повреждена; `InvariantViolation` — `txnid`
    /// исчерпан.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        map: Arc<FileMap>,
        page_size: u32,
        page_count_max: u32,
        snapshot_txn: u64,
        high_water: u32,
        reclaim_txn: u64,
        freelist_head: u32,
        freelist_tail: u32,
        freelist_buckets: u32,
        freelist_entries: u32,
    ) -> Result<Self, ZoneFileError> {
        let txn = snapshot_txn
            .checked_add(1)
            .ok_or(ZoneFileError::IdSpaceExhausted)?;
        let freelist = Freelist::load(
            &map,
            page_size,
            snapshot_txn,
            high_water,
            freelist_head,
            freelist_buckets,
            freelist_entries,
            freelist_tail,
        )?;
        Ok(Self {
            map,
            page_size,
            txn,
            high_water,
            page_count_max,
            reclaim_txn,
            dirty: BTreeMap::new(),
            freed: Vec::new(),
            freed_set: HashSet::new(),
            freelist,
        })
    }

    /// Номер создаваемой транзакции.
    #[must_use]
    pub const fn txn(&self) -> u64 {
        self.txn
    }

    /// Текущий high water.
    #[must_use]
    pub const fn high_water(&self) -> u32 {
        self.high_water
    }

    /// Записанные (dirty) страницы.
    #[must_use]
    pub fn dirty_pages(&self) -> &BTreeMap<u32, Vec<u8>> {
        &self.dirty
    }

    /// Число страниц, освобождённых в этой транзакции (до пересборки цепочки).
    #[must_use]
    pub fn freed_count(&self) -> usize {
        self.freed.len()
    }

    /// Граница переиспользования страниц.
    #[must_use]
    pub const fn reclaim_txn(&self) -> u64 {
        self.reclaim_txn
    }

    fn bounds(page_no: u32) -> ZoneFileError {
        ZoneFileError::corrupt(
            CorruptKind::Bounds,
            Some(page_no),
            CorruptDetail::ChildRange,
        )
    }

    fn bump_high_water(&mut self) -> Result<u32, ZoneFileError> {
        if self.high_water >= self.page_count_max || self.high_water >= MAX_FILE_PAGES {
            return if self.freelist.entry_count() > 0 {
                Err(ZoneFileError::NoSpace {
                    needed: 1,
                    free: self.freelist.entry_count(),
                })
            } else {
                Err(ZoneFileError::MapFull {
                    high_water: self.high_water,
                    page_count_max: self.page_count_max,
                })
            };
        }
        let page = self.high_water;
        self.high_water = self
            .high_water
            .checked_add(1)
            .ok_or_else(|| Self::bounds(page))?;
        Ok(page)
    }

    /// Пересобирает freelist в свежие bucket-страницы (COW).
    ///
    /// Старые bucket-страницы попадают в набор освобождённых текущей
    /// транзакции; образам выдаются страницы из eligible-хвоста freelist, а при
    /// их отсутствии — из `high_water`.
    ///
    /// # Errors
    ///
    /// `NoSpace`/`MapFull` — не хватает места под bucket'ы; ошибки кодирования.
    pub fn finalize_freelist(&mut self) -> Result<FreeMeta, ZoneFileError> {
        self.freelist.take_empty_buckets(&mut self.freed);
        let capacity = freelist::bucket_capacity(self.page_size)?;
        let mut bucket_pages: Vec<u32> = Vec::new();
        let groups = loop {
            let groups = self.collect_free_groups();
            let needed = freelist::needed_buckets(&groups, capacity);
            if bucket_pages.len() < needed {
                let page = if let Some(page) = self.freelist.pop_eligible(self.reclaim_txn) {
                    page
                } else {
                    self.bump_high_water()?
                };
                bucket_pages.push(page);
                self.freelist.take_empty_buckets(&mut self.freed);
                continue;
            }
            if bucket_pages.len() > needed {
                // Пересборка могла потребовать меньше образов: лишняя уже
                // выделенная страница возвращается в текущую группу.
                if let Some(page) = bucket_pages.pop()
                    && self.freed_set.insert(page)
                {
                    self.freed.push(page);
                }
                continue;
            }
            break groups;
        };
        let mut images = Vec::new();
        let list = Freelist::build(
            &groups,
            self.page_size,
            self.txn,
            &bucket_pages,
            &mut |page, image| {
                images.push((page, image));
                Ok(())
            },
        )?;
        for (page, image) in images {
            self.write_page(page, &image)?;
        }
        self.freelist = list;
        self.freed.clear();
        self.freed_set.clear();
        Ok(FreeMeta {
            head: self.freelist.head(),
            tail: self.freelist.tail(),
            buckets: self.freelist.bucket_count(),
            entries: self.freelist.entry_count(),
        })
    }

    /// Группы свободных страниц по исходному `free_txn`; текущая группа —
    /// страницы, освобождённые этой транзакцией (включая старые bucket-образы).
    fn collect_free_groups(&self) -> Vec<(u64, Vec<u32>)> {
        let mut groups: Vec<(u64, Vec<u32>)> = Vec::new();
        for bucket in self.freelist.buckets() {
            if !bucket.pages.is_empty() {
                push_group(&mut groups, bucket.free_txn, bucket.pages.clone());
            }
        }
        let mut current = self.freed.clone();
        current.extend(self.freelist.buckets().iter().map(|bucket| bucket.page));
        if !current.is_empty() {
            push_group(&mut groups, self.txn, current);
        }
        groups
    }
}

impl PageIo for TxnPages {
    fn page_size(&self) -> u32 {
        self.page_size
    }

    fn alloc_page(&mut self) -> Result<u32, ZoneFileError> {
        self.freelist.take_empty_buckets(&mut self.freed);
        if let Some(page) = self.freelist.pop_eligible(self.reclaim_txn) {
            return Ok(page);
        }
        if self.high_water < self.page_count_max && self.high_water < MAX_FILE_PAGES {
            return self.bump_high_water();
        }
        let free = self.freelist.entry_count();
        if free > 0 {
            Err(ZoneFileError::NoSpace { needed: 1, free })
        } else {
            Err(ZoneFileError::MapFull {
                high_water: self.high_water,
                page_count_max: self.page_count_max,
            })
        }
    }

    fn read_page(&self, page_no: u32) -> Result<&[u8], ZoneFileError> {
        if page_no < PAGE_DATA_FIRST || page_no >= self.high_water {
            return Err(Self::bounds(page_no));
        }
        if let Some(page) = self.dirty.get(&page_no) {
            return Ok(page);
        }
        self.map.page(page_no, self.page_size).ok_or_else(|| {
            ZoneFileError::corrupt(CorruptKind::Bounds, Some(page_no), CorruptDetail::Truncated)
        })
    }

    fn write_page(&mut self, page_no: u32, page: &[u8]) -> Result<(), ZoneFileError> {
        if page_no < PAGE_DATA_FIRST
            || page_no >= self.high_water
            || page.len() != usize::try_from(self.page_size).unwrap_or(0)
        {
            return Err(Self::bounds(page_no));
        }
        self.dirty.insert(page_no, page.to_vec());
        Ok(())
    }

    fn free_page(&mut self, page_no: u32) -> Result<(), ZoneFileError> {
        if page_no < PAGE_DATA_FIRST || page_no >= self.high_water {
            return Err(Self::bounds(page_no));
        }
        if !self.freed_set.insert(page_no) {
            return Err(ZoneFileError::InvariantViolation(
                crate::InvariantId::DuplicatePage,
            ));
        }
        self.freed.push(page_no);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::PAGE_SIZE_DEFAULT;

    #[test]
    fn allocator_distinguishes_no_space_and_map_full() {
        // Проверяется арифметика без файла: high_water == page_count_max,
        // freelist пуст → MapFull; при непустом freelist — NoSpace.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.map");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.set_len(u64::from(PAGE_SIZE_DEFAULT) * 16).unwrap();
        let map = Arc::new(
            FileMap::map_read(
                &file,
                u64::from(PAGE_SIZE_DEFAULT) * 16,
                crate::mem::HugePages::Never,
            )
            .unwrap(),
        );
        let mut pages = TxnPages::new(map, PAGE_SIZE_DEFAULT, 16, 1, 16, 0, 0, 0, 0, 0).unwrap();
        assert!(matches!(
            pages.alloc_page(),
            Err(ZoneFileError::MapFull { .. })
        ));
    }

    #[test]
    fn allocator_reports_no_space_for_young_pages() {
        use std::os::unix::fs::FileExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("young.map");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.set_len(u64::from(PAGE_SIZE_DEFAULT) * 16).unwrap();
        // Bucket на странице 14: страница 15 освобождена в txn 2.
        let mut images = Vec::new();
        let groups = [(2_u64, vec![15_u32])];
        Freelist::build(&groups, PAGE_SIZE_DEFAULT, 2, &[14], &mut |page, image| {
            images.push((page, image));
            Ok(())
        })
        .unwrap();
        for (page, image) in images {
            file.write_all_at(&image, u64::from(page) * u64::from(PAGE_SIZE_DEFAULT))
                .unwrap();
        }
        let map = Arc::new(
            FileMap::map_read(
                &file,
                u64::from(PAGE_SIZE_DEFAULT) * 16,
                crate::mem::HugePages::Never,
            )
            .unwrap(),
        );
        let mut pages = TxnPages::new(map, PAGE_SIZE_DEFAULT, 16, 2, 16, 0, 14, 14, 1, 1).unwrap();
        assert!(matches!(
            pages.alloc_page(),
            Err(ZoneFileError::NoSpace { free: 1, .. })
        ));
    }
}
