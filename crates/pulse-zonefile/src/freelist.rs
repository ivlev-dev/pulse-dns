//! Freelist: bucket-страницы и правила переиспользования (`zonefile-v1.md` §11.7, §14).
//!
//! Цепочка bucket-страниц упорядочена по `free_txn` по возрастанию (голова —
//! самая старая). Аллокатор берёт страницы только пока
//! `free_txn <= reclaim_txn`, где
//! `reclaim_txn = min(durable_watermark - 1, oldest_reader_txn)`.
//!
//! Bucket-страницы никогда не изменяются на месте: коммит пересобирает цепочку
//! в свежие страницы (COW), а старые образы попадают в набор освобождённых
//! этого же коммита. Это O(число bucket-страниц) на коммит с освобождениями;
//! при стабильной нагрузке число непустых bucket'ов не растёт, потому что все
//! страницы одного коммита лежат в bucket'ах с одинаковым `free_txn`.

use std::collections::HashSet;

use crate::consts::{FREELIST_HEADER_SIZE, PAGE_OFF_PAYLOAD_LEN, PAGE_TYPE_FREELIST};
use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::map::FileMap;
use crate::node::{self, EncodeContext};
use crate::page::PageHeader;
use crate::wire;

const FL_OFF_NEXT: usize = 40;
const FL_OFF_RESERVED0: usize = 44;
const FL_OFF_FREE_TXN: usize = 48;
const FL_OFF_COUNT: usize = 56;
const FL_OFF_RESERVED1: usize = 60;
const FL_OFF_PAGES: usize = 64;

/// Один bucket в памяти.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// Страница, на которой лежит образ bucket'а.
    pub page: u32,
    /// Txn, в котором освобождены страницы bucket'а.
    pub free_txn: u64,
    /// Освобождённые страницы.
    pub pages: Vec<u32>,
}

/// Freelist, прочитанный из активной meta.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Freelist {
    buckets: Vec<Bucket>,
}

impl Freelist {
    /// Пустой freelist.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Число bucket-страниц.
    #[must_use]
    pub fn bucket_count(&self) -> u32 {
        u32::try_from(self.buckets.len()).unwrap_or(u32::MAX)
    }

    /// Число страниц во всех bucket'ах.
    #[must_use]
    pub fn entry_count(&self) -> u32 {
        self.buckets
            .iter()
            .try_fold(0_u32, |sum, bucket| {
                u32::try_from(bucket.pages.len())
                    .ok()
                    .and_then(|len| sum.checked_add(len))
            })
            .unwrap_or(u32::MAX)
    }

    /// Голова цепочки (`0` — пусто).
    #[must_use]
    pub fn head(&self) -> u32 {
        self.buckets.first().map_or(0, |bucket| bucket.page)
    }

    /// Хвост цепочки (`0` — пусто).
    #[must_use]
    pub fn tail(&self) -> u32 {
        self.buckets.last().map_or(0, |bucket| bucket.page)
    }

    /// Bucket'ы в порядке цепочки.
    #[must_use]
    pub fn buckets(&self) -> &[Bucket] {
        &self.buckets
    }

    /// Берёт одну страницу, разрешённую к переиспользованию.
    ///
    /// Список отсортирован по `free_txn`, поэтому при первом «молодом» bucket'е
    /// обход прекращается.
    pub fn pop_eligible(&mut self, reclaim_txn: u64) -> Option<u32> {
        let bucket = self.buckets.first_mut()?;
        if bucket.free_txn > reclaim_txn {
            return None;
        }
        let page = bucket.pages.pop()?;
        // Пустые bucket'ы в цепочке не существуют; удаление вместе с
        // страницей bucket'а выполняется при пересборке цепочки на коммите.
        Some(page)
    }

    /// Убирает пустые головные bucket'ы; возвращает их страницы для freelist.
    pub fn take_empty_buckets(&mut self, freed: &mut Vec<u32>) {
        while self
            .buckets
            .first()
            .is_some_and(|bucket| bucket.pages.is_empty())
        {
            if let Some(bucket) = self.buckets.first() {
                freed.push(bucket.page);
            }
            self.buckets.remove(0);
        }
    }

    /// Читает цепочку из файла и проверяет инварианты.
    ///
    /// # Errors
    ///
    /// `Corrupt(FreelistCycle)`/`Corrupt(Bounds)` — цикл, пустой bucket,
    /// нарушение порядка `free_txn`, выход за `high_water`, несовпадение
    /// счётчиков meta.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn load(
        map: &FileMap,
        page_size: u32,
        snapshot_txn: u64,
        high_water: u32,
        head: u32,
        expected_buckets: u32,
        expected_entries: u32,
        tail: u32,
    ) -> Result<Self, ZoneFileError> {
        if head == 0 {
            if expected_buckets != 0 || expected_entries != 0 || tail != 0 {
                return Err(corrupt(CorruptDetail::Overlap));
            }
            return Ok(Self::new());
        }
        let mut buckets = Vec::new();
        let mut visited_pages = HashSet::new();
        let mut entries = HashSet::new();
        let mut page_no = head;
        let mut previous_txn = 0_u64;
        while page_no != 0 {
            if page_no < crate::consts::PAGE_DATA_FIRST || page_no >= high_water {
                return Err(corrupt(CorruptDetail::ChildRange));
            }
            if !visited_pages.insert(page_no) {
                return Err(corrupt(CorruptDetail::Cycle));
            }
            let page = map
                .page(page_no, page_size)
                .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
            let bucket = decode_bucket(page, page_no, snapshot_txn, page_size, high_water)?;
            if bucket.free_txn < previous_txn {
                return Err(corrupt(CorruptDetail::Overlap));
            }
            previous_txn = bucket.free_txn;
            for &freed in &bucket.pages {
                if !entries.insert(freed) {
                    return Err(corrupt(CorruptDetail::Overlap));
                }
            }
            buckets.push(bucket);
            page_no = wire::read_u32(page, FL_OFF_NEXT)
                .ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        }
        if tail != buckets.last().map_or(0, |bucket| bucket.page) {
            return Err(corrupt(CorruptDetail::Overlap));
        }
        let bucket_count =
            u32::try_from(buckets.len()).map_err(|_| corrupt(CorruptDetail::Overlap))?;
        let entry_count =
            u32::try_from(entries.len()).map_err(|_| corrupt(CorruptDetail::Overlap))?;
        if bucket_count != expected_buckets || entry_count != expected_entries {
            return Err(corrupt(CorruptDetail::Overlap));
        }
        // Bucket-страницы не могут одновременно лежать в page_ids.
        if buckets.iter().any(|bucket| entries.contains(&bucket.page)) {
            return Err(corrupt(CorruptDetail::Overlap));
        }
        Ok(Self { buckets })
    }

    /// Создаёт новую цепочку из сгруппированных по `free_txn` страниц.
    ///
    /// `groups` обязаны идти по возрастанию `free_txn`; `bucket_pages` уже
    /// выделены (по одной странице на chunk). Образы пишутся через `write` в
    /// порядке цепочки; порядок `free_txn` сохраняется, поэтому старые
    /// свободные страницы не «омолаживаются» при пересборке.
    ///
    /// # Errors
    ///
    /// `Corrupt`/`InvariantViolation` — некорректные размеры; ошибки записи.
    pub(crate) fn build(
        groups: &[(u64, Vec<u32>)],
        page_size: u32,
        txn: u64,
        bucket_pages: &[u32],
        write: &mut impl FnMut(u32, Vec<u8>) -> Result<(), ZoneFileError>,
    ) -> Result<Self, ZoneFileError> {
        let capacity = bucket_capacity(page_size)?;
        let needed = needed_buckets(groups, capacity);
        if needed == 0 {
            if !bucket_pages.is_empty() {
                return Err(ZoneFileError::InvariantViolation(
                    crate::InvariantId::DuplicatePage,
                ));
            }
            return Ok(Self::new());
        }
        if bucket_pages.len() != needed {
            return Err(ZoneFileError::InvariantViolation(
                crate::InvariantId::DuplicatePage,
            ));
        }
        let mut assigned = 0_usize;
        let mut buckets = Vec::with_capacity(needed);
        for (free_txn, pages) in groups {
            for chunk in pages.chunks(capacity) {
                let page = bucket_pages
                    .get(assigned)
                    .copied()
                    .ok_or_else(|| corrupt(CorruptDetail::Overlap))?;
                let next = bucket_pages.get(assigned + 1).copied().unwrap_or(0);
                assigned += 1;
                let image = encode_bucket(page, page_size, txn, next, *free_txn, chunk)?;
                write(page, image)?;
                buckets.push(Bucket {
                    page,
                    free_txn: *free_txn,
                    pages: chunk.to_vec(),
                });
            }
        }
        Ok(Self { buckets })
    }
}

/// Число bucket-страниц для групп свободных страниц.
pub(crate) fn needed_buckets(groups: &[(u64, Vec<u32>)], capacity: usize) -> usize {
    groups
        .iter()
        .map(|(_, pages)| pages.len().div_ceil(capacity))
        .sum()
}

/// Ёмкость bucket'а в страницах.
///
/// # Errors
///
/// `Corrupt(Bounds)` — размер страницы меньше заголовка.
pub fn bucket_capacity(page_size: u32) -> Result<usize, ZoneFileError> {
    let usable = page_size
        .checked_sub(FREELIST_HEADER_SIZE)
        .ok_or_else(|| corrupt(CorruptDetail::OffsetOutOfRange))?;
    usize::try_from(usable / 4).map_err(|_| corrupt(CorruptDetail::OffsetOutOfRange))
}

fn encode_bucket(
    page_no: u32,
    page_size: u32,
    txn: u64,
    next: u32,
    free_txn: u64,
    pages: &[u32],
) -> Result<Vec<u8>, ZoneFileError> {
    let capacity = bucket_capacity(page_size)?;
    if pages.is_empty() || pages.len() > capacity {
        return Err(corrupt(CorruptDetail::Overlap));
    }
    let count = u32::try_from(pages.len()).map_err(|_| corrupt(CorruptDetail::Overlap))?;
    let payload_len = FREELIST_HEADER_SIZE
        .checked_add(
            count
                .checked_mul(4)
                .ok_or_else(|| corrupt(CorruptDetail::Overlap))?,
        )
        .ok_or_else(|| corrupt(CorruptDetail::Overlap))?;
    let len = usize::try_from(page_size).map_err(|_| corrupt(CorruptDetail::Overlap))?;
    let mut page = vec![0_u8; len];
    let ctx = EncodeContext {
        page_no,
        page_size,
        txn,
        lsn: 0,
    };
    node::write_page_header(&mut page, ctx, PAGE_TYPE_FREELIST, 0)?;
    wire::write_u32(&mut page, FL_OFF_NEXT, next);
    wire::write_u32(&mut page, FL_OFF_RESERVED0, 0);
    wire::write_u64(&mut page, FL_OFF_FREE_TXN, free_txn);
    wire::write_u32(&mut page, FL_OFF_COUNT, count);
    wire::write_u32(&mut page, FL_OFF_RESERVED1, 0);
    wire::write_u32(&mut page, PAGE_OFF_PAYLOAD_LEN, payload_len);
    for (index, &freed) in pages.iter().enumerate() {
        let off = FL_OFF_PAGES
            .checked_add(
                index
                    .checked_mul(4)
                    .ok_or_else(|| corrupt(CorruptDetail::Overlap))?,
            )
            .ok_or_else(|| corrupt(CorruptDetail::Overlap))?;
        wire::write_u32(&mut page, off, freed);
    }
    node::finish_page(&mut page, len)?;
    Ok(page)
}

fn decode_bucket(
    page: &[u8],
    page_no: u32,
    snapshot_txn: u64,
    page_size: u32,
    high_water: u32,
) -> Result<Bucket, ZoneFileError> {
    let header = PageHeader::decode(page, page_no, snapshot_txn, page_size)?;
    if header.page_type != PAGE_TYPE_FREELIST {
        return Err(corrupt(CorruptDetail::PageType));
    }
    let _next =
        wire::read_u32(page, FL_OFF_NEXT).ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
    let reserved0 =
        wire::read_u32(page, FL_OFF_RESERVED0).ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
    let free_txn =
        wire::read_u64(page, FL_OFF_FREE_TXN).ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
    let count =
        wire::read_u32(page, FL_OFF_COUNT).ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
    let reserved1 =
        wire::read_u32(page, FL_OFF_RESERVED1).ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
    let capacity = bucket_capacity(page_size)?;
    let count_usize = usize::try_from(count).map_err(|_| corrupt(CorruptDetail::Overlap))?;
    let expected_len = FREELIST_HEADER_SIZE
        .checked_add(
            count
                .checked_mul(4)
                .ok_or_else(|| corrupt(CorruptDetail::Overlap))?,
        )
        .ok_or_else(|| corrupt(CorruptDetail::Overlap))?;
    if reserved0 != 0
        || reserved1 != 0
        || count == 0
        || count_usize > capacity
        || free_txn < 2
        || free_txn > snapshot_txn
        || header.payload_len != expected_len
    {
        return Err(corrupt(CorruptDetail::Overlap));
    }
    let mut pages = Vec::with_capacity(count_usize);
    for index in 0..count_usize {
        let off = FL_OFF_PAGES
            .checked_add(
                index
                    .checked_mul(4)
                    .ok_or_else(|| corrupt(CorruptDetail::Overlap))?,
            )
            .ok_or_else(|| corrupt(CorruptDetail::Overlap))?;
        let freed = wire::read_u32(page, off).ok_or_else(|| corrupt(CorruptDetail::Truncated))?;
        if freed < crate::consts::PAGE_DATA_FIRST || freed >= high_water {
            return Err(corrupt(CorruptDetail::ChildRange));
        }
        pages.push(freed);
    }
    Ok(Bucket {
        page: page_no,
        free_txn,
        pages,
    })
}

fn corrupt(detail: CorruptDetail) -> ZoneFileError {
    ZoneFileError::corrupt(CorruptKind::FreelistCycle, None, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_capacity_matches_spec() {
        assert_eq!(bucket_capacity(4096).unwrap(), 1008);
        assert_eq!(bucket_capacity(8192).unwrap(), 2032);
        assert_eq!(bucket_capacity(16384).unwrap(), 4080);
    }

    #[test]
    fn bucket_roundtrip() {
        let pages = vec![13, 14, 15];
        let image = encode_bucket(40, 4096, 3, 0, 3, &pages).unwrap();
        assert_eq!(wire::read_u32(&image, 0), Some(PAGE_TYPE_FREELIST));
        assert_eq!(wire::read_u32(&image, 8), Some(40));
        assert_eq!(wire::read_u32(&image, 36), Some(64 + 4 * 3));
        assert_eq!(wire::read_u32(&image, 40), Some(0));
        assert_eq!(wire::read_u64(&image, 48), Some(3));
        assert_eq!(wire::read_u32(&image, 56), Some(3));
        assert_eq!(wire::read_u32(&image, 64), Some(13));
        assert_eq!(wire::read_u32(&image, 68), Some(14));
        assert_eq!(wire::read_u32(&image, 72), Some(15));
        let bucket = decode_bucket(&image, 40, 3, 4096, 100).unwrap();
        assert_eq!(bucket.page, 40);
        assert_eq!(bucket.free_txn, 3);
        assert_eq!(bucket.pages, pages);
    }

    #[test]
    fn load_validates_order_and_bucket_page_overlap() {
        use std::os::unix::fs::FileExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freelist.map");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.set_len(100 * 4096).unwrap();
        let map = FileMap::map_read(&file, 100 * 4096, crate::mem::HugePages::Never).unwrap();
        // Пишем два bucket'а: 20 -> 21, free_txn 2 и 3.
        let first = encode_bucket(20, 4096, 3, 21, 2, &[40, 41]).unwrap();
        let second = encode_bucket(21, 4096, 3, 0, 3, &[42]).unwrap();
        file.write_all_at(&first, 20 * 4096).unwrap();
        file.write_all_at(&second, 21 * 4096).unwrap();
        let loaded = Freelist::load(&map, 4096, 3, 100, 20, 2, 3, 21).unwrap();
        assert_eq!(loaded.entry_count(), 3);
        assert_eq!(loaded.bucket_count(), 2);
    }
}
