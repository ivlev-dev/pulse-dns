//! Per-zone пул освобождённых страниц и `is_reclaimable` (фаза B2a).
//!
//! Bucket-страница — `PAGE_TYPE_FREELIST` (`docs/spec/parallel-writes-v2.md`
//! §6.1): цепочка `free_head → next_bucket → …`, упорядоченная по `drop_txn`
//! возрастанию. Страница неизменяема: коммит с освобождениями пересобирает
//! цепочку в свежие страницы (COW), а старые образы попадают в группу
//! `drop_txn = V` этого же коммита.
//!
//! Правило выдачи — §6.2:
//!
//! ```text
//! is_reclaimable(drop_txn, D_z, RV_z, current_version) =
//!       drop_txn >= 2
//!    && drop_txn <  D_z
//!    && drop_txn <= RV_z
//!    && drop_txn <  current_version
//! ```
//!
//! `drop_txn < D_z` — строго: худшая восстановимая версия `D_z − 1`, поэтому
//! страница, освобождённая в `V`, выдаётся не раньше, чем durable станет
//! `V + 1`. `RV_z = min(D_z − 1, MP(z), freeze_epoch)` включает пины, поэтому
//! читатель версии `V` не увидит страницу, переиспользованную после `V`.

use std::fs::File;

use crate::checksum::verify_page_crc;
use crate::consts::{
    PAGE_OFF_CRC32C, PAGE_OFF_PAGE_NO, PAGE_OFF_PAGE_TYPE, PAGE_OFF_PAYLOAD_LEN, PAGE_OFF_TXN,
    PAGE_TYPE_FREELIST,
};
use crate::node::{self, EncodeContext};
use crate::parallel::consts::PAGE_SIZE_V2;
use crate::parallel::error::{ParallelError, V2CorruptKind};
use crate::parallel::geometry::Geometry;
use crate::parallel::ring::Ring;
use crate::parallel::root::RootEntry;
use crate::wire;

/// Смещение `next_bucket` в bucket-странице (§6.1).
pub(crate) const FREE_OFF_NEXT: usize = 40;
/// Смещение `owner_zone` (§6.1).
pub(crate) const FREE_OFF_OWNER: usize = 44;
/// Смещение `drop_txn` (§6.1).
pub(crate) const FREE_OFF_DROP_TXN: usize = 48;
/// Смещение `count` (§6.1).
pub(crate) const FREE_OFF_COUNT: usize = 56;
/// Смещение `flags` (§6.1).
pub(crate) const FREE_OFF_FLAGS: usize = 60;
/// Смещение массива `page_ids[]` (§6.1).
pub(crate) const FREE_OFF_PAGES: usize = 64;
/// Ёмкость bucket-страницы при `page_size = 4096`.
pub(crate) const FREE_BUCKET_CAPACITY: usize = (PAGE_SIZE_V2 as usize - FREE_OFF_PAGES) / 4;
/// Максимальное число bucket-страниц цепочки (защита от цикла при чтении).
pub(crate) const MAX_FREE_BUCKETS: u32 = 65_536;

const _: () = assert!(FREE_BUCKET_CAPACITY == 1008);
const _: () = assert!(FREE_OFF_PAGES == 64);

/// Условие выдачи страницы из пула (§6.2).
///
/// `durable_version` — `D_z` (версия durable-головы зоны), `reclaim_version` —
/// `RV_z`, `current_version` — версия коммита, который сейчас планируется.
#[must_use]
pub const fn is_reclaimable(
    drop_txn: u64,
    durable_version: u64,
    reclaim_version: u64,
    current_version: u64,
) -> bool {
    drop_txn >= 2
        && drop_txn < durable_version
        && drop_txn <= reclaim_version
        && drop_txn < current_version
}

/// Одна группа освобождённых страниц (`drop_txn` общий).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FreeBucket {
    /// Страница, на которой лежит образ группы.
    pub(crate) page: u32,
    /// Версия, в которой страницы освобождены.
    pub(crate) drop_txn: u64,
    /// Страницы группы (непустая).
    pub(crate) pages: Vec<u32>,
}

/// Декодированный образ bucket-страницы (без привязки к номеру группы).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BucketImage {
    /// `next_bucket` (0 — конец цепочки).
    pub(crate) next: u32,
    /// `drop_txn` группы.
    pub(crate) drop_txn: u64,
    /// `flags` (в B2a всегда 0).
    pub(crate) flags: u32,
    /// Страницы группы.
    pub(crate) pages: Vec<u32>,
}

/// Образы bucket-страниц: `(page_no, bytes)`.
pub(crate) type BucketImages = Vec<(u32, Vec<u8>)>;

/// Фрагмент группы, которому при COW-пересборке нужна отдельная страница.
struct BucketChunk<'a> {
    drop_txn: u64,
    pages: &'a [u32],
}

/// Цепочка bucket'ов одной зоны (в памяти, порядок `drop_txn` возрастает).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FreeChain {
    buckets: Vec<FreeBucket>,
    /// Страница-голова on-disk цепочки (`0` — пусто).
    ///
    /// Для COW-пересборки (single-process) это страница самой старой группы;
    /// для append-режима (multi-process) — самой новой. `buckets` всегда
    /// хранится в порядке `drop_txn` возрастания.
    head_page: u32,
}

impl FreeChain {
    /// Пустая цепочка.
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// Число свободных страниц.
    #[must_use]
    pub(crate) fn page_count(&self) -> usize {
        self.buckets.iter().map(|bucket| bucket.pages.len()).sum()
    }

    /// Голова цепочки (`0` — пусто).
    #[must_use]
    pub(crate) fn head(&self) -> u32 {
        if self.head_page != 0 {
            self.head_page
        } else {
            self.buckets.first().map_or(0, |bucket| bucket.page)
        }
    }

    /// Bucket'ы в порядке цепочки.
    #[must_use]
    pub(crate) fn buckets(&self) -> &[FreeBucket] {
        &self.buckets
    }

    /// Читает durable-цепочку из файла и проверяет инварианты.
    ///
    /// # Errors
    ///
    /// `Corrupt` — цикл, нарушение порядка `drop_txn`, чужой `owner_zone`,
    /// битый CRC/`payload_len`, дубли страниц или выход за `page_limit`.
    pub(crate) fn load(
        file: &File,
        geometry: &Geometry,
        zone: u32,
        head: &RootEntry,
    ) -> Result<Self, ParallelError> {
        let mut buckets = Vec::new();
        let mut page = head.free_head;
        let mut seen_buckets = std::collections::HashSet::new();
        let mut seen_pages = std::collections::HashSet::new();
        let ring = Ring::new(file, geometry);
        let mut hops = 0_u32;
        while page != 0 {
            hops = hops.saturating_add(1);
            if hops > MAX_FREE_BUCKETS || !seen_buckets.insert(page) {
                return Err(corrupt(page, V2CorruptKind::WatermarkRegression));
            }
            let raw = ring.read_page(page)?;
            let image = decode_bucket(&raw, page, zone, head.page_limit_at_commit)?;
            if image.drop_txn > head.version {
                return Err(corrupt(page, V2CorruptKind::WatermarkRegression));
            }
            for freed in &image.pages {
                if !seen_pages.insert(*freed) {
                    return Err(corrupt(*freed, V2CorruptKind::WatermarkRegression));
                }
            }
            buckets.push(FreeBucket {
                page,
                drop_txn: image.drop_txn,
                pages: image.pages,
            });
            page = image.next;
        }
        // Цепочка читается от `free_head`. В single-process режиме группы
        // идут по возрастанию `drop_txn` (COW-пересборка), в append-режиме
        // (multi-process) — по убыванию. Оба порядка валидны; смешанный —
        // порча. В памяти всегда ascending.
        let mut ascending = true;
        let mut descending = true;
        for pair in buckets.windows(2) {
            let (left, right) = match pair {
                [left, right] => (left.drop_txn, right.drop_txn),
                _ => continue,
            };
            if left > right {
                ascending = false;
            }
            if left < right {
                descending = false;
            }
        }
        if !ascending && !descending {
            return Err(corrupt(head.free_head, V2CorruptKind::WatermarkRegression));
        }
        if descending {
            buckets.reverse();
        }
        if buckets
            .iter()
            .any(|bucket| seen_pages.contains(&bucket.page))
        {
            return Err(corrupt(head.free_head, V2CorruptKind::WatermarkRegression));
        }
        Ok(Self {
            buckets,
            head_page: head.free_head,
        })
    }

    /// Строит in-memory цепочку из уже прочитанных образов (для тестов).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn from_buckets(buckets: Vec<FreeBucket>) -> Self {
        let head_page = buckets.first().map_or(0, |bucket| bucket.page);
        Self { buckets, head_page }
    }

    /// Добавляет группу `drop_txn` (сливает с существующей группой).
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница уже присутствует в пуле (double-free).
    pub(crate) fn push_group(
        &mut self,
        drop_txn: u64,
        pages: &[u32],
        data_first: u32,
    ) -> Result<(), ParallelError> {
        if pages.is_empty() {
            return Ok(());
        }
        for bucket in &self.buckets {
            for freed in &bucket.pages {
                if pages.contains(freed) {
                    return Err(corrupt(*freed, V2CorruptKind::WatermarkRegression));
                }
            }
        }
        for freed in pages {
            if *freed < data_first {
                return Err(corrupt(*freed, V2CorruptKind::Bounds));
            }
        }
        match self
            .buckets
            .binary_search_by_key(&drop_txn, |bucket| bucket.drop_txn)
        {
            Ok(index) => {
                if let Some(bucket) = self.buckets.get_mut(index) {
                    bucket.pages.extend_from_slice(pages);
                    return Ok(());
                }
            }
            Err(index) => self.buckets.insert(
                index,
                FreeBucket {
                    page: 0,
                    drop_txn,
                    pages: pages.to_vec(),
                },
            ),
        }
        Ok(())
    }

    /// Забирает одну выдаваемую страницу (самая старая подходящая группа).
    pub(crate) fn take_eligible(
        &mut self,
        durable_version: u64,
        reclaim_version: u64,
        current_version: u64,
    ) -> Option<u32> {
        for bucket in &mut self.buckets {
            if is_reclaimable(
                bucket.drop_txn,
                durable_version,
                reclaim_version,
                current_version,
            ) && let Some(page) = bucket.pages.pop()
            {
                return Some(page);
            }
        }
        None
    }

    /// Число bucket-страниц, нужных для текущих групп.
    #[must_use]
    pub(crate) fn needed_images(&self) -> usize {
        self.buckets
            .iter()
            .filter(|bucket| !bucket.pages.is_empty())
            .map(|bucket| bucket.pages.len().div_ceil(FREE_BUCKET_CAPACITY))
            .sum()
    }

    /// Число страниц под одну append-группу `pages` (multi-process).
    #[must_use]
    pub(crate) fn append_pages_needed(pages: usize) -> usize {
        pages.div_ceil(FREE_BUCKET_CAPACITY)
    }

    /// Планирует append-образы новой группы без изменения цепочки.
    ///
    /// On-disk цепочка в multi-режиме идёт по убыванию `drop_txn`: голова —
    /// новейшая группа, `next` последней страницы новой группы указывает на
    /// старый head. Установка в память — отдельный шаг
    /// [`FreeChain::install_group`] (после durable-фазы 1), поэтому неудачная
    /// подготовка не оставляет «половину» группы в пуле.
    ///
    /// # Errors
    ///
    /// `Corrupt` — не совпало число страниц.
    pub(crate) fn plan_append(
        &self,
        zone: u32,
        drop_txn: u64,
        freed: &[u32],
        page_ids: &[u32],
    ) -> Result<(u32, BucketImages), ParallelError> {
        if freed.is_empty() {
            return Ok((self.head(), Vec::new()));
        }
        let needed = Self::append_pages_needed(freed.len());
        if page_ids.len() != needed {
            return Err(corrupt(0, V2CorruptKind::WatermarkRegression));
        }
        let mut images = Vec::with_capacity(needed);
        for (index, chunk) in freed.chunks(FREE_BUCKET_CAPACITY).enumerate() {
            let Some(page) = page_ids.get(index).copied() else {
                return Err(corrupt(0, V2CorruptKind::WatermarkRegression));
            };
            let next = page_ids
                .get(index + 1)
                .copied()
                .unwrap_or_else(|| self.head());
            images.push((page, encode_bucket(page, zone, drop_txn, next, chunk)?));
        }
        Ok((
            page_ids.first().copied().unwrap_or_else(|| self.head()),
            images,
        ))
    }

    /// Устанавливает append-группу в память после записи/fsync её образов.
    ///
    /// Идемпотентна: повторный вызов с тем же `drop_txn` ничего не делает.
    ///
    /// # Errors
    ///
    /// `Corrupt` — страница уже присутствует в пуле.
    pub(crate) fn install_group(
        &mut self,
        drop_txn: u64,
        freed: &[u32],
        group_head: u32,
        data_first: u32,
    ) -> Result<(), ParallelError> {
        if freed.is_empty() {
            return Ok(());
        }
        if self
            .buckets
            .iter()
            .any(|bucket| bucket.drop_txn == drop_txn && bucket.page != 0)
        {
            return Ok(());
        }
        if group_head < data_first {
            return Err(corrupt(group_head, V2CorruptKind::Bounds));
        }
        let mut seen = std::collections::HashSet::new();
        for page in freed {
            if *page < data_first || !seen.insert(*page) {
                return Err(corrupt(*page, V2CorruptKind::Bounds));
            }
            if self
                .buckets
                .iter()
                .any(|bucket| bucket.pages.contains(page))
            {
                return Err(corrupt(*page, V2CorruptKind::WatermarkRegression));
            }
        }
        self.buckets.push(FreeBucket {
            page: group_head,
            drop_txn,
            pages: freed.to_vec(),
        });
        self.head_page = group_head;
        Ok(())
    }

    /// Назначает новые bucket-страницы группам и возвращает образы для записи.
    ///
    /// `pages.len()` обязан совпадать с [`FreeChain::needed_images`].
    /// Возвращает `(new_head, images)`; цепочка обновляется на новые страницы.
    ///
    /// `descending` задаёт порядок on-disk цепочки: `false` — по возрастанию
    /// `drop_txn` (COW single-process, голова — самая старая группа),
    /// `true` — по убыванию (append-режим multi: голова — самая новая группа).
    /// Смешивать порядки в одной цепочке нельзя: загрузка отвергает такую
    /// цепочку как `WatermarkRegression`.
    ///
    /// # Errors
    ///
    /// `Corrupt` — несовпадение числа образов/пустая группа.
    pub(crate) fn encode_images(
        &mut self,
        zone: u32,
        pages: &[u32],
        descending: bool,
    ) -> Result<(u32, BucketImages), ParallelError> {
        let needed = self.needed_images();
        if pages.len() != needed {
            return Err(corrupt(0, V2CorruptKind::WatermarkRegression));
        }
        // Нарезаем группы на будущие страницы в порядке возрастания
        // `drop_txn` (внутри группы — по порядку страниц). `buckets` всегда
        // хранится по возрастанию, поэтому этот список — канонический порядок
        // для памяти; on-disk цепочка может идти и в обратном направлении.
        let mut chunks: Vec<BucketChunk<'_>> = Vec::with_capacity(needed);
        for bucket in &self.buckets {
            if bucket.pages.is_empty() {
                // Пустой bucket уже отдан в группу `version` (его страница
                // была добавлена до пересборки).
                continue;
            }
            let mut offset = 0_usize;
            while offset < bucket.pages.len() {
                let end = offset
                    .saturating_add(FREE_BUCKET_CAPACITY)
                    .min(bucket.pages.len());
                chunks.push(BucketChunk {
                    drop_txn: bucket.drop_txn,
                    pages: bucket.pages.get(offset..end).unwrap_or(&[]),
                });
                offset = end;
            }
        }
        // Порядок обхода = порядок on-disk цепочки: для убывающей (multi)
        // начинаем с самой новой группы.
        let mut order: Vec<usize> = (0..chunks.len()).collect();
        if descending {
            order.reverse();
        }
        let mut assigned = 0_usize;
        let mut images = Vec::with_capacity(needed);
        let mut new_pages: Vec<u32> = vec![0; chunks.len()];
        for index in order {
            let Some(chunk) = chunks.get(index) else {
                continue;
            };
            let page = *pages
                .get(assigned)
                .ok_or_else(|| corrupt(0, V2CorruptKind::WatermarkRegression))?;
            assigned += 1;
            if let Some(slot) = new_pages.get_mut(index) {
                *slot = page;
            }
            let next = pages.get(assigned).copied().unwrap_or(0);
            let raw = encode_bucket(page, zone, chunk.drop_txn, next, chunk.pages)?;
            images.push((page, raw));
        }
        self.buckets = chunks
            .iter()
            .zip(new_pages)
            .map(|(chunk, page)| FreeBucket {
                page,
                drop_txn: chunk.drop_txn,
                pages: chunk.pages.to_vec(),
            })
            .collect();
        self.head_page = pages.first().copied().unwrap_or(0);
        Ok((self.head(), images))
    }
}

/// Кодирует bucket-страницу (4096 Б) с CRC и `owner_zone`.
///
/// # Errors
///
/// `Corrupt` — пустой/слишком большой набор страниц.
pub(crate) fn encode_bucket(
    page_no: u32,
    owner_zone: u32,
    drop_txn: u64,
    next: u32,
    pages: &[u32],
) -> Result<Vec<u8>, ParallelError> {
    if pages.is_empty() || pages.len() > FREE_BUCKET_CAPACITY {
        return Err(corrupt(page_no, V2CorruptKind::Bounds));
    }
    let count = u32::try_from(pages.len()).map_err(|_| corrupt(page_no, V2CorruptKind::Bounds))?;
    let payload_len = u32::try_from(FREE_OFF_PAGES)
        .ok()
        .and_then(|base| base.checked_add(count.checked_mul(4)?))
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Bounds))?;
    let mut page = vec![0_u8; PAGE_SIZE_V2 as usize];
    node::write_page_header(
        &mut page,
        EncodeContext {
            page_no,
            page_size: PAGE_SIZE_V2,
            txn: drop_txn,
            lsn: 0,
        },
        PAGE_TYPE_FREELIST,
        0,
    )
    .map_err(|_| corrupt(page_no, V2CorruptKind::Bounds))?;
    let _ = wire::write_u32(&mut page, FREE_OFF_NEXT, next);
    let _ = wire::write_u32(&mut page, FREE_OFF_OWNER, owner_zone);
    let _ = wire::write_u64(&mut page, FREE_OFF_DROP_TXN, drop_txn);
    let _ = wire::write_u32(&mut page, FREE_OFF_COUNT, count);
    let _ = wire::write_u32(&mut page, FREE_OFF_FLAGS, 0);
    let _ = wire::write_u32(&mut page, PAGE_OFF_PAYLOAD_LEN, payload_len);
    for (index, freed) in pages.iter().enumerate() {
        let offset = FREE_OFF_PAGES
            .checked_add(index.saturating_mul(4))
            .ok_or_else(|| corrupt(page_no, V2CorruptKind::Bounds))?;
        let _ = wire::write_u32(&mut page, offset, *freed);
    }
    node::finish_page(&mut page, PAGE_SIZE_V2 as usize)
        .map_err(|_| corrupt(page_no, V2CorruptKind::Bounds))?;
    Ok(page)
}

/// Декодирует и валидирует bucket-страницу.
///
/// # Errors
///
/// `Corrupt` — тип/CRC/`owner_zone`/`payload_len`/границы.
pub(crate) fn decode_bucket(
    raw: &[u8],
    page_no: u32,
    owner_zone: u32,
    page_limit: u32,
) -> Result<BucketImage, ParallelError> {
    let page = raw
        .get(..PAGE_SIZE_V2 as usize)
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Truncated))?;
    if wire::read_u32(page, PAGE_OFF_PAGE_TYPE) != Some(PAGE_TYPE_FREELIST) {
        return Err(corrupt(page_no, V2CorruptKind::Bounds));
    }
    if wire::read_u32(page, PAGE_OFF_PAGE_NO) != Some(page_no) {
        return Err(corrupt(page_no, V2CorruptKind::Bounds));
    }
    let stored_crc = wire::read_u32(page, PAGE_OFF_CRC32C)
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Truncated))?;
    if !verify_page_crc(page, PAGE_OFF_CRC32C, stored_crc) {
        return Err(corrupt(page_no, V2CorruptKind::Bounds));
    }
    let drop_txn = wire::read_u64(page, PAGE_OFF_TXN)
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Truncated))?;
    let next = wire::read_u32(page, FREE_OFF_NEXT)
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Truncated))?;
    let owner = wire::read_u32(page, FREE_OFF_OWNER)
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Truncated))?;
    let stored_drop = wire::read_u64(page, FREE_OFF_DROP_TXN)
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Truncated))?;
    let count = wire::read_u32(page, FREE_OFF_COUNT)
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Truncated))?;
    let flags = wire::read_u32(page, FREE_OFF_FLAGS)
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Truncated))?;
    let payload_len = wire::read_u32(page, PAGE_OFF_PAYLOAD_LEN)
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Truncated))?;
    let count = usize::try_from(count).map_err(|_| corrupt(page_no, V2CorruptKind::Bounds))?;
    let expected_payload = FREE_OFF_PAGES
        .checked_add(count.saturating_mul(4))
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| corrupt(page_no, V2CorruptKind::Bounds))?;
    if owner != owner_zone
        || stored_drop != drop_txn
        || flags != 0
        || drop_txn < 2
        || count == 0
        || count > FREE_BUCKET_CAPACITY
        || payload_len != expected_payload
        || (next != 0 && next >= page_limit)
    {
        return Err(corrupt(page_no, V2CorruptKind::Bounds));
    }
    let mut pages = Vec::with_capacity(count);
    for index in 0..count {
        let offset = FREE_OFF_PAGES
            .checked_add(index.saturating_mul(4))
            .ok_or_else(|| corrupt(page_no, V2CorruptKind::Bounds))?;
        let freed =
            wire::read_u32(page, offset).ok_or_else(|| corrupt(page_no, V2CorruptKind::Bounds))?;
        if freed == 0 || freed >= page_limit {
            return Err(corrupt(page_no, V2CorruptKind::Bounds));
        }
        pages.push(freed);
    }
    Ok(BucketImage {
        next,
        drop_txn,
        flags,
        pages,
    })
}

fn corrupt(page: u32, kind: V2CorruptKind) -> ParallelError {
    ParallelError::Corrupt {
        kind,
        page: Some(page),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reclaim_boundaries_are_strict() {
        assert!(!is_reclaimable(1, u64::MAX, u64::MAX, u64::MAX));
        // drop_txn == D_z: запись V ещё не переживёт откат на V−1.
        assert!(!is_reclaimable(3, 3, u64::MAX, 9));
        assert!(is_reclaimable(2, 3, 3, 9));
        // Пин ниже drop_txn задерживает выдачу.
        assert!(!is_reclaimable(3, 9, 2, 9));
        // Текущий коммит не переиспользует только что освобождённое.
        assert!(!is_reclaimable(4, 9, 9, 4));
        assert!(is_reclaimable(4, 9, 9, 5));
    }

    #[test]
    fn bucket_roundtrip_layout() {
        let raw = encode_bucket(17, 42, 7, 0, &[100, 101, 102]).unwrap();
        assert_eq!(wire::read_u32(&raw, 0), Some(PAGE_TYPE_FREELIST));
        assert_eq!(wire::read_u32(&raw, 8), Some(17));
        assert_eq!(wire::read_u64(&raw, 16), Some(7));
        assert_eq!(wire::read_u32(&raw, 40), Some(0));
        assert_eq!(wire::read_u32(&raw, 44), Some(42));
        assert_eq!(wire::read_u64(&raw, 48), Some(7));
        assert_eq!(wire::read_u32(&raw, 56), Some(3));
        assert_eq!(wire::read_u32(&raw, 60), Some(0));
        assert_eq!(wire::read_u32(&raw, 64), Some(100));
        assert_eq!(wire::read_u32(&raw, 72), Some(102));
        let image = decode_bucket(&raw, 17, 42, 1000).unwrap();
        assert_eq!(image.drop_txn, 7);
        assert_eq!(image.pages, vec![100, 101, 102]);
    }

    #[test]
    fn bucket_rejects_foreign_owner_and_bit_rot() {
        let raw = encode_bucket(17, 42, 7, 0, &[100]).unwrap();
        assert!(decode_bucket(&raw, 17, 43, 1000).is_err());
        assert!(decode_bucket(&raw, 18, 42, 1000).is_err());
        let mut broken = raw.clone();
        let byte = broken.get_mut(48).copied().unwrap_or(0) ^ 1;
        if let Some(slot) = broken.get_mut(48) {
            *slot = byte;
        }
        assert!(decode_bucket(&broken, 17, 42, 1000).is_err());
        assert!(decode_bucket(&raw, 17, 42, 50).is_err());
    }

    #[test]
    fn chain_selects_oldest_eligible_and_detects_duplicates() {
        let mut chain = FreeChain::from_buckets(vec![
            FreeBucket {
                page: 10,
                drop_txn: 3,
                pages: vec![100, 101],
            },
            FreeBucket {
                page: 11,
                drop_txn: 5,
                pages: vec![102],
            },
        ]);
        // D_z = 4: группа 5 ещё не durable-освобождена, группа 3 — да.
        assert_eq!(chain.take_eligible(4, 3, 9), Some(101));
        assert_eq!(chain.take_eligible(4, 3, 9), Some(100));
        assert_eq!(chain.take_eligible(4, 3, 9), None);
        assert_eq!(chain.take_eligible(6, 5, 9), Some(102));
        let mut chain = FreeChain::from_buckets(vec![FreeBucket {
            page: 10,
            drop_txn: 3,
            pages: vec![100],
        }]);
        assert!(chain.push_group(6, &[100], 42).is_err());
        assert!(chain.push_group(6, &[41], 42).is_err());
    }

    #[test]
    fn encode_images_descending_keeps_append_order() {
        let mut chain = FreeChain::from_buckets(vec![
            FreeBucket {
                page: 10,
                drop_txn: 3,
                pages: vec![100, 101],
            },
            FreeBucket {
                page: 11,
                drop_txn: 5,
                pages: vec![102],
            },
        ]);
        let needed = chain.needed_images();
        assert_eq!(needed, 2);
        let (head, images) = chain.encode_images(7, &[200, 201], true).unwrap();
        // Голова — самая новая группа (drop_txn = 5), её next — старая.
        assert_eq!(head, 200);
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].0, 200);
        assert_eq!(wire::read_u32(&images[0].1, FREE_OFF_NEXT), Some(201));
        assert_eq!(wire::read_u64(&images[0].1, 48), Some(5));
        assert_eq!(images[1].0, 201);
        assert_eq!(wire::read_u32(&images[1].1, FREE_OFF_NEXT), Some(0));
        assert_eq!(wire::read_u64(&images[1].1, 48), Some(3));
        // В памяти группы по-прежнему по возрастанию `drop_txn`.
        assert_eq!(
            chain
                .buckets()
                .iter()
                .map(|bucket| bucket.drop_txn)
                .collect::<Vec<_>>(),
            vec![3, 5]
        );
        assert_eq!(chain.head(), 200);
    }

    #[test]
    fn encode_images_assigns_pages_in_order() {
        let mut chain = FreeChain::from_buckets(vec![
            FreeBucket {
                page: 10,
                drop_txn: 3,
                pages: vec![100, 101],
            },
            FreeBucket {
                page: 11,
                drop_txn: 5,
                pages: vec![102],
            },
        ]);
        let needed = chain.needed_images();
        assert_eq!(needed, 2);
        let (head, images) = chain.encode_images(7, &[200, 201], false).unwrap();
        assert_eq!(head, 200);
        assert_eq!(images.len(), 2);
        assert_eq!(images[0].0, 200);
        assert_eq!(wire::read_u32(&images[0].1, FREE_OFF_NEXT), Some(201));
        assert_eq!(wire::read_u32(&images[0].1, FREE_OFF_OWNER), Some(7));
        assert_eq!(wire::read_u64(&images[0].1, 48), Some(3));
        assert_eq!(chain.head(), 200);
        assert_eq!(chain.page_count(), 3);
    }
}
