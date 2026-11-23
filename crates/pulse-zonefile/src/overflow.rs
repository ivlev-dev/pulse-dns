//! Overflow-цепочки RDATA (`zonefile-v1.md` §11.4).
//!
//! Цепочка — единый байтовый поток, нарезанный по границам страниц. Ни RR,
//! ни его RDATA не обязаны совпадать с границей: `payload` из
//! `{u16 rdlength; u8 rdata[rdlength]} * rr_count` (big-endian префиксы длин,
//! DNS wire) может разрываться где угодно.
//! Инвариант `sum(data_len) == rdlen + 2*rr_count` проверяется при чтении
//! с `checked_add`; цикл или цепочка длиннее [`MAX_OVERFLOW_PAGES`] — ошибка.
//!
//! Доступ к RDATA одного RR — [`RdataRef`]: `len`, `chunks`, `copy_into`
//! (без частичной записи при недостатке буфера). Материализации всего набора нет.

use std::fmt;

use crate::consts::{
    MAX_OVERFLOW_PAGES, MAX_RRSET_PAYLOAD, OVERFLOW_HEADER_SIZE, PAGE_OFF_PAYLOAD_LEN,
    PAGE_TYPE_OVERFLOW,
};
use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::node::{self, EncodeContext};
use crate::page::PageHeader;
use crate::tree::PageIo;
use crate::wire;

/// Лимит страниц цепочки в виде `usize`.
pub const OVERFLOW_PAGE_LIMIT: usize = 64;

const _: () = assert!(OVERFLOW_PAGE_LIMIT == MAX_OVERFLOW_PAGES as usize);

/// Ошибка «буфер меньше RDATA».
///
/// `copy_into` не выполняет частичную запись: при ошибке `dst` не изменяется.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall {
    /// Требуется байт.
    pub needed: usize,
    /// Доступно байт.
    pub available: usize,
}

impl fmt::Display for BufferTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "buffer too small: need {} bytes, have {}",
            self.needed, self.available
        )
    }
}

impl std::error::Error for BufferTooSmall {}

fn corrupt(page: Option<u32>, detail: CorruptDetail) -> ZoneFileError {
    ZoneFileError::corrupt(CorruptKind::BadRdata, page, detail)
}

fn expected_stream_len(rdlen: u16, rr_count: u16) -> Result<u32, ZoneFileError> {
    let extra = u32::from(rr_count)
        .checked_mul(2)
        .ok_or_else(|| corrupt(None, CorruptDetail::RdataSum))?;
    u32::from(rdlen)
        .checked_add(extra)
        .filter(|&total| total <= MAX_RRSET_PAYLOAD)
        .ok_or_else(|| corrupt(None, CorruptDetail::RdataSum))
}

/// Записывает payload в новую overflow-цепочку.
///
/// Возвращает номер первой страницы. Страницы цепочки не освобождаются;
/// освобождение старой цепочки — забота вызывающего ([`free_chain`]).
///
/// # Errors
///
/// `RrsetTooLarge` — payload пуст или больше [`MAX_RRSET_PAYLOAD`];
/// `Corrupt(BadRdata)` — не хватает места/цепочка длиннее лимита;
/// ошибки `PageIo`.
pub fn write_chain<P: PageIo + ?Sized>(
    io: &mut P,
    txn: u64,
    payload: &[u8],
) -> Result<u32, ZoneFileError> {
    let page_size = io.page_size();
    let header_size = usize::try_from(OVERFLOW_HEADER_SIZE)
        .map_err(|_| corrupt(None, CorruptDetail::OffsetOutOfRange))?;
    let page_size_usize =
        usize::try_from(page_size).map_err(|_| corrupt(None, CorruptDetail::OffsetOutOfRange))?;
    let usable = page_size_usize
        .checked_sub(header_size)
        .filter(|&usable| usable > 0)
        .ok_or_else(|| corrupt(None, CorruptDetail::OffsetOutOfRange))?;
    let total = u32::try_from(payload.len())
        .ok()
        .filter(|&total| total > 0 && total <= MAX_RRSET_PAYLOAD)
        .ok_or(ZoneFileError::RrsetTooLarge)?;
    let usable_u32 = u32::try_from(usable).map_err(|_| ZoneFileError::RrsetTooLarge)?;
    let page_count =
        usize::try_from(total.div_ceil(usable_u32)).map_err(|_| ZoneFileError::RrsetTooLarge)?;
    if page_count == 0 || page_count > OVERFLOW_PAGE_LIMIT {
        return Err(ZoneFileError::RrsetTooLarge);
    }
    let mut pages = Vec::with_capacity(page_count);
    for _ in 0..page_count {
        pages.push(io.alloc_page()?);
    }
    let mut offset = 0_usize;
    for (index, &page_no) in pages.iter().enumerate() {
        let remaining = payload.len().saturating_sub(offset);
        let data_len = remaining.min(usable);
        let data = payload
            .get(offset..offset + data_len)
            .ok_or_else(|| corrupt(Some(page_no), CorruptDetail::OverflowChain))?;
        let next = pages.get(index + 1).copied().unwrap_or(0);
        let mut page = vec![0_u8; page_size_usize];
        let ctx = EncodeContext {
            page_no,
            page_size,
            txn,
            lsn: 0,
        };
        node::write_page_header(&mut page, ctx, PAGE_TYPE_OVERFLOW, 0)?;
        node::put_u32(&mut page, 40, next)?;
        node::put_u32(
            &mut page,
            44,
            u32::try_from(data_len)
                .map_err(|_| corrupt(Some(page_no), CorruptDetail::OverflowChain))?,
        )?;
        page.get_mut(header_size..header_size + data_len)
            .ok_or_else(|| corrupt(Some(page_no), CorruptDetail::OverflowChain))?
            .copy_from_slice(data);
        node::put_u32(
            &mut page,
            PAGE_OFF_PAYLOAD_LEN,
            u32::try_from(header_size + data_len)
                .map_err(|_| corrupt(Some(page_no), CorruptDetail::OverflowChain))?,
        )?;
        node::finish_page(&mut page, page_size_usize)?;
        io.write_page(page_no, &page)?;
        offset += data_len;
    }
    pages.first().copied().ok_or(ZoneFileError::RrsetTooLarge)
}

/// Освобождает страницы цепочки (в фазе 2 — `PageIo::free_page`, обычно no-op).
///
/// # Errors
///
/// `Corrupt(BadRdata)` — цикл или цепочка длиннее лимита; ошибки `PageIo`.
pub fn free_chain<P: PageIo + ?Sized>(io: &mut P, first_page: u32) -> Result<(), ZoneFileError> {
    let mut page_no = first_page;
    let mut visited = 0_usize;
    while page_no != 0 {
        visited += 1;
        if visited > OVERFLOW_PAGE_LIMIT {
            return Err(corrupt(Some(page_no), CorruptDetail::Cycle));
        }
        let page = io.read_page(page_no)?;
        let next = wire::read_u32(page, 40)
            .ok_or_else(|| corrupt(Some(page_no), CorruptDetail::Truncated))?;
        io.free_page(page_no)?;
        page_no = next;
    }
    Ok(())
}

/// Прочитанный `RRset` из overflow-цепочки.
///
/// Содержит срезы страниц (zero-copy) и позволяет получить RDATA одного RR
/// через [`OverflowRrset::rr`].
#[derive(Debug, Clone)]
pub struct OverflowRrset<'a> {
    segments: [&'a [u8]; OVERFLOW_PAGE_LIMIT],
    segment_count: usize,
    stream_len: u32,
    rr_count: u16,
    rdlen: u16,
}

impl<'a> OverflowRrset<'a> {
    /// Читает и валидирует цепочку.
    ///
    /// Проверки: `PageHeader` (тип/CRC/`txn`/`payload_len`), границы `data_len`,
    /// отсутствие циклов (лимит страниц), `sum(data_len) == rdlen + 2*rr_count`
    /// и `sum(rdlength) == rdlen`.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadRdata)` — любое нарушение цепочки или сумм;
    /// `Corrupt(Bounds)` — неверный тип/границы страницы.
    pub fn decode<P: PageIo + ?Sized>(
        io: &'a P,
        txn: u64,
        first_page: u32,
        rdlen: u16,
        rr_count: u16,
    ) -> Result<Self, ZoneFileError> {
        if first_page == 0 {
            return Err(corrupt(None, CorruptDetail::OverflowChain));
        }
        let expected = expected_stream_len(rdlen, rr_count)?;
        let page_size = io.page_size();
        let page_size_usize = usize::try_from(page_size)
            .map_err(|_| corrupt(None, CorruptDetail::OffsetOutOfRange))?;
        let header_size = usize::try_from(OVERFLOW_HEADER_SIZE)
            .map_err(|_| corrupt(None, CorruptDetail::OffsetOutOfRange))?;
        let mut segments: [&'a [u8]; OVERFLOW_PAGE_LIMIT] = [&[]; OVERFLOW_PAGE_LIMIT];
        let mut segment_count = 0_usize;
        let mut page_no = first_page;
        let mut sum = 0_u32;
        while page_no != 0 {
            if segment_count >= OVERFLOW_PAGE_LIMIT {
                return Err(corrupt(Some(page_no), CorruptDetail::Cycle));
            }
            let page = io.read_page(page_no)?;
            let header = PageHeader::decode(page, page_no, txn, page_size)?;
            if header.page_type != PAGE_TYPE_OVERFLOW {
                return Err(ZoneFileError::corrupt(
                    CorruptKind::Bounds,
                    Some(page_no),
                    CorruptDetail::PageType,
                ));
            }
            let next = wire::read_u32(page, 40)
                .ok_or_else(|| corrupt(Some(page_no), CorruptDetail::Truncated))?;
            let data_len = wire::read_u32(page, 44)
                .ok_or_else(|| corrupt(Some(page_no), CorruptDetail::Truncated))?;
            let data_len_usize = usize::try_from(data_len)
                .map_err(|_| corrupt(Some(page_no), CorruptDetail::OverflowChain))?;
            let expected_payload = u32::try_from(header_size)
                .ok()
                .and_then(|head| head.checked_add(data_len))
                .ok_or_else(|| corrupt(Some(page_no), CorruptDetail::OverflowChain))?;
            if header.payload_len != expected_payload
                || data_len_usize > page_size_usize.saturating_sub(header_size)
            {
                return Err(corrupt(Some(page_no), CorruptDetail::OverflowChain));
            }
            let data = page
                .get(header_size..header_size + data_len_usize)
                .ok_or_else(|| corrupt(Some(page_no), CorruptDetail::OverflowChain))?;
            if let Some(slot) = segments.get_mut(segment_count) {
                *slot = data;
            }
            segment_count += 1;
            sum = sum
                .checked_add(data_len)
                .ok_or_else(|| corrupt(Some(page_no), CorruptDetail::RdataSum))?;
            if sum > expected {
                return Err(corrupt(Some(page_no), CorruptDetail::RdataSum));
            }
            page_no = next;
        }
        if sum != expected {
            return Err(corrupt(None, CorruptDetail::RdataSum));
        }
        let rrset = Self {
            segments,
            segment_count,
            stream_len: expected,
            rr_count,
            rdlen,
        };
        rrset.validate_records()?;
        Ok(rrset)
    }

    /// Число RR.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.rr_count)
    }

    /// Истина, если RR нет (недостижимо для валидного набора).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rr_count == 0
    }

    /// Длина байтового потока (`rdlen + 2*rr_count`).
    #[must_use]
    pub const fn stream_len(&self) -> u32 {
        self.stream_len
    }

    /// `rdlen` набора.
    #[must_use]
    pub const fn rdlen(&self) -> u16 {
        self.rdlen
    }

    /// Срезы сегментов цепочки.
    fn segment_slice(&self) -> &[&'a [u8]] {
        self.segments.get(..self.segment_count).unwrap_or(&[])
    }

    fn validate_records(&self) -> Result<(), ZoneFileError> {
        let segments = self.segment_slice();
        let mut cursor = StreamCursor::new(segments);
        let mut sum = 0_u32;
        for _ in 0..self.rr_count {
            let length = cursor
                .read_u16()
                .ok_or_else(|| corrupt(None, CorruptDetail::RdataSum))?;
            sum = sum
                .checked_add(u32::from(length))
                .ok_or_else(|| corrupt(None, CorruptDetail::RdataSum))?;
            cursor
                .skip(usize::from(length))
                .ok_or_else(|| corrupt(None, CorruptDetail::RdataSum))?;
        }
        if sum != u32::from(self.rdlen) || !cursor.is_at_end() {
            return Err(corrupt(None, CorruptDetail::RdataSum));
        }
        Ok(())
    }

    /// RDATA RR по индексу (zero-copy).
    ///
    /// # Errors
    ///
    /// `Corrupt(BadRdata)` — цепочка/длины не сходятся (недостижимо после
    /// `decode`); индекс вне диапазона возвращает `Ok(None)`.
    pub fn rr(&self, index: u16) -> Result<Option<RdataRef<'_>>, ZoneFileError> {
        if index >= self.rr_count {
            return Ok(None);
        }
        let segments = self.segment_slice();
        let mut cursor = StreamCursor::new(segments);
        for _ in 0..index {
            let length = cursor
                .read_u16()
                .ok_or_else(|| corrupt(None, CorruptDetail::RdataSum))?;
            cursor
                .skip(usize::from(length))
                .ok_or_else(|| corrupt(None, CorruptDetail::RdataSum))?;
        }
        let length = cursor
            .read_u16()
            .ok_or_else(|| corrupt(None, CorruptDetail::RdataSum))?;
        let offset = cursor.position();
        Ok(Some(RdataRef {
            segments: self.segments,
            segment_count: self.segment_count,
            offset,
            len: length,
        }))
    }

    /// Сравнивает поток цепочки с `bytes` без материализации.
    #[must_use]
    pub fn stream_matches(&self, bytes: &[u8]) -> bool {
        if u32::try_from(bytes.len()).ok() != Some(self.stream_len) {
            return false;
        }
        let mut offset = 0_usize;
        for segment in self.segment_slice() {
            let end = offset + segment.len();
            let Some(expected) = bytes.get(offset..end) else {
                return false;
            };
            if *segment != expected {
                return false;
            }
            offset = end;
        }
        offset == bytes.len()
    }
}

/// Курсор по байтовому потоку из сегментов.
#[derive(Debug, Clone)]
struct StreamCursor<'a> {
    segments: &'a [&'a [u8]],
    index: usize,
    offset: usize,
    absolute: usize,
}

impl<'a> StreamCursor<'a> {
    const fn new(segments: &'a [&'a [u8]]) -> Self {
        Self {
            segments,
            index: 0,
            offset: 0,
            absolute: 0,
        }
    }

    fn position(&self) -> usize {
        self.absolute
    }

    fn read_u16(&mut self) -> Option<u16> {
        let mut bytes = [0_u8; 2];
        for slot in &mut bytes {
            loop {
                let segment = *self.segments.get(self.index)?;
                if let Some(&byte) = segment.get(self.offset) {
                    *slot = byte;
                    self.offset += 1;
                    self.absolute += 1;
                    break;
                }
                self.index += 1;
                self.offset = 0;
            }
        }
        Some(u16::from_be_bytes(bytes))
    }

    fn skip(&mut self, mut length: usize) -> Option<()> {
        while length > 0 {
            let segment = *self.segments.get(self.index)?;
            let available = segment.len().saturating_sub(self.offset);
            if length < available {
                self.offset += length;
                self.absolute += length;
                return Some(());
            }
            length -= available;
            self.absolute += available;
            self.index += 1;
            self.offset = 0;
            if length == 0 {
                return Some(());
            }
        }
        Some(())
    }

    fn is_at_end(&self) -> bool {
        self.segments
            .get(self.index)
            .is_none_or(|segment| self.offset == segment.len())
    }
}

/// RDATA одного RR внутри overflow-цепочки.
///
/// Значение владеет списком сегментов (срезы в страницы `PageIo`), поэтому
/// не заимствует [`OverflowRrset`] и может храниться отдельно.
#[derive(Debug, Clone, Copy)]
pub struct RdataRef<'a> {
    segments: [&'a [u8]; OVERFLOW_PAGE_LIMIT],
    segment_count: usize,
    offset: usize,
    len: u16,
}

impl<'a> RdataRef<'a> {
    /// Длина RDATA (`rdlength`).
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Истина для `rdlength = 0`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn segment_slice(&self) -> &[&'a [u8]] {
        self.segments.get(..self.segment_count).unwrap_or(&[])
    }

    /// Непрерывный срез, если RDATA целиком лежит в одном сегменте.
    ///
    /// Для overflow это оптимизация: вызывающий обязан работать и через
    /// [`RdataRef::chunks`] / [`RdataRef::copy_into`].
    #[must_use]
    pub fn as_slice(&self) -> Option<&'a [u8]> {
        let (index, start) = locate(self.segment_slice(), self.offset)?;
        let segment = *self.segments.get(index)?;
        segment.get(start..start + usize::from(self.len))
    }

    /// Непрерывные куски RDATA в порядке потока; сумма длин == [`RdataRef::len`].
    #[must_use]
    pub fn chunks(&self) -> RdataChunks<'a> {
        let (index, start) =
            locate(self.segment_slice(), self.offset).unwrap_or((self.segment_count, 0));
        RdataChunks {
            segments: self.segments,
            segment_count: self.segment_count,
            index,
            offset: start,
            remaining: usize::from(self.len),
        }
    }

    /// Копирует ровно [`RdataRef::len`] байт в `dst`.
    ///
    /// # Errors
    ///
    /// [`BufferTooSmall`] — `dst.len() < len`; `dst` при этом не изменяется.
    pub fn copy_into(&self, dst: &mut [u8]) -> Result<usize, BufferTooSmall> {
        let len = usize::from(self.len);
        if dst.len() < len {
            return Err(BufferTooSmall {
                needed: len,
                available: dst.len(),
            });
        }
        let mut written = 0_usize;
        for chunk in self.chunks() {
            let end = written + chunk.len();
            if let Some(slot) = dst.get_mut(written..end) {
                slot.copy_from_slice(chunk);
            }
            written = end;
        }
        Ok(written)
    }
}

/// Итератор непрерывных кусков RDATA.
#[derive(Debug, Clone)]
pub struct RdataChunks<'a> {
    segments: [&'a [u8]; OVERFLOW_PAGE_LIMIT],
    segment_count: usize,
    index: usize,
    offset: usize,
    remaining: usize,
}

impl<'a> Iterator for RdataChunks<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.remaining == 0 || self.index >= self.segment_count {
                return None;
            }
            let segment = *self.segments.get(self.index)?;
            if self.offset >= segment.len() {
                self.index += 1;
                self.offset = 0;
                continue;
            }
            let available = segment.len().saturating_sub(self.offset);
            let take = available.min(self.remaining);
            let chunk = segment.get(self.offset..self.offset + take)?;
            self.offset += take;
            self.remaining -= take;
            return Some(chunk);
        }
    }
}

fn locate(segments: &[&[u8]], position: usize) -> Option<(usize, usize)> {
    let mut base = 0_usize;
    for (index, segment) in segments.iter().enumerate() {
        let end = base.checked_add(segment.len())?;
        if position < end {
            return Some((index, position - base));
        }
        base = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::PAGE_SIZE_DEFAULT;
    use crate::tree::{MemoryStore, PageIo};

    fn payload(rrs: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for rdata in rrs {
            out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            out.extend_from_slice(rdata);
        }
        out
    }

    #[test]
    fn roundtrip_two_large_rrs_splits_rdata() {
        let first = vec![0xAA_u8; 6000];
        let second = vec![0xBB_u8; 6000];
        let stream = payload(&[&first, &second]);
        let mut store = MemoryStore::new(4096).unwrap();
        let first_page = write_chain(&mut store, 2, &stream).unwrap();
        let rrset = OverflowRrset::decode(&store, 2, first_page, 12_000, 2).unwrap();
        assert_eq!(rrset.len(), 2);
        let rr2 = rrset.rr(1).unwrap().unwrap();
        assert_eq!(rr2.len(), 6000);
        let chunks: Vec<_> = rr2.chunks().collect();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 2092);
        assert_eq!(chunks[1].len(), 3908);
        let mut out = vec![0_u8; 6000];
        assert_eq!(rr2.copy_into(&mut out).unwrap(), 6000);
        assert!(out.iter().all(|&byte| byte == 0xBB));
        assert!(rr2.as_slice().is_none());
        let mut small = [0_u8; 10];
        assert_eq!(
            rr2.copy_into(&mut small),
            Err(BufferTooSmall {
                needed: 6000,
                available: 10
            })
        );
        assert_eq!(small, [0_u8; 10]);
    }

    fn put_page(store: &mut MemoryStore, page_no: u32, txn: u64, next: u32, data: &[u8]) {
        let mut page = vec![0_u8; PAGE_SIZE_DEFAULT as usize];
        let ctx = EncodeContext {
            page_no,
            page_size: PAGE_SIZE_DEFAULT,
            txn,
            lsn: 0,
        };
        node::write_page_header(&mut page, ctx, PAGE_TYPE_OVERFLOW, 0).unwrap();
        node::put_u32(&mut page, 40, next).unwrap();
        node::put_u32(&mut page, 44, u32::try_from(data.len()).unwrap()).unwrap();
        page.get_mut(48..48 + data.len())
            .unwrap()
            .copy_from_slice(data);
        node::put_u32(
            &mut page,
            PAGE_OFF_PAYLOAD_LEN,
            u32::try_from(48 + data.len()).unwrap(),
        )
        .unwrap();
        node::finish_page(&mut page, PAGE_SIZE_DEFAULT as usize).unwrap();
        store.write_page(page_no, &page).unwrap();
    }

    #[test]
    fn single_rr_sizes() {
        for size in [0_usize, 1, 6000, 65_535] {
            let rdata = vec![0x5A_u8; size];
            let stream = payload(&[&rdata]);
            let mut store = MemoryStore::new(4096).unwrap();
            let first = write_chain(&mut store, 2, &stream).unwrap();
            let rrset =
                OverflowRrset::decode(&store, 2, first, u16::try_from(size).unwrap(), 1).unwrap();
            let rr = rrset.rr(0).unwrap().unwrap();
            assert_eq!(rr.len(), size);
            assert_eq!(rr.chunks().map(<[u8]>::len).sum::<usize>(), size);
            let mut out = vec![0_u8; size];
            assert_eq!(rr.copy_into(&mut out).unwrap(), size);
            assert_eq!(out, rdata);
            if size == 1 {
                assert_eq!(rr.as_slice(), Some(&rdata[..]), "one byte is continuous");
            }
            if size >= 6000 {
                assert!(rr.as_slice().is_none(), "large RDATA crosses pages");
            }
        }
    }

    #[test]
    fn cycle_is_rejected() {
        let mut store = MemoryStore::new(4096).unwrap();
        put_page(&mut store, 1, 2, 2, &[1]);
        put_page(&mut store, 2, 2, 1, &[2]);
        let error = OverflowRrset::decode(&store, 2, 1, 65_535, 1).unwrap_err();
        assert!(matches!(
            error,
            ZoneFileError::Corrupt {
                detail: CorruptDetail::Cycle,
                ..
            }
        ));
    }

    #[test]
    fn page_limit_is_enforced() {
        let mut store = MemoryStore::new(4096).unwrap();
        for page_no in 1..=64_u32 {
            let next = if page_no == 64 { 65 } else { page_no + 1 };
            put_page(&mut store, page_no, 2, next, &[1]);
        }
        put_page(&mut store, 65, 2, 0, &[1]);
        let error = OverflowRrset::decode(&store, 2, 1, 65_535, 1).unwrap_err();
        assert!(matches!(
            error,
            ZoneFileError::Corrupt {
                detail: CorruptDetail::Cycle,
                ..
            }
        ));
    }

    #[test]
    fn short_chain_sum_mismatch() {
        let mut store = MemoryStore::new(4096).unwrap();
        put_page(&mut store, 1, 2, 0, &[1, 2, 3]);
        assert!(OverflowRrset::decode(&store, 2, 1, 100, 1).is_err());
    }

    #[test]
    fn stream_matches_is_zero_copy_equality() {
        let first = vec![0xAA_u8; 6000];
        let second = vec![0xBB_u8; 700];
        let stream = payload(&[&first, &second]);
        let mut store = MemoryStore::new(4096).unwrap();
        let first_page = write_chain(&mut store, 2, &stream).unwrap();
        let rrset = OverflowRrset::decode(&store, 2, first_page, 6700, 2).unwrap();
        assert!(rrset.stream_matches(&stream));
        let mut different = stream.clone();
        if let Some(byte) = different.last_mut() {
            *byte ^= 1;
        }
        assert!(!rrset.stream_matches(&different));
        assert!(!rrset.stream_matches(&stream[..stream.len() - 1]));
    }
}
