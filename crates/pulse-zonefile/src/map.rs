//! Отображения `mmap`. Единственный модуль крейта, содержащий `unsafe`.
//!
//! Здесь находятся:
//! - read-only отображение всего файла (`PROT_READ`, `MAP_SHARED`);
//! - единственное writable-отображение региона reader table
//!   (`PROT_READ|PROT_WRITE`, `MAP_SHARED`).
//!
//! Остальные модули работают с этими отображениями через безопасный API.

#![allow(unsafe_code)]

use std::fs::File;
use std::sync::atomic::{AtomicU32, AtomicU64};

use memmap2::{Mmap, MmapMut, MmapOptions};

use crate::consts::{
    PAGE_READER_TABLE, READER_PAGE_DESC_SIZE, READER_SLOT_SIZE, RTP_OFF_SLOTS_USED,
    SLOT_OFF_ACTIVE, SLOT_OFF_FLAGS, SLOT_OFF_HEARTBEAT, SLOT_OFF_OWNER,
};
use crate::errors::ZoneFileError;

fn map_error(size: u64, error: &std::io::Error) -> ZoneFileError {
    ZoneFileError::MapAllocFailed {
        size,
        errno: error.raw_os_error().unwrap_or(0),
        hint: "mmap failed; check container quota, RLIMIT_AS and map_size",
    }
}

/// Read-only отображение всего файла.
#[derive(Debug)]
pub(crate) struct FileMap {
    mmap: Mmap,
}

impl FileMap {
    /// Отображает весь файл `[0, size)` как `PROT_READ | MAP_SHARED`.
    pub(crate) fn map_read(file: &File, size: u64) -> Result<Self, ZoneFileError> {
        let len = usize::try_from(size).map_err(|_| ZoneFileError::MapAllocFailed {
            size,
            errno: 0,
            hint: "file size does not fit into the address space",
        })?;
        // SAFETY: `file` is an open regular file validated by the caller; the
        // mapping is read-only and lives as long as the `File` handle (which is
        // owned by the same `ZoneFile`). No writable alias is created here.
        let mmap = unsafe { MmapOptions::new().len(len).map(file) }
            .map_err(|error| map_error(size, &error))?;
        Ok(Self { mmap })
    }

    /// Возвращает страницу файла по номеру.
    pub(crate) fn page(&self, page_no: u32, page_size: u32) -> Option<&[u8]> {
        let start = usize::try_from(page_no)
            .ok()?
            .checked_mul(usize::try_from(page_size).ok()?)?;
        let end = start.checked_add(usize::try_from(page_size).ok()?)?;
        self.mmap.get(start..end)
    }
}

/// Ссылки на атомарные поля одного слота reader table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SlotAtomics<'a> {
    /// `owner_token`; 0 — слот свободен.
    pub(crate) owner: &'a AtomicU64,
    /// `active_txn`; 0 — пин не взят.
    pub(crate) active: &'a AtomicU64,
    /// `heartbeat_ns` (`CLOCK_MONOTONIC`).
    pub(crate) heartbeat: &'a AtomicU64,
    /// Флаги слота.
    pub(crate) flags: &'a AtomicU64,
}

/// Writable-отображение региона reader table.
///
/// `base` — `*mut u8`, полученный из `MmapMut::as_mut_ptr()` (writable provenance).
/// Именно от него строятся ссылки на атомарные поля; shared-ссылок на этот
/// регион как на `[u8]` не создаётся, иначе запись через атомики шла бы через
/// память с read-only provenance.
#[derive(Debug)]
pub(crate) struct ReaderRegion {
    // Поле держит маппинг живым; доступ идёт через `base`.
    _mmap: MmapMut,
    base: *mut u8,
    len: usize,
    page_size: u32,
    pages: u32,
    slots_per_page: u32,
}

// SAFETY: `ReaderRegion` владеет единственным writable-маппингом региона.
// `MmapMut` уже `Send + Sync`; `base` — стабильный указатель на его память.
// Все обращения к изменяемым полям идут через атомики (`AtomicU32`/`AtomicU64`),
// неизменяемые поля дескриптора читаются побайтово без создания ссылок.
// Копирование/перемещение `ReaderRegion` не меняет адрес маппинга.
unsafe impl Send for ReaderRegion {}
// SAFETY: см. `Send`; несколько потоков обращаются к региону только через атомики.
unsafe impl Sync for ReaderRegion {}

impl ReaderRegion {
    /// Отображает регион reader table как `PROT_READ|PROT_WRITE | MAP_SHARED`.
    ///
    /// # Errors
    ///
    /// `MapAllocFailed` — `mmap` не удался; `Corrupt` — некорректная
    /// геометрия региона (`off % 64 != 0`, длина не кратна странице).
    pub(crate) fn map(
        file: &File,
        region_off: u64,
        region_len: u64,
        page_size: u32,
        pages: u32,
        slots_per_page: u32,
    ) -> Result<Self, ZoneFileError> {
        if !region_off.is_multiple_of(64) || slots_per_page == 0 {
            return Err(ZoneFileError::corrupt(
                crate::errors::CorruptKind::Bounds,
                None,
                crate::errors::CorruptDetail::BadReaderRegion,
            ));
        }
        let expected_len = u64::from(pages) * u64::from(page_size);
        if region_len != expected_len {
            return Err(ZoneFileError::corrupt(
                crate::errors::CorruptKind::Bounds,
                None,
                crate::errors::CorruptDetail::BadReaderRegion,
            ));
        }
        let len = usize::try_from(region_len).map_err(|_| ZoneFileError::MapAllocFailed {
            size: region_len,
            errno: 0,
            hint: "reader region does not fit into the address space",
        })?;
        // SAFETY: the caller validated `region_off` and `region_len` against the
        // file size and `off % 64 == 0`; the offset is also page-aligned because
        // it equals `page_reader_table * page_size`. This is the only writable
        // mapping in the crate (SEC-ZF-014) and it covers exactly the reader table.
        let mut mmap = unsafe { MmapOptions::new().offset(region_off).len(len).map_mut(file) }
            .map_err(|error| map_error(region_len, &error))?;
        // Provenance: `base` comes from the writable mapping itself, so writes to
        // atomics built from it are valid; `&[u8]` from a read-only view is never
        // used as their origin.
        let base = mmap.as_mut_ptr();
        Ok(Self {
            _mmap: mmap,
            base,
            len,
            page_size,
            pages,
            slots_per_page,
        })
    }

    pub(crate) fn page_size(&self) -> u32 {
        self.page_size
    }

    pub(crate) fn pages(&self) -> u32 {
        self.pages
    }

    pub(crate) fn slots_per_page(&self) -> u32 {
        self.slots_per_page
    }

    fn page_offset(&self, page_no: u32) -> Option<usize> {
        let index = page_no.checked_sub(PAGE_READER_TABLE)?;
        if index >= self.pages {
            return None;
        }
        usize::try_from(index)
            .ok()?
            .checked_mul(usize::try_from(self.page_size).ok()?)
    }

    fn read_array<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        let end = off.checked_add(N)?;
        if end > self.len {
            return None;
        }
        let mut out = [0_u8; N];
        // SAFETY: `off + N <= self.len`; `base` points into the live writable
        // mapping for `self.len` bytes. `copy_nonoverlapping` reads bytes without
        // creating a reference to the mapping; the copied fields are immutable or
        // (for `slots_used`) read via atomic access instead of this helper.
        unsafe {
            std::ptr::copy_nonoverlapping(self.base.add(off), out.as_mut_ptr(), N);
        }
        Some(out)
    }

    /// Immutable `u16` поля дескриптора reader-страницы (LE).
    pub(crate) fn descriptor_u16(&self, page_no: u32, off: usize) -> Option<u16> {
        let start = self.page_offset(page_no)?.checked_add(off)?;
        let bytes = self.read_array::<2>(start)?;
        Some(u16::from_le_bytes(bytes))
    }

    /// Immutable `u32` поля дескриптора reader-страницы (LE).
    pub(crate) fn descriptor_u32(&self, page_no: u32, off: usize) -> Option<u32> {
        let start = self.page_offset(page_no)?.checked_add(off)?;
        let bytes = self.read_array::<4>(start)?;
        Some(u32::from_le_bytes(bytes))
    }

    /// Атомарный счётчик занятых слотов страницы.
    #[allow(clippy::cast_ptr_alignment)]
    pub(crate) fn slots_used(&self, page_no: u32) -> Option<&AtomicU32> {
        let index = page_no.checked_sub(PAGE_READER_TABLE)?;
        if index >= self.pages {
            return None;
        }
        let page_off = self.page_offset(page_no)?;
        let off = page_off.checked_add(RTP_OFF_SLOTS_USED)?;
        if off.checked_add(4)? > self.len {
            return None;
        }
        let address = self.base.wrapping_add(off).cast::<AtomicU32>();
        // SAFETY: `off + 4 <= len`; page bases are multiples of `page_size`
        // (>= 4096) and `RTP_OFF_SLOTS_USED == 12`, so the address is 4-byte
        // aligned. `base` has writable provenance from `MmapMut`; all accesses
        // are atomic, and no shared byte reference aliases this field.
        Some(unsafe { &*address })
    }

    /// Атомарные поля слота по глобальному индексу `0..READER_SLOTS`.
    #[allow(clippy::cast_ptr_alignment)]
    pub(crate) fn slot(&self, index: u32) -> Option<SlotAtomics<'_>> {
        if index >= crate::consts::READER_SLOTS {
            return None;
        }
        let page_index = index / self.slots_per_page;
        if page_index >= self.pages {
            return None;
        }
        let slot_in_page = index % self.slots_per_page;
        let page_off = usize::try_from(page_index)
            .ok()?
            .checked_mul(usize::try_from(self.page_size).ok()?)?;
        let slot_off = usize::try_from(slot_in_page)
            .ok()?
            .checked_mul(usize::try_from(READER_SLOT_SIZE).ok()?)?;
        let base = page_off
            .checked_add(usize::try_from(READER_PAGE_DESC_SIZE).ok()?)?
            .checked_add(slot_off)?;
        if base.checked_add(usize::try_from(READER_SLOT_SIZE).ok()?)? > self.len {
            return None;
        }
        let read = |delta: usize| -> &AtomicU64 {
            let address = self.base.wrapping_add(base + delta).cast::<AtomicU64>();
            // SAFETY: `base + delta + 8 <= len` for all four slot fields
            // (`delta` in {0, 8, 16, 24}); the slot base is 32-byte aligned
            // relative to a page-aligned mapping, so the address is 8-byte
            // aligned. `base` has writable provenance from `MmapMut`; all
            // accesses happen through `AtomicU64`, never via a `&[u8]` view.
            unsafe { &*address }
        };
        Some(SlotAtomics {
            owner: read(SLOT_OFF_OWNER),
            active: read(SLOT_OFF_ACTIVE),
            heartbeat: read(SLOT_OFF_HEARTBEAT),
            flags: read(SLOT_OFF_FLAGS),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_region_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ReaderRegion>();
    }

    #[test]
    fn descriptor_and_slot_bounds_are_checked() {
        let file = tempfile::tempfile().unwrap();
        file.set_len(4 * 4096 + 4096).unwrap();
        let region = ReaderRegion::map(&file, 4 * 4096, 4096, 4096, 1, 127).unwrap();
        assert!(region.descriptor_u32(PAGE_READER_TABLE, 0).is_some());
        assert!(region.descriptor_u32(PAGE_READER_TABLE + 1, 0).is_none());
        assert!(region.slot(0).is_some());
        assert!(region.slot(crate::consts::READER_SLOTS).is_none());
    }
}
