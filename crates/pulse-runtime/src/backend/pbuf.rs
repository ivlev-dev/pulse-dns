//! Ring provided buffers (`IORING_REGISTER_PBUF_RING`).
//!
//! Память кольца выдаётся `mmap` (выравнивание на страницу, как требует
//! интерфейс), записи публикуются через release-store в `tail`. Буферы
//! (полезная нагрузка) живут в арене worker'а и не перемещаются.

use std::io;
use std::ptr;
use std::sync::atomic::{AtomicU16, Ordering};

use io_uring::types::BufRingEntry;

/// Кольцо provided buffers (user-memory ring, без `IOU_PBUF_RING_MMAP`).
pub(crate) struct ProvidedBufRing {
    base: *mut u8,
    bytes: usize,
    entries: u16,
    mask: u16,
    tail: u16,
    bgid: u16,
    available: u16,
}

// SAFETY: кольцо принадлежит одному worker-потоку; указатель валиден до `Drop`,
// который освобождает mmap. `Send` нужен, чтобы создать структуру в потоке
// инициализации и переместить в worker до первого использования.
unsafe impl Send for ProvidedBufRing {}

impl ProvidedBufRing {
    /// Выделить и обнулить память кольца.
    pub(crate) fn new(entries: u16, bgid: u16) -> io::Result<Self> {
        debug_assert!(entries.is_power_of_two());
        let bytes = usize::from(entries)
            .checked_mul(std::mem::size_of::<BufRingEntry>())
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        // SAFETY: стандартный анонимный mmap; результат проверяется.
        let base = unsafe {
            libc::mmap(
                ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `base` — валидный mmap-регион длиной `bytes`.
        unsafe { ptr::write_bytes(base.cast::<u8>(), 0, bytes) };
        Ok(Self {
            base: base.cast::<u8>(),
            bytes,
            entries,
            mask: entries - 1,
            tail: 0,
            bgid,
            available: 0,
        })
    }

    /// Зарегистрировать ring в io_uring.
    ///
    /// # Safety
    ///
    /// `submitter` должен принадлежать io_uring, который живёт не дольше этого
    /// ring'а; вызывающий должен позже вызвать
    /// [`unregister`](Self::unregister) до `Drop`.
    pub(crate) unsafe fn register(&self, submitter: &io_uring::Submitter<'_>) -> io::Result<()> {
        // SAFETY: память кольца валидна и не перемещается (см. контракт выше).
        unsafe {
            submitter.register_buf_ring_with_flags(
                self.base as usize as u64,
                self.entries,
                self.bgid,
                0,
            )
        }
    }

    /// Снять регистрацию ring'а.
    pub(crate) fn unregister(&self, submitter: &io_uring::Submitter<'_>) -> io::Result<()> {
        submitter.unregister_buf_ring(self.bgid)
    }

    /// Вернуть буфер `bid` в кольцо.
    pub(crate) fn push(&mut self, bid: u16, addr: u64, len: u32) {
        let index = usize::from(self.tail & self.mask);
        // SAFETY: `index < entries`, а запись по этому индексу не принадлежит
        // ядру: буфер возвращается только после CQE, т.е. ядро уже отдало его.
        unsafe {
            let entry = self.base.cast::<BufRingEntry>().add(index);
            (*entry).set_addr(addr);
            (*entry).set_len(len);
            (*entry).set_bid(bid);
            self.tail = self.tail.wrapping_add(1);
            let tail = BufRingEntry::tail(self.base.cast::<BufRingEntry>()).cast::<AtomicU16>();
            // Release: записи entry выше обязаны быть видны до публикации tail.
            (*tail).store(self.tail, Ordering::Release);
        }
        debug_assert!(
            self.available < self.entries,
            "pbuf ring overflow: {} buffers for {} entries",
            u32::from(self.available) + 1,
            self.entries
        );
        self.available += 1;
    }

    pub(crate) const fn available(&self) -> u16 {
        self.available
    }

    pub(crate) fn take_one_available(&mut self) {
        debug_assert!(self.available > 0, "pbuf available underflow");
        self.available = self.available.saturating_sub(1);
    }
}

impl Drop for ProvidedBufRing {
    fn drop(&mut self) {
        // SAFETY: `base`/`bytes` получены из успешного mmap и ещё не освобождены.
        unsafe {
            libc::munmap(self.base.cast(), self.bytes);
        }
    }
}
