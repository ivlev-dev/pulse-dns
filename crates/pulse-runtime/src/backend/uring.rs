//! io_uring backend: ring на worker, multishot recvmsg + provided buffers,
//! батчевый `sendmsg`, backpressure по TX-слотам, graceful shutdown.

use std::io;
use std::mem::{self, MaybeUninit};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use io_uring::types::{CancelBuilder, RecvMsgOut, Timespec};
use io_uring::{IoUring, cqueue, opcode, squeue, types};
use rustix::net::addr::SocketAddrStorage;

use super::pbuf::ProvidedBufRing;
use crate::backend::probe::build_ring;
use crate::config::{RuntimeConfig, RxMode};
use crate::error::RuntimeError;
use crate::handler::{Handler, Reply};
use crate::panic_hook;
use crate::pktinfo::{CMSG_BUF_LEN, DstInfo};
use crate::socket::sockaddr_from_bytes;
use crate::stats::WorkerCounters;

const OP_RECV: u8 = 1;
const OP_SEND: u8 = 2;
const OP_WAKE: u8 = 3;

/// Buffer group id для provided buffers (один на worker).
const BGID_RX: u16 = 1;

/// `sizeof(struct io_uring_recvmsg_out)`, который ядро пишет в начало каждого
/// provided-буфера перед sockaddr и полезной нагрузкой.
const RECVMSG_OUT_LEN: usize = 16;

/// `sizeof(struct sockaddr_storage)`: столько места резервируется под адрес пира.
const SOCKADDR_STORAGE_LEN: usize = 128;

/// Резерв под control message (`IP_PKTINFO`/`IPV6_PKTINFO`) в provided-буфере.
const RECVMSG_CTRL_LEN: usize = CMSG_BUF_LEN;

const MAX_CQE_BATCH: usize = 256;

/// Тег `user_data`: op (8) | slot (16) | generation (32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tag {
    op: u8,
    slot: u16,
    generation: u32,
}

const fn make_tag(op: u8, slot: u16, generation: u32) -> u64 {
    ((generation as u64) << 32) | ((slot as u64) << 8) | op as u64
}

const fn decode_tag(user_data: u64) -> Tag {
    Tag {
        op: (user_data & 0xff) as u8,
        slot: ((user_data >> 8) & 0xffff) as u16,
        generation: (user_data >> 32) as u32,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Multishot,
    Batch,
}

/// Заголовок `recvmsg` для multishot-приёма: ядру нужны только размеры
/// `msg_namelen`/`msg_controllen`, данные складываются в provided-буфер.
struct MultishotHdr {
    hdr: libc::msghdr,
}

impl MultishotHdr {
    fn new() -> Box<Self> {
        // SAFETY: `msghdr` — POD, все нули — валидное состояние; поля-указатели
        // для multishot-приёма ядром не используются.
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_namelen = SOCKADDR_STORAGE_LEN as libc::socklen_t;
        hdr.msg_controllen = RECVMSG_CTRL_LEN;
        Box::new(Self { hdr })
    }

    const fn ptr(&self) -> *const libc::msghdr {
        &raw const self.hdr
    }
}

/// Один слот батчевого приёма.
///
/// `hdr`/`iov`/`name` — самоссылочная структура: указатели инициализируются
/// после размещения в `Box` и больше не меняются.
struct RxSlot {
    buf: Vec<u8>,
    name: MaybeUninit<SocketAddrStorage>,
    control: [u8; CMSG_BUF_LEN],
    iov: libc::iovec,
    hdr: libc::msghdr,
    generation: u32,
    in_flight: bool,
}

impl RxSlot {
    fn new(capacity: usize) -> Box<Self> {
        let mut slot = Box::new(Self {
            buf: vec![0_u8; capacity],
            name: MaybeUninit::uninit(),
            control: [0_u8; CMSG_BUF_LEN],
            iov: libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            },
            // SAFETY: `msghdr` — POD, нулевое значение валидно; указатели
            // заполняются ниже до первого использования.
            hdr: unsafe { mem::zeroed() },
            generation: 0,
            in_flight: false,
        });
        let base: *mut Self = &raw mut *slot;
        // SAFETY: `slot` живёт в `Box` и не перемещается; указатели ссылаются
        // на его же поля, которые переживут структуру.
        unsafe {
            let iov_base = (*base).buf.as_mut_ptr().cast();
            (*base).iov = libc::iovec {
                iov_base,
                iov_len: 0,
            };
            (*base).hdr.msg_name = (*base).name.as_mut_ptr().cast();
            (*base).hdr.msg_namelen = SOCKADDR_STORAGE_LEN as libc::socklen_t;
            (*base).hdr.msg_iov = &raw mut (*base).iov;
            (*base).hdr.msg_iovlen = 1;
            (*base).hdr.msg_control = (*base).control.as_mut_ptr().cast();
            (*base).hdr.msg_controllen = RECVMSG_CTRL_LEN;
            (*base).hdr.msg_flags = 0;
        }
        slot
    }

    fn arm(&mut self, fd: RawFd, slot: u16) -> squeue::Entry {
        self.generation = self.generation.wrapping_add(1);
        self.in_flight = true;
        self.hdr.msg_namelen = SOCKADDR_STORAGE_LEN as libc::socklen_t;
        self.hdr.msg_controllen = RECVMSG_CTRL_LEN;
        self.hdr.msg_flags = 0;
        self.iov.iov_len = self.buf.len();
        opcode::RecvMsg::new(types::Fd(fd), &raw mut self.hdr)
            .build()
            .user_data(make_tag(OP_RECV, slot, self.generation))
    }

    fn peer(&self) -> Option<SocketAddr> {
        let len = usize::try_from(self.hdr.msg_namelen)
            .unwrap_or(0)
            .min(SOCKADDR_STORAGE_LEN);
        if len < 2 {
            return None;
        }
        // SAFETY: ядро записало `msg_namelen` байт в `name` при завершении
        // `recvmsg`, слот не находится в полёте.
        let bytes = unsafe { slice::from_raw_parts(self.name.as_ptr().cast::<u8>(), len) };
        sockaddr_from_bytes(bytes)
    }

    fn dst_info(&self) -> DstInfo {
        let len = self.hdr.msg_controllen.min(CMSG_BUF_LEN);
        DstInfo::parse(&self.control[..len])
    }
}

/// TX-слот: буфер ответа и самоссылочный `msghdr` для `sendmsg`.
struct TxSlot {
    buf: Vec<u8>,
    name: MaybeUninit<SocketAddrStorage>,
    control: [u8; CMSG_BUF_LEN],
    iov: libc::iovec,
    hdr: libc::msghdr,
    generation: u32,
    in_flight: bool,
    /// Длина прошлого ответа: этот префикс обнуляется перед новым запросом,
    /// чтобы слот не отправил хвост чужого ответа.
    written: usize,
}

impl TxSlot {
    fn new(capacity: usize) -> Box<Self> {
        let mut slot = Box::new(Self {
            buf: vec![0_u8; capacity],
            name: MaybeUninit::uninit(),
            control: [0_u8; CMSG_BUF_LEN],
            iov: libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            },
            // SAFETY: `msghdr` — POD; указатели заполняются ниже.
            hdr: unsafe { mem::zeroed() },
            generation: 0,
            in_flight: false,
            written: 0,
        });
        let base: *mut Self = &raw mut *slot;
        // SAFETY: `slot` в `Box`, адрес стабилен; `hdr`/`iov`/`name`/`buf`
        // принадлежат той же структуре и переживут её.
        unsafe {
            let iov_base = (*base).buf.as_mut_ptr().cast();
            (*base).iov = libc::iovec {
                iov_base,
                iov_len: 0,
            };
            (*base).hdr.msg_name = (*base).name.as_mut_ptr().cast();
            (*base).hdr.msg_namelen = 0;
            (*base).hdr.msg_iov = &raw mut (*base).iov;
            (*base).hdr.msg_iovlen = 1;
            (*base).hdr.msg_control = (*base).control.as_mut_ptr().cast();
            (*base).hdr.msg_controllen = 0;
            (*base).hdr.msg_flags = 0;
        }
        slot
    }
}

struct TxPool {
    // Box фиксирует адрес слота: `msghdr` внутри ссылается на поля того же слота.
    #[allow(clippy::vec_box)]
    slots: Vec<Box<TxSlot>>,
    free: Vec<u16>,
    low: usize,
    high: usize,
    in_flight: usize,
}

impl TxPool {
    fn new(cfg: &RuntimeConfig) -> Self {
        let mut slots = Vec::with_capacity(cfg.tx_slots);
        let mut free = Vec::with_capacity(cfg.tx_slots);
        for index in 0..cfg.tx_slots {
            slots.push(TxSlot::new(cfg.tx_slot_size));
            free.push(u16::try_from(index).unwrap_or(u16::MAX));
        }
        let low = (cfg.tx_slots / 8).max(1);
        let high = (cfg.tx_slots / 4).max(low + 1);
        Self {
            slots,
            free,
            low,
            high,
            in_flight: 0,
        }
    }

    fn free_count(&self) -> usize {
        self.free.len()
    }

    fn in_flight(&self) -> usize {
        self.in_flight
    }

    fn slot_capacity(&self) -> usize {
        self.slots.first().map_or(0, |slot| slot.buf.len())
    }

    fn alloc(&mut self) -> Option<u16> {
        let slot = self.free.pop()?;
        if let Some(entry) = self.slots.get_mut(usize::from(slot))
            && entry.written > 0
        {
            // Не отдаём обработчику и не отправляем хвост прошлого ответа.
            entry.buf[..entry.written].fill(0);
            entry.written = 0;
        }
        Some(slot)
    }

    fn release(&mut self, slot: u16) {
        if usize::from(slot) < self.slots.len() {
            self.free.push(slot);
        }
    }

    fn out(&mut self, slot: u16) -> Option<&mut [u8]> {
        self.slots
            .get_mut(usize::from(slot))
            .map(|slot| slot.buf.as_mut_slice())
    }

    fn copy_owned(&mut self, slot: u16, bytes: &[u8]) -> bool {
        let Some(dst) = self.out(slot) else {
            return false;
        };
        if bytes.len() > dst.len() {
            return false;
        }
        dst[..bytes.len()].copy_from_slice(bytes);
        true
    }

    /// Подготовить `sendmsg`: адрес пира, `IP_PKTINFO` (если был во входящей
    /// датаграмме), длина и генерация.
    fn send_entry(
        &mut self,
        slot: u16,
        len: usize,
        peer: SocketAddr,
        dst: DstInfo,
        fd: RawFd,
    ) -> Option<squeue::Entry> {
        let index = usize::from(slot);
        let tx_slot = self.slots.get_mut(index)?;
        if tx_slot.in_flight || len > tx_slot.buf.len() {
            return None;
        }
        tx_slot.generation = tx_slot.generation.wrapping_add(1);
        tx_slot.in_flight = true;
        tx_slot.written = len;
        tx_slot.iov.iov_len = len;
        // SAFETY: слот не в полёте, `name` — валидная выровненная память слота.
        let name_len = unsafe { crate::socket::write_sockaddr(peer, tx_slot.name.as_mut_ptr()) };
        tx_slot.hdr.msg_namelen = name_len as libc::socklen_t;
        tx_slot.hdr.msg_controllen = dst.write(&mut tx_slot.control);
        self.in_flight += 1;
        Some(
            opcode::SendMsg::new(types::Fd(fd), &raw const tx_slot.hdr)
                .build()
                .user_data(make_tag(OP_SEND, slot, tx_slot.generation)),
        )
    }

    /// Завершить отправку; `false` — CQE устарел либо слот не в полёте.
    fn complete(&mut self, slot: u16, generation: u32) -> bool {
        let Some(entry) = self.slots.get_mut(usize::from(slot)) else {
            return false;
        };
        if !entry.in_flight || entry.generation != generation {
            return false;
        }
        entry.in_flight = false;
        self.in_flight = self.in_flight.saturating_sub(1);
        self.free.push(slot);
        true
    }
}

struct RxState {
    armed: bool,
    generation: u32,
    inflight: usize,
    held: Vec<u16>,
}

impl RxState {
    fn new(pbuf_slots: u16) -> Self {
        Self {
            armed: false,
            generation: 0,
            inflight: 0,
            held: Vec::with_capacity(usize::from(pbuf_slots)),
        }
    }
}

/// Состояние worker'а и его главный цикл.
pub(crate) struct UringWorker {
    // Поля объявлены так, что ring уничтожается первым: к этому моменту все
    // операции отменены, а буферы ещё живы.
    ring: IoUring,
    /// Владеет fd сокета; ring использует только номер.
    _socket: OwnedFd,
    fd: RawFd,
    cfg: Arc<RuntimeConfig>,
    handler: Arc<dyn Handler>,
    counters: Arc<WorkerCounters>,
    stop: Arc<AtomicBool>,
    abort: Arc<AtomicBool>,
    wake: OwnedFd,
    mode: Mode,
    pbuf: Option<ProvidedBufRing>,
    arena: Vec<u8>,
    arena_stride: usize,
    arena_buffers: u16,
    rx_hdr: Box<MultishotHdr>,
    // Box фиксирует адрес слота: `msghdr`/`iovec` ссылаются на поля слота.
    #[allow(clippy::vec_box)]
    rx_slots: Vec<Box<RxSlot>>,
    rx: RxState,
    tx: TxPool,
    sq_ops: Vec<squeue::Entry>,
    closed: bool,
    fatal: Option<io::Error>,
}

impl UringWorker {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        socket: OwnedFd,
        cfg: Arc<RuntimeConfig>,
        handler: Arc<dyn Handler>,
        counters: Arc<WorkerCounters>,
        stop: Arc<AtomicBool>,
        abort: Arc<AtomicBool>,
        wake: OwnedFd,
    ) -> Result<Self, RuntimeError> {
        let fd = socket.as_raw_fd();
        let (ring, _fast_flags) = build_ring(&cfg).map_err(|source| RuntimeError::IoUring {
            context: "io_uring_setup (worker)",
            source,
        })?;

        let prefer_multishot = cfg.rx_mode != RxMode::RecvBatch;
        let forced_multishot = cfg.rx_mode == RxMode::Multishot;

        let mut pbuf = None;
        let mut arena = Vec::new();
        let mut arena_stride = 0;
        let mut mode = Mode::Batch;

        if prefer_multishot {
            match Self::setup_provided_buffers(&ring, &cfg) {
                Ok((ring_buf, buf, stride)) => {
                    pbuf = Some(ring_buf);
                    arena = buf;
                    arena_stride = stride;
                    mode = Mode::Multishot;
                }
                Err(source) if forced_multishot => {
                    return Err(RuntimeError::IoUring {
                        context: "register provided buffers (rx_mode = Multishot)",
                        source,
                    });
                }
                Err(_) => {
                    // L1-фолбэк: батч одиночных recvmsg, без provided buffers.
                    mode = Mode::Batch;
                }
            }
        }

        let rx_slots = if mode == Mode::Batch {
            (0..cfg.batch_size)
                .map(|_| RxSlot::new(cfg.rx_buffer_size))
                .collect()
        } else {
            Vec::new()
        };
        let arena_buffers = if mode == Mode::Multishot {
            cfg.rx_buffers
        } else {
            0
        };

        let mut worker = Self {
            ring,
            _socket: socket,
            fd,
            handler,
            counters,
            stop,
            abort,
            wake,
            mode,
            pbuf,
            arena,
            arena_stride,
            arena_buffers,
            rx_hdr: MultishotHdr::new(),
            rx_slots,
            rx: RxState::new(arena_buffers),
            tx: TxPool::new(&cfg),
            cfg,
            sq_ops: Vec::with_capacity(MAX_CQE_BATCH * 2 + 8),
            closed: false,
            fatal: None,
        };
        worker.fill_provided_buffers();
        worker.arm_wake();
        Ok(worker)
    }

    /// Выделить арену и зарегистрировать ring provided buffers.
    fn setup_provided_buffers(
        ring: &IoUring,
        cfg: &RuntimeConfig,
    ) -> io::Result<(ProvidedBufRing, Vec<u8>, usize)> {
        let stride = cfg
            .rx_buffer_size
            .checked_add(RECVMSG_OUT_LEN + SOCKADDR_STORAGE_LEN + RECVMSG_CTRL_LEN)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let total = stride
            .checked_mul(usize::from(cfg.rx_buffers))
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let ring_buf = ProvidedBufRing::new(cfg.rx_buffers, BGID_RX)?;
        // SAFETY: ring_buf не перемещается (живёт в worker до shutdown, где
        // снимается регистрация) и переживает io_uring.
        unsafe { ring_buf.register(&ring.submitter())? };
        Ok((ring_buf, vec![0_u8; total], stride))
    }

    fn fill_provided_buffers(&mut self) {
        let (Some(pbuf), mode) = (self.pbuf.as_mut(), self.mode) else {
            return;
        };
        if mode != Mode::Multishot {
            return;
        }
        let base = self.arena.as_ptr() as u64;
        let stride = self.arena_stride;
        for index in 0..self.arena_buffers {
            let addr = base + u64::from(index) * stride as u64;
            pbuf.push(index, addr, stride as u32);
        }
    }

    fn arm_wake(&mut self) {
        let entry = opcode::PollAdd::new(types::Fd(self.wake.as_raw_fd()), libc::POLLIN as u32)
            .build()
            .user_data(make_tag(OP_WAKE, 0, 0));
        self.sq_ops.push(entry);
    }

    /// Проверить, не пора ли выходить, и доиграть CQ.
    pub(crate) fn run(mut self) -> Result<(), RuntimeError> {
        loop {
            if self.stopping() {
                break;
            }
            self.pump();
            self.flush_submissions()?;

            if self.ring.completion().is_empty() {
                match self.ring.submit_and_wait(1) {
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(source) => {
                        return Err(RuntimeError::IoUring {
                            context: "io_uring_submit_and_wait",
                            source,
                        });
                    }
                }
            } else if !self.ring.submission().is_empty() {
                self.ring.submit().map_err(|source| RuntimeError::IoUring {
                    context: "io_uring_submit",
                    source,
                })?;
            }

            self.drain_completions();
            let overflow = self.ring.completion().overflow();
            if overflow > 0 {
                self.counters.cq_overflow();
                return Err(RuntimeError::IoUring {
                    context: "completion queue overflow",
                    source: io::Error::other(format!(
                        "CQ overflowed, {overflow} completion(s) lost"
                    )),
                });
            }
            if let Some(source) = self.fatal.take() {
                return Err(RuntimeError::IoUring {
                    context: "recvmsg (unrecoverable)",
                    source,
                });
            }
        }
        self.graceful_stop()
    }

    fn drain_completions(&mut self) {
        let mut batch = [(0_u64, 0_i32, 0_u32); MAX_CQE_BATCH];
        let mut count = 0;
        {
            let mut cq = self.ring.completion();
            while count < MAX_CQE_BATCH {
                let Some(cqe) = cq.next() else {
                    break;
                };
                batch[count] = (cqe.user_data(), cqe.result(), cqe.flags());
                count += 1;
            }
        }
        for &(user_data, result, flags) in &batch[..count] {
            self.dispatch(user_data, result, flags);
        }
    }

    fn flush_submissions(&mut self) -> Result<(), RuntimeError> {
        let total = self.sq_ops.len();
        let mut index = 0;
        while index < total {
            {
                let mut sq = self.ring.submission();
                while index < total && !sq.is_full() {
                    // SAFETY: каждый SQE ссылается на живой буфер/сокет worker'а;
                    // слоты не освобождаются до CQE, арена не перемещается.
                    unsafe { sq.push(&self.sq_ops[index]) }.map_err(|_| {
                        RuntimeError::io_uring(
                            "submission queue push",
                            io::Error::from_raw_os_error(libc::EBUSY),
                        )
                    })?;
                    index += 1;
                }
            }
            if index < total {
                self.ring.submit().map_err(|source| RuntimeError::IoUring {
                    context: "io_uring_submit (queue drain)",
                    source,
                })?;
            }
        }
        self.sq_ops.clear();
        Ok(())
    }

    fn dispatch(&mut self, user_data: u64, result: i32, flags: u32) {
        let tag = decode_tag(user_data);
        match tag.op {
            OP_WAKE => self.on_wake(),
            OP_SEND => self.on_send(tag, result),
            OP_RECV if self.mode == Mode::Multishot => {
                self.on_recv_multishot(tag, result, flags);
            }
            OP_RECV => self.on_recv_batch(tag, result),
            _ => self.counters.stale(),
        }
    }

    fn on_wake(&mut self) {
        let mut buf = [0_u8; 8];
        let _ = rustix::io::read(&self.wake, &mut buf);
        if !self.stopping() {
            self.arm_wake();
        }
    }

    fn on_send(&mut self, tag: Tag, result: i32) {
        if !self.tx.complete(tag.slot, tag.generation) {
            self.counters.stale();
            return;
        }
        if result >= 0 {
            self.counters.add_sent(1);
            self.counters.add_bytes_sent(result as u64);
        } else {
            self.counters.send_error();
        }
        self.maybe_flush_held();
    }

    fn on_recv_multishot(&mut self, tag: Tag, result: i32, flags: u32) {
        let more = cqueue::more(flags);
        if !more {
            self.rx.armed = false;
        }
        if tag.generation != self.rx.generation {
            self.counters.stale();
            // Буфер, выданный под этот CQE, всё равно нужно вернуть в кольцо.
            if result >= 0
                && let Some(bid) = cqueue::buffer_select(flags)
                && bid < self.arena_buffers
            {
                if let Some(pbuf) = self.pbuf.as_mut() {
                    pbuf.take_one_available();
                }
                self.return_buffer(bid);
            }
            return;
        }
        if result < 0 {
            self.record_recv_error(-result);
            return;
        }

        let Some(bid) = cqueue::buffer_select(flags) else {
            self.counters.recv_error();
            return;
        };
        if bid >= self.arena_buffers {
            self.counters.recv_error();
            return;
        }
        if let Some(pbuf) = self.pbuf.as_mut() {
            pbuf.take_one_available();
        }

        let start = usize::from(bid) * self.arena_stride;
        let buffer = &self.arena[start..start + self.arena_stride];
        let parsed = RecvMsgOut::parse(buffer, &self.rx_hdr.hdr);
        match parsed {
            Ok(msg) => {
                let truncated = msg.is_payload_truncated();
                let dst = DstInfo::parse(msg.control_data());
                match sockaddr_from_bytes(msg.name_data()) {
                    Some(peer) => respond(
                        msg.payload_data(),
                        peer,
                        dst,
                        truncated,
                        &*self.handler,
                        &mut self.tx,
                        &self.counters,
                        &mut self.sq_ops,
                        self.fd,
                    ),
                    None => self.counters.recv_error(),
                }
            }
            Err(()) => self.counters.recv_error(),
        }
        self.return_buffer(bid);
    }

    fn on_recv_batch(&mut self, tag: Tag, result: i32) {
        let index = usize::from(tag.slot);
        let Some(slot) = self.rx_slots.get_mut(index) else {
            self.counters.stale();
            return;
        };
        if !slot.in_flight || slot.generation != tag.generation {
            self.counters.stale();
            return;
        }
        slot.in_flight = false;
        self.rx.inflight = self.rx.inflight.saturating_sub(1);

        if result < 0 {
            self.record_recv_error(-result);
            return;
        }
        let len = usize::try_from(result).unwrap_or(0).min(slot.buf.len());
        let truncated = (slot.hdr.msg_flags & libc::MSG_TRUNC) != 0;
        let Some(peer) = slot.peer() else {
            self.counters.recv_error();
            return;
        };
        let dst = slot.dst_info();
        respond(
            &slot.buf[..len],
            peer,
            dst,
            truncated,
            &*self.handler,
            &mut self.tx,
            &self.counters,
            &mut self.sq_ops,
            self.fd,
        );
    }

    /// Учесть ошибку приёма; невосстановимую — запомнить и завершить worker.
    fn record_recv_error(&mut self, errno: i32) {
        match errno {
            libc::ENOBUFS => self.counters.starve(),
            libc::ECANCELED | libc::EAGAIN | libc::EINTR => {}
            _ => {
                self.counters.recv_error();
                if self.fatal.is_none() {
                    self.fatal = Some(io::Error::from_raw_os_error(errno));
                }
            }
        }
    }

    /// Вернуть provided-буфер ядру либо удержать его (backpressure).
    fn return_buffer(&mut self, bid: u16) {
        if self.tx.free_count() < self.tx.low {
            self.counters.pressure();
            self.rx.held.push(bid);
        } else {
            self.release_buffer(bid);
        }
    }

    fn release_buffer(&mut self, bid: u16) {
        let (Some(pbuf), stride) = (self.pbuf.as_mut(), self.arena_stride) else {
            return;
        };
        let addr = self.arena.as_ptr() as u64 + u64::from(bid) * stride as u64;
        pbuf.push(bid, addr, stride as u32);
    }

    fn maybe_flush_held(&mut self) {
        if self.rx.held.is_empty() || self.tx.free_count() < self.tx.high {
            return;
        }
        while let Some(bid) = self.rx.held.pop() {
            self.release_buffer(bid);
        }
    }

    /// Доармировать приём: multishot или свободные слоты батча.
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || self.abort.load(Ordering::Relaxed)
    }

    fn pump(&mut self) {
        self.maybe_flush_held();
        if self.stopping() {
            return;
        }
        match self.mode {
            Mode::Multishot => {
                let available = self.pbuf.as_ref().map_or(0, ProvidedBufRing::available);
                if !self.rx.armed && available > 0 && self.tx.free_count() > 0 {
                    self.rx.generation = self.rx.generation.wrapping_add(1);
                    let entry =
                        opcode::RecvMsgMulti::new(types::Fd(self.fd), self.rx_hdr.ptr(), BGID_RX)
                            .build()
                            .user_data(make_tag(OP_RECV, 0, self.rx.generation));
                    self.sq_ops.push(entry);
                    self.rx.armed = true;
                }
            }
            Mode::Batch => {
                let free = self.tx.free_count();
                if free == 0 {
                    return;
                }
                let target = free.min(self.cfg.batch_size);
                let mut wanted = target.saturating_sub(self.rx.inflight);
                if wanted == 0 {
                    return;
                }
                for index in 0..self.rx_slots.len() {
                    if wanted == 0 {
                        break;
                    }
                    let slot = &mut self.rx_slots[index];
                    if slot.in_flight {
                        continue;
                    }
                    let slot_index = u16::try_from(index).unwrap_or(u16::MAX);
                    let entry = slot.arm(self.fd, slot_index);
                    self.sq_ops.push(entry);
                    self.rx.inflight += 1;
                    wanted -= 1;
                }
            }
        }
    }

    fn graceful_stop(&mut self) -> Result<(), RuntimeError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let deadline = Instant::now() + self.cfg.shutdown_timeout;

        // 1. Досылаем всё, что уже лежит в SQ: отмена должна покрывать весь
        //    набор submitted-операций, иначе счётчики in-flight расходятся.
        let _ = self.flush_submissions();
        self.sq_ops.clear();

        // 2. Синхронная отмена с таймаутом; EINTR ретраится, пока есть время.
        let mut cancel_error = None;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                cancel_error = Some(io::Error::from(io::ErrorKind::TimedOut));
                break;
            }
            let timespec = Timespec::new()
                .sec(remaining.as_secs())
                .nsec(remaining.subsec_nanos());
            match self
                .ring
                .submitter()
                .register_sync_cancel(Some(timespec), CancelBuilder::any().all())
            {
                Ok(()) => break,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => {
                    cancel_error = Some(err);
                    break;
                }
            }
        }

        // 3. Ждём, пока CQ опустеет и ни одна операция не может ссылаться на
        //    пользовательскую память. Дедлайн — shutdown_timeout.
        let mut drained = false;
        loop {
            self.drain_shutdown();
            if !self.has_in_flight() {
                drained = true;
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            // DEFER_TASKRUN: CQE доставляются только на enter с GETEVENTS.
            // Ждём не дольше 10 мс за итерацию, чтобы дедлайн соблюдался даже
            // при неожиданном поведении отмены.
            let wait = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(10));
            let timespec = Timespec::new()
                .sec(wait.as_secs())
                .nsec(wait.subsec_nanos());
            let args = types::SubmitArgs::new().timespec(&timespec);
            match self.ring.submitter().submit_with_args(1, &args) {
                Ok(_) => {}
                Err(err)
                    if err.kind() == io::ErrorKind::Interrupted
                        || err.raw_os_error() == Some(libc::ETIME) => {}
                Err(_) => {
                    // EXT_ARG недоступен: не блокируемся, просто дадим шанс
                    // task work и поспим до следующей итерации.
                    let _ = self.ring.submit_and_wait(0);
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }

        if !drained {
            // Ядро может всё ещё писать в наши буферы: освобождать нельзя.
            // Намеренная утечка памяти worker'а (arena/pbuf/slots) вместо UAF.
            self.leak_buffers();
            return Err(RuntimeError::IoUring {
                context: "shutdown: completion queue did not drain",
                source: cancel_error.unwrap_or_else(|| io::Error::from(io::ErrorKind::TimedOut)),
            });
        }

        // 4. Снять регистрацию provided buffers до munmap. Если не удалось —
        //    mmap нельзя освобождать (ring ещё жив), утекаем и сообщаем.
        if let Some(pbuf) = self.pbuf.as_ref()
            && let Err(source) = pbuf.unregister(&self.ring.submitter())
        {
            self.leak_buffers();
            return Err(RuntimeError::IoUring {
                context: "IORING_UNREGISTER_PBUF_RING",
                source,
            });
        }
        self.pbuf = None;
        Ok(())
    }

    /// Есть ли submitted-операции, чьи буферы может читать/писать ядро.
    fn has_in_flight(&self) -> bool {
        self.rx.armed || self.rx.inflight > 0 || self.tx.in_flight() > 0
    }

    /// Не освобождать память, на которую может ссылаться ядро. Вызывается только
    /// при недренированном CQ/ошибке unregister: утечка — осознанная цена
    /// безопасности, процесс всё равно завершается.
    fn leak_buffers(&mut self) {
        std::mem::forget(std::mem::take(&mut self.arena));
        if let Some(pbuf) = self.pbuf.take() {
            std::mem::forget(pbuf);
        }
        let rx_slots = std::mem::take(&mut self.rx_slots);
        std::mem::forget(rx_slots);
        let tx_slots = std::mem::take(&mut self.tx.slots);
        std::mem::forget(tx_slots);
    }

    /// Дренаж CQ на shutdown без вызова обработчика: только учёт завершений.
    fn drain_shutdown(&mut self) {
        let mode = self.mode;
        let cq = self.ring.completion();
        for cqe in cq {
            let tag = decode_tag(cqe.user_data());
            match tag.op {
                OP_SEND => {
                    self.tx.complete(tag.slot, tag.generation);
                }
                OP_RECV if mode == Mode::Multishot => {
                    if cqe.result() < 0 || !cqueue::more(cqe.flags()) {
                        self.rx.armed = false;
                    }
                }
                OP_RECV => {
                    if let Some(slot) = self.rx_slots.get_mut(usize::from(tag.slot))
                        && slot.in_flight
                        && slot.generation == tag.generation
                    {
                        slot.in_flight = false;
                        self.rx.inflight = self.rx.inflight.saturating_sub(1);
                    }
                }
                _ => {}
            }
        }
    }
}

impl Drop for UringWorker {
    fn drop(&mut self) {
        // Ошибка worker'а не должна оставлять ядро со ссылками на буферы:
        // отменяем операции до того, как поля структуры начнут освобождаться.
        let _ = self.graceful_stop();
    }
}

/// Обработать одну датаграмму: вызвать `handler` и поставить `sendmsg` в очередь.
#[allow(clippy::too_many_arguments)]
fn respond(
    payload: &[u8],
    peer: SocketAddr,
    dst: DstInfo,
    truncated: bool,
    handler: &dyn Handler,
    tx: &mut TxPool,
    counters: &WorkerCounters,
    sq_ops: &mut Vec<squeue::Entry>,
    fd: RawFd,
) {
    counters.add_received(1);
    counters.add_bytes_received(payload.len() as u64);
    if truncated {
        counters.oversize();
        return;
    }

    let Some(slot) = tx.alloc() else {
        counters.response_dropped();
        return;
    };
    let capacity = tx.slot_capacity();
    let Some(out) = tx.out(slot) else {
        counters.response_dropped();
        tx.release(slot);
        return;
    };
    let reply = panic_hook::catch(|| handler.handle(payload, peer, out));
    let Ok(reply) = reply else {
        counters.handler_panic();
        tx.release(slot);
        return;
    };

    let len = match reply {
        Reply::Send(len) => len,
        Reply::Owned(bytes) => {
            if !tx.copy_owned(slot, &bytes) {
                counters.response_dropped();
                tx.release(slot);
                return;
            }
            bytes.len()
        }
        Reply::Drop => {
            tx.release(slot);
            return;
        }
    };

    // Обработчик не может отправить больше, чем ему дали: иначе ушёл бы
    // хвост прошлого ответа. Обрезать нельзя — это чужие байты.
    if len > capacity {
        counters.response_dropped();
        tx.release(slot);
        return;
    }

    if let Some(entry) = tx.send_entry(slot, len, peer, dst, fd) {
        sq_ops.push(entry);
    } else {
        counters.response_dropped();
        tx.release(slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_roundtrip() {
        for (op, slot, generation) in [
            (OP_RECV, 0_u16, 0_u32),
            (OP_SEND, 511, 1),
            (OP_WAKE, 1, u32::MAX),
            (OP_RECV, u16::MAX, 0xDEAD_BEEF),
        ] {
            let tag = decode_tag(make_tag(op, slot, generation));
            assert_eq!(
                tag,
                Tag {
                    op,
                    slot,
                    generation
                }
            );
        }
    }
}
