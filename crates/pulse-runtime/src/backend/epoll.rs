//! epoll-фолбэк: `recvmmsg`/`sendmmsg` на неблокирующем сокете (edge-triggered).
//!
//! Семантика та же, что у io_uring-бэкенда, но приём идёт батчами по
//! [`RuntimeConfig::batch_size`](crate::RuntimeConfig), а отправка — одним
//! `sendmmsg` на батч. Отличия, задокументированные в отчёте: одна лишняя
//! копия на приём (нет provided buffers) и отсутствие TX-слотов — ответы
//! отправляются синхронно, backpressure обеспечивает сокетный буфер ядра.
//! `EPOLLET` требует вычитывать сокет до `EAGAIN`, что и делает [`dgram_loop`];
//! `stop` проверяется на каждом батче, поэтому shutdown не ждёт конца флуда.

use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::ptr;
use std::slice;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::event::epoll;
use rustix::net::addr::SocketAddrStorage;

use crate::config::RuntimeConfig;
use crate::error::RuntimeError;
use crate::handler::{Handler, Reply};
use crate::panic_hook;
use crate::pktinfo::{CMSG_BUF_LEN, DstInfo};
use crate::socket::sockaddr_from_bytes;
use crate::stats::WorkerCounters;

const SOCKADDR_STORAGE_LEN: usize = 128;
const WAKE_DATA: u64 = 1;
const SOCKET_DATA: u64 = 2;
const EPOLL_EVENTS: usize = 64;
/// Сколько раз пробовать дослать батч при EAGAIN, прежде чем дропнуть остаток.
const EAGAIN_RETRIES: u32 = 3;

/// `struct mmsghdr` (Linux ABI: `msghdr` + `u32 msg_len`).
#[repr(C)]
struct Mmsghdr {
    msg_hdr: libc::msghdr,
    msg_len: u32,
}

struct RxBatch {
    bufs: Vec<Vec<u8>>,
    names: Vec<MaybeUninit<SocketAddrStorage>>,
    control: Vec<[u8; CMSG_BUF_LEN]>,
    iovs: Vec<libc::iovec>,
    msgs: Vec<Mmsghdr>,
}

impl RxBatch {
    fn new(count: usize, capacity: usize) -> Self {
        let mut bufs = Vec::with_capacity(count);
        let mut names: Vec<MaybeUninit<SocketAddrStorage>> = Vec::with_capacity(count);
        let mut control = Vec::with_capacity(count);
        let mut iovs = Vec::with_capacity(count);
        let mut msgs = Vec::with_capacity(count);
        for _ in 0..count {
            bufs.push(vec![0_u8; capacity]);
            names.push(MaybeUninit::uninit());
            control.push([0_u8; CMSG_BUF_LEN]);
            iovs.push(libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: capacity,
            });
            // SAFETY: `msghdr` — POD; поля заполняются ниже.
            msgs.push(Mmsghdr {
                msg_hdr: unsafe { std::mem::zeroed() },
                msg_len: 0,
            });
        }
        // Указатели устанавливаются после того, как Vec'ы перестали расти:
        // буферы лежат в куче и не перемещаются.
        for index in 0..count {
            let iov_base = bufs[index].as_mut_ptr().cast();
            iovs[index].iov_base = iov_base;
            msgs[index].msg_hdr.msg_name = names[index].as_mut_ptr().cast();
            msgs[index].msg_hdr.msg_namelen = SOCKADDR_STORAGE_LEN as libc::socklen_t;
            msgs[index].msg_hdr.msg_iov = &raw mut iovs[index];
            msgs[index].msg_hdr.msg_iovlen = 1;
            msgs[index].msg_hdr.msg_control = control[index].as_mut_ptr().cast();
            msgs[index].msg_hdr.msg_controllen = CMSG_BUF_LEN;
        }
        Self {
            bufs,
            names,
            control,
            iovs,
            msgs,
        }
    }

    fn reset(&mut self) {
        for (index, msg) in self.msgs.iter_mut().enumerate() {
            msg.msg_len = 0;
            msg.msg_hdr.msg_namelen = SOCKADDR_STORAGE_LEN as libc::socklen_t;
            msg.msg_hdr.msg_controllen = CMSG_BUF_LEN;
            msg.msg_hdr.msg_flags = 0;
            self.iovs[index].iov_len = self.bufs[index].len();
        }
    }

    fn dst_info(&self, index: usize) -> DstInfo {
        let len = self.msgs[index].msg_hdr.msg_controllen.min(CMSG_BUF_LEN);
        DstInfo::parse(&self.control[index][..len])
    }
}

struct TxBatch {
    bufs: Vec<Vec<u8>>,
    names: Vec<MaybeUninit<SocketAddrStorage>>,
    control: Vec<[u8; CMSG_BUF_LEN]>,
    iovs: Vec<libc::iovec>,
    msgs: Vec<Mmsghdr>,
}

impl TxBatch {
    fn new(count: usize, capacity: usize) -> Self {
        let mut bufs = Vec::with_capacity(count);
        let mut names: Vec<MaybeUninit<SocketAddrStorage>> = Vec::with_capacity(count);
        let mut control = Vec::with_capacity(count);
        let mut iovs = Vec::with_capacity(count);
        let mut msgs = Vec::with_capacity(count);
        for _ in 0..count {
            bufs.push(vec![0_u8; capacity]);
            names.push(MaybeUninit::uninit());
            control.push([0_u8; CMSG_BUF_LEN]);
            iovs.push(libc::iovec {
                iov_base: ptr::null_mut(),
                iov_len: 0,
            });
            // SAFETY: `msghdr` — POD; поля заполняются ниже.
            msgs.push(Mmsghdr {
                msg_hdr: unsafe { std::mem::zeroed() },
                msg_len: 0,
            });
        }
        for index in 0..count {
            let iov_base = bufs[index].as_mut_ptr().cast();
            iovs[index].iov_base = iov_base;
            msgs[index].msg_hdr.msg_iov = &raw mut iovs[index];
            msgs[index].msg_hdr.msg_iovlen = 1;
            msgs[index].msg_hdr.msg_control = control[index].as_mut_ptr().cast();
            msgs[index].msg_hdr.msg_controllen = 0;
        }
        Self {
            bufs,
            names,
            control,
            iovs,
            msgs,
        }
    }

    fn capacity(&self) -> usize {
        self.bufs.first().map_or(0, Vec::len)
    }

    /// Подготовить ответ `index`: адрес пира, `IP_PKTINFO`, длина.
    fn prepare(&mut self, index: usize, name: &[u8], len: usize, dst: DstInfo) -> bool {
        if index >= self.msgs.len() || len > self.capacity() {
            return false;
        }
        let copy_len = name.len().min(SOCKADDR_STORAGE_LEN);
        // SAFETY: `names[index]` — валидная выровненная память слота; копируем
        // не больше её размера, `name` пришёл из `recvmsg`.
        unsafe {
            ptr::copy_nonoverlapping(
                name.as_ptr(),
                self.names[index].as_mut_ptr().cast(),
                copy_len,
            );
        }
        self.iovs[index].iov_len = len;
        self.msgs[index].msg_hdr.msg_name = self.names[index].as_mut_ptr().cast();
        self.msgs[index].msg_hdr.msg_namelen = copy_len as libc::socklen_t;
        self.msgs[index].msg_hdr.msg_controllen = dst.write(&mut self.control[index]);
        true
    }
}

// Worker забирает сокет и общее состояние на всё время жизни потока, поэтому
// аргументы передаются по значению (вызывающий их больше не использует).
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn run_worker(
    socket: OwnedFd,
    cfg: Arc<RuntimeConfig>,
    handler: Arc<dyn Handler>,
    counters: Arc<WorkerCounters>,
    stop: Arc<AtomicBool>,
    abort: Arc<AtomicBool>,
    wake: Arc<OwnedFd>,
) -> Result<(), RuntimeError> {
    let fd = socket.as_raw_fd();
    let epfd = epoll::create(epoll::CreateFlags::CLOEXEC).map_err(errno)?;

    epoll::add(
        &epfd,
        &socket,
        epoll::EventData::new_u64(SOCKET_DATA),
        epoll::EventFlags::IN | epoll::EventFlags::ET,
    )
    .map_err(errno)?;
    epoll::add(
        &epfd,
        wake.as_ref(),
        epoll::EventData::new_u64(WAKE_DATA),
        epoll::EventFlags::IN,
    )
    .map_err(errno)?;

    let batch = cfg.batch_size.min(cfg.tx_slots).max(1);
    let mut rx = RxBatch::new(batch, cfg.rx_buffer_size);
    let mut tx = TxBatch::new(batch, cfg.tx_slot_size);
    let mut events: Vec<epoll::Event> = Vec::with_capacity(EPOLL_EVENTS);
    let mut pending: Vec<usize> = Vec::with_capacity(batch);

    while !stopping(&stop, &abort) {
        events.clear();
        let ready = match epoll::wait(&epfd, rustix::buffer::spare_capacity(&mut events), None) {
            Ok(ready) => ready,
            Err(rustix::io::Errno::INTR) => continue,
            Err(err) => return Err(errno(err)),
        };
        for event in &events[..ready] {
            match event.data.u64() {
                WAKE_DATA => {
                    let mut buf = [0_u8; 8];
                    let _ = rustix::io::read(wake.as_ref(), &mut buf);
                }
                SOCKET_DATA => {
                    dgram_loop(
                        fd,
                        &mut rx,
                        &mut tx,
                        &mut pending,
                        &handler,
                        &counters,
                        &stop,
                        &abort,
                    )
                    .map_err(|source| RuntimeError::SocketIo { source })?;
                }
                _ => {}
            }
            if stopping(&stop, &abort) {
                break;
            }
        }
    }
    Ok(())
}

fn stopping(stop: &AtomicBool, abort: &AtomicBool) -> bool {
    stop.load(Ordering::Relaxed) || abort.load(Ordering::Relaxed)
}

#[allow(clippy::too_many_arguments)]
fn dgram_loop(
    fd: RawFd,
    rx: &mut RxBatch,
    tx: &mut TxBatch,
    pending: &mut Vec<usize>,
    handler: &Arc<dyn Handler>,
    counters: &WorkerCounters,
    stop: &AtomicBool,
    abort: &AtomicBool,
) -> io::Result<()> {
    loop {
        // EPOLLET: вычитываем до EAGAIN, но stop проверяем на каждом батче,
        // чтобы shutdown под флудом не ждал конца очереди.
        if stopping(stop, abort) {
            return Ok(());
        }
        rx.reset();
        let count = match recvmmsg(fd, &mut rx.msgs) {
            Ok(count) => count,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if count == 0 {
            return Ok(());
        }

        pending.clear();
        for index in 0..count {
            let msg = &rx.msgs[index];
            let len = msg.msg_len as usize;
            let name_len = usize::try_from(msg.msg_hdr.msg_namelen)
                .unwrap_or(0)
                .min(SOCKADDR_STORAGE_LEN);
            // SAFETY: ядро записало `name_len` байт адреса и `len` байт данных.
            let name =
                unsafe { slice::from_raw_parts(rx.names[index].as_ptr().cast::<u8>(), name_len) };
            let payload = &rx.bufs[index][..len.min(rx.bufs[index].len())];
            let Some(peer) = sockaddr_from_bytes(name) else {
                counters.recv_error();
                continue;
            };
            let dst = rx.dst_info(index);
            let truncated = (msg.msg_hdr.msg_flags & libc::MSG_TRUNC) != 0;
            counters.add_received(1);
            counters.add_bytes_received(payload.len() as u64);
            if truncated {
                counters.oversize();
                continue;
            }
            if pending.len() >= tx.msgs.len() {
                counters.response_dropped();
                continue;
            }
            let slot = pending.len();
            let out = &mut tx.bufs[slot];
            let reply = panic_hook::catch(|| handler.handle(payload, peer, out));
            let Ok(reply) = reply else {
                counters.handler_panic();
                continue;
            };
            let reply_len = match reply {
                Reply::Send(len) => len,
                Reply::Owned(bytes) => {
                    if bytes.len() > tx.capacity() {
                        counters.response_dropped();
                        continue;
                    }
                    tx.bufs[slot][..bytes.len()].copy_from_slice(&bytes);
                    bytes.len()
                }
                Reply::Drop => continue,
            };
            // Больше, чем дали, отправлять нельзя: это хвост чужого ответа.
            if reply_len > tx.capacity() || !tx.prepare(slot, name, reply_len, dst) {
                counters.response_dropped();
                continue;
            }
            pending.push(slot);
        }

        if pending.is_empty() {
            continue;
        }
        send_batch(fd, tx, pending.len(), counters);
        if stopping(stop, abort) {
            return Ok(());
        }
    }
}

fn send_batch(fd: RawFd, tx: &mut TxBatch, count: usize, counters: &WorkerCounters) {
    if count == 0 {
        return;
    }
    let mut sent = 0_usize;
    let mut retries = 0_u32;
    while sent < count {
        match sendmmsg(fd, &mut tx.msgs[sent..count]) {
            Ok(0) => {
                for _ in sent..count {
                    counters.send_error();
                }
                sent = count;
            }
            Ok(done) => {
                sent += done;
                retries = 0;
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) if err.kind() == io::ErrorKind::WouldBlock && retries < EAGAIN_RETRIES => {
                // Короткая пауза на заполненном SO_SNDBUF; без EPOLLOUT-очереди
                // после исчерпания ретраев остаток честно учитывается как drop.
                retries += 1;
                std::hint::spin_loop();
            }
            Err(_) => {
                for _ in sent..count {
                    counters.send_error();
                }
                sent = count;
            }
        }
    }
    counters.add_sent(sent as u64);
    let bytes: usize = (0..sent).map(|index| tx.iovs[index].iov_len).sum();
    counters.add_bytes_sent(bytes as u64);
}

fn recvmmsg(fd: RawFd, msgs: &mut [Mmsghdr]) -> io::Result<usize> {
    let count = i32::try_from(msgs.len()).unwrap_or(i32::MAX);
    // SAFETY: `msgs` — валидный массив `mmsghdr` с инициализированными
    // указателями; `Mmsghdr` имеет C-раскладку, совместимую с ядром.
    let result = unsafe {
        libc::recvmmsg(
            fd,
            msgs.as_mut_ptr().cast(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT,
            ptr::null_mut(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(result).unwrap_or(0))
}

fn sendmmsg(fd: RawFd, msgs: &mut [Mmsghdr]) -> io::Result<usize> {
    let count = i32::try_from(msgs.len()).unwrap_or(i32::MAX);
    // SAFETY: `msgs` — валидный массив `mmsghdr`, подготовленный `TxBatch`.
    let result = unsafe {
        libc::sendmmsg(
            fd,
            msgs.as_mut_ptr().cast(),
            count as libc::c_uint,
            libc::MSG_DONTWAIT,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(result).unwrap_or(0))
}

fn errno(errno: rustix::io::Errno) -> RuntimeError {
    RuntimeError::SocketIo {
        source: io::Error::from_raw_os_error(errno.raw_os_error()),
    }
}
