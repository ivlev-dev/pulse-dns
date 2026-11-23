//! Thread-per-core UDP-рантайм для `pulse-dns` (MVP, model из
//! `docs/spec/io-uring-runtime.md`).
//!
//! # Что реализовано
//!
//! - **Ring per worker.** Каждый worker — отдельный поток с собственным
//!   `io_uring`; сокеты объединяются в `SO_REUSEPORT`-группу, ядро распределяет
//!   датаграммы по 4-tuple без общих блокировок.
//! - **Multishot `recvmsg` + provided buffers** (`IORING_REGISTER_PBUF_RING`):
//!   один SQE на worker, буферы выдаются кольцом. При отказе регистрации —
//!   автоматический L1-фолбэк на батч одиночных `RECVMSG`.
//! - **Батчевый `sendmsg`**. Ответ пишется в TX-слот, SQE уходит в общий submit.
//! - **Backpressure.** При нехватке TX-слотов provided-буферы не возвращаются
//!   ядру; приём останавливается, пока слоты не освободятся.
//! - **`MSG_TRUNC`.** Датаграмма больше RX-буфера принимается, считается в
//!   `oversize_received` и не передаётся обработчику (anti-amplification).
//! - **`IP_PKTINFO`/`IPV6_RECVPKTINFO`.** Ответ с wildcard-bind уходит с того
//!   же локального адреса, на который пришёл запрос.
//! - **Graceful shutdown** через `eventfd` + `IORING_REGISTER_SYNC_CANCEL`;
//!   если CQ не опустел в дедлайн, память намеренно утекает вместо UAF.
//! - **Изоляция паник.** Вывод panic-hook подавляется внутри обработчика,
//!   счётчик `handler_panics` растёт, worker продолжает работу.
//! - **CQ overflow** — fail-fast и `cq_overflow_total`; инвариант
//!   `rx_buffers + tx_slots + 2 <= cq_entries` проверяется при создании.
//! - **Без tokio и без async.** Синхронный обработчик, completion loop.
//! - **epoll-фолбэк** (feature `epoll-fallback`): `recvmmsg`/`sendmmsg`,
//!   `EPOLLET`, ретрай `EINTR` и частичной отправки.
//!
//! `SO_REUSEPORT` — не изоляция: другой процесс того же uid может привязаться
//! к тому же порту и получать часть трафика.
//!
//! # Пример
//!
//! ```
//! use std::io::ErrorKind;
//! use std::net::SocketAddr;
//! use pulse_runtime::{Reply, UdpServer};
//!
//! let server = UdpServer::bind(
//!     "127.0.0.1:0".parse().unwrap(),
//!     |request: &[u8], _peer: SocketAddr, out: &mut [u8]| {
//!         let len = request.len().min(out.len());
//!         out[..len].copy_from_slice(&request[..len]);
//!         Reply::Send(len)
//!     },
//!     2,
//! )
//! .unwrap();
//! let addr = server.local_addr();
//! // `start()` не блокирует; `run()` — то же плюс ожидание остановки.
//! server.start().unwrap();
//!
//! // Клиент: один запрос — один ответ.
//! let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
//! client.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
//! client.send_to(b"ping", addr).unwrap();
//! let mut buf = [0_u8; 64];
//! let (len, _) = loop {
//!     match client.recv_from(&mut buf) {
//!         Ok(reply) => break reply,
//!         Err(err) if err.kind() == ErrorKind::Interrupted => continue,
//!         Err(err) => panic!("recv: {err}"),
//!     }
//! };
//! assert_eq!(&buf[..len], b"ping");
//!
//! server.shutdown().unwrap();
//! ```
//!
//! # Пример DNS-обработчика
//!
//! Ответ пишется в тот же provided-буфер, в котором пришёл запрос: копирования
//! и аллокаций на горячем пути нет. Проверка длины — обязательна, обработчик
//! не должен паниковать на произвольных байтах.
//!
//! ```
//! use std::net::SocketAddr;
//! use pulse_runtime::Reply;
//!
//! fn dns_handler(request: &[u8], _peer: SocketAddr, out: &mut [u8]) -> Reply {
//!     // 12-байтовый заголовок DNS: ID, флаги, 4 счётчика.
//!     if request.len() < 12 || out.len() < request.len() {
//!         return Reply::Drop;
//!     }
//!     out[..request.len()].copy_from_slice(request);
//!     out[2] = 0x81; // QR = 1, RD = 1
//!     out[3] = 0x80; // RA = 1, RCODE = NOERROR
//!     // ANCOUNT = 0: пример не добавляет RR, только подтверждает форму ответа.
//!     out[6] = 0;
//!     out[7] = 0;
//!     Reply::Send(request.len())
//! }
//! # let _ = dns_handler;
//! ```
//!
//! # Безопасность `unsafe`
//!
//! `unsafe` разрешён только в модулях, работающих с памятью io_uring:
//! provided-buffer ring (`mmap`, публикация `tail`), самоссылочные `msghdr`
//! для `recvmsg`/`sendmsg`, разбор сырого `sockaddr`. Остальной код —
//! безопасный Rust. Каждый блок помечен `SAFETY:` с обоснованием.
//!
//! # Соответствие спецификации
//!
//! Реализованы L1–L3 для UDP (spec §4.2), §6.1 (provided buffers), §7
//! (multishot recv), §8 (батчи и backpressure), §9.3 (отмена), §10.1–10.2
//! (сокеты, `SO_REUSEPORT`, `IP_PKTINFO`, приём, `MSG_TRUNC`), §15 (счётчики).
//! Не входят в MVP: TCP, таймеры домена, `SEND_ZC`, `IORING_REGISTER_FILES`,
//! `SO_BUSY_POLL`, SQPOLL по умолчанию, dual-stack `IPV6_V6ONLY=0`.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
#![allow(clippy::module_name_repetitions)]
// Низкоуровневый код: размеры/индексы заведомо укладываются в целевые типы
// (Linux, u32/socklen_t), а ммap-регион выровнен на страницу.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::cast_ptr_alignment,
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::unnecessary_box_returns
)]

mod backend;
mod config;
mod error;
mod handler;
mod panic_hook;
mod pktinfo;
mod server;
mod socket;
mod stats;

pub use config::{BackendKind, BackendPreference, Capabilities, RuntimeConfig, RxMode};
pub use error::RuntimeError;
pub use handler::{Handler, OwnedFn, Reply, owned};
pub use server::{Runtime, UdpServer};
pub use stats::{ServerStats, WorkerStats};
