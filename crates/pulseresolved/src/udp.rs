//! UDP-транспорт на `pulse-runtime` (io_uring, SO_REUSEPORT).

use std::net::SocketAddr;
use std::sync::Arc;

use pulse_runtime::{BackendKind, Reply, RuntimeConfig, RuntimeError, ServerStats, UdpServer};

use crate::query::{Processor, Transport};

/// Максимальный размер ответа (совпадает с EDNS_MAX_PAYLOAD и TX-слотом).
const TX_SLOT_SIZE: usize = 4096;
/// Размер приёмного буфера: запрос с EDNS редко превышает 4 КиБ.
const RX_BUFFER_SIZE: usize = 4096;

/// Запущенный UDP-сервер.
pub(crate) struct UdpService {
    server: UdpServer,
}

impl UdpService {
    pub(crate) fn start(
        addr: SocketAddr,
        workers: usize,
        processor: Arc<Processor>,
    ) -> Result<Self, RuntimeError> {
        let config = RuntimeConfig::default()
            .with_workers(workers)
            .with_rx_buffer_size(RX_BUFFER_SIZE)
            .with_tx(512, TX_SLOT_SIZE);
        let handler = move |request: &[u8], _peer: SocketAddr, _out: &mut [u8]| {
            Reply::from_owned(processor.handle(request, Transport::Udp))
        };
        let server = UdpServer::bind_with(addr, handler, config)?;
        server.start()?;
        Ok(Self { server })
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    pub(crate) fn workers(&self) -> usize {
        self.server.workers()
    }

    pub(crate) fn backend(&self) -> BackendKind {
        self.server.backend()
    }

    pub(crate) fn stats(&self) -> ServerStats {
        self.server.stats()
    }

    pub(crate) fn shutdown(&self) -> Result<(), RuntimeError> {
        self.server.shutdown()
    }
}
