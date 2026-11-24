//! UDP-транспорт на `pulse-runtime` (io_uring, SO_REUSEPORT).

use std::net::SocketAddr;
use std::sync::Arc;

use pulse_runtime::{BackendKind, Reply, RuntimeConfig, ServerStats, UdpServer};
use pulse_server::Transport;

use crate::dns;
use crate::stats::Stats;
use crate::store::SharedZoneAdmin;

/// Запущенный UDP-сервер.
pub(crate) struct UdpService {
    server: UdpServer,
}

impl UdpService {
    pub(crate) fn start(
        addr: SocketAddr,
        workers: usize,
        admin: Arc<SharedZoneAdmin>,
        stats: Arc<Stats>,
    ) -> Result<Self, pulse_runtime::RuntimeError> {
        let config = RuntimeConfig::default().with_workers(workers);
        let handler = move |request: &[u8], peer: SocketAddr, out: &mut [u8]| -> Reply {
            match admin
                .transfer()
                .handle_notify_in(request, peer.ip(), crate::transfer::now_unix())
            {
                Some(crate::transfer::NotifyAction::Ignore) => return Reply::Drop,
                Some(crate::transfer::NotifyAction::Reply(response)) => {
                    if response.len() > out.len() {
                        stats.drop_response();
                        return Reply::Drop;
                    }
                    out[..response.len()].copy_from_slice(&response);
                    stats.response();
                    return Reply::Send(response.len());
                }
                None => {}
            }
            let engine = admin.engine();
            let Some(response) = dns::respond(request, Transport::Udp, &engine, &stats) else {
                return Reply::Drop;
            };
            if response.len() > out.len() {
                stats.drop_response();
                return Reply::Drop;
            }
            out[..response.len()].copy_from_slice(&response);
            Reply::Send(response.len())
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

    pub(crate) fn shutdown(&self) -> Result<(), pulse_runtime::RuntimeError> {
        self.server.shutdown()
    }
}
