//! TCP-транспорт: неблокирующий event-loop, length-prefixed framing.
//!
//! Соединения обслуживаются задачами общего tokio event-loop
//! (`pulse_tls::net::TcpServer`), а не отдельными OS-потоками. Лимит
//! соединений, idle-таймаут и graceful shutdown общие для всех TCP/TLS
//! транспортов процесса.

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use pulse_tls::net::{BufferPool, ConnectionHandler, ServerHooks, TcpServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::timeout;

use crate::logging;
use crate::query::{Processor, Transport};
use crate::stats::Stats;

const REQUEST_BUFFER_CHUNK: usize = 4096;
const REQUEST_BUFFER_POOL: usize = 1024;
const RESPONSE_POOL: usize = 256;

/// Запущенный TCP-сервер.
pub(crate) struct TcpService {
    tcp: TcpServer,
    stats: Arc<Stats>,
}

impl TcpService {
    pub(crate) fn start(
        addr: SocketAddr,
        max_connections: usize,
        idle_timeout: Duration,
        processor: Arc<Processor>,
        stats: Arc<Stats>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let requests = Arc::new(BufferPool::new(REQUEST_BUFFER_CHUNK, REQUEST_BUFFER_POOL));
        let responses = Arc::new(BufferPool::new(pulse_dns::MAX_MESSAGE_LEN, RESPONSE_POOL));
        let handler: ConnectionHandler = {
            let processor = Arc::clone(&processor);
            let stats = Arc::clone(&stats);
            Arc::new(move |stream, peer, shutdown| {
                let processor = Arc::clone(&processor);
                let stats = Arc::clone(&stats);
                let requests = Arc::clone(&requests);
                let responses = Arc::clone(&responses);
                Box::pin(async move {
                    stats.tcp_opened();
                    let _guard = ConnectionGuard(Arc::clone(&stats));
                    if let Err(error) = serve(
                        stream,
                        peer,
                        &processor,
                        shutdown,
                        idle_timeout,
                        &requests,
                        &responses,
                    )
                    .await
                    {
                        stats.tcp_io_error();
                        logging::debug(
                            "tcp_connection",
                            &format!("connection {peer} closed with error: {error}"),
                        );
                    }
                })
            })
        };
        let hooks = ServerHooks::new(
            Some({
                let stats = Arc::clone(&stats);
                Arc::new(move || stats.tcp_rejected())
            }),
            Some({
                let stats = Arc::clone(&stats);
                Arc::new(move || stats.tcp_io_error())
            }),
        );
        let shutdown_timeout = idle_timeout + Duration::from_millis(500);
        let tcp = TcpServer::start(
            "pulseresolved-tcp",
            listener,
            max_connections,
            shutdown_timeout,
            hooks,
            handler,
        )?;
        Ok(Self { tcp, stats })
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.tcp.local_addr()
    }

    pub(crate) fn shutdown(&mut self) -> io::Result<()> {
        match self.tcp.shutdown() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                logging::warn(
                    "tcp_shutdown",
                    &format!(
                        "{} TCP connection(s) still active after graceful deadline",
                        self.stats.tcp_active()
                    ),
                );
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for TcpService {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

struct ConnectionGuard(Arc<Stats>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.tcp_closed();
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    processor: &Processor,
    mut shutdown: watch::Receiver<bool>,
    idle_timeout: Duration,
    requests: &Arc<BufferPool>,
    responses: &Arc<BufferPool>,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let prefix = tokio::select! {
            biased;
            _ = shutdown.changed() => return Ok(()),
            prefix = read_prefix(&mut stream, idle_timeout) => prefix?,
        };
        let Some(length) = prefix else {
            return Ok(());
        };
        if length == 0 {
            return Ok(());
        }
        let mut request_buffer = requests.acquire();
        let buffer = request_buffer.prepare(usize::from(length));
        match timeout(idle_timeout, stream.read_exact(buffer)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok(()),
        }
        let request = request_buffer.take_vec(usize::from(length));

        let mut response_buffer = responses.acquire();
        let out = response_buffer.prepare(pulse_dns::MAX_MESSAGE_LEN);
        let Some(len) = processor.handle_into(&request, Transport::Tcp, peer, out) else {
            return Ok(());
        };
        let Some(frame) = out.get(..len) else {
            return Ok(());
        };
        write_frame(&mut stream, frame, idle_timeout).await?;
    }
}

async fn write_frame(
    stream: &mut tokio::net::TcpStream,
    response: &[u8],
    deadline: Duration,
) -> io::Result<()> {
    let length = u16::try_from(response.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response exceeds 65535 bytes"))?;
    let write = async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(response).await?;
        stream.flush().await
    };
    match timeout(deadline, write).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TCP write timed out",
        )),
    }
}

async fn read_prefix(
    stream: &mut tokio::net::TcpStream,
    idle_timeout: Duration,
) -> io::Result<Option<u16>> {
    let mut prefix = [0_u8; 2];
    match timeout(idle_timeout, stream.read_exact(&mut prefix)).await {
        Ok(Ok(_)) => Ok(Some(u16::from_be_bytes(prefix))),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Ok(Err(error)) => Err(error),
        Err(_) => Ok(None),
    }
}
