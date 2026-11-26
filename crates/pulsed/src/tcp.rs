//! TCP-транспорт: неблокирующий event-loop, length-prefixed framing.
//!
//! Обычные DNS-запросы обслуживаются задачами общего tokio event-loop
//! (`pulse_tls::net::TcpServer`): поток на соединение не создаётся, лимит
//! соединений и idle-таймаут задаёт конфигурация. AXFR/IXFR остаются
//! потоковыми: после разбора запроса сокет передаётся в `spawn_blocking`,
//! потому что протокол трансфера пишет серию кадров через синхронный
//! `Read + Write`. Такой поток ограничен таймаутами сокета и не занимает
//! воркер event-loop.

use std::io;
use std::net::{Shutdown as SocketShutdown, SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use pulse_dns::{DecodeLimits, Message, Opcode, Rtype};
use pulse_server::Transport;
use pulse_tls::net::{BufferPool, ConnectionHandler, ServerHooks, SocketOptions, TcpServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio::time::timeout;

use crate::stats::Stats;
use crate::store::SharedZoneAdmin;
use crate::{dns, logging};

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
        admin: &Arc<SharedZoneAdmin>,
        stats: Arc<Stats>,
        nodelay: bool,
        busy_poll_us: Option<u32>,
    ) -> io::Result<Self> {
        let admin = Arc::clone(admin);
        let listener = TcpListener::bind(addr)?;
        let requests = Arc::new(BufferPool::new(REQUEST_BUFFER_CHUNK, REQUEST_BUFFER_POOL));
        let responses = Arc::new(BufferPool::new(
            pulse_dns::MAX_MESSAGE_LEN + 2,
            RESPONSE_POOL,
        ));
        let handler: ConnectionHandler = {
            let admin = Arc::clone(&admin);
            let stats = Arc::clone(&stats);
            Arc::new(move |stream, peer, shutdown| {
                let admin = Arc::clone(&admin);
                let stats = Arc::clone(&stats);
                let requests = Arc::clone(&requests);
                let responses = Arc::clone(&responses);
                Box::pin(async move {
                    stats.tcp_connection_opened();
                    let _guard = ConnectionGuard(Arc::clone(&stats));
                    if let Err(error) = serve(
                        stream,
                        peer,
                        &admin,
                        &stats,
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
                Arc::new(move || stats.tcp_accept_error())
            }),
        );
        let shutdown_timeout = idle_timeout + Duration::from_millis(500);
        let tcp = TcpServer::start_with_options(
            "pulse-tcp",
            listener,
            max_connections,
            shutdown_timeout,
            hooks,
            SocketOptions {
                nodelay,
                busy_poll_us,
            },
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
        self.0.tcp_connection_closed();
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    admin: &Arc<SharedZoneAdmin>,
    stats: &Arc<Stats>,
    mut shutdown: watch::Receiver<bool>,
    idle_timeout: Duration,
    requests: &Arc<BufferPool>,
    responses: &Arc<BufferPool>,
) -> io::Result<()> {
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
        let length = usize::from(length);
        let mut request_buffer = requests.acquire();
        let buffer = request_buffer.prepare(length);
        match timeout(idle_timeout, stream.read_exact(buffer)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error),
            Err(_) => return Ok(()),
        }

        let now = crate::transfer::now_unix();
        match admin
            .transfer()
            .handle_notify_in(request_buffer.as_slice(), peer.ip(), now)
        {
            Some(crate::transfer::NotifyAction::Reply(response)) => {
                write_frame(&mut stream, &response, idle_timeout).await?;
                stats.response();
                continue;
            }
            Some(crate::transfer::NotifyAction::Accepted { zone, response, .. }) => {
                write_frame(&mut stream, &response, idle_timeout).await?;
                stats.response();
                admin.wake_secondary(&zone, std::time::Instant::now());
                continue;
            }
            Some(crate::transfer::NotifyAction::Ignore) => return Ok(()),
            None => {}
        }

        if is_transfer_request(request_buffer.as_slice()) {
            let request = request_buffer.take_vec(length);
            let stream = stream.into_std()?;
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(idle_timeout))?;
            stream.set_write_timeout(Some(idle_timeout))?;
            let admin = Arc::clone(admin);
            let stats = Arc::clone(stats);
            let outcome = tokio::task::spawn_blocking(move || {
                let mut stream = stream;
                stats.tcp_query();
                let result = match admin.transfer().handle_transfer(
                    &mut stream,
                    &request,
                    peer.ip(),
                    crate::transfer::now_unix(),
                ) {
                    Some(Ok(())) => {
                        stats.response();
                        Ok(())
                    }
                    Some(Err(error)) => {
                        stats.tcp_io_error();
                        logging::debug(
                            "tcp_transfer",
                            &format!("transfer from {} failed: {error}", peer.ip()),
                        );
                        Err(io::Error::other(error.to_string()))
                    }
                    None => Ok(()),
                };
                let _ = stream.shutdown(SocketShutdown::Both);
                result
            })
            .await;
            return outcome.map_err(io::Error::other)?;
        }

        let engine = admin.engine();
        let mut response_buffer = responses.acquire();
        let buffer = response_buffer.prepare(pulse_dns::MAX_MESSAGE_LEN + 2);
        let Some(body) = buffer.get_mut(2..2 + pulse_dns::MAX_MESSAGE_LEN) else {
            continue;
        };
        let Some(len) = dns::respond_into(
            request_buffer.as_slice(),
            Transport::Tcp,
            &engine,
            stats,
            body,
        ) else {
            continue;
        };
        let Ok(length_prefix) = u16::try_from(len) else {
            continue;
        };
        let Some(prefix) = buffer.get_mut(..2) else {
            continue;
        };
        prefix.copy_from_slice(&length_prefix.to_be_bytes());
        let Some(frame) = buffer.get(..len + 2) else {
            continue;
        };
        write_raw_frame(&mut stream, frame, idle_timeout).await?;
    }
}

fn is_transfer_request(raw: &[u8]) -> bool {
    let Ok(message) = Message::decode(raw, &DecodeLimits::default()) else {
        return false;
    };
    message.opcode() == Opcode::QUERY
        && message
            .questions()
            .first()
            .is_some_and(|question| matches!(question.qtype(), Rtype::AXFR | Rtype::IXFR))
}

async fn write_raw_frame(
    stream: &mut tokio::net::TcpStream,
    frame: &[u8],
    deadline: Duration,
) -> io::Result<()> {
    let write = async {
        stream.write_all(frame).await?;
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
