//! Запуск HTTP-сервера и graceful shutdown.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use thiserror::Error;

use crate::config::{ApiConfig, ApiConfigError};
use crate::handler::Api;
use crate::http::{HttpLimits, read_request, write_response};
use crate::port::ZoneAdmin;
use crate::problem::Problem;

/// Ошибка запуска API-сервера.
#[derive(Debug, Error)]
pub enum ApiServerError {
    /// Некорректная конфигурация.
    #[error(transparent)]
    Config(#[from] ApiConfigError),
    /// Не удалось занять адрес.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        /// Адрес.
        addr: SocketAddr,
        /// Причина.
        source: io::Error,
    },
    /// Ошибка настройки listener.
    #[error("failed to configure listener: {0}")]
    Listener(io::Error),
    /// Не удалось запустить поток.
    #[error("failed to spawn server thread: {0}")]
    Thread(io::Error),
}

/// Запущенный API-сервер.
pub struct RunningServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl RunningServer {
    /// Фактический адрес прослушивания (полезно при bind на порт 0).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Останавливает сервер и ждёт завершения активных соединений.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
        let workers = {
            let mut guard = self.workers.lock().unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        for worker in workers {
            let _ = worker.join();
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Запускает API-сервер на настроенном loopback-адресе.
///
/// # Errors
///
/// [`ApiServerError`] при некорректной конфигурации, занятом адресе или
/// невозможности запустить поток.
pub fn serve<Z: ZoneAdmin>(
    config: ApiConfig,
    store: Arc<Z>,
) -> Result<RunningServer, ApiServerError> {
    let authenticator = config.validate()?;
    let bind = config.bind;
    let listener =
        TcpListener::bind(bind).map_err(|source| ApiServerError::Bind { addr: bind, source })?;
    listener
        .set_nonblocking(true)
        .map_err(ApiServerError::Listener)?;
    let addr = listener.local_addr().map_err(ApiServerError::Listener)?;
    let limits = HttpLimits {
        max_body_bytes: config.max_body_bytes,
        request_timeout: config.request_timeout,
        write_timeout: config.write_timeout,
    };
    let max_connections = config.max_connections;
    let store: Arc<dyn ZoneAdmin> = store;
    let api = Arc::new(Api::new(&config, store, authenticator));
    let shutdown = Arc::new(AtomicBool::new(false));
    let workers = Arc::new(Mutex::new(Vec::new()));
    let accept = {
        let api = Arc::clone(&api);
        let shutdown = Arc::clone(&shutdown);
        let workers = Arc::clone(&workers);
        thread::Builder::new()
            .name("pulse-api-accept".to_owned())
            .spawn(move || {
                accept_loop(listener, &api, &shutdown, &workers, limits, max_connections);
            })
            .map_err(ApiServerError::Thread)?
    };
    Ok(RunningServer {
        addr,
        shutdown,
        accept: Some(accept),
        workers,
    })
}

fn accept_loop(
    listener: TcpListener,
    api: &Arc<Api>,
    shutdown: &Arc<AtomicBool>,
    workers: &Arc<Mutex<Vec<JoinHandle<()>>>>,
    limits: HttpLimits,
    max_connections: usize,
) {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        match listener.accept() {
            Ok((mut stream, peer)) => {
                let previous = active.fetch_add(1, Ordering::SeqCst);
                if previous >= max_connections {
                    active.fetch_sub(1, Ordering::SeqCst);
                    let _ = respond_overloaded(&mut stream, &limits);
                    continue;
                }
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_nodelay(true);
                let api = Arc::clone(api);
                let worker_active = Arc::clone(&active);
                let handle = match thread::Builder::new()
                    .name("pulse-api-conn".to_owned())
                    .spawn(move || {
                        let _guard = ActiveGuard(worker_active);
                        serve_connection(&mut stream, peer, &api, &limits);
                    }) {
                    Ok(handle) => handle,
                    Err(_) => {
                        active.fetch_sub(1, Ordering::SeqCst);
                        continue;
                    }
                };
                let mut guard = workers.lock().unwrap_or_else(PoisonError::into_inner);
                if guard.len() >= 64 {
                    guard.retain(|worker| !worker.is_finished());
                }
                guard.push(handle);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn serve_connection(stream: &mut TcpStream, peer: SocketAddr, api: &Api, limits: &HttpLimits) {
    match read_request(stream, limits) {
        Ok(request) => {
            let response = api.handle(&request, peer);
            let _ = write_response(stream, &response, limits);
        }
        Err(error) => {
            let response =
                Problem::new(error.status, error.code, error.detail, "/", "req_unparsed")
                    .into_response();
            let _ = write_response(stream, &response, limits);
        }
    }
}

fn respond_overloaded(stream: &mut TcpStream, limits: &HttpLimits) -> io::Result<()> {
    let response = Problem::new(
        503,
        "unavailable",
        "Too many concurrent connections.",
        "/",
        "req_overloaded",
    )
    .retryable(true)
    .with_header("Retry-After", "1")
    .into_response();
    write_response(stream, &response, limits)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::auth::TokenConfig;
    use crate::memory::InMemoryZoneAdmin;

    fn config() -> ApiConfig {
        let mut config = ApiConfig::new(vec![TokenConfig {
            id: "test".to_owned(),
            token: "test-token-value".to_owned(),
            scopes: vec!["admin".to_owned()],
            zone_scope: None,
        }]);
        config.bind = SocketAddr::from(([127, 0, 0, 1], 0));
        config
    }

    fn get(addr: SocketAddr, path: &str) -> std::io::Result<String> {
        use std::io::Read;
        use std::io::Write;
        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    #[test]
    fn starts_and_shuts_down() {
        let store = Arc::new(InMemoryZoneAdmin::new());
        let server = serve(config(), store).unwrap();
        let addr = server.addr();
        let response = get(addr, "/healthz").unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        server.shutdown();
        let started = Instant::now();
        assert!(TcpStream::connect(addr).is_err() || started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn rejects_non_loopback() {
        let mut config = config();
        config.bind = SocketAddr::from(([0, 0, 0, 0], 0));
        let store = Arc::new(InMemoryZoneAdmin::new());
        assert!(matches!(
            serve(config, store),
            Err(ApiServerError::Config(_))
        ));
    }

    #[test]
    fn store_is_used_for_readiness() {
        let store = Arc::new(InMemoryZoneAdmin::new());
        store.set_ready(false);
        let server = serve(config(), store).unwrap();
        let response = get(server.addr(), "/readyz").unwrap();
        assert!(response.starts_with("HTTP/1.1 503"));
        server.shutdown();
    }
}
