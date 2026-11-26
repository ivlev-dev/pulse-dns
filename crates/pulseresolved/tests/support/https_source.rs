//! Минимальный HTTPS-сервер для тестов загрузчика blocklist.

#![allow(dead_code)]

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// Параметры ответа mock-сервера.
#[derive(Clone, Default)]
pub struct SourceState {
    /// Тело ответа.
    pub body: Vec<u8>,
    /// `ETag` (включая кавычки).
    pub etag: Option<String>,
    /// `Last-Modified`.
    pub last_modified: Option<String>,
    /// Статус; `0` — 200.
    pub status: u16,
    /// Отдавать тело chunked.
    pub chunked: bool,
    /// Редирект (302) на этот URL.
    pub redirect: Option<String>,
    /// Отдавать редирект только для этого пути (`None` — для всех).
    pub redirect_from: Option<String>,
}

/// Заголовки последнего запроса.
#[derive(Debug, Clone, Default)]
pub struct RequestInfo {
    /// `If-None-Match`.
    pub if_none_match: Option<String>,
    /// `If-Modified-Since`.
    pub if_modified_since: Option<String>,
}

/// HTTPS mock с self-signed сертификатом для `127.0.0.1`.
pub struct MockHttpsSource {
    address: SocketAddr,
    cert_pem: String,
    state: Arc<Mutex<SourceState>>,
    request: Arc<Mutex<RequestInfo>>,
    hits: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MockHttpsSource {
    /// Запускает сервер с заданным телом.
    pub fn start(body: impl Into<Vec<u8>>) -> Self {
        let key = KeyPair::generate().expect("key");
        let params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("params");
        let certificate = params.self_signed(&key).expect("self-signed");
        let cert_pem = certificate.pem();
        let cert_der = certificate.der().to_vec();
        let key_der = key.serialize_der();

        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .expect("server config");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock https");
        listener.set_nonblocking(true).expect("nonblocking");
        let address = listener.local_addr().expect("mock addr");
        let state = Arc::new(Mutex::new(SourceState {
            body: body.into(),
            ..SourceState::default()
        }));
        let request = Arc::new(Mutex::new(RequestInfo::default()));
        let hits = Arc::new(AtomicU64::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));

        let thread_state = Arc::clone(&state);
        let thread_request = Arc::clone(&request);
        let thread_hits = Arc::clone(&hits);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = thread::spawn(move || {
            while !thread_shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_hits.fetch_add(1, Ordering::Relaxed);
                        let _ = handle(stream, &config, &thread_state, &thread_request);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            address,
            cert_pem,
            state,
            request,
            hits,
            shutdown,
            thread: Some(thread),
        }
    }

    /// Адрес сервера.
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// URL источника.
    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.address.port())
    }

    /// PEM self-signed сертификата.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Пишет CA-файл и возвращает путь.
    pub fn write_ca(&self, directory: &std::path::Path) -> std::path::PathBuf {
        let path = directory.join("mock-ca.pem");
        std::fs::write(&path, self.cert_pem.as_bytes()).expect("write CA");
        path
    }

    /// Последние условные заголовки запроса.
    pub fn last_request(&self) -> RequestInfo {
        self.request.lock().expect("request lock").clone()
    }

    /// Число TCP-подключений.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Меняет состояние ответа.
    pub fn update(&self, change: impl FnOnce(&mut SourceState)) {
        change(&mut self.state.lock().expect("state lock"));
    }
}

impl Drop for MockHttpsSource {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[allow(clippy::too_many_lines)]
fn handle(
    stream: TcpStream,
    config: &Arc<ServerConfig>,
    state: &Arc<Mutex<SourceState>>,
    request_slot: &Arc<Mutex<RequestInfo>>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let connection = ServerConnection::new(Arc::clone(config)).map_err(std::io::Error::other)?;
    let mut tls = StreamOwned::new(connection, stream);
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        if head.len() > 64 * 1024 {
            return Ok(());
        }
        let read = tls.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        head.extend_from_slice(chunk.get(..read).unwrap_or_default());
    }
    let text = String::from_utf8_lossy(&head);
    let request_path = text
        .split("\r\n")
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    let mut info = RequestInfo::default();
    for line in text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("if-none-match") {
            info.if_none_match = Some(value.trim().to_owned());
        } else if name.eq_ignore_ascii_case("if-modified-since") {
            info.if_modified_since = Some(value.trim().to_owned());
        }
    }
    *request_slot.lock().expect("request lock") = info.clone();

    let snapshot = state.lock().expect("state lock").clone();
    let redirect_applies = snapshot.redirect.is_some()
        && snapshot
            .redirect_from
            .as_deref()
            .is_none_or(|path| path == request_path);
    if redirect_applies {
        let location = snapshot.redirect.unwrap_or_default();
        let head = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(head.as_bytes())?;
        tls.flush()?;
        return Ok(());
    }
    if snapshot.status != 0 && snapshot.status != 200 {
        let head = format!(
            "HTTP/1.1 {} Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            snapshot.status
        );
        tls.write_all(head.as_bytes())?;
        tls.flush()?;
        return Ok(());
    }
    let not_modified = snapshot
        .etag
        .as_deref()
        .is_some_and(|etag| info.if_none_match.as_deref() == Some(etag))
        || snapshot
            .last_modified
            .as_deref()
            .is_some_and(|value| info.if_modified_since.as_deref() == Some(value));
    if not_modified {
        let mut head = String::from("HTTP/1.1 304 Not Modified\r\n");
        if let Some(etag) = &snapshot.etag {
            let _ = write!(head, "ETag: {etag}\r\n");
        }
        if let Some(value) = &snapshot.last_modified {
            let _ = write!(head, "Last-Modified: {value}\r\n");
        }
        head.push_str("Connection: close\r\n\r\n");
        tls.write_all(head.as_bytes())?;
        tls.flush()?;
        return Ok(());
    }
    let mut head = String::from("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n");
    if let Some(etag) = &snapshot.etag {
        let _ = write!(head, "ETag: {etag}\r\n");
    }
    if let Some(value) = &snapshot.last_modified {
        let _ = write!(head, "Last-Modified: {value}\r\n");
    }
    if snapshot.chunked {
        head.push_str("Transfer-Encoding: chunked\r\n");
    } else {
        let _ = write!(head, "Content-Length: {}\r\n", snapshot.body.len());
    }
    head.push_str("Connection: close\r\n\r\n");
    tls.write_all(head.as_bytes())?;
    if snapshot.chunked {
        let split = snapshot.body.len() / 2;
        for part in [&snapshot.body[..split], &snapshot.body[split..]] {
            if part.is_empty() {
                continue;
            }
            tls.write_all(format!("{:x}\r\n", part.len()).as_bytes())?;
            tls.write_all(part)?;
            tls.write_all(b"\r\n")?;
        }
        tls.write_all(b"0\r\n\r\n")?;
    } else {
        tls.write_all(&snapshot.body)?;
    }
    tls.flush()?;
    Ok(())
}
