//! Синхронные клиенты DNS-over-TLS (RFC 7858) и DNS-over-HTTPS/1.1
//! (RFC 8484) для upstream-резолвера.
//!
//! Клиенты используют только `rustls` и std-сокеты: без tokio и без `unsafe`.
//! Каждый клиент держит одно keep-alive-соединение на upstream; при обрыве
//! соединение пересоздаётся (одна повторная попытка), сертификат сервера
//! проверяется по webpki-roots или по явно заданному CA.
//!
//! # Пример DoT
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use pulse_tls::client::DotClient;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = DotClient::new("1.1.1.1", Some(853), "cloudflare-dns.com", None)?;
//! let response = client.query(&[0_u8; 12], Duration::from_secs(2), Duration::from_secs(2))?;
//! println!("{} bytes", response.len());
//! # Ok(())
//! # }
//! ```
//!
//! # Пример DoH
//!
//! ```no_run
//! use std::time::Duration;
//!
//! use pulse_tls::client::DohClient;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = DohClient::new("https://dns.google/dns-query", None)?;
//! let response = client.query(&[0_u8; 12], Duration::from_secs(2), Duration::from_secs(2))?;
//! println!("{} bytes", response.len());
//! # Ok(())
//! # }
//! ```

use std::fs;
use std::io::{BufReader, Cursor, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

use crate::error::Error;

const DEFAULT_DOT_PORT: u16 = 853;
const DEFAULT_HTTPS_PORT: u16 = 443;
const DEFAULT_DOH_PATH: &str = "/dns-query";
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_DNS_MESSAGE: usize = 65_535;

/// TLS-конфигурация клиента: доверенные корни и ALPN.
#[derive(Clone)]
pub struct ClientTlsConfig {
    inner: Arc<ClientConfig>,
    alpn: Vec<u8>,
}

impl std::fmt::Debug for ClientTlsConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientTlsConfig")
            .field("alpn", &self.alpn)
            .finish_non_exhaustive()
    }
}

impl ClientTlsConfig {
    /// Конфигурация с публичными корнями Mozilla (webpki-roots).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] при пустом ALPN или ошибка сборки rustls.
    pub fn with_webpki_roots(alpn: &[u8]) -> Result<Self, Error> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::build(roots, alpn)
    }

    /// Конфигурация с явно заданным CA в PEM (цепочка доверия upstream).
    ///
    /// Публичные корни при этом не добавляются: это позволяет использовать
    /// self-signed CA и одновременно гарантирует, что чужой сертификат не
    /// пройдёт проверку.
    ///
    /// # Errors
    ///
    /// [`Error::NoCertificates`] при отсутствии сертификатов в PEM,
    /// [`Error::InvalidConfig`] при пустом ALPN или ошибка сборки rustls.
    pub fn with_ca_pem(ca_pem: &[u8], alpn: &[u8]) -> Result<Self, Error> {
        let mut roots = RootCertStore::empty();
        let mut reader = BufReader::new(Cursor::new(ca_pem));
        let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
        if certificates.is_empty() {
            return Err(Error::NoCertificates);
        }
        for certificate in certificates {
            roots.add(certificate)?;
        }
        Self::build(roots, alpn)
    }

    /// Конфигурация с CA из PEM-файла.
    ///
    /// # Errors
    ///
    /// См. [`ClientTlsConfig::with_ca_pem`] и ошибки чтения файла.
    pub fn with_ca_file(path: impl AsRef<Path>, alpn: &[u8]) -> Result<Self, Error> {
        let pem = fs::read(path)?;
        Self::with_ca_pem(&pem, alpn)
    }

    /// Конфигурация DoT (ALPN `dot`).
    ///
    /// # Errors
    ///
    /// См. [`ClientTlsConfig::with_webpki_roots`].
    pub fn for_dot() -> Result<Self, Error> {
        Self::with_webpki_roots(b"dot")
    }

    /// Конфигурация DoH/1.1 (ALPN `http/1.1`).
    ///
    /// # Errors
    ///
    /// См. [`ClientTlsConfig::with_webpki_roots`].
    pub fn for_doh() -> Result<Self, Error> {
        Self::with_webpki_roots(b"http/1.1")
    }

    fn build(roots: RootCertStore, alpn: &[u8]) -> Result<Self, Error> {
        if alpn.is_empty() {
            return Err(Error::InvalidConfig("client ALPN must not be empty"));
        }
        if roots.is_empty() {
            return Err(Error::NoCertificates);
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        Ok(Self {
            inner: Arc::new(config),
            alpn: alpn.to_vec(),
        })
    }

    /// Внутренняя rustls-конфигурация.
    #[must_use]
    pub fn config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.inner)
    }

    /// Ожидаемый ALPN.
    #[must_use]
    pub fn alpn(&self) -> &[u8] {
        &self.alpn
    }
}

/// TLS-соединение клиента с общим дедлайном на каждую операцию.
struct ClientStream {
    connection: ClientConnection,
    socket: TcpStream,
}

impl ClientStream {
    fn connect(
        tls: &ClientTlsConfig,
        server_name: ServerName<'static>,
        address: SocketAddr,
        timeout: Duration,
    ) -> Result<Self, Error> {
        if timeout.is_zero() {
            return Err(Error::Timeout);
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(Error::InvalidConfig("connect timeout is too large"))?;
        let mut socket = TcpStream::connect_timeout(&address, timeout)?;
        socket.set_nodelay(true)?;
        let mut connection = ClientConnection::new(tls.config(), server_name)?;
        while connection.is_handshaking() {
            let remaining = remaining(deadline)?;
            socket.set_read_timeout(Some(remaining))?;
            socket.set_write_timeout(Some(remaining))?;
            match connection.complete_io(&mut socket) {
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    if Instant::now() >= deadline {
                        return Err(Error::HandshakeTimeout);
                    }
                }
                Err(error) => return Err(Error::Io(error)),
            }
        }
        match connection.alpn_protocol() {
            Some(protocol) if protocol == tls.alpn() => {}
            Some(protocol) => {
                return Err(Error::AlpnMismatch {
                    expected: tls.alpn().to_vec(),
                    got: protocol.to_vec(),
                });
            }
            None => return Err(Error::AlpnMissing),
        }
        Ok(Self { connection, socket })
    }

    fn write_all(&mut self, data: &[u8], deadline: Instant) -> Result<(), Error> {
        self.connection.writer().write_all(data)?;
        while self.connection.wants_write() {
            let remaining = remaining(deadline)?;
            self.socket.set_write_timeout(Some(remaining))?;
            match self.connection.write_tls(&mut self.socket) {
                Ok(0) => {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "TLS write returned zero bytes",
                    )));
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(Error::Timeout);
                }
                Err(error) => return Err(Error::Io(error)),
            }
        }
        Ok(())
    }

    fn read(&mut self, buffer: &mut [u8], deadline: Instant) -> Result<usize, Error> {
        loop {
            match self.connection.reader().read(buffer) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(Error::Io(error)),
            }
            let remaining = remaining(deadline)?;
            self.socket.set_read_timeout(Some(remaining))?;
            let read = match self.connection.read_tls(&mut self.socket) {
                Ok(read) => read,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(Error::Timeout);
                }
                Err(error) => return Err(Error::Io(error)),
            };
            if read == 0 {
                return Err(Error::Closed);
            }
            self.connection.process_new_packets()?;
        }
    }

    fn read_exact(&mut self, buffer: &mut [u8], deadline: Instant) -> Result<(), Error> {
        let mut offset = 0_usize;
        while offset < buffer.len() {
            let part = buffer
                .get_mut(offset..)
                .ok_or_else(|| Error::Http("read offset out of bounds".to_owned()))?;
            match self.read(part, deadline)? {
                0 => return Err(Error::Closed),
                read => offset = offset.saturating_add(read),
            }
        }
        Ok(())
    }

    fn close(&mut self) {
        self.connection.send_close_notify();
        while self.connection.wants_write() {
            match self.connection.write_tls(&mut self.socket) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}

/// DNS-over-TLS клиент с одним keep-alive-соединением.
pub struct DotClient {
    addresses: Vec<SocketAddr>,
    server_name: ServerName<'static>,
    tls: ClientTlsConfig,
    connection: Mutex<Option<ClientStream>>,
    reconnects: AtomicU64,
}

impl DotClient {
    /// Создаёт клиент для `host:port` (порт по умолчанию 853).
    ///
    /// `server_name` — имя для SNI и проверки сертификата. Если `ca` задан,
    /// он используется как единственный корень доверия.
    ///
    /// # Errors
    ///
    /// [`Error::NoAddresses`] если хост не разрешился, ошибки чтения CA или
    /// сборки rustls.
    pub fn new(
        host: &str,
        port: Option<u16>,
        server_name: &str,
        ca: Option<&Path>,
    ) -> Result<Self, Error> {
        let port = port.unwrap_or(DEFAULT_DOT_PORT);
        let mut addresses = resolve(host, port)?;
        addresses.dedup();
        let tls = match ca {
            Some(path) => ClientTlsConfig::with_ca_file(path, b"dot")?,
            None => ClientTlsConfig::for_dot()?,
        };
        Ok(Self {
            addresses,
            server_name: parse_server_name(server_name)?,
            tls,
            connection: Mutex::new(None),
            reconnects: AtomicU64::new(0),
        })
    }

    /// Создаёт клиент для уже разрешённого адреса.
    ///
    /// # Errors
    ///
    /// См. [`DotClient::new`].
    pub fn from_addr(
        address: SocketAddr,
        server_name: &str,
        ca: Option<&Path>,
    ) -> Result<Self, Error> {
        let tls = match ca {
            Some(path) => ClientTlsConfig::with_ca_file(path, b"dot")?,
            None => ClientTlsConfig::for_dot()?,
        };
        Self::from_addr_with_tls(address, server_name, tls)
    }

    /// Создаёт клиент для адреса с готовой TLS-конфигурацией.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] при некорректном имени сервера.
    pub fn from_addr_with_tls(
        address: SocketAddr,
        server_name: &str,
        tls: ClientTlsConfig,
    ) -> Result<Self, Error> {
        Ok(Self {
            addresses: vec![address],
            server_name: parse_server_name(server_name)?,
            tls,
            connection: Mutex::new(None),
            reconnects: AtomicU64::new(0),
        })
    }

    /// Число переподключений (для метрик).
    #[must_use]
    pub fn reconnects(&self) -> u64 {
        self.reconnects.load(Ordering::Relaxed)
    }

    /// Отправляет DNS-сообщение и возвращает ответ.
    ///
    /// `connect_timeout` ограничивает установку соединения, `io_timeout` —
    /// обмен DNS-сообщением. При обрыве соединения выполняется одно
    /// переподключение.
    ///
    /// # Errors
    ///
    /// Ошибки TLS, I/O, таймауты и некорректное length-prefix-сообщение.
    pub fn query(
        &self,
        message: &[u8],
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Vec<u8>, Error> {
        if message.len() > MAX_DNS_MESSAGE {
            return Err(Error::MessageTooLarge {
                limit: MAX_DNS_MESSAGE,
            });
        }
        if connect_timeout.is_zero() || io_timeout.is_zero() {
            return Err(Error::Timeout);
        }
        let total = connect_timeout.saturating_add(io_timeout);
        let overall = Instant::now()
            .checked_add(total)
            .ok_or(Error::InvalidConfig("query timeout is too large"))?;
        let mut guard = lock_until(&self.connection, overall)?;
        let mut last_error = Error::Timeout;
        for attempt in 0..2 {
            if guard.is_none() {
                let connect_deadline = deadline_after(connect_timeout, overall)?;
                match self.connect(connect_deadline) {
                    Ok(stream) => {
                        if attempt > 0 {
                            self.reconnects.fetch_add(1, Ordering::Relaxed);
                        }
                        *guard = Some(stream);
                    }
                    Err(error) => {
                        last_error = error;
                        if attempt > 0 || !last_error.is_retryable_connection() {
                            return Err(last_error);
                        }
                        continue;
                    }
                }
            }
            let Some(stream) = guard.as_mut() else {
                continue;
            };
            let io_deadline = deadline_after(io_timeout, overall)?;
            match exchange_dot(stream, message, io_deadline) {
                Ok(response) => return Ok(response),
                Err(error) => {
                    *guard = None;
                    last_error = error;
                    if attempt > 0 || !last_error.is_retryable_connection() {
                        return Err(last_error);
                    }
                }
            }
        }
        Err(last_error)
    }

    fn connect(&self, deadline: Instant) -> Result<ClientStream, Error> {
        let mut last_error = Error::NoAddresses("upstream".to_owned());
        for address in &self.addresses {
            let remaining = remaining(deadline)?;
            match ClientStream::connect(&self.tls, self.server_name.clone(), *address, remaining) {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    let retryable = error.is_retryable_connection();
                    last_error = error;
                    if !retryable {
                        return Err(last_error);
                    }
                }
            }
        }
        Err(last_error)
    }
}

impl std::fmt::Debug for DotClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DotClient")
            .field("addresses", &self.addresses)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl Drop for DotClient {
    fn drop(&mut self) {
        if let Ok(guard) = self.connection.get_mut()
            && let Some(stream) = guard.as_mut()
        {
            stream.close();
        }
    }
}

fn exchange_dot(
    stream: &mut ClientStream,
    message: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    let length = u16::try_from(message.len()).map_err(|_| Error::MessageTooLarge {
        limit: usize::from(u16::MAX),
    })?;
    stream.write_all(&length.to_be_bytes(), deadline)?;
    stream.write_all(message, deadline)?;
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix, deadline)?;
    let length = usize::from(u16::from_be_bytes(prefix));
    if length < 12 {
        return Err(Error::Http("invalid DNS/TCP response length".to_owned()));
    }
    let mut response = vec![0_u8; length];
    stream.read_exact(&mut response, deadline)?;
    Ok(response)
}

struct HttpsConnection {
    stream: ClientStream,
    pending: Vec<u8>,
}

/// DNS-over-HTTPS/1.1 клиент с keep-alive соединением.
pub struct DohClient {
    addresses: Vec<SocketAddr>,
    server_name: ServerName<'static>,
    host_header: String,
    path: String,
    tls: ClientTlsConfig,
    connection: Mutex<Option<HttpsConnection>>,
    reconnects: AtomicU64,
}

impl DohClient {
    /// Создаёт клиент из `https://host[:port]/dns-query`.
    ///
    /// Фрагмент URL (`#name`) переопределяет SNI/имя для проверки
    /// сертификата, что удобно для тестовых серверов на IP-адресе.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] при некорректной схеме/хосте,
    /// [`Error::NoAddresses`] если хост не разрешился, ошибки CA/rustls.
    pub fn new(url: &str, ca: Option<&Path>) -> Result<Self, Error> {
        let tls = match ca {
            Some(path) => ClientTlsConfig::with_ca_file(path, b"http/1.1")?,
            None => ClientTlsConfig::for_doh()?,
        };
        Self::with_tls(url, tls)
    }

    /// Создаёт клиент из URL с готовой TLS-конфигурацией.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUrl`] при некорректной схеме/хосте,
    /// [`Error::NoAddresses`] если хост не разрешился.
    pub fn with_tls(url: &str, tls: ClientTlsConfig) -> Result<Self, Error> {
        let parsed = parse_doh_url(url)?;
        let mut addresses = resolve(&parsed.host, parsed.port)?;
        addresses.dedup();
        let display_host = if parsed.host.contains(':') {
            format!("[{}]", parsed.host)
        } else {
            parsed.host.clone()
        };
        let host_header = if parsed.port == DEFAULT_HTTPS_PORT {
            display_host
        } else {
            format!("{display_host}:{}", parsed.port)
        };
        Ok(Self {
            addresses,
            server_name: parse_server_name(&parsed.server_name)?,
            host_header,
            path: parsed.path,
            tls,
            connection: Mutex::new(None),
            reconnects: AtomicU64::new(0),
        })
    }

    /// Число переподключений (для метрик).
    #[must_use]
    pub fn reconnects(&self) -> u64 {
        self.reconnects.load(Ordering::Relaxed)
    }

    /// Отправляет DNS-сообщение POST-запросом и возвращает тело ответа.
    ///
    /// # Errors
    ///
    /// Ошибки TLS/HTTP, таймауты, не-200 статус и неверный Content-Type.
    pub fn query(
        &self,
        message: &[u8],
        connect_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<Vec<u8>, Error> {
        if message.is_empty() {
            return Err(Error::Http("empty DNS message".to_owned()));
        }
        if message.len() > MAX_DNS_MESSAGE {
            return Err(Error::MessageTooLarge {
                limit: MAX_DNS_MESSAGE,
            });
        }
        if connect_timeout.is_zero() || io_timeout.is_zero() {
            return Err(Error::Timeout);
        }
        let total = connect_timeout.saturating_add(io_timeout);
        let overall = Instant::now()
            .checked_add(total)
            .ok_or(Error::InvalidConfig("query timeout is too large"))?;
        let mut guard = lock_until(&self.connection, overall)?;
        let mut last_error = Error::Timeout;
        for attempt in 0..2 {
            if guard.is_none() {
                let connect_deadline = deadline_after(connect_timeout, overall)?;
                match self.connect(connect_deadline) {
                    Ok(stream) => {
                        if attempt > 0 {
                            self.reconnects.fetch_add(1, Ordering::Relaxed);
                        }
                        *guard = Some(HttpsConnection {
                            stream,
                            pending: Vec::new(),
                        });
                    }
                    Err(error) => {
                        last_error = error;
                        if attempt > 0 || !last_error.is_retryable_connection() {
                            return Err(last_error);
                        }
                        continue;
                    }
                }
            }
            let Some(connection) = guard.as_mut() else {
                continue;
            };
            let io_deadline = deadline_after(io_timeout, overall)?;
            match self.exchange(connection, message, io_deadline) {
                Ok((body, keep_alive)) => {
                    if !keep_alive {
                        *guard = None;
                    }
                    return Ok(body);
                }
                Err(error) => {
                    *guard = None;
                    last_error = error;
                    if attempt > 0 || !last_error.is_retryable_connection() {
                        return Err(last_error);
                    }
                }
            }
        }
        Err(last_error)
    }

    fn connect(&self, deadline: Instant) -> Result<ClientStream, Error> {
        let mut last_error = Error::NoAddresses("upstream".to_owned());
        for address in &self.addresses {
            let remaining = remaining(deadline)?;
            match ClientStream::connect(&self.tls, self.server_name.clone(), *address, remaining) {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    let retryable = error.is_retryable_connection();
                    last_error = error;
                    if !retryable {
                        return Err(last_error);
                    }
                }
            }
        }
        Err(last_error)
    }

    fn exchange(
        &self,
        connection: &mut HttpsConnection,
        message: &[u8],
        deadline: Instant,
    ) -> Result<(Vec<u8>, bool), Error> {
        let head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            self.path,
            self.host_header,
            message.len()
        );
        connection.stream.write_all(head.as_bytes(), deadline)?;
        connection.stream.write_all(message, deadline)?;
        let response_head = read_http_head(connection, deadline)?;
        let parsed = parse_response_head(&response_head)?;
        let length = parsed
            .content_length
            .ok_or_else(|| Error::Http("DoH response has no Content-Length".to_owned()))?;
        if length > MAX_DNS_MESSAGE {
            return Err(Error::MessageTooLarge {
                limit: MAX_DNS_MESSAGE,
            });
        }
        let mut body = Vec::with_capacity(length);
        let take = length.min(connection.pending.len());
        let initial = connection
            .pending
            .get(..take)
            .ok_or_else(|| Error::Http("body offset out of bounds".to_owned()))?;
        body.extend_from_slice(initial);
        connection.pending.drain(..take);
        while body.len() < length {
            let mut chunk = [0_u8; 8192];
            let want = (length - body.len()).min(chunk.len());
            let buffer = chunk
                .get_mut(..want)
                .ok_or_else(|| Error::Http("body chunk out of bounds".to_owned()))?;
            let read = connection.stream.read(buffer, deadline)?;
            if read == 0 {
                return Err(Error::Closed);
            }
            let data = chunk
                .get(..read)
                .ok_or_else(|| Error::Http("body read out of bounds".to_owned()))?;
            body.extend_from_slice(data);
        }
        Ok((body, parsed.keep_alive))
    }
}

impl std::fmt::Debug for DohClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DohClient")
            .field("addresses", &self.addresses)
            .field("host_header", &self.host_header)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Drop for DohClient {
    fn drop(&mut self) {
        if let Ok(guard) = self.connection.get_mut()
            && let Some(connection) = guard.as_mut()
        {
            connection.stream.close();
        }
    }
}

#[derive(Debug)]
struct ResponseHead {
    content_length: Option<usize>,
    keep_alive: bool,
}

fn parse_response_head(head: &[u8]) -> Result<ResponseHead, Error> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::Http("empty HTTP response".to_owned()))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.eq_ignore_ascii_case("HTTP/1.1") && !version.eq_ignore_ascii_case("HTTP/1.0") {
        return Err(Error::Http(format!("unsupported HTTP version {version:?}")));
    }
    let status = parts
        .next()
        .ok_or_else(|| Error::Http("missing HTTP status".to_owned()))?
        .parse::<u16>()
        .map_err(|_| Error::Http("invalid HTTP status".to_owned()))?;
    if status != 200 {
        return Err(Error::HttpStatus { status });
    }
    let mut content_length = None;
    let mut content_type_ok = false;
    let mut close = false;
    let mut keep_alive = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| Error::Http("invalid Content-Length".to_owned()))?,
            );
        } else if name.eq_ignore_ascii_case("content-type") {
            content_type_ok = value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/dns-message"));
        } else if name.eq_ignore_ascii_case("connection") {
            close = contains_token(value, "close");
            keep_alive = contains_token(value, "keep-alive");
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Error::Http(
                "chunked DoH responses are not supported".to_owned(),
            ));
        }
    }
    if !content_type_ok {
        return Err(Error::HttpContentType);
    }
    let keep_alive = if close {
        false
    } else if version.eq_ignore_ascii_case("HTTP/1.0") {
        keep_alive
    } else {
        true
    };
    Ok(ResponseHead {
        content_length,
        keep_alive,
    })
}

fn contains_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

fn read_http_head(connection: &mut HttpsConnection, deadline: Instant) -> Result<Vec<u8>, Error> {
    loop {
        if let Some(end) = find_head_end(&connection.pending) {
            let head = connection
                .pending
                .get(..end)
                .ok_or_else(|| Error::Http("head offset out of bounds".to_owned()))?
                .to_vec();
            connection.pending.drain(..end);
            return Ok(head);
        }
        if connection.pending.len() >= MAX_HEADER_BYTES {
            return Err(Error::MessageTooLarge {
                limit: MAX_HEADER_BYTES,
            });
        }
        let capacity = MAX_HEADER_BYTES - connection.pending.len();
        let mut chunk = [0_u8; 4096];
        let read_len = chunk.len().min(capacity);
        let buffer = chunk
            .get_mut(..read_len)
            .ok_or_else(|| Error::Http("head chunk out of bounds".to_owned()))?;
        let read = connection.stream.read(buffer, deadline)?;
        if read == 0 {
            return Err(Error::Closed);
        }
        let data = chunk
            .get(..read)
            .ok_or_else(|| Error::Http("head read out of bounds".to_owned()))?;
        connection.pending.extend_from_slice(data);
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

struct DohUrl {
    host: String,
    port: u16,
    server_name: String,
    path: String,
}

fn parse_doh_url(url: &str) -> Result<DohUrl, Error> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| Error::InvalidUrl(url.to_owned()))?;
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(Error::InvalidUrl(url.to_owned()));
    }
    let (rest, fragment) = match rest.split_once('#') {
        Some((rest, fragment)) => (rest, Some(fragment)),
        None => (rest, None),
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, DEFAULT_DOH_PATH.to_owned()),
    };
    if authority.is_empty()
        || authority.contains('\r')
        || authority.contains('\n')
        || path.contains('\r')
        || path.contains('\n')
    {
        return Err(Error::InvalidUrl(url.to_owned()));
    }
    if authority.contains('@') {
        return Err(Error::InvalidUrl(url.to_owned()));
    }
    let (host, port) = split_host_port(authority)?;
    if host.is_empty() {
        return Err(Error::InvalidUrl(url.to_owned()));
    }
    let server_name = fragment
        .filter(|name| !name.is_empty())
        .map_or_else(|| host.clone(), ToOwned::to_owned);
    let path = if path.is_empty() {
        DEFAULT_DOH_PATH.to_owned()
    } else {
        path
    };
    Ok(DohUrl {
        host,
        port,
        server_name,
        path,
    })
}

fn split_host_port(authority: &str) -> Result<(String, u16), Error> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| Error::InvalidUrl(authority.to_owned()))?;
        let port = match after.strip_prefix(':') {
            Some(port) if !port.is_empty() => port
                .parse::<u16>()
                .map_err(|_| Error::InvalidUrl(authority.to_owned()))?,
            Some(_) => return Err(Error::InvalidUrl(authority.to_owned())),
            None => DEFAULT_HTTPS_PORT,
        };
        return Ok((host.to_owned(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|ch| ch.is_ascii_digit()) => Ok((
            host.to_owned(),
            port.parse::<u16>()
                .map_err(|_| Error::InvalidUrl(authority.to_owned()))?,
        )),
        Some(_) => Err(Error::InvalidUrl(authority.to_owned())),
        None => Ok((authority.to_owned(), DEFAULT_HTTPS_PORT)),
    }
}

fn parse_server_name(value: &str) -> Result<ServerName<'static>, Error> {
    let trimmed = value.trim().trim_matches(|ch| ch == '[' || ch == ']');
    if let Ok(address) = trimmed.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(address.into()));
    }
    ServerName::try_from(trimmed.to_owned()).map_err(|_| Error::InvalidUrl(value.to_owned()))
}

fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, Error> {
    let host = host.trim().trim_matches(|ch| ch == '[' || ch == ']');
    let mut addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| Error::NoAddresses(host.to_owned()))?
        .collect();
    if addresses.is_empty() {
        return Err(Error::NoAddresses(host.to_owned()));
    }
    addresses.sort();
    Ok(addresses)
}

fn deadline_after(timeout: Duration, overall: Instant) -> Result<Instant, Error> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(Error::InvalidConfig("query timeout is too large"))?;
    Ok(deadline.min(overall))
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Error::Timeout);
    }
    Ok(remaining)
}

fn lock_until<T>(mutex: &Mutex<T>, deadline: Instant) -> Result<MutexGuard<'_, T>, Error> {
    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                return Ok(PoisonError::into_inner(poisoned));
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(Error::Timeout);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_urls() {
        let parsed = parse_doh_url("https://dns.google/dns-query").expect("url");
        assert_eq!(parsed.host, "dns.google");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/dns-query");
        assert_eq!(parsed.server_name, "dns.google");

        let parsed = parse_doh_url("https://127.0.0.1:8443/dns-query#localhost").expect("url");
        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 8443);
        assert_eq!(parsed.server_name, "localhost");

        let parsed = parse_doh_url("https://[::1]:8443").expect("url");
        assert_eq!(parsed.host, "::1");
        assert_eq!(parsed.port, 8443);
        assert_eq!(parsed.path, "/dns-query");
    }

    #[test]
    fn doh_host_header_has_a_single_port() {
        let tls = ClientTlsConfig::for_doh().expect("tls");
        let client =
            DohClient::with_tls("https://127.0.0.1:8443/dns-query", tls).expect("doh client");
        assert_eq!(client.host_header, "127.0.0.1:8443");

        let tls = ClientTlsConfig::for_doh().expect("tls");
        let client = DohClient::with_tls("https://127.0.0.1/dns-query", tls).expect("doh client");
        assert_eq!(client.host_header, "127.0.0.1");
    }

    #[test]
    fn rejects_invalid_urls() {
        assert!(parse_doh_url("http://dns.google/dns-query").is_err());
        assert!(parse_doh_url("https:///dns-query").is_err());
        assert!(parse_doh_url("https://dns.google:bad/dns-query").is_err());
        assert!(parse_doh_url("https://user@dns.google/dns-query").is_err());
    }

    #[test]
    fn parses_response_headers() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 12\r\nConnection: keep-alive\r\n\r\n";
        let parsed = parse_response_head(head).expect("head");
        assert_eq!(parsed.content_length, Some(12));
        assert!(parsed.keep_alive);

        let head = b"HTTP/1.1 500 Server Error\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            parse_response_head(head),
            Err(Error::HttpStatus { status: 500 })
        ));

        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n";
        assert!(matches!(
            parse_response_head(head),
            Err(Error::HttpContentType)
        ));
    }
}
