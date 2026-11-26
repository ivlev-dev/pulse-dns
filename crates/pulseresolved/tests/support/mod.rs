//! Mock upstream (UDP) и клиенты для интеграционных тестов.

#![allow(dead_code, clippy::doc_markdown)]

pub mod e2e;
pub mod https_source;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use e2e::{Attempt, SOCKET_TIMEOUT, retry, wait_until};

use pulse_dns::{
    DecodeLimits, Edns, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Record,
    Rtype, SoaData, Ttl,
};
use pulse_dnscrypt::{
    Certificate, CertificateParams as DnscryptCertificateParams, DnscryptClient, ProviderKeypair,
    ResolverKeypair, random_client_magic,
};
use pulseresolved::config::{CacheSetting, Config, ModeSetting, TimeoutSetting};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

/// UDP mock-upstream с обработчиком запросов.
pub struct MockUpstream {
    address: SocketAddr,
    hits: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MockUpstream {
    /// Запускает сервер; обработчик получает запрос и возвращает ответ.
    pub fn start<F>(handler: F) -> Self
    where
        F: Fn(&Message) -> Option<Message> + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind mock upstream");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("read timeout");
        let address = socket.local_addr().expect("mock addr");
        let hits = Arc::new(AtomicU64::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        let thread_hits = Arc::clone(&hits);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while !thread_shutdown.load(Ordering::Relaxed) {
                let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                thread_hits.fetch_add(1, Ordering::Relaxed);
                let Some(bytes) = buffer.get(..length) else {
                    continue;
                };
                let Ok(request) = Message::decode(bytes, &DecodeLimits::default()) else {
                    continue;
                };
                if let Some(response) = handler(&request)
                    && let Ok(mut encoded) = response.encode(&EncodeOptions::default())
                {
                    // Настоящий upstream сохраняет регистр QNAME; `Name`
                    // канонизирует его в нижний, поэтому 0x20 восстанавливаем
                    // из исходного запроса.
                    preserve_question_case(&mut encoded, bytes);
                    let _ = socket.send_to(&encoded, peer);
                }
            }
        });
        Self {
            address,
            hits,
            shutdown,
            thread: Some(thread),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Конфигурация с forward-режимом на mock upstream и эфемерными портами.
pub fn base_config(upstream: SocketAddr) -> Config {
    Config {
        listen_udp: Some("127.0.0.1:0".parse().unwrap()),
        listen_tcp: Some("127.0.0.1:0".parse().unwrap()),
        workers: 1,
        mode: ModeSetting::Forward,
        forwarders: vec![upstream],
        timeouts: TimeoutSetting {
            // Щедрые лимиты: debug-сборка под нагрузкой может планироваться
            // с задержкой, а mock upstream отвечает из отдельного потока.
            per_query_ms: 2_000,
            tcp_ms: 3_000,
            total_ms: 15_000,
        },
        cache: CacheSetting {
            max_entries: 1_024,
            max_bytes: 1 << 20,
            ..CacheSetting::default()
        },
        ..Config::default()
    }
}

/// Запрос A/AAAA/TXT с опциональным EDNS payload.
pub fn make_query(name: &str, rtype: Rtype, edns_payload: Option<u16>) -> Message {
    let question = Question::new(Name::parse(name).expect("valid qname"), rtype, Rclass::IN);
    let mut message = Message::query(0x4242, question);
    if let Some(payload) = edns_payload {
        message.set_edns(Some(Edns::new(payload)));
    }
    message
}

/// UDP-запрос; возвращает декодированный ответ или `None` по таймауту.
pub fn udp_query(server: SocketAddr, request: &Message, timeout: Duration) -> Option<Message> {
    let bytes = request.encode(&EncodeOptions::default()).expect("encode");
    udp_query_raw(server, &bytes, timeout)
}

/// Сырой UDP-запрос.
pub fn udp_query_raw(server: SocketAddr, request: &[u8], timeout: Duration) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    socket
        .set_read_timeout(Some(timeout))
        .expect("client timeout");
    e2e::send_to(&socket, request, server).ok()?;
    let mut buffer = [0_u8; 4096];
    match e2e::recv_from(&socket, &mut buffer) {
        Ok((length, _)) => {
            let bytes = buffer.get(..length)?;
            Message::decode(bytes, &DecodeLimits::default()).ok()
        }
        Err(_) => None,
    }
}

/// UDP-запрос с повторами до общего дедлайна e2e.
///
/// # Panics
///
/// Если корректный ответ не получен до [`e2e::E2E_DEADLINE`].
pub fn udp_query_retry(server: SocketAddr, request: &Message, label: &str) -> Message {
    udp_query_retry_counted(server, request, label).0
}

/// Как [`udp_query_retry`], но возвращает и число фактических отправок.
///
/// Полезно для проверки счётчиков: повтор мог быть доставлен серверу.
///
/// # Panics
///
/// Если корректный ответ не получен до [`e2e::E2E_DEADLINE`].
pub fn udp_query_retry_counted(
    server: SocketAddr,
    request: &Message,
    label: &str,
) -> (Message, u64) {
    let bytes = request.encode(&EncodeOptions::default()).expect("encode");
    let mut attempts = 0_u64;
    let message = retry(
        label,
        || format!("udp {server}"),
        || {
            attempts = attempts.saturating_add(1);
            udp_query_raw(server, &bytes, SOCKET_TIMEOUT)
                .ok_or_else(|| format!("нет ответа от UDP {server} за {SOCKET_TIMEOUT:?}"))
        },
    );
    (message, attempts)
}

/// TCP-подключение с повторами до общего дедлайна e2e.
///
/// # Panics
///
/// Если подключиться не удалось до [`e2e::E2E_DEADLINE`].
pub fn connect_tcp(server: SocketAddr, label: &str) -> TcpStream {
    retry(
        label,
        || format!("tcp {server}"),
        || TcpStream::connect(server).map_err(|error| e2e::io_error("connect", &error)),
    )
}

/// TCP-запрос с length-prefix framing.
pub fn tcp_query(server: SocketAddr, request: &Message, timeout: Duration) -> Option<Message> {
    let bytes = request.encode(&EncodeOptions::default()).expect("encode");
    let mut stream = TcpStream::connect(server).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let length = u16::try_from(bytes.len()).ok()?;
    e2e::write_all(&mut stream, &length.to_be_bytes()).ok()?;
    e2e::write_all(&mut stream, &bytes).ok()?;
    stream.flush().ok()?;
    let mut prefix = [0_u8; 2];
    e2e::read_exact(&mut stream, &mut prefix).ok()?;
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    e2e::read_exact(&mut stream, &mut response).ok()?;
    Message::decode(&response, &DecodeLimits::default()).ok()
}

/// TCP-запрос с повторами до общего дедлайна e2e.
///
/// # Panics
///
/// Если корректный ответ не получен до [`e2e::E2E_DEADLINE`].
pub fn tcp_query_retry(server: SocketAddr, request: &Message, label: &str) -> Message {
    let bytes = request.encode(&EncodeOptions::default()).expect("encode");
    retry(
        label,
        || format!("tcp {server}"),
        || {
            let mut stream =
                TcpStream::connect(server).map_err(|error| e2e::io_error("connect", &error))?;
            stream
                .set_read_timeout(Some(SOCKET_TIMEOUT))
                .map_err(|error| e2e::io_error("set_read_timeout", &error))?;
            stream
                .set_write_timeout(Some(SOCKET_TIMEOUT))
                .map_err(|error| e2e::io_error("set_write_timeout", &error))?;
            let length =
                u16::try_from(bytes.len()).map_err(|_| "query does not fit u16".to_owned())?;
            e2e::write_all(&mut stream, &length.to_be_bytes())
                .map_err(|error| e2e::io_error("write length", &error))?;
            e2e::write_all(&mut stream, &bytes)
                .map_err(|error| e2e::io_error("write query", &error))?;
            stream
                .flush()
                .map_err(|error| e2e::io_error("flush", &error))?;
            let mut prefix = [0_u8; 2];
            e2e::read_exact(&mut stream, &mut prefix)
                .map_err(|error| e2e::io_error("read length", &error))?;
            let mut response = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
            e2e::read_exact(&mut stream, &mut response)
                .map_err(|error| e2e::io_error("read response", &error))?;
            Message::decode(&response, &DecodeLimits::default())
                .map_err(|error| format!("декодирование ответа: {error}"))
        },
    )
}

fn preserve_question_case(response: &mut [u8], request: &[u8]) {
    let Some((request_start, request_end)) = question_range(request) else {
        return;
    };
    let Some((response_start, response_end)) = question_range(response) else {
        return;
    };
    let Some(source) = request.get(request_start..request_end) else {
        return;
    };
    let Some(target) = response.get_mut(response_start..response_end) else {
        return;
    };
    if source.len() == target.len() {
        target.copy_from_slice(source);
    }
}

fn question_range(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut position = 12_usize;
    loop {
        let length = *bytes.get(position)?;
        if length == 0 {
            return Some((12, position.checked_add(1)?));
        }
        if length > 63 {
            return None;
        }
        position = position.checked_add(1 + usize::from(length))?;
        if position >= bytes.len() {
            return None;
        }
    }
}

/// A-ответ с TTL.
pub fn a_record(name: &str, address: [u8; 4], ttl: u32) -> Record {
    Record::new(
        Name::parse(name).expect("owner"),
        Rtype::A,
        Rclass::IN,
        Ttl::new(ttl).expect("ttl"),
        Rdata::A(address.into()),
    )
    .expect("A record")
}

/// Простой положительный ответ на единственный вопрос.
pub fn positive_response(request: &Message, record: Record) -> Message {
    let mut response = Message::response(request);
    response.set_rcode(Rcode::NOERROR);
    response.add_answer(record);
    response
}

/// `NS`-запись.
pub fn ns(owner: &str, ttl: u32, target: &str) -> Record {
    Record::new(
        Name::parse(owner).expect("owner"),
        Rtype::NS,
        Rclass::IN,
        Ttl::new(ttl).expect("ttl"),
        Rdata::Ns(Name::parse(target).expect("target")),
    )
    .expect("NS record")
}

/// Делегирование: NOERROR без ответов, NS в authority.
pub fn referral_response(request: &Message) -> Message {
    let mut response = Message::response(request);
    response.set_rcode(Rcode::NOERROR);
    response
}

/// NXDOMAIN с SOA в authority (RFC 2308 negative caching).
pub fn nxdomain_response(request: &Message, zone: &str) -> Message {
    let owner = Name::parse(zone).expect("zone");
    let soa = Record::new(
        owner,
        Rtype::SOA,
        Rclass::IN,
        Ttl::new(300).expect("ttl"),
        Rdata::Soa(SoaData::new(
            Name::parse("ns1.example.test").expect("mname"),
            Name::parse("hostmaster.example.test").expect("rname"),
            pulse_dns::Serial::new(1),
            3600,
            600,
            86_400,
            60,
        )),
    )
    .expect("SOA");
    let mut response = Message::response(request);
    response.set_rcode(Rcode::NXDOMAIN);
    response.add_authority(soa);
    response
}

/// Self-signed сертификат и файлы на диске (ключ с правами `0600`).
pub struct TestPki {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    /// Каталог живёт столько же, сколько `TestPki`.
    pub dir: tempfile::TempDir,
}

impl TestPki {
    /// Генерирует пару для `localhost`/`127.0.0.1` и пишет её в tempdir.
    pub fn generate() -> Self {
        let key = KeyPair::generate().expect("key pair");
        let params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("certificate params");
        let certificate = params.self_signed(&key).expect("self-signed");
        let cert_pem = certificate.pem();
        let key_pem = key.serialize_pem();
        let cert_der = certificate.der().to_vec();
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert");
        write_secret(&key_path, key_pem.as_bytes());
        Self {
            cert_pem,
            key_pem,
            cert_der,
            cert_path,
            key_path,
            dir,
        }
    }
}

/// Записывает файл и выставляет права `0600` (Unix).
pub fn write_secret(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write secret file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    }
}

/// Клиентский rustls-конфиг, доверяющий только `cert_der`.
pub fn tls_client_config(cert_der: &[u8], alpn: &[u8]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.to_vec()))
        .expect("add root");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

/// HTTP-ответ тестового клиента.
pub struct HttpsResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: Option<String>,
}

/// Синхронный TLS-клиент для DoT и DoH/1.1 (std + rustls).
pub struct TestTlsClient {
    connection: ClientConnection,
    socket: TcpStream,
    buffer: Vec<u8>,
}

impl TestTlsClient {
    pub fn connect(addr: SocketAddr, cert_der: &[u8], alpn: &[u8]) -> Option<Self> {
        let config = tls_client_config(cert_der, alpn);
        let name = ServerName::try_from("localhost").ok()?;
        let mut connection = ClientConnection::new(Arc::new(config), name).ok()?;
        let mut socket = TcpStream::connect(addr).ok()?;
        socket.set_read_timeout(Some(SOCKET_TIMEOUT)).ok()?;
        socket.set_write_timeout(Some(SOCKET_TIMEOUT)).ok()?;
        socket.set_nodelay(true).ok()?;
        while connection.is_handshaking() {
            connection.complete_io(&mut socket).ok()?;
        }
        Some(Self {
            connection,
            socket,
            buffer: Vec::new(),
        })
    }

    pub fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        self.connection.alpn_protocol().map(<[u8]>::to_vec)
    }

    pub fn send(&mut self, data: &[u8]) -> Option<()> {
        self.connection.writer().write_all(data).ok()?;
        while self.connection.wants_write() {
            match self.connection.write_tls(&mut self.socket) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
        }
        Some(())
    }

    fn fill(&mut self) -> Option<()> {
        let mut chunk = [0_u8; 4096];
        loop {
            match self.connection.reader().read(&mut chunk) {
                Ok(0) => return None,
                Ok(read) => {
                    self.buffer.extend_from_slice(chunk.get(..read)?);
                    return Some(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return None,
            }
            let read = match self.connection.read_tls(&mut self.socket) {
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            };
            if read == 0 {
                return None;
            }
            self.connection.process_new_packets().ok()?;
        }
    }

    pub fn read_exact(&mut self, length: usize) -> Option<Vec<u8>> {
        while self.buffer.len() < length {
            self.fill()?;
        }
        let bytes = self.buffer.get(..length)?.to_vec();
        self.buffer.drain(..length);
        Some(bytes)
    }

    /// DoT: length-prefixed DNS-запрос и ответ (RFC 7858).
    pub fn dot_query(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        let length = u16::try_from(message.len()).ok()?;
        self.send(&length.to_be_bytes())?;
        self.send(message)?;
        let prefix = self.read_exact(2)?;
        let length = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
        self.read_exact(length)
    }

    /// DoH/1.1 POST /dns-query.
    pub fn https_post(&mut self, path: &str, body: &[u8]) -> Option<HttpsResponse> {
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            body.len()
        );
        self.send(head.as_bytes())?;
        self.send(body)?;
        self.read_http()
    }

    /// DoH/1.1 GET с уже закодированным query string.
    pub fn https_get(&mut self, target: &str) -> Option<HttpsResponse> {
        let head = format!(
            "GET {target} HTTP/1.1\r\nHost: localhost\r\nAccept: application/dns-message\r\nConnection: keep-alive\r\n\r\n"
        );
        self.send(head.as_bytes())?;
        self.read_http()
    }

    fn read_http(&mut self) -> Option<HttpsResponse> {
        let head_end = loop {
            if let Some(position) = find_head_end(&self.buffer) {
                break position;
            }
            self.fill()?;
        };
        let head = String::from_utf8_lossy(self.buffer.get(..head_end)?).into_owned();
        self.buffer.drain(..head_end);
        let mut lines = head.split("\r\n");
        let status = lines
            .next()?
            .split_whitespace()
            .nth(1)?
            .parse::<u16>()
            .ok()?;
        let mut content_type = None;
        let mut length = 0_usize;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim().to_ascii_lowercase();
                match name.as_str() {
                    "content-type" => content_type = Some(value.trim().to_owned()),
                    "content-length" => length = value.trim().parse().ok()?,
                    _ => {}
                }
            }
        }
        let body = self.read_exact(length)?;
        Some(HttpsResponse {
            status,
            body,
            content_type,
        })
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Ключи, сертификат и клиент DNSCrypt v2.
pub struct DnscryptFixture {
    pub provider: ProviderKeypair,
    pub resolver: ResolverKeypair,
    pub certificate: Certificate,
    pub client: DnscryptClient,
    pub provider_path: PathBuf,
    pub resolver_path: PathBuf,
    pub cert_path: PathBuf,
}

impl DnscryptFixture {
    /// Генерирует материал и файлы для конфигурации `pulseresolved`.
    pub fn generate(dir: &Path) -> Self {
        let provider = ProviderKeypair::generate().expect("provider key");
        let resolver = ResolverKeypair::generate().expect("resolver key");
        let now = unix_now();
        let params = DnscryptCertificateParams::new(
            resolver.public_key().to_bytes(),
            random_client_magic().expect("client magic"),
            1,
            u32::try_from(now).expect("now fits u32"),
            u32::try_from(now + 86_400).expect("validity fits u32"),
        );
        let certificate = Certificate::sign(&provider, params).expect("sign certificate");
        let client = DnscryptClient::new(certificate.clone(), provider.public_key(), now)
            .expect("dnscrypt client");

        let provider_path = dir.join("dnscrypt-provider.key");
        let resolver_path = dir.join("dnscrypt-resolver.key");
        let cert_path = dir.join("dnscrypt-cert.hex");
        let provider_hex = pulse_dnscrypt::to_hex(&*provider.to_seed());
        let resolver_hex = pulse_dnscrypt::to_hex(&*resolver.to_secret_bytes());
        write_secret(&provider_path, provider_hex.as_bytes());
        write_secret(&resolver_path, resolver_hex.as_bytes());
        std::fs::write(&cert_path, certificate.to_hex()).expect("write certificate");
        Self {
            provider,
            resolver,
            certificate,
            client,
            provider_path,
            resolver_path,
            cert_path,
        }
    }
}

/// UDP-обмен DNSCrypt-пакетами (одна попытка, новый client nonce).
pub fn dnscrypt_udp_query(
    server: SocketAddr,
    client: &DnscryptClient,
    request: &Message,
    timeout: Duration,
) -> Option<Message> {
    let wire = request.encode(&EncodeOptions::default()).ok()?;
    // build_query генерирует случайный client-nonce: повтор пакета сервер
    // отбросит из-за anti-replay, поэтому каждая попытка шифруется заново.
    let pending = client
        .build_query(&wire, pulse_dnscrypt::Transport::Udp)
        .ok()?;
    let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    e2e::send_to(&socket, pending.packet(), server).ok()?;
    let mut buffer = [0_u8; 8192];
    let (length, _) = e2e::recv_from(&socket, &mut buffer).ok()?;
    let packet = buffer.get(..length)?;
    let response = client.decrypt_response(&pending, packet).ok()?;
    Message::decode(&response, &DecodeLimits::default()).ok()
}

/// Диалог DNSCrypt over UDP: каждый повтор строит новый запрос (новый
/// client nonce), иначе сервер отбросит пакет как replay.
pub struct DnscryptUdpClient<'a> {
    server: SocketAddr,
    client: &'a DnscryptClient,
    sent: u64,
}

impl<'a> DnscryptUdpClient<'a> {
    pub const fn new(server: SocketAddr, client: &'a DnscryptClient) -> Self {
        Self {
            server,
            client,
            sent: 0,
        }
    }

    /// Число фактически отправленных запросов (включая повторы).
    pub const fn sent(&self) -> u64 {
        self.sent
    }

    /// Выполняет запрос с повторами до [`e2e::E2E_DEADLINE`].
    ///
    /// # Panics
    ///
    /// Если сервер не ответил до дедлайна.
    pub fn query(
        &mut self,
        request: &Message,
        label: &str,
        diagnostics: impl Fn() -> String,
    ) -> Message {
        let server = self.server;
        let client = self.client;
        retry(label, diagnostics, || {
            self.sent = self.sent.saturating_add(1);
            dnscrypt_udp_query(server, client, request, SOCKET_TIMEOUT)
                .ok_or_else(|| format!("нет DNSCrypt UDP ответа от {server} за {SOCKET_TIMEOUT:?}"))
        })
    }
}

/// Ждёт, пока UDP-сокет DNSCrypt начнёт принимать пакеты.
///
/// Шлёт заведомо некорректный (слишком короткий) пакет: сервер обязан
/// увеличить счётчик ошибок, не трогая счётчики валидных запросов.
///
/// # Panics
///
/// Если сервер не начал читать сокет до [`e2e::E2E_DEADLINE`].
pub fn wait_dnscrypt_udp_listening(server: SocketAddr, errors: impl Fn() -> u64) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind dnscrypt probe");
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("probe timeout");
    wait_until(
        "DNSCrypt UDP listener",
        || format!("probe {server}"),
        || {
            let before = errors();
            let _ = e2e::send_to(&socket, b"pulse-e2e-probe", server);
            std::thread::sleep(Duration::from_millis(20));
            errors() > before
        },
    );
}

/// TCP-обмен DNSCrypt-кадрами (одна попытка, новый client nonce).
pub fn dnscrypt_tcp_query(
    stream: &mut TcpStream,
    client: &DnscryptClient,
    request: &Message,
    timeout: Duration,
) -> Option<Message> {
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let wire = request.encode(&EncodeOptions::default()).ok()?;
    let pending = client
        .build_query(&wire, pulse_dnscrypt::Transport::Tcp)
        .ok()?;
    e2e::write_all(stream, pending.packet()).ok()?;
    stream.flush().ok()?;
    let mut prefix = [0_u8; 2];
    e2e::read_exact(stream, &mut prefix).ok()?;
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut frame = vec![0_u8; 2 + length];
    frame.get_mut(..2)?.copy_from_slice(&prefix);
    e2e::read_exact(stream, frame.get_mut(2..)?).ok()?;
    let response = client.decrypt_response(&pending, &frame).ok()?;
    Message::decode(&response, &DecodeLimits::default()).ok()
}

/// Диалог DNSCrypt over TCP: держит соединение, но при обрыве переподключается.
///
/// Каждая попытка шифруется с новым client nonce, поэтому повтор безопасен
/// с точки зрения anti-replay.
pub struct DnscryptTcpClient<'a> {
    server: SocketAddr,
    client: &'a DnscryptClient,
    stream: Option<TcpStream>,
    sent: u64,
    connections: u64,
}

impl<'a> DnscryptTcpClient<'a> {
    pub const fn new(server: SocketAddr, client: &'a DnscryptClient) -> Self {
        Self {
            server,
            client,
            stream: None,
            sent: 0,
            connections: 0,
        }
    }

    /// Число фактически отправленных запросов (включая повторы).
    pub const fn sent(&self) -> u64 {
        self.sent
    }

    /// Число успешных TCP-подключений (включая переподключения).
    pub const fn connections(&self) -> u64 {
        self.connections
    }

    fn connect(&mut self) -> Attempt<()> {
        let stream = TcpStream::connect(self.server)
            .map_err(|error| e2e::io_error("dnscrypt tcp connect", &error))?;
        stream
            .set_nodelay(true)
            .map_err(|error| e2e::io_error("dnscrypt tcp nodelay", &error))?;
        self.stream = Some(stream);
        self.connections = self.connections.saturating_add(1);
        Ok(())
    }

    /// Устанавливает соединение с повторами до [`e2e::E2E_DEADLINE`].
    ///
    /// # Panics
    ///
    /// Если подключиться не удалось.
    pub fn ensure_connected(&mut self, label: &str, diagnostics: impl Fn() -> String) {
        retry(label, diagnostics, || {
            if self.stream.is_some() {
                return Ok(());
            }
            self.connect()
        });
    }

    /// Выполняет запрос с повторами; при обрыве соединение пересоздаётся.
    ///
    /// # Panics
    ///
    /// Если сервер не ответил до дедлайна.
    pub fn query(
        &mut self,
        request: &Message,
        label: &str,
        diagnostics: impl Fn() -> String,
    ) -> Message {
        let server = self.server;
        let client = self.client;
        retry(label, diagnostics, || {
            if self.stream.is_none() {
                self.connect()?;
            }
            self.sent = self.sent.saturating_add(1);
            let Some(stream) = self.stream.as_mut() else {
                return Err("dnscrypt tcp stream missing after connect".to_owned());
            };
            if let Some(message) = dnscrypt_tcp_query(stream, client, request, SOCKET_TIMEOUT) {
                Ok(message)
            } else {
                self.stream = None;
                Err(format!("нет DNSCrypt TCP ответа от {server}"))
            }
        })
    }
}

/// Компактный снимок всех счётчиков сервера для диагностики при падении.
pub fn server_diagnostics(server: &pulseresolved::server::Server) -> String {
    format!(
        "stats={:?}; dot={:?}; doh={:?}; doh2={:?}; doq={:?}; resolver={:?}",
        server.stats(),
        server.dot_stats(),
        server.doh_stats(),
        server.doh2_stats(),
        server.doq_stats(),
        server.resolver_stats(),
    )
}

/// `A`-ответ с TTL.
pub fn txt_records(name: &str, count: usize, ttl: u32) -> Vec<Record> {
    (0..count)
        .map(|index| {
            let text = format!("{index:04}-{}", "x".repeat(100));
            Record::new(
                Name::parse(name).expect("owner"),
                Rtype::TXT,
                Rclass::IN,
                Ttl::new(ttl).expect("ttl"),
                Rdata::Txt(pulse_dns::TxtData::new([text.as_bytes().to_vec()]).expect("txt")),
            )
            .expect("TXT record")
        })
        .collect()
}

/// `AAAA`-ответ с TTL.
pub fn aaaa_record(name: &str, address: &str, ttl: u32) -> Record {
    Record::new(
        Name::parse(name).expect("owner"),
        Rtype::AAAA,
        Rclass::IN,
        Ttl::new(ttl).expect("ttl"),
        Rdata::Aaaa(address.parse().expect("ipv6")),
    )
    .expect("AAAA record")
}

/// Форматирует hex в нижнем регистре (для отладочных сообщений тестов).
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
