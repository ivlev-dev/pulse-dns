//! DNSCrypt v2: загрузка ключей/сертификата, UDP-транспорт и генератор
//! сертификатов (`pulsed dnscrypt-gencert`).
//!
//! Сервер получает расшифрованный DNS-запрос и обрабатывает его тем же
//! путём, что и UDP: `decode → QueryEngine (mmap snapshot) → encode`.
//! DNSCrypt v2 не имеет открытого текста на проводе: клиент аутентифицирован
//! сертификатом провайдера, ответ шифруется ключом резолвера.
//!
//! Ограничение MVP: реализован UDP-транспорт (`dnscrypt_listen`). TCP-порт
//! DNSCrypt не поднимается; клиенты, получившие `TC`, должны использовать
//! обычные DoT/DoH или UDP/TCP-транспорты `pulsed`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::{Shutdown as SocketShutdown, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pulse_dns::Name;
use pulse_dnscrypt::{
    Certificate, CertificateParams, DnscryptServer, ProviderKeypair, ProviderPublicKey,
    ResolverKeypair, ServerConfig, random_client_magic,
};
use pulse_runtime::{Reply, RuntimeConfig, UdpServer};
use pulse_server::Transport;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::Config;
use crate::dns;
use crate::metrics::TransportMetrics;
use crate::stats::Stats;
use crate::store::SharedZoneAdmin;

/// Имя файла provider-ключа по умолчанию.
pub const PROVIDER_KEY_FILE: &str = "dnscrypt-provider.key";
/// Имя файла resolver-ключа по умолчанию.
pub const RESOLVER_KEY_FILE: &str = "dnscrypt-resolver.key";
/// Имя файла подписанного сертификата по умолчанию.
pub const CERT_FILE: &str = "dnscrypt-cert.json";
/// Имя файла с готовой TXT-записью по умолчанию.
pub const TXT_FILE: &str = "dnscrypt-cert.txt";

/// Ошибка запуска DNSCrypt или генерации сертификата.
#[derive(Debug, Error)]
pub enum DnscryptError {
    /// Ошибка файловой системы.
    #[error("DNSCrypt I/O error for {path}: {source}")]
    Io {
        /// Путь.
        path: PathBuf,
        /// Причина.
        #[source]
        source: std::io::Error,
    },
    /// Некорректный ключ в файле.
    #[error("invalid DNSCrypt key {path}: {reason}")]
    InvalidKey {
        /// Путь.
        path: PathBuf,
        /// Причина.
        reason: String,
    },
    /// Некорректный сертификат или его несоответствие ключам.
    #[error("invalid DNSCrypt certificate: {0}")]
    Certificate(String),
    /// Слишком широкие права на приватный ключ.
    #[error("insecure DNSCrypt key permissions: {0}")]
    Permission(String),
    /// Ошибка криптографии/протокола `pulse-dnscrypt`.
    #[error(transparent)]
    Crypto(#[from] pulse_dnscrypt::Error),
    /// Некорректное имя провайдера.
    #[error(transparent)]
    Name(#[from] pulse_dns::NameError),
    /// Ошибка UDP-рантайма.
    #[error(transparent)]
    Runtime(#[from] pulse_runtime::RuntimeError),
    /// Ошибка TCP-listener'а DNSCrypt.
    #[error("DNSCrypt TCP transport error: {source}")]
    Tcp {
        /// Причина.
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct CertificateFile {
    serial: u32,
    valid_from: u32,
    valid_until: u32,
    client_magic: String,
    provider_public_key: String,
    resolver_public_key: String,
    certificate: String,
}

/// Параметры `pulsed dnscrypt-gencert`.
#[derive(Debug, Clone)]
pub(crate) struct GenCertOptions {
    /// Каталог для ключей и сертификата.
    pub out_dir: PathBuf,
    /// Полное имя провайдера (`2.dnscrypt-cert.example.com.`).
    pub provider_name: String,
    /// Серийный номер сертификата.
    pub serial: u32,
    /// Срок действия в днях.
    pub validity_days: u32,
    /// Перезаписать существующие файлы.
    pub force: bool,
}

/// Результат генерации.
#[derive(Debug, Clone)]
pub(crate) struct GeneratedCert {
    /// Нормализованное имя провайдера.
    pub provider_name: String,
    /// Публичный ключ провайдера (hex).
    pub provider_public_key: String,
    /// Файл provider-ключа.
    pub provider_key: PathBuf,
    /// Файл resolver-ключа.
    pub resolver_key: PathBuf,
    /// Файл сертификата.
    pub cert: PathBuf,
    /// Файл с TXT-записями для master-файла.
    pub txt: PathBuf,
    /// Готовые TXT-записи.
    pub txt_records: String,
}

impl DnscryptError {
    fn io(path: &Path) -> impl FnOnce(std::io::Error) -> Self + '_ {
        move |source| Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// Загружает ключи и подписанный сертификат, собирает `DnscryptServer`.
///
/// # Errors
///
/// [`DnscryptError`] при ошибке чтения, прав или проверки сертификата.
pub(crate) fn load_server(
    config: &Config,
) -> Result<(Arc<DnscryptServer>, Certificate), DnscryptError> {
    let provider_path =
        config
            .dnscrypt_provider_key
            .as_deref()
            .ok_or_else(|| DnscryptError::InvalidKey {
                path: PathBuf::from("dnscrypt_provider_key"),
                reason: "not configured".to_owned(),
            })?;
    let resolver_path =
        config
            .dnscrypt_resolver_key
            .as_deref()
            .ok_or_else(|| DnscryptError::InvalidKey {
                path: PathBuf::from("dnscrypt_resolver_key"),
                reason: "not configured".to_owned(),
            })?;
    let cert_path = config
        .dnscrypt_cert
        .as_deref()
        .ok_or_else(|| DnscryptError::Certificate("dnscrypt_cert is not configured".to_owned()))?;
    crate::perms::ensure_private(provider_path, "dnscrypt_provider_key")
        .map_err(DnscryptError::Permission)?;
    crate::perms::ensure_private(resolver_path, "dnscrypt_resolver_key")
        .map_err(DnscryptError::Permission)?;

    let provider = ProviderKeypair::from_seed(read_key_seed(provider_path)?);
    let resolver = ResolverKeypair::from_secret_bytes(read_key_seed(resolver_path)?);
    let (certificate, file) = read_certificate(cert_path)?;
    let expected_provider = provider.public_key();
    let declared = ProviderPublicKey::from_hex(file.provider_public_key.trim())
        .map_err(|_| DnscryptError::Certificate("invalid provider_public_key".to_owned()))?;
    if declared != expected_provider {
        return Err(DnscryptError::Certificate(
            "certificate provider_public_key does not match dnscrypt_provider_key".to_owned(),
        ));
    }
    let mut server = DnscryptServer::new(expected_provider, ServerConfig::default())?;
    server.add_certificate(certificate.clone(), resolver)?;
    Ok((Arc::new(server), certificate))
}

fn read_key_seed(path: &Path) -> Result<[u8; 32], DnscryptError> {
    let text = fs::read_to_string(path).map_err(DnscryptError::io(path))?;
    let bytes = hex::decode(text.trim()).map_err(|error| DnscryptError::InvalidKey {
        path: path.to_path_buf(),
        reason: format!("not valid hex: {error}"),
    })?;
    bytes.try_into().map_err(|_| DnscryptError::InvalidKey {
        path: path.to_path_buf(),
        reason: "expected exactly 32 bytes".to_owned(),
    })
}

fn read_certificate(path: &Path) -> Result<(Certificate, CertificateFile), DnscryptError> {
    let text = fs::read_to_string(path).map_err(DnscryptError::io(path))?;
    let file: CertificateFile = serde_json::from_str(&text)
        .map_err(|error| DnscryptError::Certificate(format!("{}: {error}", path.display())))?;
    let certificate = Certificate::from_hex(file.certificate.trim())
        .map_err(|error| DnscryptError::Certificate(format!("{}: {error}", path.display())))?;
    if certificate.serial() != file.serial
        || certificate.ts_start() != file.valid_from
        || certificate.ts_end() != file.valid_until
    {
        return Err(DnscryptError::Certificate(format!(
            "{}: fields do not match the signed certificate",
            path.display()
        )));
    }
    let magic = hex::decode(file.client_magic.trim()).map_err(|error| {
        DnscryptError::Certificate(format!("{}: invalid client_magic: {error}", path.display()))
    })?;
    if magic.as_slice() != certificate.client_magic() {
        return Err(DnscryptError::Certificate(format!(
            "{}: client_magic does not match the certificate",
            path.display()
        )));
    }
    let resolver = hex::decode(file.resolver_public_key.trim()).map_err(|error| {
        DnscryptError::Certificate(format!(
            "{}: invalid resolver_public_key: {error}",
            path.display()
        ))
    })?;
    if resolver.as_slice() != certificate.resolver_pk() {
        return Err(DnscryptError::Certificate(format!(
            "{}: resolver_public_key does not match the certificate",
            path.display()
        )));
    }
    Ok((certificate, file))
}

/// Генерирует provider/resolver ключи и подписанный сертификат.
///
/// Приватные ключи записываются с правами 0600, каталог (если создаётся) —
/// 0700. Секреты не возвращаются и не печатаются.
///
/// # Errors
///
/// [`DnscryptError`] при ошибке файловой системы, генерации или подписи.
pub(crate) fn generate_certificate(
    options: &GenCertOptions,
) -> Result<GeneratedCert, DnscryptError> {
    let provider_name = Name::parse(options.provider_name.trim())?;
    if provider_name == Name::root() || provider_name.labels().any(|label| label == b"*") {
        return Err(DnscryptError::Certificate(
            "provider name must be a non-root name without wildcards".to_owned(),
        ));
    }
    if options.serial == 0 {
        return Err(DnscryptError::Certificate(
            "serial must be greater than zero".to_owned(),
        ));
    }
    if options.validity_days == 0 {
        return Err(DnscryptError::Certificate(
            "validity_days must be greater than zero".to_owned(),
        ));
    }
    let now = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                DnscryptError::Certificate(format!("system clock is before Unix epoch: {error}"))
            })?
            .as_secs(),
    )
    .map_err(|_| DnscryptError::Certificate("system clock exceeds u32 range".to_owned()))?;
    let validity = options
        .validity_days
        .checked_mul(86_400)
        .ok_or_else(|| DnscryptError::Certificate("validity_days is too large".to_owned()))?;
    let valid_until = now
        .checked_add(validity)
        .ok_or_else(|| DnscryptError::Certificate("validity_days overflows time".to_owned()))?;

    let provider = ProviderKeypair::generate()?;
    let resolver = ResolverKeypair::generate()?;
    let provider_public = provider.public_key();
    let resolver_public = resolver.public_key();
    let params = CertificateParams::new(
        resolver_public.to_bytes(),
        random_client_magic()?,
        options.serial,
        now,
        valid_until,
    );
    let certificate = Certificate::sign(&provider, params)?;

    ensure_dir(&options.out_dir)?;
    let provider_key = options.out_dir.join(PROVIDER_KEY_FILE);
    let resolver_key = options.out_dir.join(RESOLVER_KEY_FILE);
    let cert_path = options.out_dir.join(CERT_FILE);
    let txt_path = options.out_dir.join(TXT_FILE);

    write_secret_file(
        &provider_key,
        hex::encode(*provider.to_seed()).as_bytes(),
        options.force,
    )?;
    write_secret_file(
        &resolver_key,
        hex::encode(*resolver.to_secret_bytes()).as_bytes(),
        options.force,
    )?;
    let file = CertificateFile {
        serial: certificate.serial(),
        valid_from: certificate.ts_start(),
        valid_until: certificate.ts_end(),
        client_magic: hex::encode(certificate.client_magic()),
        provider_public_key: provider_public.to_hex(),
        resolver_public_key: resolver_public.to_hex(),
        certificate: certificate.to_hex(),
    };
    let json = serde_json::to_string_pretty(&file).map_err(|error| {
        DnscryptError::Certificate(format!("cannot encode certificate: {error}"))
    })?;
    write_secret_file(&cert_path, json.as_bytes(), options.force)?;

    let txt_records = txt_records(&provider_name, &certificate, &provider_public);
    write_public_file(&txt_path, txt_records.as_bytes(), options.force)?;

    Ok(GeneratedCert {
        provider_name: provider_name.to_string(),
        provider_public_key: provider_public.to_hex(),
        provider_key,
        resolver_key,
        cert: cert_path,
        txt: txt_path,
        txt_records,
    })
}

fn ensure_dir(dir: &Path) -> Result<(), DnscryptError> {
    if dir.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(DnscryptError::io(dir))?;
    }
    #[cfg(not(unix))]
    {
        DirBuilder::new()
            .recursive(true)
            .create(dir)
            .map_err(DnscryptError::io(dir))?;
    }
    Ok(())
}

fn write_secret_file(path: &Path, bytes: &[u8], force: bool) -> Result<(), DnscryptError> {
    write_file(path, bytes, force, true)
}

fn write_public_file(path: &Path, bytes: &[u8], force: bool) -> Result<(), DnscryptError> {
    write_file(path, bytes, force, false)
}

fn write_file(path: &Path, bytes: &[u8], force: bool, private: bool) -> Result<(), DnscryptError> {
    let mut options = OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path).map_err(|error| DnscryptError::Io {
        path: path.to_path_buf(),
        source: error,
    })?;
    file.write_all(bytes).map_err(DnscryptError::io(path))?;
    file.sync_all().map_err(DnscryptError::io(path))?;
    if private {
        crate::perms::set_mode(path, 0o600).map_err(DnscryptError::io(path))?;
    }
    Ok(())
}

fn txt_records(
    provider: &Name,
    certificate: &Certificate,
    provider_public: &ProviderPublicKey,
) -> String {
    let mut out = String::new();
    let pubkey_name = format!("2.pubkey.{provider}");
    let _ = writeln!(
        out,
        "{pubkey_name} 3600 IN TXT \"{}\"",
        provider_public.to_hex()
    );
    let _ = writeln!(
        out,
        "; Provider: {provider}\n; Publish this record manually or through the REST API/zonefile."
    );
    let _ = write!(out, "{provider} 3600 IN TXT");
    for chunk in certificate.to_bytes().chunks(255) {
        out.push_str(" \"");
        for byte in chunk {
            let _ = write!(out, "\\{byte:03}");
        }
        out.push('"');
    }
    out.push('\n');
    out
}

/// Запущенный DNSCrypt UDP-сервер.
pub(crate) struct DnscryptService {
    server: UdpServer,
    provider_name: Option<String>,
    serial: u32,
    valid_until: u32,
}

impl DnscryptService {
    /// Поднимает DNSCrypt UDP listener и загружает сертификат.
    ///
    /// # Errors
    ///
    /// [`DnscryptError`] при ошибке ключей, сертификата или bind.
    pub(crate) fn start(
        config: &Config,
        addr: SocketAddr,
        cpu_affinity: &[usize],
        admin: Arc<SharedZoneAdmin>,
        stats: Arc<Stats>,
        metrics: Arc<TransportMetrics>,
    ) -> Result<Self, DnscryptError> {
        let (dnscrypt, certificate) = load_server(config)?;
        let serial = certificate.serial();
        let valid_until = certificate.ts_end();

        let handler = move |packet: &[u8], _peer: SocketAddr, out: &mut [u8]| -> Reply {
            metrics.dnscrypt_packet();
            let engine = admin.engine();
            let inner = |query: &[u8]| -> Result<Vec<u8>, NoResponse> {
                dns::respond(query, Transport::Udp, &engine, &stats).ok_or(NoResponse)
            };
            let Ok(response) = dnscrypt.handle_udp(packet, &inner) else {
                metrics.dnscrypt_error();
                return Reply::Drop;
            };
            if response.len() > out.len() {
                metrics.dnscrypt_drop();
                return Reply::Drop;
            }
            let length = response.len();
            out[..length].copy_from_slice(&response);
            metrics.dnscrypt_query();
            metrics.dnscrypt_response();
            Reply::Send(length)
        };
        let server = UdpServer::bind_with(
            addr,
            handler,
            RuntimeConfig::default()
                .with_workers(config.workers)
                .with_cpu_affinity(cpu_affinity.to_vec())
                .with_huge_pages(config.huge_pages.runtime()),
        )?;
        server.start()?;
        Ok(Self {
            server,
            provider_name: config.dnscrypt_provider_name.clone(),
            serial,
            valid_until,
        })
    }

    /// Фактический адрес.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    /// Число worker'ов.
    pub(crate) fn workers(&self) -> usize {
        self.server.workers()
    }

    /// Снимок счётчиков UDP-рантайма.
    pub(crate) fn stats(&self) -> pulse_runtime::ServerStats {
        self.server.stats()
    }

    /// Имя провайдера из конфигурации.
    pub(crate) fn provider_name(&self) -> Option<&str> {
        self.provider_name.as_deref()
    }

    /// Серийный номер загруженного сертификата.
    pub(crate) fn serial(&self) -> u32 {
        self.serial
    }

    /// Конец действия сертификата (Unix-время).
    pub(crate) fn valid_until(&self) -> u32 {
        self.valid_until
    }

    /// Останавливает worker'ы.
    ///
    /// # Errors
    ///
    /// Ошибка UDP-рантайма.
    pub(crate) fn shutdown(&self) -> Result<(), pulse_runtime::RuntimeError> {
        self.server.shutdown()
    }
}

#[derive(Debug, Error)]
#[error("DNS handler produced no response")]
struct NoResponse;

const DNSCRYPT_TCP_ACCEPT_POLL: Duration = Duration::from_millis(20);
const DNSCRYPT_TCP_ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

static NEXT_DNSCRYPT_TCP_CONNECTION: AtomicU64 = AtomicU64::new(1);

/// Запущенный DNSCrypt TCP-сервер.
///
/// Кадры — 2-байтовый big-endian length-prefix + payload DNSCrypt. На одном
/// соединении разрешено несколько последовательных запросов; idle timeout
/// закрывает простаивающее соединение. Большие ответы не усекаются (в отличие
/// от UDP): кадр ограничен `dnscrypt_tcp_max_frame`.
pub(crate) struct DnscryptTcpService {
    local_addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    connections: Arc<Mutex<HashMap<u64, TcpStream>>>,
    active: Arc<AtomicU64>,
    idle_timeout: Duration,
    provider_name: Option<String>,
    serial: u32,
    valid_until: u32,
    acceptor: Option<JoinHandle<()>>,
}

impl DnscryptTcpService {
    /// Поднимает DNSCrypt TCP listener.
    ///
    /// # Errors
    ///
    /// [`DnscryptError`] при ошибке ключей, сертификата, bind или spawn'а
    /// acceptor-потока.
    pub(crate) fn start(
        config: &Config,
        addr: SocketAddr,
        cpu_affinity: &[usize],
        admin: Arc<SharedZoneAdmin>,
        stats: Arc<Stats>,
        metrics: Arc<TransportMetrics>,
    ) -> Result<Self, DnscryptError> {
        let (dnscrypt, certificate) = load_server(config)?;
        let serial = certificate.serial();
        let valid_until = certificate.ts_end();
        let listener = TcpListener::bind(addr).map_err(DnscryptError::tcp)?;
        listener.set_nonblocking(true).map_err(DnscryptError::tcp)?;
        let local_addr = listener.local_addr().map_err(DnscryptError::tcp)?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(HashMap::new()));
        let active = Arc::new(AtomicU64::new(0));
        let idle_timeout = Duration::from_millis(config.dnscrypt_tcp_idle_timeout_ms);
        let max_connections = config.dnscrypt_tcp_max_connections;
        let max_frame = config.dnscrypt_tcp_max_frame;
        let cpus = Arc::new(cpu_affinity.to_vec());
        let acceptor = {
            let shutdown = Arc::clone(&shutdown);
            let connections = Arc::clone(&connections);
            let active = Arc::clone(&active);
            let cpus = Arc::clone(&cpus);
            thread::Builder::new()
                .name("pulse-dnscrypt-tcp-accept".to_owned())
                .spawn(move || {
                    if let Some(&cpu) = cpus.first() {
                        let _ = pulse_runtime::affinity::pin_current(cpu);
                    }
                    let context = TcpAcceptContext {
                        max_connections,
                        max_frame,
                        idle_timeout,
                        admin,
                        stats,
                        metrics,
                        dnscrypt,
                    };
                    accept_loop(&listener, &context, &shutdown, &connections, &active, &cpus);
                })
                .map_err(DnscryptError::tcp)?
        };
        Ok(Self {
            local_addr,
            shutdown,
            connections,
            active,
            idle_timeout,
            provider_name: config.dnscrypt_provider_name.clone(),
            serial,
            valid_until,
            acceptor: Some(acceptor),
        })
    }

    /// Фактический адрес listener'а.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Имя провайдера из конфигурации.
    pub(crate) fn provider_name(&self) -> Option<&str> {
        self.provider_name.as_deref()
    }

    /// Серийный номер загруженного сертификата.
    pub(crate) fn serial(&self) -> u32 {
        self.serial
    }

    /// Конец действия сертификата (Unix-время).
    pub(crate) fn valid_until(&self) -> u32 {
        self.valid_until
    }

    /// Останавливает acceptor и закрывает открытые соединения.
    ///
    /// # Errors
    ///
    /// Ошибка join'а acceptor-потока.
    pub(crate) fn shutdown(&mut self) -> Result<(), DnscryptError> {
        self.shutdown.store(true, Ordering::Release);
        if let Some(acceptor) = self.acceptor.take() {
            acceptor.join().map_err(|_| {
                DnscryptError::tcp(std::io::Error::other(
                    "dnscrypt tcp acceptor thread panicked",
                ))
            })?;
        }
        let streams: Vec<TcpStream> = {
            let connections = self
                .connections
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            connections
                .values()
                .filter_map(|stream| stream.try_clone().ok())
                .collect()
        };
        for stream in streams {
            let _ = stream.shutdown(SocketShutdown::Both);
        }
        let deadline = Instant::now() + self.idle_timeout + Duration::from_millis(500);
        while self.active.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        if self.active.load(Ordering::Acquire) > 0 {
            crate::logging::warn(
                "dnscrypt_tcp_shutdown",
                &format!(
                    "{} DNSCrypt TCP connection(s) still active after graceful deadline",
                    self.active.load(Ordering::Acquire)
                ),
            );
        }
        Ok(())
    }
}

impl Drop for DnscryptTcpService {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

impl DnscryptError {
    fn tcp(source: std::io::Error) -> Self {
        Self::Tcp { source }
    }
}

struct TcpAcceptContext {
    max_connections: usize,
    max_frame: usize,
    idle_timeout: Duration,
    admin: Arc<SharedZoneAdmin>,
    stats: Arc<Stats>,
    metrics: Arc<TransportMetrics>,
    dnscrypt: Arc<DnscryptServer>,
}

fn accept_loop(
    listener: &TcpListener,
    context: &TcpAcceptContext,
    shutdown: &Arc<AtomicBool>,
    connections: &Arc<Mutex<HashMap<u64, TcpStream>>>,
    active: &Arc<AtomicU64>,
    cpu_affinity: &Arc<Vec<usize>>,
) {
    while !shutdown.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                spawn_connection(stream, context, shutdown, connections, active, cpu_affinity);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(DNSCRYPT_TCP_ACCEPT_POLL);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                context.metrics.dnscrypt_tcp_error();
                crate::logging::warn("dnscrypt_tcp_accept", &format!("accept failed: {error}"));
                thread::sleep(DNSCRYPT_TCP_ACCEPT_BACKOFF);
            }
        }
    }
}

fn spawn_connection(
    stream: TcpStream,
    context: &TcpAcceptContext,
    shutdown: &Arc<AtomicBool>,
    connections: &Arc<Mutex<HashMap<u64, TcpStream>>>,
    active: &Arc<AtomicU64>,
    cpu_affinity: &Arc<Vec<usize>>,
) {
    let active_now = usize::try_from(active.load(Ordering::Acquire)).unwrap_or(usize::MAX);
    if active_now >= context.max_connections {
        context.metrics.dnscrypt_tcp_rejected();
        let _ = stream.shutdown(SocketShutdown::Both);
        return;
    }
    active.fetch_add(1, Ordering::AcqRel);
    context.metrics.dnscrypt_tcp_connection();
    let id = NEXT_DNSCRYPT_TCP_CONNECTION.fetch_add(1, Ordering::Relaxed);
    let guard = TcpConnectionGuard {
        id,
        connections: Arc::clone(connections),
        active: Arc::clone(active),
        metrics: Arc::clone(&context.metrics),
    };
    if let Ok(tracked) = stream.try_clone() {
        guard
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, tracked);
    }
    let admin = Arc::clone(&context.admin);
    let stats = Arc::clone(&context.stats);
    let metrics = Arc::clone(&context.metrics);
    let dnscrypt = Arc::clone(&context.dnscrypt);
    let shutdown = Arc::clone(shutdown);
    let idle_timeout = context.idle_timeout;
    let max_frame = context.max_frame;
    let cpu = if cpu_affinity.is_empty() {
        None
    } else {
        Some(cpu_affinity[usize::try_from(id).unwrap_or(0) % cpu_affinity.len()])
    };
    let spawned = thread::Builder::new()
        .name(format!("pulse-dnscrypt-tcp-{id}"))
        .spawn(move || {
            if let Some(cpu) = cpu {
                let _ = pulse_runtime::affinity::pin_current(cpu);
            }
            let _guard = guard;
            if let Err(error) = handle_tcp_connection(
                stream,
                &dnscrypt,
                &admin,
                &stats,
                &metrics,
                &shutdown,
                idle_timeout,
                max_frame,
            ) {
                metrics.dnscrypt_tcp_error();
                crate::logging::debug(
                    "dnscrypt_tcp_connection",
                    &format!("connection {id} closed with error: {error}"),
                );
            }
        });
    if let Err(error) = spawned {
        crate::logging::warn(
            "dnscrypt_tcp_spawn",
            &format!("cannot spawn DNSCrypt TCP connection thread: {error}"),
        );
    }
}

struct TcpConnectionGuard {
    id: u64,
    connections: Arc<Mutex<HashMap<u64, TcpStream>>>,
    active: Arc<AtomicU64>,
    metrics: Arc<TransportMetrics>,
}

impl Drop for TcpConnectionGuard {
    fn drop(&mut self) {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.id);
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.metrics.dnscrypt_tcp_connection_closed();
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_tcp_connection(
    mut stream: TcpStream,
    dnscrypt: &DnscryptServer,
    admin: &SharedZoneAdmin,
    stats: &Stats,
    metrics: &TransportMetrics,
    shutdown: &AtomicBool,
    idle_timeout: Duration,
    max_frame: usize,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(idle_timeout))?;
    stream.set_write_timeout(Some(idle_timeout))?;
    stream.set_nodelay(true)?;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Ok(());
        }
        let Some(frame) = read_frame(&mut stream, max_frame, metrics)? else {
            return Ok(());
        };
        let engine = admin.engine();
        let handler = |query: &[u8]| -> Result<Vec<u8>, NoResponse> {
            dns::respond(query, Transport::Tcp, &engine, stats).ok_or(NoResponse)
        };
        let response = match dnscrypt.handle_tcp_frame(&frame, &handler) {
            Ok(response) => response,
            Err(error) => {
                metrics.dnscrypt_tcp_error();
                crate::logging::debug(
                    "dnscrypt_tcp_frame",
                    &format!("cannot process DNSCrypt TCP frame: {error}"),
                );
                return Ok(());
            }
        };
        stream.write_all(&response)?;
        stream.flush()?;
        metrics.dnscrypt_tcp_query();
        metrics.dnscrypt_tcp_response();
    }
}

fn read_frame(
    stream: &mut TcpStream,
    max_frame: usize,
    metrics: &TransportMetrics,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut prefix = [0_u8; 2];
    if !read_exact_idle(stream, &mut prefix)? {
        return Ok(None);
    }
    let length = usize::from(u16::from_be_bytes(prefix));
    if length == 0 {
        return Ok(None);
    }
    if length > max_frame {
        metrics.dnscrypt_tcp_error();
        return Ok(None);
    }
    let mut payload = vec![0_u8; length];
    if !read_exact_idle(stream, &mut payload)? {
        return Ok(None);
    }
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(&payload);
    Ok(Some(frame))
}

fn read_exact_idle(stream: &mut TcpStream, buffer: &mut [u8]) -> std::io::Result<bool> {
    let mut filled = 0;
    while filled < buffer.len() {
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Ok(false),
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_record_is_master_file_escaped() {
        let provider = ProviderKeypair::from_seed([7_u8; 32]);
        let resolver = ResolverKeypair::generate().expect("resolver");
        let certificate = Certificate::sign(
            &provider,
            CertificateParams::new(
                resolver.public_key().to_bytes(),
                [1, 2, 3, 4, 5, 6, 7, 8],
                9,
                1_700_000_000,
                1_800_000_000,
            ),
        )
        .expect("certificate");
        let name = Name::parse("2.dnscrypt-cert.example.com.").expect("name");
        let text = txt_records(&name, &certificate, &provider.public_key());
        assert!(text.contains("2.pubkey.2.dnscrypt-cert.example.com. 3600 IN TXT"));
        assert!(text.contains("2.dnscrypt-cert.example.com. 3600 IN TXT \"\\068\\078\\083\\067"));
    }
}
