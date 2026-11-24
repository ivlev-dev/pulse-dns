//! Конфигурация резолвера.
//!
//! Все значения по умолчанию безопасны: рекурсия стартует от встроенных
//! root hints, DNSSEC-валидация выключена (passthrough), blocklist пуст,
//! 0x20 включена для UDP.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use pulse_dns::{DsData, Name, Rdata, Rtype, Ttl};

use crate::error::ResolverError;

/// Режим резолюции.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Итеративный обход от корня.
    Iterative(IterativeConfig),
    /// Пересылка настроенным рекурсивным серверам.
    Forward(ForwardConfig),
}

impl Default for Mode {
    fn default() -> Self {
        Self::Iterative(IterativeConfig::default())
    }
}

/// Параметры итеративного режима.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IterativeConfig {
    /// Root hints. Пустой список означает встроенные адреса IANA.
    pub root_hints: Vec<SocketAddr>,
    /// Порт авторитетных серверов, полученных из делегирований/glue.
    /// По умолчанию 53; в тестах позволяет поднять mock upstream на
    /// непривилегированном порту.
    pub ns_port: u16,
}

impl Default for IterativeConfig {
    fn default() -> Self {
        Self {
            root_hints: Vec::new(),
            ns_port: 53,
        }
    }
}

/// Upstream DNS-over-TLS.
///
/// `host`/`port` разрешаются клиентом при подключении; `server_name` задаёт
/// SNI и имя для проверки сертификата. `ca` — PEM-файл единственного
/// доверенного CA (без него используются webpki-roots).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsUpstream {
    /// Имя хоста или IP-литерал без скобок.
    pub host: String,
    /// Порт (по умолчанию 853).
    pub port: u16,
    /// Имя для SNI/проверки сертификата.
    pub server_name: String,
    /// Опциональный PEM-файл CA.
    pub ca: Option<PathBuf>,
}

impl TlsUpstream {
    /// Создаёт upstream из разрешённого адреса.
    #[must_use]
    pub fn new(address: SocketAddr, server_name: impl Into<String>) -> Self {
        Self {
            host: address.ip().to_string(),
            port: address.port(),
            server_name: server_name.into(),
            ca: None,
        }
    }

    /// `host:port` (IPv6-литерал в скобках).
    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl std::fmt::Display for TlsUpstream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "tls://{}#{}", self.authority(), self.server_name)
    }
}

/// Upstream DNS-over-HTTPS (HTTP/1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsUpstream {
    /// Полный URL `https://host[:port]/path`.
    pub url: String,
    /// Опциональный PEM-файл CA.
    pub ca: Option<PathBuf>,
}

impl std::fmt::Display for HttpsUpstream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.url)
    }
}

/// Один upstream смешанного списка.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamConfig {
    /// Классический UDP с TCP-fallback при TC.
    Udp(SocketAddr),
    /// Только TCP (RFC 7766).
    Tcp(SocketAddr),
    /// DNS-over-TLS (RFC 7858).
    Tls(TlsUpstream),
    /// DNS-over-HTTPS/1.1 (RFC 8484).
    Https(HttpsUpstream),
}

impl UpstreamConfig {
    /// Разбирает URL или адрес: `1.1.1.1`, `tcp://…`, `tls://…#name`,
    /// `https://…/dns-query`.
    ///
    /// # Errors
    ///
    /// [`ResolverError::Config`] при некорректной схеме, адресе или имени.
    pub fn parse(value: &str) -> Result<Self, ResolverError> {
        Self::parse_with_ca(value, None)
    }

    /// То же, но с CA-файлом для DoT/DoH.
    ///
    /// # Errors
    ///
    /// См. [`UpstreamConfig::parse`].
    pub fn parse_with_ca(value: &str, ca: Option<PathBuf>) -> Result<Self, ResolverError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ResolverError::config("upstream must not be empty"));
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("tls://") {
            return Self::parse_tls(trimmed, ca);
        }
        if lower.starts_with("https://") {
            return Self::parse_https(trimmed, ca);
        }
        if lower.starts_with("http://") {
            return Err(ResolverError::config(
                "DoH upstream must use https://, http:// is not allowed",
            ));
        }
        if lower.starts_with("tcp://") {
            let rest = trimmed.get(6..).unwrap_or_default();
            return Ok(Self::Tcp(parse_socket_addr(rest, 53)?));
        }
        if lower.starts_with("udp://") {
            let rest = trimmed.get(6..).unwrap_or_default();
            return Ok(Self::Udp(parse_socket_addr(rest, 53)?));
        }
        if let Some((scheme, _)) = trimmed.split_once("://") {
            return Err(ResolverError::config(format!(
                "unsupported upstream scheme {scheme:?}"
            )));
        }
        Ok(Self::Udp(parse_socket_addr(trimmed, 53)?))
    }

    fn parse_tls(value: &str, ca: Option<PathBuf>) -> Result<Self, ResolverError> {
        let rest = value.get("tls://".len()..).unwrap_or_default();
        let (authority, server_name) = match rest.split_once('#') {
            Some((authority, name)) => (authority, Some(name)),
            None => (rest, None),
        };
        let (host, port) = split_host_port(authority, 853, "tls")?;
        if host.is_empty() {
            return Err(ResolverError::config(format!(
                "invalid TLS upstream {value:?}"
            )));
        }
        let server_name = server_name
            .filter(|name| !name.trim().is_empty())
            .map_or_else(|| host.clone(), |name| name.trim().to_owned());
        if server_name.contains('/') || server_name.contains(' ') {
            return Err(ResolverError::config(format!(
                "invalid TLS server name {server_name:?}"
            )));
        }
        Ok(Self::Tls(TlsUpstream {
            host,
            port,
            server_name,
            ca,
        }))
    }

    fn parse_https(value: &str, ca: Option<PathBuf>) -> Result<Self, ResolverError> {
        let rest = value.get("https://".len()..).unwrap_or_default();
        let authority = rest
            .split_once('/')
            .map_or(rest, |(authority, _)| authority);
        let authority = authority.split('#').next().unwrap_or(authority);
        if authority.is_empty()
            || authority.contains('\r')
            || authority.contains('\n')
            || authority.contains(' ')
        {
            return Err(ResolverError::config(format!("invalid DoH URL {value:?}")));
        }
        let (host, _port) = split_host_port(authority, 443, "https")?;
        if host.is_empty() {
            return Err(ResolverError::config(format!("invalid DoH URL {value:?}")));
        }
        Ok(Self::Https(HttpsUpstream {
            url: value.to_owned(),
            ca,
        }))
    }

    /// Тип upstream для метрик: `udp`, `tcp`, `tls` или `https`.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Udp(_) => "udp",
            Self::Tcp(_) => "tcp",
            Self::Tls(_) => "tls",
            Self::Https(_) => "https",
        }
    }
}

impl std::fmt::Display for UpstreamConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp(address) => write!(formatter, "udp://{address}"),
            Self::Tcp(address) => write!(formatter, "tcp://{address}"),
            Self::Tls(upstream) => upstream.fmt(formatter),
            Self::Https(upstream) => upstream.fmt(formatter),
        }
    }
}

fn split_host_port(
    authority: &str,
    default_port: u16,
    scheme: &str,
) -> Result<(String, u16), ResolverError> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err(ResolverError::config(format!(
            "{scheme} upstream has an empty host"
        )));
    }
    if authority.parse::<std::net::IpAddr>().is_ok() {
        return Ok((authority.to_owned(), default_port));
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(|| {
            ResolverError::config(format!("{scheme} upstream has an invalid IPv6 host"))
        })?;
        let port = match after.strip_prefix(':') {
            Some(port) if !port.is_empty() => port.parse::<u16>().map_err(|_| {
                ResolverError::config(format!("{scheme} upstream has an invalid port"))
            })?,
            Some(_) => {
                return Err(ResolverError::config(format!(
                    "{scheme} upstream has an invalid port"
                )));
            }
            None => default_port,
        };
        return Ok((host.to_owned(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|ch| ch.is_ascii_digit()) => Ok((
            host.to_owned(),
            port.parse::<u16>().map_err(|_| {
                ResolverError::config(format!("{scheme} upstream has an invalid port"))
            })?,
        )),
        Some(_) if authority.matches(':').count() == 1 => Err(ResolverError::config(format!(
            "{scheme} upstream has an invalid port"
        ))),
        Some(_) | None => Ok((authority.to_owned(), default_port)),
    }
}

fn parse_socket_addr(value: &str, default_port: u16) -> Result<SocketAddr, ResolverError> {
    let value = value.trim();
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address);
    }
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    if let Some((host, port)) = value.rsplit_once(':')
        && port.chars().all(|ch| ch.is_ascii_digit())
        && !host.is_empty()
        && !host.contains(':')
    {
        let port = port
            .parse::<u16>()
            .map_err(|_| ResolverError::config(format!("invalid upstream port in {value:?}")))?;
        return resolve_first(host, port);
    }
    resolve_first(value, default_port)
}

fn resolve_first(host: &str, port: u16) -> Result<SocketAddr, ResolverError> {
    (host, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addresses| addresses.next())
        .ok_or_else(|| ResolverError::config(format!("cannot resolve upstream host {host:?}")))
}

/// Параметры forward-режима.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardConfig {
    /// Адреса UDP-forwarder-ов (legacy-поле; используется, если `upstreams`
    /// пуст).
    pub servers: Vec<SocketAddr>,
    /// Смешанный список upstream (UDP/TCP/DoT/DoH).
    pub upstreams: Vec<UpstreamConfig>,
    /// Сколько подряд ошибок переводят forwarder в cooldown.
    pub max_failures: u32,
    /// Длительность cooldown.
    pub cooldown: Duration,
}

impl ForwardConfig {
    /// Создаёт конфигурацию из UDP-адресов.
    #[must_use]
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self {
            servers,
            upstreams: Vec::new(),
            max_failures: 2,
            cooldown: Duration::from_secs(30),
        }
    }

    /// Создаёт конфигурацию из смешанного списка upstream.
    #[must_use]
    pub fn with_upstreams(upstreams: Vec<UpstreamConfig>) -> Self {
        let servers = upstreams
            .iter()
            .filter_map(|upstream| match upstream {
                UpstreamConfig::Udp(address) => Some(*address),
                UpstreamConfig::Tcp(_) | UpstreamConfig::Tls(_) | UpstreamConfig::Https(_) => None,
            })
            .collect();
        Self {
            servers,
            upstreams,
            max_failures: 2,
            cooldown: Duration::from_secs(30),
        }
    }

    /// Итоговый список upstream: явный `upstreams` или legacy `servers`.
    #[must_use]
    pub fn effective_upstreams(&self) -> Vec<UpstreamConfig> {
        if self.upstreams.is_empty() {
            self.servers
                .iter()
                .copied()
                .map(UpstreamConfig::Udp)
                .collect()
        } else {
            self.upstreams.clone()
        }
    }
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Параметры пула keep-alive соединений к DoT/DoH upstream.
///
/// Пул ленивый: соединение открывается по требованию, поэтому
/// последовательные запросы переиспользуют одно соединение, а параллельные
/// занимают до `size` слотов. `size` одновременно является лимитом
/// одновременных запросов к одному upstream: при занятости всех слотов
/// запрос ждёт свободный до общего дедлайна резолюции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpstreamPoolConfig {
    /// Число keep-alive соединений (1..=64).
    pub size: usize,
    /// Начальная задержка переподключения после неудачного connect.
    pub reconnect_backoff: Duration,
    /// Максимальная задержка переподключения (экспоненциальный backoff).
    pub max_reconnect_backoff: Duration,
}

impl Default for UpstreamPoolConfig {
    fn default() -> Self {
        Self {
            size: 4,
            reconnect_backoff: Duration::from_millis(100),
            max_reconnect_backoff: Duration::from_secs(5),
        }
    }
}

/// Таймауты.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutConfig {
    /// Таймаут одного UDP/TCP-запроса.
    pub per_query: Duration,
    /// Таймаут TCP-соединения и чтения.
    pub tcp: Duration,
    /// Общий бюджет одной резолюции.
    pub total: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            per_query: Duration::from_secs(2),
            tcp: Duration::from_secs(3),
            total: Duration::from_secs(6),
        }
    }
}

/// Параметры кеша.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheConfig {
    /// Максимум записей во всём кеше.
    pub max_entries: usize,
    /// Максимум приблизительной памяти кеша.
    pub max_bytes: usize,
    /// Минимальный TTL при вставке.
    pub min_ttl: u32,
    /// Максимальный TTL при вставке.
    pub max_ttl: u32,
    /// Число независимых шардов.
    pub shards: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 16_384,
            max_bytes: 8 * 1024 * 1024,
            min_ttl: 0,
            max_ttl: 86_400,
            shards: 16,
        }
    }
}

/// Trust anchor для DNSSEC-валидации.
#[derive(Debug, Clone)]
pub struct TrustAnchorConfig {
    /// Зона, для которой anchor задан (обычно корень).
    pub zone: Name,
    /// DS-запись, которой доверяем.
    pub ds: DsData,
}

impl TrustAnchorConfig {
    /// Создаёт anchor.
    #[must_use]
    pub const fn new(zone: Name, ds: DsData) -> Self {
        Self { zone, ds }
    }
}

/// Параметры DNSSEC.
#[derive(Debug, Clone)]
pub struct DnssecConfig {
    /// Включить валидацию. По умолчанию выключена (passthrough).
    pub enabled: bool,
    /// Явные trust anchors. Пусто — встроенные корневые KSK IANA.
    pub anchors: Vec<TrustAnchorConfig>,
    /// Максимум RRSIG на один RRset (защита от KeyTrap).
    pub max_rrsigs_per_rrset: usize,
    /// Максимум DNSKEY в RRset.
    pub max_dnskeys: usize,
    /// Максимум криптографических проверок на одну резолюцию.
    pub max_verifications: usize,
}

impl Default for DnssecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            anchors: Vec::new(),
            max_rrsigs_per_rrset: 8,
            max_dnskeys: 16,
            max_verifications: 64,
        }
    }
}

/// Ответ на заблокированное имя.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BlockResponse {
    /// NXDOMAIN по умолчанию.
    #[default]
    NxDomain,
    /// Синтетические A/AAAA (`0.0.0.0` / `::` по умолчанию).
    Null {
        /// IPv4-адрес ответа.
        ipv4: Ipv4Addr,
        /// IPv6-адрес ответа.
        ipv6: Ipv6Addr,
    },
}

impl BlockResponse {
    /// Политика «null address».
    #[must_use]
    pub const fn null() -> Self {
        Self::Null {
            ipv4: Ipv4Addr::UNSPECIFIED,
            ipv6: Ipv6Addr::UNSPECIFIED,
        }
    }
}

/// Параметры blocklist.
#[derive(Debug, Clone)]
pub struct BlocklistConfig {
    /// Файл blocklist (домены или hosts-формат).
    pub path: Option<PathBuf>,
    /// Дополнительные файлы blocklist. Все файлы объединяются в один снимок.
    pub paths: Vec<PathBuf>,
    /// Домены-исключения (включая поддомены).
    pub allowlist: Vec<String>,
    /// Политика ответа на заблокированное имя.
    pub response: BlockResponse,
}

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            path: None,
            paths: Vec::new(),
            allowlist: Vec::new(),
            response: BlockResponse::NxDomain,
        }
    }
}

impl BlocklistConfig {
    /// Все файлы blocklist в порядке загрузки: `path`, затем `paths`.
    #[must_use]
    pub fn all_paths(&self) -> Vec<PathBuf> {
        self.path.iter().chain(self.paths.iter()).cloned().collect()
    }
}

/// Статическая запись override.
///
/// Поддерживаются только `A`, `AAAA` и `CNAME`. Для одного имени либо
/// задаётся один `CNAME`, либо один и более адресных RR.
#[derive(Debug, Clone)]
pub struct Override {
    /// Владелец.
    pub name: Name,
    /// TTL.
    pub ttl: Ttl,
    /// Данные.
    pub data: Vec<Rdata>,
}

impl Override {
    /// Создаёт override с проверкой типа данных.
    ///
    /// # Errors
    ///
    /// [`ResolverError::Config`], если список пуст, содержит несколько
    /// `CNAME` или типы вне `A`/`AAAA`/`CNAME`.
    pub fn new(name: Name, ttl: Ttl, data: Vec<Rdata>) -> Result<Self, ResolverError> {
        if data.is_empty() {
            return Err(ResolverError::config(
                "override must contain at least one record",
            ));
        }
        let cnames = data
            .iter()
            .filter(|rdata| rdata.rr_type() == Rtype::CNAME)
            .count();
        if cnames > 1 || (cnames == 1 && data.len() > 1) {
            return Err(ResolverError::config(
                "override must be either one CNAME or address records",
            ));
        }
        if !data
            .iter()
            .all(|rdata| matches!(rdata.rr_type(), Rtype::A | Rtype::AAAA | Rtype::CNAME))
        {
            return Err(ResolverError::config(
                "override supports only A, AAAA and CNAME records",
            ));
        }
        Ok(Self { name, ttl, data })
    }

    /// Создаёт `A`-override.
    #[must_use]
    pub fn a(name: Name, ttl: Ttl, address: Ipv4Addr) -> Self {
        Self {
            name,
            ttl,
            data: vec![Rdata::A(address)],
        }
    }

    /// Создаёт `AAAA`-override.
    #[must_use]
    pub fn aaaa(name: Name, ttl: Ttl, address: Ipv6Addr) -> Self {
        Self {
            name,
            ttl,
            data: vec![Rdata::Aaaa(address)],
        }
    }

    /// Создаёт `CNAME`-override.
    #[must_use]
    pub fn cname(name: Name, ttl: Ttl, target: Name) -> Self {
        Self {
            name,
            ttl,
            data: vec![Rdata::Cname(target)],
        }
    }
}

/// Полная конфигурация резолвера.
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    /// Режим.
    pub mode: Mode,
    /// Таймауты.
    pub timeouts: TimeoutConfig,
    /// Повторы одного запроса к upstream.
    pub retries: u8,
    /// EDNS0 payload size, который предлагаем upstream.
    pub edns_payload: u16,
    /// Включить 0x20-рандомизацию для UDP.
    pub use_0x20: bool,
    /// Включить qname minimization.
    pub qname_minimization: bool,
    /// Лимит CNAME-цепи.
    pub max_cname_chain: usize,
    /// Лимит глубины рекурсии/делегирований.
    pub max_depth: usize,
    /// Лимит запросов на одну резолюцию.
    pub max_queries: usize,
    /// Сколько NS опрашивать параллельно (1–3).
    pub parallel_ns: usize,
    /// Максимальный размер ответа upstream.
    pub max_response_bytes: usize,
    /// Пул keep-alive соединений DoT/DoH.
    pub pool: UpstreamPoolConfig,
    /// Кеш.
    pub cache: CacheConfig,
    /// DNSSEC.
    pub dnssec: DnssecConfig,
    /// RFC 5011 provider: текущие anchors и приём валидированных DNSKEY.
    pub trust_anchor_provider: Option<std::sync::Arc<dyn pulse_dnssec::TrustAnchorProvider>>,
    /// Blocklist.
    pub blocklist: BlocklistConfig,
    /// Overrides.
    pub overrides: Vec<Override>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            timeouts: TimeoutConfig::default(),
            retries: 2,
            edns_payload: pulse_dns::EDNS_DEFAULT_PAYLOAD,
            use_0x20: true,
            qname_minimization: false,
            max_cname_chain: 16,
            max_depth: 32,
            max_queries: 64,
            parallel_ns: 2,
            max_response_bytes: pulse_dns::MAX_UDP_PAYLOAD * 8,
            pool: UpstreamPoolConfig::default(),
            cache: CacheConfig::default(),
            dnssec: DnssecConfig::default(),
            trust_anchor_provider: None,
            blocklist: BlocklistConfig::default(),
            overrides: Vec::new(),
        }
    }
}

impl ResolverConfig {
    /// Конфигурация forward-режима.
    #[must_use]
    pub fn forward(servers: Vec<SocketAddr>) -> Self {
        Self {
            mode: Mode::Forward(ForwardConfig::new(servers)),
            ..Self::default()
        }
    }

    /// Конфигурация forward-режима со смешанными upstream.
    #[must_use]
    pub fn forward_upstreams(upstreams: Vec<UpstreamConfig>) -> Self {
        Self {
            mode: Mode::Forward(ForwardConfig::with_upstreams(upstreams)),
            ..Self::default()
        }
    }

    /// Конфигурация итеративного режима со встроенными root hints.
    #[must_use]
    pub fn iterative() -> Self {
        Self::default()
    }

    /// Проверяет конфигурацию.
    ///
    /// # Errors
    ///
    /// [`ResolverError::Config`] при некорректных лимитах, пустом списке
    /// forwarder-ов или несовместимых значениях.
    pub fn validate(&self) -> Result<(), ResolverError> {
        if !(512..=pulse_dns::EDNS_MAX_PAYLOAD).contains(&self.edns_payload) {
            return Err(ResolverError::config(format!(
                "edns_payload {} outside 512..={}",
                self.edns_payload,
                pulse_dns::EDNS_MAX_PAYLOAD
            )));
        }
        if self.retries > 10 {
            return Err(ResolverError::config("retries must be at most 10"));
        }
        if !(1..=3).contains(&self.parallel_ns) {
            return Err(ResolverError::config("parallel_ns must be 1..=3"));
        }
        if self.max_cname_chain == 0
            || self.max_depth == 0
            || self.max_queries == 0
            || self.max_response_bytes < 512
        {
            return Err(ResolverError::config("resolution limits must be positive"));
        }
        if self.timeouts.per_query.is_zero()
            || self.timeouts.tcp.is_zero()
            || self.timeouts.total.is_zero()
        {
            return Err(ResolverError::config("timeouts must be non-zero"));
        }
        if !(1..=pulse_tls::MAX_POOL_SIZE).contains(&self.pool.size) {
            return Err(ResolverError::config("pool size must be in 1..=64"));
        }
        if self.pool.reconnect_backoff.is_zero()
            || self.pool.max_reconnect_backoff < self.pool.reconnect_backoff
        {
            return Err(ResolverError::config(
                "pool reconnect backoff must be positive and not exceed the maximum",
            ));
        }
        if self.cache.max_entries == 0
            || self.cache.max_bytes == 0
            || !(1..=256).contains(&self.cache.shards)
        {
            return Err(ResolverError::config("invalid cache limits"));
        }
        if self.cache.min_ttl > self.cache.max_ttl {
            return Err(ResolverError::config("cache min_ttl exceeds max_ttl"));
        }
        if self.dnssec.max_rrsigs_per_rrset == 0
            || self.dnssec.max_dnskeys == 0
            || self.dnssec.max_verifications == 0
        {
            return Err(ResolverError::config("dnssec limits must be positive"));
        }
        if let Mode::Forward(forward) = &self.mode
            && forward.effective_upstreams().is_empty()
        {
            return Err(ResolverError::config(
                "forward mode requires at least one upstream",
            ));
        }
        for entry in &self.overrides {
            Override::new(entry.name.clone(), entry.ttl, entry.data.clone())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid() {
        let config = ResolverConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.use_0x20, "0x20 must be on by default");
        assert_eq!(config.edns_payload, 1232);
    }

    #[test]
    fn forward_without_servers_is_rejected() {
        let config = ResolverConfig::forward(Vec::new());
        assert!(config.validate().is_err());
    }

    #[test]
    fn override_rejects_mixed_cname() {
        let name = Name::parse("example.com").unwrap();
        let ttl = Ttl::new(60).unwrap();
        let data = vec![
            Rdata::Cname(Name::parse("target.example.com").unwrap()),
            Rdata::A(Ipv4Addr::LOCALHOST),
        ];
        assert!(Override::new(name, ttl, data).is_err());
    }

    #[test]
    fn cache_limits_are_checked() {
        let mut config = ResolverConfig::default();
        config.cache.min_ttl = 100;
        config.cache.max_ttl = 10;
        assert!(config.validate().is_err());
    }

    #[test]
    fn pool_config_is_validated() {
        let mut config = ResolverConfig::default();
        assert_eq!(config.pool.size, 4, "pool size defaults to 4");
        config.pool.size = 0;
        assert!(config.validate().is_err());
        config.pool.size = 65;
        assert!(config.validate().is_err());
        config.pool.size = 4;
        config.pool.reconnect_backoff = std::time::Duration::ZERO;
        assert!(config.validate().is_err());
        config.pool.reconnect_backoff = std::time::Duration::from_secs(1);
        config.pool.max_reconnect_backoff = std::time::Duration::from_millis(100);
        assert!(config.validate().is_err());
    }

    #[test]
    fn parses_upstream_urls() {
        assert_eq!(
            UpstreamConfig::parse("1.1.1.1").unwrap(),
            UpstreamConfig::Udp("1.1.1.1:53".parse().unwrap())
        );
        assert_eq!(
            UpstreamConfig::parse("tcp://1.1.1.1:5353").unwrap(),
            UpstreamConfig::Tcp("1.1.1.1:5353".parse().unwrap())
        );
        let tls = UpstreamConfig::parse("tls://dns.example:853#dns.example").unwrap();
        match &tls {
            UpstreamConfig::Tls(upstream) => {
                assert_eq!(upstream.host, "dns.example");
                assert_eq!(upstream.port, 853);
                assert_eq!(upstream.server_name, "dns.example");
            }
            other => panic!("unexpected upstream: {other:?}"),
        }
        assert_eq!(tls.kind(), "tls");
        assert_eq!(
            UpstreamConfig::parse("https://dns.example/dns-query")
                .unwrap()
                .kind(),
            "https"
        );
        assert!(UpstreamConfig::parse("http://dns.example/dns-query").is_err());
        assert!(UpstreamConfig::parse("quic://dns.example").is_err());
        assert!(UpstreamConfig::parse("tls:///foo").is_err());
    }

    #[test]
    fn mixed_upstreams_validate() {
        let upstreams = vec![
            UpstreamConfig::Udp("127.0.0.1:53".parse().unwrap()),
            UpstreamConfig::Tls(TlsUpstream {
                host: "127.0.0.1".to_owned(),
                port: 853,
                server_name: "localhost".to_owned(),
                ca: None,
            }),
        ];
        let config = ResolverConfig::forward_upstreams(upstreams);
        assert!(config.validate().is_ok());
        let Mode::Forward(forward) = &config.mode else {
            return;
        };
        assert_eq!(forward.effective_upstreams().len(), 2);
        assert_eq!(forward.servers.len(), 1);
    }
}
