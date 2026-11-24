//! Конфигурация резолвера.
//!
//! Все значения по умолчанию безопасны: рекурсия стартует от встроенных
//! root hints, DNSSEC-валидация выключена (passthrough), blocklist пуст,
//! 0x20 включена для UDP.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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

/// Параметры forward-режима.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardConfig {
    /// Адреса forwarder-ов.
    pub servers: Vec<SocketAddr>,
    /// Сколько подряд ошибок переводят forwarder в cooldown.
    pub max_failures: u32,
    /// Длительность cooldown.
    pub cooldown: Duration,
}

impl ForwardConfig {
    /// Создаёт конфигурацию из адресов.
    #[must_use]
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        Self {
            servers,
            max_failures: 2,
            cooldown: Duration::from_secs(30),
        }
    }
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self::new(Vec::new())
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
    /// Кеш.
    pub cache: CacheConfig,
    /// DNSSEC.
    pub dnssec: DnssecConfig,
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
            cache: CacheConfig::default(),
            dnssec: DnssecConfig::default(),
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
            && forward.servers.is_empty()
        {
            return Err(ResolverError::config(
                "forward mode requires at least one server",
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
}
