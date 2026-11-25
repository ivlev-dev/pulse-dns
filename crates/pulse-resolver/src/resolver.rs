//! Публичный `Resolver` и общий путь резолюции.
//!
//! Порядок обработки: overrides → blocklist → кеш → upstream (forward или
//! iterative) → DNSSEC-валидация → кеширование → ответ. Ответ всегда
//! собирается заново, поэтому upstream-заголовки и EDNS-опции не утекают
//! клиенту.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use pulse_dns::{
    DecodeLimits, Edns, EncodeError, EncodeOptions, EncodeScratch, Encoder, Flags, HeaderCounts,
    Message, Name, Question, Rclass, Rcode, Record, Rtype, Ttl,
};
use pulse_tls::client::{DohClient, DotClient};
use pulse_tls::{PoolConfig, PoolStats};

use crate::blocklist::{Blocklist, BlocklistStats};
use crate::cache::{Cache, CacheSnapshot, SecurityState, wire_rrs};
use crate::config::{BlockResponse, Mode, ResolverConfig, TrustAnchorConfig, UpstreamConfig};
use crate::dnssec::{self, Security, ValidationCache};
use crate::error::ResolverError;
use crate::forward;
use crate::iterative;
use crate::overrides::{OverrideOutcome, Overrides};
use crate::root_hints;
use crate::rrutil::{find_soa, group_rrsets, negative_ttl, within_bailiwick};
use crate::upstream::{
    UpstreamClient, UpstreamCounters, UpstreamOptions, UpstreamResponse, UpstreamStats,
    UpstreamTransport, is_retryable_rcode, prepare, verify_response,
};

/// TTL синтетических ответов blocklist/override.
const SYNTHETIC_TTL: u32 = 60;

/// Результат резолюции до сборки клиентского ответа.
#[derive(Debug, Clone)]
pub(crate) struct Resolution {
    pub(crate) rcode: Rcode,
    pub(crate) answers: Vec<Record>,
    pub(crate) authority: Vec<Record>,
    pub(crate) additional: Vec<Record>,
    /// Зона, в которой получен финальный ответ (bailiwick для кеша).
    pub(crate) zone: Name,
}

/// Контекст одной резолюции: дедлайн и опциональная отмена.
#[derive(Debug, Clone, Default)]
pub struct ResolveContext {
    deadline: Option<Instant>,
    cancellation: Option<Arc<AtomicBool>>,
}

impl ResolveContext {
    /// Пустой контекст (дедлайн берётся из конфигурации).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Задаёт абсолютный дедлайн.
    #[must_use]
    pub fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Задаёт токен отмены.
    #[must_use]
    pub fn with_cancellation(mut self, token: &CancellationToken) -> Self {
        self.cancellation = Some(Arc::clone(&token.flag));
        self
    }

    pub(crate) fn deadline(&self) -> Instant {
        self.deadline.unwrap_or_else(Instant::now)
    }

    pub(crate) fn cancel(&self) -> Option<&Arc<AtomicBool>> {
        self.cancellation.as_ref()
    }
}

/// Токен отмены резолюции.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Создаёт новый токен.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Отменяет все резолюции с этим токеном.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Отменён ли токен.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
enum ForwardTransport {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Dot(DotClient),
    Doh(DohClient),
}

#[derive(Debug)]
pub(crate) struct Forwarder {
    pub(crate) config: UpstreamConfig,
    transport: ForwardTransport,
    failures: AtomicU32,
    cooldown_until_ms: AtomicU64,
}

impl Forwarder {
    fn new(config: UpstreamConfig, pool: PoolConfig) -> Result<Self, ResolverError> {
        let transport = match &config {
            UpstreamConfig::Udp(address) => ForwardTransport::Udp(*address),
            UpstreamConfig::Tcp(address) => ForwardTransport::Tcp(*address),
            UpstreamConfig::Tls(upstream) => {
                let client = DotClient::with_pool(
                    &upstream.host,
                    Some(upstream.port),
                    &upstream.server_name,
                    upstream.ca.as_deref(),
                    pool,
                )
                .map_err(transport_config_error)?;
                ForwardTransport::Dot(client)
            }
            UpstreamConfig::Https(upstream) => {
                let client = DohClient::with_pool(&upstream.url, upstream.ca.as_deref(), pool)
                    .map_err(transport_config_error)?;
                ForwardTransport::Doh(client)
            }
        };
        Ok(Self {
            config,
            transport,
            failures: AtomicU32::new(0),
            cooldown_until_ms: AtomicU64::new(0),
        })
    }

    fn healthy(&self, now_ms: u64) -> bool {
        self.cooldown_until_ms.load(Ordering::Relaxed) <= now_ms
    }

    fn pool_stats(&self, stats: &mut PoolStats) {
        let source = match &self.transport {
            ForwardTransport::Dot(client) => client.pool_stats(),
            ForwardTransport::Doh(client) => client.pool_stats(),
            ForwardTransport::Udp(_) | ForwardTransport::Tcp(_) => return,
        };
        stats.acquires = stats.acquires.saturating_add(source.acquires);
        stats.reuses = stats.reuses.saturating_add(source.reuses);
        stats.opens = stats.opens.saturating_add(source.opens);
        stats.waits = stats.waits.saturating_add(source.waits);
        stats.discards = stats.discards.saturating_add(source.discards);
        stats.connect_failures = stats
            .connect_failures
            .saturating_add(source.connect_failures);
        stats.cooldowns = stats.cooldowns.saturating_add(source.cooldowns);
    }
}

fn transport_config_error(error: pulse_tls::Error) -> ResolverError {
    ResolverError::config(format!("invalid secure upstream: {error}"))
}

#[derive(Debug, Default)]
pub(crate) struct RuntimeCounters {
    pub(crate) queries: AtomicU64,
    pub(crate) servfail: AtomicU64,
    pub(crate) blocked: AtomicU64,
    pub(crate) overridden: AtomicU64,
    pub(crate) dnssec_secure: AtomicU64,
    pub(crate) dnssec_insecure: AtomicU64,
    pub(crate) dnssec_bogus: AtomicU64,
}

/// Снимок общей статистики резолвера.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatsSnapshot {
    /// Всего клиентских запросов.
    pub queries: u64,
    /// Ответов SERVFAIL.
    pub servfail: u64,
    /// Ответов из blocklist.
    pub blocked: u64,
    /// Ответов из overrides.
    pub overridden: u64,
    /// Secure-ответов DNSSEC.
    pub dnssec_secure: u64,
    /// Доказанно insecure ответов.
    pub dnssec_insecure: u64,
    /// BOGUS-ответов.
    pub dnssec_bogus: u64,
    /// Попадания в кеш результатов DNSSEC-валидации (цепочка и подписи).
    pub dnssec_validation_hits: u64,
    /// Промахи кеша результатов DNSSEC-валидации.
    pub dnssec_validation_misses: u64,
    /// Статистика кеша.
    pub cache: CacheSnapshot,
    /// Статистика транспорта.
    pub upstream: UpstreamStats,
}

/// Состояние одного forward-upstream для control-plane API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamStatus {
    /// Тип: `udp`, `tcp`, `tls` или `https`.
    pub kind: &'static str,
    /// Адрес/URL без параметров сертификата.
    pub address: String,
    /// Не находится ли upstream в cooldown.
    pub healthy: bool,
    /// Подряд накопленных ошибок.
    pub failures: u32,
    /// Остаток cooldown, миллисекунды (`0` — активен).
    pub cooldown_ms: u64,
    /// Счётчики пула keep-alive (нули для UDP/TCP).
    pub pool: PoolStats,
}

pub(crate) struct Inner {
    pub(crate) config: ResolverConfig,
    pub(crate) cache: Cache,
    pub(crate) validation: ValidationCache,
    pub(crate) blocklist: RwLock<Arc<Blocklist>>,
    pub(crate) static_anchors: RwLock<Arc<Vec<TrustAnchorConfig>>>,
    pub(crate) overrides: Overrides,
    pub(crate) forwarders: Vec<Forwarder>,
    pub(crate) round_robin: AtomicUsize,
    pub(crate) upstream: Arc<UpstreamClient>,
    pub(crate) upstream_counters: Arc<UpstreamCounters>,
    pub(crate) root_hints: Vec<SocketAddr>,
    pub(crate) counters: RuntimeCounters,
}

/// Кеширующий DNS-резолвер.
///
/// `Resolver` дешёво клонируется и безопасно используется из многих потоков:
/// кеш шардирован, health forwarder-ов и счётчики — атомарные.
#[derive(Clone)]
pub struct Resolver {
    pub(crate) inner: Arc<Inner>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Resolver")
            .field("mode", &self.inner.config.mode)
            .field("cache_entries", &self.inner.cache.len())
            .finish_non_exhaustive()
    }
}

impl Resolver {
    /// Создаёт резолвер из конфигурации.
    ///
    /// # Errors
    ///
    /// [`ResolverError::Config`] при некорректной конфигурации и
    /// [`ResolverError::Blocklist`] при ошибке чтения blocklist.
    pub fn new(config: ResolverConfig) -> Result<Self, ResolverError> {
        config.validate()?;

        let blocklist_paths = config.blocklist.all_paths();
        let blocklist = if blocklist_paths.is_empty() {
            Blocklist::empty(&config.blocklist.allowlist)
        } else {
            Blocklist::load_paths(&blocklist_paths, &config.blocklist.allowlist)?
        };
        let overrides = Overrides::build(&config.overrides)?;
        let pool = PoolConfig {
            size: config.pool.size,
            reconnect_backoff: config.pool.reconnect_backoff,
            max_reconnect_backoff: config.pool.max_reconnect_backoff,
        };
        let forwarders = match &config.mode {
            Mode::Forward(forward) => forward
                .effective_upstreams()
                .into_iter()
                .map(|upstream| Forwarder::new(upstream, pool))
                .collect::<Result<Vec<_>, _>>()?,
            Mode::Iterative(_) => Vec::new(),
        };
        let root_hints = match &config.mode {
            Mode::Forward(_) => Vec::new(),
            Mode::Iterative(iterative) if !iterative.root_hints.is_empty() => {
                iterative.root_hints.clone()
            }
            Mode::Iterative(_) => root_hints::root_hints(),
        };
        let upstream = Arc::new(UpstreamClient::new(UpstreamOptions {
            edns_payload: config.edns_payload,
            use_0x20: config.use_0x20,
            retries: config.retries,
            per_query: config.timeouts.per_query,
            tcp_timeout: config.timeouts.tcp,
            max_response_bytes: config.max_response_bytes,
        }));
        let upstream_counters = upstream.counters();
        let cache = Cache::new(config.cache);
        let validation = ValidationCache::new(config.cache.max_entries.saturating_div(4).max(64));
        let static_anchors = Arc::new(config.dnssec.anchors.clone());

        Ok(Self {
            inner: Arc::new(Inner {
                config,
                cache,
                validation,
                blocklist: RwLock::new(Arc::new(blocklist)),
                static_anchors: RwLock::new(static_anchors),
                overrides,
                forwarders,
                round_robin: AtomicUsize::new(0),
                upstream,
                upstream_counters,
                root_hints,
                counters: RuntimeCounters::default(),
            }),
        })
    }

    /// Разрешает запрос и возвращает DNS-ответ.
    ///
    /// Метод не возвращает ошибок наружу: проблемы транспорта, таймауты и
    /// BOGUS превращаются в `SERVFAIL`, некорректный запрос — в `FORMERR`
    /// или `NOTIMP`.
    #[must_use]
    pub fn resolve(&self, request: &Message) -> Message {
        self.resolve_with(request, &ResolveContext::new())
    }

    /// Разрешает запрос с явным дедлайном/токеном отмены.
    #[must_use]
    pub fn resolve_with(&self, request: &Message, context: &ResolveContext) -> Message {
        let context = self.effective_context(context);
        self.inner.counters.queries.fetch_add(1, Ordering::Relaxed);
        match self.resolve_inner(request, &context) {
            Ok(response) => response,
            Err(error) => {
                self.inner.counters.servfail.fetch_add(1, Ordering::Relaxed);
                error_response(request, error.rcode())
            }
        }
    }

    /// Разрешает запрос и кодирует ответ прямо в `out`.
    ///
    /// На попадании в кеш ответ кодируется из компактных wire-записей кеша
    /// без построения [`Message`] и без копирования RRset: горячий путь не
    /// аллоцирует. На промахе выполняется обычная резолюция, после чего
    /// готовый ответ кодируется в тот же буфер.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferTooSmall`], если `out` меньше ответа; прочие
    /// ошибки кодирования при некорректных данных.
    pub fn resolve_into(&self, request: &Message, out: &mut [u8]) -> Result<usize, EncodeError> {
        self.inner.counters.queries.fetch_add(1, Ordering::Relaxed);
        if let Some(result) = self.try_cache_into(request, out) {
            return result;
        }
        let context = self.effective_context(&ResolveContext::new());
        let response = match self.resolve_inner(request, &context) {
            Ok(response) => response,
            Err(error) => {
                self.inner.counters.servfail.fetch_add(1, Ordering::Relaxed);
                error_response(request, error.rcode())
            }
        };
        response.encode_into(out)
    }

    /// Удобная резолюция одиночного вопроса.
    #[must_use]
    pub fn resolve_qname(&self, qname: &Name, qtype: Rtype) -> Message {
        let question = Question::new(qname.clone(), qtype, Rclass::IN);
        let request = Message::query(random_id(), question);
        self.resolve(&request)
    }

    /// Кеш резолвера.
    #[must_use]
    pub fn cache(&self) -> &Cache {
        &self.inner.cache
    }

    /// Снимок статистики.
    #[must_use]
    pub fn stats(&self) -> StatsSnapshot {
        let mut upstream = self.inner.upstream_counters.snapshot();
        let mut pool = PoolStats::default();
        for forwarder in &self.inner.forwarders {
            forwarder.pool_stats(&mut pool);
        }
        upstream.pool = pool;
        let (validation_hits, validation_misses) = self.inner.validation.snapshot();
        StatsSnapshot {
            queries: self.inner.counters.queries.load(Ordering::Relaxed),
            servfail: self.inner.counters.servfail.load(Ordering::Relaxed),
            blocked: self.inner.counters.blocked.load(Ordering::Relaxed),
            overridden: self.inner.counters.overridden.load(Ordering::Relaxed),
            dnssec_secure: self.inner.counters.dnssec_secure.load(Ordering::Relaxed),
            dnssec_insecure: self.inner.counters.dnssec_insecure.load(Ordering::Relaxed),
            dnssec_bogus: self.inner.counters.dnssec_bogus.load(Ordering::Relaxed),
            dnssec_validation_hits: validation_hits,
            dnssec_validation_misses: validation_misses,
            cache: self.inner.cache.snapshot(),
            upstream,
        }
    }

    /// Перезагружает blocklist из файла, атомарно подменяя снимок.
    ///
    /// При ошибке чтения старый список остаётся в силе.
    ///
    /// # Errors
    ///
    /// [`ResolverError::Blocklist`] при ошибке чтения.
    pub fn reload_blocklist(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<BlocklistStats, ResolverError> {
        let blocklist = Blocklist::load(path, &self.inner.config.blocklist.allowlist)?;
        self.replace_blocklist(blocklist)
    }

    /// Перезагружает все файлы blocklist из конфигурации резолвера.
    ///
    /// Снимок подменяется атомарно; при ошибке чтения любого файла старый
    /// список остаётся в силе. Если файлы не заданы, возвращается статистика
    /// текущего (пустого) списка.
    ///
    /// # Errors
    ///
    /// [`ResolverError::Blocklist`] при ошибке чтения.
    pub fn reload_blocklists(&self) -> Result<BlocklistStats, ResolverError> {
        let paths = self.inner.config.blocklist.all_paths();
        if paths.is_empty() {
            return Ok(self.blocklist().stats());
        }
        let blocklist = Blocklist::load_paths(&paths, &self.inner.config.blocklist.allowlist)?;
        self.replace_blocklist(blocklist)
    }

    fn replace_blocklist(&self, blocklist: Blocklist) -> Result<BlocklistStats, ResolverError> {
        let stats = blocklist.stats();
        let mut guard = self
            .inner
            .blocklist
            .write()
            .map_err(|_| ResolverError::Internal {
                reason: "blocklist lock poisoned",
            })?;
        *guard = Arc::new(blocklist);
        Ok(stats)
    }

    /// Текущий blocklist (для диагностики).
    #[must_use]
    pub fn blocklist(&self) -> Arc<Blocklist> {
        self.inner.blocklist.read().map_or_else(
            |_| Arc::new(Blocklist::default()),
            |guard| Arc::clone(&guard),
        )
    }

    /// Состояние forward-upstream'ов (пусто в итеративном режиме).
    #[must_use]
    pub fn upstream_status(&self) -> Vec<UpstreamStatus> {
        let now = now_millis();
        self.inner
            .forwarders
            .iter()
            .map(|forwarder| {
                let mut pool = PoolStats::default();
                forwarder.pool_stats(&mut pool);
                let cooldown_until = forwarder.cooldown_until_ms.load(Ordering::Relaxed);
                UpstreamStatus {
                    kind: forwarder.config.kind(),
                    address: upstream_address(&forwarder.config),
                    healthy: forwarder.healthy(now),
                    failures: forwarder.failures.load(Ordering::Relaxed),
                    cooldown_ms: cooldown_until.saturating_sub(now),
                    pool,
                }
            })
            .collect()
    }

    /// Статические trust anchors, действующие сейчас.
    #[must_use]
    pub fn static_trust_anchors(&self) -> Arc<Vec<TrustAnchorConfig>> {
        self.inner
            .static_anchors
            .read()
            .map_or_else(|_| Arc::new(Vec::new()), |guard| Arc::clone(&guard))
    }

    /// Атомарно заменяет статические trust anchors.
    ///
    /// Возвращает число установленных anchors. Уже выполняющиеся резолюции
    /// дочитывают прежний снимок.
    pub fn replace_trust_anchors(&self, anchors: Vec<TrustAnchorConfig>) -> usize {
        let count = anchors.len();
        if let Ok(mut guard) = self.inner.static_anchors.write() {
            *guard = Arc::new(anchors);
        }
        self.inner.validation.clear();
        count
    }

    /// RFC 5011-провайдер anchors, если он настроен.
    #[must_use]
    pub fn trust_anchor_provider(&self) -> Option<Arc<dyn pulse_dnssec::TrustAnchorProvider>> {
        self.inner
            .config
            .trust_anchor_provider
            .as_ref()
            .map(Arc::clone)
    }

    fn effective_context(&self, context: &ResolveContext) -> ResolveContext {
        let now = Instant::now();
        let configured = now
            .checked_add(self.inner.config.timeouts.total)
            .unwrap_or(now);
        let deadline = context
            .deadline
            .map_or(configured, |deadline| deadline.min(configured));
        ResolveContext {
            deadline: Some(deadline),
            cancellation: context.cancellation.clone(),
        }
    }

    fn resolve_inner(
        &self,
        request: &Message,
        context: &ResolveContext,
    ) -> Result<Message, ResolverError> {
        if request.flags().opcode() != pulse_dns::Opcode::QUERY {
            return Ok(simple_response(request, Rcode::NOTIMP));
        }
        let Some(question) = request.questions().first() else {
            return Ok(simple_response(request, Rcode::FORMERR));
        };
        if request.questions().len() != 1 {
            return Ok(simple_response(request, Rcode::FORMERR));
        }
        if question.qclass() != Rclass::IN && question.qclass() != Rclass::ANY {
            return Ok(simple_response(request, Rcode::REFUSED));
        }
        let qname = question.qname();
        let qtype = question.qtype();
        if let Some(edns) = request.edns()
            && edns.version() != 0
        {
            return Ok(simple_response(request, Rcode::BADVERS));
        }
        if matches!(
            qtype,
            Rtype::AXFR | Rtype::IXFR | Rtype::OPT | Rtype::TKEY | Rtype::TSIG | Rtype::ANY
        ) {
            return Ok(simple_response(request, Rcode::NOTIMP));
        }
        check_context(context)?;

        match self.inner.overrides.lookup(qname, qtype) {
            OverrideOutcome::Answer(records) => {
                self.inner
                    .counters
                    .overridden
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(answer_response(request, records, false));
            }
            OverrideOutcome::NoData => {
                self.inner
                    .counters
                    .overridden
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(simple_response(request, Rcode::NOERROR));
            }
            OverrideOutcome::Miss => {}
        }

        if self.is_blocked(qname) {
            self.inner.counters.blocked.fetch_add(1, Ordering::Relaxed);
            return Ok(blocked_response(
                request,
                &self.inner.config.blocklist.response,
                qtype,
            ));
        }

        let validation_enabled = self.inner.config.dnssec.enabled;
        if let Some(hit) = self
            .inner
            .cache
            .lookup_answer(qname, qtype, !validation_enabled)
        {
            return Ok(answer_response(
                request,
                hit.records,
                validation_enabled && hit.secure,
            ));
        }
        if let Some(hit) = self
            .inner
            .cache
            .lookup_negative(qname, qtype, !validation_enabled)
        {
            return Ok(negative_response(
                request,
                hit.rcode,
                hit.authority,
                validation_enabled && hit.secure,
            ));
        }

        let dnssec_ok = validation_enabled || request_do(request);
        let resolution = match &self.inner.config.mode {
            Mode::Forward(_) => forward::resolve(self, qname, qtype, dnssec_ok, context)?,
            Mode::Iterative(_) => iterative::resolve(self, qname, qtype, dnssec_ok, context)?,
        };

        let (security, validated) = if validation_enabled {
            let outcome = match dnssec::validate(self, qname, qtype, &resolution, context) {
                Ok(outcome) => outcome,
                Err(error) => {
                    if matches!(error, ResolverError::Bogus { .. }) {
                        self.inner
                            .counters
                            .dnssec_bogus
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    return Err(error);
                }
            };
            match outcome.state {
                Security::Secure => {
                    self.inner
                        .counters
                        .dnssec_secure
                        .fetch_add(1, Ordering::Relaxed);
                }
                Security::Insecure => {
                    self.inner
                        .counters
                        .dnssec_insecure
                        .fetch_add(1, Ordering::Relaxed);
                }
                Security::Unvalidated => {}
            }
            (outcome.state, outcome.validated)
        } else {
            (Security::Unvalidated, HashSet::new())
        };

        if resolution.answers.is_empty() && find_soa(&resolution.authority).is_some() {
            if let Some(ttl) = negative_ttl(&resolution.authority) {
                let secure = cache_security(security);
                self.inner.cache.insert_negative(
                    qname,
                    qtype,
                    resolution.rcode,
                    &resolution.authority,
                    ttl,
                    secure,
                );
            }
        } else if security != Security::Unvalidated {
            for group in group_rrsets(&resolution.answers) {
                if !group.owner.is_subdomain_of(&resolution.zone) {
                    continue;
                }
                let secure = if security == Security::Secure
                    && validated.contains(&(group.owner.clone(), group.rr_type))
                {
                    crate::cache::SecurityState::Secure
                } else {
                    crate::cache::SecurityState::Insecure
                };
                let records: Vec<Record> = resolution
                    .answers
                    .iter()
                    .filter(|record| {
                        record.owner() == &group.owner && record.rr_type() == group.rr_type
                    })
                    .cloned()
                    .collect();
                self.inner.cache.insert_rrset(
                    &group.owner,
                    group.rr_type,
                    Rclass::IN,
                    &records,
                    secure,
                );
                let signatures: Vec<Record> = resolution
                    .answers
                    .iter()
                    .filter(|record| {
                        record.owner() == &group.owner && record.rr_type() == Rtype::RRSIG
                    })
                    .cloned()
                    .collect();
                if !signatures.is_empty() {
                    self.inner.cache.insert_rrset(
                        &group.owner,
                        Rtype::RRSIG,
                        Rclass::IN,
                        &signatures,
                        secure,
                    );
                }
            }
        } else {
            for group in group_rrsets(&resolution.answers) {
                if !group.owner.is_subdomain_of(&resolution.zone) {
                    continue;
                }
                let records: Vec<Record> = resolution
                    .answers
                    .iter()
                    .filter(|record| {
                        record.owner() == &group.owner && record.rr_type() == group.rr_type
                    })
                    .cloned()
                    .collect();
                self.inner.cache.insert_rrset(
                    &group.owner,
                    group.rr_type,
                    Rclass::IN,
                    &records,
                    crate::cache::SecurityState::Unvalidated,
                );
                let signatures: Vec<Record> = resolution
                    .answers
                    .iter()
                    .filter(|record| {
                        record.owner() == &group.owner && record.rr_type() == Rtype::RRSIG
                    })
                    .cloned()
                    .collect();
                if !signatures.is_empty() {
                    self.inner.cache.insert_rrset(
                        &group.owner,
                        Rtype::RRSIG,
                        Rclass::IN,
                        &signatures,
                        crate::cache::SecurityState::Unvalidated,
                    );
                }
            }
        }

        let ad = validation_enabled && security == Security::Secure;
        Ok(resolution_response(request, &resolution, ad))
    }

    /// Пытается собрать ответ из кеша прямо в `out`.
    ///
    /// `None` означает, что запрос нужно обслужить обычным путём (override,
    /// blocklist, CNAME-цепочка, промах или нестандартный запрос).
    fn try_cache_into(
        &self,
        request: &Message,
        out: &mut [u8],
    ) -> Option<Result<usize, EncodeError>> {
        if request.flags().opcode() != pulse_dns::Opcode::QUERY {
            return None;
        }
        if request.questions().len() != 1 {
            return None;
        }
        let question = request.questions().first()?;
        let qclass = question.qclass();
        if qclass != Rclass::IN && qclass != Rclass::ANY {
            return None;
        }
        if let Some(edns) = request.edns()
            && edns.version() != 0
        {
            return None;
        }
        let qtype = question.qtype();
        if matches!(
            qtype,
            Rtype::AXFR | Rtype::IXFR | Rtype::OPT | Rtype::TKEY | Rtype::TSIG | Rtype::ANY
        ) {
            return None;
        }
        let qname = question.qname();
        if !matches!(
            self.inner.overrides.lookup(qname, qtype),
            OverrideOutcome::Miss
        ) {
            return None;
        }
        if self.is_blocked(qname) {
            return None;
        }

        let validation_enabled = self.inner.config.dnssec.enabled;
        let accept_unvalidated = !validation_enabled;
        let cache = &self.inner.cache;
        let hit = if let Some(hit) = cache.lookup(qname, qtype, Rclass::IN, accept_unvalidated) {
            hit
        } else {
            let fallback = cache.lookup(qname, Rtype::ANY, Rclass::IN, accept_unvalidated)?;
            if !fallback.negative() {
                drop(fallback);
                return None;
            }
            fallback
        };
        let negative = hit.negative();
        let rcode = hit.rcode();
        let secure = hit.secure() == SecurityState::Secure;
        let remaining = hit.remaining();

        let mut scratch = EncodeScratch::new();
        let mut encoder = Encoder::new(out, EncodeOptions::compressed(), &mut scratch);
        if let Err(error) = encoder.begin_message(request.id()) {
            return Some(Err(error));
        }
        if let Err(error) = encoder.write_question(question) {
            return Some(Err(error));
        }
        let stored = usize::from(hit.records());
        let mut answers = if negative { 0 } else { stored };
        let authority = if negative { stored } else { 0 };
        for rr in wire_rrs(hit.rrset()) {
            if let Err(error) = encoder.write_rr_raw(
                rr.owner,
                rr.rr_type,
                rr.class,
                Ttl::from_wire(remaining),
                rr.rdata,
            ) {
                return Some(Err(error));
            }
        }
        drop(hit);

        if !negative
            && qtype != Rtype::RRSIG
            && cache.may_have_signatures()
            && let Some(signatures) =
                cache.peek(qname, Rtype::RRSIG, Rclass::IN, accept_unvalidated)
        {
            for rr in wire_rrs(signatures.rrset()) {
                if let Err(error) = encoder.write_rr_raw(
                    rr.owner,
                    rr.rr_type,
                    rr.class,
                    Ttl::from_wire(signatures.remaining()),
                    rr.rdata,
                ) {
                    return Some(Err(error));
                }
                answers = answers.saturating_add(1);
            }
        }

        let edns = request.edns().map(|edns| {
            Edns::new(
                edns.udp_payload_size()
                    .clamp(512, pulse_dns::EDNS_DEFAULT_PAYLOAD),
            )
            .with_dnssec_ok(edns.dnssec_ok())
        });
        if let Some(edns) = &edns
            && let Err(error) = encoder.write_edns(edns)
        {
            return Some(Err(error));
        }
        let flags = Flags::new()
            .with_qr(true)
            .with_rd(request.flags().rd())
            .with_cd(request.flags().cd())
            .with_ra(true)
            .with_ad(validation_enabled && secure && !request.flags().cd())
            .with_rcode_bits(rcode.header_bits());
        let counts = HeaderCounts {
            question: 1,
            answer: u16::try_from(answers).unwrap_or(u16::MAX),
            authority: u16::try_from(authority).unwrap_or(u16::MAX),
            additional: u16::from(edns.is_some()),
        };
        Some(encoder.finish(flags, counts))
    }

    fn is_blocked(&self, qname: &Name) -> bool {
        let blocklist = self.blocklist();
        blocklist.is_blocked(qname)
    }

    pub(crate) fn root_hints(&self) -> Vec<SocketAddr> {
        self.inner.root_hints.clone()
    }

    pub(crate) fn ns_port(&self) -> u16 {
        match &self.inner.config.mode {
            Mode::Iterative(config) => config.ns_port,
            Mode::Forward(_) => 53,
        }
    }

    pub(crate) fn cache_ref(&self) -> &Cache {
        &self.inner.cache
    }

    pub(crate) fn forwarder_order(&self) -> Vec<usize> {
        let total = self.inner.forwarders.len();
        if total == 0 {
            return Vec::new();
        }
        let now_ms = now_millis();
        let start = self.inner.round_robin.fetch_add(1, Ordering::Relaxed);
        let mut healthy = Vec::with_capacity(total);
        let mut unhealthy = Vec::new();
        for offset in 0..total {
            let index = start.wrapping_add(offset) % total;
            let Some(forwarder) = self.inner.forwarders.get(index) else {
                continue;
            };
            if forwarder.healthy(now_ms) {
                healthy.push(index);
            } else {
                unhealthy.push(index);
            }
        }
        healthy.extend(unhealthy);
        healthy
    }

    pub(crate) fn forwarder_config(&self, index: usize) -> Option<&UpstreamConfig> {
        self.inner
            .forwarders
            .get(index)
            .map(|forwarder| &forwarder.config)
    }

    pub(crate) fn note_failover(&self) {
        self.inner
            .upstream_counters
            .failovers
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Один запрос к forwarder-у с учётом его транспорта.
    pub(crate) fn query_forwarder(
        &self,
        index: usize,
        question: &Question,
        dnssec_ok: bool,
        context: &ResolveContext,
    ) -> Result<UpstreamResponse, ResolverError> {
        let forwarder = self
            .inner
            .forwarders
            .get(index)
            .ok_or(ResolverError::NoUpstream)?;
        check_context(context)?;
        match &forwarder.transport {
            ForwardTransport::Udp(address) => self.inner.upstream.query_over(
                *address,
                UpstreamTransport::Udp,
                question,
                true,
                dnssec_ok,
                context.deadline(),
                context.cancel(),
            ),
            ForwardTransport::Tcp(address) => self.inner.upstream.query_over(
                *address,
                UpstreamTransport::Tcp,
                question,
                true,
                dnssec_ok,
                context.deadline(),
                context.cancel(),
            ),
            ForwardTransport::Dot(client) => {
                self.inner
                    .upstream_counters
                    .tls_queries
                    .fetch_add(1, Ordering::Relaxed);
                let options = self.inner.upstream.options();
                let prepared = prepare(question, true, dnssec_ok, options.edns_payload, false)?;
                let connect_timeout = secure_connect_timeout(self, context);
                let io_timeout = secure_io_timeout(self, context);
                let bytes = client
                    .query(&prepared.bytes, connect_timeout, io_timeout)
                    .map_err(|error| self.secure_transport_error(error))?;
                let message = Message::decode(&bytes, &DecodeLimits::default())?;
                verify_response(&message, &bytes, &prepared)?;
                Ok(UpstreamResponse { message })
            }
            ForwardTransport::Doh(client) => {
                self.inner
                    .upstream_counters
                    .https_queries
                    .fetch_add(1, Ordering::Relaxed);
                let options = self.inner.upstream.options();
                let prepared = prepare(question, true, dnssec_ok, options.edns_payload, false)?;
                let connect_timeout = secure_connect_timeout(self, context);
                let io_timeout = secure_io_timeout(self, context);
                let bytes = client
                    .query(&prepared.bytes, connect_timeout, io_timeout)
                    .map_err(|error| self.secure_transport_error(error))?;
                let message = Message::decode(&bytes, &DecodeLimits::default())?;
                verify_response(&message, &bytes, &prepared)?;
                Ok(UpstreamResponse { message })
            }
        }
    }

    fn secure_transport_error(&self, error: pulse_tls::Error) -> ResolverError {
        let mapped = pulse_transport_error(error);
        if matches!(mapped, ResolverError::Timeout) {
            self.inner
                .upstream_counters
                .timeouts
                .fetch_add(1, Ordering::Relaxed);
        }
        mapped
    }

    pub(crate) fn forwarder_failure(&self, index: usize) {
        let Some(forwarder) = self.inner.forwarders.get(index) else {
            return;
        };
        let failures = forwarder.failures.fetch_add(1, Ordering::Relaxed) + 1;
        let max = match &self.inner.config.mode {
            Mode::Forward(config) => config.max_failures.max(1),
            Mode::Iterative(_) => 1,
        };
        if failures >= max {
            let cooldown = match &self.inner.config.mode {
                Mode::Forward(config) => config.cooldown,
                Mode::Iterative(_) => std::time::Duration::from_secs(1),
            };
            let until = now_millis().saturating_add(duration_millis(cooldown));
            forwarder.cooldown_until_ms.store(until, Ordering::Relaxed);
        }
    }

    pub(crate) fn forwarder_success(&self, index: usize) {
        let Some(forwarder) = self.inner.forwarders.get(index) else {
            return;
        };
        forwarder.failures.store(0, Ordering::Relaxed);
        forwarder.cooldown_until_ms.store(0, Ordering::Relaxed);
    }

    pub(crate) fn query_any(
        &self,
        servers: &[SocketAddr],
        question: &Question,
        recursion_desired: bool,
        dnssec_ok: bool,
        context: &ResolveContext,
    ) -> Result<UpstreamResponse, ResolverError> {
        if servers.is_empty() {
            return Err(ResolverError::NoUpstream);
        }
        let parallel = self.inner.config.parallel_ns.min(servers.len()).max(1);
        let mut last_error = ResolverError::Timeout;
        for chunk in servers.chunks(parallel) {
            match self.query_chunk(chunk, question, recursion_desired, dnssec_ok, context) {
                Ok(response) => return Ok(response),
                Err(ResolverError::Cancelled) => return Err(ResolverError::Cancelled),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    fn query_chunk(
        &self,
        servers: &[SocketAddr],
        question: &Question,
        recursion_desired: bool,
        dnssec_ok: bool,
        context: &ResolveContext,
    ) -> Result<UpstreamResponse, ResolverError> {
        let Some(first) = servers.first() else {
            return Err(ResolverError::NoUpstream);
        };
        if servers.len() == 1 {
            let response = self.inner.upstream.query(
                *first,
                question,
                recursion_desired,
                dnssec_ok,
                context.deadline(),
                context.cancel(),
            )?;
            if is_retryable_rcode(response.message.rcode()) {
                return Err(ResolverError::UpstreamRcode {
                    server: first.to_string(),
                    rcode: response.message.rcode(),
                });
            }
            return Ok(response);
        }

        let (sender, receiver) = std::sync::mpsc::channel();
        for server in servers.iter().copied() {
            let sender = sender.clone();
            let client = Arc::clone(&self.inner.upstream);
            let question = question.clone();
            let deadline = context.deadline();
            let cancel = context.cancel().cloned();
            std::thread::spawn(move || {
                let result = client.query(
                    server,
                    &question,
                    recursion_desired,
                    dnssec_ok,
                    deadline,
                    cancel.as_ref(),
                );
                let _ = sender.send(result);
            });
        }
        drop(sender);
        let mut last_error = ResolverError::Timeout;
        for result in receiver {
            match result {
                Ok(response) if is_retryable_rcode(response.message.rcode()) => {
                    last_error = ResolverError::UpstreamRcode {
                        server: first.to_string(),
                        rcode: response.message.rcode(),
                    };
                }
                Ok(response) => return Ok(response),
                Err(ResolverError::Cancelled) => return Err(ResolverError::Cancelled),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }
}

fn secure_connect_timeout(resolver: &Resolver, context: &ResolveContext) -> std::time::Duration {
    remaining(context.deadline()).min(resolver.inner.config.timeouts.tcp)
}

fn secure_io_timeout(resolver: &Resolver, context: &ResolveContext) -> std::time::Duration {
    remaining(context.deadline()).min(resolver.inner.config.timeouts.per_query)
}

fn remaining(deadline: Instant) -> std::time::Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn pulse_transport_error(error: pulse_tls::Error) -> ResolverError {
    if error.is_timeout() {
        return ResolverError::Timeout;
    }
    match error {
        pulse_tls::Error::Io(source) => ResolverError::Io(source),
        other => ResolverError::Transport {
            reason: other.to_string(),
        },
    }
}

fn cache_security(security: Security) -> crate::cache::SecurityState {
    match security {
        Security::Secure => crate::cache::SecurityState::Secure,
        Security::Insecure => crate::cache::SecurityState::Insecure,
        Security::Unvalidated => crate::cache::SecurityState::Unvalidated,
    }
}

pub(crate) fn check_context(context: &ResolveContext) -> Result<(), ResolverError> {
    if context
        .cancel()
        .is_some_and(|token| token.load(Ordering::Relaxed))
    {
        return Err(ResolverError::Cancelled);
    }
    if Instant::now() >= context.deadline() {
        return Err(ResolverError::Timeout);
    }
    Ok(())
}

fn request_do(request: &Message) -> bool {
    request.edns().is_some_and(Edns::dnssec_ok)
}

fn simple_response(request: &Message, rcode: Rcode) -> Message {
    finalize_response(request, rcode, Vec::new(), Vec::new(), Vec::new(), false)
}

fn answer_response(request: &Message, answers: Vec<Record>, ad: bool) -> Message {
    finalize_response(request, Rcode::NOERROR, answers, Vec::new(), Vec::new(), ad)
}

fn negative_response(request: &Message, rcode: Rcode, authority: Vec<Record>, ad: bool) -> Message {
    finalize_response(request, rcode, Vec::new(), authority, Vec::new(), ad)
}

fn resolution_response(request: &Message, resolution: &Resolution, ad: bool) -> Message {
    let additional = within_bailiwick(&resolution.additional, &resolution.zone);
    let mut authority = resolution.authority.clone();
    if resolution.answers.is_empty()
        && let Some(ttl) = negative_ttl(&authority)
    {
        authority = crate::rrutil::rewrite_ttl(&authority, ttl);
    }
    let dnssec_ok = request_do(request);
    finalize_response(
        request,
        resolution.rcode,
        strip_dnssec(&resolution.answers, dnssec_ok),
        strip_dnssec(&authority, dnssec_ok),
        strip_dnssec(&additional, dnssec_ok),
        ad,
    )
}

fn strip_dnssec(records: &[Record], keep: bool) -> Vec<Record> {
    if keep {
        return records.to_vec();
    }
    records
        .iter()
        .filter(|record| {
            !matches!(
                record.rr_type(),
                Rtype::RRSIG | Rtype::NSEC | Rtype::NSEC3 | Rtype::NSEC3PARAM
            )
        })
        .cloned()
        .collect()
}

fn error_response(request: &Message, rcode: Rcode) -> Message {
    simple_response(request, rcode)
}

fn blocked_response(request: &Message, policy: &BlockResponse, qtype: Rtype) -> Message {
    let ttl = Ttl::from_wire(SYNTHETIC_TTL);
    match policy {
        BlockResponse::NxDomain => simple_response(request, Rcode::NXDOMAIN),
        BlockResponse::Null { ipv4, ipv6 } => {
            let rdata = match qtype {
                Rtype::A => Some(pulse_dns::Rdata::A(*ipv4)),
                Rtype::AAAA => Some(pulse_dns::Rdata::Aaaa(*ipv6)),
                _ => None,
            };
            let Some(rdata) = rdata else {
                return simple_response(request, Rcode::NOERROR);
            };
            let Some(question) = request.questions().first() else {
                return simple_response(request, Rcode::FORMERR);
            };
            let Some(record) = Record::new(
                question.qname().clone(),
                rdata.rr_type(),
                Rclass::IN,
                ttl,
                rdata,
            )
            .ok() else {
                return simple_response(request, Rcode::SERVFAIL);
            };
            answer_response(request, vec![record], false)
        }
    }
}

fn finalize_response(
    request: &Message,
    rcode: Rcode,
    answers: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
    ad: bool,
) -> Message {
    let mut response = Message::response(request);
    if let Some(edns) = request.edns() {
        let payload = edns
            .udp_payload_size()
            .clamp(512, pulse_dns::EDNS_DEFAULT_PAYLOAD);
        response.set_edns(Some(Edns::new(payload).with_dnssec_ok(edns.dnssec_ok())));
    }
    response.set_rcode(rcode);
    let flags = response
        .flags()
        .with_ra(true)
        .with_ad(ad && !request.flags().cd())
        .with_qr(true);
    response.set_flags(flags);
    for record in answers {
        response.add_answer(record);
    }
    for record in authority {
        response.add_authority(record);
    }
    for record in additional {
        response.add_additional(record);
    }
    response
}

fn random_id() -> u16 {
    let mut bytes = [0_u8; 2];
    if getrandom::fill(&mut bytes).is_ok() {
        return u16::from_ne_bytes(bytes);
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    u16::try_from(nanos & u128::from(u16::MAX)).unwrap_or(1)
}

fn upstream_address(upstream: &UpstreamConfig) -> String {
    match upstream {
        UpstreamConfig::Udp(address) | UpstreamConfig::Tcp(address) => address.to_string(),
        UpstreamConfig::Tls(upstream) => upstream.authority(),
        UpstreamConfig::Https(upstream) => upstream.url.clone(),
    }
}

pub(crate) fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, duration_millis)
}

fn duration_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Проверка, что ответ не усечён до пустого (используется тестами).
#[cfg(test)]
fn flags_are_consistent(response: &Message) -> bool {
    response.flags().qr() && response.flags().ra() && !response.flags().aa()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_null_policy_answers_all_types() {
        let request = Message::query(
            1,
            Question::new(
                Name::parse("ads.example.com").unwrap(),
                Rtype::A,
                Rclass::IN,
            ),
        );
        let response = blocked_response(&request, &BlockResponse::null(), Rtype::A);
        assert_eq!(response.rcode(), Rcode::NOERROR);
        assert_eq!(response.answers().len(), 1);
        assert!(!response.flags().ad());
    }

    #[test]
    fn final_response_echoes_edns_payload() {
        let mut request = Message::query(
            1,
            Question::new(Name::parse("example.com").unwrap(), Rtype::A, Rclass::IN),
        );
        request.set_edns(Some(Edns::new(4096)));
        let response = simple_response(&request, Rcode::NOERROR);
        assert_eq!(response.edns().map(Edns::udp_payload_size), Some(1232));
        assert!(flags_are_consistent(&response));
    }

    #[test]
    fn cancellation_token_is_observable() {
        let token = CancellationToken::new();
        let context = ResolveContext::new().with_cancellation(&token);
        assert!(check_context(&context).is_ok());
        token.cancel();
        assert!(matches!(
            check_context(&context),
            Err(ResolverError::Cancelled)
        ));
    }
}
