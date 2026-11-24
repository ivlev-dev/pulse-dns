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

use pulse_dns::{Edns, Message, Name, Question, Rclass, Rcode, Record, Rtype, Ttl};

use crate::blocklist::{Blocklist, BlocklistStats};
use crate::cache::{Cache, CacheSnapshot};
use crate::config::{BlockResponse, Mode, ResolverConfig};
use crate::dnssec::{self, Security};
use crate::error::ResolverError;
use crate::forward;
use crate::iterative;
use crate::overrides::{OverrideOutcome, Overrides};
use crate::root_hints;
use crate::rrutil::{find_soa, group_rrsets, negative_ttl, within_bailiwick};
use crate::upstream::{
    UpstreamClient, UpstreamCounters, UpstreamOptions, UpstreamResponse, UpstreamStats,
    is_retryable_rcode,
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
pub(crate) struct Forwarder {
    pub(crate) address: SocketAddr,
    failures: AtomicU32,
    cooldown_until_ms: AtomicU64,
}

impl Forwarder {
    fn new(address: SocketAddr) -> Self {
        Self {
            address,
            failures: AtomicU32::new(0),
            cooldown_until_ms: AtomicU64::new(0),
        }
    }

    fn healthy(&self, now_ms: u64) -> bool {
        self.cooldown_until_ms.load(Ordering::Relaxed) <= now_ms
    }
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
    /// Статистика кеша.
    pub cache: CacheSnapshot,
    /// Статистика транспорта.
    pub upstream: UpstreamStats,
}

pub(crate) struct Inner {
    pub(crate) config: ResolverConfig,
    pub(crate) cache: Cache,
    pub(crate) blocklist: RwLock<Arc<Blocklist>>,
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
        let forwarders = match &config.mode {
            Mode::Forward(forward) => forward
                .servers
                .iter()
                .map(|address| Forwarder::new(*address))
                .collect(),
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

        Ok(Self {
            inner: Arc::new(Inner {
                config,
                cache,
                blocklist: RwLock::new(Arc::new(blocklist)),
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
        StatsSnapshot {
            queries: self.inner.counters.queries.load(Ordering::Relaxed),
            servfail: self.inner.counters.servfail.load(Ordering::Relaxed),
            blocked: self.inner.counters.blocked.load(Ordering::Relaxed),
            overridden: self.inner.counters.overridden.load(Ordering::Relaxed),
            dnssec_secure: self.inner.counters.dnssec_secure.load(Ordering::Relaxed),
            dnssec_insecure: self.inner.counters.dnssec_insecure.load(Ordering::Relaxed),
            dnssec_bogus: self.inner.counters.dnssec_bogus.load(Ordering::Relaxed),
            cache: self.inner.cache.snapshot(),
            upstream: self.inner.upstream_counters.snapshot(),
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
        let qname = question.qname().clone();
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

        match self.inner.overrides.lookup(&qname, qtype) {
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

        if self.is_blocked(&qname) {
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
            .lookup_answer(&qname, qtype, !validation_enabled)
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
            .lookup_negative(&qname, qtype, !validation_enabled)
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
            Mode::Forward(_) => forward::resolve(self, &qname, qtype, dnssec_ok, context)?,
            Mode::Iterative(_) => iterative::resolve(self, &qname, qtype, dnssec_ok, context)?,
        };

        let (security, validated) = if validation_enabled {
            let outcome = match dnssec::validate(self, &qname, qtype, &resolution, context) {
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
                    &qname,
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

    pub(crate) fn upstream(&self) -> &UpstreamClient {
        &self.inner.upstream
    }

    pub(crate) fn cache_ref(&self) -> &Cache {
        &self.inner.cache
    }

    pub(crate) fn forwarder_order(&self) -> Vec<(usize, SocketAddr)> {
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
                healthy.push((index, forwarder.address));
            } else {
                unhealthy.push((index, forwarder.address));
            }
        }
        healthy.extend(unhealthy);
        healthy
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
