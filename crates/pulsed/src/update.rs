//! Приём DNS UPDATE: политика, TSIG, replay и маршрутизация в движок.
//!
//! Порядок обработки (RFC 2136 §3.1–3.3):
//!
//! 1. Opcode `UPDATE` и валидный формат секций (`FORMERR`).
//! 2. Аутентификация до любых изменений: TSIG **или** SIG(0); неизвестный
//!    ключ → `BADKEY`/`NOTAUTH`, неверный MAC/подпись → `BADSIG`/`NOTAUTH`,
//!    replay/время → `BADTIME`/`NOTAUTH`, отсутствие аутентификации при
//!    `require_tsig` → `NOTAUTH`.
//! 3. Грубый ACL: `enabled`, source IP/CIDR, allowlist зон и ключей → `REFUSED`.
//! 4. Авторитетность: неизвестная зона/класс → `NOTAUTH`; secondary/forward
//!    или не-Serving → `REFUSED`.
//! 5. Per-name `update.policy` (первое совпадение, по умолчанию deny при
//!    непустом списке) → `REFUSED` до применения.
//! 6. Prerequisites и update-операции в одной транзакции writer'а:
//!    ошибка → ничего не закоммичено (`SERVFAIL` при сбое хранилища).
//! 7. Ответ с эхом Zone-секции и TSIG/SIG(0), если запрос был подписан.
//!
//! UPDATE принимается на UDP/TCP/DoT/DoH/DoQ/DNSCrypt: ограничение
//! `allow_from`/TSIG не зависит от транспорта, а размер ответа ограничен
//! буфером транспорта.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pulse_api::ZoneKind;
use pulse_dns::DnskeyData;
use pulse_dns::update::UpdateOp;
use pulse_dns::{
    DecodeLimits, EncodeOptions, Flags, Message, Name, Opcode, Rclass, Rcode, Rtype, UpdateRequest,
};
use pulse_dnssec::PrivateKey;
use pulse_dnssec::Sig0Error;
use pulse_dnssec::sig0::{find_sig0, sign_response, verify_request};
use pulse_transfer::{
    TsigEnvelope, TsigErrorCode, TsigKey, append_tsig, build_tsig_error_response, parse_tsig,
};

use crate::config::{
    Config, Sig0KeyConfig, UpdateAction, UpdateName, UpdatePrincipal, UpdateTypes, sig0_algorithm,
    validate_cidr,
};
use crate::logging;
use crate::store::SharedZoneAdmin;
use crate::tsigkeys::{TsigKeyStore, cidr_contains};

/// Счётчики UPDATE для `GET /metrics`.
#[derive(Debug, Default)]
pub(crate) struct UpdateMetrics {
    requests: AtomicU64,
    success: AtomicU64,
    changed: AtomicU64,
    refused: AtomicU64,
    notauth: AtomicU64,
    formerr: AtomicU64,
    other_errors: AtomicU64,
    tsig_failures: AtomicU64,
    sig0_failures: AtomicU64,
    policy_denied: AtomicU64,
    replay: AtomicU64,
}

impl UpdateMetrics {
    pub(crate) fn request(&self) {
        self.requests.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn success(&self, changed: bool) {
        self.success.fetch_add(1, Ordering::Relaxed);
        if changed {
            self.changed.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn rcode(&self, rcode: Rcode) {
        match rcode {
            Rcode::REFUSED => self.refused.fetch_add(1, Ordering::Relaxed),
            Rcode::NOTAUTH => self.notauth.fetch_add(1, Ordering::Relaxed),
            Rcode::FORMERR | Rcode::NOTZONE => self.formerr.fetch_add(1, Ordering::Relaxed),
            Rcode::NOERROR => 0,
            _ => self.other_errors.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub(crate) fn tsig_failure(&self) {
        self.tsig_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn sig0_failure(&self) {
        self.sig0_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn policy_denied(&self) {
        self.policy_denied.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn replay(&self) {
        self.replay.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> UpdateMetricsSnapshot {
        UpdateMetricsSnapshot {
            requests: self.requests.load(Ordering::Relaxed),
            success: self.success.load(Ordering::Relaxed),
            changed: self.changed.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            notauth: self.notauth.load(Ordering::Relaxed),
            formerr: self.formerr.load(Ordering::Relaxed),
            other_errors: self.other_errors.load(Ordering::Relaxed),
            tsig_failures: self.tsig_failures.load(Ordering::Relaxed),
            sig0_failures: self.sig0_failures.load(Ordering::Relaxed),
            policy_denied: self.policy_denied.load(Ordering::Relaxed),
            replay: self.replay.load(Ordering::Relaxed),
        }
    }
}

/// Снимок счётчиков UPDATE.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UpdateMetricsSnapshot {
    pub requests: u64,
    pub success: u64,
    pub changed: u64,
    pub refused: u64,
    pub notauth: u64,
    pub formerr: u64,
    pub other_errors: u64,
    pub tsig_failures: u64,
    pub sig0_failures: u64,
    pub policy_denied: u64,
    pub replay: u64,
}

/// IP/CIDR из `update.allow_from`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpNet {
    address: IpAddr,
    prefix: u8,
}

impl IpNet {
    fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (value, None),
        };
        let address: IpAddr = address.parse().ok()?;
        let prefix = match prefix {
            Some(prefix) => prefix.parse().ok()?,
            None => {
                if address.is_ipv4() {
                    32
                } else {
                    128
                }
            }
        };
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return None;
        }
        Some(Self { address, prefix })
    }

    fn contains(self, candidate: IpAddr) -> bool {
        match (self.address, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                (u32::from(network) & mask) == (u32::from(candidate) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                (u128::from(network) & mask) == (u128::from(candidate) & mask)
            }
            _ => false,
        }
    }
}

/// Bounded replay-кэш по (key, Time Signed, MAC).
///
/// Полный TSIG MAC уникален для сообщения; повтор того же MAC внутри окна
/// `Fudge` отвергается. В отличие от [`pulse_transfer::TsigReplayCache`],
/// здесь разрешены несколько обновлений в одну секунду: ключ включает MAC.
#[derive(Debug)]
struct ReplayCache {
    seen: HashSet<Vec<u8>>,
    order: VecDeque<Vec<u8>>,
    capacity: usize,
}

impl ReplayCache {
    fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    fn check_and_record(&mut self, key: &Name, time: u64, mac: &[u8]) -> bool {
        let mut id = Vec::with_capacity(key.as_wire().len() + 8 + mac.len());
        id.extend_from_slice(key.as_wire());
        id.extend_from_slice(&time.to_be_bytes());
        id.extend_from_slice(mac);
        if self.seen.contains(&id) {
            return false;
        }
        if self.order.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        self.order.push_back(id.clone());
        self.seen.insert(id);
        true
    }
}

/// Доверенный SIG(0)-ключ в рантайме.
struct Sig0KeyEntry {
    principal: Name,
    dnskey: DnskeyData,
    private: Option<Arc<PrivateKey>>,
}

/// Кто выполняет UPDATE (для политики).
#[derive(Debug, Clone)]
enum Principal {
    Tsig(Name),
    Sig0(Name),
    Subnet(IpAddr),
}

/// Скомпилированное правило per-name политики.
struct PolicyRule {
    principal: UpdatePrincipal,
    zone: NamePattern,
    name: NamePattern,
    types: Option<HashSet<Rtype>>,
    grant: bool,
}

#[derive(Debug, Clone)]
enum NamePattern {
    Any,
    Exact(Name),
    Suffix(Name),
    Wildcard(Name),
}

impl NamePattern {
    fn compile(value: &UpdateName, field: &str) -> Result<Self, String> {
        let parse = |text: &str| {
            Name::parse(text.trim())
                .map_err(|error| format!("update.policy: {field}: invalid name {text:?}: {error}"))
        };
        Ok(match value {
            UpdateName::Any => Self::Any,
            UpdateName::Exact(text) => Self::Exact(parse(text)?),
            UpdateName::Suffix(text) => Self::Suffix(parse(text)?),
            UpdateName::Wildcard(text) => {
                let wildcard = parse(text)?;
                if !wildcard.is_wildcard_owner() {
                    return Err(format!(
                        "update.policy: {field}: wildcard {text:?} must start with '*.' and have one '*' label"
                    ));
                }
                Self::Wildcard(wildcard.parent().ok_or_else(|| {
                    format!("update.policy: {field}: wildcard {text:?} has no parent")
                })?)
            }
        })
    }

    fn matches(&self, name: &Name) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => expected == name,
            Self::Suffix(suffix) => name.is_subdomain_of(suffix),
            Self::Wildcard(suffix) => {
                name.is_subdomain_of(suffix) && name.label_count() > suffix.label_count()
            }
        }
    }
}

/// Настройки и ключи UPDATE.
pub(crate) struct UpdateService {
    enabled: bool,
    require_auth: bool,
    allow_from: Vec<IpNet>,
    allow_zones: HashSet<Name>,
    allow_keys: Option<HashSet<Name>>,
    keys: Arc<TsigKeyStore>,
    sig0: HashMap<Name, Arc<Sig0KeyEntry>>,
    policy: Vec<PolicyRule>,
    sig0_max_validity: u32,
    sig0_inception_skew: u32,
    sig0_response_validity: u32,
    replay: Mutex<ReplayCache>,
    sig0_replay: Mutex<ReplayCache>,
    metrics: Arc<UpdateMetrics>,
}

impl UpdateService {
    /// Собирает сервис из конфигурации.
    ///
    /// # Errors
    ///
    /// Строка с причиной: некорректный ключ/секрет/CIDR/зона.
    pub(crate) fn new(config: &Config, keys: Arc<TsigKeyStore>) -> Result<Self, String> {
        let allow_from = config
            .update
            .allow_from
            .iter()
            .map(|cidr| {
                IpNet::parse(cidr)
                    .ok_or_else(|| format!("update.allow_from: invalid CIDR {cidr:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let allow_zones = config
            .update
            .allow_zones
            .iter()
            .map(|origin| {
                Name::parse(origin.trim()).map_err(|error| {
                    format!("update.allow_zones: invalid origin {origin:?}: {error}")
                })
            })
            .collect::<Result<HashSet<_>, _>>()?;
        let allow_keys = if config.update.tsig_keys.is_empty() {
            None
        } else {
            Some(
                config
                    .update
                    .tsig_keys
                    .iter()
                    .map(|name| {
                        Name::parse(name.trim()).map_err(|error| {
                            format!("update.tsig_keys: invalid name {name:?}: {error}")
                        })
                    })
                    .collect::<Result<HashSet<_>, _>>()?,
            )
        };
        // Дополнительная проверка: сервис создаётся и при выключенном UPDATE,
        // чтобы конфигурация с опечаткой падала на старте, а не при первом
        // запросе.
        for cidr in &config.update.allow_from {
            validate_cidr(cidr)
                .map_err(|reason| format!("update.allow_from: {cidr:?}: {reason}"))?;
        }
        let sig0 = build_sig0(&config.update.sig0_keys)?;
        let policy = build_policy(&config.update.policy)?;
        Ok(Self {
            enabled: config.update.enabled,
            require_auth: config.update.require_tsig,
            allow_from,
            allow_zones,
            allow_keys,
            keys,
            sig0,
            policy,
            sig0_max_validity: config.update.sig0_max_validity,
            sig0_inception_skew: config.update.sig0_inception_skew,
            sig0_response_validity: config.update.sig0_response_validity,
            replay: Mutex::new(ReplayCache::new(16_384)),
            sig0_replay: Mutex::new(ReplayCache::new(16_384)),
            metrics: Arc::new(UpdateMetrics::default()),
        })
    }

    pub(crate) fn metrics(&self) -> Arc<UpdateMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Обрабатывает пакет, если это UPDATE.
    ///
    /// `None` — пакет не является UPDATE (его обрабатывает QueryEngine или
    /// другой opcode). `Some(bytes)` — готовый ответ.
    pub(crate) fn handle(
        &self,
        admin: &SharedZoneAdmin,
        raw: &[u8],
        source: IpAddr,
        now: u64,
    ) -> Option<Vec<u8>> {
        if !is_update_packet(raw) {
            return None;
        }
        self.metrics.request();
        let Ok(message) = Message::decode(raw, &DecodeLimits::default()) else {
            // Заголовок читается (is_update_packet), но тело — нет.
            let id = message_id(raw);
            let mut response =
                Message::new(id, Flags::new().with_qr(true).with_opcode(Opcode::UPDATE));
            response.set_rcode(Rcode::FORMERR);
            self.metrics.rcode(Rcode::FORMERR);
            return encode_message(&response);
        };
        if message.flags().qr() {
            return None;
        }
        if !self.enabled {
            self.metrics.rcode(Rcode::REFUSED);
            logging::warn("update_refused", "UPDATE is disabled");
            return Some(self.respond_message(&message, None, raw, Rcode::REFUSED, now));
        }
        Some(self.process(admin, raw, &message, source, now))
    }

    #[allow(clippy::too_many_lines)]
    fn process(
        &self,
        admin: &SharedZoneAdmin,
        raw: &[u8],
        message: &Message,
        source: IpAddr,
        now: u64,
    ) -> Vec<u8> {
        // 1. Аутентификация до разбора и любых изменений: ответ на
        //    подписанный запрос тоже подписывается, а неизвестный ключ не
        //    раскрывает состояние зоны.
        let auth = match self.authenticate(raw, message, now) {
            Ok(auth) => auth,
            Err(response) => return response,
        };

        // 2. Формат секций.
        let request = match UpdateRequest::from_message(message) {
            Ok(request) => request,
            Err(error) => {
                let rcode = error.rcode();
                self.metrics.rcode(rcode);
                return self.respond_message(message, auth.as_ref(), raw, rcode, now);
            }
        };

        // 3. Грубый ACL.
        if !self.source_allowed(source) {
            logging::warn(
                "update_acl",
                &format!(
                    "UPDATE for {} from {source} denied by source ACL",
                    request.zone()
                ),
            );
            return self.refuse(&request, auth.as_ref(), raw, Rcode::REFUSED, now, "source");
        }
        if !self.allow_zones.is_empty() && !self.allow_zones.contains(request.zone()) {
            return self.refuse(&request, auth.as_ref(), raw, Rcode::REFUSED, now, "zone");
        }
        if let Some(allow) = &self.allow_keys
            && let Some(Authentication::Tsig { key, .. }) = &auth
            && !allow.contains(key.name())
        {
            return self.refuse(&request, auth.as_ref(), raw, Rcode::REFUSED, now, "key");
        }

        // 4. Авторитетность и вид зоны.
        let state = match admin.update_zone_state(request.zone()) {
            Ok(state) => state,
            Err(error) => {
                logging::error("update", &format!("zone {}: {error}", request.zone()));
                return self.respond(&request, auth.as_ref(), raw, Rcode::SERVFAIL, now);
            }
        };
        let Some(state) = state else {
            self.metrics.rcode(Rcode::NOTAUTH);
            return self.respond(&request, auth.as_ref(), raw, Rcode::NOTAUTH, now);
        };
        if request.zone_class() != Rclass::IN || state.class != request.zone_class() {
            self.metrics.rcode(Rcode::NOTAUTH);
            return self.respond(&request, auth.as_ref(), raw, Rcode::NOTAUTH, now);
        }
        if !matches!(state.kind, ZoneKind::Primary) || !state.serving {
            return self.refuse(
                &request,
                auth.as_ref(),
                raw,
                Rcode::REFUSED,
                now,
                "zone-kind",
            );
        }

        // 5. Per-name политика. Проверяется до применения: любая запрещённая
        //    операция отклоняет весь запрос, частичных коммитов нет.
        if !self.policy.is_empty() {
            let principal = principal_of(auth.as_ref(), source);
            if let Err((op, name, rr_type)) = self.check_policy(&request, &principal) {
                self.metrics.policy_denied();
                logging::warn(
                    "update_policy",
                    &format!(
                        "zone {}: {principal:?} denied {op} {name}/{}",
                        request.zone(),
                        rr_type.map_or_else(|| "ANY".to_owned(), |value| value.to_string())
                    ),
                );
                return self.refuse(&request, auth.as_ref(), raw, Rcode::REFUSED, now, "policy");
            }
        }

        // 6. Prerequisites + update в одной транзакции.
        match admin.apply_zone_update(&request) {
            Ok(outcome) => {
                self.metrics.success(outcome.changed);
                logging::info(
                    "update",
                    &format!(
                        "zone {} from {source}: NOERROR serial={} changed={}",
                        request.zone(),
                        outcome.serial,
                        outcome.changed
                    ),
                );
                self.respond(&request, auth.as_ref(), raw, Rcode::NOERROR, now)
            }
            Err(error) => {
                let rcode = error.rcode();
                self.metrics.rcode(rcode);
                if matches!(rcode, Rcode::SERVFAIL) {
                    logging::error("update", &format!("zone {}: {error}", request.zone()));
                } else {
                    logging::info(
                        "update",
                        &format!("zone {}: {rcode} ({error})", request.zone()),
                    );
                }
                self.respond(&request, auth.as_ref(), raw, rcode, now)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn authenticate(
        &self,
        raw: &[u8],
        message: &Message,
        now: u64,
    ) -> Result<Option<Authentication>, Vec<u8>> {
        let envelope = match parse_tsig(raw) {
            Ok(envelope) => envelope,
            Err(error) => {
                self.metrics.tsig_failure();
                logging::warn("update_tsig", &format!("malformed TSIG: {error}"));
                return Err(Self::tsig_error_response(
                    message,
                    None,
                    None,
                    TsigErrorCode::BADSIG,
                    now,
                ));
            }
        };
        if let Some(envelope) = envelope {
            // RFC 2931 §3.1: TSIG и SIG(0) одновременно недопустимы.
            if find_sig0(raw).ok().flatten().is_some() {
                self.metrics.sig0_failure();
                logging::warn("update_auth", "request contains both TSIG and SIG(0)");
                return Err(response_without_tsig(message, Rcode::NOTAUTH));
            }
            let Some(entry) = self.keys.get(envelope.record().key_name()) else {
                self.metrics.tsig_failure();
                logging::warn(
                    "update_tsig",
                    &format!("unknown TSIG key {}", envelope.record().key_name()),
                );
                return Err(Self::tsig_error_response(
                    message,
                    Some(&envelope),
                    None,
                    TsigErrorCode::BADKEY,
                    now,
                ));
            };
            let key = Arc::clone(&entry.key);
            let verified = match key.verify_request_envelope(&envelope, now) {
                Ok(verified) => verified,
                Err(error) => {
                    self.metrics.tsig_failure();
                    let code = error.error_code().unwrap_or(TsigErrorCode::BADSIG);
                    logging::warn("update_tsig", &format!("TSIG verification failed: {error}"));
                    return Err(Self::tsig_error_response(
                        message,
                        Some(&envelope),
                        Some(key.as_ref()),
                        code,
                        now,
                    ));
                }
            };
            let replay_ok = {
                let mut replay = self.replay.lock().unwrap_or_else(PoisonError::into_inner);
                replay.check_and_record(key.name(), verified.time_signed(), verified.mac())
            };
            if !replay_ok {
                self.metrics.replay();
                self.metrics.tsig_failure();
                logging::warn("update_tsig", &format!("replay of TSIG key {}", key.name()));
                return Err(Self::tsig_error_response(
                    message,
                    Some(&envelope),
                    Some(key.as_ref()),
                    TsigErrorCode::BADTIME,
                    now,
                ));
            }
            self.keys.mark_used(key.name(), now);
            return Ok(Some(Authentication::Tsig {
                key,
                request_mac: verified.mac().to_vec(),
            }));
        }

        let location = match find_sig0(raw) {
            Ok(location) => location,
            Err(error) => {
                self.metrics.sig0_failure();
                logging::warn("update_sig0", &format!("malformed SIG(0): {error}"));
                return Err(response_without_tsig(message, Rcode::NOTAUTH));
            }
        };
        let Some(location) = location else {
            if self.require_auth {
                self.metrics.sig0_failure();
                return Err(response_without_tsig(message, Rcode::NOTAUTH));
            }
            return Ok(None);
        };
        let Some(entry) = self.sig0.get(&location.signature.signer).cloned() else {
            self.metrics.sig0_failure();
            logging::warn(
                "update_sig0",
                &format!("unknown SIG(0) principal {}", location.signature.signer),
            );
            return Err(response_without_tsig(message, Rcode::NOTAUTH));
        };
        let now32 = u32::try_from(now).unwrap_or(u32::MAX);
        let signature = match verify_request(raw, &entry.dnskey, now32, self.sig0_max_validity) {
            Ok(signature) => signature,
            Err(error) => {
                self.metrics.sig0_failure();
                let reason = match error {
                    Sig0Error::TimeInvalid | Sig0Error::ValidityTooWide => "time",
                    Sig0Error::KeyMismatch => "key",
                    Sig0Error::BadSignature => "signature",
                    _ => "malformed",
                };
                logging::warn(
                    "update_sig0",
                    &format!("SIG(0) rejected ({reason}) for {}", entry.principal),
                );
                return Err(response_without_tsig(message, Rcode::NOTAUTH));
            }
        };
        let replay_ok = {
            let mut replay = self
                .sig0_replay
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            replay.check_and_record(
                &signature.signer,
                u64::from(signature.inception),
                &signature.signature,
            )
        };
        if !replay_ok {
            self.metrics.replay();
            self.metrics.sig0_failure();
            logging::warn(
                "update_sig0",
                &format!("replay of SIG(0) principal {}", signature.signer),
            );
            return Err(response_without_tsig(message, Rcode::NOTAUTH));
        }
        Ok(Some(Authentication::Sig0 {
            principal: signature.signer,
        }))
    }

    fn source_allowed(&self, source: IpAddr) -> bool {
        self.allow_from.is_empty()
            || self
                .allow_from
                .iter()
                .any(|network| network.contains(source))
    }

    fn check_policy(
        &self,
        request: &UpdateRequest,
        principal: &Principal,
    ) -> Result<(), (&'static str, Name, Option<Rtype>)> {
        for op in request.updates() {
            let (action, name, rr_type) = match op {
                UpdateOp::Add { name, rr_type, .. } => ("add", name, Some(*rr_type)),
                UpdateOp::DeleteRrset { name, rr_type } => ("delete-rrset", name, Some(*rr_type)),
                UpdateOp::DeleteRecord { name, rr_type, .. } => {
                    ("delete-record", name, Some(*rr_type))
                }
                UpdateOp::DeleteName { name } => ("delete-name", name, None),
            };
            let allowed = self
                .policy
                .iter()
                .find(|rule| rule.matches(principal, request.zone(), name, rr_type))
                .is_some_and(|rule| rule.grant);
            if !allowed {
                return Err((action, name.clone(), rr_type));
            }
        }
        Ok(())
    }

    fn refuse(
        &self,
        request: &UpdateRequest,
        auth: Option<&Authentication>,
        raw: &[u8],
        rcode: Rcode,
        now: u64,
        reason: &str,
    ) -> Vec<u8> {
        self.metrics.rcode(rcode);
        logging::warn(
            "update_refused",
            &format!("zone {}: {reason}", request.zone()),
        );
        self.respond(request, auth, raw, rcode, now)
    }

    fn respond_message(
        &self,
        message: &Message,
        auth: Option<&Authentication>,
        raw: &[u8],
        rcode: Rcode,
        now: u64,
    ) -> Vec<u8> {
        let response = pulse_dns::update::error_response(message, rcode);
        self.encode_signed(&response, auth, raw, now)
            .unwrap_or_else(|| {
                logging::error("update", "cannot encode UPDATE response");
                Vec::new()
            })
    }

    fn respond(
        &self,
        request: &UpdateRequest,
        auth: Option<&Authentication>,
        raw: &[u8],
        rcode: Rcode,
        now: u64,
    ) -> Vec<u8> {
        let message = request.response(rcode);
        self.encode_signed(&message, auth, raw, now)
            .unwrap_or_else(|| {
                logging::error("update", "cannot encode UPDATE response");
                Vec::new()
            })
    }

    fn encode_signed(
        &self,
        message: &Message,
        auth: Option<&Authentication>,
        raw: &[u8],
        now: u64,
    ) -> Option<Vec<u8>> {
        let base = message.encode(&EncodeOptions::compressed()).ok()?;
        match auth {
            None => Some(base),
            Some(Authentication::Tsig { key, request_mac }) => {
                let record = key
                    .sign_response(&base, request_mac, message.id(), now)
                    .ok()?;
                append_tsig(base, &record).ok()
            }
            Some(Authentication::Sig0 { principal }) => {
                let Some(entry) = self.sig0.get(principal) else {
                    logging::error("update_sig0", "SIG(0) key disappeared during request");
                    return Some(base);
                };
                let Some(private) = &entry.private else {
                    return Some(base);
                };
                let now32 = u32::try_from(now).unwrap_or(u32::MAX);
                match sign_response(
                    raw,
                    &base,
                    &entry.principal,
                    private,
                    &entry.dnskey,
                    now32,
                    self.sig0_response_validity,
                    self.sig0_inception_skew,
                ) {
                    Ok(signed) => Some(signed),
                    Err(error) => {
                        logging::error("update_sig0", &format!("cannot sign response: {error}"));
                        Some(base)
                    }
                }
            }
        }
    }

    fn tsig_error_response(
        message: &Message,
        envelope: Option<&TsigEnvelope>,
        key: Option<&TsigKey>,
        code: TsigErrorCode,
        now: u64,
    ) -> Vec<u8> {
        let request_mac = envelope.map(|envelope| envelope.record().mac());
        build_tsig_error_response(
            message,
            envelope.map(TsigEnvelope::record),
            key,
            request_mac,
            code,
            now,
        )
        .unwrap_or_else(|error| {
            logging::error("update_tsig", &format!("cannot encode TSIG error: {error}"));
            response_without_tsig(message, Rcode::NOTAUTH)
        })
    }
}

/// Результат успешной аутентификации.
enum Authentication {
    Tsig {
        key: Arc<TsigKey>,
        request_mac: Vec<u8>,
    },
    Sig0 {
        principal: Name,
    },
}

impl PolicyRule {
    fn matches(
        &self,
        principal: &Principal,
        zone: &Name,
        name: &Name,
        rr_type: Option<Rtype>,
    ) -> bool {
        if !self.zone.matches(zone) || !self.name.matches(name) {
            return false;
        }
        match (&self.types, rr_type) {
            (None, _) => {}
            (Some(types), Some(rr_type)) if types.contains(&rr_type) => {}
            _ => return false,
        }
        match &self.principal {
            UpdatePrincipal::Any => true,
            UpdatePrincipal::TsigKey(expected) => match principal {
                Principal::Tsig(actual) => actual.to_string() == *expected,
                _ => false,
            },
            UpdatePrincipal::Sig0Key(expected) => match principal {
                Principal::Sig0(actual) => actual.to_string() == *expected,
                _ => false,
            },
            UpdatePrincipal::Subnet(cidr) => match principal {
                Principal::Subnet(address) => cidr_contains(cidr, *address).unwrap_or(false),
                _ => false,
            },
        }
    }
}

fn principal_of(auth: Option<&Authentication>, source: IpAddr) -> Principal {
    match auth {
        Some(Authentication::Tsig { key, .. }) => Principal::Tsig(key.name().clone()),
        Some(Authentication::Sig0 { principal }) => Principal::Sig0(principal.clone()),
        None => Principal::Subnet(source),
    }
}

fn build_sig0(keys: &[Sig0KeyConfig]) -> Result<HashMap<Name, Arc<Sig0KeyEntry>>, String> {
    let mut map = HashMap::with_capacity(keys.len());
    for config in keys {
        let principal = Name::parse(config.name.trim())
            .map_err(|error| format!("SIG(0) principal {:?}: {error}", config.name))?;
        let algorithm = sig0_algorithm(&config.algorithm).map_err(|error| error.to_string())?;
        let public_key = STANDARD
            .decode(config.public_key.trim())
            .map_err(|error| format!("SIG(0) key {principal}: invalid base64: {error}"))?;
        let dnskey = DnskeyData::new(256, 3, algorithm.as_u8(), public_key)
            .map_err(|error| format!("SIG(0) key {principal}: {error}"))?;
        let tag = pulse_dnssec::key_tag(&dnskey);
        if let Some(expected) = config.key_tag
            && expected != tag
        {
            return Err(format!(
                "SIG(0) key {principal}: key_tag {expected} does not match DNSKEY tag {tag}"
            ));
        }
        let private = match &config.private_key {
            Some(path) => {
                let key = pulse_dnssec::read_private_key_file(path)
                    .map_err(|error| format!("SIG(0) key {principal}: {error}"))?;
                if key.algorithm().as_u8() != dnskey.algorithm() {
                    return Err(format!(
                        "SIG(0) key {principal}: private key algorithm does not match public key"
                    ));
                }
                let private_tag = key
                    .key_tag(dnskey.flags())
                    .map_err(|error| format!("SIG(0) key {principal}: {error}"))?;
                if private_tag != tag {
                    return Err(format!(
                        "SIG(0) key {principal}: private key tag {private_tag} does not match DNSKEY tag {tag}"
                    ));
                }
                Some(Arc::new(key))
            }
            None => None,
        };
        map.insert(
            principal.clone(),
            Arc::new(Sig0KeyEntry {
                principal,
                dnskey,
                private,
            }),
        );
    }
    Ok(map)
}

fn build_policy(rules: &[crate::config::UpdatePolicyRule]) -> Result<Vec<PolicyRule>, String> {
    let mut compiled = Vec::with_capacity(rules.len());
    for (index, rule) in rules.iter().enumerate() {
        let zone = NamePattern::compile(&rule.zone, &format!("policy[{index}].zone"))?;
        let name = NamePattern::compile(&rule.name, &format!("policy[{index}].name"))?;
        let types = match &rule.types {
            UpdateTypes::Any => None,
            UpdateTypes::List(list) => Some(
                list.iter()
                    .map(|value| {
                        crate::config::parse_update_rtype(value)
                            .ok_or_else(|| format!("policy[{index}].types: unknown type {value:?}"))
                    })
                    .collect::<Result<HashSet<_>, _>>()?,
            ),
        };
        compiled.push(PolicyRule {
            principal: rule.principal.clone(),
            zone,
            name,
            types,
            grant: matches!(rule.action, UpdateAction::Grant),
        });
    }
    Ok(compiled)
}

fn response_without_tsig(message: &Message, rcode: Rcode) -> Vec<u8> {
    let response = pulse_dns::update::error_response(message, rcode);
    encode_message(&response).unwrap_or_default()
}

fn encode_message(message: &Message) -> Option<Vec<u8>> {
    message.encode(&EncodeOptions::compressed()).ok()
}

/// `true`, если заголовок сообщает opcode UPDATE (без полного декодирования).
pub(crate) fn is_update_packet(raw: &[u8]) -> bool {
    let Some(flags) = raw.get(2..4) else {
        return false;
    };
    let Ok(bytes) = <[u8; 2]>::try_from(flags) else {
        return false;
    };
    let flags = Flags::from_bits(u16::from_be_bytes(bytes));
    !flags.qr() && flags.opcode() == Opcode::UPDATE
}

fn message_id(raw: &[u8]) -> u16 {
    raw.get(..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map_or(0, u16::from_be_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matching() {
        let v4 = IpNet::parse("192.0.2.0/24").unwrap();
        assert!(v4.contains("192.0.2.7".parse().unwrap()));
        assert!(!v4.contains("192.0.3.7".parse().unwrap()));
        let v6 = IpNet::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert!(
            IpNet::parse("127.0.0.1")
                .unwrap()
                .contains("127.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn replay_cache_distinguishes_macs_in_same_second() {
        let name = Name::parse("key.example.com").unwrap();
        let mut cache = ReplayCache::new(2);
        assert!(cache.check_and_record(&name, 100, b"mac-1"));
        assert!(cache.check_and_record(&name, 100, b"mac-2"));
        assert!(!cache.check_and_record(&name, 100, b"mac-1"));
        assert!(cache.check_and_record(&name, 100, b"mac-3"));
        // mac-1 вытеснен, mac-2 ещё в кэше.
        assert!(!cache.check_and_record(&name, 100, b"mac-2"));
        assert!(cache.check_and_record(&name, 100, b"mac-1"));
    }

    #[test]
    fn update_opcode_detection() {
        let mut raw = vec![0_u8; 12];
        raw[2] = 5 << 3;
        assert!(is_update_packet(&raw));
        raw[2] |= 0x80;
        assert!(!is_update_packet(&raw));
        assert!(!is_update_packet(&[0, 1]));
    }
}
