//! Приём DNS UPDATE: политика, TSIG, replay и маршрутизация в движок.
//!
//! Порядок обработки (RFC 2136 §3.1–3.3):
//!
//! 1. Opcode `UPDATE` и валидный формат секций (`FORMERR`).
//! 2. TSIG до любых изменений: неизвестный ключ → `BADKEY`/`NOTAUTH`,
//!    неверный MAC → `BADSIG`/`NOTAUTH`, replay/время → `BADTIME`/`NOTAUTH`,
//!    отсутствие TSIG при `require_tsig` → `NOTAUTH`.
//! 3. Политика: `enabled`, source IP/CIDR, allowlist зон и ключей → `REFUSED`.
//! 4. Авторитетность: неизвестная зона/класс → `NOTAUTH`; secondary/forward
//!    или не-Serving → `REFUSED`.
//! 5. Prerequisites и update-операции в одной транзакции writer'а:
//!    ошибка → ничего не закоммичено (`SERVFAIL` при сбое хранилища).
//! 6. Ответ с эхом Zone-секции и TSIG, если запрос был подписан.
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
use pulse_dns::{
    DecodeLimits, EncodeOptions, Flags, Message, Name, Opcode, Rclass, Rcode, UpdateRequest,
};
use pulse_transfer::{
    TsigEnvelope, TsigErrorCode, TsigKey, append_tsig, build_tsig_error_response, parse_tsig,
};

use crate::config::{Config, TsigKeyConfig, parse_tsig_algorithm, validate_cidr};
use crate::logging;
use crate::store::SharedZoneAdmin;

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

/// Настройки и ключи UPDATE.
pub(crate) struct UpdateService {
    enabled: bool,
    require_tsig: bool,
    allow_from: Vec<IpNet>,
    allow_zones: HashSet<Name>,
    allow_keys: Option<HashSet<Name>>,
    keys: HashMap<Name, Arc<TsigKey>>,
    replay: Mutex<ReplayCache>,
    metrics: Arc<UpdateMetrics>,
}

impl UpdateService {
    /// Собирает сервис из конфигурации.
    ///
    /// # Errors
    ///
    /// Строка с причиной: некорректный ключ/секрет/CIDR/зона.
    pub(crate) fn new(config: &Config) -> Result<Self, String> {
        let keys = build_keys(&config.tsig_keys)?;
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
        Ok(Self {
            enabled: config.update.enabled,
            require_tsig: config.update.require_tsig,
            allow_from,
            allow_zones,
            allow_keys,
            keys,
            replay: Mutex::new(ReplayCache::new(16_384)),
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
            return Some(Self::respond_message(&message, None, Rcode::REFUSED, now));
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
        // 1. TSIG до разбора и любых изменений: ответ на подписанный запрос
        //    тоже подписывается, а неизвестный ключ не раскрывает состояние зоны.
        let signed = match self.authenticate(raw, message, now) {
            Ok(signed) => signed,
            Err(response) => return response,
        };

        // 2. Формат секций.
        let request = match UpdateRequest::from_message(message) {
            Ok(request) => request,
            Err(error) => {
                let rcode = error.rcode();
                self.metrics.rcode(rcode);
                return Self::respond_message(message, signed.as_ref(), rcode, now);
            }
        };

        // 3. Политика.
        if !self.source_allowed(source) {
            logging::warn(
                "update_acl",
                &format!(
                    "UPDATE for {} from {source} denied by source ACL",
                    request.zone()
                ),
            );
            return self.refuse(&request, signed.as_ref(), Rcode::REFUSED, now, "source");
        }
        if !self.allow_zones.is_empty() && !self.allow_zones.contains(request.zone()) {
            return self.refuse(&request, signed.as_ref(), Rcode::REFUSED, now, "zone");
        }
        if let Some(signed) = &signed
            && let Some(allow) = &self.allow_keys
            && !allow.contains(signed.key.name())
        {
            return self.refuse(&request, Some(signed), Rcode::REFUSED, now, "key");
        }

        // 4. Авторитетность и вид зоны.
        let state = match admin.update_zone_state(request.zone()) {
            Ok(state) => state,
            Err(error) => {
                logging::error("update", &format!("zone {}: {error}", request.zone()));
                return Self::respond(&request, signed.as_ref(), Rcode::SERVFAIL, now);
            }
        };
        let Some(state) = state else {
            self.metrics.rcode(Rcode::NOTAUTH);
            return Self::respond(&request, signed.as_ref(), Rcode::NOTAUTH, now);
        };
        if request.zone_class() != Rclass::IN || state.class != request.zone_class() {
            self.metrics.rcode(Rcode::NOTAUTH);
            return Self::respond(&request, signed.as_ref(), Rcode::NOTAUTH, now);
        }
        if !matches!(state.kind, ZoneKind::Primary) || !state.serving {
            return self.refuse(&request, signed.as_ref(), Rcode::REFUSED, now, "zone-kind");
        }

        // 5. Prerequisites + update в одной транзакции.
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
                Self::respond(&request, signed.as_ref(), Rcode::NOERROR, now)
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
                Self::respond(&request, signed.as_ref(), rcode, now)
            }
        }
    }

    fn authenticate(
        &self,
        raw: &[u8],
        message: &Message,
        now: u64,
    ) -> Result<Option<VerifiedUpdate>, Vec<u8>> {
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
        let Some(envelope) = envelope else {
            if self.require_tsig {
                self.metrics.tsig_failure();
                return Err(response_without_tsig(message, Rcode::NOTAUTH));
            }
            return Ok(None);
        };
        let Some(key) = self.keys.get(envelope.record().key_name()).cloned() else {
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
        Ok(Some(VerifiedUpdate {
            key,
            request_mac: verified.mac().to_vec(),
        }))
    }

    fn source_allowed(&self, source: IpAddr) -> bool {
        self.allow_from.is_empty()
            || self
                .allow_from
                .iter()
                .any(|network| network.contains(source))
    }

    fn refuse(
        &self,
        request: &UpdateRequest,
        signed: Option<&VerifiedUpdate>,
        rcode: Rcode,
        now: u64,
        reason: &str,
    ) -> Vec<u8> {
        self.metrics.rcode(rcode);
        logging::warn(
            "update_refused",
            &format!("zone {}: {reason}", request.zone()),
        );
        Self::respond(request, signed, rcode, now)
    }

    fn respond_message(
        message: &Message,
        signed: Option<&VerifiedUpdate>,
        rcode: Rcode,
        now: u64,
    ) -> Vec<u8> {
        let response = pulse_dns::update::error_response(message, rcode);
        encode_signed(&response, signed, now).unwrap_or_else(|| {
            logging::error("update", "cannot encode UPDATE response");
            Vec::new()
        })
    }

    fn respond(
        request: &UpdateRequest,
        signed: Option<&VerifiedUpdate>,
        rcode: Rcode,
        now: u64,
    ) -> Vec<u8> {
        let message = request.response(rcode);
        encode_signed(&message, signed, now).unwrap_or_else(|| {
            logging::error("update", "cannot encode UPDATE response");
            Vec::new()
        })
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

struct VerifiedUpdate {
    key: Arc<TsigKey>,
    request_mac: Vec<u8>,
}

fn encode_signed(message: &Message, signed: Option<&VerifiedUpdate>, now: u64) -> Option<Vec<u8>> {
    let base = message.encode(&EncodeOptions::compressed()).ok()?;
    let Some(signed) = signed else {
        return Some(base);
    };
    let record = signed
        .key
        .sign_response(&base, &signed.request_mac, message.id(), now)
        .ok()?;
    append_tsig(base, &record).ok()
}

fn response_without_tsig(message: &Message, rcode: Rcode) -> Vec<u8> {
    let response = pulse_dns::update::error_response(message, rcode);
    encode_message(&response).unwrap_or_default()
}

fn encode_message(message: &Message) -> Option<Vec<u8>> {
    message.encode(&EncodeOptions::compressed()).ok()
}

fn build_keys(keys: &[TsigKeyConfig]) -> Result<HashMap<Name, Arc<TsigKey>>, String> {
    let mut map = HashMap::with_capacity(keys.len());
    for config in keys {
        let name = Name::parse(config.name.trim())
            .map_err(|error| format!("invalid TSIG key name {:?}: {error}", config.name))?;
        let algorithm = parse_tsig_algorithm(&config.algorithm)
            .map_err(|error| format!("TSIG key {name}: {error}"))?;
        let secret = STANDARD
            .decode(config.secret.trim())
            .map_err(|error| format!("TSIG key {name}: invalid base64: {error}"))?;
        let key = TsigKey::new(name.clone(), algorithm, secret)
            .map_err(|source| format!("TSIG key {name}: {source}"))?;
        map.insert(name, Arc::new(key));
    }
    Ok(map)
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
