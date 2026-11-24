//! Response Rate Limiting (RRL) для UDP-ответов резолвера.
//!
//! RRL ограничивает не запросы, а **ответы**, сгруппированные по классу,
//! источнику и имени. Это защищает от reflection/amplification-флуда
//! (NXDOMAIN и referral) и от потоков уникальных имён: бакет — это
//! `(source IP, class, hash(qname))`, причём для NXDOMAIN/referral
//! хешируется родительское имя, чтобы флуд по случайным поддоменам одной
//! зоны попадал в один бакет.
//!
//! Классы ответов:
//!
//! - `noerror` — NOERROR с данными или пустой NODATA-ответ (SOA в authority);
//! - `nxdomain` — NXDOMAIN;
//! - `referral` — NOERROR без ответов, NS в authority и без SOA;
//! - `error` — SERVFAIL/REFUSED/NOTIMP и прочие коды.
//!
//! У каждого класса свои `qps`/`burst`. При превышении действует политика
//! [`RateLimitAction`]: `drop` (молча), `truncate` (пустой TC-ответ) или
//! `refused`. `slip` задаёт, какая доля ограниченных ответов всё-таки
//! отправляется: `0` — все отбрасываются, `1` — все отправляются, `N` —
//! каждый N-й. Таблица бакетов ограничена `max_entries` и шардирована;
//! переполнение вытесняет произвольную запись, а не растёт без границ.
//!
//! RRL применяется только к UDP: TCP-клиент не может быть использован для
//! amplification с подменой источника.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use pulse_dns::{Message, Name, Rcode, Rtype};

use crate::config::RateLimitAction;
use crate::error::ConfigError;

/// Число шардов таблицы бакетов.
pub const RRL_SHARDS: usize = 16;

/// Максимум записей таблицы.
pub const MAX_RRL_ENTRIES: usize = 1_000_000;

/// Через сколько простоя бакет считается устаревшим.
const STALE_AFTER: Duration = Duration::from_secs(300);

/// Класс ответа для RRL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseClass {
    /// NOERROR (данные или NODATA).
    NoError,
    /// NXDOMAIN.
    NxDomain,
    /// Делегирование (NOERROR, NS без SOA).
    Referral,
    /// SERVFAIL, REFUSED, NOTIMP и прочие ошибки.
    Error,
}

impl ResponseClass {
    /// Все классы в порядке индексов счётчиков.
    pub const ALL: [Self; 4] = [Self::NoError, Self::NxDomain, Self::Referral, Self::Error];

    /// Метка класса для метрик.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoError => "noerror",
            Self::NxDomain => "nxdomain",
            Self::Referral => "referral",
            Self::Error => "error",
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::NoError => 0,
            Self::NxDomain => 1,
            Self::Referral => 2,
            Self::Error => 3,
        }
    }

    /// Классифицирует ответ по коду и секциям.
    #[must_use]
    pub fn classify(response: &Message) -> Self {
        match response.rcode() {
            Rcode::NOERROR => {
                let authority = response.authority();
                let has_soa = authority
                    .iter()
                    .any(|record| record.rr_type() == Rtype::SOA);
                let has_ns = authority.iter().any(|record| record.rr_type() == Rtype::NS);
                if response.answers().is_empty() && has_ns && !has_soa {
                    Self::Referral
                } else {
                    Self::NoError
                }
            }
            Rcode::NXDOMAIN => Self::NxDomain,
            _ => Self::Error,
        }
    }

    const fn groups_by_parent(self) -> bool {
        matches!(self, Self::NxDomain | Self::Referral)
    }
}

/// Лимит класса: средняя скорость и burst.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RrlRate {
    /// Пополнение токенов в секунду.
    pub qps: f64,
    /// Максимальный запас токенов.
    pub burst: u32,
}

impl RrlRate {
    /// Создаёт лимит.
    #[must_use]
    pub const fn new(qps: f64, burst: u32) -> Self {
        Self { qps, burst }
    }

    fn validate(self, class: ResponseClass) -> Result<(), ConfigError> {
        if !self.qps.is_finite() || self.qps <= 0.0 {
            return Err(ConfigError::invalid(format!(
                "rrl {} qps must be finite and positive",
                class.as_str()
            )));
        }
        if self.burst == 0 {
            return Err(ConfigError::invalid(format!(
                "rrl {} burst must be positive",
                class.as_str()
            )));
        }
        Ok(())
    }
}

/// Конфигурация RRL.
#[derive(Debug, Clone, PartialEq)]
pub struct RrlConfig {
    /// `1/N` ограниченных ответов отправляется (`0` — ни одного).
    pub slip: u32,
    /// Максимум записей таблицы.
    pub max_entries: usize,
    /// Действие для отправляемых ограниченных ответов.
    pub action: RateLimitAction,
    /// Лимиты по классам: `NoError`, `NxDomain`, `Referral`, `Error`.
    pub rates: [RrlRate; 4],
    /// Агрегированный лимит на источник (все имена и классы вместе).
    pub source: RrlRate,
}

impl Default for RrlConfig {
    fn default() -> Self {
        Self {
            slip: 2,
            max_entries: 20_000,
            action: RateLimitAction::Truncate,
            rates: [
                RrlRate::new(20.0, 100),
                RrlRate::new(5.0, 20),
                RrlRate::new(10.0, 40),
                RrlRate::new(5.0, 20),
            ],
            source: RrlRate::new(50.0, 200),
        }
    }
}

impl RrlConfig {
    /// Проверяет параметры RRL.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] при некорректных `slip`, `max_entries` или
    /// лимитах классов.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.slip > 1_000 {
            return Err(ConfigError::invalid("rrl slip must be in 0..=1000"));
        }
        if self.max_entries == 0 || self.max_entries > MAX_RRL_ENTRIES {
            return Err(ConfigError::invalid(format!(
                "rrl max_entries must be in 1..={MAX_RRL_ENTRIES}"
            )));
        }
        for (class, rate) in ResponseClass::ALL.iter().zip(self.rates) {
            rate.validate(*class)?;
        }
        if !self.source.qps.is_finite() || self.source.qps <= 0.0 {
            return Err(ConfigError::invalid(
                "rrl source qps must be finite and positive",
            ));
        }
        if self.source.burst == 0 {
            return Err(ConfigError::invalid("rrl source burst must be positive"));
        }
        Ok(())
    }
}

/// Решение RRL по конкретному ответу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrlOutcome {
    /// Ответ не ограничен.
    Allow,
    /// Ограниченный ответ нужно отправить с заданным действием.
    Respond(RateLimitAction),
    /// Ограниченный ответ нужно молча отбросить.
    Drop,
}

/// Счётчики одного класса.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RrlClassStats {
    /// Ответов ограничено.
    pub limited: u64,
    /// Ограниченных ответов отправлено (slip).
    pub slipped: u64,
    /// Ограниченных ответов отброшено.
    pub dropped: u64,
}

/// Снимок статистики RRL.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RrlSnapshot {
    /// Класс NOERROR.
    pub noerror: RrlClassStats,
    /// Класс NXDOMAIN.
    pub nxdomain: RrlClassStats,
    /// Класс referral.
    pub referral: RrlClassStats,
    /// Класс error.
    pub error: RrlClassStats,
    /// Занятых записей таблицы.
    pub entries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    source: IpAddr,
    class: u8,
    scope: u8,
    name: u64,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
    limited: u64,
}

struct ClassCounters {
    limited: AtomicU64,
    slipped: AtomicU64,
    dropped: AtomicU64,
}

impl ClassCounters {
    fn new() -> Self {
        Self {
            limited: AtomicU64::new(0),
            slipped: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> RrlClassStats {
        RrlClassStats {
            limited: self.limited.load(Ordering::Relaxed),
            slipped: self.slipped.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
        }
    }
}

/// Ограничитель ответов.
pub struct Rrl {
    config: RwLock<Arc<RrlConfig>>,
    shards: Vec<Mutex<HashMap<Key, Bucket>>>,
    source_shards: Vec<Mutex<HashMap<Key, Bucket>>>,
    counters: [ClassCounters; 4],
}

impl std::fmt::Debug for Rrl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Rrl")
            .field("config", &self.config_snapshot())
            .finish_non_exhaustive()
    }
}

impl Rrl {
    /// Создаёт RRL.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] при некорректной конфигурации.
    pub fn new(config: RrlConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        let mut shards = Vec::with_capacity(RRL_SHARDS);
        let mut source_shards = Vec::with_capacity(RRL_SHARDS);
        for _ in 0..RRL_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
            source_shards.push(Mutex::new(HashMap::new()));
        }
        Ok(Self {
            config: RwLock::new(Arc::new(config)),
            shards,
            source_shards,
            counters: std::array::from_fn(|_| ClassCounters::new()),
        })
    }

    /// Текущая конфигурация.
    #[must_use]
    pub fn config(&self) -> Arc<RrlConfig> {
        self.config_snapshot()
    }

    /// Атомарно применяет новые лимиты/политику.
    ///
    /// Валидация выполняется до подмены; при ошибке прежняя конфигурация
    /// остаётся в силе. Таблица бакетов не очищается.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] при некорректных параметрах.
    pub fn update_config(&self, config: RrlConfig) -> Result<(), ConfigError> {
        config.validate()?;
        let mut guard = self.config.write().unwrap_or_else(PoisonError::into_inner);
        *guard = Arc::new(config);
        Ok(())
    }

    fn config_snapshot(&self) -> Arc<RrlConfig> {
        let guard = self.config.read().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&guard)
    }

    /// Проверяет ответ и при необходимости ограничивает его.
    #[must_use]
    pub fn check(&self, source: IpAddr, response: &Message) -> RrlOutcome {
        self.check_at(source, response, Instant::now())
    }

    /// `check` с явным временем (для тестов).
    #[must_use]
    pub fn check_at(&self, source: IpAddr, response: &Message, now: Instant) -> RrlOutcome {
        let config = self.config_snapshot();
        let per_shard = per_shard(config.max_entries);
        let Some(question) = response.questions().first() else {
            return RrlOutcome::Allow;
        };
        let class = ResponseClass::classify(response);
        let index = class.index();
        let rate = config.rates[index];
        let source = normalize_ip(source);
        let key = Key {
            source,
            class: u8::try_from(index).unwrap_or(u8::MAX),
            scope: 0,
            name: hash_name(question.qname(), class),
        };
        let source_key = Key {
            source,
            class: u8::try_from(index).unwrap_or(u8::MAX),
            scope: 1,
            name: 0,
        };
        let Some(shard_mutex) = self.shards.get(shard_index(key, RRL_SHARDS)) else {
            return RrlOutcome::Allow;
        };
        let name_limited = {
            let mut shard = shard_mutex.lock().unwrap_or_else(PoisonError::into_inner);
            consume(&mut shard, key, rate, per_shard, now)
        };
        let Some(source_mutex) = self.source_shards.get(shard_index(source_key, RRL_SHARDS)) else {
            return RrlOutcome::Allow;
        };
        let source_limited = {
            let mut shard = source_mutex.lock().unwrap_or_else(PoisonError::into_inner);
            consume(&mut shard, source_key, config.source, per_shard, now)
        };
        let limited = match (name_limited, source_limited) {
            (Some(name), Some(source)) => name.max(source),
            (Some(name), None) => name,
            (None, Some(source)) => source,
            (None, None) => return RrlOutcome::Allow,
        };
        self.counters[index].limited.fetch_add(1, Ordering::Relaxed);
        let slip = config.slip;
        let respond =
            slip > 0 && limited % u64::from(slip) == 0 && config.action != RateLimitAction::Drop;
        if respond {
            self.counters[index].slipped.fetch_add(1, Ordering::Relaxed);
            RrlOutcome::Respond(config.action)
        } else {
            self.counters[index].dropped.fetch_add(1, Ordering::Relaxed);
            RrlOutcome::Drop
        }
    }

    /// Снимок статистики.
    #[must_use]
    pub fn snapshot(&self) -> RrlSnapshot {
        let counters = [
            self.counters[0].snapshot(),
            self.counters[1].snapshot(),
            self.counters[2].snapshot(),
            self.counters[3].snapshot(),
        ];
        let entries = self
            .shards
            .iter()
            .chain(self.source_shards.iter())
            .map(|shard| shard.lock().unwrap_or_else(PoisonError::into_inner).len())
            .sum();
        RrlSnapshot {
            noerror: counters[0],
            nxdomain: counters[1],
            referral: counters[2],
            error: counters[3],
            entries,
        }
    }
}

impl RrlSnapshot {
    /// Счётчики класса.
    #[must_use]
    pub const fn class(&self, class: ResponseClass) -> RrlClassStats {
        match class {
            ResponseClass::NoError => self.noerror,
            ResponseClass::NxDomain => self.nxdomain,
            ResponseClass::Referral => self.referral,
            ResponseClass::Error => self.error,
        }
    }
}

fn per_shard(max_entries: usize) -> usize {
    max_entries.div_ceil(RRL_SHARDS * 2).max(1)
}

/// Списывает токен из бакета. Возвращает `None`, если ответ разрешён, иначе —
/// номер ограниченного ответа в этом бакете (для slip).
fn consume(
    shard: &mut HashMap<Key, Bucket>,
    key: Key,
    rate: RrlRate,
    per_shard: usize,
    now: Instant,
) -> Option<u64> {
    if !shard.contains_key(&key) {
        if shard.len() >= per_shard {
            shard.retain(|_, bucket| now.saturating_duration_since(bucket.last) < STALE_AFTER);
            while shard.len() >= per_shard {
                let Some(victim) = shard.keys().next().copied() else {
                    break;
                };
                shard.remove(&victim);
            }
        }
        shard.insert(
            key,
            Bucket {
                tokens: f64::from(rate.burst),
                last: now,
                limited: 0,
            },
        );
    }
    let bucket = shard.get_mut(&key)?;
    let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * rate.qps).min(f64::from(rate.burst));
    bucket.last = now;
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        return None;
    }
    bucket.limited = bucket.limited.saturating_add(1);
    Some(bucket.limited)
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        IpAddr::V4(_) => address,
    }
}

fn hash_name(qname: &Name, class: ResponseClass) -> u64 {
    let wire = qname.as_wire();
    let bytes = if class.groups_by_parent() {
        skip_first_label(wire).unwrap_or(wire)
    } else {
        wire
    };
    // FNV-1a: стабильный хеш без случайного seed (таблица и так приватна).
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn skip_first_label(wire: &[u8]) -> Option<&[u8]> {
    let first = *wire.first()?;
    if first == 0 {
        return None;
    }
    let start = 1_usize.checked_add(usize::from(first))?;
    wire.get(start..)
}

fn shard_index(key: Key, shards: usize) -> usize {
    if shards == 0 {
        return 0;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325_u64 ^ key.name;
    match key.source {
        IpAddr::V4(address) => {
            for byte in address.octets() {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        IpAddr::V6(address) => {
            for byte in address.octets() {
                hash ^= u64::from(byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
    }
    hash ^= u64::from(key.class);
    hash ^= u64::from(key.scope);
    usize::try_from(hash % u64::try_from(shards).unwrap_or(1)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use pulse_dns::{Name, Question, Rclass, Rdata, Record, SoaData, Ttl};

    use super::*;

    fn request(name: &str) -> Message {
        Message::query(
            1,
            Question::new(Name::parse(name).expect("name"), Rtype::A, Rclass::IN),
        )
    }

    fn soa() -> Record {
        Record::new(
            Name::parse("example.test").expect("name"),
            Rtype::SOA,
            Rclass::IN,
            Ttl::new(60).expect("ttl"),
            Rdata::Soa(SoaData::new(
                Name::parse("ns.example.test").expect("mname"),
                Name::parse("hostmaster.example.test").expect("rname"),
                pulse_dns::Serial::new(1),
                3600,
                600,
                86_400,
                60,
            )),
        )
        .expect("soa")
    }

    fn ns() -> Record {
        Record::new(
            Name::parse("example.test").expect("name"),
            Rtype::NS,
            Rclass::IN,
            Ttl::new(60).expect("ttl"),
            Rdata::Ns(Name::parse("ns.example.test").expect("ns")),
        )
        .expect("ns")
    }

    fn answer() -> Record {
        Record::new(
            Name::parse("example.test").expect("name"),
            Rtype::A,
            Rclass::IN,
            Ttl::new(60).expect("ttl"),
            Rdata::A([192, 0, 2, 1].into()),
        )
        .expect("a")
    }

    fn response(request: &Message, rcode: Rcode) -> Message {
        let mut response = Message::response(request);
        response.set_rcode(rcode);
        response
    }

    fn nxdomain_response(request: &Message) -> Message {
        let mut response = response(request, Rcode::NXDOMAIN);
        response.add_authority(soa());
        response
    }

    fn referral_response(request: &Message) -> Message {
        let mut response = response(request, Rcode::NOERROR);
        response.add_authority(ns());
        response
    }

    fn positive_response(request: &Message) -> Message {
        let mut response = response(request, Rcode::NOERROR);
        response.add_answer(answer());
        response
    }

    fn rrl(rates: [RrlRate; 4], slip: u32, action: RateLimitAction) -> Rrl {
        Rrl::new(RrlConfig {
            slip,
            max_entries: 256,
            action,
            rates,
            ..RrlConfig::default()
        })
        .expect("rrl")
    }

    fn strict_nxdomain() -> Rrl {
        rrl(
            [
                RrlRate::new(1_000.0, 1_000),
                RrlRate::new(0.001, 2),
                RrlRate::new(1_000.0, 1_000),
                RrlRate::new(1_000.0, 1_000),
            ],
            1,
            RateLimitAction::Truncate,
        )
    }

    #[test]
    fn classifies_responses() {
        let request = request("www.example.test");
        assert_eq!(
            ResponseClass::classify(&positive_response(&request)),
            ResponseClass::NoError
        );
        assert_eq!(
            ResponseClass::classify(&nxdomain_response(&request)),
            ResponseClass::NxDomain
        );
        assert_eq!(
            ResponseClass::classify(&referral_response(&request)),
            ResponseClass::Referral
        );
        let mut servfail = response(&request, Rcode::SERVFAIL);
        servfail.add_authority(soa());
        assert_eq!(ResponseClass::classify(&servfail), ResponseClass::Error);
        let mut nodata = response(&request, Rcode::NOERROR);
        nodata.add_authority(soa());
        assert_eq!(ResponseClass::classify(&nodata), ResponseClass::NoError);
    }

    #[test]
    fn nxdomain_flood_is_limited() {
        let rrl = strict_nxdomain();
        let source: IpAddr = "192.0.2.1".parse().expect("ip");
        let request = request("missing.example.test");
        let response = nxdomain_response(&request);
        let start = Instant::now();
        assert_eq!(rrl.check_at(source, &response, start), RrlOutcome::Allow);
        assert_eq!(rrl.check_at(source, &response, start), RrlOutcome::Allow);
        for _ in 0..5 {
            assert_eq!(
                rrl.check_at(source, &response, start),
                RrlOutcome::Respond(RateLimitAction::Truncate)
            );
        }
        let snapshot = rrl.snapshot();
        assert_eq!(snapshot.nxdomain.limited, 5);
        assert_eq!(snapshot.nxdomain.slipped, 5);
        assert_eq!(snapshot.nxdomain.dropped, 0);
        assert_eq!(snapshot.noerror.limited, 0);
    }

    #[test]
    fn referral_flood_uses_its_own_bucket() {
        let rrl = rrl(
            [
                RrlRate::new(1_000.0, 1_000),
                RrlRate::new(1_000.0, 1_000),
                RrlRate::new(0.001, 1),
                RrlRate::new(1_000.0, 1_000),
            ],
            1,
            RateLimitAction::Drop,
        );
        let source: IpAddr = "192.0.2.2".parse().expect("ip");
        let start = Instant::now();
        let referral = referral_response(&request("www.example.test"));
        assert_eq!(rrl.check_at(source, &referral, start), RrlOutcome::Allow);
        assert_eq!(rrl.check_at(source, &referral, start), RrlOutcome::Drop);
        // Другой класс не затронут.
        let nx = nxdomain_response(&request("missing.example.test"));
        assert_eq!(rrl.check_at(source, &nx, start), RrlOutcome::Allow);
        let snapshot = rrl.snapshot();
        assert_eq!(snapshot.referral.limited, 1);
        assert_eq!(snapshot.nxdomain.limited, 0);
    }

    #[test]
    fn legitimate_traffic_is_not_limited() {
        let rrl = strict_nxdomain();
        let source: IpAddr = "192.0.2.3".parse().expect("ip");
        let start = Instant::now();
        // Разные зоны — разные бакеты, даже для NXDOMAIN (внутри одной зоны
        // NXDOMAIN группируется по родительскому имени).
        for index in 0..20 {
            let request = request(&format!("host-{index}.zone{index}.test"));
            let response = nxdomain_response(&request);
            assert_eq!(
                rrl.check_at(source, &response, start),
                RrlOutcome::Allow,
                "unique name {index}"
            );
        }
        // Другой источник — свой бакет.
        let request = request("missing.example.test");
        let response = nxdomain_response(&request);
        assert_eq!(
            rrl.check_at("198.51.100.1".parse().expect("ip"), &response, start),
            RrlOutcome::Allow
        );
    }

    #[test]
    fn slip_controls_fraction_of_responses() {
        let rrl = rrl(
            [
                RrlRate::new(1_000.0, 1_000),
                RrlRate::new(0.001, 1),
                RrlRate::new(1_000.0, 1_000),
                RrlRate::new(1_000.0, 1_000),
            ],
            2,
            RateLimitAction::Truncate,
        );
        let source: IpAddr = "192.0.2.4".parse().expect("ip");
        let start = Instant::now();
        let response = nxdomain_response(&request("missing.example.test"));
        assert_eq!(rrl.check_at(source, &response, start), RrlOutcome::Allow);
        assert_eq!(rrl.check_at(source, &response, start), RrlOutcome::Drop);
        assert_eq!(
            rrl.check_at(source, &response, start),
            RrlOutcome::Respond(RateLimitAction::Truncate)
        );
        assert_eq!(rrl.check_at(source, &response, start), RrlOutcome::Drop);
        let snapshot = rrl.snapshot();
        assert_eq!(snapshot.nxdomain.limited, 3);
        assert_eq!(snapshot.nxdomain.dropped, 2);
        assert_eq!(snapshot.nxdomain.slipped, 1);
    }

    #[test]
    fn slip_zero_drops_everything() {
        let rrl = rrl(
            [
                RrlRate::new(1_000.0, 1_000),
                RrlRate::new(0.001, 1),
                RrlRate::new(1_000.0, 1_000),
                RrlRate::new(1_000.0, 1_000),
            ],
            0,
            RateLimitAction::Refused,
        );
        let source: IpAddr = "192.0.2.5".parse().expect("ip");
        let start = Instant::now();
        let response = nxdomain_response(&request("missing.example.test"));
        assert_eq!(rrl.check_at(source, &response, start), RrlOutcome::Allow);
        for _ in 0..4 {
            assert_eq!(rrl.check_at(source, &response, start), RrlOutcome::Drop);
        }
        assert_eq!(rrl.snapshot().nxdomain.slipped, 0);
        assert_eq!(rrl.snapshot().nxdomain.dropped, 4);
    }

    #[test]
    fn ipv4_and_ipv6_are_separate_sources() {
        let rrl = strict_nxdomain();
        let start = Instant::now();
        let response = nxdomain_response(&request("missing.example.test"));
        assert_eq!(
            rrl.check_at("192.0.2.6".parse().expect("ip"), &response, start),
            RrlOutcome::Allow
        );
        assert_eq!(
            rrl.check_at("192.0.2.6".parse().expect("ip"), &response, start),
            RrlOutcome::Allow
        );
        assert_eq!(
            rrl.check_at("2001:db8::6".parse().expect("ip"), &response, start),
            RrlOutcome::Allow
        );
    }

    #[test]
    fn per_source_limit_catches_unique_name_flood() {
        let rates = [RrlRate::new(1_000.0, 1_000); 4];
        let rrl = Rrl::new(RrlConfig {
            slip: 1,
            max_entries: 256,
            action: RateLimitAction::Truncate,
            rates,
            source: RrlRate::new(0.001, 3),
        })
        .expect("rrl");
        let start = Instant::now();
        let source: IpAddr = "192.0.2.8".parse().expect("ip");
        for index in 0..3 {
            let response = nxdomain_response(&request(&format!("host-{index}.zone{index}.test")));
            assert_eq!(
                rrl.check_at(source, &response, start),
                RrlOutcome::Allow,
                "unique zone {index}"
            );
        }
        // Четвёртое уникальное имя в пределах burst источника — лимит.
        let response = nxdomain_response(&request("host-3.zone3.test"));
        assert_eq!(
            rrl.check_at(source, &response, start),
            RrlOutcome::Respond(RateLimitAction::Truncate)
        );
        // Другой источник не затронут.
        let response = nxdomain_response(&request("host-4.zone4.test"));
        assert_eq!(
            rrl.check_at("198.51.100.9".parse().expect("ip"), &response, start),
            RrlOutcome::Allow
        );
        assert_eq!(rrl.snapshot().nxdomain.limited, 1);
    }

    #[test]
    fn table_is_bounded() {
        let rrl = Rrl::new(RrlConfig {
            slip: 1,
            max_entries: 16,
            action: RateLimitAction::Drop,
            rates: [
                RrlRate::new(1_000.0, 1_000),
                RrlRate::new(0.001, 1),
                RrlRate::new(1_000.0, 1_000),
                RrlRate::new(1_000.0, 1_000),
            ],
            ..RrlConfig::default()
        })
        .expect("rrl");
        let start = Instant::now();
        for index in 0..1_000 {
            let request = request(&format!("flood-{index}.example.test"));
            let response = nxdomain_response(&request);
            let _ = rrl.check_at("192.0.2.7".parse().expect("ip"), &response, start);
        }
        let entries = rrl.snapshot().entries;
        // Две таблицы (имя и источник), по одному слоту на шард.
        assert!(entries <= 32, "entries: {entries}");
        assert!(entries > 0);
    }

    #[test]
    fn rejects_invalid_config() {
        let config = RrlConfig {
            slip: 10_000,
            ..RrlConfig::default()
        };
        assert!(Rrl::new(config).is_err());
        let config = RrlConfig {
            max_entries: 0,
            ..RrlConfig::default()
        };
        assert!(Rrl::new(config).is_err());
        let mut rates = RrlConfig::default().rates;
        rates[1] = RrlRate::new(0.0, 10);
        assert!(
            Rrl::new(RrlConfig {
                rates,
                ..RrlConfig::default()
            })
            .is_err()
        );
        let mut rates = RrlConfig::default().rates;
        rates[2] = RrlRate::new(1.0, 0);
        assert!(
            Rrl::new(RrlConfig {
                rates,
                ..RrlConfig::default()
            })
            .is_err()
        );
    }
}
