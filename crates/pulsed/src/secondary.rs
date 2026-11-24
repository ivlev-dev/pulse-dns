//! Secondary-зоны: AXFR/IXFR-in, SOA-refresh, NOTIFY и таймеры.
//!
//! Сетевые операции выполняются только в фоновом [`SecondaryScheduler`].
//! DNS-запросы обслуживают уже готовый `QueryEngine`-снапшот и никогда не
//! ждут трансфер. На одну зону действует lease: одновременно выполняется не
//! более одного AXFR/IXFR.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pulse_api::StoreSnapshot;
use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Record, Rrset,
    Rtype, Serial, Ttl,
};
use pulse_server::ZoneState;
use pulse_transfer::{
    AxfrClient, IxfrClient, IxfrOutcome, TransferError, TransferLimits, TsigKey, ZoneSnapshot,
    apply_ixfr, soa_serial,
};
use thiserror::Error;

use crate::config::{Config, SecondaryZoneConfig};
use crate::logging;
use crate::store::SharedZoneAdmin;

/// Таймеры secondary-зоны (SOA refresh/retry/expire).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Timers {
    refresh: Duration,
    retry: Duration,
    expire: Duration,
}

impl Default for Timers {
    fn default() -> Self {
        Self {
            refresh: Duration::from_secs(3_600),
            retry: Duration::from_secs(600),
            expire: Duration::from_hours(168),
        }
    }
}

/// Состояние одной secondary-зоны.
#[derive(Debug)]
struct SecondaryState {
    last_success: Option<Instant>,
    next_refresh: Instant,
    force: bool,
    expired: bool,
    timers: Timers,
    serial: Option<Serial>,
    last_error: Option<String>,
}

impl SecondaryState {
    fn new(now: Instant, exists: bool, timers: Timers) -> Self {
        Self {
            last_success: exists.then_some(now),
            next_refresh: now,
            force: false,
            expired: false,
            timers,
            serial: None,
            last_error: None,
        }
    }
}

/// Ошибка secondary-трансфера.
#[derive(Debug, Error)]
pub(crate) enum SecondaryError {
    /// Нет master-адресов.
    #[error("secondary zone has no masters")]
    NoMasters,
    /// Master не ответил в отведённое время.
    #[error("master {master} timed out")]
    Timeout {
        /// Адрес master.
        master: SocketAddr,
    },
    /// Ошибка I/O.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// Ошибка DNS-кодека.
    #[error(transparent)]
    Decode(#[from] pulse_dns::DecodeError),
    /// Ошибка кодирования DNS.
    #[error(transparent)]
    Encode(#[from] pulse_dns::EncodeError),
    /// Ошибка transfer-протокола.
    #[error(transparent)]
    Transfer(#[from] TransferError),
    /// Master вернул неожиданный ответ.
    #[error("master {master} returned {rcode}")]
    Rcode {
        /// Адрес master.
        master: SocketAddr,
        /// RCODE.
        rcode: Rcode,
    },
    /// В ответе нет apex SOA.
    #[error("master {0} did not return the zone SOA")]
    NoSoa(SocketAddr),
    /// Serial неоднозначен по RFC 1982.
    #[error("master serial is ambiguous under RFC 1982")]
    AmbiguousSerial,
    /// Master отдал serial не новее локального.
    #[error("master serial {master} is not newer than local {local}")]
    Stale {
        /// Локальный serial.
        local: Serial,
        /// Serial master.
        master: Serial,
    },
    /// Некорректные данные зоны.
    #[error("zone data error: {0}")]
    Zone(String),
    /// Не удалось обновить store.
    #[error("store error: {0}")]
    Store(String),
    /// Некорректная конфигурация secondary.
    #[error("invalid secondary configuration: {0}")]
    Config(String),
}

/// Одна secondary-зона.
pub(crate) struct SecondaryZone {
    origin: Name,
    masters: Vec<SocketAddr>,
    key: Option<Arc<TsigKey>>,
    bootstrap: bool,
    timers_override: TimersOverride,
    state: Mutex<SecondaryState>,
    lease: Mutex<()>,
}

#[derive(Debug, Clone, Copy, Default)]
struct TimersOverride {
    refresh: Option<Duration>,
    retry: Option<Duration>,
    expire: Option<Duration>,
}

impl fmt::Debug for SecondaryZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecondaryZone")
            .field("origin", &self.origin)
            .field("masters", &self.masters)
            .field("tsig", &self.key.as_ref().map(|key| key.name()))
            .field("bootstrap", &self.bootstrap)
            .finish_non_exhaustive()
    }
}

impl SecondaryZone {
    fn new(
        config: &SecondaryZoneConfig,
        key: Option<Arc<TsigKey>>,
        exists: bool,
        now: Instant,
    ) -> Result<Self, SecondaryError> {
        let origin = Name::parse(config.origin.trim()).map_err(|error| {
            SecondaryError::Config(format!("invalid origin {:?}: {error}", config.origin))
        })?;
        let timers_override = TimersOverride {
            refresh: config
                .refresh
                .map(|seconds| Duration::from_secs(u64::from(seconds))),
            retry: config
                .retry
                .map(|seconds| Duration::from_secs(u64::from(seconds))),
            expire: config
                .expire
                .map(|seconds| Duration::from_secs(u64::from(seconds))),
        };
        let timers = Timers {
            refresh: timers_override.refresh.unwrap_or(Timers::default().refresh),
            retry: timers_override.retry.unwrap_or(Timers::default().retry),
            expire: timers_override.expire.unwrap_or(Timers::default().expire),
        };
        Ok(Self {
            origin,
            masters: config.masters.clone(),
            key,
            bootstrap: config.bootstrap,
            timers_override,
            state: Mutex::new(SecondaryState::new(now, exists, timers)),
            lease: Mutex::new(()),
        })
    }

    /// Origin.
    pub(crate) fn origin(&self) -> &Name {
        &self.origin
    }

    /// Нужно ли загружать отсутствующую зону автоматически.
    pub(crate) fn bootstrap(&self) -> bool {
        self.bootstrap
    }

    /// Запрашивает обновление у master-ов.
    pub(crate) fn fetch(
        &self,
        local: Option<&ZoneSnapshot>,
        limits: TransferLimits,
    ) -> Result<SecondaryUpdate, SecondaryError> {
        fetch(
            &self.origin,
            &self.masters,
            self.key.as_deref(),
            local,
            limits,
        )
    }

    fn lock_state(&self) -> MutexGuard<'_, SecondaryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn try_lease(&self) -> Option<MutexGuard<'_, ()>> {
        self.lease.try_lock().ok()
    }

    fn is_due(&self, now: Instant) -> bool {
        let state = self.lock_state();
        state.force || now >= state.next_refresh
    }

    pub(crate) fn take_force(&self) -> bool {
        let mut state = self.lock_state();
        let force = state.force;
        state.force = false;
        force
    }

    pub(crate) fn expire_due(&self, now: Instant) -> bool {
        let mut state = self.lock_state();
        expire_state(&mut state, now)
    }

    pub(crate) fn note_success(&self, soa: &Record, now: Instant) -> bool {
        let mut state = self.lock_state();
        let was_expired = state.expired;
        state.expired = false;
        state.last_success = Some(now);
        state.serial = soa_serial(soa);
        state.last_error = None;
        state.timers = self.timers_from_soa(soa, &state);
        state.next_refresh = now + state.timers.refresh;
        was_expired
    }

    pub(crate) fn note_failure(&self, error: String, now: Instant) -> bool {
        let mut state = self.lock_state();
        state.last_error = Some(error);
        state.next_refresh = now + state.timers.retry;
        expire_state(&mut state, now)
    }

    pub(crate) fn note_skip(&self, now: Instant) {
        let mut state = self.lock_state();
        state.next_refresh = now + state.timers.refresh;
    }

    pub(crate) fn wake(&self, now: Instant) {
        let mut state = self.lock_state();
        state.force = true;
        state.next_refresh = now;
    }

    fn timers_from_soa(&self, soa: &Record, state: &SecondaryState) -> Timers {
        let Rdata::Soa(data) = soa.rdata() else {
            return state.timers;
        };
        Timers {
            refresh: self
                .timers_override
                .refresh
                .unwrap_or_else(|| Duration::from_secs(u64::from(data.refresh.max(1)))),
            retry: self
                .timers_override
                .retry
                .unwrap_or_else(|| Duration::from_secs(u64::from(data.retry.max(1)))),
            expire: self
                .timers_override
                .expire
                .unwrap_or_else(|| Duration::from_secs(u64::from(data.expire.max(1)))),
        }
    }

    fn is_expired(&self) -> bool {
        self.lock_state().expired
    }

    fn last_error(&self) -> Option<String> {
        self.lock_state().last_error.clone()
    }
}

fn expire_state(state: &mut SecondaryState, now: Instant) -> bool {
    if state.expired {
        return false;
    }
    let Some(last_success) = state.last_success else {
        return false;
    };
    if now.duration_since(last_success) < state.timers.expire {
        return false;
    }
    state.expired = true;
    true
}

/// Набор secondary-зон.
pub(crate) struct SecondaryManager {
    zones: HashMap<Name, Arc<SecondaryZone>>,
}

impl SecondaryManager {
    /// Создаёт менеджер из конфигурации.
    pub(crate) fn from_config(
        config: &Config,
        snapshot: &StoreSnapshot,
        key: impl Fn(&Name) -> Option<Arc<TsigKey>>,
        now: Instant,
    ) -> Result<Self, SecondaryError> {
        let mut zones = HashMap::with_capacity(config.secondary_zones.len());
        for zone_config in &config.secondary_zones {
            let key = match &zone_config.tsig_key {
                Some(name) => {
                    let name = Name::parse(name.trim()).map_err(|error| {
                        SecondaryError::Config(format!(
                            "secondary {:?}: invalid tsig_key: {error}",
                            zone_config.origin
                        ))
                    })?;
                    Some(key(&name).ok_or_else(|| {
                        SecondaryError::Config(format!(
                            "secondary {:?}: TSIG key {name} is not configured",
                            zone_config.origin
                        ))
                    })?)
                }
                None => None,
            };
            let origin = Name::parse(zone_config.origin.trim()).map_err(|error| {
                SecondaryError::Config(format!(
                    "invalid secondary origin {:?}: {error}",
                    zone_config.origin
                ))
            })?;
            let exists = snapshot
                .zones
                .iter()
                .any(|zone| zone.origin == origin && zone.kind == pulse_api::ZoneKind::Secondary);
            let zone = Arc::new(SecondaryZone::new(zone_config, key, exists, now)?);
            zones.insert(origin, zone);
        }
        Ok(Self { zones })
    }

    /// Есть ли secondary-зоны.
    pub(crate) fn is_empty(&self) -> bool {
        self.zones.is_empty()
    }

    /// Зона по origin.
    pub(crate) fn get(&self, origin: &Name) -> Option<Arc<SecondaryZone>> {
        self.zones.get(origin).cloned()
    }

    /// Зоны, которым пора обновиться.
    pub(crate) fn due(&self, now: Instant) -> Vec<Name> {
        let mut due = Vec::new();
        for zone in self.zones.values() {
            if zone.is_due(now) {
                due.push(zone.origin.clone());
            }
        }
        due
    }

    /// Проверяет expire и возвращает `true`, если состояние изменилось.
    pub(crate) fn expire_due(&self, now: Instant) -> bool {
        let mut changed = false;
        for zone in self.zones.values() {
            if zone.expire_due(now) {
                logging::warn(
                    "secondary",
                    &format!("zone {} expired; DNS answers SERVFAIL", zone.origin()),
                );
                changed = true;
            }
        }
        changed
    }

    /// Ставит зону в очередь немедленного обновления (NOTIFY-in).
    pub(crate) fn wake(&self, origin: &Name, now: Instant) {
        if let Some(zone) = self.zones.get(origin) {
            zone.wake(now);
        }
    }

    /// Множество истёкших зон для `QueryEngine`.
    pub(crate) fn expired_origins(&self) -> HashSet<Name> {
        self.zones
            .values()
            .filter(|zone| zone.is_expired())
            .map(|zone| zone.origin.clone())
            .collect()
    }

    /// Диагностика последней ошибки зоны.
    pub(crate) fn last_error(&self, origin: &Name) -> Option<String> {
        self.zones.get(origin).and_then(|zone| zone.last_error())
    }
}

impl fmt::Debug for SecondaryManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecondaryManager")
            .field("zones", &self.zones.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Результат проверки/трансфера с master.
pub(crate) enum SecondaryUpdate {
    /// Serial master не новее локального.
    UpToDate {
        /// SOA master.
        soa: Record,
    },
    /// Новый снапшот зоны (AXFR или IXFR).
    Zone(ZoneSnapshot),
}

impl SecondaryUpdate {
    /// SOA обновлённой/проверенной зоны.
    pub(crate) fn soa(&self) -> &Record {
        match self {
            Self::UpToDate { soa } => soa,
            Self::Zone(zone) => zone.soa(),
        }
    }
}

/// Запрашивает SOA/IXFR/AXFR у master-ов по порядку.
pub(crate) fn fetch(
    origin: &Name,
    masters: &[SocketAddr],
    key: Option<&TsigKey>,
    local: Option<&ZoneSnapshot>,
    limits: TransferLimits,
) -> Result<SecondaryUpdate, SecondaryError> {
    let mut last_error = None;
    for master in masters {
        match fetch_from(*master, origin, key, local, limits) {
            Ok(update) => return Ok(update),
            Err(error) => {
                logging::warn(
                    "secondary",
                    &format!("zone {origin}: master {master} failed: {error}"),
                );
                last_error = Some(error);
            }
        }
    }
    last_error.map_or(Err(SecondaryError::NoMasters), Err)
}

fn fetch_from(
    master: SocketAddr,
    origin: &Name,
    key: Option<&TsigKey>,
    local: Option<&ZoneSnapshot>,
    limits: TransferLimits,
) -> Result<SecondaryUpdate, SecondaryError> {
    if let Some(local) = local {
        match query_soa(master, origin, limits) {
            Ok(master_soa) => {
                let Some(master_serial) = soa_serial(&master_soa) else {
                    return Err(SecondaryError::NoSoa(master));
                };
                match local.serial().cmp_rfc1982(master_serial) {
                    Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater) => {
                        return Ok(SecondaryUpdate::UpToDate { soa: master_soa });
                    }
                    None => return Err(SecondaryError::AmbiguousSerial),
                    Some(std::cmp::Ordering::Less) => {}
                }
            }
            Err(error) => logging::warn(
                "secondary",
                &format!("zone {origin}: SOA query to {master} failed: {error}; trying transfer"),
            ),
        }

        match ixfr_from(master, origin, local, key, limits) {
            Ok(IxfrOutcome::UpToDate { soa }) => {
                return Ok(SecondaryUpdate::UpToDate { soa });
            }
            Ok(IxfrOutcome::Incremental { deltas, .. }) => {
                let zone = apply_ixfr(local, &deltas)?;
                logging::info(
                    "secondary",
                    &format!(
                        "zone {origin}: IXFR applied from {master}: {} delta(s), serial {}",
                        deltas.len(),
                        zone.serial()
                    ),
                );
                return Ok(SecondaryUpdate::Zone(zone));
            }
            Ok(IxfrOutcome::AxfrFallback { zone }) => {
                logging::info(
                    "secondary",
                    &format!(
                        "zone {origin}: IXFR fallback to AXFR from {master}, serial {}",
                        zone.serial()
                    ),
                );
                return Ok(SecondaryUpdate::Zone(zone));
            }
            Err(error) => logging::warn(
                "secondary",
                &format!("zone {origin}: IXFR from {master} failed: {error}; trying AXFR"),
            ),
        }
    }

    let zone = axfr_from(master, origin, key, limits)?;
    if let Some(local) = local {
        match zone.serial().cmp_rfc1982(local.serial()) {
            Some(std::cmp::Ordering::Equal) => {
                return Ok(SecondaryUpdate::UpToDate {
                    soa: zone.soa().clone(),
                });
            }
            Some(std::cmp::Ordering::Greater) => {}
            Some(std::cmp::Ordering::Less) => {
                return Err(SecondaryError::Stale {
                    local: local.serial(),
                    master: zone.serial(),
                });
            }
            None => return Err(SecondaryError::AmbiguousSerial),
        }
    }
    logging::info(
        "secondary",
        &format!(
            "zone {origin}: AXFR from {master}: {} record(s), serial {}",
            zone.records().len(),
            zone.serial()
        ),
    );
    Ok(SecondaryUpdate::Zone(zone))
}

fn query_soa(
    master: SocketAddr,
    origin: &Name,
    limits: TransferLimits,
) -> Result<Record, SecondaryError> {
    match query_soa_udp(master, origin, limits) {
        Ok(soa) => Ok(soa),
        Err(udp_error) => {
            logging::debug(
                "secondary",
                &format!(
                    "zone {origin}: SOA over UDP to {master} failed: {udp_error}; retrying over TCP"
                ),
            );
            query_soa_tcp(master, origin, limits)
        }
    }
}

fn query_soa_udp(
    master: SocketAddr,
    origin: &Name,
    limits: TransferLimits,
) -> Result<Record, SecondaryError> {
    let timeout = limits.timeout.unwrap_or(Duration::from_secs(30));
    let socket = UdpSocket::bind(bind_address(master))?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    let id = next_id();
    let query = Message::query(id, Question::new(origin.clone(), Rtype::SOA, Rclass::IN));
    let bytes = query.encode(&EncodeOptions::compressed())?;
    socket.send_to(&bytes, master)?;
    let mut buffer = [0_u8; 4096];
    let length = loop {
        match socket.recv_from(&mut buffer) {
            Ok((length, _)) => break length,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(SecondaryError::Timeout { master });
            }
            Err(error) => return Err(error.into()),
        }
    };
    decode_soa_response(master, origin, id, buffer.get(..length).unwrap_or_default())
}

fn query_soa_tcp(
    master: SocketAddr,
    origin: &Name,
    limits: TransferLimits,
) -> Result<Record, SecondaryError> {
    let timeout = limits.timeout.unwrap_or(Duration::from_secs(30));
    let mut stream = TcpStream::connect_timeout(&master, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let id = next_id();
    let query = Message::query(id, Question::new(origin.clone(), Rtype::SOA, Rclass::IN));
    let bytes = query.encode(&EncodeOptions::compressed())?;
    pulse_transfer::write_message(&mut stream, &bytes)?;
    let response = pulse_transfer::read_message(&mut stream)?;
    decode_soa_response(master, origin, id, &response)
}

fn decode_soa_response(
    master: SocketAddr,
    origin: &Name,
    id: u16,
    bytes: &[u8],
) -> Result<Record, SecondaryError> {
    let response = Message::decode(bytes, &DecodeLimits::default())?;
    if !response.flags().qr() || response.id() != id {
        return Err(SecondaryError::Zone("unexpected SOA response".to_owned()));
    }
    if response.rcode() != Rcode::NOERROR {
        return Err(SecondaryError::Rcode {
            master,
            rcode: response.rcode(),
        });
    }
    response
        .answers()
        .iter()
        .chain(response.authority().iter())
        .find(|record| record.rr_type() == Rtype::SOA && record.owner() == origin)
        .cloned()
        .ok_or(SecondaryError::NoSoa(master))
}

fn axfr_from(
    master: SocketAddr,
    origin: &Name,
    key: Option<&TsigKey>,
    limits: TransferLimits,
) -> Result<ZoneSnapshot, SecondaryError> {
    let timeout = limits.timeout.unwrap_or(Duration::from_secs(30));
    let stream = TcpStream::connect_timeout(&master, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut client = AxfrClient::with_limits(stream, limits);
    Ok(client.transfer(origin, next_id(), key, crate::transfer::now_unix())?)
}

fn ixfr_from(
    master: SocketAddr,
    origin: &Name,
    local: &ZoneSnapshot,
    key: Option<&TsigKey>,
    limits: TransferLimits,
) -> Result<IxfrOutcome, SecondaryError> {
    let timeout = limits.timeout.unwrap_or(Duration::from_secs(30));
    let stream = TcpStream::connect_timeout(&master, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut client = IxfrClient::with_limits(stream, limits);
    Ok(client.transfer(
        origin,
        local.soa(),
        next_id(),
        key,
        crate::transfer::now_unix(),
    )?)
}

fn bind_address(target: SocketAddr) -> SocketAddr {
    if target.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    }
}

fn next_id() -> u16 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    u16::try_from(NEXT.fetch_add(1, Ordering::Relaxed) & 0xFFFF).unwrap_or(1)
}

/// Преобразует снапшот трансфера в RRset-набор store.
pub(crate) fn rrsets_from_snapshot(snapshot: &ZoneSnapshot) -> Result<Vec<Rrset>, SecondaryError> {
    let mut groups: HashMap<(String, u16), (Ttl, Vec<Rdata>)> = HashMap::new();
    for record in snapshot.records_with_soa() {
        let key = (record.owner().to_string(), record.rr_type().as_u16());
        match groups.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if entry.get().0 != record.ttl() {
                    return Err(SecondaryError::Zone(format!(
                        "inconsistent TTL for {} {}",
                        record.owner(),
                        record.rr_type()
                    )));
                }
                entry.get_mut().1.push(record.rdata().clone());
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert((record.ttl(), vec![record.rdata().clone()]));
            }
        }
    }
    let mut rrsets = Vec::with_capacity(groups.len());
    for ((owner, rr_type), (ttl, rdata)) in groups {
        let owner = Name::parse(&owner).map_err(|error| SecondaryError::Zone(error.to_string()))?;
        let rrset = Rrset::new(owner, Rtype::from_u16(rr_type), Rclass::IN, ttl, rdata)
            .map_err(|error| SecondaryError::Zone(error.to_string()))?;
        rrsets.push(rrset);
    }
    Ok(rrsets)
}

/// Фоновой поток обновления secondary-зон.
pub(crate) struct SecondaryScheduler {
    stop: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl SecondaryScheduler {
    /// Запускает планировщик для `admin`.
    pub(crate) fn start(admin: std::sync::Weak<SharedZoneAdmin>) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("pulse-secondary".to_owned())
            .spawn(move || {
                while !worker_stop.load(Ordering::Acquire) {
                    if let Some(admin) = admin.upgrade() {
                        admin.secondary_tick(Instant::now());
                    } else {
                        break;
                    }
                    thread::sleep(Duration::from_millis(200));
                }
            })?;
        Ok(Self {
            stop,
            handle: Mutex::new(Some(handle)),
        })
    }

    /// Останавливает планировщик.
    pub(crate) fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self
            .handle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = handle.join();
        }
    }
}

impl Drop for SecondaryScheduler {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Истёкшие зоны и состояние `Serving`/`Expired` используются при построении
/// `QueryEngine`; эта функция оставлена для явного тестирования политики.
pub(crate) fn state_for(expired: bool, has_data: bool) -> ZoneState {
    if has_data {
        if expired {
            ZoneState::Expired
        } else {
            ZoneState::Serving
        }
    } else {
        ZoneState::Initializing
    }
}
