//! AXFR/IXFR-out, TSIG, IXFR-история и NOTIFY для `pulsed`.
//!
//! Модуль связывает in-memory store зон с протокольным крейтом
//! `pulse-transfer`:
//!
//! - при каждой мутации store (`REST`, DNSSEC-подпись, создание/удаление
//!   зоны) строится новый [`ZoneSnapshot`] и дельта IXFR;
//! - AXFR/IXFR обслуживаются только по TCP, с ACL источника/зоны и TSIG;
//! - NOTIFY-out уходит в фоновую очередь, поэтому REST-ответ не ждёт UDP;
//! - NOTIFY-in возвращает `NOERROR` и помечает зону к обновлению.
//!
//! Секреты TSIG не логируются и не попадают в `Debug`.

use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pulse_api::{StoreSnapshot, ZoneKind};
use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Opcode, Rcode, Record, Rtype, Serial};
use pulse_transfer::{
    AxfrServer, IxfrServer, NotifyIgnoreReason, NotifyOutcome, NotifyPolicy, NotifyRequest,
    NotifyServer, TransferConfig, TransferError, TransferLimits, TsigError, TsigErrorCode, TsigKey,
    TsigReplayCache, ZoneDelta, ZoneHistory, ZoneSnapshot, build_tsig_error_response, parse_tsig,
    write_message,
};
use thiserror::Error;

use crate::config::{TransferSettings, TsigKeyConfig, parse_tsig_algorithm};
use crate::logging;

/// Текущее время UNIX в секундах.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Ошибка инициализации подсистемы transfer.
#[derive(Debug, Error)]
pub(crate) enum TransferSetupError {
    /// Некорректный или неподдерживаемый TSIG-ключ.
    #[error("invalid TSIG key {name}: {source}")]
    Key {
        /// Имя ключа.
        name: String,
        /// Причина.
        #[source]
        source: TsigError,
    },
    /// Секрет ключа не является base64.
    #[error("TSIG key {name} has invalid base64 secret: {reason}")]
    Secret {
        /// Имя ключа.
        name: String,
        /// Причина.
        reason: String,
    },
    /// Некорректная конфигурация transfer.
    #[error("invalid transfer configuration: {0}")]
    Config(String),
    /// Ошибка построения зоны для трансфера.
    #[error(transparent)]
    Transfer(#[from] TransferError),
}

/// Действие для входящего NOTIFY.
pub(crate) enum NotifyAction {
    /// Ответа нет (источник вне ACL; для UDP пакет отбрасывается).
    Ignore,
    /// Отправить готовый wire-ответ.
    Reply(Vec<u8>),
}

/// Одна зона в transfer-состоянии.
struct ZoneTransfer {
    snapshot: Arc<ZoneSnapshot>,
    history: Arc<ZoneHistory>,
}

/// Состояние AXFR/IXFR-out, TSIG-replay и NOTIFY.
pub(crate) struct TransferState {
    settings: TransferSettings,
    config: TransferConfig,
    keys: HashMap<Name, Arc<TsigKey>>,
    allow_from: HashSet<IpAddr>,
    allow_zones: HashSet<Name>,
    zones: RwLock<HashMap<Name, Arc<ZoneTransfer>>>,
    replay: Mutex<TsigReplayCache>,
    pending: Mutex<HashMap<Name, Option<Serial>>>,
    notify: Option<Arc<NotifyDispatcher>>,
}

impl TransferState {
    /// Создаёт состояние из конфигурации и начального снапшота store.
    ///
    /// Начальные зоны не порождают NOTIFY: уведомления отправляются только
    /// после мутаций.
    pub(crate) fn from_config(
        settings: &TransferSettings,
        keys: &[TsigKeyConfig],
        snapshot: &StoreSnapshot,
        notify: Option<Arc<NotifyDispatcher>>,
    ) -> Result<Self, TransferSetupError> {
        let config = build_transfer_config(settings)?;
        let key_map = build_keys(keys)?;
        let allow_from: HashSet<IpAddr> = settings.allow_from.iter().copied().collect();
        let allow_zones = settings
            .allow_zones
            .iter()
            .map(|origin| {
                Name::parse(origin.trim()).map_err(|error| {
                    TransferSetupError::Config(format!(
                        "transfer.allow_zones: invalid origin {origin:?}: {error}"
                    ))
                })
            })
            .collect::<Result<HashSet<_>, _>>()?;

        let mut zones = HashMap::with_capacity(snapshot.zones.len());
        for zone in &snapshot.zones {
            if let Some(built) = build_zone(zone) {
                zones.insert(
                    zone.origin.clone(),
                    Arc::new(ZoneTransfer {
                        snapshot: Arc::new(built),
                        history: Arc::new(ZoneHistory::new()),
                    }),
                );
            }
        }
        Ok(Self {
            settings: settings.clone(),
            config,
            keys: key_map,
            allow_from,
            allow_zones,
            zones: RwLock::new(zones),
            replay: Mutex::new(TsigReplayCache::new(16_384)),
            pending: Mutex::new(HashMap::new()),
            notify,
        })
    }

    /// Перестраивает transfer-снапшоты после мутации store и ставит NOTIFY.
    pub(crate) fn refresh(&self, snapshot: &StoreSnapshot) {
        let built: Vec<(Name, ZoneSnapshot)> = snapshot
            .zones
            .iter()
            .filter_map(|zone| build_zone(zone).map(|built| (zone.origin.clone(), built)))
            .collect();
        let max_deltas = self.settings.history_deltas;
        let mut next: HashMap<Name, Arc<ZoneTransfer>> = HashMap::with_capacity(built.len());
        let mut notifications: Vec<NotifyJob> = Vec::new();
        let mut current: HashSet<Name> = HashSet::with_capacity(built.len());

        {
            let zones = self.zones.read().unwrap_or_else(PoisonError::into_inner);
            for (origin, snapshot) in built {
                current.insert(origin.clone());
                let previous = zones.get(&origin);
                let (history, changed) = match previous {
                    Some(previous) => update_history(
                        previous.snapshot.as_ref(),
                        previous.history.as_ref(),
                        &snapshot,
                        max_deltas,
                    ),
                    None => (ZoneHistory::new(), true),
                };
                if changed {
                    notifications.push(NotifyJob {
                        id: next_notify_id(),
                        zone: origin.clone(),
                        soa: Some(snapshot.soa().clone()),
                    });
                }
                next.insert(
                    origin,
                    Arc::new(ZoneTransfer {
                        snapshot: Arc::new(snapshot),
                        history: Arc::new(history),
                    }),
                );
            }
            for origin in zones.keys() {
                if !current.contains(origin) {
                    notifications.push(NotifyJob {
                        id: next_notify_id(),
                        zone: origin.clone(),
                        soa: None,
                    });
                }
            }
        }
        *self.zones.write().unwrap_or_else(PoisonError::into_inner) = next;

        for job in notifications {
            self.enqueue_notify(job);
        }
    }

    /// Помечает зону к обновлению после входящего NOTIFY.
    pub(crate) fn mark_pending(&self, zone: &Name, serial: Option<Serial>) {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(zone.clone(), serial);
    }

    /// Зоны, ожидающие обновления после NOTIFY-in.
    pub(crate) fn pending_updates(&self) -> Vec<Name> {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    /// Обслуживает AXFR/IXFR, если запрос адресован трансферу.
    ///
    /// `None` означает, что запрос не является AXFR/IXFR и его должен
    /// обработать обычный `QueryEngine`.
    pub(crate) fn handle_transfer<S: Read + Write>(
        &self,
        stream: &mut S,
        raw: &[u8],
        source: IpAddr,
        now: u64,
    ) -> Option<Result<(), TransferError>> {
        let Ok(request) = Message::decode(raw, &DecodeLimits::default()) else {
            return None;
        };
        if request.opcode() != Opcode::QUERY {
            return None;
        }
        let question = request.questions().first()?;
        let qtype = question.qtype();
        if !matches!(qtype, Rtype::AXFR | Rtype::IXFR) {
            return None;
        }
        Some(self.serve_transfer(stream, raw, &request, question.qname(), qtype, source, now))
    }

    #[allow(clippy::too_many_arguments)]
    fn serve_transfer<S: Read + Write>(
        &self,
        stream: &mut S,
        raw: &[u8],
        request: &Message,
        origin: &Name,
        qtype: Rtype,
        source: IpAddr,
        now: u64,
    ) -> Result<(), TransferError> {
        if !self.settings.enabled {
            return send_refusal(stream, request, Rcode::REFUSED);
        }
        if !self.allow_from.is_empty() && !self.allow_from.contains(&source) {
            logging::warn(
                "transfer_acl",
                &format!("AXFR/IXFR from {source} for {origin} denied by source ACL"),
            );
            return send_refusal(stream, request, Rcode::REFUSED);
        }
        if !self.allow_zones.is_empty() && !self.allow_zones.contains(origin) {
            logging::warn(
                "transfer_acl",
                &format!("AXFR/IXFR from {source} for {origin} denied by zone ACL"),
            );
            return send_refusal(stream, request, Rcode::REFUSED);
        }
        let Some(zone) = self
            .zones
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(origin)
            .cloned()
        else {
            return send_refusal(stream, request, Rcode::REFUSED);
        };

        let key = self.authenticate_transfer(request, raw, now, stream)?;

        let mut framed = Vec::with_capacity(raw.len().saturating_add(2));
        let length = u16::try_from(raw.len())
            .map_err(|_| TransferError::MessageTooLarge { len: raw.len() })?;
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(raw);
        let mut rewind = Rewound {
            input: Cursor::new(framed),
            output: stream,
        };
        let stats = match qtype {
            Rtype::AXFR => AxfrServer::new(self.config).serve(
                &mut rewind,
                zone.snapshot.as_ref(),
                key.as_deref(),
                now,
            )?,
            Rtype::IXFR => IxfrServer::new(self.config).serve(
                &mut rewind,
                zone.snapshot.as_ref(),
                zone.history.as_ref(),
                key.as_deref(),
                now,
            )?,
            _ => return Ok(()),
        };
        logging::info(
            "transfer",
            &format!(
                "{qtype} {origin} to {source}: messages={} records={} bytes={}",
                stats.messages, stats.records, stats.bytes
            ),
        );
        Ok(())
    }

    fn authenticate_transfer<S: Write>(
        &self,
        request: &Message,
        raw: &[u8],
        now: u64,
        stream: &mut S,
    ) -> Result<Option<Arc<TsigKey>>, TransferError> {
        match parse_tsig(raw) {
            Ok(None) => Ok(None),
            Ok(Some(envelope)) => {
                let Some(key) = self.keys.get(envelope.record().key_name()).cloned() else {
                    logging::warn(
                        "transfer_tsig",
                        &format!(
                            "AXFR/IXFR with unknown TSIG key {}",
                            envelope.record().key_name()
                        ),
                    );
                    send_tsig_error(stream, request, &envelope, None, now, TsigErrorCode::BADKEY)?;
                    return Err(TransferError::Tsig(TsigError::Missing));
                };
                if let Err(error) = key.verify_request_envelope(&envelope, now) {
                    let code = error.error_code().unwrap_or(TsigErrorCode::BADSIG);
                    logging::warn(
                        "transfer_tsig",
                        &format!("TSIG verification failed: {error}"),
                    );
                    send_tsig_error(stream, request, &envelope, Some(key.as_ref()), now, code)?;
                    return Err(TransferError::Tsig(error));
                }
                {
                    let mut replay = self.replay.lock().unwrap_or_else(PoisonError::into_inner);
                    if let Err(error) =
                        replay.check_and_record(key.name(), envelope.record().time_signed())
                    {
                        logging::warn("transfer_tsig", &format!("TSIG replay: {error}"));
                        send_tsig_error(
                            stream,
                            request,
                            &envelope,
                            Some(key.as_ref()),
                            now,
                            TsigErrorCode::BADTIME,
                        )?;
                        return Err(TransferError::Tsig(error));
                    }
                }
                Ok(Some(key))
            }
            Err(error) => {
                send_refusal(stream, request, Rcode::NOTAUTH)?;
                Err(TransferError::Tsig(error))
            }
        }
    }

    /// Обрабатывает входящий NOTIFY.
    ///
    /// `None` — сообщение не является NOTIFY.
    pub(crate) fn handle_notify_in(
        &self,
        raw: &[u8],
        source: IpAddr,
        now: u64,
    ) -> Option<NotifyAction> {
        let message = Message::decode(raw, &DecodeLimits::default()).ok()?;
        if message.opcode() != Opcode::NOTIFY {
            return None;
        }
        let key = match parse_tsig(raw) {
            Ok(Some(envelope)) => {
                if let Some(key) = self.keys.get(envelope.record().key_name()).cloned() {
                    Some(key)
                } else {
                    let response = build_tsig_error_response(
                        &message,
                        Some(envelope.record()),
                        None,
                        Some(envelope.record().mac()),
                        TsigErrorCode::BADKEY,
                        now,
                    )
                    .map_err(|error| {
                        logging::error("notify_in", &format!("cannot encode BADKEY: {error}"));
                    })
                    .ok()?;
                    return Some(NotifyAction::Reply(response));
                }
            }
            Ok(None) => None,
            Err(error) => {
                logging::warn("notify_in", &format!("malformed TSIG: {error}"));
                let response = build_tsig_error_response(
                    &message,
                    None,
                    None,
                    None,
                    TsigErrorCode::BADSIG,
                    now,
                )
                .map_err(|error| {
                    logging::error("notify_in", &format!("cannot encode NOTAUTH: {error}"));
                })
                .ok()?;
                return Some(NotifyAction::Reply(response));
            }
        };

        let zones: Vec<Name> = self
            .zones
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        let policy = NotifyPolicy::new(self.settings.allow_from.clone(), zones);
        let server =
            NotifyServer::with_shared_key(policy, key).require_tsig(self.settings.require_tsig);
        match server.handle(raw, source, now) {
            Ok(NotifyOutcome::Accepted {
                zone,
                serial,
                response,
            }) => {
                self.mark_pending(&zone, serial);
                logging::info(
                    "notify_in",
                    &format!("NOTIFY from {source} accepted for {zone} (serial {serial:?})"),
                );
                Some(NotifyAction::Reply(response))
            }
            Ok(NotifyOutcome::Refused { response }) => {
                logging::warn("notify_in", &format!("NOTIFY from {source} refused"));
                Some(NotifyAction::Reply(response))
            }
            Ok(NotifyOutcome::Ignored {
                reason: NotifyIgnoreReason::SourceNotAllowed,
            }) => {
                logging::warn(
                    "notify_in",
                    &format!("NOTIFY from {source} ignored: source is not allowed"),
                );
                Some(NotifyAction::Ignore)
            }
            Err(error) => {
                logging::error("notify_in", &format!("cannot handle NOTIFY: {error}"));
                Some(NotifyAction::Ignore)
            }
        }
    }

    /// Останавливает фоновую очередь NOTIFY.
    pub(crate) fn shutdown_notify(&self) {
        if let Some(notify) = &self.notify {
            notify.shutdown();
        }
    }

    fn enqueue_notify(&self, job: NotifyJob) {
        let Some(notify) = &self.notify else {
            return;
        };
        notify.try_send(job);
    }
}

fn build_transfer_config(
    settings: &TransferSettings,
) -> Result<TransferConfig, TransferSetupError> {
    let config = TransferConfig {
        limits: TransferLimits {
            max_records: settings.max_records,
            max_bytes: settings.max_bytes,
            max_messages: settings.max_messages,
            timeout: Some(Duration::from_millis(settings.timeout_ms)),
            decode: DecodeLimits::default(),
        },
        message_bytes: settings.message_bytes,
        tsig_every: settings.tsig_every,
        require_tsig: settings.require_tsig,
        allow_axfr_fallback: settings.allow_axfr_fallback,
    };
    config
        .validate()
        .map_err(|error| TransferSetupError::Config(error.to_string()))?;
    Ok(config)
}

/// Возвращает TSIG-ключ для NOTIFY-out, если он настроен.
pub(crate) fn notify_key(
    settings: &TransferSettings,
    keys: &[TsigKeyConfig],
) -> Result<Option<Arc<TsigKey>>, TransferSetupError> {
    let Some(name) = &settings.notify_tsig_key else {
        return Ok(None);
    };
    let name = Name::parse(name.trim()).map_err(|error| TransferSetupError::Secret {
        name: name.clone(),
        reason: error.to_string(),
    })?;
    let map = build_keys(keys)?;
    map.get(&name)
        .cloned()
        .map(Some)
        .ok_or_else(|| TransferSetupError::Config(format!("notify key {name} is not configured")))
}

fn build_keys(keys: &[TsigKeyConfig]) -> Result<HashMap<Name, Arc<TsigKey>>, TransferSetupError> {
    let mut map = HashMap::with_capacity(keys.len());
    for config in keys {
        let name = Name::parse(config.name.trim()).map_err(|error| TransferSetupError::Secret {
            name: config.name.clone(),
            reason: error.to_string(),
        })?;
        let algorithm = parse_tsig_algorithm(&config.algorithm)
            .map_err(|error| TransferSetupError::Config(error.to_string()))?;
        let secret =
            STANDARD
                .decode(config.secret.trim())
                .map_err(|error| TransferSetupError::Secret {
                    name: name.to_string(),
                    reason: error.to_string(),
                })?;
        let key = TsigKey::new(name.clone(), algorithm, secret).map_err(|source| {
            TransferSetupError::Key {
                name: name.to_string(),
                source,
            }
        })?;
        map.insert(name, Arc::new(key));
    }
    Ok(map)
}

fn build_zone(zone: &pulse_api::ZoneSnapshot) -> Option<ZoneSnapshot> {
    if zone.kind != ZoneKind::Primary {
        return None;
    }
    let mut records = Vec::new();
    for rrset in &zone.rrsets {
        for rdata in rrset.rdatas() {
            match Record::new(
                rrset.owner().clone(),
                rrset.rr_type(),
                rrset.class(),
                rrset.ttl(),
                rdata.clone(),
            ) {
                Ok(record) => records.push(record),
                Err(error) => {
                    logging::error(
                        "transfer",
                        &format!("zone {}: cannot build record: {error}", zone.origin),
                    );
                    return None;
                }
            }
        }
    }
    match ZoneSnapshot::new(zone.origin.clone(), records) {
        Ok(snapshot) => Some(snapshot),
        Err(error) => {
            logging::error(
                "transfer",
                &format!("zone {} cannot be transferred: {error}", zone.origin),
            );
            None
        }
    }
}

fn update_history(
    previous: &ZoneSnapshot,
    previous_history: &ZoneHistory,
    current: &ZoneSnapshot,
    max_deltas: usize,
) -> (ZoneHistory, bool) {
    let content_changed =
        previous.soa() != current.soa() || previous.records() != current.records();
    let previous_serial = previous.serial();
    let current_serial = current.serial();
    if previous_serial == current_serial {
        if content_changed {
            return (ZoneHistory::new(), true);
        }
        return (previous_history.clone(), false);
    }
    if current_serial.is_newer_than(previous_serial) != Some(true) {
        return (ZoneHistory::new(), content_changed);
    }
    let Some(delta) = make_delta(previous, current) else {
        return (ZoneHistory::new(), content_changed);
    };
    let mut history = ZoneHistory::new();
    let keep = max_deltas.saturating_sub(1);
    let start = previous_history.deltas().len().saturating_sub(keep);
    for old in previous_history.deltas().iter().skip(start) {
        if history.push(old.clone()).is_err() {
            return (ZoneHistory::new(), true);
        }
    }
    if let Err(error) = history.push(delta) {
        logging::error(
            "transfer",
            &format!("cannot append IXFR delta for {}: {error}", current.origin()),
        );
        return (ZoneHistory::new(), true);
    }
    (history, true)
}

fn make_delta(previous: &ZoneSnapshot, current: &ZoneSnapshot) -> Option<ZoneDelta> {
    let old_records: HashSet<&Record> = previous.records().iter().collect();
    let new_records: HashSet<&Record> = current.records().iter().collect();
    let deletions: Vec<Record> = previous
        .records()
        .iter()
        .filter(|record| !new_records.contains(*record))
        .cloned()
        .collect();
    let additions: Vec<Record> = current
        .records()
        .iter()
        .filter(|record| !old_records.contains(*record))
        .cloned()
        .collect();
    match ZoneDelta::new(
        previous.soa().clone(),
        current.soa().clone(),
        deletions,
        additions,
    ) {
        Ok(delta) => Some(delta),
        Err(error) => {
            logging::error(
                "transfer",
                &format!("cannot build IXFR delta for {}: {error}", current.origin()),
            );
            None
        }
    }
}

fn send_refusal<S: Write>(
    stream: &mut S,
    request: &Message,
    rcode: Rcode,
) -> Result<(), TransferError> {
    let mut response = Message::response(request);
    response.set_rcode(rcode);
    let bytes = response.encode(&EncodeOptions::default())?;
    write_message(stream, &bytes)
}

fn send_tsig_error<S: Write>(
    stream: &mut S,
    request: &Message,
    envelope: &pulse_transfer::TsigEnvelope,
    key: Option<&TsigKey>,
    now: u64,
    code: TsigErrorCode,
) -> Result<(), TransferError> {
    let bytes = build_tsig_error_response(
        request,
        Some(envelope.record()),
        key,
        Some(envelope.record().mac()),
        code,
        now,
    )?;
    write_message(stream, &bytes)
}

/// Поток с уже прочитанным запросом: сервер `pulse-transfer` читает кадр из
/// курсора, а ответы пишет в исходный TCP-поток.
struct Rewound<'a, S> {
    input: Cursor<Vec<u8>>,
    output: &'a mut S,
}

impl<S: Read> Read for Rewound<'_, S> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.input.read(buffer)
    }
}

impl<S: Write> Write for Rewound<'_, S> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.output.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

struct NotifyJob {
    id: u16,
    zone: Name,
    soa: Option<Record>,
}

/// Фоновая очередь NOTIFY-out.
pub(crate) struct NotifyDispatcher {
    sender: SyncSender<NotifyJob>,
    stop: Arc<AtomicBool>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl NotifyDispatcher {
    /// Запускает фоновый поток отправки NOTIFY.
    pub(crate) fn start(
        settings: &TransferSettings,
        key: Option<Arc<TsigKey>>,
    ) -> io::Result<Self> {
        let (sender, receiver) = sync_channel(settings.notify_queue);
        let stop = Arc::new(AtomicBool::new(false));
        let targets = settings.notify.clone();
        let retries = settings.notify_retries;
        let timeout = Duration::from_millis(settings.notify_timeout_ms);
        let worker_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("pulse-notify".to_owned())
            .spawn(move || notify_loop(receiver, targets, key, retries, timeout, worker_stop))?;
        Ok(Self {
            sender,
            stop,
            handle: Mutex::new(Some(handle)),
        })
    }

    fn try_send(&self, job: NotifyJob) {
        match self.sender.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(job)) => logging::warn(
                "notify_out",
                &format!("queue is full; NOTIFY for {} dropped", job.zone),
            ),
            Err(TrySendError::Disconnected(job)) => logging::warn(
                "notify_out",
                &format!("worker is stopped; NOTIFY for {} dropped", job.zone),
            ),
        }
    }

    fn shutdown(&self) {
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

#[allow(clippy::needless_pass_by_value)]
fn notify_loop(
    receiver: Receiver<NotifyJob>,
    targets: Vec<SocketAddr>,
    key: Option<Arc<TsigKey>>,
    retries: u32,
    timeout: Duration,
    stop: Arc<AtomicBool>,
) {
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(job) => send_notify(&job, &targets, key.as_deref(), retries, timeout),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn send_notify(
    job: &NotifyJob,
    targets: &[SocketAddr],
    key: Option<&TsigKey>,
    retries: u32,
    timeout: Duration,
) {
    let request = match &job.soa {
        Some(soa) => match NotifyRequest::new(job.id, job.zone.clone()).with_soa(soa.clone()) {
            Ok(request) => request,
            Err(error) => {
                logging::error(
                    "notify_out",
                    &format!("cannot build NOTIFY for {}: {error}", job.zone),
                );
                return;
            }
        },
        None => NotifyRequest::new(job.id, job.zone.clone()),
    };
    for target in targets {
        let socket = match UdpSocket::bind(bind_address(*target)) {
            Ok(socket) => socket,
            Err(error) => {
                logging::warn(
                    "notify_out",
                    &format!("cannot bind NOTIFY socket for {target}: {error}"),
                );
                continue;
            }
        };
        let _ = socket.set_write_timeout(Some(timeout));
        let mut sent = false;
        for attempt in 0..=retries {
            let now = now_unix();
            let encoded = match request.encode(key, now) {
                Ok(encoded) => encoded,
                Err(error) => {
                    logging::error(
                        "notify_out",
                        &format!("cannot encode NOTIFY for {}: {error}", job.zone),
                    );
                    return;
                }
            };
            match socket.send_to(&encoded.bytes, *target) {
                Ok(_) => {
                    sent = true;
                    break;
                }
                Err(error) if attempt < retries => logging::warn(
                    "notify_out",
                    &format!(
                        "NOTIFY for {} to {target} failed (attempt {}): {error}",
                        job.zone,
                        attempt.saturating_add(1)
                    ),
                ),
                Err(error) => logging::warn(
                    "notify_out",
                    &format!("NOTIFY for {} to {target} failed: {error}", job.zone),
                ),
            }
        }
        if sent {
            logging::info(
                "notify_out",
                &format!("NOTIFY for {} sent to {target}", job.zone),
            );
        }
    }
}

fn bind_address(target: SocketAddr) -> SocketAddr {
    if target.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    }
}

fn next_notify_id() -> u16 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let value = NEXT.fetch_add(1, Ordering::Relaxed);
    let time = now_unix();
    u16::try_from((value ^ time) & 0xFFFF).unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use pulse_dns::{Rclass, Rdata, SoaData, Ttl};

    use super::*;

    fn origin() -> Name {
        Name::parse("example.com.").expect("origin")
    }

    fn snapshot(serial: u32, last_octet: u8) -> ZoneSnapshot {
        let ttl = Ttl::new(300).expect("ttl");
        let soa = Record::new(
            origin(),
            Rtype::SOA,
            Rclass::IN,
            ttl,
            Rdata::Soa(SoaData::new(
                Name::parse("ns1.example.com.").expect("mname"),
                Name::parse("hostmaster.example.com.").expect("rname"),
                Serial::new(serial),
                7200,
                900,
                1_209_600,
                300,
            )),
        )
        .expect("soa");
        let ns = Record::new(
            origin(),
            Rtype::NS,
            Rclass::IN,
            ttl,
            Rdata::Ns(Name::parse("ns1.example.com.").expect("ns")),
        )
        .expect("ns");
        let a = Record::new(
            Name::parse("www.example.com.").expect("owner"),
            Rtype::A,
            Rclass::IN,
            ttl,
            Rdata::A(Ipv4Addr::new(192, 0, 2, last_octet)),
        )
        .expect("a");
        ZoneSnapshot::new(origin(), [soa, ns, a]).expect("snapshot")
    }

    #[test]
    fn history_is_bounded_and_contiguous() {
        let mut previous = snapshot(1, 1);
        let mut history = ZoneHistory::new();
        for serial in 2..=10 {
            let current = snapshot(serial, u8::try_from(serial).expect("octet"));
            let (next, changed) = update_history(&previous, &history, &current, 3);
            assert!(changed);
            history = next;
            assert!(history.deltas().len() <= 3);
            previous = current;
        }
        assert_eq!(history.latest_serial(), Some(Serial::new(10)));
        let first = history.deltas().first().expect("first delta");
        assert_eq!(first.from(), Serial::new(7));
        assert!(
            history
                .path_from(Serial::new(7))
                .is_some_and(|path| path.len() == 3)
        );
        assert!(history.path_from(Serial::new(2)).is_none());
    }

    #[test]
    fn unchanged_serial_with_new_data_drops_history() {
        let previous = snapshot(5, 1);
        let current = snapshot(5, 2);
        let history = ZoneHistory::new();
        let (history, changed) = update_history(&previous, &history, &current, 8);
        assert!(changed);
        assert_eq!(history.deltas().len(), 0);
    }
}
