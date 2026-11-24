//! IXFR: инкрементальный трансфер зоны (RFC 1995) с fallback на AXFR.

use std::io::{Read, Write};

use pulse_dns::{EncodeOptions, Message, Name, Question, Rclass, Rcode, Record, Rtype, Serial};

use crate::error::{TransferError, TsigError};
use crate::net::{read_message, write_message};
use crate::server::{
    AuthResult, TransferStats, authenticate_request, build_stream, check_request_limits,
    refusal_response, validate_query,
};
use crate::stream::ResponseReader;
use crate::tsig::{TsigKey, append_tsig};
use crate::zone::{
    Deadline, TransferConfig, TransferLimits, ZoneSnapshot, apply_deltas, soa_serial,
};

/// Одна дельта IXFR: `[old SOA, deletions..., new SOA, additions...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneDelta {
    from: Serial,
    to: Serial,
    old_soa: Record,
    new_soa: Record,
    deletions: Vec<Record>,
    additions: Vec<Record>,
}

impl ZoneDelta {
    /// Создаёт и валидирует дельту.
    ///
    /// # Errors
    ///
    /// [`TransferError::Serial`] при неверной последовательности serial или
    /// [`TransferError::Zone`] при некорректных записях.
    pub fn new(
        old_soa: Record,
        new_soa: Record,
        deletions: impl IntoIterator<Item = Record>,
        additions: impl IntoIterator<Item = Record>,
    ) -> Result<Self, TransferError> {
        let from = soa_serial(&old_soa).ok_or(TransferError::serial("old record is not SOA"))?;
        let to = soa_serial(&new_soa).ok_or(TransferError::serial("new record is not SOA"))?;
        if old_soa.owner() != new_soa.owner() {
            return Err(TransferError::serial(
                "old and new SOA have different owners",
            ));
        }
        if old_soa.class() != Rclass::IN || new_soa.class() != Rclass::IN {
            return Err(TransferError::zone("IXFR delta SOA must be class IN"));
        }
        if to.is_newer_than(from) != Some(true) {
            return Err(TransferError::serial(
                "new SOA serial is not newer than old SOA serial",
            ));
        }
        let origin = old_soa.owner().clone();
        let deletions: Vec<Record> = deletions.into_iter().collect();
        let additions: Vec<Record> = additions.into_iter().collect();
        validate_delta_records(&origin, &deletions)?;
        validate_delta_records(&origin, &additions)?;
        Ok(Self {
            from,
            to,
            old_soa,
            new_soa,
            deletions,
            additions,
        })
    }

    /// Serial «до».
    #[must_use]
    pub const fn from(&self) -> Serial {
        self.from
    }

    /// Serial «после».
    #[must_use]
    pub const fn to(&self) -> Serial {
        self.to
    }

    /// Старая SOA.
    #[must_use]
    pub const fn old_soa(&self) -> &Record {
        &self.old_soa
    }

    /// Новая SOA.
    #[must_use]
    pub const fn new_soa(&self) -> &Record {
        &self.new_soa
    }

    /// Удалённые записи (без SOA).
    #[must_use]
    pub fn deletions(&self) -> &[Record] {
        &self.deletions
    }

    /// Добавленные записи (без SOA).
    #[must_use]
    pub fn additions(&self) -> &[Record] {
        &self.additions
    }

    /// Последовательность записей дельты в wire-порядке RFC 1995.
    #[must_use]
    pub fn sequence(&self) -> Vec<Record> {
        let mut records = Vec::with_capacity(self.deletions.len() + self.additions.len() + 2);
        records.push(self.old_soa.clone());
        records.extend(self.deletions.iter().cloned());
        records.push(self.new_soa.clone());
        records.extend(self.additions.iter().cloned());
        records
    }

    /// Суммарная каноническая длина записей дельты.
    ///
    /// # Errors
    ///
    /// [`TransferError::Record`] при некорректной записи.
    pub fn encoded_len(&self) -> Result<usize, TransferError> {
        let mut total = 0_usize;
        for record in self.sequence() {
            total = total.saturating_add(record.to_canonical_wire()?.len());
        }
        Ok(total)
    }
}

fn validate_delta_records(origin: &Name, records: &[Record]) -> Result<(), TransferError> {
    for record in records {
        record.validate()?;
        if record.class() != Rclass::IN {
            return Err(TransferError::zone("only class IN is supported"));
        }
        if record.rr_type() == Rtype::SOA {
            return Err(TransferError::zone("SOA in the middle of an IXFR delta"));
        }
        if !record.owner().is_subdomain_of(origin) {
            return Err(TransferError::zone("delta record is outside the zone"));
        }
    }
    Ok(())
}

/// История дельт зоны (от старых к новым).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneHistory {
    deltas: Vec<ZoneDelta>,
}

impl ZoneHistory {
    /// Создаёт пустую историю.
    #[must_use]
    pub const fn new() -> Self {
        Self { deltas: Vec::new() }
    }

    /// Добавляет дельту, проверяя непрерывность.
    ///
    /// # Errors
    ///
    /// [`TransferError::Serial`], если дельта не продолжает предыдущую.
    pub fn push(&mut self, delta: ZoneDelta) -> Result<(), TransferError> {
        if let Some(last) = self.deltas.last()
            && delta.from != last.to
        {
            return Err(TransferError::serial(
                "IXFR history is not contiguous at the new delta",
            ));
        }
        self.deltas.push(delta);
        Ok(())
    }

    /// Все дельты.
    #[must_use]
    pub fn deltas(&self) -> &[ZoneDelta] {
        &self.deltas
    }

    /// Последний serial истории.
    #[must_use]
    pub fn latest_serial(&self) -> Option<Serial> {
        self.deltas.last().map(ZoneDelta::to)
    }

    /// Путь дельт от `from` до последней версии.
    ///
    /// `None`, если версия неизвестна.
    #[must_use]
    pub fn path_from(&self, from: Serial) -> Option<&[ZoneDelta]> {
        if let Some(last) = self.deltas.last()
            && from == last.to
        {
            return self.deltas.get(self.deltas.len()..);
        }
        let start = self.deltas.iter().position(|delta| delta.from == from)?;
        self.deltas.get(start..)
    }
}

/// Результат IXFR-клиента.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IxfrOutcome {
    /// У клиента уже актуальная версия.
    UpToDate {
        /// Текущая SOA сервера.
        soa: Record,
    },
    /// Инкрементальные дельты.
    Incremental {
        /// Версия клиента.
        from: Serial,
        /// Текущая SOA сервера.
        current: Record,
        /// Дельта(ы) от `from` до текущей версии.
        deltas: Vec<ZoneDelta>,
    },
    /// Сервер отдал полную зону (fallback).
    AxfrFallback {
        /// Полная зона.
        zone: ZoneSnapshot,
    },
}

/// IXFR-клиент.
pub struct IxfrClient<S> {
    stream: S,
    limits: TransferLimits,
}

impl<S> IxfrClient<S> {
    /// Создаёт клиент.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            limits: TransferLimits::default(),
        }
    }

    /// Создаёт клиент с лимитами.
    pub fn with_limits(stream: S, limits: TransferLimits) -> Self {
        Self { stream, limits }
    }

    /// Возвращает вложенный поток.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> IxfrClient<S> {
    /// Выполняет IXFR от версии `client_soa`.
    ///
    /// # Errors
    ///
    /// [`TransferError`] при ошибке транспорта, TSIG, формата дельт или лимитов.
    pub fn transfer(
        &mut self,
        origin: &Name,
        client_soa: &Record,
        id: u16,
        key: Option<&TsigKey>,
        now: u64,
    ) -> Result<IxfrOutcome, TransferError> {
        if client_soa.rr_type() != Rtype::SOA || client_soa.owner() != origin {
            return Err(TransferError::protocol(
                "client SOA must be the zone apex SOA",
            ));
        }
        let client_serial =
            soa_serial(client_soa).ok_or(TransferError::serial("client record is not SOA"))?;
        let base = ixfr_query(id, origin, client_soa).encode(&EncodeOptions::default())?;
        let (wire, request_mac) = match key {
            Some(key) => {
                let record = key.sign_request(&base, id, now)?;
                (append_tsig(base, &record)?, Some(record.mac().to_vec()))
            }
            None => (base, None),
        };
        write_message(&mut self.stream, &wire)?;

        let mut reader = ResponseReader::new(&mut self.stream, self.limits, key, request_mac, id);
        let mut parser = IxfrParser::new(origin.clone(), client_serial);
        let mut records_seen = 0_usize;
        let mut first_message = true;
        let mut done = false;

        while !done {
            let response = match reader.next(now) {
                Ok(response) => response,
                Err(TransferError::Io(error))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    return Err(TransferError::Truncated {
                        reason: "IXFR stream ended before the final SOA",
                    });
                }
                Err(error) => return Err(error),
            };
            let tsig_error = response
                .tsig
                .as_ref()
                .map(crate::tsig::TsigRecord::error)
                .filter(|code| code.is_error());
            if response.message.rcode() != Rcode::NOERROR || tsig_error.is_some() {
                return Err(TransferError::Server {
                    rcode: response.message.rcode(),
                    tsig_error,
                });
            }
            let answers = response.message.answers();
            if answers.is_empty() {
                return Err(TransferError::protocol("empty IXFR response message"));
            }
            for (index, record) in answers.iter().enumerate() {
                records_seen = records_seen.saturating_add(1);
                crate::zone::check_record_limit(&self.limits, records_seen)?;
                parser.push(record.clone(), index.saturating_add(1) == answers.len())?;
            }
            if first_message && answers.len() == 1 {
                parser.mark_up_to_date();
            }
            first_message = false;
            if parser.is_done() {
                if key.is_some() && response.tsig.is_none() {
                    return Err(TransferError::Tsig(TsigError::Missing));
                }
                done = true;
            }
        }
        parser.finish()
    }
}

fn ixfr_query(id: u16, origin: &Name, client_soa: &Record) -> Message {
    let mut message = Message::query(id, Question::new(origin.clone(), Rtype::IXFR, Rclass::IN));
    message.add_authority(client_soa.clone());
    message
}

/// Строит wire-запрос IXFR.
///
/// # Errors
///
/// [`TransferError::Encode`].
pub fn build_ixfr_query(
    id: u16,
    origin: &Name,
    client_soa: &Record,
) -> Result<Vec<u8>, TransferError> {
    Ok(ixfr_query(id, origin, client_soa).encode(&EncodeOptions::default())?)
}

/// IXFR-сервер.
pub struct IxfrServer {
    config: TransferConfig,
}

impl IxfrServer {
    /// Создаёт сервер.
    #[must_use]
    pub const fn new(config: TransferConfig) -> Self {
        Self { config }
    }

    /// Возвращает конфигурацию.
    #[must_use]
    pub const fn config(&self) -> &TransferConfig {
        &self.config
    }

    /// Обслуживает один IXFR-запрос.
    ///
    /// # Errors
    ///
    /// [`TransferError`] при ошибке запроса, TSIG, транспорта или лимитов.
    pub fn serve<S: Read + Write>(
        &self,
        stream: &mut S,
        current: &ZoneSnapshot,
        history: &ZoneHistory,
        key: Option<&TsigKey>,
        now: u64,
    ) -> Result<TransferStats, TransferError> {
        self.config.validate()?;
        let raw = read_message(stream)?;
        check_request_limits(&self.config.limits, raw.len())?;
        let request = Message::decode(&raw, &self.config.limits.decode)?;

        if let Err(error) = validate_query(&request, Rtype::IXFR, current.origin(), false) {
            let response = refusal_response(&request, Rcode::NOTAUTH)?;
            write_message(stream, &response)?;
            return Err(error);
        }
        if let Err(error) = client_soa_from_request(&request, current.origin()) {
            let response = refusal_response(&request, Rcode::FORMERR)?;
            write_message(stream, &response)?;
            return Err(error);
        }

        let credentials = match authenticate_request(&self.config, &raw, &request, key, now)? {
            AuthResult::Ok(credentials) => credentials,
            AuthResult::Reject { response, error } => {
                write_message(stream, &response)?;
                return Err(error);
            }
        };

        let signing_key = if credentials.request_mac.is_some() {
            key
        } else {
            None
        };
        let (messages, stats) = self.build_messages(
            &request,
            current,
            history,
            signing_key,
            credentials.request_mac.as_deref(),
            now,
        )?;
        let deadline = Deadline::new(&self.config.limits);
        for message in &messages {
            deadline.check()?;
            write_message(stream, message)?;
        }
        Ok(stats)
    }

    /// Строит подписанные сообщения IXFR без записи в поток.
    ///
    /// # Errors
    ///
    /// [`TransferError`] при некорректном запросе, fallback-политике или
    /// кодировании.
    pub fn build_messages(
        &self,
        request: &Message,
        current: &ZoneSnapshot,
        history: &ZoneHistory,
        key: Option<&TsigKey>,
        request_mac: Option<&[u8]>,
        now: u64,
    ) -> Result<(Vec<Vec<u8>>, TransferStats), TransferError> {
        let client_soa = client_soa_from_request(request, current.origin())?;
        let client_serial =
            soa_serial(&client_soa).ok_or(TransferError::serial("client record is not SOA"))?;
        let current_serial = current.serial();
        let answers = self.select_answers(current, history, client_serial, current_serial)?;
        build_stream(request, &answers, &self.config, key, request_mac, now)
    }

    fn select_answers(
        &self,
        current: &ZoneSnapshot,
        history: &ZoneHistory,
        client_serial: Serial,
        current_serial: Serial,
    ) -> Result<Vec<Record>, TransferError> {
        match client_serial.cmp_rfc1982(current_serial) {
            Some(std::cmp::Ordering::Equal | std::cmp::Ordering::Greater) => {
                Ok(vec![current.soa().clone()])
            }
            Some(std::cmp::Ordering::Less) => {
                let path = history.path_from(client_serial);
                if let Some(deltas) = path
                    && !deltas.is_empty()
                    && deltas.last().map(ZoneDelta::to) == Some(current_serial)
                {
                    let delta_size = deltas.iter().try_fold(0_usize, |total, delta| {
                        Ok::<usize, TransferError>(total.saturating_add(delta.encoded_len()?))
                    })?;
                    let full_size = current.encoded_len()?;
                    if !self.config.allow_axfr_fallback || delta_size < full_size {
                        let mut answers = Vec::new();
                        answers.push(current.soa().clone());
                        for delta in deltas {
                            answers.push(delta.old_soa().clone());
                            answers.extend(delta.deletions().iter().cloned());
                            answers.push(delta.new_soa().clone());
                            answers.extend(delta.additions().iter().cloned());
                        }
                        answers.push(current.soa().clone());
                        return Ok(answers);
                    }
                }
                if self.config.allow_axfr_fallback {
                    Ok(axfr_answers(current))
                } else {
                    Err(TransferError::protocol(
                        "IXFR history does not contain the client serial",
                    ))
                }
            }
            None => {
                if self.config.allow_axfr_fallback {
                    Ok(axfr_answers(current))
                } else {
                    Err(TransferError::serial(
                        "client serial is ambiguous under RFC 1982",
                    ))
                }
            }
        }
    }
}

fn axfr_answers(current: &ZoneSnapshot) -> Vec<Record> {
    let mut answers = Vec::with_capacity(current.records().len() + 2);
    answers.push(current.soa().clone());
    answers.extend(current.records().iter().cloned());
    answers.push(current.soa().clone());
    answers
}

fn client_soa_from_request(request: &Message, origin: &Name) -> Result<Record, TransferError> {
    if request.authority().len() != 1 {
        return Err(TransferError::protocol(
            "IXFR query must contain exactly one authority SOA",
        ));
    }
    let soa = request
        .authority()
        .first()
        .ok_or(TransferError::protocol("missing client SOA"))?;
    if soa.rr_type() != Rtype::SOA || soa.owner() != origin || soa.class() != Rclass::IN {
        return Err(TransferError::protocol(
            "IXFR authority record must be the zone apex SOA",
        ));
    }
    Ok(soa.clone())
}

/// Применяет дельты IXFR к снапшоту.
///
/// # Errors
///
/// [`TransferError`] при неверном serial или отсутствующей удаляемой записи.
pub fn apply_ixfr(
    base: &ZoneSnapshot,
    deltas: &[ZoneDelta],
) -> Result<ZoneSnapshot, TransferError> {
    apply_deltas(base, deltas)
}

enum IxfrPhase {
    Deletions {
        old_soa: Record,
        deletions: Vec<Record>,
    },
    Additions {
        old_soa: Record,
        new_soa: Record,
        deletions: Vec<Record>,
        additions: Vec<Record>,
    },
}

#[allow(clippy::large_enum_variant)]
enum IxfrState {
    AwaitFirst,
    AwaitSecond {
        first: Record,
    },
    Axfr {
        first: Record,
        records: Vec<Record>,
    },
    Ixfr {
        current: Record,
        phase: IxfrPhase,
    },
    UpToDate {
        soa: Record,
    },
    AxfrDone {
        records: Vec<Record>,
    },
    IxfrDone {
        current: Record,
        deltas: Vec<ZoneDelta>,
    },
}

struct IxfrParser {
    origin: Name,
    client_serial: Serial,
    deltas: Vec<ZoneDelta>,
    state: IxfrState,
}

impl IxfrParser {
    fn new(origin: Name, client_serial: Serial) -> Self {
        Self {
            origin,
            client_serial,
            deltas: Vec::new(),
            state: IxfrState::AwaitFirst,
        }
    }

    fn is_done(&self) -> bool {
        matches!(
            self.state,
            IxfrState::UpToDate { .. } | IxfrState::AxfrDone { .. } | IxfrState::IxfrDone { .. }
        )
    }

    fn mark_up_to_date(&mut self) {
        match core::mem::replace(&mut self.state, IxfrState::AwaitFirst) {
            IxfrState::AwaitSecond { first } => {
                self.state = IxfrState::UpToDate { soa: first };
            }
            other => self.state = other,
        }
    }

    fn push(&mut self, record: Record, is_last: bool) -> Result<(), TransferError> {
        match core::mem::replace(&mut self.state, IxfrState::AwaitFirst) {
            IxfrState::AwaitFirst => {
                if record.rr_type() != Rtype::SOA || record.owner() != &self.origin {
                    return Err(TransferError::protocol(
                        "IXFR response must start with the zone SOA",
                    ));
                }
                self.state = IxfrState::AwaitSecond { first: record };
            }
            IxfrState::AwaitSecond { first } => {
                if record.rr_type() == Rtype::SOA {
                    if record == first {
                        if !is_last {
                            return Err(TransferError::protocol(
                                "empty AXFR closing SOA is not the last record",
                            ));
                        }
                        self.state = IxfrState::AxfrDone {
                            records: vec![first, record],
                        };
                    } else {
                        let old_serial = soa_serial(&record)
                            .ok_or(TransferError::serial("IXFR old record is not SOA"))?;
                        if old_serial != self.client_serial {
                            return Err(TransferError::serial(
                                "IXFR old SOA does not match the client serial",
                            ));
                        }
                        self.state = IxfrState::Ixfr {
                            current: first,
                            phase: IxfrPhase::Deletions {
                                old_soa: record,
                                deletions: Vec::new(),
                            },
                        };
                    }
                } else {
                    self.state = IxfrState::Axfr {
                        first: first.clone(),
                        records: vec![first, record],
                    };
                }
            }
            IxfrState::Axfr { first, mut records } => {
                if record.rr_type() == Rtype::SOA {
                    if record != first {
                        return Err(TransferError::protocol(
                            "AXFR fallback closing SOA does not match the opening SOA",
                        ));
                    }
                    if !is_last {
                        return Err(TransferError::protocol(
                            "AXFR fallback closing SOA is not the last record",
                        ));
                    }
                    self.state = IxfrState::AxfrDone { records };
                } else {
                    records.push(record);
                    self.state = IxfrState::Axfr { first, records };
                }
            }
            IxfrState::Ixfr { current, phase } => match phase {
                IxfrPhase::Deletions {
                    old_soa,
                    mut deletions,
                } => {
                    if record.rr_type() == Rtype::SOA {
                        let old_serial = soa_serial(&old_soa)
                            .ok_or(TransferError::serial("old record is not SOA"))?;
                        let new_serial = soa_serial(&record)
                            .ok_or(TransferError::serial("new record is not SOA"))?;
                        if new_serial.is_newer_than(old_serial) != Some(true) {
                            return Err(TransferError::serial(
                                "IXFR new SOA is not newer than old SOA",
                            ));
                        }
                        let current_serial = soa_serial(&current)
                            .ok_or(TransferError::serial("current record is not SOA"))?;
                        if current_serial.cmp_rfc1982(new_serial) == Some(std::cmp::Ordering::Less)
                        {
                            return Err(TransferError::serial(
                                "IXFR delta is newer than the current zone",
                            ));
                        }
                        self.state = IxfrState::Ixfr {
                            current,
                            phase: IxfrPhase::Additions {
                                old_soa,
                                new_soa: record,
                                deletions,
                                additions: Vec::new(),
                            },
                        };
                    } else {
                        additions_check(&record, &old_soa)?;
                        deletions.push(record);
                        self.state = IxfrState::Ixfr {
                            current,
                            phase: IxfrPhase::Deletions { old_soa, deletions },
                        };
                    }
                }
                IxfrPhase::Additions {
                    old_soa,
                    new_soa,
                    deletions,
                    mut additions,
                } => {
                    if record.rr_type() == Rtype::SOA {
                        let new_serial = soa_serial(&new_soa)
                            .ok_or(TransferError::serial("new record is not SOA"))?;
                        let current_serial = soa_serial(&current)
                            .ok_or(TransferError::serial("current record is not SOA"))?;
                        if record == current && new_serial == current_serial {
                            if !is_last {
                                return Err(TransferError::protocol(
                                    "IXFR final SOA is not the last record",
                                ));
                            }
                            let delta = ZoneDelta::new(old_soa, new_soa, deletions, additions)?;
                            self.deltas.push(delta);
                            self.state = IxfrState::IxfrDone {
                                current,
                                deltas: core::mem::take(&mut self.deltas),
                            };
                        } else if soa_serial(&record) == Some(new_serial) {
                            let delta = ZoneDelta::new(old_soa, new_soa, deletions, additions)?;
                            self.deltas.push(delta);
                            self.state = IxfrState::Ixfr {
                                current,
                                phase: IxfrPhase::Deletions {
                                    old_soa: record,
                                    deletions: Vec::new(),
                                },
                            };
                        } else {
                            return Err(TransferError::serial(
                                "IXFR delta sequence is not contiguous",
                            ));
                        }
                    } else {
                        additions_check(&record, &current)?;
                        additions.push(record);
                        self.state = IxfrState::Ixfr {
                            current,
                            phase: IxfrPhase::Additions {
                                old_soa,
                                new_soa,
                                deletions,
                                additions,
                            },
                        };
                    }
                }
            },
            IxfrState::UpToDate { .. }
            | IxfrState::AxfrDone { .. }
            | IxfrState::IxfrDone { .. } => {
                return Err(TransferError::protocol("IXFR record after the final SOA"));
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<IxfrOutcome, TransferError> {
        match core::mem::replace(&mut self.state, IxfrState::AwaitFirst) {
            IxfrState::UpToDate { soa } => Ok(IxfrOutcome::UpToDate { soa }),
            IxfrState::AxfrDone { records } => {
                let zone = ZoneSnapshot::new(self.origin, records)?;
                Ok(IxfrOutcome::AxfrFallback { zone })
            }
            IxfrState::IxfrDone { current, deltas } => Ok(IxfrOutcome::Incremental {
                from: self.client_serial,
                current,
                deltas,
            }),
            _ => Err(TransferError::Truncated {
                reason: "IXFR response ended before the final SOA",
            }),
        }
    }
}

fn additions_check(record: &Record, soa: &Record) -> Result<(), TransferError> {
    if record.class() != Rclass::IN {
        return Err(TransferError::zone("IXFR addition must be class IN"));
    }
    if !record.owner().is_subdomain_of(soa.owner()) {
        return Err(TransferError::zone("IXFR addition is outside the zone"));
    }
    Ok(())
}
