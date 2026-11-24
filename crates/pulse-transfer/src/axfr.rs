//! AXFR: полный трансфер зоны (RFC 5936).
//!
//! Клиент [`AxfrClient`] работает поверх любых синхронных `Read + Write`
//! (TCP или in-memory pipe), сервер [`AxfrServer`] отдаёт [`ZoneSnapshot`]
//! блоками с корректными counts, SOA first/last и TSIG.

use std::io::{Read, Write};

use pulse_dns::{EncodeOptions, Message, Name, Question, Rclass, Rcode, Record, Rtype};

use crate::error::{TransferError, TsigError};
use crate::net::{read_message, write_message};
use crate::server::{
    AuthResult, TransferStats, authenticate_request, build_stream, check_request_limits,
    refusal_response, validate_query,
};
use crate::stream::ResponseReader;
use crate::tsig::{TsigKey, append_tsig};
use crate::zone::{Deadline, TransferConfig, TransferLimits, ZoneSnapshot, check_record_limit};

/// Клиент AXFR.
pub struct AxfrClient<S> {
    stream: S,
    limits: TransferLimits,
}

impl<S> AxfrClient<S> {
    /// Создаёт клиент с лимитами по умолчанию.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            limits: TransferLimits::default(),
        }
    }

    /// Создаёт клиент с явными лимитами.
    pub fn with_limits(stream: S, limits: TransferLimits) -> Self {
        Self { stream, limits }
    }

    /// Возвращает вложенный поток.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> AxfrClient<S> {
    /// Выполняет AXFR зоны `origin`.
    ///
    /// # Errors
    ///
    /// [`TransferError`] при ошибке транспорта, TSIG, протокола или лимитов.
    pub fn transfer(
        &mut self,
        origin: &Name,
        id: u16,
        key: Option<&TsigKey>,
        now: u64,
    ) -> Result<ZoneSnapshot, TransferError> {
        let base = axfr_query(id, origin).encode(&EncodeOptions::default())?;
        let (wire, request_mac) = match key {
            Some(key) => {
                let record = key.sign_request(&base, id, now)?;
                (append_tsig(base, &record)?, Some(record.mac().to_vec()))
            }
            None => (base, None),
        };
        write_message(&mut self.stream, &wire)?;

        let mut reader = ResponseReader::new(&mut self.stream, self.limits, key, request_mac, id);
        let mut records: Vec<Record> = Vec::new();
        let mut first_soa: Option<Record> = None;
        let mut done = false;

        while !done {
            let response = match reader.next(now) {
                Ok(response) => response,
                Err(TransferError::Io(error))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    return Err(TransferError::Truncated {
                        reason: "AXFR stream ended before the closing SOA",
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
                return Err(TransferError::protocol("empty AXFR response message"));
            }
            for (index, record) in answers.iter().enumerate() {
                if done {
                    return Err(TransferError::protocol("AXFR record after the closing SOA"));
                }
                check_record_limit(&self.limits, records.len().saturating_add(1))?;
                if first_soa.is_none() {
                    if record.rr_type() != Rtype::SOA || record.owner() != origin {
                        return Err(TransferError::protocol(
                            "AXFR response must start with the zone SOA",
                        ));
                    }
                    first_soa = Some(record.clone());
                } else if record.rr_type() == Rtype::SOA {
                    let opening = first_soa
                        .as_ref()
                        .ok_or(TransferError::protocol("AXFR opening SOA is missing"))?;
                    if record != opening {
                        return Err(TransferError::protocol(
                            "AXFR closing SOA does not match the opening SOA",
                        ));
                    }
                    if index.saturating_add(1) != answers.len() {
                        return Err(TransferError::protocol(
                            "AXFR closing SOA is not the last record of its message",
                        ));
                    }
                    done = true;
                }
                records.push(record.clone());
            }
            if done && key.is_some() && response.tsig.is_none() {
                return Err(TransferError::Tsig(TsigError::Missing));
            }
        }

        ZoneSnapshot::new(origin.clone(), records)
    }
}

fn axfr_query(id: u16, origin: &Name) -> Message {
    Message::query(id, Question::new(origin.clone(), Rtype::AXFR, Rclass::IN))
}

/// Строит wire-запрос AXFR без TSIG.
///
/// # Errors
///
/// [`TransferError::Encode`] при ошибке кодирования.
pub fn build_axfr_query(id: u16, origin: &Name) -> Result<Vec<u8>, TransferError> {
    Ok(axfr_query(id, origin).encode(&EncodeOptions::default())?)
}

/// Строит wire-запрос AXFR, опционально подписанный TSIG.
///
/// # Errors
///
/// [`TransferError`] при ошибке кодирования или TSIG.
pub fn build_signed_axfr_query(
    id: u16,
    origin: &Name,
    key: Option<&TsigKey>,
    now: u64,
) -> Result<(Vec<u8>, Option<Vec<u8>>), TransferError> {
    let base = build_axfr_query(id, origin)?;
    match key {
        Some(key) => {
            let record = key.sign_request(&base, id, now)?;
            Ok((append_tsig(base, &record)?, Some(record.mac().to_vec())))
        }
        None => Ok((base, None)),
    }
}

/// Сервер AXFR.
pub struct AxfrServer {
    config: TransferConfig,
}

impl AxfrServer {
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

    /// Обслуживает один AXFR-запрос из `stream`.
    ///
    /// # Errors
    ///
    /// [`TransferError`] при ошибке запроса, TSIG, транспорта или лимитов.
    /// Перед возвратом ошибки сервер, если возможно, отправляет корректный
    /// отказ или TSIG error response.
    pub fn serve<S: Read + Write>(
        &self,
        stream: &mut S,
        snapshot: &ZoneSnapshot,
        key: Option<&TsigKey>,
        now: u64,
    ) -> Result<TransferStats, TransferError> {
        self.config.validate()?;
        let raw = read_message(stream)?;
        check_request_limits(&self.config.limits, raw.len())?;
        let request = Message::decode(&raw, &self.config.limits.decode)?;

        if let Err(error) = validate_query(&request, Rtype::AXFR, snapshot.origin(), true) {
            let response = refusal_response(&request, Rcode::NOTAUTH)?;
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
            snapshot,
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

    /// Строит подписанные сообщения AXFR без записи в поток.
    ///
    /// Вызывающий обязан сам аутентифицировать запрос и передать его MAC.
    ///
    /// # Errors
    ///
    /// [`TransferError`] при кодировании или превышении лимитов.
    pub fn build_messages(
        &self,
        request: &Message,
        snapshot: &ZoneSnapshot,
        key: Option<&TsigKey>,
        request_mac: Option<&[u8]>,
        now: u64,
    ) -> Result<(Vec<Vec<u8>>, TransferStats), TransferError> {
        let mut answers = Vec::with_capacity(snapshot.records().len() + 2);
        answers.push(snapshot.soa().clone());
        answers.extend(snapshot.records().iter().cloned());
        answers.push(snapshot.soa().clone());
        build_stream(request, &answers, &self.config, key, request_mac, now)
    }
}
