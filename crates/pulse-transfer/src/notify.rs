//! NOTIFY (RFC 1996): построение, разбор, ответ, policy и TSIG.

use std::net::IpAddr;

use pulse_dns::{
    EncodeOptions, Flags, Message, Name, Opcode, Question, Rclass, Rcode, Record, Rtype, Serial,
};

use crate::error::{TransferError, TsigError, TsigErrorCode};
use crate::tsig::{TsigEnvelope, TsigKey, append_tsig, build_tsig_error_response, parse_tsig};
use crate::zone::soa_serial;

/// Закодированный NOTIFY-запрос вместе с request MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedNotify {
    /// Wire-сообщение.
    pub bytes: Vec<u8>,
    /// MAC запроса, если он был подписан.
    pub request_mac: Option<Vec<u8>>,
}

/// NOTIFY-запрос.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotifyRequest {
    id: u16,
    zone: Name,
    class: Rclass,
    soa: Option<Record>,
}

impl NotifyRequest {
    /// Создаёт запрос для зоны.
    #[must_use]
    pub fn new(id: u16, zone: Name) -> Self {
        Self {
            id,
            zone,
            class: Rclass::IN,
            soa: None,
        }
    }

    /// Добавляет SOA-hint.
    ///
    /// # Errors
    ///
    /// [`TransferError::Protocol`], если запись не является apex SOA зоны.
    pub fn with_soa(mut self, soa: Record) -> Result<Self, TransferError> {
        if soa.rr_type() != Rtype::SOA || soa.owner() != &self.zone || soa.class() != Rclass::IN {
            return Err(TransferError::protocol(
                "NOTIFY hint must be the zone apex SOA",
            ));
        }
        self.soa = Some(soa);
        Ok(self)
    }

    /// ID.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// Зона.
    #[must_use]
    pub const fn zone(&self) -> &Name {
        &self.zone
    }

    /// Класс.
    #[must_use]
    pub const fn class(&self) -> Rclass {
        self.class
    }

    /// SOA-hint.
    #[must_use]
    pub const fn soa(&self) -> Option<&Record> {
        self.soa.as_ref()
    }

    /// Serial из SOA-hint.
    #[must_use]
    pub fn serial(&self) -> Option<Serial> {
        self.soa.as_ref().and_then(soa_serial)
    }

    /// Строит DNS-сообщение.
    #[must_use]
    pub fn to_message(&self) -> Message {
        let flags = Flags::new().with_opcode(Opcode::NOTIFY).with_aa(true);
        let mut message = Message::new(self.id, flags);
        message.add_question(Question::new(self.zone.clone(), Rtype::SOA, self.class));
        if let Some(soa) = &self.soa {
            message.add_answer(soa.clone());
        }
        message
    }

    /// Кодирует запрос, опционально подписывая TSIG.
    ///
    /// # Errors
    ///
    /// [`TransferError`] при кодировании или TSIG.
    pub fn encode(&self, key: Option<&TsigKey>, now: u64) -> Result<EncodedNotify, TransferError> {
        let base = self.to_message().encode(&EncodeOptions::default())?;
        match key {
            Some(key) => {
                let record = key.sign_request(&base, self.id, now)?;
                Ok(EncodedNotify {
                    bytes: append_tsig(base, &record)?,
                    request_mac: Some(record.mac().to_vec()),
                })
            }
            None => Ok(EncodedNotify {
                bytes: base,
                request_mac: None,
            }),
        }
    }

    /// Разбирает NOTIFY-запрос.
    ///
    /// # Errors
    ///
    /// [`TransferError::Protocol`] при нарушении формата, [`TransferError::Decode`]
    /// или ошибка TSIG.
    pub fn decode(raw: &[u8]) -> Result<(Self, Option<TsigEnvelope>), TransferError> {
        let message = Message::decode(raw, &pulse_dns::DecodeLimits::default())?;
        if message.flags().qr() {
            return Err(TransferError::protocol("NOTIFY request has QR=1"));
        }
        if message.opcode() != Opcode::NOTIFY {
            return Err(TransferError::protocol("message is not NOTIFY"));
        }
        if message.questions().len() != 1 {
            return Err(TransferError::protocol(
                "NOTIFY request must have one question",
            ));
        }
        let question = message
            .questions()
            .first()
            .ok_or(TransferError::protocol("missing NOTIFY question"))?;
        if question.qtype() != Rtype::SOA {
            return Err(TransferError::protocol("NOTIFY qtype must be SOA"));
        }
        if question.qclass() != Rclass::IN {
            return Err(TransferError::protocol("NOTIFY class must be IN"));
        }
        if message.answers().len() > 1 {
            return Err(TransferError::protocol(
                "NOTIFY may carry at most one SOA hint",
            ));
        }
        let soa = message.answers().first().cloned();
        if let Some(record) = &soa
            && (record.rr_type() != Rtype::SOA
                || record.owner() != question.qname()
                || record.class() != Rclass::IN)
        {
            return Err(TransferError::protocol(
                "NOTIFY hint must be the zone apex SOA",
            ));
        }
        let request = Self {
            id: message.id(),
            zone: question.qname().clone(),
            class: question.qclass(),
            soa,
        };
        let envelope = parse_tsig(raw)?;
        Ok((request, envelope))
    }
}

/// NOTIFY-ответ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyResponse {
    id: u16,
    rcode: Rcode,
}

impl NotifyResponse {
    /// Создаёт ответ.
    #[must_use]
    pub const fn new(id: u16, rcode: Rcode) -> Self {
        Self { id, rcode }
    }

    /// ID.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// RCODE.
    #[must_use]
    pub const fn rcode(&self) -> Rcode {
        self.rcode
    }

    /// Строит DNS-сообщение ответа.
    #[must_use]
    pub fn to_message(&self, request: &NotifyRequest) -> Message {
        let flags = Flags::new()
            .with_qr(true)
            .with_aa(true)
            .with_opcode(Opcode::NOTIFY);
        let mut message = Message::new(self.id, flags);
        message.add_question(Question::new(
            request.zone.clone(),
            Rtype::SOA,
            request.class,
        ));
        message.set_rcode(self.rcode);
        message
    }

    /// Кодирует ответ, опционально подписывая TSIG.
    ///
    /// # Errors
    ///
    /// [`TransferError`] при кодировании или TSIG.
    pub fn encode(
        &self,
        request: &NotifyRequest,
        key: Option<&TsigKey>,
        request_mac: Option<&[u8]>,
        now: u64,
    ) -> Result<Vec<u8>, TransferError> {
        let base = self.to_message(request).encode(&EncodeOptions::default())?;
        match key {
            Some(key) => {
                let request_mac = request_mac.ok_or(TransferError::Tsig(TsigError::Missing))?;
                let record = key.sign_response(&base, request_mac, request.id, now)?;
                Ok(append_tsig(base, &record)?)
            }
            None => Ok(base),
        }
    }

    /// Разбирает и проверяет ответ.
    ///
    /// # Errors
    ///
    /// [`TransferError::Protocol`] при нарушении формата, [`TransferError`]
    /// при ошибке TSIG.
    pub fn decode(
        raw: &[u8],
        request: &NotifyRequest,
        request_mac: Option<&[u8]>,
        key: Option<&TsigKey>,
        now: u64,
    ) -> Result<(Self, Option<TsigEnvelope>), TransferError> {
        let message = Message::decode(raw, &pulse_dns::DecodeLimits::default())?;
        if !message.flags().qr() {
            return Err(TransferError::protocol("NOTIFY response has QR=0"));
        }
        if message.opcode() != Opcode::NOTIFY {
            return Err(TransferError::protocol("message is not NOTIFY"));
        }
        if message.id() != request.id {
            return Err(TransferError::protocol("NOTIFY response ID mismatch"));
        }
        if message.questions().len() != 1 {
            return Err(TransferError::protocol(
                "NOTIFY response must have one question",
            ));
        }
        let question = message
            .questions()
            .first()
            .ok_or(TransferError::protocol("missing NOTIFY question"))?;
        if question.qtype() != Rtype::SOA
            || question.qclass() != request.class
            || question.qname() != &request.zone
        {
            return Err(TransferError::protocol("NOTIFY response question mismatch"));
        }
        let envelope = parse_tsig(raw)?;
        match (key, &envelope) {
            (Some(key), Some(envelope)) => {
                let request_mac = request_mac.ok_or(TransferError::Tsig(TsigError::Missing))?;
                key.verify_response_envelope(envelope, request_mac, request.id, now)?;
            }
            (Some(_), None) => return Err(TransferError::Tsig(TsigError::Missing)),
            (None, Some(_)) => return Err(TransferError::Tsig(TsigError::Unexpected)),
            (None, None) => {}
        }
        Ok((
            Self {
                id: message.id(),
                rcode: message.rcode(),
            },
            envelope,
        ))
    }
}

/// Политика приёма NOTIFY (SEC-REP-002).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NotifyPolicy {
    /// Разрешённые source IP; пустой список — любой.
    pub allowed_sources: Vec<IpAddr>,
    /// Обслуживаемые зоны; пустой список — любая.
    pub zones: Vec<Name>,
}

impl NotifyPolicy {
    /// Создаёт политику.
    #[must_use]
    pub fn new(allowed_sources: Vec<IpAddr>, zones: Vec<Name>) -> Self {
        Self {
            allowed_sources,
            zones,
        }
    }

    /// Разрешён ли source.
    #[must_use]
    pub fn allows_source(&self, source: IpAddr) -> bool {
        self.allowed_sources.is_empty() || self.allowed_sources.contains(&source)
    }

    /// Обслуживается ли зона.
    #[must_use]
    pub fn allows_zone(&self, zone: &Name) -> bool {
        self.zones.is_empty() || self.zones.contains(zone)
    }
}

/// Причина игнорирования NOTIFY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyIgnoreReason {
    /// Source не входит в ACL.
    SourceNotAllowed,
}

/// Результат обработки NOTIFY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifyOutcome {
    /// Запрос принят; `response` — готовые байты ответа.
    Accepted {
        /// Зона.
        zone: Name,
        /// Serial из hint.
        serial: Option<Serial>,
        /// Подписанный/неподписанный ответ.
        response: Vec<u8>,
    },
    /// Запрос отвергнут; ответ нужно отправить.
    Refused {
        /// Готовые байты ответа.
        response: Vec<u8>,
    },
    /// Запрос нужно молча игнорировать.
    Ignored {
        /// Причина.
        reason: NotifyIgnoreReason,
    },
}

/// NOTIFY-сервер: policy + TSIG + построение ответа.
pub struct NotifyServer {
    policy: NotifyPolicy,
    key: Option<std::sync::Arc<TsigKey>>,
    require_tsig: bool,
}

impl NotifyServer {
    /// Создаёт сервер.
    #[must_use]
    pub fn new(policy: NotifyPolicy, key: Option<TsigKey>) -> Self {
        Self {
            policy,
            key: key.map(std::sync::Arc::new),
            require_tsig: true,
        }
    }

    /// Создаёт сервер с разделяемым ключом.
    #[must_use]
    pub fn with_shared_key(policy: NotifyPolicy, key: Option<std::sync::Arc<TsigKey>>) -> Self {
        Self {
            policy,
            key,
            require_tsig: true,
        }
    }

    /// Требовать ли TSIG.
    #[must_use]
    pub const fn require_tsig(mut self, require: bool) -> Self {
        self.require_tsig = require;
        self
    }

    /// Обрабатывает один NOTIFY-запрос.
    ///
    /// # Errors
    ///
    /// [`TransferError`] при некорректном сообщении или ошибке кодирования
    /// ответа.
    pub fn handle(
        &self,
        raw: &[u8],
        source: IpAddr,
        now: u64,
    ) -> Result<NotifyOutcome, TransferError> {
        let (request, envelope) = NotifyRequest::decode(raw)?;
        if !self.policy.allows_source(source) {
            return Ok(NotifyOutcome::Ignored {
                reason: NotifyIgnoreReason::SourceNotAllowed,
            });
        }
        let request_mac = match &self.key {
            Some(key) => {
                let Some(envelope) = &envelope else {
                    if self.require_tsig {
                        let response = NotifyResponse::new(request.id(), Rcode::NOTAUTH)
                            .encode(&request, None, None, now)?;
                        return Ok(NotifyOutcome::Refused { response });
                    }
                    return self.accepted(&request, None, now);
                };
                match key.verify_request_envelope(envelope, now) {
                    Ok(verified) => Some(verified.mac().to_vec()),
                    Err(error) => {
                        let code = error.error_code().unwrap_or(TsigErrorCode::BADSIG);
                        let response = build_tsig_error_response(
                            &request.to_message(),
                            Some(envelope.record()),
                            Some(key.as_ref()),
                            Some(envelope.record().mac()),
                            code,
                            now,
                        )?;
                        return Ok(NotifyOutcome::Refused { response });
                    }
                }
            }
            None => {
                if self.require_tsig || envelope.is_some() {
                    let response = NotifyResponse::new(request.id(), Rcode::NOTAUTH)
                        .encode(&request, None, None, now)?;
                    return Ok(NotifyOutcome::Refused { response });
                }
                None
            }
        };

        if !self.policy.allows_zone(request.zone()) {
            let response = NotifyResponse::new(request.id(), Rcode::REFUSED)
                .encode(&request, None, None, now)?;
            return Ok(NotifyOutcome::Refused { response });
        }
        self.accepted(&request, request_mac.as_deref(), now)
    }

    fn accepted(
        &self,
        request: &NotifyRequest,
        request_mac: Option<&[u8]>,
        now: u64,
    ) -> Result<NotifyOutcome, TransferError> {
        let signing_key = if request_mac.is_some() {
            self.key.as_deref()
        } else {
            None
        };
        let response = NotifyResponse::new(request.id(), Rcode::NOERROR).encode(
            request,
            signing_key,
            request_mac,
            now,
        )?;
        Ok(NotifyOutcome::Accepted {
            zone: request.zone().clone(),
            serial: request.serial(),
            response,
        })
    }
}
