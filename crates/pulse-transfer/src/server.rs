//! Общее построение серверного потока AXFR/IXFR.

use pulse_dns::{
    EncodeOptions, Flags, MAX_MESSAGE_LEN, Message, Name, Opcode, Rclass, Rcode, Record, Rtype,
};

use crate::error::{TransferError, TsigError, TsigErrorCode};
use crate::tsig::{TsigEnvelope, TsigKey, append_tsig, build_tsig_error_response, parse_tsig};
use crate::zone::{
    TransferConfig, TransferLimits, check_byte_limit, check_message_limit, check_record_limit,
};

/// Статистика трансфера.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransferStats {
    /// Число сообщений.
    pub messages: usize,
    /// Число записей в ответах.
    pub records: usize,
    /// Суммарный размер wire-сообщений.
    pub bytes: u64,
}

/// Проверяет базовую форму AXFR/IXFR-запроса.
pub(crate) fn validate_query(
    request: &Message,
    qtype: Rtype,
    origin: &Name,
    empty_authority: bool,
) -> Result<(), TransferError> {
    if request.flags().qr() {
        return Err(TransferError::protocol("query has QR=1"));
    }
    if request.opcode() != Opcode::QUERY {
        return Err(TransferError::protocol("query has non-QUERY opcode"));
    }
    if request.questions().len() != 1 {
        return Err(TransferError::protocol(
            "zone transfer query must have exactly one question",
        ));
    }
    let question = request
        .questions()
        .first()
        .ok_or(TransferError::protocol("missing question"))?;
    if question.qtype() != qtype {
        return Err(TransferError::protocol("unexpected query type"));
    }
    if question.qclass() != Rclass::IN {
        return Err(TransferError::protocol("only class IN is supported"));
    }
    if question.qname() != origin {
        return Err(TransferError::protocol("query name is not the zone origin"));
    }
    if !request.answers().is_empty() {
        return Err(TransferError::protocol("query answer section is not empty"));
    }
    if empty_authority && !request.authority().is_empty() {
        return Err(TransferError::protocol(
            "AXFR query authority section must be empty",
        ));
    }
    Ok(())
}

/// Строит простой отказ с заданным RCODE.
pub(crate) fn refusal_response(request: &Message, rcode: Rcode) -> Result<Vec<u8>, TransferError> {
    let mut response = Message::response(request);
    response.set_rcode(rcode);
    Ok(response.encode(&EncodeOptions::default())?)
}

/// Собирает и подписывает поток ответов.
///
/// `answers` должны быть в порядке, в котором они пойдут в Answer-секции:
/// первый и последний элементы — SOA (для AXFR/fallback IXFR) либо
/// последовательность IXFR.
pub(crate) fn build_stream(
    request: &Message,
    answers: &[Record],
    config: &TransferConfig,
    key: Option<&TsigKey>,
    request_mac: Option<&[u8]>,
    now: u64,
) -> Result<(Vec<Vec<u8>>, TransferStats), TransferError> {
    config.validate()?;
    if answers.is_empty() {
        return Err(TransferError::protocol("empty transfer response"));
    }
    check_record_limit(&config.limits, answers.len())?;
    let target = config
        .message_bytes
        .clamp(256, MAX_MESSAGE_LEN.saturating_sub(2048));

    let mut blocks: Vec<Vec<Record>> = Vec::new();
    let mut current: Vec<Record> = Vec::new();
    let mut estimate = 0_usize;
    for record in answers {
        let size = record.to_canonical_wire()?.len();
        if !current.is_empty() && estimate.saturating_add(size) > target {
            blocks.push(core::mem::take(&mut current));
            estimate = 0;
        }
        current.push(record.clone());
        estimate = estimate.saturating_add(size);
    }
    if !current.is_empty() {
        blocks.push(current);
    }
    if blocks.is_empty() {
        return Err(TransferError::protocol("empty transfer response"));
    }

    let last_index = blocks.len().saturating_sub(1);
    let mut messages = Vec::with_capacity(blocks.len());
    let mut stats = TransferStats {
        records: answers.len(),
        ..TransferStats::default()
    };
    let mut prior_mac: Option<Vec<u8>> = None;
    let mut pending: Vec<Vec<u8>> = Vec::new();

    for (index, block) in blocks.iter().enumerate() {
        let flags = Flags::new()
            .with_qr(true)
            .with_aa(true)
            .with_opcode(Opcode::QUERY)
            .with_rd(request.flags().rd());
        let mut message = Message::new(request.id(), flags);
        if index == 0
            && let Some(question) = request.questions().first()
        {
            message.add_question(question.clone());
        }
        for record in block {
            message.add_answer(record.clone());
        }
        let base = message.encode(&EncodeOptions::default())?;

        let should_sign =
            key.is_some() && (index == 0 || index == last_index || index % config.tsig_every == 0);
        let wire = if should_sign {
            let key = key.ok_or(TransferError::Tsig(TsigError::Missing))?;
            let record = if index == 0 {
                let request_mac = request_mac.ok_or(TransferError::Tsig(TsigError::Missing))?;
                key.sign_response(&base, request_mac, request.id(), now)?
            } else {
                let prior = prior_mac
                    .as_deref()
                    .ok_or(TransferError::Tsig(TsigError::Missing))?;
                let mut parts: Vec<&[u8]> = Vec::with_capacity(pending.len() + 1);
                parts.extend(pending.iter().map(Vec::as_slice));
                parts.push(&base);
                key.sign_chain(prior, &parts, request.id(), now, key.fudge())?
            };
            prior_mac = Some(record.mac().to_vec());
            pending.clear();
            append_tsig(base, &record)?
        } else {
            pending.push(base.clone());
            base
        };

        if wire.len() > MAX_MESSAGE_LEN {
            return Err(TransferError::MessageTooLarge { len: wire.len() });
        }
        stats.bytes = stats.bytes.saturating_add(wire.len() as u64);
        check_byte_limit(&config.limits, stats.bytes)?;
        messages.push(wire);
        check_message_limit(&config.limits, messages.len())?;
    }
    stats.messages = messages.len();
    Ok((messages, stats))
}

/// Успешная аутентификация запроса.
pub(crate) struct Credentials {
    pub(crate) request_mac: Option<Vec<u8>>,
}

/// Результат аутентификации.
pub(crate) enum AuthResult {
    /// Запрос аутентифицирован.
    Ok(Credentials),
    /// Нужно отправить ответ и завершить обработку.
    Reject {
        /// Готовый wire-ответ.
        response: Vec<u8>,
        /// Ошибка для вызывающего.
        error: TransferError,
    },
}

/// Проверяет TSIG-политику запроса.
pub(crate) fn authenticate_request(
    config: &TransferConfig,
    raw: &[u8],
    request: &Message,
    key: Option<&TsigKey>,
    now: u64,
) -> Result<AuthResult, TransferError> {
    let envelope: Option<TsigEnvelope> = match parse_tsig(raw) {
        Ok(envelope) => envelope,
        Err(error @ TsigError::Malformed { .. }) => {
            return Ok(AuthResult::Reject {
                response: refusal_response(request, Rcode::FORMERR)?,
                error: TransferError::Tsig(error),
            });
        }
        Err(error @ TsigError::UnsupportedAlgorithm { .. }) => {
            return Ok(AuthResult::Reject {
                response: refusal_response(request, Rcode::NOTAUTH)?,
                error: TransferError::Tsig(error),
            });
        }
        Err(error) => return Err(TransferError::Tsig(error)),
    };
    let Some(key) = key else {
        if envelope.is_some() {
            return Ok(AuthResult::Reject {
                response: refusal_response(request, Rcode::NOTAUTH)?,
                error: TransferError::Tsig(TsigError::Unexpected),
            });
        }
        if config.require_tsig {
            return Ok(AuthResult::Reject {
                response: refusal_response(request, Rcode::NOTAUTH)?,
                error: TransferError::Tsig(TsigError::Missing),
            });
        }
        return Ok(AuthResult::Ok(Credentials { request_mac: None }));
    };

    let Some(envelope) = envelope else {
        if config.require_tsig {
            return Ok(AuthResult::Reject {
                response: refusal_response(request, Rcode::NOTAUTH)?,
                error: TransferError::Tsig(TsigError::Missing),
            });
        }
        return Ok(AuthResult::Ok(Credentials { request_mac: None }));
    };

    match key.verify_request_envelope(&envelope, now) {
        Ok(verified) => Ok(AuthResult::Ok(Credentials {
            request_mac: Some(verified.mac().to_vec()),
        })),
        Err(error) => {
            let code = error.error_code().unwrap_or(TsigErrorCode::BADSIG);
            let response = build_tsig_error_response(
                request,
                Some(envelope.record()),
                Some(key),
                Some(envelope.record().mac()),
                code,
                now,
            )?;
            Ok(AuthResult::Reject {
                response,
                error: TransferError::Tsig(error),
            })
        }
    }
}

/// Проверяет лимиты запроса.
pub(crate) fn check_request_limits(
    limits: &TransferLimits,
    request_len: usize,
) -> Result<(), TransferError> {
    crate::zone::check_byte_limit(limits, request_len as u64)
}
