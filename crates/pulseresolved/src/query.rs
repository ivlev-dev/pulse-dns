//! Обработка одного DNS-запроса: decode → resolve → encode с усечением.

use std::sync::Arc;

use pulse_dns::{
    DecodeLimits, EDNS_DEFAULT_PAYLOAD, EDNS_MAX_PAYLOAD, Edns, EncodeError, EncodeOptions, Flags,
    MAX_MESSAGE_LEN, MAX_UDP_PAYLOAD, Message, Opcode, Rcode, Rtype,
};
use pulse_resolver::Resolver;

use crate::stats::Stats;

/// Транспорт, по которому пришёл запрос.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
}

/// Общий обработчик UDP и TCP.
pub(crate) struct Processor {
    resolver: Resolver,
    stats: Arc<Stats>,
}

impl Processor {
    pub(crate) fn new(resolver: Resolver, stats: Arc<Stats>) -> Self {
        Self { resolver, stats }
    }

    /// Обрабатывает пакет и возвращает wire-ответ (или `None`, если отвечать
    /// не нужно/невозможно).
    pub(crate) fn handle(&self, request: &[u8], transport: Transport) -> Option<Vec<u8>> {
        match transport {
            Transport::Udp => self.stats.udp_query(),
            Transport::Tcp => self.stats.tcp_query(),
        }
        let limit = match transport {
            Transport::Udp => MAX_UDP_PAYLOAD,
            Transport::Tcp => MAX_MESSAGE_LEN,
        };
        let Ok(request) = Message::decode(request, &DecodeLimits::default()) else {
            self.stats.decode_error();
            return self.formerr(request, limit, transport);
        };
        if request.flags().qr() {
            self.stats.dropped();
            return None;
        }
        let limit = match transport {
            Transport::Udp => udp_limit(&request),
            Transport::Tcp => MAX_MESSAGE_LEN,
        };
        let axfr = request
            .questions()
            .iter()
            .any(|question| matches!(question.qtype(), Rtype::AXFR | Rtype::IXFR));
        let response = if axfr {
            error_response(&request, Rcode::REFUSED)
        } else {
            self.resolver.resolve(&request)
        };
        match response.rcode() {
            Rcode::FORMERR => self.stats.formerr(),
            Rcode::REFUSED => self.stats.refused(),
            _ => {}
        }
        let Ok((bytes, truncated)) = encode_limited(&response, limit) else {
            self.stats.encode_error();
            return None;
        };
        if truncated {
            self.stats.truncated();
        }
        tracing_response(self.stats.as_ref(), transport);
        Some(bytes)
    }

    fn formerr(&self, raw: &[u8], limit: usize, transport: Transport) -> Option<Vec<u8>> {
        if raw.len() < 12 {
            self.stats.dropped();
            return None;
        }
        let id = u16::from_be_bytes([*raw.first()?, *raw.get(1)?]);
        let opcode = raw.get(2).map_or(0, |byte| byte >> 3) & 0x0F;
        let mut response = Message::new(
            id,
            Flags::new()
                .with_qr(true)
                .with_ra(true)
                .with_opcode(Opcode::from_u8(opcode)),
        );
        response.set_rcode(Rcode::FORMERR);
        self.stats.formerr();
        let Ok((bytes, _)) = encode_limited(&response, limit) else {
            self.stats.encode_error();
            return None;
        };
        tracing_response(self.stats.as_ref(), transport);
        Some(bytes)
    }
}

fn tracing_response(stats: &Stats, transport: Transport) {
    match transport {
        Transport::Udp => stats.udp_response(),
        Transport::Tcp => stats.tcp_response(),
    }
}

fn udp_limit(request: &Message) -> usize {
    request.edns().map_or(MAX_UDP_PAYLOAD, |edns| {
        usize::from(edns.udp_payload_size().clamp(512, EDNS_MAX_PAYLOAD))
    })
}

fn error_response(request: &Message, rcode: Rcode) -> Message {
    let mut response = Message::response(request);
    response.set_flags(response.flags().with_ra(true));
    if let Some(edns) = request.edns() {
        let payload = edns.udp_payload_size().clamp(512, EDNS_DEFAULT_PAYLOAD);
        response.set_edns(Some(Edns::new(payload).with_dnssec_ok(edns.dnssec_ok())));
    }
    response.set_rcode(rcode);
    response
}

/// Кодирует ответ; если он больше лимита, отбрасывает секции и ставит TC.
fn encode_limited(response: &Message, limit: usize) -> Result<(Vec<u8>, bool), EncodeError> {
    let options = EncodeOptions::default();
    let encoded = response.encode(&options)?;
    if encoded.len() <= limit {
        return Ok((encoded, false));
    }
    for (answers, authority, questions) in [
        (true, true, true),
        (true, false, true),
        (false, false, true),
        (false, false, false),
    ] {
        let candidate = rebuild(response, answers, authority, questions);
        let encoded = candidate.encode(&options)?;
        if encoded.len() <= limit {
            return Ok((encoded, true));
        }
    }
    // Минимальный заголовок (12 байт) всегда укладывается в limit ≥ 512.
    let encoded = rebuild(response, false, false, false).encode(&options)?;
    Ok((encoded, true))
}

fn rebuild(response: &Message, answers: bool, authority: bool, questions: bool) -> Message {
    let mut out = Message::new(response.id(), response.flags().with_qr(true).with_tc(true));
    if questions {
        for question in response.questions() {
            out.add_question(question.clone());
        }
    }
    out.set_rcode(response.rcode());
    if let Some(edns) = response.edns() {
        out.set_edns(Some(edns.clone()));
    }
    if answers {
        for record in response.answers() {
            out.add_answer(record.clone());
        }
    }
    if authority {
        for record in response.authority() {
            out.add_authority(record.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use pulse_dns::{Name, Question, Rclass, Rdata, Record, Ttl};

    use super::*;

    fn response_with_txt(count: usize) -> Message {
        let name = Name::parse("big.test").unwrap();
        let mut response = Message::query(7, Question::new(name.clone(), Rtype::TXT, Rclass::IN));
        response = Message::response(&response);
        for index in 0..count {
            let text = format!("{index:04}-{}", "x".repeat(100));
            let record = Record::new(
                name.clone(),
                Rtype::TXT,
                Rclass::IN,
                Ttl::new(60).unwrap(),
                Rdata::Txt(pulse_dns::TxtData::new([text.as_bytes().to_vec()]).unwrap()),
            )
            .unwrap();
            response.add_answer(record);
        }
        response
    }

    #[test]
    fn small_response_is_not_truncated() {
        let response = response_with_txt(1);
        let (bytes, truncated) = encode_limited(&response, 512).unwrap();
        assert!(!truncated);
        assert!(bytes.len() <= 512);
        assert!(
            !Message::decode(&bytes, &DecodeLimits::default())
                .unwrap()
                .flags()
                .tc()
        );
    }

    #[test]
    fn oversized_response_sets_tc_and_fits() {
        let response = response_with_txt(20);
        let (bytes, truncated) = encode_limited(&response, 512).unwrap();
        assert!(truncated);
        assert!(bytes.len() <= 512);
        let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
        assert!(decoded.flags().tc());
        assert_eq!(decoded.questions().len(), 1);
        assert_eq!(decoded.answers().len(), 0);
    }

    #[test]
    fn huge_edns_payload_keeps_answer() {
        let response = response_with_txt(20);
        let (bytes, truncated) = encode_limited(&response, 4096).unwrap();
        assert!(!truncated);
        let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.answers().len(), 20);
    }
}
