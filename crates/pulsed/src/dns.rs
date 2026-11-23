//! Преобразование wire-пакета в ответ: decode → `QueryEngine` → encode.

use pulse_dns::{DecodeLimits, EncodeOptions, Flags, Message, Rcode};
use pulse_server::{QueryEngine, Transport};

use crate::stats::Stats;

/// Обрабатывает один DNS-пакет.
///
/// `None` означает, что ответа нет: пакет короче заголовка, помечен как ответ
/// (защита от петель) или ответ не кодируется. Некорректный запрос с читаемым
/// заголовком получает `FORMERR` с тем же ID.
pub(crate) fn respond(
    request: &[u8],
    transport: Transport,
    engine: &QueryEngine,
    stats: &Stats,
) -> Option<Vec<u8>> {
    if request.len() < 12 {
        stats.decode_error();
        return None;
    }
    let Ok(message) = Message::decode(request, &DecodeLimits::default()) else {
        stats.decode_error();
        if request.get(2).is_some_and(|flags| flags & 0x80 != 0) {
            return None;
        }
        return formerr(request).map_err(|()| stats.encode_error()).ok();
    };
    match transport {
        Transport::Udp => stats.udp_query(),
        Transport::Tcp => stats.tcp_query(),
    }
    let response = engine.respond(&message, transport);
    if let Ok(bytes) = response.encode(&EncodeOptions::compressed()) {
        stats.response();
        Some(bytes)
    } else {
        stats.encode_error();
        None
    }
}

fn formerr(request: &[u8]) -> Result<Vec<u8>, ()> {
    let id = u16::from_be_bytes([*request.first().ok_or(())?, *request.get(1).ok_or(())?]);
    let raw_flags = u16::from_be_bytes([*request.get(2).ok_or(())?, *request.get(3).ok_or(())?]);
    let flags = Flags::from_bits(raw_flags);
    let response_flags = Flags::new()
        .with_qr(true)
        .with_opcode(flags.opcode())
        .with_rd(flags.rd())
        .with_cd(flags.cd())
        .with_aa(false)
        .with_ra(false)
        .with_tc(false);
    let mut response = Message::new(id, response_flags);
    response.set_rcode(Rcode::FORMERR);
    response
        .encode(&EncodeOptions::compressed())
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pulse_dns::{Name, Question, Rclass, Rtype, Ttl};
    use pulse_server::testkit::InMemoryZone;

    use super::*;

    fn engine() -> QueryEngine {
        let origin = Name::parse("example.com.").unwrap();
        let mut zone = InMemoryZone::new(origin.clone());
        zone.insert(
            pulse_dns::Rrset::new(
                origin.clone(),
                Rtype::SOA,
                Rclass::IN,
                Ttl::new(3600).unwrap(),
                [pulse_dns::Rdata::Soa(pulse_dns::SoaData::new(
                    Name::parse("ns1.example.com.").unwrap(),
                    Name::parse("hostmaster.example.com.").unwrap(),
                    pulse_dns::Serial::new(1),
                    3600,
                    600,
                    604_800,
                    300,
                ))],
            )
            .unwrap(),
        )
        .unwrap();
        zone.insert(
            pulse_dns::Rrset::new(
                origin,
                Rtype::NS,
                Rclass::IN,
                Ttl::new(3600).unwrap(),
                [pulse_dns::Rdata::Ns(
                    Name::parse("ns1.example.com.").unwrap(),
                )],
            )
            .unwrap(),
        )
        .unwrap();
        QueryEngine::new(vec![Arc::new(zone)])
    }

    #[test]
    fn decodes_and_encodes_query() {
        let stats = Stats::new();
        let query = Message::query(
            7,
            Question::new(Name::parse("example.com.").unwrap(), Rtype::SOA, Rclass::IN),
        );
        let bytes = query.encode(&EncodeOptions::compressed()).unwrap();
        let response = respond(&bytes, Transport::Udp, &engine(), &stats).unwrap();
        let decoded = Message::decode(&response, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.id(), 7);
        assert_eq!(decoded.answers().len(), 1);
        assert_eq!(stats.snapshot().udp_queries, 1);
        assert_eq!(stats.snapshot().responses, 1);
    }

    #[test]
    fn malformed_query_gets_formerr() {
        let stats = Stats::new();
        let mut bytes = vec![0_u8; 12];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[4] = 0;
        bytes[5] = 1;
        let response = respond(&bytes, Transport::Udp, &engine(), &stats).unwrap();
        let decoded = Message::decode(&response, &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.id(), 0x1234);
        assert_eq!(decoded.rcode(), Rcode::FORMERR);
        assert_eq!(stats.snapshot().decode_errors, 1);
    }

    #[test]
    fn short_packet_is_dropped() {
        let stats = Stats::new();
        assert!(respond(&[1, 2, 3], Transport::Udp, &engine(), &stats).is_none());
        assert_eq!(stats.snapshot().decode_errors, 1);
    }

    #[test]
    fn response_message_is_not_answered() {
        let stats = Stats::new();
        let mut bytes = vec![0_u8; 12];
        bytes[2] = 0x80;
        bytes[5] = 1; // QDCOUNT = 1 without a question: decode fails.
        assert!(respond(&bytes, Transport::Udp, &engine(), &stats).is_none());
    }
}
