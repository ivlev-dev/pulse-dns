//! Преобразование wire-пакета в ответ: decode → `QueryEngine` → encode.
//!
//! Горячий путь ([`respond_into`]) пишет ответ прямо в caller-provided буфер
//! (TX-слот UDP, буфер соединения TCP) без промежуточного `Vec` и без копии.
//! [`respond`] сохранён для обработчиков, которым нужен владеемый `Vec`
//! (DoT/DoH/DoQ в `pulse-tls`).

use std::cell::RefCell;

use pulse_dns::DecodeLimits;
use pulse_dns::{
    EncodeOptions, EncodeScratch, Encoder, Flags, HeaderCounts, Message, MessageRef, Rcode,
};
use pulse_server::{QueryEngine, Scratch, Transport};

use crate::stats::Stats;

thread_local! {
    /// Переиспользуемое состояние ответа на worker-потоке.
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::new());
}

/// Обрабатывает один DNS-пакет, записывая ответ в `out`.
///
/// `None` означает, что ответа нет: пакет короче заголовка, помечен как ответ
/// (защита от петель) или ответ не помещается в `out`. Некорректный запрос с
/// читаемым заголовком получает `FORMERR` с тем же ID.
pub(crate) fn respond_into(
    request: &[u8],
    transport: Transport,
    engine: &QueryEngine,
    stats: &Stats,
    out: &mut [u8],
) -> Option<usize> {
    if request.len() < 12 {
        stats.decode_error();
        return None;
    }
    // Горячий путь: простой запрос разбирается без аллокаций, ответ
    // кодируется из заимствованных RRset прямо в TX-слот. Любой не-горячий
    // случай уходит в полный декодер ниже без изменения поведения.
    if let Some(parsed) = MessageRef::decode_simple(request) {
        let fast = SCRATCH.with(|scratch| {
            let mut scratch = scratch.borrow_mut();
            engine.respond_ref_into(&parsed, transport, out, &mut scratch)
        });
        if let Some(len) = fast {
            match transport {
                Transport::Udp => stats.udp_query(),
                Transport::Tcp => stats.tcp_query(),
            }
            stats.response();
            return Some(len);
        }
    }
    let Ok(message) = Message::decode(request, &DecodeLimits::default()) else {
        stats.decode_error();
        if request.get(2).is_some_and(|flags| flags & 0x80 != 0) {
            return None;
        }
        return formerr_into(request, out)
            .map_err(|()| stats.encode_error())
            .ok();
    };
    match transport {
        Transport::Udp => stats.udp_query(),
        Transport::Tcp => stats.tcp_query(),
    }
    let outcome = SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        engine.respond_into(&message, transport, out, &mut scratch)
    });
    if let Ok(len) = outcome {
        stats.response();
        Some(len)
    } else {
        stats.encode_error();
        None
    }
}

/// Обрабатывает один DNS-пакет и возвращает владеемый ответ.
///
/// Используется транспортами, чей handler-контракт требует `Vec<u8>`
/// (DoT/DoH/DoQ). Для UDP/TCP предпочтителен [`respond_into`].
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
    let response_flags = error_flags(flags);
    let mut response = Message::new(id, response_flags);
    response.set_rcode(Rcode::FORMERR);
    response
        .encode(&EncodeOptions::compressed())
        .map_err(|_| ())
}

fn formerr_into(request: &[u8], out: &mut [u8]) -> Result<usize, ()> {
    let id = u16::from_be_bytes([*request.first().ok_or(())?, *request.get(1).ok_or(())?]);
    let raw_flags = u16::from_be_bytes([*request.get(2).ok_or(())?, *request.get(3).ok_or(())?]);
    let flags =
        error_flags(Flags::from_bits(raw_flags)).with_rcode_bits(Rcode::FORMERR.header_bits());
    let mut scratch = EncodeScratch::new();
    let mut encoder = Encoder::new(out, EncodeOptions::compressed(), &mut scratch);
    encoder.begin_message(id).map_err(|_| ())?;
    encoder
        .finish(flags, HeaderCounts::default())
        .map_err(|_| ())
}

fn error_flags(request: Flags) -> Flags {
    Flags::new()
        .with_qr(true)
        .with_opcode(request.opcode())
        .with_rd(request.rd())
        .with_cd(request.cd())
        .with_aa(false)
        .with_ra(false)
        .with_tc(false)
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
        zone.insert(
            pulse_dns::Rrset::new(
                Name::parse("www.example.com.").unwrap(),
                Rtype::A,
                Rclass::IN,
                Ttl::new(300).unwrap(),
                [pulse_dns::Rdata::A("192.0.2.1".parse().unwrap())],
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
        let mut out = [0_u8; 4096];
        let len = respond_into(&bytes, Transport::Udp, &engine(), &stats, &mut out).unwrap();
        let decoded = Message::decode(&out[..len], &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.id(), 7);
        assert_eq!(decoded.answers().len(), 1);
        assert_eq!(stats.snapshot().udp_queries, 1);
        assert_eq!(stats.snapshot().responses, 1);
    }

    #[test]
    fn streaming_matches_owned_path() {
        let stats = Stats::new();
        let engine = engine();
        let query = Message::query(
            9,
            Question::new(Name::parse("example.com.").unwrap(), Rtype::SOA, Rclass::IN),
        );
        let bytes = query.encode(&EncodeOptions::compressed()).unwrap();
        let owned = respond(&bytes, Transport::Udp, &engine, &stats).unwrap();
        let mut out = [0_u8; 4096];
        let len = respond_into(&bytes, Transport::Udp, &engine, &stats, &mut out).unwrap();
        assert_eq!(&out[..len], owned.as_slice());
    }

    #[test]
    fn zero_copy_a_matches_owned_path() {
        let stats = Stats::new();
        let engine = engine();
        let query = Message::query(
            11,
            Question::new(
                Name::parse("www.example.com.").unwrap(),
                Rtype::A,
                Rclass::IN,
            ),
        );
        let bytes = query.encode(&EncodeOptions::compressed()).unwrap();
        let owned = respond(&bytes, Transport::Udp, &engine, &stats).unwrap();
        let mut out = [0_u8; 4096];
        let len = respond_into(&bytes, Transport::Udp, &engine, &stats, &mut out).unwrap();
        assert_eq!(&out[..len], owned.as_slice());
    }

    #[test]
    fn malformed_query_gets_formerr() {
        let stats = Stats::new();
        let mut bytes = vec![0_u8; 12];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[4] = 0;
        bytes[5] = 1;
        let mut out = [0_u8; 4096];
        let len = respond_into(&bytes, Transport::Udp, &engine(), &stats, &mut out).unwrap();
        let decoded = Message::decode(&out[..len], &DecodeLimits::default()).unwrap();
        assert_eq!(decoded.id(), 0x1234);
        assert_eq!(decoded.rcode(), Rcode::FORMERR);
        assert_eq!(stats.snapshot().decode_errors, 1);
    }

    #[test]
    fn short_packet_is_dropped() {
        let stats = Stats::new();
        let mut out = [0_u8; 4096];
        assert!(respond_into(&[1, 2, 3], Transport::Udp, &engine(), &stats, &mut out).is_none());
        assert_eq!(stats.snapshot().decode_errors, 1);
    }

    #[test]
    fn response_message_is_not_answered() {
        let stats = Stats::new();
        let mut bytes = vec![0_u8; 12];
        bytes[2] = 0x80;
        bytes[5] = 1; // QDCOUNT = 1 without a question: decode fails.
        let mut out = [0_u8; 4096];
        assert!(respond_into(&bytes, Transport::Udp, &engine(), &stats, &mut out).is_none());
    }
}
