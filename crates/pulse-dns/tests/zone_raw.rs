//! Побайтовая эквивалентность `write_rr` и `write_rr_zone_raw`.
//!
//! Горячий путь кодирует `RRset` прямо из `payload` зоны. Для всех типов
//! ответ должен совпадать с кодированием из доменной формы — иначе быстрый и
//! полный пути разойдутся в октетах.

mod common;

use common::{name, question, record};
use pulse_dns::{
    EncodeOptions, EncodeScratch, Encoder, Flags, HeaderCounts, Message, Rclass, Rdata, Record,
    Rtype, SvcbData,
};

fn sample_records() -> Vec<Record> {
    vec![
        record(
            "www.example.com",
            Rtype::A,
            300,
            Rdata::A("192.0.2.1".parse().expect("ipv4")),
        ),
        record(
            "www.example.com",
            Rtype::AAAA,
            300,
            Rdata::Aaaa("2001:db8::1".parse().expect("ipv6")),
        ),
        record(
            "alias.example.com",
            Rtype::CNAME,
            120,
            Rdata::Cname(name("www.example.com")),
        ),
        record(
            "example.com",
            Rtype::MX,
            600,
            Rdata::Mx {
                preference: 10,
                exchange: name("mail.example.com"),
            },
        ),
        record(
            "example.com",
            Rtype::TXT,
            300,
            Rdata::Txt(
                pulse_dns::TxtData::new([b"hello".to_vec(), b"world".to_vec()]).expect("txt"),
            ),
        ),
        record(
            "_sip._tcp.example.com",
            Rtype::SRV,
            300,
            Rdata::Srv {
                priority: 10,
                weight: 5,
                port: 5060,
                target: name("sip.example.com"),
            },
        ),
        record(
            "svc.example.com",
            Rtype::SVCB,
            300,
            Rdata::Svcb(
                SvcbData::new(1, name("svc-target.example.com"), Vec::new()).expect("svcb"),
            ),
        ),
        record(
            "example.com",
            Rtype::NS,
            3600,
            Rdata::Ns(name("ns1.example.com")),
        ),
        record(
            "example.com",
            Rtype::SOA,
            600,
            Rdata::Soa(pulse_dns::SoaData::new(
                name("ns1.example.com"),
                name("hostmaster.example.com"),
                pulse_dns::Serial::new(7),
                3600,
                600,
                604_800,
                300,
            )),
        ),
    ]
}

fn message() -> Message {
    let mut message = Message::query(0x5151, question("www.example.com", Rtype::A));
    message.set_flags(Flags::new().with_qr(true).with_aa(true).with_rd(true));
    for record in sample_records() {
        message.add_answer(record);
    }
    message
}

fn encode_with(message: &Message, options: EncodeOptions, raw: bool) -> Vec<u8> {
    let mut scratch = EncodeScratch::new();
    let mut out = vec![0_u8; 65_535];
    let mut encoder = Encoder::new(&mut out, options, &mut scratch);
    encoder.begin_message(message.id()).expect("begin");
    for question in message.questions() {
        encoder.write_question(question).expect("question");
    }
    let mut answers = 0_u16;
    for record in message.answers() {
        if raw {
            let payload = record.rdata().to_canonical_wire();
            encoder
                .write_rr_zone_raw(
                    record.owner().as_wire(),
                    record.rr_type(),
                    record.class(),
                    record.ttl(),
                    &payload,
                )
                .expect("raw rr");
        } else {
            encoder
                .write_rr(
                    record.owner(),
                    record.rr_type(),
                    record.class(),
                    record.ttl(),
                    record.rdata(),
                )
                .expect("domain rr");
        }
        answers = answers.saturating_add(1);
    }
    let len = encoder
        .finish(
            message.flags(),
            HeaderCounts {
                question: 1,
                answer: answers,
                authority: 0,
                additional: 0,
            },
        )
        .expect("finish");
    out.truncate(len);
    out
}

#[test]
fn raw_rdata_matches_domain_form_bytes() {
    let message = message();
    for options in [EncodeOptions::compressed(), EncodeOptions::uncompressed()] {
        let expected = encode_with(&message, options, false);
        let actual = encode_with(&message, options, true);
        assert_eq!(actual, expected, "options {options:?}");
        assert_eq!(
            actual,
            message.encode(&options).expect("legacy encode"),
            "options {options:?} vs Message::encode"
        );
    }
}

#[test]
fn raw_rdata_rejects_malformed_zone_payload() {
    let mut scratch = EncodeScratch::new();
    let mut out = [0_u8; 512];
    let mut encoder = Encoder::new(&mut out, EncodeOptions::compressed(), &mut scratch);
    encoder.begin_message(0).expect("begin");
    // Обрезанное имя в RDATA CNAME.
    let error = encoder
        .write_rr_zone_raw(
            name("example.com").as_wire(),
            Rtype::CNAME,
            Rclass::IN,
            common::ttl(300),
            &[3, b'w'],
        )
        .expect_err("truncated name must be rejected");
    assert!(matches!(error, pulse_dns::EncodeError::Internal { .. }));
}
