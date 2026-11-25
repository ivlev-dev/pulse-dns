//! `encode_into`/`encoded_len`/`Encoder`: побайтовая эквивалентность
//! прежнему `encode`, границы буфера и отсутствие регрессии компрессии.

mod common;

use common::{a_record, name, question, record, soa_record, txt_record};
use pulse_dns::{
    Edns, EdnsOption, EncodeOptions, EncodeScratch, Encoder, Flags, HeaderCounts, Message, Rclass,
    Rdata, Rtype, Ttl,
};

fn sample_message() -> Message {
    let mut message = Message::query(0x4444, question("www.example.com", Rtype::A));
    message.set_flags(Flags::new().with_qr(true).with_aa(true).with_rd(true));
    message.add_answer(a_record("www.example.com", [192, 0, 2, 1], 300));
    message.add_answer(record(
        "www.example.com",
        Rtype::AAAA,
        300,
        Rdata::Aaaa("2001:db8::1".parse().expect("ipv6")),
    ));
    message.add_answer(record(
        "www.example.com",
        Rtype::CNAME,
        300,
        Rdata::Cname(name("target.example.com")),
    ));
    message.add_authority(soa_record("example.com", 7, 600));
    message.add_authority(record(
        "example.com",
        Rtype::NS,
        3600,
        Rdata::Ns(name("ns1.example.com")),
    ));
    message.add_additional(a_record("ns1.example.com", [192, 0, 2, 53], 3600));
    message.add_additional(txt_record("example.com", b"hello", 60));
    message
}

fn edns_message() -> Message {
    let mut message = sample_message();
    let mut edns = Edns::new(1232).with_dnssec_ok(true);
    edns.push_option(EdnsOption::new(10, vec![1, 2, 3, 4]).expect("option"))
        .expect("push option");
    edns.push_option(EdnsOption::new(12, Vec::new()).expect("option"))
        .expect("push option");
    message.set_edns(Some(edns));
    message
}

#[test]
fn encode_into_matches_encode() {
    for message in [sample_message(), edns_message()] {
        for options in [EncodeOptions::compressed(), EncodeOptions::uncompressed()] {
            let expected = message.encode(&options).expect("legacy encode");
            let mut out = vec![0_u8; 65_535];
            let len = message
                .encode_into_with(&mut out, &options)
                .expect("encode_into");
            assert_eq!(&out[..len], expected.as_slice());
            assert_eq!(message.encoded_len_with(&options).unwrap(), expected.len());
        }
    }
}

#[test]
fn exact_size_buffer_is_enough() {
    let message = sample_message();
    let expected = message.encode(&EncodeOptions::compressed()).unwrap();
    let mut out = vec![0_u8; expected.len()];
    let len = message.encode_into(&mut out).expect("exact buffer");
    assert_eq!(len, expected.len());
    assert_eq!(out, expected);

    let mut short = vec![0_u8; expected.len() - 1];
    assert!(matches!(
        message.encode_into(&mut short),
        Err(pulse_dns::EncodeError::BufferTooSmall { .. })
    ));
}

#[test]
fn encoded_len_matches_wire_length() {
    let message = edns_message();
    let bytes = message.encode(&EncodeOptions::compressed()).unwrap();
    assert_eq!(message.encoded_len().unwrap(), bytes.len());
}

#[test]
fn streaming_encoder_matches_message_encode() {
    let message = sample_message();
    let expected = message.encode(&EncodeOptions::compressed()).unwrap();
    let mut scratch = EncodeScratch::new();
    let mut out = [0_u8; 2048];
    let mut encoder = Encoder::new(&mut out, EncodeOptions::compressed(), &mut scratch);
    encoder.begin_message(message.id()).unwrap();
    for got in message.questions() {
        encoder.write_question(got).unwrap();
    }
    for record in message
        .answers()
        .iter()
        .chain(message.authority().iter())
        .chain(message.additional().iter())
    {
        encoder.write_record(record).unwrap();
    }
    if let Some(edns) = message.edns() {
        encoder.write_edns(edns).unwrap();
    }
    let counts = HeaderCounts {
        question: 1,
        answer: u16::try_from(message.answers().len()).unwrap(),
        authority: u16::try_from(message.authority().len()).unwrap(),
        additional: u16::try_from(message.additional().len()).unwrap(),
    };
    let len = encoder.finish(message.flags(), counts).unwrap();
    assert_eq!(&out[..len], expected.as_slice());
}

#[test]
fn rollback_drops_record_and_compression_state() {
    let message = sample_message();
    let expected = message.encode(&EncodeOptions::compressed()).unwrap();
    let mut scratch = EncodeScratch::new();
    let mut out = [0_u8; 2048];
    let mut encoder = Encoder::new(&mut out, EncodeOptions::compressed(), &mut scratch);
    encoder.begin_message(message.id()).unwrap();
    encoder
        .write_question(message.questions().first().expect("question"))
        .unwrap();
    let checkpoint = encoder.checkpoint();
    let extra = record(
        "extra.example.com",
        Rtype::TXT,
        300,
        Rdata::Txt(pulse_dns::TxtData::new([b"junk".to_vec()]).expect("txt")),
    );
    encoder.write_record(&extra).unwrap();
    encoder.rollback(checkpoint);
    for record in message
        .answers()
        .iter()
        .chain(message.authority().iter())
        .chain(message.additional().iter())
    {
        encoder.write_record(record).unwrap();
    }
    let counts = HeaderCounts {
        question: 1,
        answer: u16::try_from(message.answers().len()).unwrap(),
        authority: u16::try_from(message.authority().len()).unwrap(),
        additional: u16::try_from(message.additional().len()).unwrap(),
    };
    let len = encoder.finish(message.flags(), counts).unwrap();
    assert_eq!(&out[..len], expected.as_slice());
}

#[test]
fn empty_and_root_names_compress() {
    let mut message = Message::query(1, question(".", Rtype::NS));
    message.set_flags(Flags::new().with_qr(true));
    message.add_answer(record(
        ".",
        Rtype::NS,
        3600,
        Rdata::Ns(name("a.root-servers.net")),
    ));
    let expected = message.encode(&EncodeOptions::compressed()).unwrap();
    let mut out = [0_u8; 512];
    let len = message.encode_into(&mut out).unwrap();
    assert_eq!(&out[..len], expected.as_slice());
    let decoded = Message::decode(&out[..len], &pulse_dns::DecodeLimits::default()).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn oversized_message_is_rejected_identically() {
    let mut message = Message::query(2, question("example.com", Rtype::A));
    message.set_flags(Flags::new().with_qr(true));
    for index in 0..300_u32 {
        message.add_answer(txt_record("example.com", &vec![b'x'; 250], 300));
        let octets = index.to_be_bytes();
        message.add_answer(a_record("example.com", octets, 300));
    }
    assert!(matches!(
        message.encode(&EncodeOptions::compressed()),
        Err(pulse_dns::EncodeError::MessageTooLong { .. })
    ));
    let mut out = vec![0_u8; 70_000];
    assert!(matches!(
        message.encode_into(&mut out),
        Err(pulse_dns::EncodeError::MessageTooLong { .. })
    ));
    assert!(matches!(
        message.encoded_len(),
        Err(pulse_dns::EncodeError::MessageTooLong { .. })
    ));
}

#[test]
fn ttl_and_class_are_preserved() {
    let mut message = Message::query(3, question("example.com", Rtype::A));
    message.set_flags(Flags::new().with_qr(true));
    message.add_answer(record(
        "example.com",
        Rtype::A,
        0,
        Rdata::A([192, 0, 2, 9].into()),
    ));
    let mut out = [0_u8; 512];
    let len = message.encode_into(&mut out).unwrap();
    let decoded = Message::decode(&out[..len], &pulse_dns::DecodeLimits::default()).unwrap();
    assert_eq!(decoded.answers()[0].ttl(), Ttl::new(0).unwrap());
    assert_eq!(decoded.answers()[0].class(), Rclass::IN);
}
