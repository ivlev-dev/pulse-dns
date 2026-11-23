//! Лимиты и защита от враждебного wire-ввода (SEC-DNS-001…005).

mod common;

use pulse_dns::{DecodeError, DecodeLimits, EncodeOptions, Message, Rdata, Rtype, TTL_MAX, Ttl};

fn header(qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
    let mut bytes = vec![0_u8; 12];
    bytes[4..6].copy_from_slice(&qd.to_be_bytes());
    bytes[6..8].copy_from_slice(&an.to_be_bytes());
    bytes[8..10].copy_from_slice(&ns.to_be_bytes());
    bytes[10..12].copy_from_slice(&ar.to_be_bytes());
    bytes
}

#[test]
fn message_larger_than_65535_is_rejected() {
    let bytes = vec![0_u8; 65_536];
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::MessageTooLong { len: 65_536 })
    ));
}

#[test]
fn truncated_header_is_rejected() {
    assert!(matches!(
        Message::decode(&[0, 1, 2], &DecodeLimits::default()),
        Err(DecodeError::Truncated { .. })
    ));
}

#[test]
fn name_longer_than_255_is_rejected() {
    let mut bytes = header(1, 0, 0, 0);
    for _ in 0..4 {
        bytes.push(63);
        bytes.extend(std::iter::repeat_n(b'a', 63));
    }
    bytes.push(0);
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::NameTooLong { .. })
    ));
}

#[test]
fn label_longer_than_63_is_rejected() {
    let mut bytes = header(1, 0, 0, 0);
    bytes.push(64);
    bytes.extend(std::iter::repeat_n(b'a', 64));
    bytes.push(0);
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::BadLabelType { .. })
    ));
}

#[test]
fn compression_loop_is_rejected() {
    let mut bytes = header(1, 0, 0, 0);
    bytes.extend_from_slice(&[3, b'a', b'b', b'c', 0xC0, 0x0C]);
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    assert!(Message::decode(&bytes, &DecodeLimits::default()).is_err());
}

#[test]
fn pointer_into_header_is_rejected() {
    let mut bytes = header(1, 0, 0, 0);
    bytes.extend_from_slice(&[0xC0, 0x00, 0x00, 0x01, 0x00, 0x01]);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::PointerIntoHeader {
            offset: 12,
            target: 0
        })
    ));
}

#[test]
fn pointer_into_label_content_is_rejected() {
    let mut bytes = header(1, 0, 0, 0);
    bytes.extend_from_slice(&[3, b'a', b'b', b'c', 0xC0, 0x0E, 0x00, 0x01, 0x00, 0x01]);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::PointerNotLabelStart {
            offset: 16,
            target: 14
        })
    ));
}

fn pointer_chain_message(pointer_count: usize) -> Vec<u8> {
    let question_count = u16::try_from(pointer_count + 1).unwrap();
    let mut bytes = header(question_count, 0, 0, 0);
    let mut previous_name_start = bytes.len();
    bytes.push(0);
    bytes.extend_from_slice(&[0, 1, 0, 1]);
    for _ in 0..pointer_count {
        let name_start = bytes.len();
        let pointer = 0xC000_u16 | u16::try_from(previous_name_start).unwrap();
        bytes.extend_from_slice(&pointer.to_be_bytes());
        bytes.extend_from_slice(&[0, 1, 0, 1]);
        previous_name_start = name_start;
    }
    bytes
}

#[test]
fn exactly_128_compression_pointers_are_accepted() {
    let bytes = pointer_chain_message(128);
    let message = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(message.questions().len(), 129);
    for question in message.questions() {
        assert_eq!(question.qname(), &common::name("."));
    }
}

#[test]
fn pointer_chain_longer_than_128_is_rejected() {
    let bytes = pointer_chain_message(129);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::TooManyPointers { .. })
    ));
}

#[test]
fn truncated_rdata_is_rejected() {
    let mut bytes = header(1, 1, 0, 0);
    bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    bytes.extend_from_slice(&[0x00]);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&2_u16.to_be_bytes());
    bytes.extend_from_slice(&[1, 2]);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::RdataTruncated {
            rr_type: Rtype::A,
            ..
        })
    ));
}

#[test]
fn rdata_length_beyond_message_is_rejected() {
    let mut bytes = header(0, 1, 0, 0);
    bytes.extend_from_slice(&[0x00]);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&100_u16.to_be_bytes());
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::RdataOutOfBounds { .. })
    ));
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut query = Message::query(0x1234, common::question("example.com", Rtype::A));
    query.set_flags(pulse_dns::Flags::new().with_rd(true));
    let mut bytes = query.encode(&EncodeOptions::default()).unwrap();
    let valid_len = bytes.len();
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::TrailingBytes { offset }) if offset == valid_len
    ));
}

#[test]
fn extra_record_beyond_ancount_is_trailing() {
    let mut bytes = header(1, 0, 0, 0);
    bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    let trailing_offset = bytes.len();
    bytes.extend_from_slice(&[0x00]);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&4_u16.to_be_bytes());
    bytes.extend_from_slice(&[192, 0, 2, 1]);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::TrailingBytes { offset }) if offset == trailing_offset
    ));
}

#[test]
fn empty_tail_is_accepted() {
    let query = Message::query(1, common::question("example.com", Rtype::A));
    let bytes = query.encode(&EncodeOptions::default()).unwrap();
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(decoded, query);
}

#[test]
fn compression_pointer_to_0x3fff_is_accepted() {
    let mut bytes = header(0, 3, 0, 0);
    // Answer 1: unknown type with opaque RDATA, чтобы следующий RR начался
    // ровно на offset 0x3FFF.
    let first_rdata_len = 0x3FFF - 23;
    bytes.push(0x00);
    bytes.extend_from_slice(&999_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(first_rdata_len).unwrap().to_be_bytes());
    bytes.extend(std::iter::repeat_n(0_u8, first_rdata_len));
    assert_eq!(bytes.len(), 0x3FFF);

    // Answer 2: имя "a" начинается ровно на 0x3FFF.
    bytes.extend_from_slice(&[1, b'a', 0]);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&4_u16.to_be_bytes());
    bytes.extend_from_slice(&[192, 0, 2, 1]);

    // Answer 3: owner — указатель на 0x3FFF.
    bytes.extend_from_slice(&[0xFF, 0xFF]);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&4_u16.to_be_bytes());
    bytes.extend_from_slice(&[192, 0, 2, 2]);

    let message = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(message.answers().len(), 3);
    assert_eq!(
        message.answers().get(2).unwrap().owner(),
        &common::name("a")
    );
}

#[test]
fn record_count_limit_is_enforced() {
    let bytes = header(0, 4097, 0, 0);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::RecordLimitExceeded { .. })
    ));

    let bytes = header(1, 1, 0, 0);
    let limits = DecodeLimits { max_records: 0 };
    assert!(matches!(
        Message::decode(&bytes, &limits),
        Err(DecodeError::RecordLimitExceeded { .. })
    ));
}

#[test]
fn ttl_is_clamped_from_wire() {
    let mut bytes = header(1, 1, 0, 0);
    bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    bytes.extend_from_slice(&[0x00]);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0x8000_0001_u32.to_be_bytes());
    bytes.extend_from_slice(&4_u16.to_be_bytes());
    bytes.extend_from_slice(&[192, 0, 2, 1]);
    let message = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    let ttl = message.answers().first().unwrap().ttl();
    assert_eq!(ttl.as_u32(), TTL_MAX);
    assert_eq!(ttl, Ttl::from_wire(0x8000_0001));
}

#[test]
fn opt_outside_additional_is_rejected() {
    let mut bytes = header(1, 1, 0, 0);
    bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    bytes.extend_from_slice(&[0x00]);
    bytes.extend_from_slice(&41_u16.to_be_bytes());
    bytes.extend_from_slice(&1232_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::OptOutsideAdditional)
    ));
}

#[test]
fn duplicate_opt_is_rejected() {
    let mut bytes = header(0, 0, 0, 2);
    for _ in 0..2 {
        bytes.extend_from_slice(&[0x00]);
        bytes.extend_from_slice(&41_u16.to_be_bytes());
        bytes.extend_from_slice(&1232_u16.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&0_u16.to_be_bytes());
    }
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::DuplicateOpt)
    ));
}

#[test]
fn malformed_edns_option_is_rejected() {
    let mut bytes = header(1, 0, 0, 1);
    bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    bytes.extend_from_slice(&[0x00]);
    bytes.extend_from_slice(&41_u16.to_be_bytes());
    bytes.extend_from_slice(&1232_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&6_u16.to_be_bytes());
    bytes.extend_from_slice(&10_u16.to_be_bytes());
    bytes.extend_from_slice(&4_u16.to_be_bytes());
    bytes.extend_from_slice(&[1, 2]);
    assert!(matches!(
        Message::decode(&bytes, &DecodeLimits::default()),
        Err(DecodeError::OptTruncated { .. })
    ));
}

#[test]
fn standalone_rdata_rejects_compression() {
    assert!(matches!(
        Rdata::from_wire(Rtype::NS, &[0xC0, 0x00]),
        Err(DecodeError::BadLabelType { .. })
    ));
}

#[test]
fn encoder_rejects_oversized_rrset() {
    let rrset = pulse_dns::Rrset::new(
        common::name("example.com"),
        Rtype::A,
        pulse_dns::Rclass::IN,
        common::ttl(300),
        (1..=4097_u32).map(|value| {
            let [a, b, c, d] = value.to_be_bytes();
            Rdata::A([a, b, c, d].into())
        }),
    );
    assert!(rrset.is_err());
}

#[test]
fn encoder_respects_message_size() {
    let mut message = Message::query(1, common::question("example.com", Rtype::A));
    for index in 0..300_u32 {
        let octets = index.to_be_bytes();
        message.add_answer(common::record(
            "example.com",
            Rtype::TXT,
            300,
            Rdata::Txt(pulse_dns::TxtData::new(vec![vec![b'x'; 250]]).unwrap()),
        ));
        message.add_answer(common::a_record("example.com", octets, 300));
    }
    let result = message.encode(&EncodeOptions::default());
    assert!(matches!(
        result,
        Err(pulse_dns::EncodeError::MessageTooLong { .. })
    ));
}
