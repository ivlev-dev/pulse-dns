//! Известные wire-векторы и EDNS0.

mod common;

use common::{a_record, name, question, soa_record};
use pulse_dns::{
    DecodeError, DecodeLimits, Edns, EdnsOption, EncodeOptions, Flags, Message, Name, Question,
    Rclass, Rcode, Rtype,
};

#[test]
fn known_a_query() {
    let mut message = Message::query(0x1234, question("example.com", Rtype::A));
    message.set_flags(Flags::new().with_rd(true));
    let bytes = message.encode(&EncodeOptions::default()).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        "123401000001000000000000076578616d706c6503636f6d0000010001"
    );

    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(decoded, message);
    assert!(decoded.flags().rd());
    assert!(!decoded.flags().qr());
}

#[test]
fn known_a_response_with_compression() {
    let request = Message::query(0x1234, question("example.com", Rtype::A));
    let mut response = Message::response(&request);
    response.set_flags(Flags::new().with_qr(true).with_rd(true).with_ra(true));
    response.add_answer(a_record("example.com", [93, 184, 216, 34], 300));

    let bytes = response.encode(&EncodeOptions::default()).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        concat!(
            "123481800001000100000000",
            "076578616d706c6503636f6d0000010001",
            "c00c000100010000012c0004",
            "5db8d822"
        )
    );

    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(decoded.answers().len(), 1);
    let answer = decoded.answers().first().unwrap();
    assert_eq!(answer.owner(), &name("example.com"));
    assert_eq!(answer.rr_type(), Rtype::A);
    assert_eq!(answer.ttl().as_u32(), 300);
    assert_eq!(
        answer.rdata(),
        &pulse_dns::Rdata::A([93, 184, 216, 34].into())
    );
}

#[test]
fn known_aaaa_response() {
    let request = Message::query(0xabcd, question("example.com", Rtype::AAAA));
    let mut response = Message::response(&request);
    response.set_flags(Flags::new().with_qr(true).with_rd(true).with_aa(true));
    response.add_answer(common::record(
        "example.com",
        Rtype::AAAA,
        60,
        pulse_dns::Rdata::Aaaa("2001:db8::1".parse().unwrap()),
    ));
    let bytes = response.encode(&EncodeOptions::default()).unwrap();
    assert_eq!(
        hex::encode(&bytes),
        concat!(
            "abcd85000001000100000000",
            "076578616d706c6503636f6d00001c0001",
            "c00c001c00010000003c0010",
            "20010db8000000000000000000000001"
        )
    );
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(
        decoded.answers().first().unwrap().rdata(),
        response.answers().first().unwrap().rdata()
    );
}

#[test]
fn nxdomain_response_with_soa() {
    let request = Message::query(0x4321, question("missing.example.com", Rtype::A));
    let mut response = Message::response(&request);
    response.set_flags(Flags::new().with_qr(true).with_rd(true).with_ra(true));
    response.set_rcode(Rcode::NXDOMAIN);
    response.add_authority(soa_record("example.com", 2_026_112_401, 300));

    let bytes = response.encode(&EncodeOptions::default()).unwrap();
    assert_eq!(&hex::encode(&bytes)[..8], "43218183");
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(decoded.rcode(), Rcode::NXDOMAIN);
    assert_eq!(decoded.answers().len(), 0);
    assert_eq!(decoded.authority().len(), 1);
    let soa = decoded.authority().first().unwrap();
    assert_eq!(soa.rr_type(), Rtype::SOA);
    assert!(soa.owner().is_subdomain_of(&name("example.com")));
}

#[test]
fn edns0_opt_roundtrip_and_wire_shape() {
    let mut query = Message::query(0x0102, question("example.com", Rtype::A));
    query.set_flags(Flags::new().with_rd(true));
    let mut edns = Edns::new(1232).with_dnssec_ok(true);
    edns.push_option(EdnsOption::new(10, vec![1, 2, 3, 4]).unwrap())
        .unwrap();
    query.set_edns(Some(edns));

    let bytes = query.encode(&EncodeOptions::default()).unwrap();
    assert!(hex::encode(&bytes).ends_with("00002904d0000080000008000a000401020304"));

    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    let edns = decoded.edns().unwrap();
    assert_eq!(edns.udp_payload_size(), 1232);
    assert!(edns.dnssec_ok());
    assert_eq!(edns.extended_rcode(), 0);
    assert_eq!(edns.options().len(), 1);
    assert_eq!(edns.options().first().unwrap().code(), 10);
    assert_eq!(edns.options().first().unwrap().data(), &[1, 2, 3, 4]);
    assert_eq!(decoded.additional().len(), 0);
    assert_eq!(decoded.header().additional_count(), 1);
}

#[test]
fn edns_extended_rcode_badvers() {
    let mut response = Message::query(0x7777, question("example.com", Rtype::A));
    response.set_rcode(Rcode::BADVERS);
    let bytes = response.encode(&EncodeOptions::default()).unwrap();
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(decoded.rcode(), Rcode::BADVERS);
    assert_eq!(decoded.flags().rcode_bits(), 0);
    assert_eq!(decoded.edns().unwrap().extended_rcode(), 1);
}

#[test]
fn tc_flag_is_preserved() {
    let mut response = Message::query(0x1111, question("example.com", Rtype::A));
    response.set_flags(Flags::new().with_qr(true).with_tc(true));
    let bytes = response.encode(&EncodeOptions::default()).unwrap();
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert!(decoded.flags().tc());
}

#[test]
fn compressed_names_use_backward_pointers() {
    let request = Message::query(0x2222, question("example.com", Rtype::NS));
    let mut response = Message::response(&request);
    response.add_answer(common::record(
        "example.com",
        Rtype::NS,
        3600,
        pulse_dns::Rdata::Ns(name("ns1.example.com")),
    ));
    let bytes = response.encode(&EncodeOptions::default()).unwrap();
    let encoded = hex::encode(&bytes);
    // owner -> pointer на qname (offset 12), target ns1.example.com -> label + pointer.
    assert!(encoded.contains("c00c0002000100000e100006036e7331c00c"));
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(
        decoded.answers().first().unwrap().rdata(),
        &pulse_dns::Rdata::Ns(name("ns1.example.com"))
    );
}

#[test]
fn uncompressed_encoding_contains_no_pointers() {
    let mut response = Message::query(0x3333, question("example.com", Rtype::NS));
    response.set_flags(Flags::new().with_qr(true));
    response.add_answer(common::record(
        "example.com",
        Rtype::NS,
        3600,
        pulse_dns::Rdata::Ns(name("ns1.example.com")),
    ));
    let bytes = response.encode(&EncodeOptions::uncompressed()).unwrap();
    for byte in &bytes[12..] {
        assert_ne!(*byte & 0xC0, 0xC0, "unexpected compression pointer");
    }
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn forward_pointer_is_rejected() {
    let mut bytes = vec![0_u8; 12];
    bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01]);
    match Message::decode(&bytes, &DecodeLimits::default()) {
        Err(DecodeError::ForwardPointer { offset, target }) => {
            assert_eq!(offset, 12);
            assert_eq!(target, 12);
        }
        other => panic!("expected ForwardPointer, got {other:?}"),
    }
}

#[test]
fn pointer_to_future_is_rejected() {
    let mut bytes = vec![0_u8; 12];
    bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&[0xC0, 0x20, 0x00, 0x01, 0x00, 0x01]);
    assert!(Message::decode(&bytes, &DecodeLimits::default()).is_err());
}

#[test]
fn question_name_roundtrip_preserves_case_canonicalization() {
    let question = Question::new(
        Name::parse("WwW.ExAmPlE.CoM").unwrap(),
        Rtype::A,
        Rclass::IN,
    );
    let message = Message::query(1, question);
    let bytes = message.encode(&EncodeOptions::default()).unwrap();
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(
        decoded.questions().first().unwrap().qname(),
        &Name::parse("www.example.com").unwrap()
    );
}
