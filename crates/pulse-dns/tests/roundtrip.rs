//! Round-trip encode → decode для всех поддерживаемых RDATA.

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use common::{name, record, ttl};
use pulse_dns::{
    CaaTag, DecodeLimits, DnskeyData, DsData, EncodeOptions, Message, Nsec3Data, Nsec3ParamData,
    NsecData, Rdata, RdataError, Record, RecordError, Rrset, RrsetError, RrsigData, Rtype, Serial,
    SoaData, SvcParam, SvcbData, TlsaData, TxtData, TypeBitmap,
};

#[allow(clippy::vec_init_then_push)]
fn all_rdata() -> Vec<Rdata> {
    let mut rdatas = Vec::new();
    rdatas.push(Rdata::A(Ipv4Addr::new(192, 0, 2, 1)));
    rdatas.push(Rdata::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
    rdatas.push(Rdata::Ns(name("ns1.example.com")));
    rdatas.push(Rdata::Cname(name("alias.example.com")));
    rdatas.push(Rdata::Soa(SoaData::new(
        name("ns1.example.com"),
        name("hostmaster.example.com"),
        Serial::new(2_026_112_401),
        3600,
        600,
        604_800,
        300,
    )));
    rdatas.push(Rdata::Ptr(name("ptr.example.com")));
    rdatas.push(Rdata::Mx {
        preference: 10,
        exchange: name("mail.example.com"),
    });
    rdatas.push(Rdata::Txt(
        TxtData::new(vec![b"hello".to_vec(), b"world".to_vec()]).unwrap(),
    ));
    rdatas.push(Rdata::Srv {
        priority: 1,
        weight: 5,
        port: 443,
        target: name("svc.example.com"),
    });
    rdatas.push(Rdata::Caa {
        flags: 128,
        tag: CaaTag::issue(),
        value: b"letsencrypt.org".to_vec(),
    });
    rdatas.push(Rdata::Dname(name("dname.example.com")));
    rdatas.push(Rdata::Ds(
        DsData::new(12_345, 13, 2, vec![0xAB; 32]).unwrap(),
    ));
    rdatas.push(Rdata::Dnskey(
        DnskeyData::new(257, 3, 13, vec![0xCD; 64]).unwrap(),
    ));
    rdatas.push(Rdata::Rrsig(
        RrsigData::new(
            Rtype::A,
            13,
            2,
            3600,
            2_000_000_000,
            1_900_000_000,
            12_345,
            name("example.com"),
            vec![0x5A; 64],
        )
        .unwrap(),
    ));
    rdatas.push(Rdata::Nsec(
        NsecData::new(
            name("b.example.com"),
            TypeBitmap::from_types([Rtype::A, Rtype::NSEC, Rtype::RRSIG]),
        )
        .unwrap(),
    ));
    rdatas.push(Rdata::Nsec3(
        Nsec3Data::new(
            1,
            0,
            0,
            vec![0xAA, 0xBB],
            vec![0x11; 20],
            TypeBitmap::from_types([Rtype::A, Rtype::RRSIG]),
        )
        .unwrap(),
    ));
    rdatas.push(Rdata::Nsec3Param(
        Nsec3ParamData::new(1, 0, 0, Vec::new()).unwrap(),
    ));
    rdatas.push(Rdata::Tlsa(TlsaData::new(3, 1, 1, vec![0xEE; 32]).unwrap()));
    rdatas.push(Rdata::Svcb(
        SvcbData::new(
            1,
            name("svc.example.com"),
            vec![
                SvcParam::new(1, b"\x02h2".to_vec()).unwrap(),
                SvcParam::new(3, 443_u16.to_be_bytes().to_vec()).unwrap(),
            ],
        )
        .unwrap(),
    ));
    rdatas.push(Rdata::Https(
        SvcbData::new(1, name("svc.example.com"), Vec::new()).unwrap(),
    ));
    rdatas.push(Rdata::unknown(Rtype::from_u16(999), vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap());
    rdatas
}

#[test]
fn all_rdata_roundtrip_through_message() {
    let mut message = Message::query(0x5555, common::question("example.com", Rtype::ANY));
    message.set_flags(pulse_dns::Flags::new().with_qr(true));
    for rdata in all_rdata() {
        let rr_type = rdata.rr_type();
        message.add_answer(record("rr.example.com", rr_type, 3600, rdata));
    }
    let bytes = message.encode(&EncodeOptions::default()).unwrap();
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn all_rdata_standalone_roundtrip() {
    for rdata in all_rdata() {
        let rr_type = rdata.rr_type();
        let wire = rdata.to_canonical_wire();
        let decoded = Rdata::from_wire(rr_type, &wire).unwrap();
        assert_eq!(decoded, rdata, "type {rr_type}");
    }
}

#[test]
fn unknown_rdata_is_opaque() {
    let rdata = Rdata::unknown(Rtype::from_u16(65000), vec![0, 1, 2, 255]).unwrap();
    assert_eq!(rdata.rr_type(), Rtype::from_u16(65000));
    let wire = rdata.to_canonical_wire();
    assert_eq!(wire, vec![0, 1, 2, 255]);
    let decoded = Rdata::from_wire(Rtype::from_u16(65000), &wire).unwrap();
    assert_eq!(decoded, rdata);
}

#[test]
fn unknown_rejects_known_type() {
    assert!(matches!(
        Rdata::unknown(Rtype::A, vec![1, 2, 3, 4]),
        Err(RdataError::KnownTypeAsUnknown { .. })
    ));
}

#[test]
fn txt_segments_are_preserved() {
    let text = TxtData::new(vec![vec![b'a'; 255], b"b".to_vec()]).unwrap();
    let rdata = Rdata::Txt(text);
    let wire = rdata.to_canonical_wire();
    assert_eq!(&wire[..2], &[255, b'a']);
    let decoded = Rdata::from_wire(Rtype::TXT, &wire).unwrap();
    assert_eq!(decoded, rdata);
}

#[test]
fn svcb_is_basic_and_ordered() {
    let port = SvcParam::new(SvcParam::KEY_PORT, vec![0, 1]).unwrap();
    let alpn = SvcParam::new(SvcParam::KEY_ALPN, vec![2]).unwrap();
    assert!(SvcbData::new(1, name("svc.example.com"), vec![port, alpn]).is_err());
}

#[test]
fn soa_timers_are_full_u32() {
    let soa = SoaData::new(
        name("ns1.example.com"),
        name("hostmaster.example.com"),
        Serial::new(7),
        u32::MAX,
        0x8000_0000,
        u32::MAX,
        0xFFFF_FFFE,
    );
    let rdata = Rdata::Soa(soa);
    let wire = rdata.to_canonical_wire();
    let decoded = Rdata::from_wire(Rtype::SOA, &wire).unwrap();
    assert_eq!(decoded, rdata);
    let Rdata::Soa(decoded_soa) = &decoded else {
        panic!("expected SOA");
    };
    assert_eq!(decoded_soa.refresh, u32::MAX);
    assert_eq!(decoded_soa.retry, 0x8000_0000);
    assert_eq!(decoded_soa.expire, u32::MAX);
    assert_eq!(decoded_soa.minimum, 0xFFFF_FFFE);

    let mut message = Message::query(0x0A0A, common::question("example.com", Rtype::SOA));
    message.add_answer(record("example.com", Rtype::SOA, 300, rdata));
    let bytes = message.encode(&EncodeOptions::default()).unwrap();
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    let Rdata::Soa(decoded_soa) = decoded.answers().first().unwrap().rdata() else {
        panic!("expected SOA");
    };
    assert_eq!(decoded_soa.expire, u32::MAX);
}

#[test]
fn rrsig_validity_window() {
    let signature = RrsigData::new(
        Rtype::A,
        13,
        2,
        3600,
        2_000,
        1_000,
        1,
        name("example.com"),
        vec![1],
    )
    .unwrap();
    assert!(!signature.is_valid_at(999));
    assert!(signature.is_valid_at(1_000));
    assert!(signature.is_valid_at(1_500));
    assert!(signature.is_valid_at(2_000));
    assert!(!signature.is_valid_at(2_001));

    let wrapped = RrsigData::new(
        Rtype::A,
        13,
        2,
        3600,
        0x0000_0100,
        0xFFFF_FF00,
        1,
        name("example.com"),
        vec![1],
    )
    .unwrap();
    assert!(wrapped.is_valid_at(0));
}

#[test]
fn type_bitmap_contains_all_inserted_types() {
    let bitmap = TypeBitmap::from_types([Rtype::A, Rtype::NSEC, Rtype::RRSIG]);
    assert!(bitmap.contains(Rtype::A));
    assert!(bitmap.contains(Rtype::NSEC));
    assert!(bitmap.contains(Rtype::RRSIG));
    assert!(!bitmap.contains(Rtype::AAAA));
    let mut types = bitmap.types();
    types.sort();
    assert_eq!(types, vec![Rtype::A, Rtype::RRSIG, Rtype::NSEC]);
}

#[test]
fn record_rejects_known_type_as_opaque_rdata() {
    let error = Record::new(
        name("example.com"),
        Rtype::A,
        pulse_dns::Rclass::IN,
        ttl(300),
        Rdata::Unknown {
            rr_type: Rtype::A,
            rdata: vec![192, 0, 2, 1],
        },
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RecordError::Rdata(RdataError::KnownTypeAsUnknown { .. })
    ));
}

#[test]
fn nsec3_allows_empty_bitmap_for_empty_non_terminal() {
    assert!(TypeBitmap::new(Vec::new()).is_err());
    let bitmap = TypeBitmap::new_allow_empty(Vec::new()).unwrap();
    let rdata = Rdata::Nsec3(Nsec3Data::new(1, 0, 0, Vec::new(), vec![0x11; 20], bitmap).unwrap());
    let wire = rdata.to_canonical_wire();
    let decoded = Rdata::from_wire(Rtype::NSEC3, &wire).unwrap();
    assert_eq!(decoded, rdata);

    let mut message = Message::query(0x0B0B, common::question("example.com", Rtype::NSEC3));
    message.add_answer(record("example.com", Rtype::NSEC3, 300, rdata));
    let bytes = message.encode(&EncodeOptions::default()).unwrap();
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn caa_tag_preserves_case_and_accepts_long_tags() {
    let upper = CaaTag::new(b"ISSUE").unwrap();
    let lower = CaaTag::new(b"issue").unwrap();
    assert_eq!(upper.as_bytes(), b"ISSUE");
    assert_ne!(upper, lower);
    assert!(upper.eq_ignore_ascii_case(&lower));

    let rdata = Rdata::Caa {
        flags: 0,
        tag: upper,
        value: b"ca.example".to_vec(),
    };
    let wire = rdata.to_canonical_wire();
    assert!(wire.windows(5).any(|window| window == b"ISSUE"));
    let decoded = Rdata::from_wire(Rtype::CAA, &wire).unwrap();
    assert_eq!(decoded, rdata);

    let mut message = Message::query(0x0C0C, common::question("example.com", Rtype::CAA));
    message.add_answer(record("example.com", Rtype::CAA, 300, rdata));
    let bytes = message.encode(&EncodeOptions::default()).unwrap();
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(decoded, message);

    for length in [16_usize, 255] {
        assert!(CaaTag::new(vec![b'A'; length]).is_ok());
    }
    assert!(CaaTag::new(Vec::new()).is_err());
    assert!(CaaTag::new(vec![b'A'; 256]).is_err());
}

#[test]
fn txt_allows_empty_character_strings() {
    for raw in [vec![0_u8], vec![0_u8, 0]] {
        let decoded = Rdata::from_wire(Rtype::TXT, &raw).unwrap();
        let Rdata::Txt(text) = &decoded else {
            panic!("expected TXT");
        };
        assert_eq!(text.segments().len(), raw.len());
        assert!(text.segments().iter().all(Vec::is_empty));
        assert_eq!(decoded.to_canonical_wire(), raw);
    }

    let mut message = Message::query(0x0D0D, common::question("example.com", Rtype::TXT));
    let rdata = Rdata::Txt(TxtData::new(vec![Vec::new(), Vec::new()]).unwrap());
    message.add_answer(record("example.com", Rtype::TXT, 300, rdata));
    let bytes = message.encode(&EncodeOptions::default()).unwrap();
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn rrsig_original_ttl_is_full_u32() {
    let rdata = Rdata::Rrsig(
        RrsigData::new(
            Rtype::A,
            13,
            2,
            u32::MAX,
            2_000,
            1_000,
            1,
            name("example.com"),
            vec![1],
        )
        .unwrap(),
    );
    let wire = rdata.to_canonical_wire();
    let decoded = Rdata::from_wire(Rtype::RRSIG, &wire).unwrap();
    let Rdata::Rrsig(signature) = &decoded else {
        panic!("expected RRSIG");
    };
    assert_eq!(signature.original_ttl(), u32::MAX);
    assert_eq!(decoded, rdata);
}

#[test]
fn svcb_known_param_validation() {
    assert!(SvcParam::new(SvcParam::KEY_MANDATORY, Vec::new()).is_err());
    assert!(SvcParam::new(SvcParam::KEY_MANDATORY, vec![0, 0]).is_err());
    assert!(SvcParam::new(SvcParam::KEY_MANDATORY, vec![0, 3, 0, 1]).is_err());
    assert!(SvcParam::new(SvcParam::KEY_MANDATORY, vec![0, 1, 0, 3]).is_ok());

    assert!(SvcParam::new(SvcParam::KEY_PORT, vec![0]).is_err());
    assert!(SvcParam::new(SvcParam::KEY_PORT, vec![0, 1]).is_ok());
    assert!(SvcParam::new(SvcParam::KEY_IPV4HINT, vec![0, 0, 0]).is_err());
    assert!(SvcParam::new(SvcParam::KEY_IPV4HINT, vec![0, 0, 0, 1]).is_ok());
    assert!(SvcParam::new(SvcParam::KEY_IPV6HINT, vec![0; 15]).is_err());
    assert!(SvcParam::new(SvcParam::KEY_IPV6HINT, vec![0; 16]).is_ok());
    assert!(SvcParam::new(99, vec![1, 2, 3]).is_ok());
}

#[test]
fn nsec3_hash_length_matches_algorithm() {
    let bitmap = TypeBitmap::new_allow_empty(Vec::new()).unwrap();
    assert!(Nsec3Data::new(1, 0, 0, Vec::new(), vec![0; 19], bitmap.clone()).is_err());
    assert!(Nsec3Data::new(1, 0, 0, Vec::new(), vec![0; 20], bitmap.clone()).is_ok());
    assert!(Nsec3Data::new(2, 0, 0, Vec::new(), vec![0; 7], bitmap).is_ok());
}

#[test]
fn record_and_rrset_reject_rdata_longer_than_65535() {
    let long = Rdata::Ds(DsData::new(1, 1, 99, vec![0; 65_535]).unwrap());
    let error = Record::new(
        name("example.com"),
        Rtype::DS,
        pulse_dns::Rclass::IN,
        ttl(300),
        long.clone(),
    )
    .unwrap_err();
    assert!(matches!(error, RecordError::RdataTooLong { len: 65_539 }));

    let error = Rrset::new(
        name("example.com"),
        Rtype::DS,
        pulse_dns::Rclass::IN,
        ttl(300),
        [long],
    )
    .unwrap_err();
    assert!(matches!(error, RrsetError::RdataTooLong { len: 65_539 }));
}

#[test]
fn record_type_must_match_rdata() {
    assert!(
        Record::new(
            name("example.com"),
            Rtype::AAAA,
            pulse_dns::Rclass::IN,
            ttl(300),
            Rdata::A(Ipv4Addr::LOCALHOST),
        )
        .is_err()
    );
}
