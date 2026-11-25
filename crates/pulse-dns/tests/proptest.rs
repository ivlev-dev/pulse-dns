//! Property-тесты: round-trip валидных сообщений и устойчивость декодера.

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use pulse_dns::{
    CaaTag, DecodeLimits, DnskeyData, DsData, Edns, EdnsOption, EncodeOptions, Flags, Message,
    Name, Nsec3Data, Nsec3ParamData, NsecData, Question, Rclass, Rdata, Record, RrsigData, Rtype,
    Serial, SoaData, SvcParam, SvcbData, TTL_MAX, TlsaData, Ttl, TxtData, TypeBitmap,
};

fn label() -> impl Strategy<Value = String> {
    proptest::collection::vec(prop::char::range('a', 'z'), 1..=10)
        .prop_map(|chars| chars.into_iter().collect())
}

fn domain_name() -> impl Strategy<Value = Name> {
    proptest::collection::vec(label(), 1..=4).prop_map(|labels| {
        let joined = labels.join(".");
        Name::parse(&joined).unwrap()
    })
}

fn txt_data() -> impl Strategy<Value = TxtData> {
    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..=40), 1..=3)
        .prop_map(|segments| TxtData::new(segments).unwrap())
}

fn rdata() -> impl Strategy<Value = Rdata> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(|octets| Rdata::A(Ipv4Addr::from(octets))),
        any::<[u8; 16]>().prop_map(|octets| Rdata::Aaaa(Ipv6Addr::from(octets))),
        domain_name().prop_map(Rdata::Ns),
        domain_name().prop_map(Rdata::Cname),
        txt_data().prop_map(Rdata::Txt),
        (any::<u16>(), domain_name()).prop_map(|(preference, exchange)| Rdata::Mx {
            preference,
            exchange,
        }),
        (any::<u16>(), any::<u16>(), any::<u16>(), domain_name()).prop_map(
            |(priority, weight, port, target)| Rdata::Srv {
                priority,
                weight,
                port,
                target,
            }
        ),
        (any::<u16>(), proptest::collection::vec(any::<u8>(), 1..=20)).prop_map(
            |(rr_type_extra, rdata)| Rdata::Unknown {
                rr_type: Rtype::from_u16(40_000 + rr_type_extra % 1_000),
                rdata,
            }
        ),
    ]
}

fn caa_tag() -> impl Strategy<Value = CaaTag> {
    proptest::collection::vec(prop::sample::select(vec![b'A', b'b', b'Z', b'9']), 1..=20)
        .prop_map(|tag| CaaTag::new(tag).unwrap())
}

fn ds_rdata() -> impl Strategy<Value = Rdata> {
    (
        any::<u16>(),
        any::<u8>(),
        prop_oneof![Just(1_u8), Just(2_u8), Just(4_u8), Just(99_u8),],
    )
        .prop_flat_map(|(key_tag, algorithm, digest_type)| {
            let length = match digest_type {
                1 => 20..=20,
                2 => 32..=32,
                4 => 48..=48,
                _ => 1..=40,
            };
            (
                Just(key_tag),
                Just(algorithm),
                Just(digest_type),
                proptest::collection::vec(any::<u8>(), length),
            )
        })
        .prop_map(|(key_tag, algorithm, digest_type, digest)| {
            Rdata::Ds(DsData::new(key_tag, algorithm, digest_type, digest).unwrap())
        })
}

fn dnskey_rdata() -> impl Strategy<Value = Rdata> {
    (
        any::<u16>(),
        any::<u8>(),
        proptest::collection::vec(any::<u8>(), 1..=80),
    )
        .prop_map(|(flags, algorithm, key)| {
            Rdata::Dnskey(DnskeyData::new(flags, 3, algorithm, key).unwrap())
        })
}

fn rrsig_rdata() -> impl Strategy<Value = Rdata> {
    (
        any::<u16>(),
        any::<u8>(),
        any::<u8>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u16>(),
        domain_name(),
        proptest::collection::vec(any::<u8>(), 1..=80),
    )
        .prop_map(
            |(
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name,
                signature,
            )| {
                Rdata::Rrsig(
                    RrsigData::new(
                        Rtype::from_u16(type_covered),
                        algorithm,
                        labels,
                        original_ttl,
                        expiration,
                        inception,
                        key_tag,
                        signer_name,
                        signature,
                    )
                    .unwrap(),
                )
            },
        )
}

fn nsec_rdata() -> impl Strategy<Value = Rdata> {
    (
        domain_name(),
        proptest::collection::vec(any::<u16>(), 1..=5),
    )
        .prop_map(|(next_domain, types)| {
            let bitmap = TypeBitmap::from_types(types.into_iter().map(Rtype::from_u16));
            Rdata::Nsec(NsecData::new(next_domain, bitmap).unwrap())
        })
}

fn nsec3_rdata() -> impl Strategy<Value = Rdata> {
    (
        0_u8..=2,
        any::<u8>(),
        any::<u16>(),
        proptest::collection::vec(any::<u8>(), 0..=20),
        any::<bool>(),
        proptest::collection::vec(any::<u16>(), 0..=5),
    )
        .prop_map(|(hash_algorithm, flags, iterations, salt, empty, types)| {
            let hash_length = if hash_algorithm == 1 {
                20
            } else {
                1 + types.len() % 20
            };
            let bitmap = if empty {
                TypeBitmap::new_allow_empty(Vec::new()).unwrap()
            } else {
                TypeBitmap::from_types(types.into_iter().map(Rtype::from_u16))
            };
            Rdata::Nsec3(
                Nsec3Data::new(
                    hash_algorithm,
                    flags,
                    iterations,
                    salt,
                    vec![0xAA; hash_length],
                    bitmap,
                )
                .unwrap(),
            )
        })
}

fn nsec3param_rdata() -> impl Strategy<Value = Rdata> {
    (
        any::<u8>(),
        any::<u8>(),
        any::<u16>(),
        proptest::collection::vec(any::<u8>(), 0..=20),
    )
        .prop_map(|(hash_algorithm, flags, iterations, salt)| {
            Rdata::Nsec3Param(Nsec3ParamData::new(hash_algorithm, flags, iterations, salt).unwrap())
        })
}

fn tlsa_rdata() -> impl Strategy<Value = Rdata> {
    (any::<u8>(), any::<u8>(), any::<u8>())
        .prop_flat_map(|(usage, selector, matching)| {
            let length = match matching {
                1 => 32..=32,
                2 => 64..=64,
                _ => 1..=40,
            };
            (
                Just(usage),
                Just(selector),
                Just(matching),
                proptest::collection::vec(any::<u8>(), length),
            )
        })
        .prop_map(|(usage, selector, matching, data)| {
            Rdata::Tlsa(TlsaData::new(usage, selector, matching, data).unwrap())
        })
}

fn svcb_rdata(https: bool) -> impl Strategy<Value = Rdata> {
    (
        any::<u16>(),
        domain_name(),
        proptest::collection::vec(any::<u8>(), 1..=20),
        any::<u16>(),
        any::<bool>(),
        any::<[u8; 4]>(),
        any::<bool>(),
        any::<[u8; 16]>(),
    )
        .prop_map(
            move |(priority, target, alpn, port, has_v4, v4, has_v6, v6)| {
                let mut params = vec![
                    SvcParam::new(SvcParam::KEY_ALPN, alpn).unwrap(),
                    SvcParam::new(SvcParam::KEY_PORT, port.to_be_bytes().to_vec()).unwrap(),
                ];
                if has_v4 {
                    params.push(SvcParam::new(SvcParam::KEY_IPV4HINT, v4.to_vec()).unwrap());
                }
                if has_v6 {
                    params.push(SvcParam::new(SvcParam::KEY_IPV6HINT, v6.to_vec()).unwrap());
                }
                let data = SvcbData::new(priority, target, params).unwrap();
                if https {
                    Rdata::Https(data)
                } else {
                    Rdata::Svcb(data)
                }
            },
        )
}

fn soa_rdata() -> impl Strategy<Value = Rdata> {
    (
        domain_name(),
        domain_name(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(|(mname, rname, serial, refresh, retry, expire, minimum)| {
            Rdata::Soa(SoaData::new(
                mname,
                rname,
                Serial::new(serial),
                refresh,
                retry,
                expire,
                minimum,
            ))
        })
}

fn complex_rdata() -> impl Strategy<Value = Rdata> {
    prop_oneof![
        soa_rdata(),
        (
            any::<u8>(),
            caa_tag(),
            proptest::collection::vec(any::<u8>(), 0..=20)
        )
            .prop_map(|(flags, tag, value)| Rdata::Caa { flags, tag, value }),
        ds_rdata(),
        dnskey_rdata(),
        rrsig_rdata(),
        nsec_rdata(),
        nsec3_rdata(),
        nsec3param_rdata(),
        tlsa_rdata(),
        svcb_rdata(false),
        svcb_rdata(true),
    ]
}

fn edns_options() -> impl Strategy<Value = Edns> {
    (
        any::<u16>(),
        any::<bool>(),
        any::<u8>(),
        any::<u8>(),
        proptest::collection::vec(
            (any::<u16>(), proptest::collection::vec(any::<u8>(), 0..=20)),
            0..=3,
        ),
    )
        .prop_map(
            |(udp_payload_size, dnssec_ok, extended_rcode, version, options)| {
                let mut edns = Edns::new(udp_payload_size)
                    .with_dnssec_ok(dnssec_ok)
                    .with_extended_rcode(extended_rcode)
                    .with_version(version);
                for (code, data) in options {
                    edns.push_option(EdnsOption::new(code, data).unwrap())
                        .unwrap();
                }
                edns
            },
        )
}

fn message() -> impl Strategy<Value = Message> {
    (
        any::<u16>(),
        domain_name(),
        any::<u16>(),
        proptest::collection::vec((rdata(), 0_u32..=TTL_MAX), 0..=8),
    )
        .prop_map(|(id, qname, qtype, records)| {
            let mut message = Message::query(
                id,
                Question::new(qname.clone(), Rtype::from_u16(qtype), Rclass::IN),
            );
            message.set_flags(Flags::new().with_rd(true));
            for (rdata, ttl) in records {
                let rr_type = rdata.rr_type();
                let record = Record::new(
                    qname.clone(),
                    rr_type,
                    Rclass::IN,
                    Ttl::new(ttl).unwrap(),
                    rdata,
                )
                .unwrap();
                message.add_answer(record);
            }
            message
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn valid_messages_roundtrip(message in message()) {
        let bytes = message.encode(&EncodeOptions::default()).unwrap();
        let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
        prop_assert_eq!(decoded, message);
    }

    #[test]
    fn encode_into_matches_encode(message in message()) {
        let expected = message.encode(&EncodeOptions::default()).unwrap();
        let mut out = vec![0_u8; expected.len()];
        let len = message.encode_into(&mut out).unwrap();
        prop_assert_eq!(len, expected.len());
        prop_assert_eq!(out, expected);
        prop_assert_eq!(message.encoded_len().unwrap(), len);
    }

    #[test]
    fn encode_into_matches_encode_with_complex_rdata(
        rdata in complex_rdata(),
        ttl in 0_u32..=TTL_MAX,
    ) {
        let record = Record::new(
            Name::parse("example.com").unwrap(),
            rdata.rr_type(),
            Rclass::IN,
            Ttl::new(ttl).unwrap(),
            rdata,
        )
        .unwrap();
        let mut message = Message::query(1, Question::new(Name::root(), Rtype::A, Rclass::IN));
        message.add_answer(record);
        let expected = message.encode(&EncodeOptions::default()).unwrap();
        let mut out = vec![0_u8; expected.len()];
        let len = message.encode_into(&mut out).unwrap();
        prop_assert_eq!(len, expected.len());
        prop_assert_eq!(out, expected);
    }

    #[test]
    fn complex_rdata_roundtrip(
        rdata in complex_rdata(),
        ttl in 0_u32..=TTL_MAX,
    ) {
        let record = Record::new(
            Name::parse("example.com").unwrap(),
            rdata.rr_type(),
            Rclass::IN,
            Ttl::new(ttl).unwrap(),
            rdata,
        )
        .unwrap();
        let mut message = Message::query(1, Question::new(Name::root(), Rtype::A, Rclass::IN));
        message.add_answer(record);
        let bytes = message.encode(&EncodeOptions::default()).unwrap();
        let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
        prop_assert_eq!(decoded, message);
    }

    #[test]
    fn edns_roundtrip(edns in edns_options()) {
        let mut message = Message::query(2, Question::new(Name::root(), Rtype::A, Rclass::IN));
        message.set_edns(Some(edns));
        let bytes = message.encode(&EncodeOptions::default()).unwrap();
        let decoded = Message::decode(&bytes, &DecodeLimits::default()).unwrap();
        prop_assert_eq!(decoded, message);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=2048)) {
        let _ = Message::decode(&bytes, &DecodeLimits::default());
    }

    #[test]
    fn arbitrary_rdata_never_panics(
        rr_type in prop_oneof![
            Just(Rtype::A),
            Just(Rtype::AAAA),
            Just(Rtype::NS),
            Just(Rtype::SOA),
            Just(Rtype::MX),
            Just(Rtype::TXT),
            Just(Rtype::SRV),
            Just(Rtype::CAA),
            Just(Rtype::DS),
            Just(Rtype::DNSKEY),
            Just(Rtype::RRSIG),
            Just(Rtype::NSEC),
            Just(Rtype::NSEC3),
            Just(Rtype::NSEC3PARAM),
            Just(Rtype::TLSA),
            Just(Rtype::SVCB),
            Just(Rtype::HTTPS),
            Just(Rtype::from_u16(65_000)),
        ],
        bytes in proptest::collection::vec(any::<u8>(), 0..=300),
    ) {
        let _ = Rdata::from_wire(rr_type, &bytes);
    }

    #[test]
    fn arbitrary_names_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=300)) {
        let _ = Name::from_wire(&bytes);
        if let Ok(text) = std::str::from_utf8(&bytes) {
            let _ = Name::parse(text);
        }
    }
}
