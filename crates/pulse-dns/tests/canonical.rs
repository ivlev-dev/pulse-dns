//! Каноническая wire-форма для DNSSEC (RFC 4034 §6.2–6.3).

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use common::{name, record, ttl};
use pulse_dns::{NameError, Rdata, Rrset, RrsetError, Rtype, canonical};

#[test]
fn record_wire_is_lowercase_and_uncompressed() {
    let record = record(
        "WWW.Example.COM",
        Rtype::A,
        300,
        Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
    );
    let wire = record.to_canonical_wire().unwrap();
    assert_eq!(
        hex::encode(&wire),
        concat!(
            "03777777076578616d706c6503636f6d00",
            "00010001",
            "0000012c",
            "0004",
            "c0000201"
        )
    );
    assert_eq!(canonical::record_wire(&record).unwrap(), wire);
}

#[test]
fn rrset_sorts_by_canonical_rdata() {
    let rrset = Rrset::new(
        name("example.com"),
        Rtype::A,
        pulse_dns::Rclass::IN,
        ttl(300),
        [
            Rdata::A(Ipv4Addr::new(192, 0, 2, 3)),
            Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
            Rdata::A(Ipv4Addr::new(192, 0, 2, 2)),
        ],
    )
    .unwrap();
    let ordered: Vec<&Rdata> = rrset.rdatas().iter().collect();
    assert_eq!(
        ordered,
        vec![
            &Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
            &Rdata::A(Ipv4Addr::new(192, 0, 2, 2)),
            &Rdata::A(Ipv4Addr::new(192, 0, 2, 3)),
        ]
    );

    let wire = rrset.to_canonical_wire().unwrap();
    assert_eq!(canonical::rrset_wire(&rrset).unwrap(), wire);
    let expected = ["c0000201", "c0000202", "c0000203"];
    let encoded = hex::encode(&wire);
    let mut search_from = 0;
    for rdata in expected {
        let position = encoded[search_from..].find(rdata).unwrap();
        search_from += position + rdata.len();
    }
}

#[test]
fn canonical_rdata_for_mx_uses_uncompressed_name() {
    let rdata = Rdata::Mx {
        preference: 10,
        exchange: name("mail.example.com"),
    };
    let wire = rdata.to_canonical_wire();
    assert_eq!(
        hex::encode(&wire),
        "000a046d61696c076578616d706c6503636f6d00"
    );
}

#[test]
fn rrset_deduplicates_equal_rdata() {
    let rrset = Rrset::new(
        name("example.com"),
        Rtype::A,
        pulse_dns::Rclass::IN,
        ttl(300),
        [
            Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
            Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
        ],
    )
    .unwrap();
    assert_eq!(rrset.len(), 1);
}

#[test]
fn rrset_rejects_non_leftmost_wildcard_owner() {
    let result = Rrset::new(
        name("a.*.example.com"),
        Rtype::A,
        pulse_dns::Rclass::IN,
        ttl(300),
        [Rdata::A(Ipv4Addr::new(192, 0, 2, 1))],
    );
    assert!(matches!(
        result,
        Err(RrsetError::Owner(NameError::WildcardNotLeftmost))
    ));

    assert!(
        Rrset::new(
            name("*.example.com"),
            Rtype::A,
            pulse_dns::Rclass::IN,
            ttl(300),
            [Rdata::A(Ipv4Addr::new(192, 0, 2, 1))],
        )
        .is_ok()
    );
}

#[test]
fn rrset_rejects_mixed_ttl_and_type() {
    let first = record(
        "example.com",
        Rtype::A,
        300,
        Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
    );
    let second = record(
        "example.com",
        Rtype::A,
        301,
        Rdata::A(Ipv4Addr::new(192, 0, 2, 2)),
    );
    assert!(Rrset::from_records([first, second]).is_err());

    assert!(
        Rrset::new(
            name("example.com"),
            Rtype::A,
            pulse_dns::Rclass::IN,
            ttl(300),
            [Rdata::A(Ipv4Addr::new(192, 0, 2, 1))],
        )
        .is_ok()
    );
    assert!(
        Rrset::new(
            name("example.com"),
            Rtype::A,
            pulse_dns::Rclass::IN,
            ttl(300),
            [Rdata::Aaaa(Ipv6Addr::LOCALHOST)],
        )
        .is_err()
    );
}
