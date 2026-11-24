#![allow(clippy::similar_names)]

//! Round-trip `parse -> to_text -> parse` на 100+ записях.

use std::fmt::Write as _;

use pulse_dns::{Name, Rdata, Record};
use pulse_master::{TextOptions, parse_zone, to_text};

fn origin() -> Name {
    Name::parse("example.com.").expect("origin")
}

fn big_zone() -> String {
    let mut zone = String::from(
        "$ORIGIN example.com.\n$TTL 3600\n\
         @ IN SOA ns1 hostmaster ( 2026112401 7200 900 1209600 300 )\n\
         @ IN NS ns1\n@ IN NS ns2\n\
         ns1 A 192.0.2.53\nns2 AAAA 2001:db8::54\n",
    );
    for index in 0..40_u16 {
        let _ = writeln!(zone, "host{index} A 192.0.2.{}", index % 250 + 1);
    }
    for index in 0..20_u16 {
        let _ = writeln!(zone, "v6-{index} AAAA 2001:db8::{:x}", index + 1);
    }
    for index in 0..15_u16 {
        let _ = writeln!(zone, "mail{index} MX {index} mx{index}.example.net.");
    }
    for index in 0..10_u16 {
        let _ = writeln!(
            zone,
            "txt{index} TXT \"value {index}\" \"quote: \\\" slash: \\\\ tab: \\009\""
        );
    }
    for index in 0..10_u16 {
        let _ = writeln!(
            zone,
            "_svc{index}._tcp SRV {index} 100 5060 target{index}.example.net."
        );
    }
    for index in 0..10_u16 {
        let _ = writeln!(zone, "alias{index} CNAME host{index}");
    }
    for index in 0..5_u16 {
        let _ = writeln!(zone, "@ CAA {index} issue \"ca{index}.example.net\"");
    }
    for index in 0..5_u16 {
        let _ = writeln!(
            zone,
            "svcb{index} SVCB {} svc{index}.example.net. alpn=\"h2,h3\" port={} ipv4hint=192.0.2.{},192.0.2.{}",
            index + 1,
            443 + index,
            index + 1,
            index + 2
        );
    }
    for index in 0..5_u16 {
        let _ = writeln!(
            zone,
            "https{index} HTTPS 1 . alpn=h2 no-default-alpn ipv6hint=2001:db8::{} ech=ACsAAwJoMg==",
            index + 1
        );
    }
    let _ = writeln!(zone, "ds DS 12345 13 2 {}", "AB".repeat(32));
    let _ = writeln!(
        zone,
        "key DNSKEY 257 3 13 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw=="
    );
    let _ = writeln!(
        zone,
        "host0 RRSIG A 13 3 3600 20261231235959 20260101000000 12345 example.com. cHVsc2UtdGVzdC1zaWduYXR1cmUtMDEyMzQ1Njc4OWFiY2RlZg=="
    );
    let _ = writeln!(zone, "nsec NSEC ns1 A NS SOA RRSIG NSEC DNSKEY CAA");
    let _ = writeln!(
        zone,
        "nsec3 NSEC3 1 0 10 AABB LATSPNFEVS0128HJ8HAMCTS8J6LBNJ6T A RRSIG"
    );
    let _ = writeln!(zone, "@ NSEC3PARAM 1 0 10 AABB");
    let _ = writeln!(zone, "_443._tcp.www TLSA 3 1 1 {}", "CD".repeat(32));
    let _ = writeln!(zone, "*.wild A 192.0.2.99");
    let _ = writeln!(zone, "rel A 192.0.2.100");
    let _ = writeln!(zone, "unknown TYPE65280 \\# 4 DEADBEEF");
    zone
}

fn options(zone: &pulse_master::ParsedZone) -> TextOptions {
    TextOptions {
        origin: Some(zone.origin.clone()),
        default_ttl: zone.default_ttl,
        sort: false,
    }
}

#[test]
fn hundred_plus_records_round_trip() {
    let text = big_zone();
    let zone = parse_zone(origin(), &text).expect("original zone");
    assert!(
        zone.records.len() > 100,
        "got {} records",
        zone.records.len()
    );

    let exported = to_text(&zone.records, &options(&zone));
    let reparsed = parse_zone(zone.origin.clone(), &exported).expect("reparsed zone");
    assert_eq!(reparsed.records, zone.records);
    assert_eq!(reparsed.default_ttl, zone.default_ttl);

    // Второй проход должен быть байт-в-байт стабильным.
    let exported_again = to_text(&reparsed.records, &options(&reparsed));
    assert_eq!(exported, exported_again);
}

#[test]
fn absolute_output_reparses_without_options() {
    let zone = parse_zone(origin(), &big_zone()).expect("zone");
    let exported = to_text(&zone.records, &TextOptions::default());
    let reparsed = parse_zone(zone.origin.clone(), &exported).expect("reparsed");
    assert_eq!(reparsed.records, zone.records);
    assert_eq!(reparsed.default_ttl, None);
}

#[test]
fn sorted_output_is_stable_and_complete() {
    let zone = parse_zone(origin(), &big_zone()).expect("zone");
    let sorted = to_text(
        &zone.records,
        &TextOptions {
            sort: true,
            ..options(&zone)
        },
    );
    let reparsed = parse_zone(zone.origin.clone(), &sorted).expect("reparsed");
    assert_eq!(reparsed.records.len(), zone.records.len());

    let mut original: Vec<String> = zone.records.iter().map(canonical_key).collect();
    original.sort();
    let mut after: Vec<String> = reparsed.records.iter().map(canonical_key).collect();
    after.sort();
    assert_eq!(original, after);

    let sorted_again = to_text(
        &reparsed.records,
        &TextOptions {
            sort: true,
            ..options(&reparsed)
        },
    );
    assert_eq!(sorted, sorted_again);
}

fn canonical_key(record: &Record) -> String {
    format!(
        "{} {} {} {} {}",
        record.owner(),
        record.rr_type(),
        record.class(),
        record.ttl(),
        match record.rdata() {
            Rdata::Unknown { rdata, .. } => hex::encode(rdata),
            other => hex::encode(other.to_canonical_wire()),
        }
    )
}

#[test]
fn escaped_names_and_binary_txt_round_trip() {
    let text = concat!(
        "$TTL 60\n@ SOA ns hostmaster 1 1 1 10 1\n@ NS ns\n",
        "weird\\.name A 192.0.2.1\n",
        "semi\\;colon A 192.0.2.2\n",
        "paren\\(x\\) A 192.0.2.3\n",
        "quote\\\"x A 192.0.2.4\n",
        "dollar\\$x A 192.0.2.5\n",
        "sp\\032ace TXT \"bin\\000\\255\\010\"\n",
    );
    let zone = parse_zone(origin(), text).expect("escaped zone");
    let exported = to_text(&zone.records, &options(&zone));
    let reparsed = parse_zone(zone.origin.clone(), &exported).expect("reparsed");
    assert_eq!(reparsed.records, zone.records);
    let txt_record = reparsed
        .records
        .iter()
        .find(|record| record.rr_type() == pulse_dns::Rtype::TXT)
        .expect("txt");
    let Rdata::Txt(txt) = txt_record.rdata() else {
        panic!("TXT expected");
    };
    assert_eq!(txt.segments(), &[vec![b'b', b'i', b'n', 0_u8, 255, 10]]);
}
