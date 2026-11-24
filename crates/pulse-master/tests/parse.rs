#![allow(clippy::similar_names)]

//! Разбор реальных фрагментов зон BIND.

use std::net::{Ipv4Addr, Ipv6Addr};

use pulse_dns::{Name, Rdata, Record, Rtype, SvcParam};
use pulse_master::parse_zone;

const ZONE: &str = r#"
; BIND-style sample covering the supported presentation formats
$ORIGIN example.com.
$TTL 1h

@   IN  SOA ns1.example.com. hostmaster.example.com. (
        2026112401 ; serial
        1h         ; refresh
        15m        ; retry
        2w         ; expire
        300 )      ; minimum
    IN  NS  ns1
    IN  NS  ns2.other.example.net.

ns1     IN  A     192.0.2.53
ns1     IN  AAAA  2001:db8::53
ns2     AAAA      2001:db8::54
@       MX  10 mail
mail    A   192.0.2.25
www     300 A 192.0.2.80
alias   CNAME www
txt     TXT "first segment" "quote: \" and backslash: \\ semicolon; ok" "tab\009!"
wild    TXT ("multi" "line" "txt")
_sip._tcp 300 IN SRV 10 60 5060 sipserver
@       CAA 0 issue "letsencrypt.org"
@       CAA 0 iodef "mailto:security@example.com"
ds      3600 IN DS 12345 13 2 ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB
dnskey  DNSKEY 257 3 13 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==
www     RRSIG A 13 3 300 20261231235959 20260101000000 12345 example.com. cHVsc2UtdGVzdC1zaWduYXR1cmUtMDEyMzQ1Njc4OWFiY2RlZg==
@       NSEC ns1 A NS SOA MX TXT RRSIG NSEC DNSKEY CAA
nsec3   NSEC3 1 0 10 AABB LATSPNFEVS0128HJ8HAMCTS8J6LBNJ6T A RRSIG
@       NSEC3PARAM 1 0 10 AABB
_443._tcp.www TLSA 3 1 1 CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD
@       SVCB 1 . alpn="h2,h3" port=443 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1 mandatory=alpn,port
www     HTTPS 1 www.example.com. alpn=h2 no-default-alpn ech=ACsAAwJoMg==
*.wild  A 192.0.2.99
rel     A 192.0.2.100
unknown TYPE65280 \# 4 DEADBEEF
generic A \# 4 C0000201
"#;

fn origin() -> Name {
    Name::parse("example.com.").expect("origin")
}

fn find<'a>(records: &'a [Record], owner: &str, rr_type: Rtype) -> &'a Record {
    records
        .iter()
        .find(|record| {
            record.owner() == &Name::parse(owner).expect("owner") && record.rr_type() == rr_type
        })
        .unwrap_or_else(|| panic!("record {owner} {rr_type} not found"))
}

#[test]
fn parses_full_bind_zone() {
    let zone = parse_zone(origin(), ZONE).expect("zone must parse");
    assert_eq!(zone.origin, origin());
    assert_eq!(zone.default_ttl.map(pulse_dns::Ttl::as_u32), Some(3600));
    assert_eq!(zone.warnings.len(), 0);
    assert!(zone.records.len() > 20);

    let soa = find(&zone.records, "example.com.", Rtype::SOA);
    let Rdata::Soa(soa) = soa.rdata() else {
        panic!("SOA expected");
    };
    assert_eq!(soa.serial.as_u32(), 2_026_112_401);
    assert_eq!(soa.refresh, 3600);
    assert_eq!(soa.retry, 900);
    assert_eq!(soa.expire, 1_209_600);
    assert_eq!(soa.minimum, 300);
    assert_eq!(soa.mname, Name::parse("ns1.example.com.").expect("mname"));
    assert_eq!(
        soa.rname,
        Name::parse("hostmaster.example.com.").expect("rname")
    );

    let txt = find(&zone.records, "txt.example.com.", Rtype::TXT);
    let Rdata::Txt(txt) = txt.rdata() else {
        panic!("TXT expected");
    };
    assert_eq!(txt.segments().len(), 3);
    assert_eq!(
        txt.segments().first().map(Vec::as_slice),
        Some(&b"first segment"[..])
    );
    assert_eq!(
        txt.segments().get(1).map(Vec::as_slice),
        Some(&b"quote: \" and backslash: \\ semicolon; ok"[..])
    );
    assert_eq!(
        txt.segments().get(2).map(Vec::as_slice),
        Some(&b"tab\t!"[..])
    );

    let wild = find(&zone.records, "wild.example.com.", Rtype::TXT);
    let Rdata::Txt(wild) = wild.rdata() else {
        panic!("TXT expected");
    };
    assert_eq!(
        wild.segments(),
        &[b"multi".to_vec(), b"line".to_vec(), b"txt".to_vec()]
    );

    let srv = find(&zone.records, "_sip._tcp.example.com.", Rtype::SRV);
    let Rdata::Srv {
        priority,
        weight,
        port,
        target,
    } = srv.rdata()
    else {
        panic!("SRV expected");
    };
    assert_eq!((*priority, *weight, *port), (10, 60, 5060));
    assert_eq!(
        target,
        &Name::parse("sipserver.example.com.").expect("target")
    );

    let mx = find(&zone.records, "example.com.", Rtype::MX);
    let Rdata::Mx {
        preference,
        exchange,
    } = mx.rdata()
    else {
        panic!("MX expected");
    };
    assert_eq!(*preference, 10);
    assert_eq!(
        exchange,
        &Name::parse("mail.example.com.").expect("exchange")
    );

    let cname = find(&zone.records, "alias.example.com.", Rtype::CNAME);
    assert_eq!(
        cname.rdata(),
        &Rdata::Cname(Name::parse("www.example.com.").expect("cname"))
    );

    let wildcard = find(&zone.records, "*.wild.example.com.", Rtype::A);
    assert_eq!(wildcard.rdata(), &Rdata::A(Ipv4Addr::new(192, 0, 2, 99)));

    let aaaa = find(&zone.records, "ns1.example.com.", Rtype::AAAA);
    assert_eq!(
        aaaa.rdata(),
        &Rdata::Aaaa("2001:db8::53".parse::<Ipv6Addr>().expect("v6"))
    );
}

#[test]
fn parses_dnssec_records() {
    let zone = parse_zone(origin(), ZONE).expect("zone must parse");

    let ds = find(&zone.records, "ds.example.com.", Rtype::DS);
    let Rdata::Ds(ds) = ds.rdata() else {
        panic!("DS expected");
    };
    assert_eq!(ds.key_tag(), 12_345);
    assert_eq!(ds.algorithm(), 13);
    assert_eq!(ds.digest_type(), 2);
    assert_eq!(ds.digest().len(), 32);

    let key = find(&zone.records, "dnskey.example.com.", Rtype::DNSKEY);
    let Rdata::Dnskey(key) = key.rdata() else {
        panic!("DNSKEY expected");
    };
    assert_eq!(key.flags(), 257);
    assert_eq!(key.protocol(), 3);
    assert_eq!(key.algorithm(), 13);
    assert_eq!(key.public_key().len(), 64);

    let sig = find(&zone.records, "www.example.com.", Rtype::RRSIG);
    let Rdata::Rrsig(sig) = sig.rdata() else {
        panic!("RRSIG expected");
    };
    assert_eq!(sig.type_covered(), Rtype::A);
    assert_eq!(sig.labels(), 3);
    assert_eq!(sig.original_ttl(), 300);
    assert_eq!(sig.key_tag(), 12_345);
    assert_eq!(sig.signer_name(), &origin());
    assert_eq!(sig.signature_expiration(), 1_798_761_599);
    assert_eq!(sig.signature_inception(), 1_767_225_600);

    let nsec = find(&zone.records, "example.com.", Rtype::NSEC);
    let Rdata::Nsec(nsec) = nsec.rdata() else {
        panic!("NSEC expected");
    };
    assert!(nsec.type_bitmap().contains(Rtype::SOA));
    assert!(nsec.type_bitmap().contains(Rtype::RRSIG));

    let nsec3 = find(&zone.records, "nsec3.example.com.", Rtype::NSEC3);
    let Rdata::Nsec3(nsec3) = nsec3.rdata() else {
        panic!("NSEC3 expected");
    };
    assert_eq!(nsec3.hash_algorithm(), 1);
    assert_eq!(nsec3.iterations(), 10);
    assert_eq!(nsec3.salt(), &[0xAA, 0xBB]);
    assert_eq!(nsec3.next_hashed_owner().len(), 20);

    let param = find(&zone.records, "example.com.", Rtype::NSEC3PARAM);
    let Rdata::Nsec3Param(param) = param.rdata() else {
        panic!("NSEC3PARAM expected");
    };
    assert_eq!(param.salt(), &[0xAA, 0xBB]);

    let tlsa = find(&zone.records, "_443._tcp.www.example.com.", Rtype::TLSA);
    let Rdata::Tlsa(tlsa) = tlsa.rdata() else {
        panic!("TLSA expected");
    };
    assert_eq!((tlsa.usage(), tlsa.selector(), tlsa.matching()), (3, 1, 1));
    assert_eq!(tlsa.certificate_association_data().len(), 32);
}

#[test]
fn parses_svcb_and_https() {
    let zone = parse_zone(origin(), ZONE).expect("zone must parse");

    let svcb = find(&zone.records, "example.com.", Rtype::SVCB);
    let Rdata::Svcb(svcb) = svcb.rdata() else {
        panic!("SVCB expected");
    };
    assert_eq!(svcb.priority(), 1);
    assert_eq!(svcb.target(), &Name::root());
    let keys: Vec<u16> = svcb.params().iter().map(SvcParam::key).collect();
    assert_eq!(keys, vec![0, 1, 3, 4, 6]);
    assert_eq!(
        svcb.params().first().map(SvcParam::value),
        Some(&[0, 1, 0, 3][..])
    );
    assert_eq!(
        svcb.params().get(1).map(SvcParam::value),
        Some(&[2, b'h', b'2', 2, b'h', b'3'][..])
    );
    assert_eq!(
        svcb.params().get(2).map(SvcParam::value),
        Some(&[0x01, 0xBB][..])
    );
    assert_eq!(
        svcb.params().get(3).map(SvcParam::value),
        Some(&[192, 0, 2, 1, 192, 0, 2, 2][..])
    );

    let https = find(&zone.records, "www.example.com.", Rtype::HTTPS);
    let Rdata::Https(https) = https.rdata() else {
        panic!("HTTPS expected");
    };
    assert_eq!(
        https.target(),
        &Name::parse("www.example.com.").expect("target")
    );
    let keys: Vec<u16> = https.params().iter().map(SvcParam::key).collect();
    assert_eq!(keys, vec![1, 2, 5]);
    assert_eq!(https.params().get(1).map(SvcParam::value), Some(&[][..]));
    assert_eq!(
        https.params().get(2).map(SvcParam::value),
        Some(&[0x00, 0x2B, 0x00, 0x03, 0x02, b'h', b'2'][..])
    );
}

#[test]
fn soa_minimum_is_the_default_ttl_without_dollar_ttl() {
    let text = "@ SOA ns hostmaster 1 1 1 10 300\n@ NS ns\nx A 192.0.2.1\n";
    let zone = parse_zone(origin(), text).expect("zone without $TTL");
    assert!(
        zone.records
            .iter()
            .all(|record| record.ttl().as_u32() == 300)
    );
}

#[test]
fn inherits_owner_ttl_and_class() {
    let text = "@ 100 SOA ns hostmaster 1 1 1 10 1\n  IN NS ns\nx 200 A 192.0.2.1\n  IN AAAA 2001:db8::1\n";
    let zone = parse_zone(origin(), text).expect("inheritance");
    let ns = find(&zone.records, "example.com.", Rtype::NS);
    assert_eq!(ns.ttl().as_u32(), 100);
    let aaaa = find(&zone.records, "x.example.com.", Rtype::AAAA);
    assert_eq!(aaaa.ttl().as_u32(), 200);
    assert_eq!(aaaa.class(), pulse_dns::Rclass::IN);
}

#[test]
fn parses_txt_escapes_and_caa() {
    let zone = parse_zone(origin(), ZONE).expect("zone must parse");
    let issue = find(&zone.records, "example.com.", Rtype::CAA);
    let Rdata::Caa { flags, tag, value } = issue.rdata() else {
        panic!("CAA expected");
    };
    assert_eq!(*flags, 0);
    assert_eq!(tag.as_bytes(), b"issue");
    assert_eq!(value, b"letsencrypt.org");

    let text = "$ORIGIN example.com.\n$TTL 60\n@ SOA ns hostmaster 1 1 1 10 1\n@ NS ns\n";
    let zone = parse_zone(origin(), text).expect("minimal zone");
    assert_eq!(zone.records.len(), 2);

    let class_first = "$TTL 60\n@ CLASS1 3600 SOA ns hostmaster 1 1 1 10 1\n@ IN 3600 NS ns\n";
    let zone = parse_zone(origin(), class_first).expect("class and ttl in either order");
    assert!(
        zone.records
            .iter()
            .all(|record| record.ttl().as_u32() == 3600)
    );
    let escapes = "$TTL 60\n@ SOA ns hostmaster 1 1 1 10 1\n@ NS ns\nx TXT \"a\\032b\" \"c\\;d\" \"e\\\"f\"\n";
    let zone = parse_zone(origin(), escapes).expect("escaped txt");
    let txt = find(&zone.records, "x.example.com.", Rtype::TXT);
    let Rdata::Txt(txt) = txt.rdata() else {
        panic!("TXT expected");
    };
    assert_eq!(
        txt.segments(),
        &[b"a b".to_vec(), b"c;d".to_vec(), b"e\"f".to_vec()]
    );
}

#[test]
fn parses_svcb_alpn_with_escaped_comma() {
    let text =
        "$TTL 60\n@ SOA ns hostmaster 1 1 1 10 1\n@ NS ns\nx SVCB 1 . alpn=\"h2\\,special,h3\"\n";
    let zone = parse_zone(origin(), text).expect("svcb");
    let record = find(&zone.records, "x.example.com.", Rtype::SVCB);
    let Rdata::Svcb(svcb) = record.rdata() else {
        panic!("SVCB expected");
    };
    let param = svcb.params().first().expect("alpn");
    assert_eq!(
        param.value(),
        &[
            10, b'h', b'2', b',', b's', b'p', b'e', b'c', b'i', b'a', b'l', 2, b'h', b'3'
        ]
    );
    let exported = pulse_master::to_text(&zone.records, &pulse_master::TextOptions::default());
    let reparsed = parse_zone(origin(), &exported).expect("reparse");
    assert_eq!(reparsed.records, zone.records);
}

#[test]
fn parses_rfc3597_unknown_and_known() {
    let zone = parse_zone(origin(), ZONE).expect("zone must parse");
    let unknown = find(
        &zone.records,
        "unknown.example.com.",
        Rtype::from_u16(65280),
    );
    assert_eq!(
        unknown.rdata(),
        &Rdata::Unknown {
            rr_type: Rtype::from_u16(65280),
            rdata: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }
    );
    let generic = find(&zone.records, "generic.example.com.", Rtype::A);
    assert_eq!(generic.rdata(), &Rdata::A(Ipv4Addr::new(192, 0, 2, 1)));
}
