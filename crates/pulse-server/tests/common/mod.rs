//! Общие фикстуры интеграционных тестов `pulse-server`.

#![allow(dead_code)]
#![allow(clippy::assert_is_empty)]
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use pulse_dns::{
    DsData, Edns, Message, Name, Question, Rclass, Rdata, Rrset, Rtype, Serial, SoaData, SvcbData,
    Ttl, TxtData,
};
use pulse_server::application::QueryEngine;
use pulse_server::testkit::InMemoryZone;

/// Разбирает имя; в тестах паника допустима.
pub fn name(text: &str) -> Name {
    Name::parse(text).expect("valid test name")
}

/// TTL из `u32`.
pub fn ttl(value: u32) -> Ttl {
    Ttl::new(value).expect("valid test ttl")
}

/// Собирает RRset класса IN.
pub fn rrset(
    owner: &str,
    rr_type: Rtype,
    ttl_value: u32,
    rdatas: impl IntoIterator<Item = Rdata>,
) -> Rrset {
    Rrset::new(name(owner), rr_type, Rclass::IN, ttl(ttl_value), rdatas).expect("valid test rrset")
}

/// Apex `SOA` для `origin`: TTL 3600, minimum 300.
pub fn soa_for(origin: &str) -> Rrset {
    soa_with(origin, 3600, 300)
}

/// Apex `SOA` с явными TTL и minimum.
pub fn soa_with(origin: &str, ttl_value: u32, minimum: u32) -> Rrset {
    rrset(
        origin,
        Rtype::SOA,
        ttl_value,
        [Rdata::Soa(SoaData::new(
            name(&format!("ns1.{origin}")),
            name(&format!("hostmaster.{origin}")),
            Serial::new(1),
            3600,
            600,
            604_800,
            minimum,
        ))],
    )
}

/// Apex `SOA` для `example.com`: TTL 3600, minimum 300.
pub fn soa_example() -> Rrset {
    soa_for("example.com")
}

/// Полная тестовая зона `example.com`.
#[allow(clippy::too_many_lines)]
pub fn example_zone() -> InMemoryZone {
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(soa_example()).expect("soa");
    zone.insert(rrset(
        "example.com",
        Rtype::NS,
        3600,
        [
            Rdata::Ns(name("ns1.example.com")),
            Rdata::Ns(name("ns2.example.com")),
        ],
    ))
    .expect("apex ns");
    zone.insert(rrset(
        "ns1.example.com",
        Rtype::A,
        3600,
        [Rdata::A("192.0.2.1".parse().expect("ipv4"))],
    ))
    .expect("ns1");
    zone.insert(rrset(
        "ns2.example.com",
        Rtype::AAAA,
        3600,
        [Rdata::Aaaa("2001:db8::2".parse().expect("ipv6"))],
    ))
    .expect("ns2");
    zone.insert(rrset(
        "example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.10".parse().expect("ipv4"))],
    ))
    .expect("apex a");
    zone.insert(rrset(
        "example.com",
        Rtype::AAAA,
        300,
        [Rdata::Aaaa("2001:db8::10".parse().expect("ipv6"))],
    ))
    .expect("apex aaaa");
    zone.insert(rrset(
        "example.com",
        Rtype::MX,
        600,
        [
            Rdata::Mx {
                preference: 10,
                exchange: name("mail.example.com"),
            },
            Rdata::Mx {
                preference: 20,
                exchange: name("mx.outside.test"),
            },
        ],
    ))
    .expect("mx");
    zone.insert(rrset(
        "www.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.20".parse().expect("ipv4"))],
    ))
    .expect("www");
    zone.insert(rrset(
        "mail.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.30".parse().expect("ipv4"))],
    ))
    .expect("mail");
    zone.insert(rrset(
        "txt.example.com",
        Rtype::TXT,
        300,
        [Rdata::Txt(
            TxtData::new([b"hello".to_vec(), b"world".to_vec()]).expect("txt"),
        )],
    ))
    .expect("txt");
    zone.insert(rrset(
        "alias.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("www.example.com"))],
    ))
    .expect("alias");
    zone.insert(rrset(
        "chain1.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("chain2.example.com"))],
    ))
    .expect("chain1");
    zone.insert(rrset(
        "chain2.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("www.example.com"))],
    ))
    .expect("chain2");
    zone.insert(rrset(
        "external.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("target.outside.test"))],
    ))
    .expect("external");
    zone.insert(rrset(
        "loop1.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("loop2.example.com"))],
    ))
    .expect("loop1");
    zone.insert(rrset(
        "loop2.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("loop1.example.com"))],
    ))
    .expect("loop2");
    zone.insert(rrset(
        "wild.example.com",
        Rtype::TXT,
        300,
        [Rdata::Txt(TxtData::new([b"base".to_vec()]).expect("txt"))],
    ))
    .expect("wild base");
    zone.insert(rrset(
        "*.wild.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.99".parse().expect("ipv4"))],
    ))
    .expect("wildcard");
    zone.insert(rrset(
        "x.ent.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.40".parse().expect("ipv4"))],
    ))
    .expect("ent child");
    zone.insert(rrset(
        "sub.example.com",
        Rtype::NS,
        300,
        [Rdata::Ns(name("ns1.sub.example.com"))],
    ))
    .expect("delegation");
    zone.insert(rrset(
        "ns1.sub.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.53".parse().expect("ipv4"))],
    ))
    .expect("glue");
    zone.insert(rrset(
        "deep.sub.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.54".parse().expect("ipv4"))],
    ))
    .expect("below cut");
    zone.insert(rrset(
        "sub.example.com",
        Rtype::DS,
        300,
        [Rdata::Ds(
            DsData::new(12_345, 8, 2, vec![0xAB; 32]).expect("ds"),
        )],
    ))
    .expect("ds");
    zone.insert(rrset(
        "dname.example.com",
        Rtype::DNAME,
        300,
        [Rdata::Dname(name("dname-target.example.com"))],
    ))
    .expect("dname");
    zone.insert(rrset(
        "host.dname-target.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.60".parse().expect("ipv4"))],
    ))
    .expect("dname target");
    zone.insert(rrset(
        "_sip._tcp.example.com",
        Rtype::SRV,
        300,
        [Rdata::Srv {
            priority: 10,
            weight: 5,
            port: 5060,
            target: name("sip.example.com"),
        }],
    ))
    .expect("srv");
    zone.insert(rrset(
        "sip.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.70".parse().expect("ipv4"))],
    ))
    .expect("srv target");
    zone.insert(rrset(
        "svc.example.com",
        Rtype::SVCB,
        300,
        [Rdata::Svcb(
            SvcbData::new(1, name("svc-target.example.com"), Vec::new()).expect("svcb"),
        )],
    ))
    .expect("svcb");
    zone.insert(rrset(
        "https.example.com",
        Rtype::HTTPS,
        300,
        [Rdata::Https(
            SvcbData::new(1, name("https-target.example.com"), Vec::new()).expect("https"),
        )],
    ))
    .expect("https");
    zone.insert(rrset(
        "svc-target.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.71".parse().expect("ipv4"))],
    ))
    .expect("svcb target");
    zone.insert(rrset(
        "https-target.example.com",
        Rtype::AAAA,
        300,
        [Rdata::Aaaa("2001:db8::71".parse().expect("ipv6"))],
    ))
    .expect("https target");
    zone
}

/// Движок над одной зоной.
pub fn engine_for(zone: InMemoryZone) -> QueryEngine {
    QueryEngine::new(vec![Arc::new(zone)])
}

/// Движок над тестовой зоной `example.com`.
pub fn example_engine() -> QueryEngine {
    engine_for(example_zone())
}

/// Обычный запрос без EDNS.
pub fn query(qname: &str, qtype: Rtype) -> Message {
    Message::query(0x1234, Question::new(name(qname), qtype, Rclass::IN))
}

/// Запрос с EDNS0.
pub fn edns_query(qname: &str, qtype: Rtype, payload: u16, dnssec_ok: bool) -> Message {
    let mut message = query(qname, qtype);
    let mut edns = Edns::new(payload);
    if dnssec_ok {
        edns = edns.with_dnssec_ok(true);
    }
    message.set_edns(Some(edns));
    message
}

/// Большой RRset TXT для проверки усечения.
pub fn big_txt_rrset(count: usize) -> Rrset {
    let payload = "x".repeat(100);
    let rdatas = (0..count).map(|index| {
        Rdata::Txt(
            TxtData::new([format!("{index:04}-{payload}").into_bytes()]).expect("txt segment"),
        )
    });
    rrset("big.example.com", Rtype::TXT, 300, rdatas)
}

/// Добавляет в зону цепочку CNAME длины `links` с уникальными именами.
pub fn insert_cname_chain(zone: &mut InMemoryZone, links: usize) {
    for index in 0..links {
        let from = format!("c{index}.example.com");
        let to = format!("c{}.example.com", index + 1);
        zone.insert(rrset(&from, Rtype::CNAME, 60, [Rdata::Cname(name(&to))]))
            .expect("chain link");
    }
    zone.insert(rrset(
        &format!("c{links}.example.com"),
        Rtype::A,
        60,
        [Rdata::A("192.0.2.88".parse().expect("ipv4"))],
    ))
    .expect("chain tail");
}

/// `SRV`-RDATA helper для читаемости тестов.
pub fn srv_rdata(priority: u16, weight: u16, port: u16, target: &str) -> Rdata {
    Rdata::Srv {
        priority,
        weight,
        port,
        target: name(target),
    }
}

/// TXT-сегменты ровно на `len` байт полезной нагрузки (255-байтные куски;
/// пустая нагрузка — один пустой сегмент, как требует INV-17).
pub fn txt_segments(len: usize) -> Vec<Vec<u8>> {
    if len == 0 {
        return vec![Vec::new()];
    }
    let mut remaining = len;
    let mut segments = Vec::new();
    while remaining > 0 {
        let take = remaining.min(255);
        segments.push(vec![b'x'; take]);
        remaining -= take;
    }
    segments
}
