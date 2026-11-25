//! Micro-bench пути ответа: `respond` + `encode` (legacy) vs `respond_into`.
//!
//! Сценарии: обычный A-ответ и усечение большого TXT по 512/1232.
//! Запуск: `cargo bench -p pulse-server --bench respond` (release).
//! Печатает ns/query и qps одного потока; критериев нет — это замер.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use pulse_dns::{
    Edns, EncodeOptions, Message, MessageRef, Name, Question, Rclass, Rdata, Rrset, Rtype, Serial,
    SoaData, Ttl, TxtData,
};
use pulse_server::application::{QueryEngine, Scratch, Transport};
use pulse_server::testkit::InMemoryZone;

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

fn ttl(value: u32) -> Ttl {
    Ttl::new(value).expect("ttl")
}

fn rrset(owner: &str, rtype: Rtype, rdatas: impl IntoIterator<Item = Rdata>) -> Rrset {
    Rrset::new(name(owner), rtype, Rclass::IN, ttl(300), rdatas).expect("rrset")
}

fn zone() -> InMemoryZone {
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(rrset(
        "example.com",
        Rtype::SOA,
        [Rdata::Soa(SoaData::new(
            name("ns1.example.com"),
            name("hostmaster.example.com"),
            Serial::new(1),
            3600,
            600,
            604_800,
            300,
        ))],
    ))
    .expect("soa");
    zone.insert(rrset(
        "example.com",
        Rtype::NS,
        [Rdata::Ns(name("ns1.example.com"))],
    ))
    .expect("ns");
    zone.insert(rrset(
        "ns1.example.com",
        Rtype::A,
        [Rdata::A([192, 0, 2, 53].into())],
    ))
    .expect("glue");
    zone.insert(rrset(
        "www.example.com",
        Rtype::A,
        (0..4_u8).map(|index| Rdata::A([192, 0, 2, index].into())),
    ))
    .expect("a");
    zone.insert(rrset(
        "example.com",
        Rtype::MX,
        [Rdata::Mx {
            preference: 10,
            exchange: name("mail.example.com"),
        }],
    ))
    .expect("mx");
    zone.insert(rrset(
        "mail.example.com",
        Rtype::A,
        [Rdata::A([192, 0, 2, 25].into())],
    ))
    .expect("mail");
    zone.insert(rrset(
        "txt.example.com",
        Rtype::TXT,
        [Rdata::Txt(
            TxtData::new([b"hello".to_vec(), b"world".to_vec()]).expect("txt"),
        )],
    ))
    .expect("txt");
    zone.insert(rrset(
        "big.example.com",
        Rtype::TXT,
        (0..40).map(|index| {
            Rdata::Txt(
                TxtData::new([format!("{index:04}-{}", "x".repeat(100)).into_bytes()])
                    .expect("txt"),
            )
        }),
    ))
    .expect("big txt");
    zone
}

fn bench(label: &str, iterations: u32, mut run: impl FnMut() -> usize) {
    for _ in 0..(iterations / 10).max(1) {
        black_box(run());
    }
    let mut best = f64::INFINITY;
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(run());
        }
        let elapsed = start.elapsed().as_secs_f64();
        best = best.min(elapsed / f64::from(iterations));
    }
    println!(
        "{label:<34} {:>9.0} ns/query   {:>12.0} qps",
        best * 1e9,
        1.0 / best
    );
}

fn query(qname: &str, rtype: Rtype, edns: Option<u16>) -> Message {
    let mut message = Message::query(0x1234, Question::new(name(qname), rtype, Rclass::IN));
    if let Some(payload) = edns {
        message.set_edns(Some(Edns::new(payload)));
    }
    message
}

fn main() {
    let engine = QueryEngine::new(vec![Arc::new(zone())]);
    let mut scratch = Scratch::new();
    let mut out = vec![0_u8; 65_535];
    let iterations = 100_000;

    for (label, request) in [
        (
            "A www.example.com",
            query("www.example.com", Rtype::A, None),
        ),
        (
            "A + EDNS 1232",
            query("www.example.com", Rtype::A, Some(1232)),
        ),
        (
            "TXT big (truncate 512)",
            query("big.example.com", Rtype::TXT, None),
        ),
        (
            "TXT big (truncate 1232)",
            query("big.example.com", Rtype::TXT, Some(1232)),
        ),
    ] {
        bench(&format!("{label} | legacy Vec"), iterations, || {
            engine
                .respond(&request, Transport::Udp)
                .encode(&EncodeOptions::compressed())
                .expect("legacy")
                .len()
        });
        bench(&format!("{label} | respond_into"), iterations, || {
            engine
                .respond_into(&request, Transport::Udp, &mut out, &mut scratch)
                .expect("streaming")
        });
    }

    // Zero-copy путь: сравнение с потоковым для каждого класса запросов.
    println!();
    for (label, request) in [
        ("A", query("www.example.com", Rtype::A, None)),
        ("AAAA", query("example.com", Rtype::AAAA, None)),
        ("MX", query("example.com", Rtype::MX, None)),
        ("TXT", query("txt.example.com", Rtype::TXT, None)),
        ("NXDOMAIN", query("missing.example.com", Rtype::A, None)),
        ("A + EDNS", query("www.example.com", Rtype::A, Some(1232))),
        ("MX + EDNS", query("example.com", Rtype::MX, Some(1232))),
    ] {
        let bytes = request
            .encode(&EncodeOptions::compressed())
            .expect("query encode");
        let parsed = MessageRef::decode_simple_edns(&bytes).expect("simple query");
        bench(&format!("{label} | respond_into"), iterations, || {
            engine
                .respond_into(&request, Transport::Udp, &mut out, &mut scratch)
                .expect("streaming")
        });
        bench(&format!("{label} | zero-copy"), iterations, || {
            engine
                .respond_ref_into(&parsed, Transport::Udp, &mut out, &mut scratch)
                .expect("zero-copy")
        });
    }

    // TCP: полный ответ без усечения.
    let tcp_request = query("big.example.com", Rtype::TXT, None);
    bench("TXT big (TCP) | legacy Vec", iterations, || {
        engine
            .respond(&tcp_request, Transport::Tcp)
            .encode(&EncodeOptions::compressed())
            .expect("legacy")
            .len()
    });
    bench("TXT big (TCP) | respond_into", iterations, || {
        engine
            .respond_into(&tcp_request, Transport::Tcp, &mut out, &mut scratch)
            .expect("streaming")
    });
}
