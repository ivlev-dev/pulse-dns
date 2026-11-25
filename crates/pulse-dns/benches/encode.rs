//! Micro-bench энкодера: `encode` (Vec) vs `encoded_len` vs `encode_into`.
//!
//! Запуск: `cargo bench -p pulse-dns --bench encode` (release).
//! Печатает ns/op и ops/s; критериев прохождения нет — это замер.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::hint::black_box;
use std::time::Instant;

use pulse_dns::{
    Edns, EncodeOptions, EncodeScratch, Flags, Message, Name, Question, Rclass, Rdata, Record,
    Rtype, Ttl,
};

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

fn record(owner: &str, rtype: Rtype, rdata: Rdata) -> Record {
    Record::new(
        name(owner),
        rtype,
        Rclass::IN,
        Ttl::new(300).expect("ttl"),
        rdata,
    )
    .expect("record")
}

fn response() -> Message {
    let mut message = Message::query(
        0x1234,
        Question::new(name("www.example.com"), Rtype::A, Rclass::IN),
    );
    message.set_flags(Flags::new().with_qr(true).with_aa(true));
    for index in 0..10_u8 {
        message.add_answer(record(
            "www.example.com",
            Rtype::A,
            Rdata::A([192, 0, 2, index].into()),
        ));
    }
    message.add_authority(record(
        "example.com",
        Rtype::NS,
        Rdata::Ns(name("ns1.example.com")),
    ));
    message.add_additional(record(
        "ns1.example.com",
        Rtype::A,
        Rdata::A([192, 0, 2, 53].into()),
    ));
    let mut edns = Edns::new(1232).with_dnssec_ok(true);
    edns.push_option(pulse_dns::EdnsOption::new(10, vec![0_u8; 16]).expect("option"))
        .expect("push");
    message.set_edns(Some(edns));
    message
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
        "{label:<28} {:>9.1} ns/op   {:>14.0} ops/s",
        best * 1e9,
        1.0 / best
    );
}

fn main() {
    let message = response();
    let mut out = vec![0_u8; 65_535];
    let mut scratch = EncodeScratch::new();
    let iterations = 200_000;

    bench("encode (Vec, legacy)", iterations, || {
        message
            .encode(&EncodeOptions::compressed())
            .expect("encode")
            .len()
    });
    bench("encoded_len (count)", iterations, || {
        message.encoded_len().expect("len")
    });
    bench("encode_into (slice)", iterations, || {
        message
            .encode_into_with(&mut out, &EncodeOptions::compressed())
            .expect("encode_into")
    });
    bench("encode_into (scratch)", iterations, || {
        let mut encoder =
            pulse_dns::Encoder::new(&mut out, EncodeOptions::compressed(), &mut scratch);
        encoder.begin_message(message.id()).expect("header");
        for question in message.questions() {
            encoder.write_question(question).expect("question");
        }
        for record in message
            .answers()
            .iter()
            .chain(message.authority().iter())
            .chain(message.additional().iter())
        {
            encoder.write_record(record).expect("record");
        }
        if let Some(edns) = message.edns() {
            encoder.write_edns(edns).expect("edns");
        }
        encoder
            .finish(
                message.flags(),
                pulse_dns::HeaderCounts {
                    question: 1,
                    answer: 10,
                    authority: 1,
                    additional: 2,
                },
            )
            .expect("finish")
    });

    let minimal = Message::query(1, Question::new(name("example.com"), Rtype::A, Rclass::IN));
    bench("minimal encode (Vec)", iterations, || {
        minimal
            .encode(&EncodeOptions::compressed())
            .expect("encode")
            .len()
    });
    bench("minimal encode_into", iterations, || {
        minimal.encode_into(&mut out).expect("encode_into")
    });

    let bytes = message.encoded_len().expect("len");
    println!("\nwire size: {bytes} octets");
}
