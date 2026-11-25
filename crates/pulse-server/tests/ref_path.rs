//! Эквивалентность байтов обычного и zero-copy путей ответа.
//!
//! Быстрый путь обязан выдавать ровно те же октеты, что и `respond_into`
//! для горячего случая (один вопрос, без EDNS, точный `A`/`AAAA`).

mod common;

use common::{engine_for, example_zone, query};
use pulse_dns::{EncodeOptions, MessageRef, Rtype};
use pulse_server::application::{Scratch, Transport};

#[test]
fn zero_copy_matches_streaming_bytes() {
    let engine = engine_for(example_zone());
    let mut fast_scratch = Scratch::new();
    let mut legacy_scratch = Scratch::new();
    let mut fast = [0_u8; 4096];
    let mut legacy = [0_u8; 4096];

    for (label, request) in [
        ("a", query("www.example.com", Rtype::A)),
        ("apex-a", query("example.com", Rtype::A)),
        ("apex-aaaa", query("example.com", Rtype::AAAA)),
    ] {
        let wire = request
            .encode(&EncodeOptions::compressed())
            .expect("query encode");
        let parsed = MessageRef::decode_simple(&wire).expect("simple query");

        let fast_len = engine
            .respond_ref_into(&parsed, Transport::Udp, &mut fast, &mut fast_scratch)
            .expect("fast path");
        let legacy_len = engine
            .respond_into(&request, Transport::Udp, &mut legacy, &mut legacy_scratch)
            .expect("streaming path");

        assert_eq!(
            &fast[..fast_len],
            &legacy[..legacy_len],
            "{label}: fast path bytes differ"
        );
    }
}

#[test]
fn non_hot_queries_fall_back() {
    let engine = engine_for(example_zone());
    let mut scratch = Scratch::new();
    let mut out = [0_u8; 4096];

    // CNAME не обслуживается горячим путём.
    let cname = query("alias.example.com", Rtype::A);
    let wire = cname.encode(&EncodeOptions::compressed()).expect("encode");
    let parsed = MessageRef::decode_simple(&wire).expect("simple query");
    assert!(
        engine
            .respond_ref_into(&parsed, Transport::Udp, &mut out, &mut scratch)
            .is_none()
    );

    // EDNS/лишние секции вообще не разбираются простым представлением.
    let mut edns = wire;
    edns[10] = 0;
    edns[11] = 1;
    assert!(MessageRef::decode_simple(&edns).is_none());
}
