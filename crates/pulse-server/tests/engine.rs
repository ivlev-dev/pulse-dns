//! Функциональные тесты авторитетного движка.

#![cfg(feature = "testkit")]
#![allow(clippy::assert_is_empty)]

mod common;

use std::sync::Arc;

use common::{
    big_txt_rrset, edns_query, engine_for, example_engine, example_zone, insert_cname_chain, name,
    query, rrset, soa_for, soa_with, txt_segments,
};
use pulse_dns::{
    DecodeLimits, Edns, EdnsOption, EncodeOptions, Flags, Message, Name, Opcode, Rclass, Rcode,
    Rdata, Rrset, Rtype, Ttl, TxtData,
};
use pulse_server::ZoneState;
use pulse_server::application::{EngineConfig, QueryEngine, Transport, ZoneView};
use pulse_server::testkit::{InMemoryZone, MemoryZoneError};
use pulse_server::{LookupOutcome, NEGATIVE_TTL_CAP};

fn encode(message: &Message) -> Vec<u8> {
    message
        .encode(&EncodeOptions::compressed())
        .expect("response encodes")
}

fn decode(message: &Message) -> Message {
    Message::decode(&encode(message), &DecodeLimits::default()).expect("response decodes")
}

fn soa_authority(message: &Message) -> &pulse_dns::Record {
    assert_eq!(message.authority().len(), 1, "one SOA in authority");
    let record = &message.authority()[0];
    assert_eq!(record.rr_type(), Rtype::SOA);
    record
}

#[test]
fn exact_a_and_aaaa_answers() {
    let engine = example_engine();

    let response = engine.respond(&query("www.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().qr());
    assert!(response.flags().aa());
    assert!(!response.flags().ra());
    assert_eq!(response.answers().len(), 1);
    let record = &response.answers()[0];
    assert_eq!(record.owner(), &name("www.example.com"));
    assert_eq!(record.ttl(), pulse_dns::Ttl::new(300).expect("ttl"));
    assert_eq!(
        record.rdata(),
        &Rdata::A("192.0.2.20".parse().expect("ipv4"))
    );

    let response = engine.respond(&query("example.com", Rtype::AAAA), Transport::Udp);
    assert_eq!(response.answers().len(), 1);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::Aaaa("2001:db8::10".parse().expect("ipv6"))
    );
}

#[test]
fn mx_and_txt_answers() {
    let engine = example_engine();
    let response = engine.respond(&query("example.com", Rtype::MX), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 2);
    assert!(response.answers().iter().all(|r| r.rr_type() == Rtype::MX));

    let response = engine.respond(&query("txt.example.com", Rtype::TXT), Transport::Udp);
    assert_eq!(response.answers().len(), 1);
    let Rdata::Txt(text) = response.answers()[0].rdata() else {
        panic!("expected TXT");
    };
    assert_eq!(text.segments().len(), 2);
}

#[test]
fn cname_chain_inside_zone() {
    let engine = example_engine();
    let response = engine.respond(&query("alias.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert_eq!(response.answers().len(), 2);
    assert_eq!(response.answers()[0].rr_type(), Rtype::CNAME);
    assert_eq!(response.answers()[0].owner(), &name("alias.example.com"));
    assert_eq!(response.answers()[1].rr_type(), Rtype::A);
    assert_eq!(response.answers()[1].owner(), &name("www.example.com"));
}

#[test]
fn cname_target_outside_zone_stops_chain() {
    let engine = example_engine();
    let response = engine.respond(&query("external.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 1);
    assert_eq!(response.answers()[0].rr_type(), Rtype::CNAME);
    assert!(response.authority().is_empty());
}

#[test]
fn cname_loop_is_servfail() {
    let engine = example_engine();
    let response = engine.respond(&query("loop1.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
    assert!(response.answers().is_empty());
}

#[test]
fn cname_chain_is_limited() {
    let mut zone = example_zone();
    insert_cname_chain(&mut zone, 20);
    let engine = engine_for(zone);
    let response = engine.respond(&query("c0.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 16);
    assert!(
        response
            .answers()
            .iter()
            .all(|record| record.rr_type() == Rtype::CNAME)
    );
}

#[test]
fn wildcard_matches_multiple_labels() {
    let engine = example_engine();
    for qname in ["foo.wild.example.com", "foo.bar.wild.example.com"] {
        let response = engine.respond(&query(qname, Rtype::A), Transport::Udp);
        assert_eq!(response.rcode(), Rcode::NOERROR, "{qname}");
        assert!(response.flags().aa());
        assert_eq!(response.answers().len(), 1, "{qname}");
        let record = &response.answers()[0];
        assert_eq!(record.owner(), &name(qname));
        assert_eq!(
            record.rdata(),
            &Rdata::A("192.0.2.99".parse().expect("ipv4"))
        );
    }
}

#[test]
fn wildcard_nodata_has_soa() {
    let engine = example_engine();
    let response = engine.respond(&query("foo.wild.example.com", Rtype::AAAA), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.answers().is_empty());
    let soa = soa_authority(&response);
    assert_eq!(soa.ttl(), pulse_dns::Ttl::new(300).expect("ttl"));
}

#[test]
fn wildcard_requires_closest_encloser() {
    let mut zone = InMemoryZone::new(name("closest.test"));
    zone.insert(soa_for("closest.test")).expect("soa");
    zone.insert(rrset(
        "sub.closest.test",
        Rtype::TXT,
        300,
        [Rdata::Txt(
            pulse_dns::TxtData::new([b"exists".to_vec()]).expect("txt"),
        )],
    ))
    .expect("sub");
    zone.insert(rrset(
        "*.closest.test",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.200".parse().expect("ipv4"))],
    ))
    .expect("wildcard");
    let engine = engine_for(zone);

    let response = engine.respond(&query("foo.closest.test", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 1);

    let response = engine.respond(&query("foo.sub.closest.test", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert!(response.answers().is_empty());
}

#[test]
fn nxdomain_has_negative_soa() {
    let engine = example_engine();
    let response = engine.respond(&query("nothere.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert!(response.flags().aa());
    assert!(response.answers().is_empty());
    let soa = soa_authority(&response);
    assert_eq!(soa.ttl(), pulse_dns::Ttl::new(300).expect("ttl"));
    assert_eq!(soa.owner(), &name("example.com"));
}

#[test]
fn nodata_has_negative_soa() {
    let engine = example_engine();
    let response = engine.respond(&query("www.example.com", Rtype::AAAA), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.answers().is_empty());
    let soa = soa_authority(&response);
    assert_eq!(soa.ttl(), pulse_dns::Ttl::new(300).expect("ttl"));
}

#[test]
fn empty_non_terminal_is_nodata() {
    let engine = example_engine();
    let response = engine.respond(&query("ent.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.answers().is_empty());
    assert_eq!(response.authority().len(), 1);
}

#[test]
fn delegation_referral_with_glue() {
    let engine = example_engine();
    let response = engine.respond(&query("host.sub.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(!response.flags().aa());
    assert!(response.answers().is_empty());
    assert_eq!(response.authority().len(), 1);
    assert_eq!(response.authority()[0].rr_type(), Rtype::NS);
    assert_eq!(response.authority()[0].owner(), &name("sub.example.com"));

    let glue: Vec<_> = response
        .additional()
        .iter()
        .filter(|record| record.owner() == &name("ns1.sub.example.com"))
        .collect();
    assert_eq!(glue.len(), 1);
    assert_eq!(glue[0].rr_type(), Rtype::A);
}

#[test]
fn delegation_includes_ds_only_with_do() {
    let engine = example_engine();

    let response = engine.respond(&query("host.sub.example.com", Rtype::A), Transport::Udp);
    assert!(
        response
            .authority()
            .iter()
            .all(|record| record.rr_type() != Rtype::DS)
    );

    let request = edns_query("host.sub.example.com", Rtype::A, 1232, true);
    let response = engine.respond(&request, Transport::Udp);
    assert!(!response.flags().aa());
    assert_eq!(response.authority().len(), 2);
    assert!(
        response
            .authority()
            .iter()
            .any(|record| record.rr_type() == Rtype::DS)
    );
    assert!(
        response
            .authority()
            .iter()
            .any(|record| record.rr_type() == Rtype::NS)
    );
}

#[test]
fn ds_query_at_cut_is_authoritative() {
    let engine = example_engine();
    let response = engine.respond(
        &edns_query("sub.example.com", Rtype::DS, 1232, true),
        Transport::Udp,
    );
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert_eq!(response.answers().len(), 1);
    assert_eq!(response.answers()[0].rr_type(), Rtype::DS);
    assert_eq!(response.answers()[0].owner(), &name("sub.example.com"));
}

#[test]
fn ns_query_at_cut_is_referral() {
    let engine = example_engine();
    let response = engine.respond(&query("sub.example.com", Rtype::NS), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(!response.flags().aa());
    assert!(response.answers().is_empty());
    assert_eq!(response.authority()[0].rr_type(), Rtype::NS);
}

#[test]
fn any_policy_synthesizes_hinfo() {
    let engine = example_engine();
    let response = engine.respond(&query("example.com", Rtype::ANY), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert_eq!(response.answers().len(), 1);
    let record = &response.answers()[0];
    assert_eq!(record.rr_type(), Rtype::from_u16(13));
    assert_eq!(record.ttl(), pulse_dns::Ttl::new(3600).expect("ttl"));
    let Rdata::Unknown { rdata, .. } = record.rdata() else {
        panic!("HINFO synthesized as opaque RDATA");
    };
    assert_eq!(rdata, &[8, b'R', b'F', b'C', b'8', b'4', b'8', b'2', 0]);
}

#[test]
fn any_policy_returns_cname_owner() {
    let engine = example_engine();
    let response = engine.respond(&query("alias.example.com", Rtype::ANY), Transport::Udp);
    assert_eq!(response.answers().len(), 1);
    assert_eq!(response.answers()[0].rr_type(), Rtype::CNAME);
}

#[test]
fn any_for_missing_name_is_nxdomain() {
    let engine = example_engine();
    let response = engine.respond(&query("missing.example.com", Rtype::ANY), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert_eq!(response.authority().len(), 1);
}

#[test]
fn edns_opt_is_echoed_with_capped_payload() {
    let engine = example_engine();

    let response = engine.respond(
        &edns_query("www.example.com", Rtype::A, 4096, true),
        Transport::Udp,
    );
    let edns = response.edns().expect("OPT in response");
    assert_eq!(edns.udp_payload_size(), 1232);
    assert_eq!(edns.version(), 0);
    assert!(edns.dnssec_ok());
    assert!(edns.options().is_empty());

    let response = engine.respond(
        &edns_query("www.example.com", Rtype::A, 600, false),
        Transport::Udp,
    );
    assert_eq!(response.edns().expect("OPT").udp_payload_size(), 600);

    let response = engine.respond(
        &edns_query("www.example.com", Rtype::A, 100, false),
        Transport::Udp,
    );
    assert_eq!(response.edns().expect("OPT").udp_payload_size(), 512);

    let response = engine.respond(&query("www.example.com", Rtype::A), Transport::Udp);
    assert!(response.edns().is_none());
}

#[test]
fn unknown_edns_options_are_ignored() {
    let engine = example_engine();
    let mut request = edns_query("www.example.com", Rtype::A, 1232, false);
    let mut edns = Edns::new(1232);
    edns.push_option(EdnsOption::new(65_001, vec![1, 2, 3]).expect("option"))
        .expect("option");
    request.set_edns(Some(edns));
    let response = engine.respond(&request, Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.edns().expect("OPT").options().is_empty());
}

#[test]
fn badvers_for_unsupported_edns_version() {
    let engine = example_engine();
    let mut request = query("www.example.com", Rtype::A);
    request.set_edns(Some(Edns::new(1232).with_version(1)));
    let response = engine.respond(&request, Transport::Udp);
    assert_eq!(response.rcode(), Rcode::BADVERS);
    assert!(response.answers().is_empty());
    let edns = response.edns().expect("OPT");
    assert_eq!(edns.version(), 0);
    assert_eq!(edns.extended_rcode(), 1);
}

#[test]
fn notimp_for_non_query_opcode() {
    let engine = example_engine();
    let mut request = query("www.example.com", Rtype::A);
    request.set_opcode(Opcode::UPDATE);
    let response = engine.respond(&request, Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOTIMP);
    assert!(!response.flags().aa());
    assert!(response.answers().is_empty());
}

#[test]
fn notimp_for_transfer_qtypes() {
    let engine = example_engine();
    let response = engine.respond(&query("example.com", Rtype::AXFR), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOTIMP);
}

#[test]
fn refused_for_outside_zone() {
    let engine = example_engine();
    let response = engine.respond(&query("other.test", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::REFUSED);
    assert!(!response.flags().aa());
    assert!(!response.flags().ra());
    assert!(response.answers().is_empty());
}

#[test]
fn refused_for_non_serving_zone() {
    let zone = InMemoryZone::new(name("example.com")).with_state(ZoneState::Initializing);
    let engine = engine_for(zone);
    let response = engine.respond(&query("example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::REFUSED);
}

#[test]
fn formerr_for_missing_question() {
    let engine = example_engine();
    let request = Message::new(0x0042, Flags::new().with_rd(true));
    let response = engine.respond(&request, Transport::Udp);
    assert_eq!(response.rcode(), Rcode::FORMERR);
    assert_eq!(response.id(), 0x0042);
}

#[test]
fn formerr_for_multiple_questions() {
    let engine = example_engine();
    let mut request = query("www.example.com", Rtype::A);
    request.add_question(pulse_dns::Question::new(
        name("txt.example.com"),
        Rtype::TXT,
        Rclass::IN,
    ));
    let response = engine.respond(&request, Transport::Udp);
    assert_eq!(response.rcode(), Rcode::FORMERR);
    assert_eq!(response.questions().len(), 1);
}

#[test]
fn refused_for_foreign_class() {
    let engine = example_engine();
    let request = Message::query(
        0x7777,
        pulse_dns::Question::new(name("www.example.com"), Rtype::A, Rclass::CH),
    );
    let response = engine.respond(&request, Transport::Udp);
    assert_eq!(response.rcode(), Rcode::REFUSED);
}

#[test]
fn rd_is_echoed_and_ra_is_zero() {
    let engine = example_engine();
    let mut request = query("www.example.com", Rtype::A);
    request.set_flags(request.flags().with_rd(true));
    let response = engine.respond(&request, Transport::Udp);
    assert!(response.flags().rd());
    assert!(!response.flags().ra());
    assert_eq!(response.answers().len(), 1);
}

#[test]
fn truncates_to_512_without_edns() {
    let mut zone = example_zone();
    zone.insert(big_txt_rrset(30)).expect("big rrset");
    let engine = engine_for(zone);
    let response = engine.respond(&query("big.example.com", Rtype::TXT), Transport::Udp);
    assert!(response.flags().tc());
    assert!(response.answers().len() < 30);
    let bytes = encode(&response);
    assert!(bytes.len() <= 512, "response is {} octets", bytes.len());
    let _ = decode(&response);
}

#[test]
fn truncates_to_negotiated_1232() {
    let mut zone = example_zone();
    zone.insert(big_txt_rrset(30)).expect("big rrset");
    let engine = engine_for(zone);
    let response = engine.respond(
        &edns_query("big.example.com", Rtype::TXT, 4096, false),
        Transport::Udp,
    );
    assert!(response.flags().tc());
    assert!(!response.answers().is_empty());
    let bytes = encode(&response);
    assert!(bytes.len() <= 1232, "response is {} octets", bytes.len());
    assert!(response.edns().is_some());
    let _ = decode(&response);
}

#[test]
fn tcp_does_not_truncate() {
    let mut zone = example_zone();
    zone.insert(big_txt_rrset(30)).expect("big rrset");
    let engine = engine_for(zone);
    let response = engine.respond(
        &edns_query("big.example.com", Rtype::TXT, 1232, false),
        Transport::Tcp,
    );
    assert!(!response.flags().tc());
    assert_eq!(response.answers().len(), 30);
    let bytes = encode(&response);
    assert!(bytes.len() > 1232);
    assert!(bytes.len() <= pulse_dns::MAX_MESSAGE_LEN);
}

#[test]
fn responses_use_name_compression() {
    let engine = example_engine();
    let response = engine.respond(&query("example.com", Rtype::MX), Transport::Udp);
    let compressed = response
        .encode(&EncodeOptions::compressed())
        .expect("compressed");
    let uncompressed = response
        .encode(&EncodeOptions::uncompressed())
        .expect("uncompressed");
    assert!(compressed.len() < uncompressed.len());
    let decoded = Message::decode(&compressed, &DecodeLimits::default()).expect("decode");
    assert_eq!(decoded, response);
}

#[test]
fn qname_case_is_not_preserved() {
    let engine = example_engine();
    let response = engine.respond(&query("WWW.ExAmPle.CoM", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 1);
    // Документированный gap (SEC-DNS-011): `Name` канонизирует регистр,
    // поэтому вопрос в ответе — в нижнем регистре.
    assert_eq!(response.questions()[0].qname(), &name("www.example.com"));
}

#[test]
fn dname_synthesis_and_chase() {
    let engine = example_engine();
    let response = engine.respond(&query("host.dname.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert_eq!(response.answers().len(), 3);
    let types: Vec<_> = response
        .answers()
        .iter()
        .map(pulse_dns::Record::rr_type)
        .collect();
    assert_eq!(types, vec![Rtype::DNAME, Rtype::CNAME, Rtype::A]);
    assert_eq!(
        response.answers()[1].owner(),
        &name("host.dname.example.com")
    );
    assert_eq!(
        response.answers()[2].owner(),
        &name("host.dname-target.example.com")
    );
}

#[test]
fn dname_overflow_is_yxdomain() {
    let label = "a".repeat(63);
    let target = format!("{label}.{label}.{label}");
    let origin = name("dlong.example");
    let mut zone = InMemoryZone::new(origin);
    zone.insert(soa_for("dlong.example")).expect("soa");
    zone.insert(rrset(
        "long.dlong.example",
        Rtype::DNAME,
        300,
        [Rdata::Dname(name(&target))],
    ))
    .expect("dname");
    let engine = engine_for(zone);
    let qname = format!("{label}.long.dlong.example");
    let response = engine.respond(&query(&qname, Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::YXDOMAIN);
    assert!(response.flags().aa());
    assert_eq!(response.answers()[0].rr_type(), Rtype::DNAME);
}

#[test]
fn additional_glue_for_mx_srv_and_apex_ns() {
    let engine = example_engine();

    let response = engine.respond(&query("example.com", Rtype::MX), Transport::Udp);
    assert!(
        response
            .additional()
            .iter()
            .any(|record| record.owner() == &name("mail.example.com")
                && record.rr_type() == Rtype::A)
    );
    assert!(
        !response
            .additional()
            .iter()
            .any(|record| record.owner() == &name("mx.outside.test"))
    );

    let response = engine.respond(&query("_sip._tcp.example.com", Rtype::SRV), Transport::Udp);
    assert!(
        response.additional().iter().any(
            |record| record.owner() == &name("sip.example.com") && record.rr_type() == Rtype::A
        )
    );

    let response = engine.respond(&query("example.com", Rtype::NS), Transport::Udp);
    assert!(
        response.additional().iter().any(
            |record| record.owner() == &name("ns1.example.com") && record.rr_type() == Rtype::A
        )
    );
    assert!(response.additional().iter().any(
        |record| record.owner() == &name("ns2.example.com") && record.rr_type() == Rtype::AAAA
    ));
}

#[test]
fn stats_count_outcomes() {
    let mut zone = example_zone();
    zone.insert(big_txt_rrset(30)).expect("big rrset");
    let engine = engine_for(zone);

    let _ = engine.respond(&query("missing.example.com", Rtype::A), Transport::Udp);
    let _ = engine.respond(&query("www.example.com", Rtype::AAAA), Transport::Udp);
    let _ = engine.respond(&query("outside.test", Rtype::A), Transport::Udp);
    let _ = engine.respond(&query("big.example.com", Rtype::TXT), Transport::Udp);
    let mut notimp = query("www.example.com", Rtype::A);
    notimp.set_opcode(Opcode::STATUS);
    let _ = engine.respond(&notimp, Transport::Udp);
    let mut badvers = query("www.example.com", Rtype::A);
    badvers.set_edns(Some(Edns::new(1232).with_version(2)));
    let _ = engine.respond(&badvers, Transport::Udp);

    let stats = engine.stats().snapshot();
    assert_eq!(stats.queries, 6);
    assert_eq!(stats.nxdomain, 1);
    assert_eq!(stats.nodata, 1);
    assert_eq!(stats.refused, 1);
    assert_eq!(stats.truncated, 1);
    assert_eq!(stats.notimp, 1);
    assert_eq!(stats.badvers, 1);
    assert_eq!(stats.servfail, 0);
}

#[test]
fn longest_suffix_zone_is_selected() {
    let mut parent = example_zone();
    parent
        .insert(rrset(
            "www.example.com",
            Rtype::TXT,
            300,
            [Rdata::Txt(
                pulse_dns::TxtData::new([b"parent".to_vec()]).expect("txt"),
            )],
        ))
        .expect("parent txt");

    let mut child = InMemoryZone::new(name("sub.example.com"));
    child.insert(soa_for("sub.example.com")).expect("soa");
    child
        .insert(rrset(
            "sub.example.com",
            Rtype::NS,
            300,
            [Rdata::Ns(name("ns1.sub.example.com"))],
        ))
        .expect("ns");
    child
        .insert(rrset(
            "www.sub.example.com",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.80".parse().expect("ipv4"))],
        ))
        .expect("child a");

    let engine = QueryEngine::new(vec![
        std::sync::Arc::new(parent),
        std::sync::Arc::new(child),
    ]);
    let response = engine.respond(&query("www.sub.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.80".parse().expect("ipv4"))
    );
}

#[test]
fn lookup_port_contract_for_delegation() {
    let zone = example_zone();
    assert!(zone.is_delegation(&name("sub.example.com")));
    assert!(!zone.is_delegation(&name("deep.sub.example.com")));
    match zone.lookup(&name("deep.sub.example.com"), Rtype::A) {
        pulse_server::LookupOutcome::Referral => {}
        other => panic!("expected Referral, got {other:?}"),
    }
    match zone.lookup(&name("sub.example.com"), Rtype::NS) {
        pulse_server::LookupOutcome::Delegation { ns, ds } => {
            assert_eq!(ns.rr_type(), Rtype::NS);
            assert!(ds.is_some());
        }
        other => panic!("expected Delegation, got {other:?}"),
    }
}

#[test]
fn rrsig_lookup_is_filtered_by_covered_type() {
    use pulse_dns::RrsigData;

    let mut zone = example_zone();
    let signature = RrsigData::new(
        Rtype::A,
        8,
        3,
        300,
        1_700_000_000,
        1_600_000_000,
        12_345,
        name("example.com"),
        vec![0xAA; 32],
    )
    .expect("rrsig");
    let other = RrsigData::new(
        Rtype::TXT,
        8,
        3,
        300,
        1_700_000_000,
        1_600_000_000,
        12_345,
        name("example.com"),
        vec![0xBB; 32],
    )
    .expect("rrsig");
    zone.insert(rrset(
        "www.example.com",
        Rtype::RRSIG,
        300,
        [Rdata::Rrsig(signature), Rdata::Rrsig(other)],
    ))
    .expect("rrsig rrset");

    let a_signatures = zone.lookup_all_rrsig(&name("www.example.com"), Rtype::A);
    assert_eq!(a_signatures.len(), 1);
    assert_eq!(a_signatures[0].len(), 1);
    let txt_signatures = zone.lookup_all_rrsig(&name("www.example.com"), Rtype::TXT);
    assert_eq!(txt_signatures.len(), 1);
    assert_eq!(txt_signatures[0].len(), 1);
    assert!(
        zone.lookup_all_rrsig(&name("www.example.com"), Rtype::MX)
            .is_empty()
    );
}

#[test]
fn multi_zone_refused_when_no_origin_matches() {
    let engine = example_engine();
    for qname in ["example.com.evil.test", "com", "."] {
        let response = engine.respond(&query(qname, Rtype::SOA), Transport::Udp);
        assert_eq!(response.rcode(), Rcode::REFUSED, "{qname}");
    }
}

#[test]
fn missing_soa_maps_to_servfail() {
    let zone = InMemoryZone::new(name("example.com"));
    let engine = engine_for(zone);
    let response = engine.respond(&query("missing.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
    assert_eq!(engine.stats().servfail(), 1);
}

#[test]
fn empty_engine_refuses_everything() {
    let engine = QueryEngine::new(Vec::new());
    let response = engine.respond(&query("example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::REFUSED);
}

#[test]
fn zone_state_is_exposed_by_port() {
    let zone = example_zone();
    assert_eq!(zone.state(), ZoneState::Serving);
    assert_eq!(zone.class(), Rclass::IN);
    assert_eq!(zone.origin(), zone.apex());
    assert!(zone.soa().is_some());
    assert!(zone.ns().is_some());
    assert!(zone.node_exists(&name("www.example.com")));
    assert!(!zone.node_exists(&name("outside.test")));
}

#[test]
fn engine_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<QueryEngine>();
    assert_send_sync::<InMemoryZone>();
}

fn hinfo_response_ttl(engine: &QueryEngine, qname: &str) -> Ttl {
    let response = engine.respond(&query(qname, Rtype::ANY), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR, "{qname}");
    assert_eq!(response.answers().len(), 1, "{qname}");
    let record = &response.answers()[0];
    assert_eq!(record.rr_type(), Rtype::from_u16(13), "{qname}");
    record.ttl()
}

#[test]
fn any_existing_names_and_ent_get_hinfo() {
    let engine = example_engine();
    assert_eq!(
        hinfo_response_ttl(&engine, "example.com"),
        Ttl::new(3600).expect("ttl")
    );
    assert_eq!(
        hinfo_response_ttl(&engine, "www.example.com"),
        Ttl::new(3600).expect("ttl")
    );
    assert_eq!(
        hinfo_response_ttl(&engine, "ent.example.com"),
        Ttl::new(3600).expect("ttl")
    );
}

#[test]
fn any_wildcard_cname_only_for_missing_names() {
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(soa_for("example.com")).expect("soa");
    zone.insert(rrset(
        "*.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("target.example.com"))],
    ))
    .expect("wildcard cname");
    zone.insert(rrset(
        "target.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.90".parse().expect("ipv4"))],
    ))
    .expect("target");
    zone.insert(rrset(
        "existing.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.91".parse().expect("ipv4"))],
    ))
    .expect("existing");
    let engine = engine_for(zone);

    // Существующее имя (включая apex) — HINFO, wildcard не применяется.
    assert_eq!(
        hinfo_response_ttl(&engine, "example.com"),
        Ttl::new(3600).expect("ttl")
    );
    assert_eq!(
        hinfo_response_ttl(&engine, "existing.example.com"),
        Ttl::new(3600).expect("ttl")
    );

    // Несуществующее имя — wildcard-CNAME синтезируется с owner = QNAME.
    let response = engine.respond(&query("missing.example.com", Rtype::ANY), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 1);
    assert_eq!(response.answers()[0].rr_type(), Rtype::CNAME);
    assert_eq!(response.answers()[0].owner(), &name("missing.example.com"));
}

#[test]
fn ds_nodata_at_cut_has_negative_soa() {
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(soa_for("example.com")).expect("soa");
    zone.insert(rrset(
        "child.example.com",
        Rtype::NS,
        300,
        [Rdata::Ns(name("ns1.child.example.com"))],
    ))
    .expect("cut");
    zone.insert(rrset(
        "ns1.child.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.150".parse().expect("ipv4"))],
    ))
    .expect("glue");
    let engine = engine_for(zone);

    for request in [
        query("child.example.com", Rtype::DS),
        edns_query("child.example.com", Rtype::DS, 1232, true),
    ] {
        let response = engine.respond(&request, Transport::Udp);
        assert_eq!(response.rcode(), Rcode::NOERROR);
        assert!(response.flags().aa());
        assert!(response.answers().is_empty());
        let soa = soa_authority(&response);
        assert_eq!(soa.ttl(), Ttl::new(300).expect("ttl"));
    }
}

#[test]
fn ds_at_cut_without_do_is_answer() {
    let engine = example_engine();
    let response = engine.respond(&query("sub.example.com", Rtype::DS), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert_eq!(response.answers().len(), 1);
    assert_eq!(response.answers()[0].rr_type(), Rtype::DS);
}

#[test]
fn additional_overflow_does_not_set_tc() {
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(soa_for("example.com")).expect("soa");
    let mut mx = Vec::new();
    for index in 0..10_u32 {
        let target = format!("m{index}.bulk.example.com");
        mx.push(Rdata::Mx {
            preference: u16::try_from(index).expect("preference"),
            exchange: name(&target),
        });
        zone.insert(rrset(
            &target,
            Rtype::A,
            300,
            [Rdata::A(
                format!("192.0.2.{}", 100 + index).parse().expect("ipv4"),
            )],
        ))
        .expect("mx target a");
        zone.insert(rrset(
            &target,
            Rtype::AAAA,
            300,
            [Rdata::Aaaa(
                format!("2001:db8::{}", 100 + index).parse().expect("ipv6"),
            )],
        ))
        .expect("mx target aaaa");
    }
    zone.insert(rrset("bulk.example.com", Rtype::MX, 300, mx))
        .expect("bulk mx");
    let engine = engine_for(zone);
    let response = engine.respond(&query("bulk.example.com", Rtype::MX), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(!response.flags().tc());
    assert_eq!(response.answers().len(), 10);
    assert!(!response.additional().is_empty());
    assert!(response.additional().len() < 20);
    let bytes = encode(&response);
    assert!(bytes.len() <= 512, "response is {} octets", bytes.len());
    assert_eq!(engine.stats().truncated(), 0);
    let _ = decode(&response);
}

#[test]
fn answer_overflow_still_sets_tc() {
    let mut zone = example_zone();
    zone.insert(big_txt_rrset(30)).expect("big rrset");
    let engine = engine_for(zone);
    let response = engine.respond(&query("big.example.com", Rtype::TXT), Transport::Udp);
    assert!(response.flags().tc());
    assert!(response.answers().len() < 30);
    assert!(encode(&response).len() <= 512);
}

#[test]
fn bailiwick_skips_targets_below_foreign_cut() {
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(soa_for("example.com")).expect("soa");
    zone.insert(rrset(
        "example.com",
        Rtype::NS,
        300,
        [
            Rdata::Ns(name("ns1.example.com")),
            Rdata::Ns(name("ns.other.example.com")),
        ],
    ))
    .expect("apex ns");
    zone.insert(rrset(
        "ns1.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.160".parse().expect("ipv4"))],
    ))
    .expect("ns1");
    zone.insert(rrset(
        "other.example.com",
        Rtype::NS,
        300,
        [Rdata::Ns(name("ns1.other.example.com"))],
    ))
    .expect("foreign cut");
    zone.insert(rrset(
        "ns.other.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.161".parse().expect("ipv4"))],
    ))
    .expect("glue below radar");
    zone.insert(rrset(
        "ns1.other.example.com",
        Rtype::A,
        300,
        [Rdata::A("192.0.2.162".parse().expect("ipv4"))],
    ))
    .expect("foreign glue");
    let engine = engine_for(zone);

    let response = engine.respond(&query("example.com", Rtype::NS), Transport::Udp);
    assert!(
        response
            .additional()
            .iter()
            .any(|record| record.owner() == &name("ns1.example.com"))
    );
    assert!(
        !response
            .additional()
            .iter()
            .any(|record| record.owner() == &name("ns.other.example.com"))
    );

    let response = engine.respond(&query("host.other.example.com", Rtype::A), Transport::Udp);
    assert!(!response.flags().aa());
    assert!(
        response
            .additional()
            .iter()
            .any(|record| record.owner() == &name("ns1.other.example.com"))
    );
}

#[test]
fn additional_order_is_deterministic() {
    let engine = example_engine();
    for qtype in [Rtype::MX, Rtype::NS, Rtype::SVCB, Rtype::HTTPS] {
        let request = query("example.com", qtype);
        let first = encode(&engine.respond(&request, Transport::Udp));
        let second = encode(&engine.respond(&request, Transport::Udp));
        assert_eq!(first, second, "{qtype}");
    }

    let response = engine.respond(&query("example.com", Rtype::NS), Transport::Udp);
    let owners: Vec<&Name> = response
        .additional()
        .iter()
        .map(pulse_dns::Record::owner)
        .collect();
    let mut sorted = owners.clone();
    sorted.sort_by(|left, right| left.cmp_canonical(right));
    assert_eq!(owners, sorted);
}

#[test]
fn self_cname_is_servfail() {
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(soa_for("example.com")).expect("soa");
    zone.insert(rrset(
        "self.example.com",
        Rtype::CNAME,
        120,
        [Rdata::Cname(name("self.example.com"))],
    ))
    .expect("self cname");
    let engine = engine_for(zone);
    let response = engine.respond(&query("self.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
    assert!(response.answers().is_empty());
}

#[test]
fn dname_cycle_is_servfail() {
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(soa_for("example.com")).expect("soa");
    zone.insert(rrset(
        "a.example.com",
        Rtype::DNAME,
        300,
        [Rdata::Dname(name("b.example.com"))],
    ))
    .expect("dname a");
    zone.insert(rrset(
        "b.example.com",
        Rtype::DNAME,
        300,
        [Rdata::Dname(name("a.example.com"))],
    ))
    .expect("dname b");
    let engine = engine_for(zone);
    let response = engine.respond(&query("x.a.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
    assert!(response.answers().is_empty());
}

#[test]
fn negative_ttl_is_capped() {
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(soa_with("example.com", 604_800, 604_800))
        .expect("soa");
    let engine = engine_for(zone);
    let response = engine.respond(&query("missing.example.com", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    let soa = soa_authority(&response);
    assert_eq!(soa.ttl(), Ttl::new(NEGATIVE_TTL_CAP).expect("cap"));
}

#[test]
fn dname_at_apex_is_rejected_by_testkit() {
    let mut zone = InMemoryZone::new(name("example.com"));
    let error = zone
        .insert(rrset(
            "example.com",
            Rtype::DNAME,
            300,
            [Rdata::Dname(name("target.example.com"))],
        ))
        .expect_err("apex DNAME must be rejected");
    assert!(matches!(error, MemoryZoneError::DnameAtApex { .. }));
}

#[test]
fn any_hinfo_ttl_is_configurable() {
    let config = EngineConfig {
        any_hinfo_ttl: Ttl::new(60).expect("ttl"),
    };
    let engine = QueryEngine::with_config(vec![Arc::new(example_zone())], config);
    assert_eq!(engine.config(), config);
    assert_eq!(
        hinfo_response_ttl(&engine, "example.com"),
        Ttl::new(60).expect("ttl")
    );
}

#[test]
fn svcb_and_https_add_target_addresses() {
    let engine = example_engine();

    let response = engine.respond(&query("svc.example.com", Rtype::SVCB), Transport::Udp);
    assert_eq!(response.answers().len(), 1);
    assert!(
        response
            .additional()
            .iter()
            .any(|record| record.owner() == &name("svc-target.example.com")
                && record.rr_type() == Rtype::A)
    );

    let response = engine.respond(&query("https.example.com", Rtype::HTTPS), Transport::Udp);
    assert_eq!(response.answers().len(), 1);
    assert!(
        response
            .additional()
            .iter()
            .any(|record| record.owner() == &name("https-target.example.com")
                && record.rr_type() == Rtype::AAAA)
    );
}

struct BrokenZone {
    origin: Name,
    outcome: LookupOutcome,
}

impl ZoneView for BrokenZone {
    fn origin(&self) -> &Name {
        &self.origin
    }

    fn apex(&self) -> &Name {
        &self.origin
    }

    fn soa(&self) -> Option<&Rrset> {
        None
    }

    fn ns(&self) -> Option<&Rrset> {
        None
    }

    fn class(&self) -> Rclass {
        Rclass::IN
    }

    fn state(&self) -> ZoneState {
        ZoneState::Serving
    }

    fn lookup(&self, _name: &Name, _rtype: Rtype) -> LookupOutcome {
        self.outcome.clone()
    }

    fn lookup_all_rrsig(&self, _name: &Name, _covered: Rtype) -> Vec<Rrset> {
        Vec::new()
    }

    fn is_delegation(&self, _name: &Name) -> bool {
        false
    }

    fn glue(&self, _name: &Name) -> Vec<Rrset> {
        Vec::new()
    }

    fn node_exists(&self, _name: &Name) -> bool {
        true
    }
}

#[test]
fn inconsistent_port_outcomes_are_servfail() {
    for outcome in [LookupOutcome::Referral, LookupOutcome::ZoneNotFound] {
        let engine = QueryEngine::new(vec![Arc::new(BrokenZone {
            origin: name("example.com"),
            outcome,
        })]);
        let response = engine.respond(&query("www.example.com", Rtype::A), Transport::Udp);
        assert_eq!(response.rcode(), Rcode::SERVFAIL);
        assert_eq!(engine.stats().servfail(), 1);
    }
}

#[test]
fn ten_thousand_zones_are_indexed_correctly() {
    let mut zones: Vec<Arc<dyn ZoneView>> = Vec::with_capacity(10_002);
    for index in 0..10_000_u32 {
        let origin = format!("z{index}.test");
        let mut zone = InMemoryZone::new(name(&origin));
        zone.insert(rrset(
            &format!("host.{origin}"),
            Rtype::A,
            300,
            [Rdata::A(std::net::Ipv4Addr::from(0x0A00_0000_u32 + index))],
        ))
        .expect("zone a");
        zones.push(Arc::new(zone));
    }

    let mut outer = InMemoryZone::new(name("z42.test"));
    outer
        .insert(rrset(
            "host.z42.test",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.210".parse().expect("ipv4"))],
        ))
        .expect("outer");
    zones.push(Arc::new(outer));

    let mut nested = InMemoryZone::new(name("deep.z42.test"));
    nested
        .insert(rrset(
            "host.deep.z42.test",
            Rtype::A,
            300,
            [Rdata::A("192.0.2.211".parse().expect("ipv4"))],
        ))
        .expect("nested");
    zones.push(Arc::new(nested));

    let engine = QueryEngine::new(zones);
    let response = engine.respond(&query("host.z9999.test", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 1);

    let response = engine.respond(&query("host.deep.z42.test", Rtype::A), Transport::Udp);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.211".parse().expect("ipv4"))
    );

    let response = engine.respond(&query("host.unknown.test", Rtype::A), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::REFUSED);
}

fn many_records_zone(rr_type: Rtype) -> InMemoryZone {
    let mut zone = InMemoryZone::new(name("example.com"));
    let rdatas: Vec<Rdata> = match rr_type {
        Rtype::A => (0..4096_u32)
            .map(|index| Rdata::A(std::net::Ipv4Addr::from(0x0A00_0000_u32 + index)))
            .collect(),
        _ => (0..4096_usize)
            .map(|index| {
                Rdata::Txt(TxtData::new([format!("{index:04}-payload").into_bytes()]).expect("txt"))
            })
            .collect(),
    };
    let name = match rr_type {
        Rtype::A => name("many-a.example.com"),
        _ => name("many-txt.example.com"),
    };
    zone.insert(
        Rrset::new(
            name,
            rr_type,
            Rclass::IN,
            Ttl::new(300).expect("ttl"),
            rdatas,
        )
        .expect("4096 records"),
    )
    .expect("many records");
    zone
}

#[test]
fn four_thousand_records_udp_truncates_not_servfail() {
    for (rr_type, qname) in [
        (Rtype::A, "many-a.example.com"),
        (Rtype::TXT, "many-txt.example.com"),
    ] {
        let engine = engine_for(many_records_zone(rr_type));
        let response = engine.respond(&query(qname, rr_type), Transport::Udp);
        assert_eq!(response.rcode(), Rcode::NOERROR, "{rr_type}");
        assert!(response.flags().tc(), "{rr_type}");
        assert!(encode(&response).len() <= 512, "{rr_type}");
        assert_eq!(engine.stats().servfail(), 0, "{rr_type}");
    }
}

#[test]
fn single_rr_over_65535_is_tc_udp_and_servfail_tcp() {
    let mut segments = vec![vec![b'x'; 255]; 255];
    segments.push(vec![b'x'; 254]);
    let txt = TxtData::new(segments).expect("65535-byte rdata");
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(rrset(
        "huge.example.com",
        Rtype::TXT,
        300,
        [Rdata::Txt(txt)],
    ))
    .expect("huge txt");
    let engine = engine_for(zone);

    let response = engine.respond(&query("huge.example.com", Rtype::TXT), Transport::Udp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().tc());
    assert!(encode(&response).len() <= 512);

    let response = engine.respond(&query("huge.example.com", Rtype::TXT), Transport::Tcp);
    assert_eq!(response.rcode(), Rcode::SERVFAIL);
}

#[test]
fn tcp_borderline_below_65535_is_not_truncated() {
    let segments = vec![vec![b'x'; 255]; 250];
    let txt = TxtData::new(segments).expect("64000-byte rdata");
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(rrset(
        "borderline.example.com",
        Rtype::TXT,
        300,
        [Rdata::Txt(txt)],
    ))
    .expect("borderline txt");
    let engine = engine_for(zone);
    let response = engine.respond(&query("borderline.example.com", Rtype::TXT), Transport::Tcp);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(!response.flags().tc());
    let bytes = encode(&response);
    assert!(bytes.len() < pulse_dns::MAX_MESSAGE_LEN);
    let _ = decode(&response);
}

fn txt_response(payload: usize, edns_payload: Option<u16>) -> Message {
    let mut zone = InMemoryZone::new(name("example.com"));
    zone.insert(rrset(
        "txt.example.com",
        Rtype::TXT,
        300,
        [Rdata::Txt(
            TxtData::new(txt_segments(payload)).expect("txt"),
        )],
    ))
    .expect("txt");
    let engine = engine_for(zone);
    let request = edns_payload.map_or_else(
        || query("txt.example.com", Rtype::TXT),
        |payload| edns_query("txt.example.com", Rtype::TXT, payload, false),
    );
    engine.respond(&request, Transport::Udp)
}

#[test]
fn exact_udp_payload_boundaries_are_not_truncated() {
    for (limit, edns) in [(512_u16, None), (1232_u16, Some(1232_u16))] {
        let expected = usize::from(limit);
        let mut found = false;
        for payload in 0..5000_usize {
            let response = txt_response(payload, edns);
            let bytes = encode(&response);
            assert!(
                bytes.len() <= expected,
                "limit {limit}, payload {payload}: {} octets",
                bytes.len()
            );
            if response.flags().tc() {
                break;
            }
            if bytes.len() == expected {
                found = true;
                let next = txt_response(payload + 1, edns);
                assert!(
                    next.flags().tc(),
                    "limit {limit}: payload {} must overflow",
                    payload + 1
                );
                break;
            }
        }
        assert!(found, "no payload produces exactly {limit} octets");
    }
}
