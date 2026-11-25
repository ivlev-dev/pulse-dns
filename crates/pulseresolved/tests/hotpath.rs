//! Горячий путь `pulseresolved`: wire-эквивалентность старому Message-пути,
//! EDNS/TC, ACL до резолва и конкурентные запросы через реальные UDP/TCP.

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;

use pulse_dns::{DecodeLimits, EncodeOptions, Message, Rtype};
use pulse_resolver::Resolver;
use pulseresolved::config::{Config, RateLimitAction, RateLimitSetting};
use pulseresolved::server::Server;

use support::e2e::{SOCKET_TIMEOUT, retry};
use support::{
    MockUpstream, a_record, make_query, positive_response, tcp_query_retry, udp_query_retry,
};

const NAME: &str = "hotpath.test";

fn upstream() -> MockUpstream {
    MockUpstream::start(|request| {
        Some(positive_response(
            request,
            a_record(NAME, [192, 0, 2, 77], 300),
        ))
    })
}

fn udp_raw(server: SocketAddr, request: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind udp client");
    socket
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("udp timeout");
    socket.send_to(request, server).expect("send udp");
    let mut buffer = [0_u8; 4096];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((length, _)) => return buffer[..length].to_vec(),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => panic!("recv udp: {error}"),
        }
    }
}

fn tcp_raw(server: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = retry(
        "tcp raw connect",
        || format!("tcp {server}"),
        || TcpStream::connect(server).map_err(|error| error.to_string()),
    );
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("tcp timeout");
    let length = u16::try_from(request.len()).expect("query fits u16");
    stream
        .write_all(&length.to_be_bytes())
        .expect("write length");
    stream.write_all(request).expect("write query");
    stream.flush().expect("flush");
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).expect("read length");
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut response).expect("read response");
    response
}

fn normalize(mut bytes: Vec<u8>) -> Vec<u8> {
    assert!(bytes.len() >= 2, "short response");
    bytes[..2].fill(0);
    bytes
}

fn reference_bytes(config: &Config, request: &Message) -> Vec<u8> {
    let resolver = Resolver::new(config.resolver_config().expect("resolver config"))
        .expect("reference resolver");
    // Прогрев: сравнение должно идти по cache hit, а не по ответу upstream.
    let first = resolver.resolve(request);
    assert_eq!(first.rcode(), pulse_dns::Rcode::NOERROR);
    let mut out = [0_u8; 4096];
    let length = resolver
        .resolve(request)
        .encode_into(&mut out)
        .expect("encode reference");
    out[..length].to_vec()
}

#[test]
fn udp_and_tcp_match_legacy_message_path_bytes() {
    let upstream = upstream();
    let config = support::base_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let tcp = server.tcp_addr().expect("tcp");
    let request = make_query(NAME, Rtype::A, None);
    let wire = request.encode(&EncodeOptions::default()).expect("encode");
    let expected = normalize(reference_bytes(&config, &request));

    // Первый запрос прогревает кеш сервера.
    let _ = udp_query_retry(udp, &request, "warmup UDP");
    assert_eq!(normalize(udp_raw(udp, &wire)), expected, "UDP");
    assert_eq!(normalize(tcp_raw(tcp, &wire)), expected, "TCP");

    let stats = server.stats();
    assert!(stats.fast_path >= 1, "wire fast path must be used");
    assert!(
        stats.zero_alloc_responses >= 1,
        "cache hit must be zero-alloc"
    );
    assert!(server.resolver_stats().cache.hits >= 1);
}

#[test]
fn edns_payload_and_do_survive_fast_path() {
    let upstream = upstream();
    let config = support::base_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let mut request = make_query(NAME, Rtype::A, Some(4096));
    request.set_edns(Some(pulse_dns::Edns::new(4096).with_dnssec_ok(true)));
    let wire = request.encode(&EncodeOptions::default()).expect("encode");
    let _ = udp_query_retry(udp, &request, "warmup EDNS");
    let expected = normalize(reference_bytes(&config, &request));
    let response = normalize(udp_raw(udp, &wire));
    assert_eq!(response, expected);
    let decoded = Message::decode(&response, &DecodeLimits::default()).expect("decode");
    let edns = decoded.edns().expect("OPT echoed");
    assert_eq!(edns.udp_payload_size(), 1232);
    assert!(edns.dnssec_ok());
    assert!(!decoded.flags().tc());
}

#[test]
fn tc_is_set_when_full_response_exceeds_client_payload() {
    let upstream = MockUpstream::start(|request| {
        let mut response = Message::response(request);
        for index in 0..30_u8 {
            let text = format!("{index:02}-{}", "x".repeat(100));
            response.add_answer(
                pulse_dns::Record::new(
                    pulse_dns::Name::parse("big.hotpath.test").expect("name"),
                    Rtype::TXT,
                    pulse_dns::Rclass::IN,
                    pulse_dns::Ttl::new(300).expect("ttl"),
                    pulse_dns::Rdata::Txt(
                        pulse_dns::TxtData::new([text.into_bytes()]).expect("txt"),
                    ),
                )
                .expect("record"),
            );
        }
        Some(response)
    });
    let config = support::base_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let mut request = make_query("big.hotpath.test", Rtype::TXT, Some(4096));
    request.set_edns(Some(pulse_dns::Edns::new(4096)));
    let wire = request.encode(&EncodeOptions::default()).expect("encode");

    let full = udp_raw(udp, &wire);
    let full = Message::decode(&full, &DecodeLimits::default()).expect("full");
    assert!(!full.flags().tc());
    assert_eq!(full.answers().len(), 30);

    // Второй ответ — cache hit с payload 512 из нового запроса.
    let small = make_query("big.hotpath.test", Rtype::TXT, Some(512));
    let small_wire = small.encode(&EncodeOptions::default()).expect("encode");
    let truncated = udp_raw(udp, &small_wire);
    let truncated = Message::decode(&truncated, &DecodeLimits::default()).expect("truncated");
    assert!(truncated.flags().tc());
    assert_eq!(truncated.answers().len(), 0);
    assert!(server.stats().truncated >= 1);
}

#[test]
fn acl_is_checked_before_resolver() {
    let upstream = upstream();
    let mut config = support::base_config(upstream.address());
    config.allow_from = vec!["192.0.2.0/24".to_owned()];
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let request = make_query(NAME, Rtype::A, None);
    let wire = request.encode(&EncodeOptions::default()).expect("encode");
    let response = udp_raw(udp, &wire);
    let response = Message::decode(&response, &DecodeLimits::default()).expect("decode");
    assert_eq!(response.rcode(), pulse_dns::Rcode::REFUSED);
    assert_eq!(server.resolver_stats().queries, 0, "ACL before resolver");
    assert!(server.stats().refused_acl >= 1);
}

#[test]
fn concurrent_udp_queries_are_consistent() {
    let upstream = upstream();
    let config = support::base_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let request = make_query(NAME, Rtype::A, None);
    let wire = Arc::new(request.encode(&EncodeOptions::default()).expect("encode"));
    let expected = normalize(reference_bytes(&config, &request));
    let _ = udp_query_retry(udp, &request, "warmup concurrent");

    let mut threads = Vec::new();
    for _ in 0..4 {
        let wire = Arc::clone(&wire);
        let expected = expected.clone();
        threads.push(std::thread::spawn(move || {
            for _ in 0..100 {
                let response = normalize(udp_raw(udp, &wire));
                assert_eq!(response, expected);
            }
        }));
    }
    for thread in threads {
        thread.join().expect("thread");
    }
    assert!(server.resolver_stats().cache.hits >= 400);
}

#[test]
fn rate_limit_runs_before_resolve_and_keeps_action() {
    let upstream = upstream();
    let mut config = support::base_config(upstream.address());
    config.rate_limit = Some(RateLimitSetting {
        burst: 1,
        qps: 0.001,
        max_entries: 16,
        action: RateLimitAction::Truncate,
        ..RateLimitSetting::default()
    });
    let server = Server::start(&config).expect("server");
    let udp = server.udp_addr().expect("udp");
    let request = make_query(NAME, Rtype::A, None);
    let wire = request.encode(&EncodeOptions::default()).expect("encode");

    let first = udp_query_retry(udp, &request, "first rate limit query");
    assert!(!first.flags().tc());
    let before = server.resolver_stats().queries;
    let limited = udp_raw(udp, &wire);
    let limited = Message::decode(&limited, &DecodeLimits::default()).expect("decode");
    assert!(limited.flags().tc());
    assert_eq!(
        server.resolver_stats().queries,
        before,
        "rate limit must run before the resolver"
    );
    assert!(server.stats().rate_limit_truncated >= 1);
}

#[test]
fn tcp_keeps_large_cache_hit_untruncated() {
    let upstream = MockUpstream::start(|request| {
        let mut response = Message::response(request);
        for index in 0..20_u8 {
            let text = format!("{index:02}-{}", "y".repeat(100));
            response.add_answer(
                pulse_dns::Record::new(
                    pulse_dns::Name::parse("big.tcp.test").expect("name"),
                    Rtype::TXT,
                    pulse_dns::Rclass::IN,
                    pulse_dns::Ttl::new(300).expect("ttl"),
                    pulse_dns::Rdata::Txt(
                        pulse_dns::TxtData::new([text.into_bytes()]).expect("txt"),
                    ),
                )
                .expect("record"),
            );
        }
        Some(response)
    });
    let config = support::base_config(upstream.address());
    let server = Server::start(&config).expect("server");
    let tcp = server.tcp_addr().expect("tcp");
    let request = make_query("big.tcp.test", Rtype::TXT, None);
    let first = tcp_query_retry(tcp, &request, "first TCP big");
    assert_eq!(first.answers().len(), 20);
    let second = tcp_query_retry(tcp, &request, "cached TCP big");
    assert_eq!(second.answers().len(), 20);
    assert!(!second.flags().tc());
}
