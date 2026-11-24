//! E2E защищённых транспортов `pulseresolved`: DoT, DoH/1.1, DoH/2, DoQ и
//! DNSCrypt v2 (UDP+TCP) реальными клиентами.
//!
//! Проверяются A/AAAA/NXDOMAIN, blocklist, overrides, большие ответы (TC и
//! без TC), ACL на всех транспортах, `tls_allow_from`, одновременная работа
//! всех транспортов, SIGHUP-перезагрузка TLS-пары, graceful shutdown и
//! метрики по транспортам.

#![allow(clippy::doc_markdown)]

mod support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::Method;
use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rtype};
use pulseresolved::config::{Config, OverrideSetting};
use pulseresolved::server::Server;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
use tokio::net::TcpStream as TokioTcpStream;
use tokio_rustls::TlsConnector;

use support::{
    DnscryptFixture, MockUpstream, TestPki, TestTlsClient, a_record, aaaa_record,
    dnscrypt_tcp_query, dnscrypt_udp_query, make_query, nxdomain_response, positive_response,
    tls_client_config, txt_records, udp_query, write_secret,
};

const TIMEOUT: Duration = Duration::from_secs(5);
const BIG_RECORDS: usize = 25;

fn upstream() -> MockUpstream {
    MockUpstream::start(|request| {
        let question = request.questions().first()?.clone();
        let name = question.qname().to_string();
        let bare = name.trim_end_matches('.');
        if bare == "missing.secure.test" {
            return Some(nxdomain_response(request, "secure.test"));
        }
        if bare == "big.secure.test" {
            let mut response = Message::response(request);
            for record in txt_records(bare, BIG_RECORDS, 60) {
                response.add_answer(record);
            }
            return Some(response);
        }
        let record = match question.qtype() {
            Rtype::AAAA => aaaa_record(bare, "2001:db8::10", 60),
            _ => a_record(bare, [192, 0, 2, 10], 60),
        };
        Some(positive_response(request, record))
    })
}

fn config_with(upstream: SocketAddr) -> Config {
    let mut config = support::base_config(upstream);
    config.listen_udp = None;
    config.listen_tcp = None;
    config.allow_from = vec!["127.0.0.0/8".to_owned(), "::1/128".to_owned()];
    config.cache.max_entries = 1024;
    config
}

fn set_tls(config: &mut Config, pki: &TestPki) {
    config.tls_cert = Some(pki.cert_path.clone());
    config.tls_key = Some(pki.key_path.clone());
}

fn set_dnscrypt(config: &mut Config, fixture: &DnscryptFixture) {
    config.dnscrypt_provider_key = Some(fixture.provider_path.clone());
    config.dnscrypt_resolver_key = Some(fixture.resolver_path.clone());
    config.dnscrypt_cert = Some(fixture.cert_path.clone());
}

fn write_blocklist(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("blocklist.txt");
    std::fs::write(&path, "blocked.secure.test\n").expect("write blocklist");
    path
}

fn query(name: &str, rtype: Rtype) -> Vec<u8> {
    make_query(name, rtype, None)
        .encode(&EncodeOptions::default())
        .expect("encode query")
}

/// RFC 9250 §4.2: DoQ требует DNS ID = 0.
fn doq_wire(name: &str, rtype: Rtype) -> Vec<u8> {
    let question = Question::new(Name::parse(name).expect("qname"), rtype, Rclass::IN);
    Message::query(0, question)
        .encode(&EncodeOptions::default())
        .expect("encode DoQ query")
}

fn decode(bytes: &[u8]) -> Message {
    Message::decode(bytes, &DecodeLimits::default()).expect("decode response")
}

fn add_policy(config: &mut Config, dir: &std::path::Path) {
    config.blocklist.paths = vec![write_blocklist(dir)];
    config.overrides = vec![OverrideSetting {
        name: "router.secure.test".to_owned(),
        ttl: 60,
        a: vec![Ipv4Addr::new(192, 168, 1, 1)],
        aaaa: vec!["fd00::10".parse().expect("ipv6")],
        cname: None,
    }];
}

fn assert_aaaa(message: &Message) {
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(message.answers().len(), 1);
    assert_eq!(message.answers()[0].rr_type(), Rtype::AAAA);
}

fn assert_a(message: &Message, address: Ipv4Addr) {
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(message.answers().len(), 1);
    assert_eq!(message.answers()[0].rr_type(), Rtype::A);
    let pulse_dns::Rdata::A(found) = message.answers()[0].rdata() else {
        panic!("A record expected");
    };
    assert_eq!(*found, address);
}

// ------------------------------------------------------------------ DoT

#[test]
fn dot_answers_a_aaaa_nxdomain_blocklist_and_override() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let mut config = config_with(upstream.address());
    set_tls(&mut config, &pki);
    config.dot_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.blocklist.paths = vec![write_blocklist(pki.dir.path())];
    config.overrides = vec![OverrideSetting {
        name: "router.secure.test".to_owned(),
        ttl: 60,
        a: vec![Ipv4Addr::new(192, 168, 1, 1)],
        aaaa: vec!["fd00::10".parse().expect("ipv6")],
        cname: None,
    }];
    let server = Server::start(&config).expect("server");
    let addr = server.dot_addr().expect("dot addr");
    let mut client = TestTlsClient::connect(addr, &pki.cert_der, b"dot").expect("DoT connect");
    assert_eq!(
        client.negotiated_alpn().as_deref(),
        Some(b"dot".as_slice()),
        "ALPN dot"
    );

    let response = client
        .dot_query(&query("dot.secure.test", Rtype::A))
        .expect("A response");
    assert_a(&decode(&response), Ipv4Addr::new(192, 0, 2, 10));

    let response = client
        .dot_query(&query("dot.secure.test", Rtype::AAAA))
        .expect("AAAA response");
    let message = decode(&response);
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(message.answers()[0].rr_type(), Rtype::AAAA);

    let response = client
        .dot_query(&query("missing.secure.test", Rtype::A))
        .expect("NXDOMAIN");
    assert_eq!(decode(&response).rcode(), Rcode::NXDOMAIN);

    let response = client
        .dot_query(&query("blocked.secure.test", Rtype::A))
        .expect("blocked");
    assert_eq!(decode(&response).rcode(), Rcode::NXDOMAIN);
    assert!(server.resolver_stats().blocked >= 1);

    let response = client
        .dot_query(&query("router.secure.test", Rtype::A))
        .expect("override");
    assert_a(&decode(&response), Ipv4Addr::new(192, 168, 1, 1));

    let counters = server.stats();
    assert_eq!(counters.dot_queries, 5);
    assert_eq!(counters.dot_responses, 5);
    assert_eq!(server.dot_stats().expect("dot stats").queries, 5);
}

#[test]
fn dot_large_response_is_not_truncated() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let mut config = config_with(upstream.address());
    set_tls(&mut config, &pki);
    config.dot_listen = Some("127.0.0.1:0".parse().expect("addr"));
    let server = Server::start(&config).expect("server");
    let addr = server.dot_addr().expect("dot addr");
    let mut client = TestTlsClient::connect(addr, &pki.cert_der, b"dot").expect("DoT connect");
    let response = client
        .dot_query(&query("big.secure.test", Rtype::TXT))
        .expect("big response");
    assert!(
        response.len() > 2_000,
        "response is {} bytes",
        response.len()
    );
    let message = decode(&response);
    assert!(!message.flags().tc(), "DoT must not truncate");
    assert_eq!(message.answers().len(), BIG_RECORDS);
}

// -------------------------------------------------------------- DoH/1.1

#[test]
fn doh_http1_answers_post_get_and_large_response() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let mut config = config_with(upstream.address());
    set_tls(&mut config, &pki);
    add_policy(&mut config, pki.dir.path());
    config.doh_listen = Some("127.0.0.1:0".parse().expect("addr"));
    let server = Server::start(&config).expect("server");
    let addr = server.doh_addr().expect("doh addr");
    let mut client = TestTlsClient::connect(addr, &pki.cert_der, b"http/1.1").expect("DoH connect");
    assert_eq!(
        client.negotiated_alpn().as_deref(),
        Some(b"http/1.1".as_slice()),
        "ALPN http/1.1"
    );

    let wire = query("doh.secure.test", Rtype::A);
    let response = client.https_post("/dns-query", &wire).expect("POST");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.content_type.as_deref(),
        Some("application/dns-message")
    );
    assert_a(&decode(&response.body), Ipv4Addr::new(192, 0, 2, 10));

    let encoded = URL_SAFE_NO_PAD.encode(&wire);
    let response = client
        .https_get(&format!("/dns-query?dns={encoded}"))
        .expect("GET");
    assert_eq!(response.status, 200);
    assert_a(&decode(&response.body), Ipv4Addr::new(192, 0, 2, 10));

    let wire = query("big.secure.test", Rtype::TXT);
    let response = client.https_post("/dns-query", &wire).expect("big POST");
    assert_eq!(response.status, 200);
    assert!(response.body.len() > 2_000);
    let message = decode(&response.body);
    assert!(!message.flags().tc());
    assert_eq!(message.answers().len(), BIG_RECORDS);

    let response = client
        .https_post("/dns-query", &query("doh.secure.test", Rtype::AAAA))
        .expect("AAAA");
    assert_eq!(response.status, 200);
    assert_aaaa(&decode(&response.body));

    let response = client
        .https_post("/dns-query", &query("missing.secure.test", Rtype::A))
        .expect("NXDOMAIN");
    assert_eq!(decode(&response.body).rcode(), Rcode::NXDOMAIN);

    let response = client
        .https_post("/dns-query", &query("blocked.secure.test", Rtype::A))
        .expect("blocked");
    assert_eq!(decode(&response.body).rcode(), Rcode::NXDOMAIN);

    let response = client
        .https_post("/dns-query", &query("router.secure.test", Rtype::A))
        .expect("override");
    assert_a(&decode(&response.body), Ipv4Addr::new(192, 168, 1, 1));

    let response = client.https_post("/dns-query", b"").expect("bad");
    assert_eq!(response.status, 400);

    let counters = server.stats();
    assert_eq!(counters.doh_queries, 7);
    assert_eq!(counters.doh_responses, 7);
    let tls = server.doh_stats().expect("doh stats");
    assert_eq!(tls.queries, 7);
    assert!(tls.http_requests >= 8);
}

// ---------------------------------------------------------------- DoH/2

struct H2Client {
    send: h2::client::SendRequest<Bytes>,
    _driver: tokio::task::JoinHandle<()>,
}

impl H2Client {
    async fn connect(addr: SocketAddr, cert_der: &[u8]) -> Self {
        let config = tls_client_config(cert_der, b"h2");
        let connector = TlsConnector::from(Arc::new(config));
        let stream = TokioTcpStream::connect(addr).await.expect("tcp connect");
        let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
        let tls = connector
            .connect(name, stream)
            .await
            .expect("TLS handshake");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let (send, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Self {
            send,
            _driver: driver,
        }
    }

    async fn request(&mut self, uri: String, body: &[u8]) -> (u16, Vec<u8>) {
        let request = http::Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("content-type", "application/dns-message")
            .body(())
            .expect("request");
        let (response, mut stream) = self.send.send_request(request, false).expect("send");
        stream
            .send_data(Bytes::copy_from_slice(body), true)
            .expect("send body");
        let response = response.await.expect("response");
        let status = response.status().as_u16();
        let mut recv = response.into_body();
        let mut out = Vec::new();
        while let Some(chunk) = recv.data().await {
            out.extend_from_slice(&chunk.expect("body chunk"));
        }
        (status, out)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_http2_answers_and_large_response() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let mut config = config_with(upstream.address());
    set_tls(&mut config, &pki);
    add_policy(&mut config, pki.dir.path());
    config.doh2_listen = Some("127.0.0.1:0".parse().expect("addr"));
    let server = Server::start(&config).expect("server");
    let addr = server.doh2_addr().expect("doh2 addr");
    let mut client = H2Client::connect(addr, &pki.cert_der).await;

    let wire = query("doh2.secure.test", Rtype::A);
    let (status, body) = client
        .request("https://localhost/dns-query".to_owned(), &wire)
        .await;
    assert_eq!(status, 200);
    assert_a(&decode(&body), Ipv4Addr::new(192, 0, 2, 10));

    let encoded = URL_SAFE_NO_PAD.encode(&wire);
    let request = http::Request::builder()
        .method(Method::GET)
        .uri(format!("https://localhost/dns-query?dns={encoded}"))
        .body(())
        .expect("request");
    let (response, _stream) = client.send.send_request(request, true).expect("send");
    let response = response.await.expect("response");
    assert_eq!(response.status().as_u16(), 200);

    let wire = query("big.secure.test", Rtype::TXT);
    let (status, body) = client
        .request("https://localhost/dns-query".to_owned(), &wire)
        .await;
    assert_eq!(status, 200);
    assert!(body.len() > 2_000);
    let message = decode(&body);
    assert!(!message.flags().tc());
    assert_eq!(message.answers().len(), BIG_RECORDS);

    let (status, body) = client
        .request(
            "https://localhost/dns-query".to_owned(),
            &query("doh2.secure.test", Rtype::AAAA),
        )
        .await;
    assert_eq!(status, 200);
    assert_aaaa(&decode(&body));

    let (status, body) = client
        .request(
            "https://localhost/dns-query".to_owned(),
            &query("missing.secure.test", Rtype::A),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(decode(&body).rcode(), Rcode::NXDOMAIN);

    let (status, body) = client
        .request(
            "https://localhost/dns-query".to_owned(),
            &query("blocked.secure.test", Rtype::A),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(decode(&body).rcode(), Rcode::NXDOMAIN);

    let (status, body) = client
        .request(
            "https://localhost/dns-query".to_owned(),
            &query("router.secure.test", Rtype::A),
        )
        .await;
    assert_eq!(status, 200);
    assert_a(&decode(&body), Ipv4Addr::new(192, 168, 1, 1));

    let counters = server.stats();
    assert_eq!(counters.doh_http2_queries, 7);
    assert_eq!(counters.doh_http2_responses, 7);
}

// ------------------------------------------------------------------ DoQ

fn quic_client_config(cert_der: &[u8]) -> quinn::ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.to_vec()))
        .expect("add root");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = RustlsClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"doq".to_vec()];
    let crypto = QuicClientConfig::try_from(config).expect("QUIC client config");
    quinn::ClientConfig::new(Arc::new(crypto))
}

async fn doq_query(connection: &quinn::Connection, wire: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = connection.open_bi().await.expect("open stream");
    let length = u16::try_from(wire.len()).expect("fits");
    send.write_all(&length.to_be_bytes()).await.expect("length");
    send.write_all(wire).await.expect("message");
    send.finish().expect("finish");
    let mut prefix = [0_u8; 2];
    recv.read_exact(&mut prefix).await.expect("prefix");
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut response = vec![0_u8; length];
    recv.read_exact(&mut response).await.expect("response");
    response
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doq_answers_and_large_response() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let mut config = config_with(upstream.address());
    set_tls(&mut config, &pki);
    add_policy(&mut config, pki.dir.path());
    config.doq_listen = Some("127.0.0.1:0".parse().expect("addr"));
    let server = Server::start(&config).expect("server");
    let addr = server.doq_addr().expect("doq addr");

    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client addr")).expect("endpoint");
    endpoint.set_default_client_config(quic_client_config(&pki.cert_der));
    let connection = endpoint
        .connect(addr, "localhost")
        .expect("connect")
        .await
        .expect("QUIC handshake");

    let response = doq_query(&connection, &doq_wire("doq.secure.test", Rtype::A)).await;
    assert_a(&decode(&response), Ipv4Addr::new(192, 0, 2, 10));

    let response = doq_query(&connection, &doq_wire("missing.secure.test", Rtype::A)).await;
    assert_eq!(decode(&response).rcode(), Rcode::NXDOMAIN);

    let response = doq_query(&connection, &doq_wire("big.secure.test", Rtype::TXT)).await;
    assert!(response.len() > 2_000);
    let message = decode(&response);
    assert!(!message.flags().tc(), "DoQ must not truncate");
    assert_eq!(message.answers().len(), BIG_RECORDS);

    let response = doq_query(&connection, &doq_wire("doq.secure.test", Rtype::AAAA)).await;
    assert_aaaa(&decode(&response));

    let response = doq_query(&connection, &doq_wire("blocked.secure.test", Rtype::A)).await;
    assert_eq!(decode(&response).rcode(), Rcode::NXDOMAIN);

    let response = doq_query(&connection, &doq_wire("router.secure.test", Rtype::A)).await;
    assert_a(&decode(&response), Ipv4Addr::new(192, 168, 1, 1));

    let counters = server.stats();
    assert_eq!(counters.doq_queries, 6);
    assert_eq!(counters.doq_responses, 6);
    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;
}

// -------------------------------------------------------------- DNSCrypt

#[test]
fn dnscrypt_udp_answers_and_truncates_large_response() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let fixture = DnscryptFixture::generate(pki.dir.path());
    let mut config = config_with(upstream.address());
    set_dnscrypt(&mut config, &fixture);
    add_policy(&mut config, pki.dir.path());
    config.dnscrypt_listen = Some("127.0.0.1:0".parse().expect("addr"));
    let server = Server::start(&config).expect("server");
    let addr = server.dnscrypt_udp_addr().expect("dnscrypt udp");

    let response = dnscrypt_udp_query(
        addr,
        &fixture.client,
        &Message::decode(
            &query("dnscrypt.secure.test", Rtype::A),
            &DecodeLimits::default(),
        )
        .expect("query"),
        TIMEOUT,
    )
    .expect("A response");
    assert_a(&response, Ipv4Addr::new(192, 0, 2, 10));

    let nxdomain = dnscrypt_udp_query(
        addr,
        &fixture.client,
        &Message::decode(
            &query("missing.secure.test", Rtype::A),
            &DecodeLimits::default(),
        )
        .expect("query"),
        TIMEOUT,
    )
    .expect("NXDOMAIN");
    assert_eq!(nxdomain.rcode(), Rcode::NXDOMAIN);

    let big = dnscrypt_udp_query(
        addr,
        &fixture.client,
        &Message::decode(
            &query("big.secure.test", Rtype::TXT),
            &DecodeLimits::default(),
        )
        .expect("query"),
        TIMEOUT,
    )
    .expect("big response");
    assert!(
        big.flags().tc(),
        "DNSCrypt UDP must truncate oversized answer"
    );

    let aaaa = dnscrypt_udp_query(
        addr,
        &fixture.client,
        &decode(&query("dnscrypt.secure.test", Rtype::AAAA)),
        TIMEOUT,
    )
    .expect("AAAA");
    assert_aaaa(&aaaa);

    let blocked = dnscrypt_udp_query(
        addr,
        &fixture.client,
        &decode(&query("blocked.secure.test", Rtype::A)),
        TIMEOUT,
    )
    .expect("blocked");
    assert_eq!(blocked.rcode(), Rcode::NXDOMAIN);

    let overridden = dnscrypt_udp_query(
        addr,
        &fixture.client,
        &decode(&query("router.secure.test", Rtype::A)),
        TIMEOUT,
    )
    .expect("override");
    assert_a(&overridden, Ipv4Addr::new(192, 168, 1, 1));

    let counters = server.stats();
    assert_eq!(counters.dnscrypt_udp_queries, 6);
    assert_eq!(counters.dnscrypt_udp_responses, 6);
}

#[test]
fn dnscrypt_tcp_answers_multiple_queries_and_no_truncation() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let fixture = DnscryptFixture::generate(pki.dir.path());
    let mut config = config_with(upstream.address());
    set_dnscrypt(&mut config, &fixture);
    add_policy(&mut config, pki.dir.path());
    config.dnscrypt_tcp_listen = Some("127.0.0.1:0".parse().expect("addr"));
    let server = Server::start(&config).expect("server");
    let addr = server.dnscrypt_tcp_addr().expect("dnscrypt tcp");
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.set_nodelay(true).expect("nodelay");

    for (name, rtype) in [
        ("dnscrypt-tcp.secure.test", Rtype::A),
        ("dnscrypt-tcp.secure.test", Rtype::AAAA),
        ("missing.secure.test", Rtype::A),
    ] {
        let request = decode(&query(name, rtype));
        let response =
            dnscrypt_tcp_query(&mut stream, &fixture.client, &request, TIMEOUT).expect("response");
        match rtype {
            Rtype::A if name.starts_with("dnscrypt-tcp") => {
                assert_a(&response, Ipv4Addr::new(192, 0, 2, 10));
            }
            Rtype::AAAA => assert_eq!(response.answers()[0].rr_type(), Rtype::AAAA),
            _ => assert_eq!(response.rcode(), Rcode::NXDOMAIN),
        }
    }

    let request = decode(&query("big.secure.test", Rtype::TXT));
    let response =
        dnscrypt_tcp_query(&mut stream, &fixture.client, &request, TIMEOUT).expect("big");
    assert!(!response.flags().tc(), "DNSCrypt TCP must not truncate");
    assert_eq!(response.answers().len(), BIG_RECORDS);

    for name in ["blocked.secure.test", "missing.secure.test"] {
        let request = decode(&query(name, Rtype::A));
        let response =
            dnscrypt_tcp_query(&mut stream, &fixture.client, &request, TIMEOUT).expect("negative");
        assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    }
    let request = decode(&query("router.secure.test", Rtype::A));
    let response =
        dnscrypt_tcp_query(&mut stream, &fixture.client, &request, TIMEOUT).expect("override");
    assert_a(&response, Ipv4Addr::new(192, 168, 1, 1));

    let counters = server.stats();
    assert_eq!(counters.dnscrypt_tcp_queries, 7);
    assert_eq!(counters.dnscrypt_tcp_responses, 7);
    assert_eq!(counters.dnscrypt_tcp_connections, 1);
}

// ------------------------------------------------------- ACL / lifecycle

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acl_refuses_clients_on_every_transport() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let fixture = DnscryptFixture::generate(pki.dir.path());
    let mut config = config_with(upstream.address());
    set_tls(&mut config, &pki);
    set_dnscrypt(&mut config, &fixture);
    config.listen_udp = Some("127.0.0.1:0".parse().expect("addr"));
    config.dot_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.doh_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.doh2_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.doq_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.dnscrypt_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.dnscrypt_tcp_listen = Some("127.0.0.1:0".parse().expect("addr"));
    // Loopback не входит в ACL.
    config.allow_from = vec!["192.0.2.0/24".to_owned()];
    let server = Server::start(&config).expect("server");
    assert!(server.udp_addr().is_some());

    // UDP.
    let request = make_query("acl.secure.test", Rtype::A, None);
    let response =
        udp_query(server.udp_addr().expect("udp"), &request, TIMEOUT).expect("udp response");
    assert_eq!(response.rcode(), Rcode::REFUSED);

    // DoT.
    let mut dot = TestTlsClient::connect(server.dot_addr().expect("dot"), &pki.cert_der, b"dot")
        .expect("DoT connect");
    let response = dot
        .dot_query(&query("acl.secure.test", Rtype::A))
        .expect("DoT response");
    assert_eq!(decode(&response).rcode(), Rcode::REFUSED);

    // DoH/1.1.
    let mut doh =
        TestTlsClient::connect(server.doh_addr().expect("doh"), &pki.cert_der, b"http/1.1")
            .expect("DoH connect");
    let response = doh
        .https_post("/dns-query", &query("acl.secure.test", Rtype::A))
        .expect("DoH response");
    assert_eq!(response.status, 200);
    assert_eq!(decode(&response.body).rcode(), Rcode::REFUSED);

    // DoH/2.
    let mut h2 = H2Client::connect(server.doh2_addr().expect("doh2"), &pki.cert_der).await;
    let (status, body) = h2
        .request(
            "https://localhost/dns-query".to_owned(),
            &query("acl.secure.test", Rtype::A),
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(decode(&body).rcode(), Rcode::REFUSED);

    // DoQ.
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("endpoint");
    endpoint.set_default_client_config(quic_client_config(&pki.cert_der));
    let connection = endpoint
        .connect(server.doq_addr().expect("doq"), "localhost")
        .expect("connect")
        .await
        .expect("QUIC handshake");
    let response = doq_query(&connection, &doq_wire("acl.secure.test", Rtype::A)).await;
    assert_eq!(decode(&response).rcode(), Rcode::REFUSED);
    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;

    // DNSCrypt UDP.
    let request = decode(&query("acl.secure.test", Rtype::A));
    let response = dnscrypt_udp_query(
        server.dnscrypt_udp_addr().expect("dnscrypt udp"),
        &fixture.client,
        &request,
        TIMEOUT,
    )
    .expect("DNSCrypt UDP response");
    assert_eq!(response.rcode(), Rcode::REFUSED);

    // DNSCrypt TCP.
    let mut stream =
        TcpStream::connect(server.dnscrypt_tcp_addr().expect("dnscrypt tcp")).expect("connect");
    let response = dnscrypt_tcp_query(&mut stream, &fixture.client, &request, TIMEOUT)
        .expect("DNSCrypt TCP response");
    assert_eq!(response.rcode(), Rcode::REFUSED);

    let counters = server.stats();
    assert_eq!(counters.refused_acl, 7, "one REFUSED per transport");
    assert!(
        server.resolver_stats().queries == 0,
        "ACL must run before the resolver"
    );
}

#[test]
fn tls_allow_from_overrides_common_acl() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let mut config = config_with(upstream.address());
    set_tls(&mut config, &pki);
    config.listen_udp = Some("127.0.0.1:0".parse().expect("addr"));
    config.dot_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.allow_from = vec!["127.0.0.0/8".to_owned()];
    config.tls_allow_from = vec!["192.0.2.0/24".to_owned()];
    let server = Server::start(&config).expect("server");

    let request = make_query("plain.secure.test", Rtype::A, None);
    let response =
        udp_query(server.udp_addr().expect("udp"), &request, TIMEOUT).expect("udp response");
    assert_eq!(response.rcode(), Rcode::NOERROR);

    let mut dot = TestTlsClient::connect(server.dot_addr().expect("dot"), &pki.cert_der, b"dot")
        .expect("DoT connect");
    let response = dot
        .dot_query(&query("plain.secure.test", Rtype::A))
        .expect("DoT response");
    assert_eq!(decode(&response).rcode(), Rcode::REFUSED);
    assert_eq!(server.stats().refused_acl, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_transports_run_together_and_shutdown_gracefully() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let fixture = DnscryptFixture::generate(pki.dir.path());
    let mut config = config_with(upstream.address());
    set_tls(&mut config, &pki);
    set_dnscrypt(&mut config, &fixture);
    config.listen_udp = Some("127.0.0.1:0".parse().expect("addr"));
    config.listen_tcp = Some("127.0.0.1:0".parse().expect("addr"));
    config.dot_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.doh_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.doh2_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.doq_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.dnscrypt_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.dnscrypt_tcp_listen = Some("127.0.0.1:0".parse().expect("addr"));
    config.metrics_listen = Some("127.0.0.1:0".parse().expect("addr"));
    let mut server = Server::start(&config).expect("server");

    let plain_udp = server.udp_addr().expect("udp");
    let plain_tcp = server.tcp_addr().expect("tcp");
    let dot_port = server.dot_addr().expect("dot");
    let doh1_port = server.doh_addr().expect("doh");
    let doh2_port = server.doh2_addr().expect("doh2");
    let quic_port = server.doq_addr().expect("doq");
    let dnscrypt_udp = server.dnscrypt_udp_addr().expect("dnscrypt udp");
    let dnscrypt_tcp = server.dnscrypt_tcp_addr().expect("dnscrypt tcp");
    let metrics_port = server.metrics_addr().expect("metrics");

    // UDP и TCP.
    let request = make_query("all.secure.test", Rtype::A, None);
    let response = udp_query(plain_udp, &request, TIMEOUT).expect("udp");
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let response = support::tcp_query(plain_tcp, &request, TIMEOUT).expect("tcp");
    assert_eq!(response.rcode(), Rcode::NOERROR);

    // DoT.
    let mut dot = TestTlsClient::connect(dot_port, &pki.cert_der, b"dot").expect("dot");
    let response = dot
        .dot_query(&query("all.secure.test", Rtype::A))
        .expect("dot response");
    assert_a(&decode(&response), Ipv4Addr::new(192, 0, 2, 10));

    // DoH/1.1.
    let mut doh = TestTlsClient::connect(doh1_port, &pki.cert_der, b"http/1.1").expect("doh");
    let response = doh
        .https_post("/dns-query", &query("all.secure.test", Rtype::A))
        .expect("doh response");
    assert_a(&decode(&response.body), Ipv4Addr::new(192, 0, 2, 10));

    // DoH/2.
    let mut h2 = H2Client::connect(doh2_port, &pki.cert_der).await;
    let (status, body) = h2
        .request(
            "https://localhost/dns-query".to_owned(),
            &query("all.secure.test", Rtype::A),
        )
        .await;
    assert_eq!(status, 200);
    assert_a(&decode(&body), Ipv4Addr::new(192, 0, 2, 10));

    // DoQ.
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr")).expect("endpoint");
    endpoint.set_default_client_config(quic_client_config(&pki.cert_der));
    let connection = endpoint
        .connect(quic_port, "localhost")
        .expect("connect")
        .await
        .expect("QUIC handshake");
    let response = doq_query(&connection, &doq_wire("all.secure.test", Rtype::A)).await;
    assert_a(&decode(&response), Ipv4Addr::new(192, 0, 2, 10));
    connection.close(0_u32.into(), b"done");
    endpoint.wait_idle().await;

    // DNSCrypt UDP/TCP.
    let request = decode(&query("all.secure.test", Rtype::A));
    let response =
        dnscrypt_udp_query(dnscrypt_udp, &fixture.client, &request, TIMEOUT).expect("dnscrypt udp");
    assert_a(&response, Ipv4Addr::new(192, 0, 2, 10));
    let mut stream = TcpStream::connect(dnscrypt_tcp).expect("dnscrypt tcp");
    let response =
        dnscrypt_tcp_query(&mut stream, &fixture.client, &request, TIMEOUT).expect("dnscrypt tcp");
    assert_a(&response, Ipv4Addr::new(192, 0, 2, 10));

    // Метрики по транспортам.
    let metrics = http_get(metrics_port, "/metrics");
    for transport in [
        "dot",
        "doh",
        "doh_http2",
        "doq",
        "dnscrypt_udp",
        "dnscrypt_tcp",
    ] {
        assert!(
            metrics.contains(&format!(
                "pulseresolved_queries_total{{transport=\"{transport}\"}}"
            )),
            "missing metrics for {transport}"
        );
    }
    assert!(metrics.contains("pulseresolved_dot_handshakes_total 1"));
    assert!(metrics.contains("pulseresolved_dnscrypt_tcp_connections_total 1"));

    server.shutdown().expect("shutdown");
    for addr in [dot_port, doh1_port, doh2_port, dnscrypt_tcp] {
        let result = TcpStream::connect_timeout(&addr, Duration::from_millis(300));
        assert!(result.is_err(), "port {addr} must be closed after shutdown");
    }
    assert!(server.dot_addr().is_none());
    assert!(server.doh_addr().is_none());
    assert!(server.doh2_addr().is_none());
    assert!(server.doq_addr().is_none());
    assert!(server.dnscrypt_udp_addr().is_none());
    assert!(server.dnscrypt_tcp_addr().is_none());
}

#[test]
fn tls_reload_replaces_certificate_for_new_connections() {
    let upstream = upstream();
    let pki = TestPki::generate();
    let mut config = config_with(upstream.address());
    set_tls(&mut config, &pki);
    config.dot_listen = Some("127.0.0.1:0".parse().expect("addr"));
    let server = Server::start(&config).expect("server");
    let addr = server.dot_addr().expect("dot addr");

    let mut client = TestTlsClient::connect(addr, &pki.cert_der, b"dot").expect("first");
    let response = client
        .dot_query(&query("reload.secure.test", Rtype::A))
        .expect("first response");
    assert_eq!(decode(&response).rcode(), Rcode::NOERROR);

    let replacement = TestPki::generate();
    write_secret(&pki.key_path, replacement.key_pem.as_bytes());
    std::fs::write(&pki.cert_path, replacement.cert_pem.as_bytes()).expect("replace cert");
    server.reload_tls().expect("reload tls");
    assert_eq!(server.stats().tls_reloads, 1);

    let mut client =
        TestTlsClient::connect(addr, &replacement.cert_der, b"dot").expect("new certificate");
    let response = client
        .dot_query(&query("reload.secure.test", Rtype::A))
        .expect("second response");
    assert_eq!(decode(&response).rcode(), Rcode::NOERROR);

    assert!(
        TestTlsClient::connect(addr, &pki.cert_der, b"dot").is_none(),
        "old certificate must be rejected for new connections"
    );
}

// ---------------------------------------------------------------- helpers

fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("metrics connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").expect("write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read");
    response
}
