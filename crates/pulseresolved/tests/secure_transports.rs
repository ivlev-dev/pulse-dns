//! E2E защищённых транспортов `pulseresolved`: DoT, DoH/1.1, DoH/2, DoQ и
//! DNSCrypt v2 (UDP+TCP) реальными клиентами.
//!
//! Проверяются A/AAAA/NXDOMAIN, blocklist, overrides, большие ответы (TC и
//! без TC), ACL на всех транспортах, `tls_allow_from`, одновременная работа
//! всех транспортов, SIGHUP-перезагрузка TLS-пары, graceful shutdown и
//! метрики по транспортам.

#![allow(clippy::doc_markdown, clippy::too_many_lines)]

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

use support::e2e::{Attempt, SOCKET_TIMEOUT, assert_counter, retry, retry_async};
use support::{
    DnscryptFixture, DnscryptTcpClient, DnscryptUdpClient, HttpsResponse, MockUpstream, TestPki,
    TestTlsClient, a_record, aaaa_record, make_query, nxdomain_response, positive_response,
    server_diagnostics, tls_client_config, txt_records, udp_query, udp_query_retry,
    wait_dnscrypt_udp_listening, write_secret,
};

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

// ------------------------------------------------- retrying TLS sessions

/// DoT-сессия: переиспользует соединение, при обрыве переподключается.
struct DotSession {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    alpn: Vec<u8>,
    client: Option<TestTlsClient>,
    connections: u64,
    sent: u64,
}

impl DotSession {
    fn new(addr: SocketAddr, cert_der: &[u8], alpn: &[u8]) -> Self {
        Self {
            addr,
            cert_der: cert_der.to_vec(),
            alpn: alpn.to_vec(),
            client: None,
            connections: 0,
            sent: 0,
        }
    }

    fn connect_once(&mut self) -> Attempt<()> {
        let client = TestTlsClient::connect(self.addr, &self.cert_der, &self.alpn)
            .ok_or_else(|| format!("DoT {}: TCP/TLS handshake не удался", self.addr))?;
        self.client = Some(client);
        self.connections = self.connections.saturating_add(1);
        Ok(())
    }

    fn connect(&mut self, label: &str, diagnostics: impl Fn() -> String) {
        retry(label, diagnostics, || self.connect_once());
    }

    fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        self.client
            .as_ref()
            .and_then(TestTlsClient::negotiated_alpn)
    }

    fn query(&mut self, wire: &[u8], label: &str, diagnostics: impl Fn() -> String) -> Vec<u8> {
        retry(label, diagnostics, || {
            if self.client.is_none() {
                self.connect_once()?;
            }
            self.sent = self.sent.saturating_add(1);
            let Some(client) = self.client.as_mut() else {
                return Err("DoT client отсутствует после connect".to_owned());
            };
            if let Some(response) = client.dot_query(wire) {
                Ok(response)
            } else {
                self.client = None;
                Err(format!("DoT {}: нет ответа", self.addr))
            }
        })
    }
}

enum DohCall<'a> {
    Post(&'a [u8]),
    Get(&'a str),
}

/// DoH/1.1-сессия с переподключением при transient-ошибках.
struct DohSession {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    alpn: Vec<u8>,
    client: Option<TestTlsClient>,
    connections: u64,
    sent: u64,
}

impl DohSession {
    fn new(addr: SocketAddr, cert_der: &[u8], alpn: &[u8]) -> Self {
        Self {
            addr,
            cert_der: cert_der.to_vec(),
            alpn: alpn.to_vec(),
            client: None,
            connections: 0,
            sent: 0,
        }
    }

    fn connect_once(&mut self) -> Attempt<()> {
        let client = TestTlsClient::connect(self.addr, &self.cert_der, &self.alpn)
            .ok_or_else(|| format!("DoH {}: TCP/TLS handshake не удался", self.addr))?;
        self.client = Some(client);
        self.connections = self.connections.saturating_add(1);
        Ok(())
    }

    fn connect(&mut self, label: &str, diagnostics: impl Fn() -> String) {
        retry(label, diagnostics, || self.connect_once());
    }

    fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        self.client
            .as_ref()
            .and_then(TestTlsClient::negotiated_alpn)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn call(
        &mut self,
        call: DohCall<'_>,
        label: &str,
        diagnostics: impl Fn() -> String,
    ) -> HttpsResponse {
        retry(label, diagnostics, || {
            if self.client.is_none() {
                self.connect_once()?;
            }
            self.sent = self.sent.saturating_add(1);
            let Some(client) = self.client.as_mut() else {
                return Err("DoH client отсутствует после connect".to_owned());
            };
            let response = match &call {
                DohCall::Post(body) => client.https_post("/dns-query", body),
                DohCall::Get(target) => client.https_get(target),
            };
            if let Some(response) = response {
                Ok(response)
            } else {
                self.client = None;
                Err(format!("DoH {}: нет HTTP-ответа", self.addr))
            }
        })
    }
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
    let diag = || server_diagnostics(&server);
    let mut client = DotSession::new(addr, &pki.cert_der, b"dot");
    client.connect("DoT connect", diag);
    assert_eq!(
        client.negotiated_alpn().as_deref(),
        Some(b"dot".as_slice()),
        "ALPN dot"
    );

    let response = client.query(&query("dot.secure.test", Rtype::A), "DoT A", diag);
    assert_a(&decode(&response), Ipv4Addr::new(192, 0, 2, 10));

    let response = client.query(&query("dot.secure.test", Rtype::AAAA), "DoT AAAA", diag);
    let message = decode(&response);
    assert_eq!(message.rcode(), Rcode::NOERROR);
    assert_eq!(message.answers()[0].rr_type(), Rtype::AAAA);

    let response = client.query(
        &query("missing.secure.test", Rtype::A),
        "DoT NXDOMAIN",
        diag,
    );
    assert_eq!(decode(&response).rcode(), Rcode::NXDOMAIN);

    let response = client.query(
        &query("blocked.secure.test", Rtype::A),
        "DoT blocklist",
        diag,
    );
    assert_eq!(decode(&response).rcode(), Rcode::NXDOMAIN);
    assert!(server.resolver_stats().blocked >= 1);

    let response = client.query(&query("router.secure.test", Rtype::A), "DoT override", diag);
    assert_a(&decode(&response), Ipv4Addr::new(192, 168, 1, 1));

    let counters = server.stats();
    assert_counter("dot_queries", counters.dot_queries, 5, client.sent);
    assert_counter("dot_responses", counters.dot_responses, 5, client.sent);
    let tls = server.dot_stats().expect("dot stats");
    assert_counter("dot tls queries", tls.queries, 5, client.sent);
    assert_eq!(tls.handshakes, client.connections);
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
    let diag = || server_diagnostics(&server);
    let mut client = DotSession::new(addr, &pki.cert_der, b"dot");
    client.connect("DoT connect", diag);
    let response = client.query(&query("big.secure.test", Rtype::TXT), "DoT big TXT", diag);
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
    let diag = || server_diagnostics(&server);
    let mut client = DohSession::new(addr, &pki.cert_der, b"http/1.1");
    client.connect("DoH connect", diag);
    assert_eq!(
        client.negotiated_alpn().as_deref(),
        Some(b"http/1.1".as_slice()),
        "ALPN http/1.1"
    );

    let wire = query("doh.secure.test", Rtype::A);
    let response = client.call(DohCall::Post(&wire), "DoH POST", diag);
    assert_eq!(response.status, 200);
    assert_eq!(
        response.content_type.as_deref(),
        Some("application/dns-message")
    );
    assert_a(&decode(&response.body), Ipv4Addr::new(192, 0, 2, 10));

    let encoded = URL_SAFE_NO_PAD.encode(&wire);
    let response = client.call(
        DohCall::Get(&format!("/dns-query?dns={encoded}")),
        "DoH GET",
        diag,
    );
    assert_eq!(response.status, 200);
    assert_a(&decode(&response.body), Ipv4Addr::new(192, 0, 2, 10));

    let wire = query("big.secure.test", Rtype::TXT);
    let response = client.call(DohCall::Post(&wire), "DoH big POST", diag);
    assert_eq!(response.status, 200);
    assert!(response.body.len() > 2_000);
    let message = decode(&response.body);
    assert!(!message.flags().tc());
    assert_eq!(message.answers().len(), BIG_RECORDS);

    let response = client.call(
        DohCall::Post(&query("doh.secure.test", Rtype::AAAA)),
        "DoH AAAA",
        diag,
    );
    assert_eq!(response.status, 200);
    assert_aaaa(&decode(&response.body));

    let response = client.call(
        DohCall::Post(&query("missing.secure.test", Rtype::A)),
        "DoH NXDOMAIN",
        diag,
    );
    assert_eq!(decode(&response.body).rcode(), Rcode::NXDOMAIN);

    let response = client.call(
        DohCall::Post(&query("blocked.secure.test", Rtype::A)),
        "DoH blocklist",
        diag,
    );
    assert_eq!(decode(&response.body).rcode(), Rcode::NXDOMAIN);

    let response = client.call(
        DohCall::Post(&query("router.secure.test", Rtype::A)),
        "DoH override",
        diag,
    );
    assert_a(&decode(&response.body), Ipv4Addr::new(192, 168, 1, 1));

    let response = client.call(DohCall::Post(b""), "DoH bad query", diag);
    assert_eq!(response.status, 400);

    let counters = server.stats();
    assert_counter("doh_queries", counters.doh_queries, 7, client.sent);
    assert_counter("doh_responses", counters.doh_responses, 7, client.sent);
    let tls = server.doh_stats().expect("doh stats");
    assert_counter("doh tls queries", tls.queries, 7, client.sent);
    assert!(
        tls.http_requests >= 8,
        "http_requests: {}",
        tls.http_requests
    );
    assert_eq!(tls.handshakes, client.connections);
}

// ---------------------------------------------------------------- DoH/2

struct H2Client {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    inner: Option<H2Inner>,
    connections: u64,
    sent: u64,
}

struct H2Inner {
    send: h2::client::SendRequest<Bytes>,
    _driver: tokio::task::JoinHandle<()>,
}

impl H2Client {
    fn new(addr: SocketAddr, cert_der: &[u8]) -> Self {
        Self {
            addr,
            cert_der: cert_der.to_vec(),
            inner: None,
            connections: 0,
            sent: 0,
        }
    }

    async fn connect_once(&mut self) -> Attempt<()> {
        let config = tls_client_config(&self.cert_der, b"h2");
        let connector = TlsConnector::from(Arc::new(config));
        let stream = TokioTcpStream::connect(self.addr)
            .await
            .map_err(|error| format!("h2 tcp connect {}: {error}", self.addr))?;
        let name = rustls::pki_types::ServerName::try_from("localhost")
            .map_err(|error| format!("server name: {error}"))?;
        let tls = connector
            .connect(name, stream)
            .await
            .map_err(|error| format!("h2 TLS handshake: {error}"))?;
        let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        if alpn.as_deref() != Some(b"h2".as_slice()) {
            return Err(format!("h2 ALPN mismatch: {alpn:?}"));
        }
        let (send, connection) = h2::client::handshake(tls)
            .await
            .map_err(|error| format!("h2 handshake: {error}"))?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        self.inner = Some(H2Inner {
            send,
            _driver: driver,
        });
        self.connections = self.connections.saturating_add(1);
        Ok(())
    }

    async fn call_once(
        &mut self,
        method: Method,
        uri: &str,
        body: &[u8],
    ) -> Attempt<(u16, Vec<u8>)> {
        if self.inner.is_none() {
            self.connect_once().await?;
        }
        self.sent = self.sent.saturating_add(1);
        let Some(inner) = self.inner.as_mut() else {
            return Err("h2 client отсутствует после connect".to_owned());
        };
        let end_stream = method == Method::GET;
        let request = http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/dns-message")
            .body(())
            .map_err(|error| format!("h2 request: {error}"))?;
        let (response, mut stream) = inner
            .send
            .send_request(request, end_stream)
            .map_err(|error| format!("h2 send_request: {error}"))?;
        if !end_stream {
            stream
                .send_data(Bytes::copy_from_slice(body), true)
                .map_err(|error| format!("h2 send_data: {error}"))?;
        }
        let response = match response.await {
            Ok(response) => response,
            Err(error) => {
                self.inner = None;
                return Err(format!("h2 response: {error}"));
            }
        };
        let status = response.status().as_u16();
        let mut recv = response.into_body();
        let mut out = Vec::new();
        while let Some(chunk) = recv.data().await {
            match chunk {
                Ok(chunk) => out.extend_from_slice(&chunk),
                Err(error) => {
                    self.inner = None;
                    return Err(format!("h2 body: {error}"));
                }
            }
        }
        Ok((status, out))
    }

    async fn call(
        &mut self,
        method: Method,
        uri: &str,
        body: &[u8],
        label: &str,
        diagnostics: impl Fn() -> String,
    ) -> (u16, Vec<u8>) {
        let deadline = tokio::time::Instant::now() + support::e2e::E2E_DEADLINE;
        let mut backoff = Duration::from_millis(50);
        let mut attempts = 0_u32;
        loop {
            attempts = attempts.saturating_add(1);
            match self.call_once(method.clone(), uri, body).await {
                Ok(value) => return value,
                Err(error) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "{label}: не удалось за {attempts} попыток; последняя ошибка: \
                         {error}; диагностика: {}",
                        diagnostics()
                    );
                    self.inner = None;
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::time::sleep(backoff.min(remaining)).await;
            backoff = backoff.saturating_mul(2).min(Duration::from_secs(1));
        }
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
    let diag = || server_diagnostics(&server);
    let mut client = H2Client::new(addr, &pki.cert_der);

    let wire = query("doh2.secure.test", Rtype::A);
    let (status, body) = client
        .call(
            Method::POST,
            "https://localhost/dns-query",
            &wire,
            "DoH/2 A",
            diag,
        )
        .await;
    assert_eq!(status, 200);
    assert_a(&decode(&body), Ipv4Addr::new(192, 0, 2, 10));

    let encoded = URL_SAFE_NO_PAD.encode(&wire);
    let (status, _body) = client
        .call(
            Method::GET,
            &format!("https://localhost/dns-query?dns={encoded}"),
            &[],
            "DoH/2 GET",
            diag,
        )
        .await;
    assert_eq!(status, 200);

    let wire = query("big.secure.test", Rtype::TXT);
    let (status, body) = client
        .call(
            Method::POST,
            "https://localhost/dns-query",
            &wire,
            "DoH/2 big TXT",
            diag,
        )
        .await;
    assert_eq!(status, 200);
    assert!(body.len() > 2_000);
    let message = decode(&body);
    assert!(!message.flags().tc());
    assert_eq!(message.answers().len(), BIG_RECORDS);

    let (status, body) = client
        .call(
            Method::POST,
            "https://localhost/dns-query",
            &query("doh2.secure.test", Rtype::AAAA),
            "DoH/2 AAAA",
            diag,
        )
        .await;
    assert_eq!(status, 200);
    assert_aaaa(&decode(&body));

    let (status, body) = client
        .call(
            Method::POST,
            "https://localhost/dns-query",
            &query("missing.secure.test", Rtype::A),
            "DoH/2 NXDOMAIN",
            diag,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(decode(&body).rcode(), Rcode::NXDOMAIN);

    let (status, body) = client
        .call(
            Method::POST,
            "https://localhost/dns-query",
            &query("blocked.secure.test", Rtype::A),
            "DoH/2 blocklist",
            diag,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(decode(&body).rcode(), Rcode::NXDOMAIN);

    let (status, body) = client
        .call(
            Method::POST,
            "https://localhost/dns-query",
            &query("router.secure.test", Rtype::A),
            "DoH/2 override",
            diag,
        )
        .await;
    assert_eq!(status, 200);
    assert_a(&decode(&body), Ipv4Addr::new(192, 168, 1, 1));

    let counters = server.stats();
    assert_counter(
        "doh_http2_queries",
        counters.doh_http2_queries,
        7,
        client.sent,
    );
    assert_counter(
        "doh_http2_responses",
        counters.doh_http2_responses,
        7,
        client.sent,
    );
    let tls = server.doh2_stats().expect("doh2 stats");
    // h2-handshake может не дойти до клиента после успешного TLS-handshake,
    // поэтому серверных рукопожатий может быть не меньше клиентских.
    assert!(
        tls.handshakes >= client.connections,
        "h2 handshakes {} < client connections {}",
        tls.handshakes,
        client.connections
    );
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

async fn doq_query_result(connection: &quinn::Connection, wire: &[u8]) -> Attempt<Vec<u8>> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| format!("doq open_bi: {error}"))?;
    let length = u16::try_from(wire.len()).map_err(|_| "DoQ query too large".to_owned())?;
    send.write_all(&length.to_be_bytes())
        .await
        .map_err(|error| format!("doq length: {error}"))?;
    send.write_all(wire)
        .await
        .map_err(|error| format!("doq message: {error}"))?;
    send.finish()
        .map_err(|error| format!("doq finish: {error}"))?;
    let mut prefix = [0_u8; 2];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|error| format!("doq prefix: {error}"))?;
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut response = vec![0_u8; length];
    recv.read_exact(&mut response)
        .await
        .map_err(|error| format!("doq response: {error}"))?;
    Ok(response)
}

/// DoQ-сессия: соединение пересоздаётся при transient-ошибках.
struct DoqSession {
    endpoint: quinn::Endpoint,
    addr: SocketAddr,
    connection: Option<quinn::Connection>,
    connections: u64,
    sent: u64,
}

impl DoqSession {
    fn new(addr: SocketAddr, cert_der: &[u8]) -> Self {
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().expect("client addr")).expect("endpoint");
        endpoint.set_default_client_config(quic_client_config(cert_der));
        Self {
            endpoint,
            addr,
            connection: None,
            connections: 0,
            sent: 0,
        }
    }

    async fn connect_once(&mut self) -> Attempt<()> {
        let connecting = self
            .endpoint
            .connect(self.addr, "localhost")
            .map_err(|error| format!("doq connect: {error}"))?;
        let connection = connecting
            .await
            .map_err(|error| format!("doq handshake: {error}"))?;
        self.connection = Some(connection);
        self.connections = self.connections.saturating_add(1);
        Ok(())
    }

    async fn connect(&mut self, label: &str, diagnostics: impl Fn() -> String) {
        let endpoint = self.endpoint.clone();
        let addr = self.addr;
        let connection = retry_async(label, diagnostics, || {
            let endpoint = endpoint.clone();
            async move {
                let connecting = endpoint
                    .connect(addr, "localhost")
                    .map_err(|error| format!("doq connect: {error}"))?;
                connecting
                    .await
                    .map_err(|error| format!("doq handshake: {error}"))
            }
        })
        .await;
        self.connection = Some(connection);
        self.connections = self.connections.saturating_add(1);
    }

    async fn query(
        &mut self,
        wire: &[u8],
        label: &str,
        diagnostics: impl Fn() -> String,
    ) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + support::e2e::E2E_DEADLINE;
        let mut backoff = Duration::from_millis(50);
        let mut attempts = 0_u32;
        let mut last = String::new();
        loop {
            attempts = attempts.saturating_add(1);
            if self.connection.is_none()
                && let Err(error) = self.connect_once().await
            {
                last = error;
            }
            if let Some(connection) = self.connection.as_ref() {
                self.sent = self.sent.saturating_add(1);
                match doq_query_result(connection, wire).await {
                    Ok(response) => return response,
                    Err(error) => {
                        last = error;
                        self.connection = None;
                    }
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{label}: не удалось за {attempts} попыток; последняя ошибка: {last}; \
                 диагностика: {}",
                diagnostics()
            );
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            tokio::time::sleep(backoff.min(remaining)).await;
            backoff = backoff.saturating_mul(2).min(Duration::from_secs(1));
        }
    }

    async fn close(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close(0_u32.into(), b"done");
        }
        self.endpoint.wait_idle().await;
    }
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
    let diag = || server_diagnostics(&server);
    let mut session = DoqSession::new(addr, &pki.cert_der);
    session.connect("DoQ connect", diag).await;

    let response = session
        .query(&doq_wire("doq.secure.test", Rtype::A), "DoQ A", diag)
        .await;
    assert_a(&decode(&response), Ipv4Addr::new(192, 0, 2, 10));

    let response = session
        .query(
            &doq_wire("missing.secure.test", Rtype::A),
            "DoQ NXDOMAIN",
            diag,
        )
        .await;
    assert_eq!(decode(&response).rcode(), Rcode::NXDOMAIN);

    let response = session
        .query(
            &doq_wire("big.secure.test", Rtype::TXT),
            "DoQ big TXT",
            diag,
        )
        .await;
    assert!(response.len() > 2_000);
    let message = decode(&response);
    assert!(!message.flags().tc(), "DoQ must not truncate");
    assert_eq!(message.answers().len(), BIG_RECORDS);

    let response = session
        .query(&doq_wire("doq.secure.test", Rtype::AAAA), "DoQ AAAA", diag)
        .await;
    assert_aaaa(&decode(&response));

    let response = session
        .query(
            &doq_wire("blocked.secure.test", Rtype::A),
            "DoQ blocklist",
            diag,
        )
        .await;
    assert_eq!(decode(&response).rcode(), Rcode::NXDOMAIN);

    let response = session
        .query(
            &doq_wire("router.secure.test", Rtype::A),
            "DoQ override",
            diag,
        )
        .await;
    assert_a(&decode(&response), Ipv4Addr::new(192, 168, 1, 1));

    let counters = server.stats();
    assert_counter("doq_queries", counters.doq_queries, 6, session.sent);
    assert_counter("doq_responses", counters.doq_responses, 6, session.sent);
    let tls = server.doq_stats().expect("doq stats");
    // Как и в h2: сервер мог завершить QUIC-handshake, а клиент — не успеть.
    assert!(
        tls.handshakes >= session.connections,
        "doq handshakes {} < client connections {}",
        tls.handshakes,
        session.connections
    );
    session.close().await;
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

    // Убеждаемся, что UDP-сокет действительно читает пакеты. Проба заведомо
    // некорректна: она увеличивает только счётчик ошибок, не queries.
    wait_dnscrypt_udp_listening(addr, || server.stats().dnscrypt_udp_errors);

    let diag = || server_diagnostics(&server);
    let mut client = DnscryptUdpClient::new(addr, &fixture.client);

    let response = client.query(
        &decode(&query("dnscrypt.secure.test", Rtype::A)),
        "DNSCrypt UDP A",
        diag,
    );
    assert_a(&response, Ipv4Addr::new(192, 0, 2, 10));

    let nxdomain = client.query(
        &decode(&query("missing.secure.test", Rtype::A)),
        "DNSCrypt UDP NXDOMAIN",
        diag,
    );
    assert_eq!(nxdomain.rcode(), Rcode::NXDOMAIN);

    let big = client.query(
        &decode(&query("big.secure.test", Rtype::TXT)),
        "DNSCrypt UDP big TXT",
        diag,
    );
    assert!(
        big.flags().tc(),
        "DNSCrypt UDP must truncate oversized answer"
    );

    let aaaa = client.query(
        &decode(&query("dnscrypt.secure.test", Rtype::AAAA)),
        "DNSCrypt UDP AAAA",
        diag,
    );
    assert_aaaa(&aaaa);

    let blocked = client.query(
        &decode(&query("blocked.secure.test", Rtype::A)),
        "DNSCrypt UDP blocklist",
        diag,
    );
    assert_eq!(blocked.rcode(), Rcode::NXDOMAIN);

    let overridden = client.query(
        &decode(&query("router.secure.test", Rtype::A)),
        "DNSCrypt UDP override",
        diag,
    );
    assert_a(&overridden, Ipv4Addr::new(192, 168, 1, 1));

    let counters = server.stats();
    assert_counter(
        "dnscrypt_udp_queries",
        counters.dnscrypt_udp_queries,
        6,
        client.sent(),
    );
    assert_counter(
        "dnscrypt_udp_responses",
        counters.dnscrypt_udp_responses,
        6,
        client.sent(),
    );
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
    let diag = || server_diagnostics(&server);
    let mut client = DnscryptTcpClient::new(addr, &fixture.client);
    client.ensure_connected("DNSCrypt TCP connect", diag);

    for (name, rtype) in [
        ("dnscrypt-tcp.secure.test", Rtype::A),
        ("dnscrypt-tcp.secure.test", Rtype::AAAA),
        ("missing.secure.test", Rtype::A),
    ] {
        let request = decode(&query(name, rtype));
        let response = client.query(&request, "DNSCrypt TCP query", diag);
        match rtype {
            Rtype::A if name.starts_with("dnscrypt-tcp") => {
                assert_a(&response, Ipv4Addr::new(192, 0, 2, 10));
            }
            Rtype::AAAA => assert_eq!(response.answers()[0].rr_type(), Rtype::AAAA),
            _ => assert_eq!(response.rcode(), Rcode::NXDOMAIN),
        }
    }

    let request = decode(&query("big.secure.test", Rtype::TXT));
    let response = client.query(&request, "DNSCrypt TCP big TXT", diag);
    assert!(!response.flags().tc(), "DNSCrypt TCP must not truncate");
    assert_eq!(response.answers().len(), BIG_RECORDS);

    for name in ["blocked.secure.test", "missing.secure.test"] {
        let request = decode(&query(name, Rtype::A));
        let response = client.query(&request, "DNSCrypt TCP negative", diag);
        assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    }
    let request = decode(&query("router.secure.test", Rtype::A));
    let response = client.query(&request, "DNSCrypt TCP override", diag);
    assert_a(&response, Ipv4Addr::new(192, 168, 1, 1));

    let counters = server.stats();
    assert_counter(
        "dnscrypt_tcp_queries",
        counters.dnscrypt_tcp_queries,
        7,
        client.sent(),
    );
    assert_counter(
        "dnscrypt_tcp_responses",
        counters.dnscrypt_tcp_responses,
        7,
        client.sent(),
    );
    assert_eq!(counters.dnscrypt_tcp_connections, client.connections());
    // Без повторов все 7 запросов должны идти по одному соединению.
    if client.sent() == 7 {
        assert_eq!(client.connections(), 1, "queries must share one connection");
    }
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
    let diag = || server_diagnostics(&server);

    // UDP.
    let request = make_query("acl.secure.test", Rtype::A, None);
    let mut udp_attempts = 0_u64;
    let response = retry("ACL UDP", diag, || {
        udp_attempts = udp_attempts.saturating_add(1);
        udp_query(server.udp_addr().expect("udp"), &request, SOCKET_TIMEOUT)
            .ok_or_else(|| "нет UDP-ответа".to_owned())
    });
    assert_eq!(response.rcode(), Rcode::REFUSED);

    // DoT.
    let mut dot = DotSession::new(server.dot_addr().expect("dot"), &pki.cert_der, b"dot");
    dot.connect("ACL DoT connect", diag);
    let response = dot.query(&query("acl.secure.test", Rtype::A), "ACL DoT query", diag);
    assert_eq!(decode(&response).rcode(), Rcode::REFUSED);

    // DoH/1.1.
    let mut doh = DohSession::new(server.doh_addr().expect("doh"), &pki.cert_der, b"http/1.1");
    doh.connect("ACL DoH connect", diag);
    let response = doh.call(
        DohCall::Post(&query("acl.secure.test", Rtype::A)),
        "ACL DoH query",
        diag,
    );
    assert_eq!(response.status, 200);
    assert_eq!(decode(&response.body).rcode(), Rcode::REFUSED);

    // DoH/2.
    let mut h2 = H2Client::new(server.doh2_addr().expect("doh2"), &pki.cert_der);
    let (status, body) = h2
        .call(
            Method::POST,
            "https://localhost/dns-query",
            &query("acl.secure.test", Rtype::A),
            "ACL DoH/2 query",
            diag,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(decode(&body).rcode(), Rcode::REFUSED);

    // DoQ.
    let mut doq = DoqSession::new(server.doq_addr().expect("doq"), &pki.cert_der);
    doq.connect("ACL DoQ connect", diag).await;
    let response = doq
        .query(
            &doq_wire("acl.secure.test", Rtype::A),
            "ACL DoQ query",
            diag,
        )
        .await;
    assert_eq!(decode(&response).rcode(), Rcode::REFUSED);

    // DNSCrypt UDP.
    wait_dnscrypt_udp_listening(server.dnscrypt_udp_addr().expect("dnscrypt udp"), || {
        server.stats().dnscrypt_udp_errors
    });
    let mut dnscrypt_udp = DnscryptUdpClient::new(
        server.dnscrypt_udp_addr().expect("dnscrypt udp"),
        &fixture.client,
    );
    let response = dnscrypt_udp.query(
        &decode(&query("acl.secure.test", Rtype::A)),
        "ACL DNSCrypt UDP",
        diag,
    );
    assert_eq!(response.rcode(), Rcode::REFUSED);

    // DNSCrypt TCP.
    let mut dnscrypt_tcp = DnscryptTcpClient::new(
        server.dnscrypt_tcp_addr().expect("dnscrypt tcp"),
        &fixture.client,
    );
    dnscrypt_tcp.ensure_connected("ACL DNSCrypt TCP connect", diag);
    let response = dnscrypt_tcp.query(
        &decode(&query("acl.secure.test", Rtype::A)),
        "ACL DNSCrypt TCP",
        diag,
    );
    assert_eq!(response.rcode(), Rcode::REFUSED);

    let counters = server.stats();
    let transport_attempts = udp_attempts
        + dot.sent
        + doh.sent
        + h2.sent
        + doq.sent
        + dnscrypt_udp.sent()
        + dnscrypt_tcp.sent();
    assert_eq!(
        counters.refused_acl, transport_attempts,
        "one REFUSED per transport attempt"
    );
    assert!(
        server.resolver_stats().queries == 0,
        "ACL must run before the resolver"
    );
    doq.close().await;
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
    let diag = || server_diagnostics(&server);

    let request = make_query("plain.secure.test", Rtype::A, None);
    let response = udp_query_retry(server.udp_addr().expect("udp"), &request, "ACL UDP allowed");
    assert_eq!(response.rcode(), Rcode::NOERROR);

    let mut dot = DotSession::new(server.dot_addr().expect("dot"), &pki.cert_der, b"dot");
    dot.connect("tls_allow_from DoT connect", diag);
    let response = dot.query(
        &query("plain.secure.test", Rtype::A),
        "tls_allow_from DoT query",
        diag,
    );
    assert_eq!(decode(&response).rcode(), Rcode::REFUSED);
    assert_eq!(server.stats().refused_acl, dot.sent);
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
    let response = udp_query_retry(plain_udp, &request, "all UDP");
    assert_eq!(response.rcode(), Rcode::NOERROR);
    let response = support::tcp_query_retry(plain_tcp, &request, "all TCP");
    assert_eq!(response.rcode(), Rcode::NOERROR);

    let diag = || server_diagnostics(&server);

    // DoT.
    let mut dot = DotSession::new(dot_port, &pki.cert_der, b"dot");
    let response = dot.query(&query("all.secure.test", Rtype::A), "all DoT", diag);
    assert_a(&decode(&response), Ipv4Addr::new(192, 0, 2, 10));

    // DoH/1.1.
    let mut doh = DohSession::new(doh1_port, &pki.cert_der, b"http/1.1");
    let response = doh.call(
        DohCall::Post(&query("all.secure.test", Rtype::A)),
        "all DoH",
        diag,
    );
    assert_a(&decode(&response.body), Ipv4Addr::new(192, 0, 2, 10));

    // DoH/2.
    let mut h2 = H2Client::new(doh2_port, &pki.cert_der);
    let (status, body) = h2
        .call(
            Method::POST,
            "https://localhost/dns-query",
            &query("all.secure.test", Rtype::A),
            "all DoH/2",
            diag,
        )
        .await;
    assert_eq!(status, 200);
    assert_a(&decode(&body), Ipv4Addr::new(192, 0, 2, 10));

    // DoQ.
    let mut doq = DoqSession::new(quic_port, &pki.cert_der);
    doq.connect("all DoQ connect", diag).await;
    let response = doq
        .query(&doq_wire("all.secure.test", Rtype::A), "all DoQ", diag)
        .await;
    assert_a(&decode(&response), Ipv4Addr::new(192, 0, 2, 10));

    // DNSCrypt UDP/TCP.
    wait_dnscrypt_udp_listening(dnscrypt_udp, || server.stats().dnscrypt_udp_errors);
    let mut dnscrypt_udp_client = DnscryptUdpClient::new(dnscrypt_udp, &fixture.client);
    let response = dnscrypt_udp_client.query(
        &decode(&query("all.secure.test", Rtype::A)),
        "all DNSCrypt UDP",
        diag,
    );
    assert_a(&response, Ipv4Addr::new(192, 0, 2, 10));
    let mut dnscrypt_tcp_client = DnscryptTcpClient::new(dnscrypt_tcp, &fixture.client);
    let response = dnscrypt_tcp_client.query(
        &decode(&query("all.secure.test", Rtype::A)),
        "all DNSCrypt TCP",
        diag,
    );
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
    assert!(
        metrics.contains(&format!(
            "pulseresolved_dot_handshakes_total {}",
            dot.connections
        )),
        "dot handshakes metric mismatch: {metrics}"
    );
    assert!(
        metrics.contains(&format!(
            "pulseresolved_dnscrypt_tcp_connections_total {}",
            dnscrypt_tcp_client.connections()
        )),
        "dnscrypt tcp connections metric mismatch: {metrics}"
    );
    doq.close().await;

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
    let diag = || server_diagnostics(&server);

    let mut client = DotSession::new(addr, &pki.cert_der, b"dot");
    let response = client.query(
        &query("reload.secure.test", Rtype::A),
        "reload first DoT query",
        diag,
    );
    assert_eq!(decode(&response).rcode(), Rcode::NOERROR);

    let replacement = TestPki::generate();
    write_secret(&pki.key_path, replacement.key_pem.as_bytes());
    std::fs::write(&pki.cert_path, replacement.cert_pem.as_bytes()).expect("replace cert");
    server.reload_tls().expect("reload tls");
    assert_eq!(server.stats().tls_reloads, 1);

    let mut client = DotSession::new(addr, &replacement.cert_der, b"dot");
    let response = client.query(
        &query("reload.secure.test", Rtype::A),
        "reload second DoT query",
        diag,
    );
    assert_eq!(decode(&response).rcode(), Rcode::NOERROR);

    assert!(
        TestTlsClient::connect(addr, &pki.cert_der, b"dot").is_none(),
        "old certificate must be rejected for new connections"
    );
}

// ---------------------------------------------------------------- helpers

fn udp_wire(server: SocketAddr, request: &[u8]) -> Vec<u8> {
    use std::net::UdpSocket;
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

fn tcp_wire(server: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut stream = retry(
        "tcp wire connect",
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
    assert!(bytes.len() >= 12, "short response");
    bytes[..2].fill(0);
    let question_count = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    let record_count = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]))
        + usize::from(u16::from_be_bytes([bytes[8], bytes[9]]))
        + usize::from(u16::from_be_bytes([bytes[10], bytes[11]]));
    let mut position = 12_usize;
    for _ in 0..question_count {
        position = skip_name(&bytes, position);
        position = position.saturating_add(4);
    }
    for _ in 0..record_count {
        position = skip_name(&bytes, position);
        let rr_type = u16::from_be_bytes([bytes[position], bytes[position + 1]]);
        // TTL декрементируется между запросами; у OPT в TTL лежат DO/extended
        // RCODE, их сравниваем как есть.
        if rr_type != 41 {
            bytes[position + 4..position + 8].fill(0);
        }
        let rdlength = usize::from(u16::from_be_bytes([
            bytes[position + 8],
            bytes[position + 9],
        ]));
        position = position.saturating_add(10).saturating_add(rdlength);
    }
    bytes
}

fn skip_name(bytes: &[u8], mut position: usize) -> usize {
    loop {
        let length = bytes[position];
        if length == 0 {
            return position + 1;
        }
        if length & 0xC0 == 0xC0 {
            return position + 2;
        }
        position = position.saturating_add(1 + usize::from(length));
    }
}

fn dnscrypt_udp_wire(
    server: SocketAddr,
    client: &pulse_dnscrypt::DnscryptClient,
    request: &[u8],
) -> Vec<u8> {
    use std::net::UdpSocket;
    let pending = client
        .build_query(request, pulse_dnscrypt::Transport::Udp)
        .expect("dnscrypt udp query");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind dnscrypt client");
    socket
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("dnscrypt timeout");
    socket
        .send_to(pending.packet(), server)
        .expect("send dnscrypt");
    let mut buffer = [0_u8; 8192];
    let (length, _) = socket.recv_from(&mut buffer).expect("recv dnscrypt");
    client
        .decrypt_response(&pending, &buffer[..length])
        .expect("decrypt dnscrypt")
}

fn dnscrypt_tcp_wire(
    server: SocketAddr,
    client: &pulse_dnscrypt::DnscryptClient,
    request: &[u8],
) -> Vec<u8> {
    let pending = client
        .build_query(request, pulse_dnscrypt::Transport::Tcp)
        .expect("dnscrypt tcp query");
    let mut stream = retry(
        "dnscrypt tcp connect",
        || format!("tcp {server}"),
        || TcpStream::connect(server).map_err(|error| error.to_string()),
    );
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .expect("dnscrypt timeout");
    stream.write_all(pending.packet()).expect("write dnscrypt");
    stream.flush().expect("flush");
    let mut prefix = [0_u8; 2];
    stream
        .read_exact(&mut prefix)
        .expect("read dnscrypt prefix");
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut frame = vec![0_u8; 2 + length];
    frame[..2].copy_from_slice(&prefix);
    stream
        .read_exact(&mut frame[2..])
        .expect("read dnscrypt frame");
    client
        .decrypt_response(&pending, &frame)
        .expect("decrypt dnscrypt")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_transports_return_same_cache_hit_wire() {
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
    let server = Server::start(&config).expect("server");
    let diag = || server_diagnostics(&server);
    let name = "wire.secure.test";
    let request = make_query(name, Rtype::A, None);
    let wire = query(name, Rtype::A);

    // Прогрев серверного кеша.
    let warm =
        udp_query(server.udp_addr().expect("udp"), &request, SOCKET_TIMEOUT).expect("warmup");
    assert_eq!(warm.rcode(), Rcode::NOERROR);

    // Эталон: старый Message-путь с тем же upstream и прогретым кешем.
    let reference =
        pulse_resolver::Resolver::new(config.resolver_config().expect("resolver config"))
            .expect("reference resolver");
    assert_eq!(reference.resolve(&request).rcode(), Rcode::NOERROR);
    let mut buffer = [0_u8; 4096];
    let length = reference
        .resolve(&request)
        .encode_into(&mut buffer)
        .expect("encode reference");
    let expected = normalize(buffer[..length].to_vec());

    // UDP и TCP — сырые байты.
    assert_eq!(
        normalize(udp_wire(server.udp_addr().expect("udp"), &wire)),
        expected,
        "UDP"
    );
    assert_eq!(
        normalize(tcp_wire(server.tcp_addr().expect("tcp"), &wire)),
        expected,
        "TCP"
    );

    // DoT.
    let mut dot = DotSession::new(server.dot_addr().expect("dot"), &pki.cert_der, b"dot");
    dot.connect("wire DoT connect", diag);
    assert_eq!(
        normalize(dot.query(&wire, "wire DoT", diag)),
        expected,
        "DoT"
    );

    // DoH/1.1.
    let mut doh = DohSession::new(server.doh_addr().expect("doh"), &pki.cert_der, b"http/1.1");
    doh.connect("wire DoH connect", diag);
    let response = doh.call(DohCall::Post(&wire), "wire DoH", diag);
    assert_eq!(response.status, 200);
    assert_eq!(normalize(response.body), expected, "DoH/1.1");

    // DoH/2.
    let mut h2 = H2Client::new(server.doh2_addr().expect("doh2"), &pki.cert_der);
    let (status, body) = h2
        .call(
            Method::POST,
            "https://localhost/dns-query",
            &wire,
            "wire DoH/2",
            diag,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(normalize(body), expected, "DoH/2");

    // DoQ (ID=0).
    let mut doq = DoqSession::new(server.doq_addr().expect("doq"), &pki.cert_der);
    doq.connect("wire DoQ connect", diag).await;
    let response = doq.query(&doq_wire(name, Rtype::A), "wire DoQ", diag).await;
    assert_eq!(normalize(response), expected, "DoQ");

    // DNSCrypt UDP/TCP.
    wait_dnscrypt_udp_listening(server.dnscrypt_udp_addr().expect("dnscrypt udp"), || {
        server.stats().dnscrypt_udp_errors
    });
    assert_eq!(
        normalize(dnscrypt_udp_wire(
            server.dnscrypt_udp_addr().expect("dnscrypt udp"),
            &fixture.client,
            &wire,
        )),
        expected,
        "DNSCrypt UDP"
    );
    assert_eq!(
        normalize(dnscrypt_tcp_wire(
            server.dnscrypt_tcp_addr().expect("dnscrypt tcp"),
            &fixture.client,
            &wire,
        )),
        expected,
        "DNSCrypt TCP"
    );

    let counters = server.stats();
    assert!(counters.fast_path >= 7, "all transports use wire fast path");
    assert!(counters.zero_alloc_responses >= 7);
    doq.close().await;
}

fn http_get(addr: SocketAddr, path: &str) -> String {
    retry(
        "metrics GET",
        || format!("metrics {addr}"),
        || {
            let mut stream = TcpStream::connect(addr)
                .map_err(|error| format!("metrics connect {addr}: {error}"))?;
            stream
                .set_read_timeout(Some(SOCKET_TIMEOUT))
                .map_err(|error| format!("metrics timeout: {error}"))?;
            write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .map_err(|error| format!("metrics write: {error}"))?;
            stream
                .flush()
                .map_err(|error| format!("metrics flush: {error}"))?;
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .map_err(|error| format!("metrics read: {error}"))?;
            Ok(response)
        },
    )
}
