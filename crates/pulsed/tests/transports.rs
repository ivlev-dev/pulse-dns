//! Реальные прогоны защищённых транспортов `pulsed`: `DoT`, `DoH` и `DNSCrypt`.
//!
//! Тесты поднимают сервер с self-signed сертификатом (`rcgen`) и клиентами
//! `rustls`/`pulse-dnscrypt`, проверяют ответы, параллельную работу трёх
//! транспортов, `/metrics`, hot-reload TLS, graceful shutdown и права файлов
//! `dnscrypt-gencert`.

mod common;

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rdata, Rtype};
use pulse_dnscrypt::{
    Certificate, DnscryptClient, ProviderPublicKey, Transport as DnscryptTransport,
};
use pulsed::config::Config;
use pulsed::server::{ApiOptions, Server};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

struct TestCert {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    cert_der: Vec<u8>,
}

impl TestCert {
    fn generate() -> Self {
        let key = KeyPair::generate().expect("generate key pair");
        let params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("certificate params");
        let certificate = params.self_signed(&key).expect("self-signed certificate");
        Self {
            cert_pem: certificate.pem().into_bytes(),
            key_pem: key.serialize_pem().into_bytes(),
            cert_der: certificate.der().to_vec(),
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write private file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod private file");
    }
}

fn write_public(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write public file");
}

fn cert_pair(dir: &Path, cert: &TestCert) -> (PathBuf, PathBuf) {
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    write_public(&cert_path, &cert.cert_pem);
    write_private(&key_path, &cert.key_pem);
    (cert_path, key_path)
}

fn dns_query(name: &str, rr_type: Rtype, id: u16) -> Vec<u8> {
    let name = Name::parse(name).expect("valid name");
    Message::query(id, Question::new(name, rr_type, Rclass::IN))
        .encode(&EncodeOptions::compressed())
        .expect("encode query")
}

fn decode(bytes: &[u8]) -> Message {
    Message::decode(bytes, &DecodeLimits::default()).expect("decode response")
}

fn a_records(message: &Message) -> Vec<String> {
    message
        .answers()
        .iter()
        .filter_map(|record| match record.rdata() {
            Rdata::A(address) => Some(address.to_string()),
            _ => None,
        })
        .collect()
}

/// Минимальный TLS-клиент на std TCP + rustls.
struct TlsClient {
    connection: ClientConnection,
    socket: TcpStream,
    buffer: Vec<u8>,
}

impl TlsClient {
    fn connect(addr: SocketAddr, cert_der: &[u8], alpn: Option<&[u8]>) -> std::io::Result<Self> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert_der.to_vec()))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        if let Some(alpn) = alpn {
            config.alpn_protocols = vec![alpn.to_vec()];
        }
        let server_name = ServerName::try_from("localhost".to_owned())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "name"))?;
        let mut connection = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut socket = TcpStream::connect(addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        socket.set_nodelay(true)?;
        while connection.is_handshaking() {
            match connection.complete_io(&mut socket) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(Self {
            connection,
            socket,
            buffer: Vec::new(),
        })
    }

    fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.connection.alpn_protocol()
    }

    fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.connection
            .writer()
            .write_all(data)
            .map_err(std::io::Error::other)?;
        while self.connection.wants_write() {
            match self.connection.write_tls(&mut self.socket) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn read_exact(&mut self, length: usize) -> std::io::Result<Vec<u8>> {
        let mut output = vec![0_u8; length];
        let mut offset = 0;
        while offset < length {
            let slice = output
                .get_mut(offset..)
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "offset"))?;
            let read = self.read(slice)?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "TLS connection closed",
                ));
            }
            offset += read;
        }
        Ok(output)
    }

    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.connection.reader().read(buffer) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            let read = loop {
                match self.connection.read_tls(&mut self.socket) {
                    Ok(read) => break read,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            };
            if read == 0 {
                return Ok(0);
            }
            self.connection
                .process_new_packets()
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        }
    }

    fn dot_request(&mut self, message: &[u8]) -> std::io::Result<Vec<u8>> {
        let length = u16::try_from(message.len())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "too large"))?;
        self.send(&length.to_be_bytes())?;
        self.send(message)?;
        let prefix = self.read_exact(2)?;
        let length = u16::from_be_bytes([prefix[0], prefix[1]]);
        self.read_exact(usize::from(length))
    }

    fn http_request(&mut self, raw: &[u8]) -> std::io::Result<HttpResponse> {
        self.send(raw)?;
        self.read_http()
    }

    fn read_http(&mut self) -> std::io::Result<HttpResponse> {
        let head_end = loop {
            if let Some(position) = find_head_end(&self.buffer) {
                break position;
            }
            self.fill()?;
        };
        let head = self
            .buffer
            .get(..head_end)
            .ok_or_else(|| std::io::Error::other("head bounds"))?
            .to_vec();
        self.buffer.drain(..head_end);
        let head = String::from_utf8_lossy(&head).into_owned();
        let mut lines = head.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "status"))?;
        let status = status_line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "status code"))?
            .parse::<u16>()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "status code"))?;
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
            }
        }
        let length = headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .and_then(|(_, value)| value.parse::<usize>().ok())
            .unwrap_or(0);
        while self.buffer.len() < length {
            self.fill()?;
        }
        let body = self
            .buffer
            .get(..length)
            .ok_or_else(|| std::io::Error::other("body bounds"))?
            .to_vec();
        self.buffer.drain(..length);
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    fn fill(&mut self) -> std::io::Result<()> {
        let mut chunk = [0_u8; 4096];
        let read = self.read(&mut chunk)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP connection closed",
            ));
        }
        let data = chunk
            .get(..read)
            .ok_or_else(|| std::io::Error::other("read bounds"))?;
        self.buffer.extend_from_slice(data);
        Ok(())
    }
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }
}

fn post_dns(path: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(body);
    request
}

fn get_path(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").into_bytes()
}

fn tls_config(zone: &common::TempZone, cert: &TestCert) -> (tempfile::TempDir, Config) {
    let dir = tempfile::Builder::new()
        .prefix("pulsed-tls-")
        .tempdir()
        .expect("temp tls dir");
    let (cert_path, key_path) = cert_pair(dir.path(), cert);
    let mut config = common::base_config(zone.path());
    config.dot_listen = Some("127.0.0.1:0".parse().expect("dot addr"));
    config.doh_listen = Some("127.0.0.1:0".parse().expect("doh addr"));
    config.tls_cert = Some(cert_path);
    config.tls_key = Some(key_path);
    config.tls_allow_from = vec!["127.0.0.0/8".to_owned()];
    (dir, config)
}

#[test]
fn dot_and_doh_answer_a_with_alpn() {
    let zone = common::TempZone::with_import("tls", "example.com.", &common::example_zone());
    let cert = TestCert::generate();
    let (_dir, config) = tls_config(&zone, &cert);
    let mut server = Server::start(&config).expect("start server");

    let dot = server.dot_addr().expect("DoT address");
    let mut client = TlsClient::connect(dot, &cert.cert_der, Some(b"dot")).expect("DoT client");
    assert_eq!(client.negotiated_alpn(), Some(b"dot".as_slice()));
    let query = dns_query("www.example.com.", Rtype::A, 0x1001);
    let response = client.dot_request(&query).expect("DoT response");
    let message = decode(&response);
    assert_eq!(message.id(), 0x1001);
    assert!(!message.flags().tc());
    assert_eq!(a_records(&message), vec!["192.0.2.20"]);

    let doh = server.doh_addr().expect("DoH address");
    let mut client =
        TlsClient::connect(doh, &cert.cert_der, Some(b"http/1.1")).expect("DoH client");
    assert_eq!(client.negotiated_alpn(), Some(b"http/1.1".as_slice()));
    let response = client
        .http_request(&post_dns("/dns-query", &query))
        .expect("DoH POST");
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("application/dns-message")
    );
    assert_eq!(a_records(&decode(&response.body)), vec!["192.0.2.20"]);

    let encoded = URL_SAFE_NO_PAD.encode(&query);
    let response = client
        .http_request(&get_path(&format!("/dns-query?dns={encoded}")))
        .expect("DoH GET");
    assert_eq!(response.status, 200);
    assert_eq!(a_records(&decode(&response.body)), vec!["192.0.2.20"]);

    let response = client
        .http_request(&get_path("/healthz"))
        .expect("DoH health");
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"ok\n");

    let stats = server.dot_stats().expect("DoT stats");
    assert_eq!(stats.queries, 1);
    assert_eq!(server.doh_stats().expect("DoH stats").queries, 2);

    server.shutdown().expect("shutdown");
    assert_port_closed(dot);
    assert_port_closed(doh);
}

#[test]
fn tls_key_permissions_are_enforced() {
    let zone = common::TempZone::with_import("tls-perms", "example.com.", &common::example_zone());
    let cert = TestCert::generate();
    let (_dir, config) = tls_config(&zone, &cert);
    let key_path = config.tls_key.clone().expect("key path");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod key");
    }
    assert!(
        Server::start(&config).is_err(),
        "a world-readable TLS private key must be rejected"
    );
}

#[test]
fn large_answers_are_not_truncated_on_dot_or_doh() {
    let (_big_dir, zone) = big_zone();
    let cert = TestCert::generate();
    let (_dir, config) = tls_config(&zone, &cert);
    let mut server = Server::start(&config).expect("start server");

    let query = dns_query("many.big.test.", Rtype::A, 0x2001);
    let mut client = TlsClient::connect(
        server.dot_addr().expect("DoT"),
        &cert.cert_der,
        Some(b"dot"),
    )
    .expect("DoT client");
    let response = decode(&client.dot_request(&query).expect("DoT response"));
    assert!(!response.flags().tc());
    assert_eq!(response.answers().len(), 40);
    assert!(
        response
            .encode(&EncodeOptions::default())
            .expect("encode")
            .len()
            > 512
    );

    let mut client = TlsClient::connect(
        server.doh_addr().expect("DoH"),
        &cert.cert_der,
        Some(b"http/1.1"),
    )
    .expect("DoH client");
    let response = client
        .http_request(&post_dns("/dns-query", &query))
        .expect("DoH POST");
    assert_eq!(response.status, 200);
    assert!(response.body.len() > 512);
    let message = decode(&response.body);
    assert!(!message.flags().tc());
    assert_eq!(message.answers().len(), 40);

    server.shutdown().expect("shutdown");
}

#[test]
fn dnscrypt_udp_answers_and_rejects_wrong_keys() {
    let zone = common::TempZone::with_import("dnscrypt", "example.com.", &common::example_zone());
    let material = generate_dnscrypt();
    let mut config = common::base_config(zone.path());
    config.dnscrypt_listen = Some("127.0.0.1:0".parse().expect("dnscrypt addr"));
    config.dnscrypt_provider_key = Some(material.provider_key.clone());
    config.dnscrypt_resolver_key = Some(material.resolver_key.clone());
    config.dnscrypt_cert = Some(material.cert.clone());
    config.dnscrypt_provider_name = Some(material.provider_name.clone());
    let mut server = Server::start(&config).expect("start server");
    let addr = server.dnscrypt_addr().expect("DNSCrypt address");
    assert_ne!(
        addr.port(),
        0,
        "server must report the real bound DNSCrypt UDP address, got {addr}"
    );

    let certificate = Certificate::from_hex(&material.certificate_hex).expect("certificate");
    let provider = ProviderPublicKey::from_hex(&material.provider_public_key).expect("provider");
    let now = unix_now();
    let client = DnscryptClient::new(certificate.clone(), provider, now).expect("client");
    let query = dns_query("www.example.com.", Rtype::A, 0x3001);
    let response = dnscrypt_exchange(addr, &client, &query);
    let message = decode(&response);
    assert_eq!(a_records(&message), vec!["192.0.2.20"]);

    let wrong = pulse_dnscrypt::ProviderKeypair::generate()
        .expect("provider")
        .public_key();
    assert!(
        DnscryptClient::new(certificate.clone(), wrong, now).is_err(),
        "a different provider key must be rejected"
    );

    let mut tampered_bytes = certificate.to_bytes();
    let last = tampered_bytes.len() - 1;
    tampered_bytes[last] ^= 0x01;
    let tampered = Certificate::parse(&tampered_bytes).expect("parse tampered certificate");
    assert!(
        tampered.verify(&provider).is_err(),
        "a tampered certificate must fail signature verification"
    );

    server.shutdown().expect("shutdown");
    assert_udp_silent(addr);
}

#[test]
fn dnscrypt_server_rejects_mismatched_resolver_key() {
    let zone =
        common::TempZone::with_import("dnscrypt-bad", "example.com.", &common::example_zone());
    let material = generate_dnscrypt();
    let other = pulse_dnscrypt::ResolverKeypair::generate().expect("resolver");
    write_private(
        &material.resolver_key,
        hex::encode(*other.to_secret_bytes()).as_bytes(),
    );
    let mut config = common::base_config(zone.path());
    config.dnscrypt_listen = Some("127.0.0.1:0".parse().expect("dnscrypt addr"));
    config.dnscrypt_provider_key = Some(material.provider_key.clone());
    config.dnscrypt_resolver_key = Some(material.resolver_key.clone());
    config.dnscrypt_cert = Some(material.cert.clone());
    assert!(
        Server::start(&config).is_err(),
        "a resolver key that does not match the certificate must be rejected"
    );
}

#[test]
fn dnscrypt_truncates_large_udp_answers_with_tc() {
    let (_big_dir, zone) = big_zone();
    let material = generate_dnscrypt();
    let mut config = common::base_config(zone.path());
    config.dnscrypt_listen = Some("127.0.0.1:0".parse().expect("dnscrypt addr"));
    config.dnscrypt_provider_key = Some(material.provider_key.clone());
    config.dnscrypt_resolver_key = Some(material.resolver_key.clone());
    config.dnscrypt_cert = Some(material.cert.clone());
    let mut server = Server::start(&config).expect("start server");

    let certificate = Certificate::from_hex(&material.certificate_hex).expect("certificate");
    let provider = ProviderPublicKey::from_hex(&material.provider_public_key).expect("provider");
    let client = DnscryptClient::new(certificate, provider, unix_now()).expect("client");
    let query = dns_query("many.big.test.", Rtype::A, 0x3002);
    let response = dnscrypt_exchange(server.dnscrypt_addr().expect("addr"), &client, &query);
    let message = decode(&response);
    assert!(message.flags().tc(), "DNSCrypt UDP must set TC");
    assert_eq!(message.answers(), []);
    server.shutdown().expect("shutdown");
}

#[test]
fn all_three_transports_run_in_parallel_and_export_metrics() {
    let zone = common::TempZone::with_import("parallel", "example.com.", &common::example_zone());
    let material = generate_dnscrypt();
    let cert = TestCert::generate();
    let (_dir, mut config) = tls_config(&zone, &cert);
    config.dnscrypt_listen = Some("127.0.0.1:0".parse().expect("dnscrypt addr"));
    config.dnscrypt_provider_key = Some(material.provider_key.clone());
    config.dnscrypt_resolver_key = Some(material.resolver_key.clone());
    config.dnscrypt_cert = Some(material.cert.clone());
    let api = ApiOptions {
        listen: "127.0.0.1:0".parse().expect("api addr"),
        token: "test-token".to_owned(),
        scopes: Vec::new(),
    };
    let mut server = Server::start_with_api(&config, Some(api)).expect("start server");

    let dot = server.dot_addr().expect("DoT");
    let doh = server.doh_addr().expect("DoH");
    let dnscrypt = server.dnscrypt_addr().expect("DNSCrypt");
    let api_addr = server.api_addr().expect("API");

    let query = dns_query("www.example.com.", Rtype::A, 0x4001);

    let mut client = TlsClient::connect(dot, &cert.cert_der, Some(b"dot")).expect("DoT");
    assert_eq!(
        a_records(&decode(&client.dot_request(&query).expect("DoT response"))),
        vec!["192.0.2.20"]
    );

    let mut client = TlsClient::connect(doh, &cert.cert_der, Some(b"http/1.1")).expect("DoH");
    let response = client
        .http_request(&post_dns("/dns-query", &query))
        .expect("DoH response");
    assert_eq!(a_records(&decode(&response.body)), vec!["192.0.2.20"]);

    let certificate = Certificate::from_hex(&material.certificate_hex).expect("certificate");
    let provider = ProviderPublicKey::from_hex(&material.provider_public_key).expect("provider");
    let dnscrypt_client =
        DnscryptClient::new(certificate, provider, unix_now()).expect("DNSCrypt client");
    let response = dnscrypt_exchange(dnscrypt, &dnscrypt_client, &query);
    assert_eq!(a_records(&decode(&response)), vec!["192.0.2.20"]);

    let metrics = http_plain(api_addr, "/metrics", Some("test-token"));
    assert_eq!(metric(&metrics, "dot_queries_total"), 1, "{metrics}");
    assert_eq!(metric(&metrics, "doh_queries_total"), 1, "{metrics}");
    // DNSCrypt UDP может быть повторён при таймауте, поэтому проверяем не
    // «ровно один», а что каждый принятый запрос получил ответ.
    let dnscrypt_queries = metric(&metrics, "dnscrypt_queries_total");
    assert!(
        dnscrypt_queries >= 1,
        "DNSCrypt must serve at least one query:\n{metrics}"
    );
    assert_eq!(
        metric(&metrics, "dnscrypt_responses_total"),
        dnscrypt_queries,
        "every DNSCrypt query must be answered:\n{metrics}"
    );
    assert_eq!(metric(&metrics, "dot_handshakes_total"), 1, "{metrics}");
    assert!(metrics.contains("doh_http_requests_total"), "{metrics}");

    server.shutdown().expect("shutdown");
    assert_port_closed(dot);
    assert_port_closed(doh);
    assert_port_closed(api_addr);
    assert_udp_silent(dnscrypt);
}

#[test]
fn tls_certificate_reload_affects_new_connections() {
    let zone = common::TempZone::with_import("reload", "example.com.", &common::example_zone());
    let first = TestCert::generate();
    let (_dir, config) = tls_config(&zone, &first);
    let cert_path = config.tls_cert.clone().expect("cert path");
    let key_path = config.tls_key.clone().expect("key path");
    let mut server = Server::start(&config).expect("start server");
    let dot = server.dot_addr().expect("DoT");

    let query = dns_query("www.example.com.", Rtype::A, 0x5001);
    let mut client = TlsClient::connect(dot, &first.cert_der, Some(b"dot")).expect("first client");
    assert!(client.dot_request(&query).is_ok());

    let second = TestCert::generate();
    write_public(&cert_path, &second.cert_pem);
    write_private(&key_path, &second.key_pem);
    server.reload_tls().expect("reload TLS");

    let mut client =
        TlsClient::connect(dot, &second.cert_der, Some(b"dot")).expect("second client");
    assert!(client.dot_request(&query).is_ok());
    assert!(
        TlsClient::connect(dot, &first.cert_der, Some(b"dot")).is_err(),
        "the old certificate must no longer be accepted"
    );

    server.shutdown().expect("shutdown");
}

#[test]
fn dnscrypt_gencert_sets_permissions_and_hides_secrets() {
    let dir = tempfile::Builder::new()
        .prefix("pulsed-gencert-")
        .tempdir()
        .expect("temp dir");
    let out = dir.path().join("keys");
    let output = Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .args([
            "dnscrypt-gencert",
            "--out",
            out.to_str().expect("utf-8 path"),
            "--provider-name",
            "2.dnscrypt-cert.example.com.",
            "--serial",
            "7",
            "--validity-days",
            "10",
        ])
        .output()
        .expect("run dnscrypt-gencert");
    assert!(
        output.status.success(),
        "gencert failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(printed.contains("2.dnscrypt-cert.example.com."));
    assert!(printed.contains("TXT"));

    let provider_key =
        std::fs::read_to_string(out.join("dnscrypt-provider.key")).expect("provider key file");
    let resolver_key =
        std::fs::read_to_string(out.join("dnscrypt-resolver.key")).expect("resolver key file");
    assert!(
        !printed.contains(provider_key.trim()),
        "provider seed leaked"
    );
    assert!(
        !printed.contains(resolver_key.trim()),
        "resolver secret leaked"
    );

    assert_mode(&out, 0o700);
    for name in [
        "dnscrypt-provider.key",
        "dnscrypt-resolver.key",
        "dnscrypt-cert.json",
    ] {
        assert_mode(&out.join(name), 0o600);
    }

    let cert_json = std::fs::read_to_string(out.join("dnscrypt-cert.json")).expect("cert json");
    let value: serde_json::Value = serde_json::from_str(&cert_json).expect("parse cert json");
    assert_eq!(value["serial"], 7);
    let certificate =
        Certificate::from_hex(value["certificate"].as_str().expect("certificate hex"))
            .expect("parse certificate");
    let provider =
        ProviderPublicKey::from_hex(value["provider_public_key"].as_str().expect("provider key"))
            .expect("parse provider");
    certificate.verify(&provider).expect("signature");
    assert!(certificate.ts_end() > certificate.ts_start());
    assert!(certificate.ts_end() - certificate.ts_start() >= 9 * 86_400);

    let txt = std::fs::read_to_string(out.join("dnscrypt-cert.txt")).expect("txt file");
    assert!(txt.contains("2.dnscrypt-cert.example.com. 3600 IN TXT"));
    assert!(txt.contains("2.pubkey.2.dnscrypt-cert.example.com."));

    let again = Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .args([
            "dnscrypt-gencert",
            "--out",
            out.to_str().expect("utf-8 path"),
            "--provider-name",
            "2.dnscrypt-cert.example.com.",
        ])
        .output()
        .expect("run dnscrypt-gencert again");
    assert!(
        !again.status.success(),
        "gencert must not overwrite secrets without --force"
    );
}

struct DnscryptMaterial {
    _dir: tempfile::TempDir,
    provider_key: PathBuf,
    resolver_key: PathBuf,
    cert: PathBuf,
    certificate_hex: String,
    provider_public_key: String,
    provider_name: String,
}

fn generate_dnscrypt() -> DnscryptMaterial {
    let dir = tempfile::Builder::new()
        .prefix("pulsed-dnscrypt-")
        .tempdir()
        .expect("temp dir");
    let out = dir.path().join("keys");
    let output = Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .args([
            "dnscrypt-gencert",
            "--out",
            out.to_str().expect("utf-8 path"),
            "--provider-name",
            "2.dnscrypt-cert.example.com.",
        ])
        .output()
        .expect("run dnscrypt-gencert");
    assert!(
        output.status.success(),
        "gencert failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cert_json = std::fs::read_to_string(out.join("dnscrypt-cert.json")).expect("cert json");
    let value: serde_json::Value = serde_json::from_str(&cert_json).expect("parse cert json");
    let provider_key = out.join("dnscrypt-provider.key");
    let resolver_key = out.join("dnscrypt-resolver.key");
    let cert = out.join("dnscrypt-cert.json");
    DnscryptMaterial {
        _dir: dir,
        provider_key,
        resolver_key,
        cert,
        certificate_hex: value["certificate"]
            .as_str()
            .expect("certificate hex")
            .to_owned(),
        provider_public_key: value["provider_public_key"]
            .as_str()
            .expect("provider key")
            .to_owned(),
        provider_name: "2.dnscrypt-cert.example.com.".to_owned(),
    }
}

fn big_zone() -> (tempfile::TempDir, common::TempZone) {
    let mut text = String::from(
        "$ORIGIN big.test.\n$TTL 3600\n@ IN SOA ns1.big.test. hostmaster.big.test. 1 3600 600 604800 300\n@ IN NS ns1.big.test.\nns1 IN A 192.0.2.1\n",
    );
    for index in 0..40 {
        writeln!(text, "many IN A 10.0.0.{}", index + 1).expect("format zone");
    }
    let (dir, path) = common::write_text("big", "big.test.zone", &text);
    let zone = common::TempZone::empty("big");
    common::import(zone.path(), "big.test.", &path);
    (dir, zone)
}

/// Сколько раз повторять `DNSCrypt` UDP-запрос перед паникой.
const DNSCRYPT_UDP_ATTEMPTS: u32 = 5;

fn dnscrypt_exchange(addr: SocketAddr, client: &DnscryptClient, query: &[u8]) -> Vec<u8> {
    // UDP не гарантирует доставку, а под полной нагрузкой workspace-тестов
    // worker сервера может не успеть обработать датаграмму за таймаут сокета.
    // Каждая попытка — новый запрос: сервер включает anti-replay по паре
    // `(client-pk, client-nonce)` и молча отбрасывает повторный nonce.
    let exchanged = common::retry(
        "dnscrypt udp exchange",
        DNSCRYPT_UDP_ATTEMPTS,
        Duration::from_millis(100),
        |_attempt| -> Result<Vec<u8>, String> {
            let pending = client
                .build_query(query, DnscryptTransport::Udp)
                .map_err(|error| format!("build query: {error}"))?;
            let socket = UdpSocket::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
            socket
                .set_read_timeout(Some(common::SOCKET_TIMEOUT))
                .map_err(|error| error.to_string())?;
            socket
                .set_write_timeout(Some(common::SOCKET_TIMEOUT))
                .map_err(|error| error.to_string())?;
            common::udp_send_to(&socket, pending.packet(), addr)
                .map_err(|error| format!("send to {addr}: {error}"))?;
            let mut buffer = [0_u8; 4096];
            let (length, _) = common::udp_recv_from(&socket, &mut buffer)
                .map_err(|error| format!("recv from {addr}: {error}"))?;
            let bytes = buffer
                .get(..length)
                .ok_or_else(|| format!("response length {length} out of range"))?;
            client
                .decrypt_response(&pending, bytes)
                .map_err(|error| format!("decrypt from {addr}: {error}"))
        },
    );
    exchanged.unwrap_or_else(|error| {
        panic!("DNSCrypt UDP exchange with {addr} failed: {error}");
    })
}

fn http_plain(addr: SocketAddr, path: &str, token: Option<&str>) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect API");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let auth = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n"
    )
    .expect("write request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

fn assert_mode(path: &Path, expected: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, expected, "unexpected mode for {}", path.display());
    }
    #[cfg(not(unix))]
    {
        let _ = (path, expected);
    }
}

fn assert_port_closed(addr: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
            Ok(_) if Instant::now() >= deadline => {
                panic!("port {addr} still accepts connections after shutdown");
            }
            Ok(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn assert_udp_silent(addr: SocketAddr) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("udp client");
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("read timeout");
    common::udp_send_to(&socket, b"\x00\x01", addr).expect("send probe");
    let mut buffer = [0_u8; 64];
    match common::udp_recv_from(&socket, &mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) => {}
        Err(error) => panic!("unexpected read error on {addr}: {error}"),
        Ok((length, _)) => {
            panic!("UDP listener {addr} still responds after shutdown ({length} bytes)");
        }
    }
}

/// Значение счётчика из текстового вывода `/metrics`.
fn metric(metrics: &str, name: &str) -> u64 {
    metrics
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next() == Some(name) {
                parts.next()?.parse().ok()
            } else {
                None
            }
        })
        .unwrap_or_else(|| panic!("metric {name} not found in:\n{metrics}"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_secs()
}

#[test]
fn dnscrypt_tcp_answers_multiple_queries_on_one_connection() {
    let zone =
        common::TempZone::with_import("dnscrypt-tcp", "example.com.", &common::example_zone());
    let material = generate_dnscrypt();
    let mut config = common::base_config(zone.path());
    config.dnscrypt_tcp_listen = Some("127.0.0.1:0".parse().expect("dnscrypt tcp addr"));
    config.dnscrypt_provider_key = Some(material.provider_key.clone());
    config.dnscrypt_resolver_key = Some(material.resolver_key.clone());
    config.dnscrypt_cert = Some(material.cert.clone());
    let mut server = Server::start(&config).expect("start server");
    let addr = server.dnscrypt_tcp_addr().expect("DNSCrypt TCP address");

    let certificate = Certificate::from_hex(&material.certificate_hex).expect("certificate");
    let provider = ProviderPublicKey::from_hex(&material.provider_public_key).expect("provider");
    let now = unix_now();
    let client = DnscryptClient::new(certificate.clone(), provider, now).expect("client");

    let mut stream = TcpStream::connect(addr).expect("connect DNSCrypt TCP");
    stream
        .set_read_timeout(Some(common::SOCKET_TIMEOUT))
        .expect("read timeout");

    for (id, name, expected) in [
        (0x7001_u16, "www.example.com.", "192.0.2.20"),
        (0x7002, "ns1.example.com.", "192.0.2.53"),
    ] {
        let query = dns_query(name, Rtype::A, id);
        let pending = client
            .build_query(&query, DnscryptTransport::Tcp)
            .expect("build DNSCrypt TCP query");
        stream
            .write_all(pending.packet())
            .expect("write DNSCrypt TCP query");
        let frame = read_tcp_frame(&mut stream);
        let response = client
            .decrypt_response(&pending, &frame)
            .expect("decrypt DNSCrypt TCP response");
        let message = decode(&response);
        assert_eq!(message.id(), id);
        assert_eq!(a_records(&message), vec![expected]);
    }

    let wrong = pulse_dnscrypt::ProviderKeypair::generate()
        .expect("provider")
        .public_key();
    assert!(
        DnscryptClient::new(certificate, wrong, now).is_err(),
        "a different provider key must be rejected for TCP too"
    );

    drop(stream);
    server.shutdown().expect("shutdown");
    assert_port_closed(addr);
}

#[test]
fn dnscrypt_tcp_large_answer_is_not_truncated() {
    let (_big_dir, zone) = big_zone();
    let material = generate_dnscrypt();
    let mut config = common::base_config(zone.path());
    config.listen_udp = None;
    config.dnscrypt_tcp_listen = Some("127.0.0.1:0".parse().expect("dnscrypt tcp addr"));
    config.dnscrypt_provider_key = Some(material.provider_key.clone());
    config.dnscrypt_resolver_key = Some(material.resolver_key.clone());
    config.dnscrypt_cert = Some(material.cert.clone());
    let mut server = Server::start(&config).expect("start server");

    let certificate = Certificate::from_hex(&material.certificate_hex).expect("certificate");
    let provider = ProviderPublicKey::from_hex(&material.provider_public_key).expect("provider");
    let client = DnscryptClient::new(certificate, provider, unix_now()).expect("client");
    let query = dns_query("many.big.test.", Rtype::A, 0x7003);

    let mut stream = TcpStream::connect(server.dnscrypt_tcp_addr().expect("addr"))
        .expect("connect DNSCrypt TCP");
    stream
        .set_read_timeout(Some(common::SOCKET_TIMEOUT))
        .expect("read timeout");
    let pending = client
        .build_query(&query, DnscryptTransport::Tcp)
        .expect("build DNSCrypt TCP query");
    stream.write_all(pending.packet()).expect("write query");
    let frame = read_tcp_frame(&mut stream);
    let response = client
        .decrypt_response(&pending, &frame)
        .expect("decrypt response");
    let message = decode(&response);
    assert!(!message.flags().tc(), "DNSCrypt TCP must not set TC");
    assert_eq!(message.answers().len(), 40);

    drop(stream);
    server.shutdown().expect("shutdown");
}

#[test]
fn dnscrypt_tcp_idle_timeout_and_metrics() {
    let zone =
        common::TempZone::with_import("dnscrypt-tcp-m", "example.com.", &common::example_zone());
    let material = generate_dnscrypt();
    let mut config = common::base_config(zone.path());
    config.dnscrypt_tcp_listen = Some("127.0.0.1:0".parse().expect("dnscrypt tcp addr"));
    config.dnscrypt_tcp_idle_timeout_ms = 200;
    config.dnscrypt_provider_key = Some(material.provider_key.clone());
    config.dnscrypt_resolver_key = Some(material.resolver_key.clone());
    config.dnscrypt_cert = Some(material.cert.clone());
    let api = ApiOptions {
        listen: "127.0.0.1:0".parse().expect("api addr"),
        token: "test-token".to_owned(),
        scopes: Vec::new(),
    };
    let mut server = Server::start_with_api(&config, Some(api)).expect("start server");
    let addr = server.dnscrypt_tcp_addr().expect("DNSCrypt TCP");
    let api_addr = server.api_addr().expect("API");

    let certificate = Certificate::from_hex(&material.certificate_hex).expect("certificate");
    let provider = ProviderPublicKey::from_hex(&material.provider_public_key).expect("provider");
    let client = DnscryptClient::new(certificate, provider, unix_now()).expect("client");
    let query = dns_query("www.example.com.", Rtype::A, 0x7004);
    let pending = client
        .build_query(&query, DnscryptTransport::Tcp)
        .expect("build query");

    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(common::SOCKET_TIMEOUT))
        .expect("read timeout");
    stream.write_all(pending.packet()).expect("write");
    let frame = read_tcp_frame(&mut stream);
    let response = client.decrypt_response(&pending, &frame).expect("decrypt");
    assert_eq!(a_records(&decode(&response)), vec!["192.0.2.20"]);

    let metrics = http_plain(api_addr, "/metrics", Some("test-token"));
    assert!(
        metrics.contains("dnscrypt_tcp_connections_total 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("dnscrypt_tcp_queries_total 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("dnscrypt_tcp_responses_total 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("dnscrypt_tcp_active_connections 1"),
        "{metrics}"
    );

    // Idle timeout закрывает соединение без нового запроса.
    let mut probe = [0_u8; 1];
    let read = stream.read(&mut probe).expect("read after idle timeout");
    assert_eq!(read, 0, "idle connection must be closed");

    drop(stream);
    server.shutdown().expect("shutdown");
    assert_port_closed(addr);
}

fn read_tcp_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).expect("read frame prefix");
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).expect("read frame payload");
    let mut frame = Vec::with_capacity(2 + length);
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(&payload);
    frame
}

#[test]
fn dnscrypt_tcp_rejects_mismatched_resolver_key() {
    let zone =
        common::TempZone::with_import("dnscrypt-tcp-bad", "example.com.", &common::example_zone());
    let material = generate_dnscrypt();
    let other = pulse_dnscrypt::ResolverKeypair::generate().expect("resolver");
    write_private(
        &material.resolver_key,
        hex::encode(*other.to_secret_bytes()).as_bytes(),
    );
    let mut config = common::base_config(zone.path());
    config.listen_udp = None;
    config.dnscrypt_tcp_listen = Some("127.0.0.1:0".parse().expect("dnscrypt tcp addr"));
    config.dnscrypt_provider_key = Some(material.provider_key.clone());
    config.dnscrypt_resolver_key = Some(material.resolver_key.clone());
    config.dnscrypt_cert = Some(material.cert.clone());
    assert!(
        Server::start(&config).is_err(),
        "a resolver key that does not match the certificate must be rejected"
    );
}

#[test]
fn dnscrypt_tcp_rejects_frames_above_limit() {
    let zone = common::TempZone::with_import(
        "dnscrypt-tcp-limit",
        "example.com.",
        &common::example_zone(),
    );
    let material = generate_dnscrypt();
    let mut config = common::base_config(zone.path());
    config.listen_udp = None;
    config.dnscrypt_tcp_listen = Some("127.0.0.1:0".parse().expect("dnscrypt tcp addr"));
    config.dnscrypt_tcp_max_frame = 512;
    config.dnscrypt_provider_key = Some(material.provider_key.clone());
    config.dnscrypt_resolver_key = Some(material.resolver_key.clone());
    config.dnscrypt_cert = Some(material.cert.clone());
    let mut server = Server::start(&config).expect("start server");
    let addr = server.dnscrypt_tcp_addr().expect("addr");

    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(common::SOCKET_TIMEOUT))
        .expect("read timeout");
    // Заявленная длина 600 > 512: сервер обязан закрыть соединение.
    let mut frame = vec![0_u8; 602];
    frame[0..2].copy_from_slice(&600_u16.to_be_bytes());
    stream.write_all(&frame).expect("write oversized frame");
    let mut probe = [0_u8; 1];
    match stream.read(&mut probe) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        other => panic!("oversized frame must close the connection, got {other:?}"),
    }

    drop(stream);
    server.shutdown().expect("shutdown");
}
