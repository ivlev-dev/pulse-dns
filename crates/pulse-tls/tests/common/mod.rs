//! Общие помощники интеграционных тестов: self-signed cert, TLS-клиент,
//! DNS-пакеты и HTTP/1.1-разбор.

#![allow(dead_code)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use pulse_dns::domain::{Message, Name, Question, Rclass, Rdata, Record, Rtype, Ttl};
use pulse_dns::wire::{DecodeLimits, EncodeOptions};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

pub struct TestCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: Vec<u8>,
}

pub fn test_cert() -> TestCert {
    let key = KeyPair::generate().expect("generate key pair");
    let params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
        .expect("certificate params");
    let certificate = params.self_signed(&key).expect("self-signed certificate");
    TestCert {
        cert_pem: certificate.pem(),
        key_pem: key.serialize_pem(),
        cert_der: certificate.der().to_vec(),
    }
}

pub fn tls_client_config(cert_der: &[u8], alpn: Option<&[u8]>) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(cert_der.to_vec()))
        .expect("add root certificate");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.to_vec()];
    }
    config
}

/// Минимальный TLS-клиент на std TCP + rustls.
pub struct TlsClient {
    connection: ClientConnection,
    socket: TcpStream,
    buffer: Vec<u8>,
}

impl TlsClient {
    pub fn connect(addr: SocketAddr, cert_der: &[u8], alpn: Option<&[u8]>) -> io::Result<Self> {
        let config = tls_client_config(cert_der, alpn);
        let server_name = ServerName::try_from("localhost".to_owned())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid server name"))?;
        let mut connection = ClientConnection::new(Arc::new(config), server_name)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut socket = TcpStream::connect(addr)?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        socket.set_nodelay(true)?;
        while connection.is_handshaking() {
            connection.complete_io(&mut socket)?;
        }
        Ok(Self {
            connection,
            socket,
            buffer: Vec::new(),
        })
    }

    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.connection.alpn_protocol()
    }

    pub fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.connection
            .writer()
            .write_all(data)
            .map_err(io::Error::other)?;
        while self.connection.wants_write() {
            self.connection.write_tls(&mut self.socket)?;
        }
        Ok(())
    }

    pub fn read_exact(&mut self, length: usize) -> io::Result<Vec<u8>> {
        let mut output = vec![0_u8; length];
        let mut offset = 0;
        while offset < length {
            let slice = output
                .get_mut(offset..)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "offset"))?;
            let read = self.read(slice)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS connection closed",
                ));
            }
            offset += read;
        }
        Ok(output)
    }

    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.connection.reader().read(buffer) {
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
            let read = self.connection.read_tls(&mut self.socket)?;
            if read == 0 {
                return Ok(0);
            }
            self.connection
                .process_new_packets()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        }
    }

    pub fn send_dot(&mut self, message: &[u8]) -> io::Result<()> {
        let length = u16::try_from(message.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too large"))?;
        self.send(&length.to_be_bytes())?;
        self.send(message)
    }

    pub fn read_dot(&mut self) -> io::Result<Vec<u8>> {
        let prefix = self.read_exact(2)?;
        let length = u16::from_be_bytes([prefix[0], prefix[1]]);
        self.read_exact(usize::from(length))
    }

    pub fn request(&mut self, raw: &[u8]) -> io::Result<TestHttpResponse> {
        self.send(raw)?;
        self.read_http()
    }

    pub fn read_http(&mut self) -> io::Result<TestHttpResponse> {
        let head_end = loop {
            if let Some(position) = find_head_end(&self.buffer) {
                break position;
            }
            self.fill()?;
        };
        let head = self
            .buffer
            .get(..head_end)
            .ok_or_else(|| io::Error::other("head bounds"))?
            .to_vec();
        self.buffer.drain(..head_end);
        let head = String::from_utf8_lossy(&head).into_owned();
        let mut lines = head.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "status line"))?;
        let status = status_line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "status code"))?
            .parse::<u16>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "status code"))?;
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
            .ok_or_else(|| io::Error::other("body bounds"))?
            .to_vec();
        self.buffer.drain(..length);
        Ok(TestHttpResponse {
            status,
            headers,
            body,
        })
    }

    fn fill(&mut self) -> io::Result<()> {
        let mut chunk = [0_u8; 4096];
        let read = self.read(&mut chunk)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP connection closed",
            ));
        }
        let data = chunk
            .get(..read)
            .ok_or_else(|| io::Error::other("read bounds"))?;
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

#[derive(Debug)]
pub struct TestHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl TestHttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub fn dns_query(id: u16) -> Vec<u8> {
    let name = Name::parse("example.com").expect("name");
    let question = Question::new(name, Rtype::A, Rclass::IN);
    Message::query(id, question)
        .encode(&EncodeOptions::default())
        .expect("encode query")
}

pub fn dns_response(id: u16, ttl: u32) -> Vec<u8> {
    let name = Name::parse("example.com").expect("name");
    let question = Question::new(name.clone(), Rtype::A, Rclass::IN);
    let query = Message::query(id, question);
    let mut response = Message::response(&query);
    response.add_answer(
        Record::new(
            name,
            Rtype::A,
            Rclass::IN,
            Ttl::new(ttl).expect("ttl"),
            Rdata::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
        )
        .expect("record"),
    );
    response
        .encode(&EncodeOptions::default())
        .expect("encode response")
}

#[allow(clippy::unnecessary_wraps)]
pub fn echo_handler(query: &[u8], _peer: SocketAddr) -> Option<Vec<u8>> {
    Some(query.to_vec())
}

pub fn decode_query(bytes: &[u8]) -> Message {
    Message::decode(bytes, &DecodeLimits::default()).expect("decode DNS message")
}
