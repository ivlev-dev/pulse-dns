//! Mock upstream (UDP) и клиенты для интеграционных тестов.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use pulse_dns::{
    DecodeLimits, Edns, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Record,
    Rtype, SoaData, Ttl,
};
use pulseresolved::config::{CacheSetting, Config, ModeSetting, TimeoutSetting};

/// UDP mock-upstream с обработчиком запросов.
pub struct MockUpstream {
    address: SocketAddr,
    hits: Arc<AtomicU64>,
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MockUpstream {
    /// Запускает сервер; обработчик получает запрос и возвращает ответ.
    pub fn start<F>(handler: F) -> Self
    where
        F: Fn(&Message) -> Option<Message> + Send + Sync + 'static,
    {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind mock upstream");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("read timeout");
        let address = socket.local_addr().expect("mock addr");
        let hits = Arc::new(AtomicU64::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));
        let handler = Arc::new(handler);
        let thread_hits = Arc::clone(&hits);
        let thread_shutdown = Arc::clone(&shutdown);
        let thread = thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while !thread_shutdown.load(Ordering::Relaxed) {
                let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                thread_hits.fetch_add(1, Ordering::Relaxed);
                let Some(bytes) = buffer.get(..length) else {
                    continue;
                };
                let Ok(request) = Message::decode(bytes, &DecodeLimits::default()) else {
                    continue;
                };
                if let Some(response) = handler(&request)
                    && let Ok(mut encoded) = response.encode(&EncodeOptions::default())
                {
                    // Настоящий upstream сохраняет регистр QNAME; `Name`
                    // канонизирует его в нижний, поэтому 0x20 восстанавливаем
                    // из исходного запроса.
                    preserve_question_case(&mut encoded, bytes);
                    let _ = socket.send_to(&encoded, peer);
                }
            }
        });
        Self {
            address,
            hits,
            shutdown,
            thread: Some(thread),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Конфигурация с forward-режимом на mock upstream и эфемерными портами.
pub fn base_config(upstream: SocketAddr) -> Config {
    Config {
        listen_udp: Some("127.0.0.1:0".parse().unwrap()),
        listen_tcp: Some("127.0.0.1:0".parse().unwrap()),
        workers: 1,
        mode: ModeSetting::Forward,
        forwarders: vec![upstream],
        timeouts: TimeoutSetting {
            per_query_ms: 500,
            tcp_ms: 700,
            total_ms: 3_000,
        },
        cache: CacheSetting {
            max_entries: 1_024,
            max_bytes: 1 << 20,
            ..CacheSetting::default()
        },
        ..Config::default()
    }
}

/// Запрос A/AAAA/TXT с опциональным EDNS payload.
pub fn make_query(name: &str, rtype: Rtype, edns_payload: Option<u16>) -> Message {
    let question = Question::new(Name::parse(name).expect("valid qname"), rtype, Rclass::IN);
    let mut message = Message::query(0x4242, question);
    if let Some(payload) = edns_payload {
        message.set_edns(Some(Edns::new(payload)));
    }
    message
}

/// UDP-запрос; возвращает декодированный ответ или `None` по таймауту.
pub fn udp_query(server: SocketAddr, request: &Message, timeout: Duration) -> Option<Message> {
    let bytes = request.encode(&EncodeOptions::default()).expect("encode");
    udp_query_raw(server, &bytes, timeout)
}

/// Сырой UDP-запрос.
pub fn udp_query_raw(server: SocketAddr, request: &[u8], timeout: Duration) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    socket
        .set_read_timeout(Some(timeout))
        .expect("client timeout");
    socket.send_to(request, server).expect("send query");
    let mut buffer = [0_u8; 4096];
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match socket.recv_from(&mut buffer) {
            Ok((length, _)) => {
                let bytes = buffer.get(..length)?;
                return Message::decode(bytes, &DecodeLimits::default()).ok();
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return None;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    None
}

/// TCP-запрос с length-prefix framing.
pub fn tcp_query(server: SocketAddr, request: &Message, timeout: Duration) -> Option<Message> {
    let bytes = request.encode(&EncodeOptions::default()).expect("encode");
    let mut stream = TcpStream::connect(server).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let length = u16::try_from(bytes.len()).ok()?;
    stream.write_all(&length.to_be_bytes()).ok()?;
    stream.write_all(&bytes).ok()?;
    stream.flush().ok()?;
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).ok()?;
    let mut response = vec![0_u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut response).ok()?;
    Message::decode(&response, &DecodeLimits::default()).ok()
}

fn preserve_question_case(response: &mut [u8], request: &[u8]) {
    let Some((request_start, request_end)) = question_range(request) else {
        return;
    };
    let Some((response_start, response_end)) = question_range(response) else {
        return;
    };
    let Some(source) = request.get(request_start..request_end) else {
        return;
    };
    let Some(target) = response.get_mut(response_start..response_end) else {
        return;
    };
    if source.len() == target.len() {
        target.copy_from_slice(source);
    }
}

fn question_range(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut position = 12_usize;
    loop {
        let length = *bytes.get(position)?;
        if length == 0 {
            return Some((12, position.checked_add(1)?));
        }
        if length > 63 {
            return None;
        }
        position = position.checked_add(1 + usize::from(length))?;
        if position >= bytes.len() {
            return None;
        }
    }
}

/// A-ответ с TTL.
pub fn a_record(name: &str, address: [u8; 4], ttl: u32) -> Record {
    Record::new(
        Name::parse(name).expect("owner"),
        Rtype::A,
        Rclass::IN,
        Ttl::new(ttl).expect("ttl"),
        Rdata::A(address.into()),
    )
    .expect("A record")
}

/// Простой положительный ответ на единственный вопрос.
pub fn positive_response(request: &Message, record: Record) -> Message {
    let mut response = Message::response(request);
    response.set_rcode(Rcode::NOERROR);
    response.add_answer(record);
    response
}

/// NXDOMAIN с SOA в authority (RFC 2308 negative caching).
pub fn nxdomain_response(request: &Message, zone: &str) -> Message {
    let owner = Name::parse(zone).expect("zone");
    let soa = Record::new(
        owner,
        Rtype::SOA,
        Rclass::IN,
        Ttl::new(300).expect("ttl"),
        Rdata::Soa(SoaData::new(
            Name::parse("ns1.example.test").expect("mname"),
            Name::parse("hostmaster.example.test").expect("rname"),
            pulse_dns::Serial::new(1),
            3600,
            600,
            86_400,
            60,
        )),
    )
    .expect("SOA");
    let mut response = Message::response(request);
    response.set_rcode(Rcode::NXDOMAIN);
    response.add_authority(soa);
    response
}
