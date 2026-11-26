//! Минимальный mock upstream: UDP+TCP на одном порту и raw-обработчик.

#![allow(dead_code, clippy::needless_pass_by_value)]

pub mod https_source;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use pulse_dns::{DecodeLimits, Message, Name, Rclass, Rcode, Rdata, Record, Rtype, SoaData, Ttl};

/// Обработчик: получает запрос и признак TCP, возвращает сырые байты ответа.
pub type RawHandler = Arc<dyn Fn(&Message, bool) -> Option<Vec<u8>> + Send + Sync>;

/// Mock-сервер с UDP и TCP на одном порту.
pub struct MockServer {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl MockServer {
    /// Запускает сервер.
    pub fn spawn(handler: RawHandler) -> Self {
        let (listener, address) = bind_pair();
        let shutdown = Arc::new(AtomicBool::new(false));

        let udp_socket = UdpSocket::bind(address).expect("bind udp mock");
        udp_socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("udp timeout");
        let udp_handler = Arc::clone(&handler);
        let udp_shutdown = Arc::clone(&shutdown);
        let udp_thread = thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while !udp_shutdown.load(Ordering::Relaxed) {
                let Ok((length, peer)) = udp_socket.recv_from(&mut buffer) else {
                    continue;
                };
                let Some(bytes) = buffer.get(..length) else {
                    continue;
                };
                let Ok(request) = Message::decode(bytes, &DecodeLimits::default()) else {
                    continue;
                };
                if let Some(response) = udp_handler(&request, false) {
                    let _ = udp_socket.send_to(&response, peer);
                }
            }
        });

        let tcp_handler = Arc::clone(&handler);
        let tcp_shutdown = Arc::clone(&shutdown);
        listener.set_nonblocking(true).expect("tcp nonblocking");
        let tcp_thread = thread::spawn(move || {
            while !tcp_shutdown.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        serve_tcp(stream, &tcp_handler);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            address,
            shutdown,
            threads: vec![udp_thread, tcp_thread],
        }
    }

    /// Адрес сервера.
    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

fn bind_pair() -> (TcpListener, SocketAddr) {
    for _ in 0..32 {
        let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
            continue;
        };
        let Ok(address) = listener.local_addr() else {
            continue;
        };
        if UdpSocket::bind(address).is_ok() {
            return (listener, address);
        }
    }
    panic!("cannot bind mock server");
}

fn serve_tcp(mut stream: TcpStream, handler: &RawHandler) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let mut length_bytes = [0_u8; 2];
    if stream.read_exact(&mut length_bytes).is_err() {
        return;
    }
    let length = usize::from(u16::from_be_bytes(length_bytes));
    let mut bytes = vec![0_u8; length];
    if stream.read_exact(&mut bytes).is_err() {
        return;
    }
    let Ok(request) = Message::decode(&bytes, &DecodeLimits::default()) else {
        return;
    };
    let Some(response) = handler(&request, true) else {
        return;
    };
    let Ok(size) = u16::try_from(response.len()) else {
        return;
    };
    let mut framed = Vec::with_capacity(response.len() + 2);
    framed.extend_from_slice(&size.to_be_bytes());
    framed.extend_from_slice(&response);
    let _ = stream.write_all(&framed);
    let _ = stream.flush();
}

/// Строит базовый ответ на запрос.
pub fn response(request: &Message, rcode: Rcode) -> Message {
    let mut message = Message::response(request);
    message.set_rcode(rcode);
    let flags = message.flags().with_ra(true).with_qr(true);
    message.set_flags(flags);
    message
}

/// Кодирует сообщение.
pub fn encode(message: &Message) -> Vec<u8> {
    message
        .encode(&pulse_dns::EncodeOptions::default())
        .expect("encode mock response")
}

/// Делает QNAME в сыром ответе заглавными (ломает 0x20-эхо).
pub fn uppercase_question(mut bytes: Vec<u8>) -> Vec<u8> {
    let Some((start, end)) = question_range(&bytes) else {
        return bytes;
    };
    for byte in bytes.iter_mut().take(end).skip(start) {
        if byte.is_ascii_lowercase() {
            *byte = byte.to_ascii_uppercase();
        }
    }
    bytes
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

/// `A`-запись.
pub fn a(owner: &str, ttl: u32, address: [u8; 4]) -> Record {
    Record::new(
        parse_name(owner),
        Rtype::A,
        Rclass::IN,
        Ttl::new(ttl).expect("ttl"),
        Rdata::A(std::net::Ipv4Addr::from(address)),
    )
    .expect("A record")
}

/// `AAAA`-запись.
pub fn aaaa(owner: &str, ttl: u32, address: std::net::Ipv6Addr) -> Record {
    Record::new(
        parse_name(owner),
        Rtype::AAAA,
        Rclass::IN,
        Ttl::new(ttl).expect("ttl"),
        Rdata::Aaaa(address),
    )
    .expect("AAAA record")
}

/// `CNAME`-запись.
pub fn cname(owner: &str, ttl: u32, target: &str) -> Record {
    Record::new(
        parse_name(owner),
        Rtype::CNAME,
        Rclass::IN,
        Ttl::new(ttl).expect("ttl"),
        Rdata::Cname(parse_name(target)),
    )
    .expect("CNAME record")
}

/// `NS`-запись.
pub fn ns(owner: &str, ttl: u32, target: &str) -> Record {
    Record::new(
        parse_name(owner),
        Rtype::NS,
        Rclass::IN,
        Ttl::new(ttl).expect("ttl"),
        Rdata::Ns(parse_name(target)),
    )
    .expect("NS record")
}

/// `SOA`-запись.
pub fn soa(zone: &str, ttl: u32, minimum: u32) -> Record {
    Record::new(
        parse_name(zone),
        Rtype::SOA,
        Rclass::IN,
        Ttl::new(ttl).expect("ttl"),
        Rdata::Soa(SoaData::new(
            parse_name("ns1.example.com"),
            parse_name("hostmaster.example.com"),
            pulse_dns::Serial::new(1),
            3600,
            600,
            86_400,
            minimum,
        )),
    )
    .expect("SOA record")
}

/// Парсит имя.
pub fn parse_name(value: &str) -> Name {
    Name::parse(value).expect("valid name")
}

/// Счётчик вызовов обработчика.
#[derive(Debug, Default)]
pub struct HitCounter {
    hits: std::sync::atomic::AtomicUsize,
}

impl HitCounter {
    /// Новый счётчик.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Увеличивает счётчик.
    pub fn hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Текущее значение.
    pub fn count(&self) -> usize {
        self.hits.load(Ordering::Relaxed)
    }
}
