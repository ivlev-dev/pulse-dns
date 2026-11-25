//! Интеграционные тесты транспортов на реальных сокетах.

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use pulse_dns::{
    DecodeLimits, Edns, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Rtype,
};
use pulsed::config::Config;
use pulsed::server::Server;

fn test_config() -> (common::TempZone, Config) {
    let zone = common::TempZone::with_import("transport", "example.com.", &common::example_zone());
    let config = common::base_config(zone.path());
    (zone, config)
}

fn name(text: &str) -> Name {
    Name::parse(text).expect("valid name")
}

fn query(text: &str, rr_type: Rtype) -> Message {
    Message::query(0x4242, Question::new(name(text), rr_type, Rclass::IN))
}

fn udp_exchange(server: &Server, message: &Message) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    let bytes = message
        .encode(&EncodeOptions::compressed())
        .expect("encode query");
    socket
        .send_to(&bytes, server.udp_addr().expect("udp enabled"))
        .expect("send query");
    let mut buffer = [0_u8; 4096];
    let (length, _) = recv_from(&socket, &mut buffer).expect("recv response");
    Message::decode(&buffer[..length], &DecodeLimits::default()).expect("decode response")
}

fn recv_from(socket: &UdpSocket, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn write_frame(stream: &mut TcpStream, message: &Message) {
    let bytes = message
        .encode(&EncodeOptions::compressed())
        .expect("encode query");
    let length = u16::try_from(bytes.len()).expect("query fits frame");
    stream.write_all(&length.to_be_bytes()).expect("prefix");
    stream.write_all(&bytes).expect("body");
}

fn read_frame(stream: &mut TcpStream) -> Message {
    let mut prefix = [0_u8; 2];
    stream.read_exact(&mut prefix).expect("frame prefix");
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body).expect("frame body");
    Message::decode(&body, &DecodeLimits::default()).expect("decode response")
}

#[test]
fn udp_serves_a_and_nxdomain() {
    let (_zone, config) = test_config();
    let mut server = Server::start(&config).expect("start server");
    assert!(server.udp_addr().is_some());

    let response = udp_exchange(&server, &query("www.example.com.", Rtype::A));
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(response.flags().aa());
    assert_eq!(response.answers().len(), 1);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.20".parse().expect("ipv4"))
    );

    let response = udp_exchange(&server, &query("alias.example.com.", Rtype::A));
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 2);
    assert_eq!(response.answers()[0].rr_type(), Rtype::CNAME);

    let response = udp_exchange(&server, &query("host.wild.example.com.", Rtype::A));
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(
        response.answers()[0].rdata(),
        &Rdata::A("192.0.2.99".parse().expect("ipv4"))
    );

    let response = udp_exchange(&server, &query("missing.example.com.", Rtype::A));
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);
    assert!(response.flags().aa());
    assert_eq!(response.answers().len(), 0);
    assert!(
        response
            .authority()
            .iter()
            .any(|record| record.rr_type() == Rtype::SOA)
    );

    server.shutdown().expect("shutdown");
}

#[test]
fn udp_edns_is_echoed_and_badvers_is_reported() {
    let (_zone, config) = test_config();
    let mut server = Server::start(&config).expect("start server");

    let mut message = query("www.example.com.", Rtype::A);
    message.set_edns(Some(Edns::new(1232)));
    let response = udp_exchange(&server, &message);
    let edns = response.edns().expect("OPT in response");
    assert_eq!(edns.udp_payload_size(), 1232);
    assert_eq!(edns.version(), 0);

    let mut message = query("www.example.com.", Rtype::A);
    message.set_edns(Some(Edns::new(1232).with_version(1)));
    let response = udp_exchange(&server, &message);
    assert_eq!(response.rcode(), Rcode::BADVERS);

    server.shutdown().expect("shutdown");
}

#[test]
fn udp_malformed_query_gets_formerr_and_short_packet_is_dropped() {
    let (_zone, config) = test_config();
    let mut server = Server::start(&config).expect("start server");
    let address = server.udp_addr().expect("udp enabled");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");

    let mut malformed = vec![0_u8; 12];
    malformed[0] = 0xbe;
    malformed[1] = 0xef;
    malformed[5] = 1; // QDCOUNT = 1, but the question is missing.
    socket.send_to(&malformed, address).expect("send malformed");
    let mut buffer = [0_u8; 512];
    let (length, _) = recv_from(&socket, &mut buffer).expect("recv formerr");
    let response = Message::decode(&buffer[..length], &DecodeLimits::default()).expect("formerr");
    assert_eq!(response.id(), 0xbeef);
    assert_eq!(response.rcode(), Rcode::FORMERR);

    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("short timeout");
    socket.send_to(&[0x01; 5], address).expect("send short");
    let error = recv_from(&socket, &mut buffer).expect_err("short packet must be ignored");
    assert!(matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));

    server.shutdown().expect("shutdown");
}

#[test]
fn tcp_handles_length_prefixed_stream_and_multiple_messages() {
    let (_zone, config) = test_config();
    let mut server = Server::start(&config).expect("start server");
    let address = server.tcp_addr().expect("tcp enabled");
    let mut stream = TcpStream::connect(address).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");

    write_frame(&mut stream, &query("www.example.com.", Rtype::A));
    let response = read_frame(&mut stream);
    assert_eq!(response.id(), 0x4242);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert_eq!(response.answers().len(), 1);

    // Malformed frame: FORMERR under the same ID, connection stays usable.
    let mut malformed = vec![0_u8; 12];
    malformed[0] = 0x12;
    malformed[1] = 0x34;
    malformed[5] = 1;
    let length = u16::try_from(malformed.len()).expect("fits");
    stream.write_all(&length.to_be_bytes()).expect("prefix");
    stream.write_all(&malformed).expect("body");
    let response = read_frame(&mut stream);
    assert_eq!(response.id(), 0x1234);
    assert_eq!(response.rcode(), Rcode::FORMERR);

    write_frame(&mut stream, &query("missing.example.com.", Rtype::A));
    let response = read_frame(&mut stream);
    assert_eq!(response.rcode(), Rcode::NXDOMAIN);

    // Graceful shutdown must close an idle connection promptly.
    let started = Instant::now();
    server.shutdown().expect("shutdown");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "graceful shutdown took {:?}",
        started.elapsed()
    );
}

#[test]
fn shutdown_releases_listeners() {
    let (_zone, config) = test_config();
    let mut server = Server::start(&config).expect("start server");
    let udp = server.udp_addr().expect("udp enabled");
    let tcp = server.tcp_addr().expect("tcp enabled");
    let stats = server.stats();
    assert_eq!(stats.tcp_connections, 0);
    server.shutdown().expect("shutdown");

    assert!(
        TcpStream::connect(tcp).is_err(),
        "TCP listener must be closed"
    );

    let socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let bytes = query("www.example.com.", Rtype::A)
        .encode(&EncodeOptions::compressed())
        .expect("encode");
    socket.send_to(&bytes, udp).expect("send");
    let mut buffer = [0_u8; 512];
    assert!(
        recv_from(&socket, &mut buffer).is_err(),
        "UDP socket must be closed"
    );
}

#[test]
fn tcp_slowloris_does_not_block_active_query() {
    let (_zone, mut config) = test_config();
    config.tcp.idle_timeout_ms = 200;
    let mut server = Server::start(&config).expect("start server");
    let address = server.tcp_addr().expect("tcp enabled");

    let mut slow = TcpStream::connect(address).expect("slow connect");
    slow.write_all(&[0_u8]).expect("partial prefix");

    let started = Instant::now();
    let mut active = TcpStream::connect(address).expect("active connect");
    active
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    write_frame(&mut active, &query("www.example.com.", Rtype::A));
    let response = read_frame(&mut active);
    assert_eq!(response.rcode(), Rcode::NOERROR);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "slowloris blocked active query for {:?}",
        started.elapsed()
    );

    slow.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("slow timeout");
    let mut byte = [0_u8; 1];
    loop {
        match slow.read(&mut byte) {
            Ok(0) => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::UnexpectedEof
                ) =>
            {
                break;
            }
            other => panic!("slowloris connection must be closed, got {other:?}"),
        }
    }
    server.shutdown().expect("shutdown");
}

#[test]
fn tcp_connection_limit_rejects_excess_and_reuses_slot() {
    let (_zone, mut config) = test_config();
    config.tcp.max_connections = 1;
    let mut server = Server::start(&config).expect("start server");
    let address = server.tcp_addr().expect("tcp enabled");

    let mut first = TcpStream::connect(address).expect("first");
    write_frame(&mut first, &query("www.example.com.", Rtype::A));
    assert_eq!(read_frame(&mut first).rcode(), Rcode::NOERROR);

    let mut excess = TcpStream::connect(address).expect("excess connect");
    excess
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("excess timeout");
    let mut byte = [0_u8; 1];
    assert!(
        matches!(excess.read(&mut byte), Ok(0) | Err(_)),
        "connection above the limit must be closed"
    );
    let deadline = Instant::now() + Duration::from_secs(1);
    while server.stats().tcp_rejected == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(server.stats().tcp_rejected >= 1);

    drop(first);
    thread::sleep(Duration::from_millis(200));
    let mut reused = TcpStream::connect(address).expect("reused slot");
    reused
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    write_frame(&mut reused, &query("www.example.com.", Rtype::A));
    assert_eq!(read_frame(&mut reused).rcode(), Rcode::NOERROR);
    server.shutdown().expect("shutdown");
}
