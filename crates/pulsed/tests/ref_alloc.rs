//! Аллокации UDP-ответа поверх v2-зоны (отдельный test-binary).
//!
//! Один тест в бинарнике: глобальный счётчик видит все потоки процесса,
//! включая worker'ы сервера.
#![allow(unsafe_code)]
#![allow(clippy::cast_precision_loss)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use pulse_dns::{EncodeOptions, Message, Name, Question, Rclass, Rdata, Rtype, Serial, SoaData};
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};
use pulsed::config::{Config, Durability};
use pulsed::server::Server;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn recv(socket: &UdpSocket, buffer: &mut [u8]) -> usize {
    loop {
        match socket.recv_from(buffer) {
            Ok((len, _)) => return len,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => panic!("recv: {error}"),
        }
    }
}

#[test]
fn udp_a_allocations_over_v2_zone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ref.v2");
    let store = ParallelStore::create(&path, StoreConfig::small(8, 4096)).expect("store");
    let apex = NameRle::from_ascii("example.test").expect("apex");
    let owner = NameRle::from_ascii("www.example.test").expect("owner");
    let mut zones = ParallelZones::open(&store).expect("catalog");
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .expect("create");
    {
        let mut writer = zones.writer(&apex).expect("writer");
        let soa = Rdata::Soa(SoaData::new(
            Name::parse("ns.example.test.").expect("mname"),
            Name::parse("hostmaster.example.test.").expect("rname"),
            Serial::new(1),
            3600,
            600,
            604_800,
            300,
        ))
        .to_canonical_wire();
        let ns = Rdata::Ns(Name::parse("ns.example.test.").expect("ns")).to_canonical_wire();
        let a = Rdata::A("192.0.2.1".parse().expect("ipv4")).to_canonical_wire();
        writer
            .upsert_rrset(
                &apex,
                6,
                0,
                &RrsetData::new(3600, 0, vec![soa]).expect("soa"),
            )
            .expect("soa write");
        writer
            .upsert_rrset(&apex, 2, 0, &RrsetData::new(3600, 0, vec![ns]).expect("ns"))
            .expect("ns write");
        writer
            .upsert_rrset(&owner, 1, 0, &RrsetData::new(60, 0, vec![a]).expect("a"))
            .expect("a write");
        writer.commit().expect("commit");
    }
    drop(zones);
    drop(store);

    let config = Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("addr")),
        listen_tcp: None,
        workers: 2,
        zonefile: Some(path),
        durability: Durability::Memory,
        journal: false,
        ..Config::default()
    };
    let mut server = Server::start(&config).expect("server");
    let address = server.udp_addr().expect("udp addr");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let query = Message::query(
        0x1234,
        Question::new(
            Name::parse("www.example.test.").expect("qname"),
            Rtype::A,
            Rclass::IN,
        ),
    )
    .encode(&EncodeOptions::compressed())
    .expect("query encode");
    let mut buffer = [0_u8; 4096];

    for _ in 0..200 {
        socket.send_to(&query, address).expect("send");
        let len = recv(&socket, &mut buffer);
        let response =
            Message::decode(&buffer[..len], &pulse_dns::DecodeLimits::default()).expect("decode");
        assert_eq!(response.answers().len(), 1, "warm A response");
    }

    let ops = 1000_u64;
    ALLOCS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let mut total_bytes = 0_usize;
    for _ in 0..ops {
        socket.send_to(&query, address).expect("send");
        total_bytes = total_bytes.saturating_add(recv(&socket, &mut buffer));
    }
    COUNTING.store(false, Ordering::Relaxed);
    let allocations = ALLOCS.load(Ordering::Relaxed);
    let per_op = allocations as f64 / ops as f64;
    let bytes_per_op = total_bytes as f64 / ops as f64;
    println!(
        "udp-e2e v2 A: {allocations} allocs / {ops} ops = {per_op:.4} allocs/op, \
         {bytes_per_op:.1} bytes/op"
    );
    server.shutdown().expect("shutdown");
    assert!(per_op <= 5.0, "allocs/op {per_op:.4} exceeds 5");
    assert!(
        bytes_per_op <= 512.0,
        "bytes/op {bytes_per_op:.1} exceeds 512"
    );
}
