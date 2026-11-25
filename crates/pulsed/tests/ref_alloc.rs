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

use pulse_dns::{
    EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Rtype, Serial, SoaData,
};
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
#[allow(clippy::too_many_lines)]
fn udp_allocations_over_v2_zone_by_class() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ref.v2");
    let store = ParallelStore::create(&path, StoreConfig::small(8, 4096)).expect("store");
    let apex = NameRle::from_ascii("example.test").expect("apex");
    let owner = NameRle::from_ascii("www.example.test").expect("owner");
    let mail = NameRle::from_ascii("mail.example.test").expect("mail");
    let alias = NameRle::from_ascii("alias.example.test").expect("alias");
    let wildcard = NameRle::from_ascii("*.wild.example.test").expect("wildcard");
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
        let aaaa = Rdata::Aaaa("2001:db8::1".parse().expect("ipv6")).to_canonical_wire();
        let mx = Rdata::Mx {
            preference: 10,
            exchange: Name::parse("mail.example.test.").expect("exchange"),
        }
        .to_canonical_wire();
        let txt = Rdata::Txt(pulse_dns::TxtData::new([b"hello".to_vec()]).expect("txt"))
            .to_canonical_wire();
        let cname =
            Rdata::Cname(Name::parse("www.example.test.").expect("target")).to_canonical_wire();
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
            .upsert_rrset(&apex, 15, 0, &RrsetData::new(600, 0, vec![mx]).expect("mx"))
            .expect("mx write");
        writer
            .upsert_rrset(
                &apex,
                16,
                0,
                &RrsetData::new(300, 0, vec![txt]).expect("txt"),
            )
            .expect("txt write");
        writer
            .upsert_rrset(&owner, 1, 0, &RrsetData::new(60, 0, vec![a]).expect("a"))
            .expect("a write");
        writer
            .upsert_rrset(
                &owner,
                28,
                0,
                &RrsetData::new(60, 0, vec![aaaa]).expect("aaaa"),
            )
            .expect("aaaa write");
        writer
            .upsert_rrset(
                &mail,
                1,
                0,
                &RrsetData::new(
                    60,
                    0,
                    vec![Rdata::A("192.0.2.2".parse().expect("ipv4")).to_canonical_wire()],
                )
                .expect("mail a"),
            )
            .expect("mail write");
        writer
            .upsert_rrset(
                &alias,
                5,
                0,
                &RrsetData::new(60, 0, vec![cname]).expect("cname"),
            )
            .expect("alias write");
        writer
            .upsert_rrset(
                &wildcard,
                1,
                0,
                &RrsetData::new(
                    60,
                    0,
                    vec![Rdata::A("192.0.2.3".parse().expect("ipv4")).to_canonical_wire()],
                )
                .expect("wildcard a"),
            )
            .expect("wildcard write");
        // Синтетическая подпись: DNSKEY + RRSIG(DNSKEY) делают зону
        // подписанной, а NSEC-цепочка включает denial-путь в горячем пути.
        let dnskey =
            Rdata::Dnskey(pulse_dns::DnskeyData::new(257, 3, 8, vec![7_u8; 32]).expect("dnskey"))
                .to_canonical_wire();
        writer
            .upsert_rrset(
                &apex,
                48,
                0,
                &RrsetData::new(300, 0, vec![dnskey]).expect("dnskey"),
            )
            .expect("dnskey write");
        let signature = |covered: Rtype| {
            Rdata::Rrsig(
                pulse_dns::RrsigData::new(
                    covered,
                    8,
                    3,
                    300,
                    u32::MAX,
                    1,
                    1,
                    Name::parse("example.test.").expect("signer"),
                    vec![9_u8; 64],
                )
                .expect("rrsig"),
            )
            .to_canonical_wire()
        };
        writer
            .upsert_rrset(
                &apex,
                46,
                Rtype::DNSKEY.as_u16(),
                &RrsetData::new(300, 0, vec![signature(Rtype::DNSKEY)]).expect("rrsig"),
            )
            .expect("dnskey rrsig write");
        writer
            .upsert_rrset(
                &owner,
                46,
                Rtype::A.as_u16(),
                &RrsetData::new(60, 0, vec![signature(Rtype::A)]).expect("rrsig"),
            )
            .expect("a rrsig write");
        let mut nsec_owners: Vec<Name> = vec![
            Name::parse("example.test.").expect("apex name"),
            Name::parse("www.example.test.").expect("www name"),
            Name::parse("mail.example.test.").expect("mail name"),
            Name::parse("alias.example.test.").expect("alias name"),
            Name::parse("*.wild.example.test.").expect("wildcard name"),
        ];
        nsec_owners.sort_by(Name::cmp_canonical);
        nsec_owners.dedup();
        let bitmap = pulse_dns::TypeBitmap::from_types([
            Rtype::A,
            Rtype::NS,
            Rtype::SOA,
            Rtype::NSEC,
            Rtype::RRSIG,
        ]);
        for (index, nsec_owner) in nsec_owners.iter().enumerate() {
            let next = nsec_owners
                .get(index + 1)
                .cloned()
                .unwrap_or_else(|| nsec_owners[0].clone());
            let nsec = Rdata::Nsec(pulse_dns::NsecData::new(next, bitmap.clone()).expect("nsec"))
                .to_canonical_wire();
            let owner_rle = NameRle::from_wire(nsec_owner.as_wire()).expect("nsec owner");
            writer
                .upsert_rrset(
                    &owner_rle,
                    Rtype::NSEC.as_u16(),
                    0,
                    &RrsetData::new(300, 0, vec![nsec]).expect("nsec data"),
                )
                .expect("nsec write");
            writer
                .upsert_rrset(
                    &owner_rle,
                    Rtype::RRSIG.as_u16(),
                    Rtype::NSEC.as_u16(),
                    &RrsetData::new(300, 0, vec![signature(Rtype::NSEC)]).expect("rrsig"),
                )
                .expect("nsec rrsig write");
        }
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
    let mut buffer = [0_u8; 4096];

    let query = |qname: &str, qtype: Rtype, edns: bool| {
        let mut message = Message::query(
            0x1234,
            Question::new(Name::parse(qname).expect("qname"), qtype, Rclass::IN),
        );
        if edns {
            message.set_edns(Some(pulse_dns::Edns::new(1232)));
        }
        message
            .encode(&EncodeOptions::compressed())
            .expect("query encode")
    };

    let signed_query = |qname: &str, qtype: Rtype| {
        let mut message = Message::query(
            0x1234,
            Question::new(Name::parse(qname).expect("qname"), qtype, Rclass::IN),
        );
        message.set_edns(Some(pulse_dns::Edns::new(1232).with_dnssec_ok(true)));
        message
            .encode(&EncodeOptions::compressed())
            .expect("signed query encode")
    };

    let classes = vec![
        (
            "A",
            query("www.example.test.", Rtype::A, false),
            Rcode::NOERROR,
            1,
        ),
        (
            "AAAA",
            query("www.example.test.", Rtype::AAAA, false),
            Rcode::NOERROR,
            1,
        ),
        (
            "MX",
            query("example.test.", Rtype::MX, false),
            Rcode::NOERROR,
            1,
        ),
        (
            "TXT",
            query("example.test.", Rtype::TXT, false),
            Rcode::NOERROR,
            1,
        ),
        (
            "CNAME",
            query("alias.example.test.", Rtype::A, false),
            Rcode::NOERROR,
            2,
        ),
        (
            "wildcard",
            query("foo.wild.example.test.", Rtype::A, false),
            Rcode::NOERROR,
            1,
        ),
        (
            "NXDOMAIN",
            query("missing.example.test.", Rtype::A, false),
            Rcode::NXDOMAIN,
            0,
        ),
        (
            "EDNS-A",
            query("www.example.test.", Rtype::A, true),
            Rcode::NOERROR,
            1,
        ),
        (
            "ANY",
            query("www.example.test.", Rtype::ANY, false),
            Rcode::NOERROR,
            1,
        ),
        (
            "DO-A",
            signed_query("www.example.test.", Rtype::A),
            Rcode::NOERROR,
            2,
        ),
        (
            "DO-NXDOMAIN",
            signed_query("missing.example.test.", Rtype::A),
            Rcode::NXDOMAIN,
            0,
        ),
    ];

    for (label, bytes, rcode, answers) in &classes {
        for _ in 0..100 {
            socket.send_to(bytes, address).expect("send");
            recv(&socket, &mut buffer);
        }
        let mut verified = false;
        for _ in 0..5 {
            socket.send_to(bytes, address).expect("send");
            let len = recv(&socket, &mut buffer);
            let response = Message::decode(&buffer[..len], &pulse_dns::DecodeLimits::default())
                .expect("decode");
            assert_eq!(response.rcode(), *rcode, "{label}: rcode");
            assert_eq!(response.answers().len(), *answers, "{label}: answers");
            verified = true;
        }
        assert!(verified, "{label}: warm response");

        let ops = 500_u64;
        ALLOCS.store(0, Ordering::Relaxed);
        COUNTING.store(true, Ordering::Relaxed);
        let mut total_bytes = 0_usize;
        for _ in 0..ops {
            socket.send_to(bytes, address).expect("send");
            total_bytes = total_bytes.saturating_add(recv(&socket, &mut buffer));
        }
        COUNTING.store(false, Ordering::Relaxed);
        let allocations = ALLOCS.load(Ordering::Relaxed);
        let per_op = allocations as f64 / ops as f64;
        let bytes_per_op = total_bytes as f64 / ops as f64;
        println!(
            "udp-e2e v2 {label}: {allocations} allocs / {ops} = {per_op:.4} allocs/op,              {bytes_per_op:.1} bytes/op"
        );
        assert!(per_op <= 5.0, "{label}: allocs/op {per_op:.4} exceeds 5");
        assert!(
            bytes_per_op <= 512.0,
            "{label}: bytes/op {bytes_per_op:.1} exceeds 512"
        );
    }
    server.shutdown().expect("shutdown");
}
