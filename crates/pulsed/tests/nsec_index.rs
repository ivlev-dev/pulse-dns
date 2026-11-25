//! NSEC-индекс v2: негативные ответы не перебирают denial-записи зоны.
//!
//! Строится подписанная зона с большим числом `NSEC`, затем измеряется p99
//! `DO = 1` NXDOMAIN-ответа. Индекс строится один раз на версию снапшота,
//! поэтому p99 должен быть в пределах миллисекунд, а не расти с размером зоны.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use pulse_dns::{
    DnskeyData, Edns, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, RrsigData,
    Rtype, Serial, SoaData, TypeBitmap,
};
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};
use pulsed::config::{Config, Durability};
use pulsed::server::Server;

const NAMES: usize = if cfg!(debug_assertions) { 500 } else { 2_000 };
const SAMPLES: usize = if cfg!(debug_assertions) { 300 } else { 3_000 };

fn origin() -> Name {
    Name::parse("example.test.").expect("origin")
}

fn owner(index: usize) -> Name {
    Name::parse(&format!("n{index:05}.example.test.")).expect("owner")
}

fn rdata_wires(rdatas: Vec<Rdata>) -> Vec<Vec<u8>> {
    rdatas
        .into_iter()
        .map(|rdata| rdata.to_canonical_wire())
        .collect()
}

fn exchange(
    socket: &UdpSocket,
    address: std::net::SocketAddr,
    bytes: &[u8],
    buffer: &mut [u8],
) -> usize {
    socket.send_to(bytes, address).expect("send");
    loop {
        match socket.recv_from(buffer) {
            Ok((len, _)) => return len,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => panic!("recv: {error}"),
        }
    }
}

#[test]
#[allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::cast_precision_loss
)]
fn nsec_index_p99_is_under_two_milliseconds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("nsec.v2");
    let store = ParallelStore::create(&path, StoreConfig::small(16, 65_536)).expect("store");
    let apex = NameRle::from_ascii("example.test").expect("apex");
    let mut zones = ParallelZones::open(&store).expect("catalog");
    zones
        .create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })
        .expect("create");

    let mut owners: Vec<Name> = (0..NAMES).map(owner).collect();
    owners.push(origin());
    owners.sort_by(Name::cmp_canonical);
    let bitmap =
        TypeBitmap::from_types([Rtype::A, Rtype::NS, Rtype::SOA, Rtype::NSEC, Rtype::RRSIG]);

    {
        let mut writer = zones.writer(&apex).expect("writer");
        fn record(
            writer: &mut pulse_zonefile::parallel::ParallelZone<'_>,
            name: &Name,
            rr_type: Rtype,
            rdatas: Vec<Rdata>,
        ) {
            let owner = NameRle::from_wire(name.as_wire()).expect("owner rle");
            let numeric = rr_type.as_u16();
            let subtype = if rr_type == Rtype::RRSIG {
                Rtype::DNSKEY.as_u16()
            } else {
                0
            };
            writer
                .upsert_rrset(
                    &owner,
                    numeric,
                    subtype,
                    &RrsetData::new(300, 0, rdata_wires(rdatas)).expect("rdata"),
                )
                .expect("write");
        }

        let mut write = |name: &Name, rr_type: Rtype, rdatas: Vec<Rdata>| {
            record(&mut writer, name, rr_type, rdatas);
        };
        write(
            &origin(),
            Rtype::SOA,
            vec![Rdata::Soa(SoaData::new(
                Name::parse("ns.example.test.").expect("mname"),
                Name::parse("hostmaster.example.test.").expect("rname"),
                Serial::new(1),
                3600,
                600,
                604_800,
                300,
            ))],
        );
        write(
            &origin(),
            Rtype::NS,
            vec![Rdata::Ns(Name::parse("ns.example.test.").expect("ns"))],
        );
        write(
            &origin(),
            Rtype::DNSKEY,
            vec![Rdata::Dnskey(
                DnskeyData::new(257, 3, 8, vec![7_u8; 32]).expect("dnskey"),
            )],
        );
        write(
            &origin(),
            Rtype::RRSIG,
            vec![Rdata::Rrsig(
                RrsigData::new(
                    Rtype::DNSKEY,
                    8,
                    2,
                    300,
                    u32::MAX,
                    1,
                    1,
                    origin(),
                    vec![9_u8; 64],
                )
                .expect("rrsig"),
            )],
        );
        for (index, owner) in owners.iter().enumerate() {
            let next = owners.get(index + 1).cloned().unwrap_or_else(origin);
            write(
                owner,
                Rtype::NSEC,
                vec![Rdata::Nsec(
                    pulse_dns::NsecData::new(next, bitmap.clone()).expect("nsec"),
                )],
            );
        }
        drop(write);
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

    let mut query = Message::query(
        0x1234,
        Question::new(
            Name::parse("missing.example.test.").expect("qname"),
            Rtype::A,
            Rclass::IN,
        ),
    );
    query.set_edns(Some(Edns::new(1232).with_dnssec_ok(true)));
    let bytes = query.encode(&EncodeOptions::compressed()).expect("encode");
    let mut buffer = [0_u8; 4096];

    // Прогрев: первый негативный запрос строит индекс по ключам B+tree.
    for _ in 0..200 {
        let len = exchange(&socket, address, &bytes, &mut buffer);
        let response =
            Message::decode(&buffer[..len], &pulse_dns::DecodeLimits::default()).expect("decode");
        assert_eq!(response.rcode(), Rcode::NXDOMAIN);
        assert!(
            response
                .authority()
                .iter()
                .any(|record| record.rr_type() == Rtype::NSEC),
            "NSEC proof expected"
        );
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let _ = exchange(&socket, address, &bytes, &mut buffer);
        samples.push(started.elapsed().as_nanos());
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[(samples.len() * 99 / 100).min(samples.len() - 1)];
    println!(
        "NSEC-index NXDOMAIN (DO=1, {NAMES} names): p50 {:.1} us, p99 {:.1} us",
        p50 as f64 / 1000.0,
        p99 as f64 / 1000.0
    );
    server.shutdown().expect("shutdown");
    let budget = if cfg!(debug_assertions) {
        50_000_000
    } else {
        2_000_000
    };
    assert!(
        p99 < budget,
        "NSEC-index p99 {:.1} us exceeds {:.1} ms",
        p99 as f64 / 1000.0,
        budget as f64 / 1_000_000.0
    );
}
