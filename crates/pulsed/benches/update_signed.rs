//! Bench: латентность RFC 2136 UPDATE на подписанной зоне 100k имён.
//!
//! Для NSEC и NSEC3 (opt-out) строится зона из 100 000 `A`, подписывается при
//! старте сервера, после чего по UDP выполняются UPDATE-запросы (add A нового
//! имени + delete A предыдущего). Печатает p50/p95/p99/max и проверяет цель
//! p99 ≤ 50 мс.
//!
//! Запуск: `cargo bench -p pulsed --bench update_signed` (release).

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pulse_dns::{
    DecodeLimits, EncodeOptions, Flags, Message, Name, Opcode, Question, Rclass, Rcode, Rdata,
    Record, Rtype, Serial, SoaData, Ttl,
};
use pulse_dnssec::{Algorithm, NoopAudit, PrivateKey, write_key_pair};
use pulse_zonefile::key::{NameRle, name_cmp};
use pulse_zonefile::parallel::{
    BulkRrset, ParallelStore, ParallelZones, RrsetData, StoreConfig, SyncModeV2, ZoneCreateMeta,
    ZoneMetaV2,
};
use pulsed::config::{
    Config, DnssecDenial, DnssecKeyConfig, DnssecKeyRole, DnssecZoneConfig, Durability,
    UpdateSettings,
};
use pulsed::server::Server;

const ORIGIN: &str = "example.test.";
const RECORDS: usize = 100_000;
const SAMPLES: usize = 200;
const WARMUP: usize = 20;
const TARGET_US: u128 = 50_000;

fn bench_dir() -> PathBuf {
    let base = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/pulsed-bench")
        .join(format!("update-signed-{}", std::process::id()));
    std::fs::create_dir_all(&base).expect("bench dir");
    base
}

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

fn rdata_data(ttl: u32, rdata: &Rdata) -> RrsetData {
    RrsetData::from_slices(ttl, 0, &[&rdata.to_canonical_wire()]).expect("rrset data")
}

fn populate(path: &Path, denial: DnssecDenial) {
    let store = ParallelStore::create(
        path,
        StoreConfig {
            page_count_max: 1 << 18,
            max_zones: 4,
            sync_mode: SyncModeV2::Sync,
            ..StoreConfig::default()
        },
    )
    .expect("create store");
    let apex = NameRle::from_ascii(ORIGIN).expect("apex");
    let mut zones = ParallelZones::open(&store).expect("catalog");
    zones
        .create_zone_with_meta(
            &apex,
            ZoneCreateMeta { soa_serial: 1 },
            ZoneMetaV2 {
                default_ttl: 3600,
                denial: u8::from(matches!(denial, DnssecDenial::Nsec3)),
                ..ZoneMetaV2::default()
            },
        )
        .expect("zone");

    let soa = Rdata::Soa(SoaData::new(
        name("ns1.example.test."),
        name("hostmaster.example.test."),
        Serial::new(1),
        7200,
        900,
        1_209_600,
        300,
    ));
    let ns = Rdata::Ns(name("ns1.example.test."));
    let mut records = Vec::with_capacity(RECORDS + 2);
    records.push(BulkRrset {
        name: apex,
        rr_type: Rtype::NS.as_u16(),
        subtype: 0,
        data: rdata_data(3600, &ns),
    });
    records.push(BulkRrset {
        name: apex,
        rr_type: Rtype::SOA.as_u16(),
        subtype: 0,
        data: rdata_data(3600, &soa),
    });
    for index in 0..RECORDS {
        let owner = NameRle::from_ascii(&format!("n{index:06}.example.test.")).expect("owner");
        let address = Rdata::A(
            format!("10.{}.{}.1", index / 65_536, index % 256)
                .parse()
                .expect("ip"),
        );
        records.push(BulkRrset {
            name: owner,
            rr_type: Rtype::A.as_u16(),
            subtype: 0,
            data: rdata_data(300, &address),
        });
    }
    records.sort_by(|left, right| {
        name_cmp(left.name.as_rle(), right.name.as_rle())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.rr_type.cmp(&right.rr_type))
            .then_with(|| left.subtype.cmp(&right.subtype))
    });
    let mut writer = zones.writer(&apex).expect("writer");
    writer.bulk_load(records).expect("bulk load");
    writer.set_soa_serial(1);
    writer.commit().expect("commit");
    drop(writer);
    drop(zones);
    store.sync().expect("sync");
}

fn config(path: &Path, denial: DnssecDenial, key_dir: &Path) -> Config {
    let ksk = PrivateKey::generate(Algorithm::ED25519).expect("ksk");
    let zsk = PrivateKey::generate(Algorithm::ED25519).expect("zsk");
    let ksk_paths = write_key_pair(key_dir, &name(ORIGIN), &ksk, 257, &NoopAudit).expect("ksk");
    let zsk_paths = write_key_pair(key_dir, &name(ORIGIN), &zsk, 256, &NoopAudit).expect("zsk");
    let mut dnssec = BTreeMap::new();
    dnssec.insert(
        ORIGIN.to_owned(),
        DnssecZoneConfig {
            keys: vec![
                DnssecKeyConfig {
                    role: Some(DnssecKeyRole::Ksk),
                    path: ksk_paths.private,
                    algorithm: None,
                    flags: None,
                },
                DnssecKeyConfig {
                    role: Some(DnssecKeyRole::Zsk),
                    path: zsk_paths.private,
                    algorithm: None,
                    flags: None,
                },
            ],
            validity_days: Some(30),
            inception_skew: Some(300),
            denial: Some(denial),
            nsec3_salt: matches!(denial, DnssecDenial::Nsec3).then(|| "aabbccdd".to_owned()),
            nsec3_iterations: matches!(denial, DnssecDenial::Nsec3).then_some(0),
            nsec3_opt_out: matches!(denial, DnssecDenial::Nsec3).then_some(true),
            rotation: None,
        },
    );
    Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: None,
        workers: 2,
        zonefile: Some(path.to_path_buf()),
        durability: Durability::Flush,
        map_size: 512 * 1024 * 1024,
        dnssec,
        transfer: pulsed::config::TransferSettings {
            enabled: false,
            ..pulsed::config::TransferSettings::default()
        },
        update: UpdateSettings {
            enabled: true,
            require_tsig: false,
            allow_from: vec!["127.0.0.1/32".to_owned(), "::1/128".to_owned()],
            allow_zones: vec![ORIGIN.to_owned()],
            ..UpdateSettings::default()
        },
        ..Config::default()
    }
}

fn update_message(id: u16) -> Message {
    let mut message = Message::new(id, Flags::new().with_opcode(Opcode::UPDATE));
    message.add_question(Question::new(name(ORIGIN), Rtype::SOA, Rclass::IN));
    message
}

fn add_a(message: &mut Message, owner: &str, octets: [u8; 4]) {
    message.add_authority(
        Record::new(
            name(owner),
            Rtype::A,
            Rclass::IN,
            Ttl::new(300).expect("ttl"),
            Rdata::A(octets.into()),
        )
        .expect("record"),
    );
}

fn delete_rrset(message: &mut Message, owner: &str, rr_type: Rtype) {
    message.add_authority(Record::update_metavalue(name(owner), rr_type, Rclass::ANY));
}

fn send(socket: &UdpSocket, address: std::net::SocketAddr, message: &Message) -> Rcode {
    let bytes = message
        .encode(&EncodeOptions::compressed())
        .expect("encode update");
    loop {
        match socket.send_to(&bytes, address) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => {
                result.expect("send");
                break;
            }
        }
    }
    let mut buffer = [0_u8; 4096];
    let (length, _) = loop {
        match socket.recv_from(&mut buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => break result.expect("recv"),
        }
    };
    Message::decode(&buffer[..length], &DecodeLimits::default())
        .expect("decode")
        .rcode()
}

fn percentile(sorted: &[u128], percent: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() as f64 - 1.0) * percent).round() as usize;
    sorted.get(index).copied().unwrap_or(0)
}

fn run(label: &str, denial: DnssecDenial) {
    let dir = bench_dir().join(label);
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("zones.pulse");
    let _ = std::fs::remove_file(&path);
    let key_dir = dir.join("keys");
    std::fs::create_dir_all(&key_dir).expect("keys");
    std::fs::set_permissions(&key_dir, std::fs::Permissions::from_mode(0o700))
        .expect("key dir mode");

    populate(&path, denial);
    let config = config(&path, denial, &key_dir);
    config.validate().expect("config valid");
    let mut server = Server::start(&config).expect("start server");
    let address = server.udp_addr().expect("udp");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");

    for index in 0..WARMUP {
        let mut update = update_message(u16::try_from(index).unwrap_or(0));
        add_a(
            &mut update,
            &format!("warm{index:04}.example.test."),
            [127, 0, 0, u8::try_from(index % 250).unwrap_or(1)],
        );
        assert_eq!(send(&socket, address, &update), Rcode::NOERROR);
    }

    let mut latencies = Vec::with_capacity(SAMPLES);
    for index in 0..SAMPLES {
        let mut update = update_message(u16::try_from(index + 1000).unwrap_or(0));
        add_a(
            &mut update,
            &format!("u{index:06}.example.test."),
            [10, 20, (index / 256) as u8, (index % 256) as u8],
        );
        if index > 0 {
            delete_rrset(
                &mut update,
                &format!("u{:06}.example.test.", index - 1),
                Rtype::A,
            );
        }
        let started = Instant::now();
        let rcode = send(&socket, address, &update);
        let elapsed = started.elapsed().as_micros();
        assert_eq!(rcode, Rcode::NOERROR, "update {index}");
        latencies.push(elapsed);
    }

    server.shutdown().expect("shutdown");
    drop(server);

    latencies.sort_unstable();
    let p50 = percentile(&latencies, 0.50);
    let p95 = percentile(&latencies, 0.95);
    let p99 = percentile(&latencies, 0.99);
    let max = latencies.last().copied().unwrap_or(0);
    println!(
        "{label:>8}: n={SAMPLES} p50={:.2}ms p95={:.2}ms p99={:.2}ms max={:.2}ms {}",
        p50 as f64 / 1000.0,
        p95 as f64 / 1000.0,
        p99 as f64 / 1000.0,
        max as f64 / 1000.0,
        if p99 <= TARGET_US { "OK" } else { "OVER 50ms" }
    );
}

fn main() {
    run("nsec", DnssecDenial::Nsec);
    run("nsec3", DnssecDenial::Nsec3);
}
