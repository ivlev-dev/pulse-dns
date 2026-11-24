//! E2E `pulsed convert`: v1 → v2 без потери зон, записей и настроек,
//! плюс понятная ошибка при открытии v1-файла как `--data`.

use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use pulse_dns::{
    DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rcode, Rdata, Rtype, Serial,
    SoaData,
};
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{OpenConfigV2, ParallelStore, ParallelZones, ZoneReader};
use pulse_zonefile::tree::RrsetData;
use pulse_zonefile::{CreateConfig, SyncMode, ZoneFile, ZoneMetaBlock};
use pulsed::config::{Config, Durability, TcpConfig};
use pulsed::server::Server;

fn rle(name: &str) -> NameRle {
    NameRle::from_ascii(name).expect("rle name")
}

fn rrset(ttl: u32, rdata: &[Rdata]) -> RrsetData {
    RrsetData::new(ttl, 0, rdata.iter().map(Rdata::to_canonical_wire).collect())
        .expect("rrset data")
}

fn write_v1(path: &Path) -> usize {
    let mut file = ZoneFile::create(
        path,
        CreateConfig {
            map_size: 32 * 1024 * 1024,
            ..CreateConfig::default()
        },
    )
    .expect("create v1");
    let apex = rle("conv.test.");
    let mut writer = file.write().expect("v1 writer");
    writer
        .create_zone_with_meta(
            &apex,
            0,
            &ZoneMetaBlock {
                default_ttl: 7200,
                denial: 0,
                ..ZoneMetaBlock::default()
            },
        )
        .expect("v1 zone");
    let soa = Rdata::Soa(SoaData::new(
        Name::parse("ns1.conv.test.").expect("mname"),
        Name::parse("hostmaster.conv.test.").expect("rname"),
        Serial::new(42),
        3600,
        600,
        604_800,
        300,
    ));
    let ns = Rdata::Ns(Name::parse("ns1.conv.test.").expect("ns"));
    let a = Rdata::A("192.0.2.10".parse().expect("ipv4"));
    let wildcard = Rdata::A("192.0.2.99".parse().expect("ipv4"));
    let glue = Rdata::A("192.0.2.80".parse().expect("ipv4"));
    let deleg_ns = Rdata::Ns(Name::parse("ns.deleg.conv.test.").expect("ns"));
    let mut records = 0_usize;
    for (name, rr_type, data) in [
        (apex, Rtype::SOA.as_u16(), rrset(3600, &[soa])),
        (apex, Rtype::NS.as_u16(), rrset(3600, &[ns])),
        (rle("www.conv.test."), Rtype::A.as_u16(), rrset(300, &[a])),
        (
            rle("*.wild.conv.test."),
            Rtype::A.as_u16(),
            rrset(300, &[wildcard]),
        ),
        (
            rle("deleg.conv.test."),
            Rtype::NS.as_u16(),
            rrset(3600, &[deleg_ns]),
        ),
        (
            rle("ns.deleg.conv.test."),
            Rtype::A.as_u16(),
            rrset(300, &[glue]),
        ),
        (
            rle("host.ent.conv.test."),
            Rtype::A.as_u16(),
            rrset(300, &[Rdata::A("192.0.2.20".parse().expect("ipv4"))]),
        ),
    ] {
        writer
            .upsert_rrset(&apex, &name, rr_type, 0, &data)
            .expect("v1 rrset");
        records += 1;
    }
    writer.commit(SyncMode::Sync).expect("v1 commit");
    records
}

fn run_convert(from: &Path, to: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .arg("convert")
        .arg("--from")
        .arg(from)
        .arg("--to")
        .arg(to)
        .arg("--durability")
        .arg("sync")
        .env_remove("PULSED_API_TOKEN")
        .output()
        .expect("run pulsed convert");
    assert!(
        output.status.success(),
        "convert failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn recv_from(socket: &UdpSocket, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

fn dns_query(server: &Server, qname: &str, qtype: Rtype) -> Message {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("client socket");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    let query = Message::query(
        0x7c7c,
        Question::new(Name::parse(qname).expect("qname"), qtype, Rclass::IN),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode");
    socket
        .send_to(&query, server.udp_addr().expect("udp"))
        .expect("send");
    let mut buffer = [0_u8; 4096];
    let (len, _) = recv_from(&socket, &mut buffer).expect("recv");
    Message::decode(&buffer[..len], &DecodeLimits::default()).expect("decode")
}

fn config(data: &Path) -> Config {
    Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: Some("127.0.0.1:0".parse().expect("tcp")),
        workers: 1,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile: Some(data.to_path_buf()),
        durability: Durability::Sync,
        map_size: 64 * 1024 * 1024,
        ..Config::default()
    }
}

#[test]
fn convert_v1_to_v2_keeps_zones_records_and_metadata() {
    let dir = tempfile::tempdir().expect("temp dir");
    let v1 = dir.path().join("zones.v1");
    let v2 = dir.path().join("zones.v2");
    let records = write_v1(&v1);
    run_convert(&v1, &v2);

    // Прямая проверка v2-файла: метаданные каталога, дерево и apex.
    let store = ParallelStore::open(&v2, OpenConfigV2::default()).expect("open v2");
    let zones = ParallelZones::open(&store).expect("catalog");
    let apex = rle("conv.test.");
    assert!(zones.zone_seq(&apex).is_some());
    let meta = zones.zone_meta(&apex).expect("zone meta");
    assert_eq!(meta.default_ttl, 7200);
    assert_eq!(meta.kind_flags, 0);
    assert_eq!(meta.denial, 0);
    let reader = store.reader().expect("reader");
    let view = ZoneReader::open(&store, &reader, apex, zones.zone_seq(&apex).expect("seq"))
        .expect("zone reader");
    let converted = view.records().expect("records");
    assert!(
        converted.len() >= records,
        "converted {} < source {records}",
        converted.len()
    );
    assert!(store.fsck_lite().expect("fsck").ok);
    drop(view);
    drop(reader);
    drop(zones);
    drop(store);

    // Сервер поверх v2 отвечает теми же данными.
    let mut server = Server::start(&config(&v2)).expect("start on v2");
    let soa = dns_query(&server, "conv.test.", Rtype::SOA);
    assert_eq!(soa.rcode(), Rcode::NOERROR);
    assert_eq!(soa.answers().len(), 1);
    match soa.answers()[0].rdata() {
        Rdata::Soa(data) => assert_eq!(data.serial, Serial::new(42)),
        other => panic!("expected SOA, got {other:?}"),
    }
    let www = dns_query(&server, "www.conv.test.", Rtype::A);
    assert_eq!(www.rcode(), Rcode::NOERROR);
    assert_eq!(
        www.answers()[0].rdata(),
        &Rdata::A("192.0.2.10".parse().expect("ipv4"))
    );
    let wildcard = dns_query(&server, "host.wild.conv.test.", Rtype::A);
    assert_eq!(wildcard.rcode(), Rcode::NOERROR);
    assert_eq!(
        wildcard.answers()[0].rdata(),
        &Rdata::A("192.0.2.99".parse().expect("ipv4"))
    );
    let ent = dns_query(&server, "ent.conv.test.", Rtype::A);
    assert_eq!(ent.rcode(), Rcode::NOERROR);
    assert_eq!(ent.answers().len(), 0, "ENT must be NODATA");
    let nxdomain = dns_query(&server, "missing.conv.test.", Rtype::A);
    assert_eq!(nxdomain.rcode(), Rcode::NXDOMAIN);
    server.shutdown().expect("shutdown");
}

#[test]
fn v1_file_is_rejected_with_convert_hint() {
    let dir = tempfile::tempdir().expect("temp dir");
    let v1 = dir.path().join("legacy.v1");
    write_v1(&v1);
    let error = match Server::start(&config(&v1)) {
        Ok(_) => panic!("v1 file must be rejected"),
        Err(error) => error.to_string(),
    };
    let lower = error.to_lowercase();
    assert!(lower.contains("v1"), "{error}");
    assert!(lower.contains("pulsed convert"), "{error}");
}
