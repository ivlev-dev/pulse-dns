//! Генерирует детерминированный seed-корпус для fuzz-таргетов.
//!
//! ```text
//! cargo +nightly run --manifest-path fuzz/Cargo.toml --bin gen_seeds
//! ```
//!
//! Файлы кладутся в `fuzz/seeds/<target>/`; CI копирует их в `fuzz/corpus`
//! перед запуском (сам `fuzz/corpus` в `.gitignore`).

use std::error::Error;
use std::fs;
use std::path::Path;

use pulse_dns::{EncodeOptions, Message, Name, Question, Rclass, Rtype};
use pulse_dnscrypt::{
    Certificate, CertificateParams, DnscryptClient, ProviderKeypair, ResolverKeypair, Transport,
};
use pulse_master::parse_zone;
use pulse_transfer::{TsigAlgorithm, TsigKey, append_tsig};
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

const PROVIDER_SEED: [u8; 32] = [0x42; 32];
const RESOLVER_SECRET: [u8; 32] = [0x24; 32];
const CLIENT_SECRET: [u8; 32] = [0x11; 32];
const CLIENT_MAGIC: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const NOW: u64 = 1_700_000_000;

const DNS_QUERY: &[u8] = &[
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
    b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
];

fn main() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
    fs::create_dir_all(&root)?;

    dns_wire(&root)?;
    master_zone(&root)?;
    zonefile_v2_open(&root)?;
    transfer_tsig(&root)?;
    dnscrypt_packet(&root)?;
    println!("seeds written to {}", root.display());
    Ok(())
}

fn write(root: &Path, target: &str, name: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let dir = root.join(target);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(name), bytes)?;
    Ok(())
}

fn dns_wire(root: &Path) -> Result<(), Box<dyn Error>> {
    write(root, "dns_wire", "query.bin", DNS_QUERY)?;
    // EDNS0-запрос: OPT (root, type 41, class 4096, ttl 0, rdlen 0).
    let mut edns = DNS_QUERY.to_vec();
    edns[10] = 0;
    edns[11] = 1;
    edns.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    write(root, "dns_wire", "query-edns.bin", &edns)?;
    // Обрезанный заголовок/вопрос: ветка ошибок декодера.
    write(root, "dns_wire", "truncated.bin", &DNS_QUERY[..17])?;
    Ok(())
}

fn master_zone(root: &Path) -> Result<(), Box<dyn Error>> {
    let simple = "\
$ORIGIN example.com.
$TTL 3600
@ IN SOA ns1 hostmaster 2026010101 7200 900 1209600 300
@ IN NS ns1
ns1 IN A 192.0.2.53
www IN AAAA 2001:db8::1
";
    let multiline = "\
$ORIGIN example.com.
@ 3600 IN SOA ns1.example.com. hostmaster.example.com. (
    2026010101 ; serial
    7200       ; refresh
    900        ; retry
    1209600    ; expire
    300 )      ; minimum
@ IN NS ns1
txt IN TXT (\"hello \" \"world\") ; склейка строк
";
    let rfc3597 = "\
$ORIGIN example.com.
@ IN SOA ns1 hostmaster 1 3600 600 604800 300
@ IN NS ns1
@ IN TYPE65280 \\# 8 0102030405060708
";
    for (name, text) in [
        ("simple.zone", simple),
        ("multiline.zone", multiline),
        ("rfc3597.zone", rfc3597),
    ] {
        // Проверяем, что seed действительно валиден (ошибка — баг генератора).
        parse_zone(Name::parse("example.com.")?, text)?;
        write(root, "master_zone", name, text.as_bytes())?;
    }
    Ok(())
}

fn zonefile_v2_open(root: &Path) -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let small = build_v2(&dir.path().join("small.v2"), false)?;
    write(root, "zonefile_v2_open", "valid-small.v2", &small)?;
    let overflow = build_v2(&dir.path().join("overflow.v2"), true)?;
    write(root, "zonefile_v2_open", "valid-overflow.v2", &overflow)?;
    Ok(())
}

fn build_v2(path: &Path, overflow: bool) -> Result<Vec<u8>, Box<dyn Error>> {
    let store = ParallelStore::create(path, StoreConfig::small(8, 80))?;
    let apex = NameRle::from_ascii("seed.example")?;
    let mut zones = ParallelZones::open(&store)?;
    let _seq = zones.create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })?;
    {
        let mut writer = zones.writer(&apex)?;
        let name = NameRle::from_ascii("www.seed.example")?;
        writer.upsert_rrset(
            &name,
            1,
            0,
            &RrsetData::from_slices(60, 0, &[&[192, 0, 2, 1]])?,
        )?;
        if overflow {
            let big = NameRle::from_ascii("big.seed.example")?;
            let payload = vec![0xAB_u8; 600];
            writer.upsert_rrset(&name, 16, 0, &RrsetData::from_slices(60, 0, &[&payload])?)?;
            writer.upsert_rrset(&big, 16, 0, &RrsetData::from_slices(60, 0, &[&payload])?)?;
        }
        writer.commit()?;
    }
    drop(zones);
    drop(store);
    Ok(fs::read(path)?)
}

fn transfer_tsig(root: &Path) -> Result<(), Box<dyn Error>> {
    let origin = Name::parse("example.com.")?;
    let query = Message::query(0x1234, Question::new(origin, Rtype::AXFR, Rclass::IN));
    let options = EncodeOptions::default();
    let query_bytes = query.encode(&options)?;
    write(root, "transfer_tsig", "axfr-query.bin", &query_bytes)?;

    let key = TsigKey::new(
        Name::parse("xfr-key.example.com.")?,
        TsigAlgorithm::HmacSha256,
        b"fuzz-secret".to_vec(),
    )?;
    let record = key.sign_request(&query_bytes, 0x1234, NOW)?;
    let signed = append_tsig(query_bytes, &record)?;
    write(root, "transfer_tsig", "axfr-tsig.bin", &signed)?;
    write(
        root,
        "transfer_tsig",
        "garbage.bin",
        b"\x00\xffnot-a-dns-message",
    )?;
    Ok(())
}

fn dnscrypt_packet(root: &Path) -> Result<(), Box<dyn Error>> {
    let provider = ProviderKeypair::from_seed(PROVIDER_SEED);
    let resolver = ResolverKeypair::from_secret_bytes(RESOLVER_SECRET);
    let params = CertificateParams::new(
        resolver.public_key().to_bytes(),
        CLIENT_MAGIC,
        1,
        u32::try_from(NOW)?,
        1_800_000_000,
    );
    let certificate = Certificate::sign(&provider, params)?;
    let client_key = ResolverKeypair::from_secret_bytes(CLIENT_SECRET);
    let client = DnscryptClient::with_keypair(certificate, provider.public_key(), NOW, client_key)?;
    let pending = client.build_query_with_nonce(DNS_QUERY, Transport::Udp, [0x5A; 12])?;
    write(root, "dnscrypt_packet", "valid-udp.bin", pending.packet())?;
    write(
        root,
        "dnscrypt_packet",
        "garbage.bin",
        b"not-a-dnscrypt-packet",
    )?;
    Ok(())
}
