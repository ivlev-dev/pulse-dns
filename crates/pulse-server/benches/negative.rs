//! Bench негативных DNSSEC-ответов: индексированный (NSEC/NSEC3) путь против
//! старого линейного перебора denial-записей.
//!
//! Печатает p50/p99 одного запроса и qps одного потока для signed-зоны
//! (по умолчанию 100k имён; размер задаётся `PULSE_BENCH_SIZE`).
//!
//! Запуск: `cargo bench -p pulse-server --bench negative` (release).

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::cmp::Ordering;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use pulse_dns::{
    DnskeyData, Edns, Message, Name, Question, Rclass, Rdata, Rrset, RrsigData, Rtype, Serial,
    SoaData, Ttl, TypeBitmap,
};
use pulse_server::application::{QueryEngine, Scratch, Transport};
use pulse_server::testkit::InMemoryZone;
use pulse_server::{DenialKind, LookupOutcome, ZoneState, ZoneView};

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

fn ttl(value: u32) -> Ttl {
    Ttl::new(value).expect("ttl")
}

fn rrset(owner: &Name, rr_type: Rtype, rdatas: impl IntoIterator<Item = Rdata>) -> Rrset {
    Rrset::new(owner.clone(), rr_type, Rclass::IN, ttl(300), rdatas).expect("rrset")
}

fn nsec_covers(owner: &Name, next: &Name, name: &Name) -> bool {
    if name == owner {
        return false;
    }
    match owner.cmp_canonical(next) {
        Ordering::Less => {
            owner.cmp_canonical(name) == Ordering::Less
                && name.cmp_canonical(next) == Ordering::Less
        }
        Ordering::Greater | Ordering::Equal => {
            owner.cmp_canonical(name) == Ordering::Less
                || name.cmp_canonical(next) == Ordering::Less
        }
    }
}

fn nsec3_covers(owner: &[u8], next: &[u8], hash: &[u8]) -> bool {
    if hash == owner {
        return false;
    }
    match owner.cmp(next) {
        Ordering::Less => hash > owner && hash < next,
        Ordering::Greater | Ordering::Equal => hash > owner || hash < next,
    }
}

/// Старый путь: полный линейный перебор denial-записей на каждый запрос.
struct LinearView {
    inner: Arc<InMemoryZone>,
    nsec: Vec<Rrset>,
    nsec3: Vec<Rrset>,
}

impl ZoneView for LinearView {
    fn origin(&self) -> &Name {
        self.inner.origin()
    }

    fn apex(&self) -> &Name {
        self.inner.apex()
    }

    fn soa(&self) -> Option<&Rrset> {
        self.inner.soa()
    }

    fn ns(&self) -> Option<&Rrset> {
        self.inner.ns()
    }

    fn class(&self) -> Rclass {
        self.inner.class()
    }

    fn state(&self) -> ZoneState {
        self.inner.state()
    }

    fn lookup(&self, name: &Name, rr_type: Rtype) -> LookupOutcome {
        self.inner.lookup(name, rr_type)
    }

    fn lookup_all_rrsig(&self, name: &Name, covered: Rtype) -> Vec<Rrset> {
        self.inner.lookup_all_rrsig(name, covered)
    }

    fn denial(&self) -> DenialKind {
        self.inner.denial()
    }

    fn nsec_at(&self, name: &Name) -> Option<Rrset> {
        self.inner.nsec_at(name)
    }

    fn nsec_cover(&self, name: &Name) -> Option<Rrset> {
        self.nsec
            .iter()
            .find(|rrset| {
                let owner = rrset.owner();
                let Some(next) = rrset.rdatas().iter().find_map(|rdata| match rdata {
                    Rdata::Nsec(nsec) => Some(nsec.next_domain()),
                    _ => None,
                }) else {
                    return false;
                };
                nsec_covers(owner, next, name)
            })
            .cloned()
    }

    fn nsec3_param(&self) -> Option<Rrset> {
        self.inner.nsec3_param()
    }

    fn nsec3_at(&self, hash: &[u8]) -> Option<Rrset> {
        self.inner.nsec3_at(hash)
    }

    fn nsec3_cover(&self, hash: &[u8]) -> Option<Rrset> {
        self.nsec3
            .iter()
            .find(|rrset| {
                let Some(label) = rrset.owner().first_label() else {
                    return false;
                };
                let Ok(owner) = pulse_dnssec::denial::base32hex::decode(label) else {
                    return false;
                };
                let Some(next) = rrset.rdatas().iter().find_map(|rdata| match rdata {
                    Rdata::Nsec3(data) => Some(data.next_hashed_owner()),
                    _ => None,
                }) else {
                    return false;
                };
                nsec3_covers(&owner, next, hash)
            })
            .cloned()
    }

    fn is_delegation(&self, name: &Name) -> bool {
        self.inner.is_delegation(name)
    }

    fn glue(&self, name: &Name) -> Vec<Rrset> {
        self.inner.glue(name)
    }

    fn node_exists(&self, name: &Name) -> bool {
        self.inner.node_exists(name)
    }
}

fn base_data(origin: &Name, zone: &mut InMemoryZone) {
    zone.insert(rrset(
        origin,
        Rtype::SOA,
        [Rdata::Soa(SoaData::new(
            name("ns1.example.com"),
            name("hostmaster.example.com"),
            Serial::new(1),
            3600,
            600,
            604_800,
            300,
        ))],
    ))
    .expect("soa");
    zone.insert(rrset(
        origin,
        Rtype::NS,
        [Rdata::Ns(name("ns1.example.com"))],
    ))
    .expect("ns");
    zone.insert(rrset(
        origin,
        Rtype::DNSKEY,
        [Rdata::Dnskey(
            DnskeyData::new(257, 3, 8, vec![7_u8; 32]).expect("dnskey"),
        )],
    ))
    .expect("dnskey");
    zone.insert(rrset(
        origin,
        Rtype::RRSIG,
        [Rdata::Rrsig(
            RrsigData::new(
                Rtype::DNSKEY,
                8,
                2,
                300,
                u32::MAX,
                1,
                1,
                origin.clone(),
                vec![9_u8; 64],
            )
            .expect("rrsig"),
        )],
    ))
    .expect("rrsig");
    let www = name("www.example.com");
    zone.insert(rrset(
        &www,
        Rtype::A,
        [Rdata::A("192.0.2.1".parse().expect("ip"))],
    ))
    .expect("positive A");
    zone.insert(rrset(
        origin,
        Rtype::A,
        [Rdata::A("192.0.2.254".parse().expect("ip"))],
    ))
    .expect("apex A");
}

fn owner_names(size: usize) -> Vec<Name> {
    let origin = name("example.com");
    let mut owners = Vec::with_capacity(size + 2);
    owners.push(origin);
    owners.push(name("www.example.com"));
    for index in 0..size {
        owners.push(name(&format!("n{index}.example.com")));
    }
    owners.sort_by(Name::cmp_canonical);
    owners.dedup();
    owners
}

fn nsec_zone(size: usize) -> (InMemoryZone, Vec<Rrset>) {
    let origin = name("example.com");
    let mut zone = InMemoryZone::new(origin.clone());
    base_data(&origin, &mut zone);
    let owners = owner_names(size);
    let bitmap =
        TypeBitmap::from_types([Rtype::A, Rtype::NS, Rtype::SOA, Rtype::NSEC, Rtype::RRSIG]);
    let mut denial = Vec::with_capacity(owners.len());
    for (index, owner) in owners.iter().enumerate() {
        let next = owners
            .get(index + 1)
            .cloned()
            .unwrap_or_else(|| origin.clone());
        let rr = rrset(
            owner,
            Rtype::NSEC,
            [Rdata::Nsec(
                pulse_dns::NsecData::new(next, bitmap.clone()).expect("nsec"),
            )],
        );
        zone.insert(rr.clone()).expect("insert nsec");
        denial.push(rr);
    }
    (zone, denial)
}

fn nsec3_zone(size: usize) -> (InMemoryZone, Vec<Rrset>) {
    let origin = name("example.com");
    let mut zone = InMemoryZone::new(origin.clone());
    base_data(&origin, &mut zone);
    let salt = vec![0xAA, 0xBB];
    zone.insert(rrset(
        &origin,
        Rtype::NSEC3PARAM,
        [Rdata::Nsec3Param(
            pulse_dns::Nsec3ParamData::new(1, 0, 0, salt.clone()).expect("param"),
        )],
    ))
    .expect("nsec3param");
    let owners = owner_names(size);
    let mut hashes: Vec<Vec<u8>> = owners
        .iter()
        .map(|owner| pulse_dnssec::rdata_util::nsec3_hash(owner, &salt, 0))
        .collect();
    hashes.sort();
    let bitmap = TypeBitmap::from_types([Rtype::A, Rtype::NS, Rtype::RRSIG]);
    let mut denial = Vec::with_capacity(hashes.len());
    for (index, hash) in hashes.iter().enumerate() {
        let next = hashes
            .get(index + 1)
            .cloned()
            .unwrap_or_else(|| hashes[0].clone());
        let owner = pulse_dnssec::denial::nsec3_owner_name(&origin, hash).expect("owner");
        let rr = rrset(
            &owner,
            Rtype::NSEC3,
            [Rdata::Nsec3(
                pulse_dns::Nsec3Data::new(1, 0, 0, salt.clone(), next, bitmap.clone())
                    .expect("nsec3"),
            )],
        );
        zone.insert(rr.clone()).expect("insert nsec3");
        denial.push(rr);
    }
    (zone, denial)
}

struct Stats {
    p50: u64,
    p99: u64,
    mean: f64,
}

fn measure(engine: &QueryEngine, request: &Message, iterations: usize) -> Stats {
    let mut scratch = Scratch::new();
    let mut out = vec![0_u8; 65_535];
    for _ in 0..(iterations / 10).max(1) {
        black_box(
            engine
                .respond_into(request, Transport::Udp, &mut out, &mut scratch)
                .expect("warmup response"),
        );
    }
    let mut samples = Vec::with_capacity(iterations);
    let start = Instant::now();
    for _ in 0..iterations {
        let begin = Instant::now();
        black_box(
            engine
                .respond_into(request, Transport::Udp, &mut out, &mut scratch)
                .expect("response"),
        );
        samples.push(u64::try_from(begin.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    let elapsed = start.elapsed().as_secs_f64();
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p99 = samples[(samples.len() * 99 / 100).min(samples.len() - 1)];
    Stats {
        p50,
        p99,
        mean: elapsed * 1e9 / iterations as f64,
    }
}

fn print_row(label: &str, stats: &Stats) {
    println!(
        "{label:<32} p50 {:>8.1} us  p99 {:>8.1} us  mean {:>8.1} us  qps {:>10.0}",
        stats.p50 as f64 / 1000.0,
        stats.p99 as f64 / 1000.0,
        stats.mean / 1000.0,
        1e9 / stats.mean,
    );
}

fn query(qname: &str, qtype: Rtype) -> Message {
    let mut message = Message::query(0x1234, Question::new(name(qname), qtype, Rclass::IN));
    message.set_edns(Some(Edns::new(1232).with_dnssec_ok(true)));
    message
}

fn main() {
    let size = std::env::var("PULSE_BENCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100_000);
    let iterations = std::env::var("PULSE_BENCH_ITERATIONS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20_000);
    let legacy_iterations = std::env::var("PULSE_BENCH_LEGACY_ITERS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50);
    println!("signed zone: {size} names + apex/www, {iterations} samples/query (DO=1)\n");

    for (label, build) in [
        ("NSEC", nsec_zone as fn(usize) -> (InMemoryZone, Vec<Rrset>)),
        ("NSEC3", nsec3_zone),
    ] {
        let started = Instant::now();
        let (zone, denial) = build(size);
        let zone = Arc::new(zone);
        let indexed = Arc::new(QueryEngine::new(vec![
            Arc::clone(&zone) as Arc<dyn ZoneView>
        ]));
        let linear = Arc::new(QueryEngine::new(vec![Arc::new(LinearView {
            inner: Arc::clone(&zone),
            nsec: denial
                .iter()
                .filter(|rrset| rrset.rr_type() == Rtype::NSEC)
                .cloned()
                .collect(),
            nsec3: denial
                .iter()
                .filter(|rrset| rrset.rr_type() == Rtype::NSEC3)
                .cloned()
                .collect(),
        }) as Arc<dyn ZoneView>]));
        println!(
            "{label}: zone built in {:.2} s\n",
            started.elapsed().as_secs_f64()
        );

        let miss = query(&format!("n{}x.example.com.", size / 2), Rtype::A);
        let hit = query("www.example.com.", Rtype::A);

        let new_neg = measure(&indexed, &miss, iterations);
        print_row(&format!("{label} NXDOMAIN indexed"), &new_neg);
        let old_neg = measure(&linear, &miss, legacy_iterations);
        print_row(&format!("{label} NXDOMAIN linear"), &old_neg);
        let new_pos = measure(&indexed, &hit, iterations);
        print_row(&format!("{label} A www indexed"), &new_pos);
        let old_pos = measure(&linear, &hit, iterations);
        print_row(&format!("{label} A www linear"), &old_pos);
        println!(
            "{label} speedup NXDOMAIN p99: {:.0}x, qps: {:.0}x; NXDOMAIN/positive p50: {:.1}x\n",
            old_neg.p99 as f64 / new_neg.p99.max(1) as f64,
            (1.0 / new_neg.mean) / (1.0 / old_neg.mean),
            new_neg.p50 as f64 / new_pos.p50.max(1) as f64,
        );
    }
}
