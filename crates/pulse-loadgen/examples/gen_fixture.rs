//! Создаёт компактный v2-zonefile с именами `r%07d.z0.bench.test.` для
//! `pulse-alloc` (per-RRset запись, без bulk-API).

use pulse_dns::{Name, Rdata, Serial, SoaData};
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{
    ParallelStore, ParallelZones, RrsetData, StoreConfig, ZoneCreateMeta,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or("usage: gen_fixture <path> [rrsets]")?;
    let rrsets: u32 = args
        .next()
        .map_or(Ok(1000), |value| value.parse())
        .map_err(|_| "invalid rrsets")?;
    let _ = std::fs::remove_file(&path);
    let store = ParallelStore::create(
        std::path::Path::new(&path),
        StoreConfig {
            page_count_max: 1 << 20,
            ..StoreConfig::default()
        },
    )?;
    let apex = NameRle::from_ascii("z0.bench.test.")?;
    let mut zones = ParallelZones::open(&store)?;
    zones.create_zone(&apex, ZoneCreateMeta { soa_serial: 1 })?;
    let mut writer = zones.writer(&apex)?;
    let soa = Rdata::Soa(SoaData::new(
        Name::parse("ns1.z0.bench.test.")?,
        Name::parse("hostmaster.z0.bench.test.")?,
        Serial::new(1),
        3600,
        600,
        604_800,
        300,
    ))
    .to_canonical_wire();
    let ns = Rdata::Ns(Name::parse("ns1.z0.bench.test.")?).to_canonical_wire();
    writer.upsert_rrset(&apex, 6, 0, &RrsetData::new(3600, 0, vec![soa])?)?;
    writer.upsert_rrset(&apex, 2, 0, &RrsetData::new(3600, 0, vec![ns])?)?;
    for index in 0..rrsets {
        let owner = NameRle::from_ascii(&format!("r{index:07}.z0.bench.test."))?;
        let a = Rdata::A("192.0.2.1".parse()?).to_canonical_wire();
        writer.upsert_rrset(&owner, 1, 0, &RrsetData::new(60, 0, vec![a])?)?;
    }
    writer.commit()?;
    println!("generated {rrsets} A records at {path}");
    Ok(())
}
