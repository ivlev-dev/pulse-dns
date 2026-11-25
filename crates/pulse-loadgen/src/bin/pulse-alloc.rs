//! `pulse-alloc` — аллокации на горячем пути (`dhat` counting allocator).
//!
//! Собирается только с `--features alloc`:
//!
//! ```text
//! cargo run -p pulse-loadgen --release --features alloc --bin pulse-alloc -- \
//!     --data target/bench/z1m.v2 --rrsets 1000000 --ops 20000 \
//!     --json-out target/bench/alloc.json
//! ```
//!
//! Отдельно измеряются `encode`, `decode`, `lookup` (материализация),
//! `lookup_ref` (zero-copy) и end-to-end UDP через in-process `pulsed`.

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::hint::black_box;
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rtype};
use pulse_loadgen::report::AllocRow;
use pulse_zonefile::key::NameRle;
use pulse_zonefile::parallel::{ParallelZones, open_read_only};
use pulsed::config::{Config, Durability};
use pulsed::server::Server;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[derive(Debug, Parser)]
#[command(
    name = "pulse-alloc",
    version,
    about = "Measure allocations per DNS operation with dhat"
)]
struct Args {
    /// Zonefile, сгенерированный `pulse-zonegen`.
    #[arg(long)]
    data: PathBuf,
    /// `RRset` на зону (для выбора имён).
    #[arg(long, default_value_t = 1000)]
    rrsets: u32,
    /// Операций на замер.
    #[arg(long, default_value_t = 10_000)]
    ops: u64,
    /// JSON-файл результата.
    #[arg(long)]
    json_out: Option<PathBuf>,
    /// Куда dhat сохранит heap-профиль.
    #[arg(long, default_value = "target/bench/dhat-heap.json")]
    dhat_out: PathBuf,
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), String> {
    let args = Args::parse();
    if let Some(parent) = args.dhat_out.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let _profiler = dhat::Profiler::builder().file_name(&args.dhat_out).build();
    let mut rows = Vec::new();

    let message = Message::query(
        0x1234,
        Question::new(
            Name::parse("r0.z0.bench.test.").expect("name"),
            Rtype::A,
            Rclass::IN,
        ),
    );
    rows.push(measure("encode", args.ops, || {
        black_box(
            message
                .encode(&EncodeOptions::compressed())
                .expect("encode"),
        );
    }));

    let encoded = Message::query(
        0x1234,
        Question::new(
            Name::parse("r0.z0.bench.test.").expect("name"),
            Rtype::A,
            Rclass::IN,
        ),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode");
    rows.push(measure("decode", args.ops, || {
        black_box(Message::decode(&encoded, &DecodeLimits::default()).expect("decode"));
    }));

    {
        let store = open_read_only(&args.data)
            .map_err(|error| format!("open {}: {error}", args.data.display()))?;
        let zones = ParallelZones::open(&store).map_err(|error| format!("catalog: {error}"))?;
        let origin = NameRle::from_ascii("z0.bench.test.").map_err(|error| error.to_string())?;
        let reader = store.reader().map_err(|error| format!("reader: {error}"))?;
        let zone = zones
            .read(&reader, &origin)
            .map_err(|error| format!("zone: {error}"))?;
        let names: Vec<NameRle> = (0..args.rrsets.max(4) / 4)
            .map(|index| {
                NameRle::from_ascii(&format!("r{}.z0.bench.test.", index * 4)).expect("record name")
            })
            .collect();
        let mut index = 0_usize;
        rows.push(measure("lookup", args.ops, || {
            let name = &names[index % names.len()];
            index = index.wrapping_add(1);
            black_box(zone.lookup(name, Rtype::A.as_u16(), 0).expect("lookup"));
        }));
        let mut index = 0_usize;
        rows.push(measure("lookup_ref", args.ops, || {
            let name = &names[index % names.len()];
            index = index.wrapping_add(1);
            black_box(
                zone.lookup_ref(name, Rtype::A.as_u16(), 0)
                    .expect("lookup_ref"),
            );
        }));
    }

    // End-to-end: сервер в этом же процессе, клиент — один сокет.
    let config = Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("addr")),
        listen_tcp: None,
        workers: 2,
        zonefile: Some(args.data.clone()),
        durability: Durability::Memory,
        journal: false,
        ..Config::default()
    };
    let mut server = Server::start(&config).map_err(|error| format!("server: {error}"))?;
    let address = server.udp_addr().ok_or("no udp addr")?;
    let socket = UdpSocket::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let query = Message::query(
        0x1234,
        Question::new(
            Name::parse("r0.z0.bench.test.").expect("name"),
            Rtype::A,
            Rclass::IN,
        ),
    )
    .encode(&EncodeOptions::compressed())
    .expect("encode");
    let mut buffer = [0_u8; 4096];
    rows.push(measure("udp-e2e", args.ops.min(20_000), || {
        socket.send_to(&query, address).expect("send");
        loop {
            match socket.recv_from(&mut buffer) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => panic!("recv: {error}"),
            }
        }
    }));
    server
        .shutdown()
        .map_err(|error| format!("shutdown: {error}"))?;

    if let Some(path) = &args.json_out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let json = serde_json::to_string_pretty(&rows).map_err(|error| error.to_string())?;
        std::fs::write(path, json).map_err(|error| error.to_string())?;
    }
    println!("operation      ops        allocs       bytes        allocs/op    bytes/op");
    for row in &rows {
        println!(
            "{:<14} {:<10} {:<12} {:<12} {:<12.4} {:<10.2}",
            row.op, row.ops, row.allocations, row.bytes, row.allocs_per_op, row.bytes_per_op
        );
    }
    Ok(())
}

fn measure(name: &str, ops: u64, mut function: impl FnMut()) -> AllocRow {
    let ops = ops.max(1);
    let warmup = (ops / 10).clamp(10, 1_000);
    for _ in 0..warmup {
        function();
    }
    let before = dhat::HeapStats::get();
    for _ in 0..ops {
        function();
    }
    let after = dhat::HeapStats::get();
    let allocations = after.total_blocks.saturating_sub(before.total_blocks);
    let bytes = after.total_bytes.saturating_sub(before.total_bytes);
    #[allow(clippy::cast_precision_loss)]
    let allocs_per_op = allocations as f64 / ops as f64;
    #[allow(clippy::cast_precision_loss)]
    let bytes_per_op = bytes as f64 / ops as f64;
    AllocRow {
        op: name.to_owned(),
        ops,
        allocations,
        bytes,
        allocs_per_op,
        bytes_per_op,
    }
}
