//! Пример AXFR-сессии поверх in-memory pipe с TSIG.
//!
//! Запуск: `cargo run -p pulse-transfer --example axfr_session`.

use std::io::{Cursor, Read, Write};
use std::net::Ipv4Addr;

use pulse_dns::{Name, Rclass, Rdata, Record, Rtype, Serial, SoaData, Ttl};
use pulse_transfer::{
    AxfrClient, AxfrServer, TransferConfig, TsigAlgorithm, TsigKey, ZoneSnapshot, append_tsig,
    build_axfr_query, write_message,
};

const NOW: u64 = 1_700_000_000;

struct Pipe {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Pipe {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
        }
    }
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let origin = Name::parse("example.com")?;
    let ttl = Ttl::new(3600)?;
    let soa = Record::new(
        origin.clone(),
        Rtype::SOA,
        Rclass::IN,
        ttl,
        Rdata::Soa(SoaData::new(
            Name::parse("ns1.example.com")?,
            Name::parse("hostmaster.example.com")?,
            Serial::new(2_026_112_401),
            7200,
            900,
            1_209_600,
            300,
        )),
    )?;
    let www = Record::new(
        Name::parse("www.example.com")?,
        Rtype::A,
        Rclass::IN,
        ttl,
        Rdata::A(Ipv4Addr::new(192, 0, 2, 10)),
    )?;
    let mail = Record::new(
        Name::parse("mail.example.com")?,
        Rtype::A,
        Rclass::IN,
        ttl,
        Rdata::A(Ipv4Addr::new(192, 0, 2, 30)),
    )?;
    let mut records = vec![soa, www, mail];
    for index in 0..20_u32 {
        records.push(Record::new(
            Name::parse(&format!("host{index}.example.com"))?,
            Rtype::A,
            Rclass::IN,
            ttl,
            Rdata::A(Ipv4Addr::new(192, 0, 2, 100 + u8::try_from(index)?)),
        )?);
    }
    let zone = ZoneSnapshot::new(origin.clone(), records)?;

    let key = TsigKey::new(
        Name::parse("transfer-key.example.com")?,
        TsigAlgorithm::HmacSha256,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )?;

    let id = 0x1234;
    let base = build_axfr_query(id, &origin)?;
    let request_tsig = key.sign_request(&base, id, NOW)?;
    let request = append_tsig(base, &request_tsig)?;
    let mut framed = Vec::new();
    write_message(&mut framed, &request)?;

    let mut server_pipe = Pipe::new(framed);
    let server = AxfrServer::new(TransferConfig {
        message_bytes: 256,
        tsig_every: 1,
        require_tsig: true,
        ..TransferConfig::default()
    });
    let stats = server.serve(&mut server_pipe, &zone, Some(&key), NOW)?;
    println!(
        "server: {} messages, {} records, {} bytes",
        stats.messages, stats.records, stats.bytes
    );

    let client_pipe = Pipe::new(server_pipe.output);
    let mut client = AxfrClient::new(client_pipe);
    let received = client.transfer(&origin, id, Some(&key), NOW)?;
    println!(
        "client: origin={}, serial={}, records={}",
        received.origin(),
        received.serial(),
        received.records().len()
    );
    assert_eq!(received, zone);
    println!("round-trip OK");
    Ok(())
}
