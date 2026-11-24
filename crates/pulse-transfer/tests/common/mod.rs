//! Общие помощники интеграционных тестов.

#![allow(dead_code)]

use std::io::{Cursor, Read, Write};
use std::net::Ipv4Addr;

use pulse_dns::Name as DnsName;
use pulse_dns::{Rclass, Rdata, Record, Rtype, Serial, SoaData, Ttl};
use pulse_transfer::ZoneSnapshot;

pub struct MemoryStream {
    pub input: Cursor<Vec<u8>>,
    pub output: Vec<u8>,
}

impl MemoryStream {
    pub fn server(query: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(query),
            output: Vec::new(),
        }
    }

    pub fn client(server_output: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(server_output),
            output: Vec::new(),
        }
    }
}

impl Read for MemoryStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for MemoryStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn origin() -> DnsName {
    DnsName::parse("example.com").unwrap()
}

pub fn ttl() -> Ttl {
    Ttl::new(3600).unwrap()
}

pub fn soa_for(origin: &DnsName, serial: u32) -> Record {
    let mname = DnsName::parse("ns1.example.com").unwrap();
    let rname = DnsName::parse("hostmaster.example.com").unwrap();
    Record::new(
        origin.clone(),
        Rtype::SOA,
        Rclass::IN,
        ttl(),
        Rdata::Soa(SoaData::new(
            mname,
            rname,
            Serial::new(serial),
            7200,
            900,
            1_209_600,
            300,
        )),
    )
    .unwrap()
}

pub fn a_record(host: &str, index: u32) -> Record {
    let name = if host == "@" {
        origin()
    } else {
        DnsName::parse(&format!("{host}.example.com")).unwrap()
    };
    let address = Ipv4Addr::new(
        10,
        ((index >> 16) & 0xFF) as u8,
        ((index >> 8) & 0xFF) as u8,
        (index & 0xFF) as u8,
    );
    Record::new(name, Rtype::A, Rclass::IN, ttl(), Rdata::A(address)).unwrap()
}

pub fn build_zone(serial: u32, count: u32) -> ZoneSnapshot {
    let origin = origin();
    let mut records = vec![soa_for(&origin, serial)];
    for index in 0..count {
        records.push(a_record(&format!("host{index}"), index));
    }
    ZoneSnapshot::new(origin, records).unwrap()
}

pub fn build_small_zone(serial: u32) -> ZoneSnapshot {
    let origin = origin();
    let records = vec![
        soa_for(&origin, serial),
        a_record("www", 1),
        a_record("mail", 2),
    ];
    ZoneSnapshot::new(origin, records).unwrap()
}

pub fn make_key(name: &str, algorithm: pulse_transfer::TsigAlgorithm) -> pulse_transfer::TsigKey {
    pulse_transfer::TsigKey::new(
        DnsName::parse(name).unwrap(),
        algorithm,
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap()
}

pub fn default_key() -> pulse_transfer::TsigKey {
    make_key(
        "transfer-key.example.com",
        pulse_transfer::TsigAlgorithm::HmacSha256,
    )
}

pub const NOW: u64 = 1_700_000_000;

pub fn split_messages(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut messages = Vec::new();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let length = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        let start = offset + 2;
        messages.push(bytes[start..start + length].to_vec());
        offset = start + length;
    }
    messages
}

pub fn axfr_roundtrip(
    zone: &ZoneSnapshot,
    config: pulse_transfer::TransferConfig,
    key: Option<&pulse_transfer::TsigKey>,
) -> Result<ZoneSnapshot, pulse_transfer::TransferError> {
    let id = 0x5151;
    let base = pulse_transfer::build_axfr_query(id, zone.origin()).unwrap();
    let query = match key {
        Some(key) => {
            let record = key.sign_request(&base, id, NOW).unwrap();
            pulse_transfer::append_tsig(base, &record).unwrap()
        }
        None => base,
    };
    let mut framed = Vec::new();
    pulse_transfer::write_message(&mut framed, &query).unwrap();
    let mut server_stream = MemoryStream::server(framed);
    let server = pulse_transfer::AxfrServer::new(config);
    server.serve(&mut server_stream, zone, key, NOW)?;
    let mut client = pulse_transfer::AxfrClient::with_limits(
        MemoryStream::client(server_stream.output),
        config.limits,
    );
    client.transfer(zone.origin(), id, key, NOW)
}
