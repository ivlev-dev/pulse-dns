//! Общая тестовая обвязка.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use pulse_dns::{Message, Name, Question, Rclass, Rtype};
use pulse_dnscrypt::{
    Certificate, CertificateParams, DnscryptClient, DnscryptServer, ProviderKeypair,
    ResolverKeypair, ServerConfig,
};

pub const NOW: u64 = 1_700_000_000;
pub const TS_START: u32 = 1_690_000_000;
pub const TS_END: u32 = 1_800_000_000;
pub const CLIENT_MAGIC: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

pub struct Fixture {
    pub provider: ProviderKeypair,
    pub resolver: ResolverKeypair,
    pub certificate: Certificate,
    pub server: DnscryptServer,
    pub client: DnscryptClient,
}

pub fn fixture() -> Fixture {
    let provider = ProviderKeypair::from_seed([0x11; 32]);
    let resolver = ResolverKeypair::from_secret_bytes([0x22; 32]);
    let certificate = certificate_for(&provider, &resolver, 1, CLIENT_MAGIC);
    let mut server = DnscryptServer::new(provider.public_key(), ServerConfig::default()).unwrap();
    server
        .add_certificate(certificate.clone(), resolver.clone())
        .unwrap();
    let client = DnscryptClient::new(certificate.clone(), provider.public_key(), NOW).unwrap();
    Fixture {
        provider,
        resolver,
        certificate,
        server,
        client,
    }
}

pub fn certificate_for(
    provider: &ProviderKeypair,
    resolver: &ResolverKeypair,
    serial: u32,
    magic: [u8; 8],
) -> Certificate {
    let params = CertificateParams::new(
        resolver.public_key().to_bytes(),
        magic,
        serial,
        TS_START,
        TS_END,
    );
    Certificate::sign(provider, params).unwrap()
}

pub fn dns_query() -> Vec<u8> {
    let question = Question::new(Name::parse("example.com").unwrap(), Rtype::A, Rclass::IN);
    Message::query(0x1234, question)
        .encode(&pulse_dns::EncodeOptions::default())
        .unwrap()
}

#[allow(clippy::unnecessary_wraps)]
pub fn echo_handler(query: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    Ok(query.to_vec())
}
