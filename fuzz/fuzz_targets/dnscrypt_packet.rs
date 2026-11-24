#![no_main]

//! DNSCrypt v2: `DnscryptServer::handle_udp` на мусоре и мутациях валидного
//! зашифрованного запроса. Ключи/сертификат детерминированы (`gen_seeds`).

use std::cell::RefCell;
use std::sync::Arc;

use libfuzzer_sys::fuzz_target;
use pulse_dnscrypt::{
    Certificate, CertificateParams, Clock, DnscryptServer, Error, ProviderKeypair, ResolverKeypair,
    ServerConfig,
};

const PROVIDER_SEED: [u8; 32] = [0x42; 32];
const RESOLVER_SECRET: [u8; 32] = [0x24; 32];
const CLIENT_MAGIC: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const NOW: u64 = 1_700_000_000;

/// Часы, зафиксированные на `NOW`: сертификат `gen_seeds` и фаззер видят
/// одинаковое время.
struct FixedClock;

impl Clock for FixedClock {
    fn now_unix_secs(&self) -> u64 {
        NOW
    }
}

thread_local! {
    static SERVER: RefCell<Option<DnscryptServer>> = const { RefCell::new(None) };
}

fn with_server<T>(f: impl FnOnce(&DnscryptServer) -> T) -> T {
    SERVER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = build_server().ok();
        }
        match slot.as_ref() {
            Some(server) => f(server),
            None => panic!("deterministic DNSCrypt server failed to initialise"),
        }
    })
}

fn build_server() -> Result<DnscryptServer, Error> {
    let provider = ProviderKeypair::from_seed(PROVIDER_SEED);
    let resolver = ResolverKeypair::from_secret_bytes(RESOLVER_SECRET);
    let params = CertificateParams::new(
        resolver.public_key().to_bytes(),
        CLIENT_MAGIC,
        1,
        u32::try_from(NOW).unwrap_or(u32::MAX),
        1_800_000_000,
    );
    let certificate = Certificate::sign(&provider, params)?;
    let mut server = DnscryptServer::with_clock(
        provider.public_key(),
        ServerConfig::default(),
        Arc::new(FixedClock),
    )?;
    server.add_certificate(certificate, resolver)?;
    Ok(server)
}

fn handler(query: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    Ok(query.to_vec())
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_535 {
        return;
    }
    with_server(|server| {
        let _ = server.handle_udp_at(data, NOW, &handler);
    });
});
