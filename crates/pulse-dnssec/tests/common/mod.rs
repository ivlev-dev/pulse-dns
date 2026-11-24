//! Общие конструкторы для интеграционных тестов.
#![allow(dead_code)]

use std::net::Ipv4Addr;

use pulse_dns::{DnskeyData, Name, Rclass, Rdata, Record, Rrset, RrsigData, Rtype, Ttl, TxtData};
use pulse_dnssec::{PrivateKey, SignOptions, sign_rrset};

/// Фиксированное «сейчас» для тестов (2023-11-14T22:13:20Z).
pub const NOW: u32 = 1_700_000_000;

pub fn name(value: &str) -> Name {
    Name::parse(value).unwrap()
}

pub fn ttl(seconds: u32) -> Ttl {
    Ttl::new(seconds).unwrap()
}

pub fn a_rrset(owner: &str, addresses: &[[u8; 4]], ttl_seconds: u32) -> Rrset {
    let rdatas = addresses
        .iter()
        .map(|address| Rdata::A(Ipv4Addr::from(*address)))
        .collect::<Vec<_>>();
    Rrset::new(name(owner), Rtype::A, Rclass::IN, ttl(ttl_seconds), rdatas).unwrap()
}

pub fn txt_rrset(owner: &str, texts: &[&[u8]], ttl_seconds: u32) -> Rrset {
    let rdatas = texts
        .iter()
        .map(|text| Rdata::Txt(TxtData::new(vec![text.to_vec()]).unwrap()))
        .collect::<Vec<_>>();
    Rrset::new(
        name(owner),
        Rtype::TXT,
        Rclass::IN,
        ttl(ttl_seconds),
        rdatas,
    )
    .unwrap()
}

pub fn dnskey_rrset(zone: &str, keys: &[(&PrivateKey, u16)]) -> Rrset {
    let rdatas = keys
        .iter()
        .map(|(key, flags)| Rdata::Dnskey(key.dnskey(*flags).unwrap()))
        .collect::<Vec<_>>();
    Rrset::new(name(zone), Rtype::DNSKEY, Rclass::IN, ttl(3600), rdatas).unwrap()
}

pub fn dnskey_of(key: &PrivateKey, flags: u16) -> DnskeyData {
    key.dnskey(flags).unwrap()
}

pub fn sign(
    key: &PrivateKey,
    rrset: &Rrset,
    signer: &str,
    flags: u16,
    now: u32,
    validity: u32,
) -> RrsigData {
    let options = SignOptions::new(name(signer), now, validity).with_dnskey_flags(flags);
    sign_rrset(key, rrset, &options).unwrap()
}

pub fn rrsig_record(owner: &str, rrsig: &RrsigData, ttl_seconds: u32) -> Record {
    Record::new(
        name(owner),
        Rtype::RRSIG,
        Rclass::IN,
        ttl(ttl_seconds),
        Rdata::Rrsig(rrsig.clone()),
    )
    .unwrap()
}

pub fn dnskey_records(zone: &str, keys: &[(&PrivateKey, u16)]) -> Vec<Record> {
    keys.iter()
        .map(|(key, flags)| {
            Record::new(
                name(zone),
                Rtype::DNSKEY,
                Rclass::IN,
                ttl(3600),
                Rdata::Dnskey(key.dnskey(*flags).unwrap()),
            )
            .unwrap()
        })
        .collect()
}

/// Пересобирает RRSIG с изменённым полем (для tamper-тестов).
pub fn rrsig_with(rrsig: &RrsigData, mutate: impl FnOnce(&mut Vec<u8>)) -> RrsigData {
    let mut signature = rrsig.signature().to_vec();
    mutate(&mut signature);
    RrsigData::new(
        rrsig.type_covered(),
        rrsig.algorithm(),
        rrsig.labels(),
        rrsig.original_ttl(),
        rrsig.signature_expiration(),
        rrsig.signature_inception(),
        rrsig.key_tag(),
        rrsig.signer_name().clone(),
        signature,
    )
    .unwrap()
}
