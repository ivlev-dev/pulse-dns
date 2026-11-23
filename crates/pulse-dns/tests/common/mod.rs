//! Общие конструкторы для интеграционных тестов.
#![allow(dead_code)]

use std::net::Ipv4Addr;

use pulse_dns::{
    Message, Name, Question, Rclass, Rdata, Record, Rtype, Serial, SoaData, Ttl, TxtData,
};

/// Разбирает имя (паникует только на заведомо валидных тестовых данных).
pub fn name(value: &str) -> Name {
    Name::parse(value).unwrap()
}

/// Создаёт TTL.
pub fn ttl(value: u32) -> Ttl {
    Ttl::new(value).unwrap()
}

/// Создаёт вопрос класса IN.
pub fn question(qname: &str, qtype: Rtype) -> Question {
    Question::new(name(qname), qtype, Rclass::IN)
}

/// Создаёт запись класса IN.
pub fn record(owner: &str, rr_type: Rtype, ttl_seconds: u32, rdata: Rdata) -> Record {
    Record::new(name(owner), rr_type, Rclass::IN, ttl(ttl_seconds), rdata).unwrap()
}

/// A-запись.
pub fn a_record(owner: &str, address: [u8; 4], ttl_seconds: u32) -> Record {
    record(
        owner,
        Rtype::A,
        ttl_seconds,
        Rdata::A(Ipv4Addr::from(address)),
    )
}

/// TXT-запись из одного сегмента.
pub fn txt_record(owner: &str, text: &[u8], ttl_seconds: u32) -> Record {
    record(
        owner,
        Rtype::TXT,
        ttl_seconds,
        Rdata::Txt(TxtData::new(vec![text.to_vec()]).unwrap()),
    )
}

/// SOA-запись.
pub fn soa_record(owner: &str, serial: u32, ttl_seconds: u32) -> Record {
    record(
        owner,
        Rtype::SOA,
        ttl_seconds,
        Rdata::Soa(SoaData::new(
            name("ns1.example.com"),
            name("hostmaster.example.com"),
            Serial::new(serial),
            3600,
            600,
            604_800,
            300,
        )),
    )
}

/// Ответ с одной A-записью в answer.
pub fn a_response(id: u16, address: [u8; 4]) -> Message {
    let request = Message::query(id, question("example.com", Rtype::A));
    let mut response = Message::response(&request);
    response.add_answer(a_record("example.com", address, 300));
    response
}
