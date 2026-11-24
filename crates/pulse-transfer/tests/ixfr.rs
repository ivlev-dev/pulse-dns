//! Тесты IXFR.

mod common;

use common::*;
use pulse_dns::{
    DecodeLimits, EncodeOptions, Flags, Message, Opcode, Question, Rclass, Rtype, Serial,
};
use pulse_transfer::{
    IxfrClient, IxfrOutcome, IxfrServer, TransferConfig, TransferError, ZoneDelta, ZoneHistory,
    ZoneSnapshot, apply_ixfr, build_ixfr_query, write_message,
};

fn zone_with(serial: u32, records: Vec<pulse_dns::Record>) -> ZoneSnapshot {
    let origin = origin();
    let mut all = vec![soa_for(&origin, serial)];
    all.extend(records);
    ZoneSnapshot::new(origin, all).unwrap()
}

fn run_ixfr(
    current: &ZoneSnapshot,
    history: &ZoneHistory,
    client_soa: &pulse_dns::Record,
    config: TransferConfig,
    key: Option<&pulse_transfer::TsigKey>,
) -> Result<IxfrOutcome, TransferError> {
    let id = 0x7777;
    let base = build_ixfr_query(id, &origin(), client_soa).unwrap();
    let query = match key {
        Some(key) => {
            let record = key.sign_request(&base, id, NOW).unwrap();
            pulse_transfer::append_tsig(base, &record).unwrap()
        }
        None => base,
    };
    let mut framed = Vec::new();
    write_message(&mut framed, &query).unwrap();
    let mut server_stream = MemoryStream::server(framed);
    IxfrServer::new(config).serve(&mut server_stream, current, history, key, NOW)?;
    let mut client =
        IxfrClient::with_limits(MemoryStream::client(server_stream.output), config.limits);
    client.transfer(&origin(), client_soa, id, key, NOW)
}

fn unsigned_config() -> TransferConfig {
    TransferConfig {
        require_tsig: false,
        message_bytes: 512,
        ..TransferConfig::default()
    }
}

fn force_ixfr_config() -> TransferConfig {
    TransferConfig {
        require_tsig: false,
        message_bytes: 512,
        allow_axfr_fallback: false,
        ..TransferConfig::default()
    }
}

fn response_wire(id: u16, answers: Vec<pulse_dns::Record>) -> Vec<u8> {
    let mut message = Message::new(
        id,
        Flags::new()
            .with_qr(true)
            .with_aa(true)
            .with_opcode(Opcode::QUERY),
    );
    message.add_question(Question::new(origin(), Rtype::IXFR, Rclass::IN));
    for record in answers {
        message.add_answer(record);
    }
    let body = message.encode(&EncodeOptions::default()).unwrap();
    let mut out = Vec::new();
    write_message(&mut out, &body).unwrap();
    out
}

fn fetch_error(wire: Vec<u8>, client_soa: &pulse_dns::Record) -> TransferError {
    let mut client =
        IxfrClient::with_limits(MemoryStream::client(wire), TransferConfig::default().limits);
    client
        .transfer(&origin(), client_soa, 0x7777, None, NOW)
        .unwrap_err()
}

#[test]
fn multiple_deltas_apply_to_current_zone() {
    let base = zone_with(1, vec![a_record("www", 1), a_record("mail", 2)]);
    let middle = zone_with(2, vec![a_record("www", 1), a_record("api", 3)]);
    let current = zone_with(3, vec![a_record("api", 3), a_record("cdn", 4)]);
    let delta1 = ZoneDelta::new(
        base.soa().clone(),
        middle.soa().clone(),
        vec![a_record("mail", 2)],
        vec![a_record("api", 3)],
    )
    .unwrap();
    let delta2 = ZoneDelta::new(
        middle.soa().clone(),
        current.soa().clone(),
        vec![a_record("www", 1)],
        vec![a_record("cdn", 4)],
    )
    .unwrap();
    let mut history = ZoneHistory::new();
    history.push(delta1).unwrap();
    history.push(delta2).unwrap();

    let outcome = run_ixfr(&current, &history, base.soa(), force_ixfr_config(), None).unwrap();
    match outcome {
        IxfrOutcome::Incremental {
            from,
            current: soa,
            deltas,
        } => {
            assert_eq!(from, Serial::new(1));
            assert_eq!(soa, *current.soa());
            assert_eq!(deltas.len(), 2);
            assert_eq!(apply_ixfr(&base, &deltas).unwrap(), current);
        }
        other => panic!("unexpected outcome {other:?}"),
    }
}

#[test]
fn single_delta() {
    let base = zone_with(10, vec![a_record("www", 1)]);
    let current = zone_with(11, vec![a_record("www", 1), a_record("api", 2)]);
    let delta = ZoneDelta::new(
        base.soa().clone(),
        current.soa().clone(),
        vec![],
        vec![a_record("api", 2)],
    )
    .unwrap();
    let mut history = ZoneHistory::new();
    history.push(delta).unwrap();
    let outcome = run_ixfr(&current, &history, base.soa(), force_ixfr_config(), None).unwrap();
    let IxfrOutcome::Incremental { deltas, .. } = outcome else {
        panic!("expected incremental");
    };
    assert_eq!(deltas.len(), 1);
    assert_eq!(apply_ixfr(&base, &deltas).unwrap(), current);
}

#[test]
fn up_to_date_returns_single_soa() {
    let current = zone_with(5, vec![a_record("www", 1)]);
    let history = ZoneHistory::new();
    let outcome = run_ixfr(&current, &history, current.soa(), unsigned_config(), None).unwrap();
    assert!(matches!(
        outcome,
        IxfrOutcome::UpToDate { soa } if &soa == current.soa()
    ));
}

#[test]
fn client_newer_than_server_returns_server_soa() {
    let current = zone_with(5, vec![a_record("www", 1)]);
    let future = zone_with(6, vec![a_record("www", 1)]);
    let history = ZoneHistory::new();
    let outcome = run_ixfr(&current, &history, future.soa(), unsigned_config(), None).unwrap();
    assert!(matches!(
        outcome,
        IxfrOutcome::UpToDate { soa } if soa == *current.soa()
    ));
}

#[test]
fn unknown_serial_falls_back_to_axfr() {
    let current = zone_with(5, vec![a_record("www", 1)]);
    let old = zone_with(0, vec![a_record("www", 1)]);
    let history = ZoneHistory::new();
    let outcome = run_ixfr(&current, &history, old.soa(), unsigned_config(), None).unwrap();
    match outcome {
        IxfrOutcome::AxfrFallback { zone } => assert_eq!(zone, current),
        other => panic!("unexpected outcome {other:?}"),
    }
}

#[test]
fn large_delta_falls_back_to_axfr() {
    let base = zone_with(1, vec![a_record("www", 1)]);
    let middle = zone_with(2, vec![a_record("www", 1)]);
    let current = zone_with(3, vec![a_record("cdn", 4)]);
    let mut deletions = Vec::new();
    for index in 0..100 {
        deletions.push(a_record(&format!("old{index}"), index));
    }
    let delta1 =
        ZoneDelta::new(base.soa().clone(), middle.soa().clone(), deletions, vec![]).unwrap();
    let delta2 = ZoneDelta::new(
        middle.soa().clone(),
        current.soa().clone(),
        vec![a_record("www", 1)],
        vec![a_record("cdn", 4)],
    )
    .unwrap();
    let mut history = ZoneHistory::new();
    history.push(delta1).unwrap();
    history.push(delta2).unwrap();
    let outcome = run_ixfr(&current, &history, base.soa(), unsigned_config(), None).unwrap();
    assert!(matches!(outcome, IxfrOutcome::AxfrFallback { .. }));
}

#[test]
fn invalid_old_serial_is_rejected() {
    let current = zone_with(3, vec![a_record("cdn", 4)]);
    let wrong_old = soa_for(&origin(), 99);
    let wire = response_wire(
        0x7777,
        vec![current.soa().clone(), wrong_old, current.soa().clone()],
    );
    let error = fetch_error(wire, &soa_for(&origin(), 1));
    assert!(matches!(error, TransferError::Serial { .. }));
}

#[test]
fn broken_delta_sequence_is_rejected() {
    let current = zone_with(3, vec![a_record("cdn", 4)]);
    let old = soa_for(&origin(), 1);
    let new = soa_for(&origin(), 2);
    let broken = soa_for(&origin(), 99);
    let wire = response_wire(
        0x7777,
        vec![
            current.soa().clone(),
            old,
            new,
            broken,
            current.soa().clone(),
        ],
    );
    let error = fetch_error(wire, &soa_for(&origin(), 1));
    assert!(matches!(error, TransferError::Serial { .. }));
}

#[test]
fn missing_final_soa_is_truncated() {
    let current = zone_with(3, vec![a_record("cdn", 4)]);
    let old = soa_for(&origin(), 1);
    let new = soa_for(&origin(), 2);
    let wire = response_wire(0x7777, vec![current.soa().clone(), old, new]);
    let error = fetch_error(wire, &soa_for(&origin(), 1));
    assert!(matches!(error, TransferError::Truncated { .. }));
}

#[test]
fn serial_wrap_around_is_supported() {
    let base = zone_with(0xFFFF_FFFE, vec![a_record("www", 1)]);
    let current = zone_with(1, vec![a_record("www", 1), a_record("cdn", 2)]);
    let delta = ZoneDelta::new(
        base.soa().clone(),
        current.soa().clone(),
        vec![],
        vec![a_record("cdn", 2)],
    )
    .unwrap();
    let mut history = ZoneHistory::new();
    history.push(delta).unwrap();
    let outcome = run_ixfr(&current, &history, base.soa(), force_ixfr_config(), None).unwrap();
    let IxfrOutcome::Incremental { deltas, .. } = outcome else {
        panic!("expected incremental");
    };
    assert_eq!(apply_ixfr(&base, &deltas).unwrap(), current);
}

#[test]
fn history_rejects_gap() {
    let base = zone_with(1, vec![]);
    let middle = zone_with(2, vec![]);
    let current = zone_with(3, vec![]);
    let delta1 = ZoneDelta::new(base.soa().clone(), middle.soa().clone(), vec![], vec![]).unwrap();
    let delta_gap =
        ZoneDelta::new(current.soa().clone(), soa_for(&origin(), 4), vec![], vec![]).unwrap();
    let mut history = ZoneHistory::new();
    history.push(delta1).unwrap();
    assert!(matches!(
        history.push(delta_gap),
        Err(TransferError::Serial { .. })
    ));
}

#[test]
fn ixfr_with_tsig_chain_over_multiple_messages() {
    let base = zone_with(1, vec![a_record("www", 1)]);
    let mut current_records = vec![a_record("www", 1)];
    let mut delta_additions = Vec::new();
    for index in 0..200 {
        let record = a_record(&format!("new{index}"), index);
        delta_additions.push(record.clone());
        current_records.push(record);
    }
    let current = zone_with(2, current_records);
    let delta = ZoneDelta::new(
        base.soa().clone(),
        current.soa().clone(),
        vec![],
        delta_additions,
    )
    .unwrap();
    let mut history = ZoneHistory::new();
    history.push(delta).unwrap();
    let key = default_key();
    let config = TransferConfig {
        message_bytes: 256,
        tsig_every: 2,
        require_tsig: true,
        allow_axfr_fallback: false,
        ..TransferConfig::default()
    };
    let outcome = run_ixfr(&current, &history, base.soa(), config, Some(&key)).unwrap();
    let IxfrOutcome::Incremental { deltas, .. } = outcome else {
        panic!("expected incremental");
    };
    assert_eq!(apply_ixfr(&base, &deltas).unwrap(), current);
}

#[test]
fn ixfr_server_requires_client_soa() {
    let current = zone_with(3, vec![a_record("cdn", 4)]);
    let mut query = Message::query(0x7777, Question::new(origin(), Rtype::IXFR, Rclass::IN));
    query.set_opcode(Opcode::QUERY);
    let body = query.encode(&EncodeOptions::default()).unwrap();
    let mut framed = Vec::new();
    write_message(&mut framed, &body).unwrap();
    let mut stream = MemoryStream::server(framed);
    let error = IxfrServer::new(unsigned_config())
        .serve(&mut stream, &current, &ZoneHistory::new(), None, NOW)
        .unwrap_err();
    assert!(matches!(error, TransferError::Protocol { .. }));
    let messages = split_messages(&stream.output);
    let response = Message::decode(&messages[0], &DecodeLimits::default()).unwrap();
    assert_eq!(response.rcode(), pulse_dns::Rcode::FORMERR);
}
