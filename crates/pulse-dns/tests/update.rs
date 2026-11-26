//! Wire round-trip UPDATE: delete-записи с CLASS ANY/NONE и пустой RDATA.

use pulse_dns::{
    DecodeLimits, EncodeOptions, Flags, Message, Name, Opcode, Question, Rclass, Rcode, Rdata,
    Record, Rtype, UpdateOp, UpdateRequest,
};

fn name(text: &str) -> Name {
    Name::parse(text).expect("name")
}

#[test]
fn update_metavalues_roundtrip_through_wire() {
    let mut message = Message::new(0x2136, Flags::new().with_opcode(Opcode::UPDATE));
    message.add_question(Question::new(name("example.com."), Rtype::SOA, Rclass::IN));
    message.add_authority(Record::update_metavalue(
        name("old.example.com."),
        Rtype::A,
        Rclass::ANY,
    ));
    message.add_authority(Record::update_metavalue(
        name("gone.example.com."),
        Rtype::ANY,
        Rclass::ANY,
    ));
    message.add_authority(Record::update_metavalue(
        name("old.example.com."),
        Rtype::AAAA,
        Rclass::NONE,
    ));

    let bytes = message
        .encode(&EncodeOptions::compressed())
        .expect("encode");
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).expect("decode");
    assert_eq!(decoded.authority().len(), 3);
    for record in decoded.authority() {
        assert_eq!(record.rdata().wire_len(), 0);
        assert!(matches!(record.rdata(), Rdata::Empty(_)));
    }
    let request = UpdateRequest::from_message(&decoded).expect("parse update");
    assert_eq!(request.zone_class(), Rclass::IN);
    assert_eq!(request.updates().len(), 3);
    assert!(matches!(request.updates()[0], UpdateOp::DeleteRrset { .. }));
    assert!(matches!(request.updates()[1], UpdateOp::DeleteName { .. }));
    assert!(matches!(
        request.updates()[2],
        UpdateOp::DeleteRecord { .. }
    ));
}

#[test]
fn response_echoes_update_zone() {
    let mut message = Message::new(1, Flags::new().with_opcode(Opcode::UPDATE));
    message.add_question(Question::new(name("example.com."), Rtype::SOA, Rclass::IN));
    let request = UpdateRequest::from_message(&message).expect("request");
    let response = request.response(Rcode::YXRRSET);
    let bytes = response
        .encode(&EncodeOptions::compressed())
        .expect("encode");
    let decoded = Message::decode(&bytes, &DecodeLimits::default()).expect("decode");
    assert_eq!(decoded.opcode(), Opcode::UPDATE);
    assert_eq!(decoded.rcode(), Rcode::YXRRSET);
    assert_eq!(decoded.questions().len(), 1);
    assert_eq!(decoded.questions()[0].qname(), &name("example.com."));
    assert_eq!(decoded.questions()[0].qtype(), Rtype::SOA);
}
