//! Тесты движка UPDATE на in-memory транзакционном порте.

use std::collections::HashMap;

use pulse_dns::domain::{Flags, Message, Opcode, Question};
use pulse_dns::{
    Name, Rclass, Rcode, Rdata, Record, Rrset, Rtype, Serial, SoaData, Ttl, UpdateError,
    UpdateRequest,
};
use pulse_server::update::{UpdateOutcome, UpdateTarget, apply_update};

struct MemoryTarget {
    origin: Name,
    class: Rclass,
    rrsets: HashMap<(String, u16), Rrset>,
}

impl MemoryTarget {
    fn new(origin: &str) -> Self {
        Self {
            origin: Name::parse(origin).unwrap(),
            class: Rclass::IN,
            rrsets: HashMap::new(),
        }
    }

    fn with_soa(mut self, serial: u32) -> Self {
        self.put(&soa_rrset(&self.origin, serial, 3600, 300));
        self
    }

    fn put(&mut self, rrset: &Rrset) {
        self.rrsets.insert(
            (rrset.owner().to_string(), rrset.rr_type().as_u16()),
            rrset.clone(),
        );
    }

    fn get(&self, name: &str, rr_type: Rtype) -> Option<&Rrset> {
        let name = Name::parse(name).unwrap().to_string();
        self.rrsets.get(&(name, rr_type.as_u16()))
    }

    fn names(&self) -> usize {
        self.rrsets.len()
    }
}

impl UpdateTarget for MemoryTarget {
    fn origin(&self) -> &Name {
        &self.origin
    }

    fn zone_class(&self) -> Rclass {
        self.class
    }

    fn rrset(&mut self, name: &Name, rr_type: Rtype) -> Result<Option<Rrset>, UpdateError> {
        Ok(self.get(&name.to_string(), rr_type).cloned())
    }

    fn types_at(&mut self, name: &Name) -> Result<Vec<Rtype>, UpdateError> {
        let owner = name.to_string();
        let mut types: Vec<Rtype> = self
            .rrsets
            .iter()
            .filter(|((candidate, _), _)| candidate == &owner)
            .map(|((_, rr_type), _)| Rtype::from_u16(*rr_type))
            .collect();
        types.sort();
        types.dedup();
        Ok(types)
    }

    fn put_rrset(&mut self, rrset: &Rrset) -> Result<(), UpdateError> {
        self.put(rrset);
        Ok(())
    }

    fn delete_rrset(&mut self, name: &Name, rr_type: Rtype) -> Result<(), UpdateError> {
        self.rrsets.remove(&(name.to_string(), rr_type.as_u16()));
        Ok(())
    }
}

fn soa_rrset(origin: &Name, serial: u32, ttl: u32, minimum: u32) -> Rrset {
    Rrset::new(
        origin.clone(),
        Rtype::SOA,
        Rclass::IN,
        Ttl::new(ttl).unwrap(),
        [Rdata::Soa(SoaData::new(
            Name::parse("ns1.example.com").unwrap(),
            Name::parse("hostmaster.example.com").unwrap(),
            Serial::new(serial),
            7200,
            900,
            86_400,
            minimum,
        ))],
    )
    .unwrap()
}

fn ns_rrset(origin: &Name, target: &str) -> Rrset {
    Rrset::new(
        origin.clone(),
        Rtype::NS,
        Rclass::IN,
        Ttl::new(3600).unwrap(),
        [Rdata::Ns(Name::parse(target).unwrap())],
    )
    .unwrap()
}

fn request(zone: &str) -> Message {
    let mut message = Message::new(1, Flags::new().with_opcode(Opcode::UPDATE));
    message.add_question(Question::new(
        Name::parse(zone).unwrap(),
        Rtype::SOA,
        Rclass::IN,
    ));
    message
}

fn add_a(message: &mut Message, owner: &str, address: &str, ttl: u32) {
    message.add_authority(
        Record::new(
            Name::parse(owner).unwrap(),
            Rtype::A,
            Rclass::IN,
            Ttl::new(ttl).unwrap(),
            Rdata::A(address.parse().unwrap()),
        )
        .unwrap(),
    );
}

fn meta(message: &mut Message, owner: &str, rr_type: Rtype, class: Rclass) {
    message.add_authority(Record::update_metavalue(
        Name::parse(owner).unwrap(),
        rr_type,
        class,
    ));
}

fn delete_a(message: &mut Message, owner: &str, address: &str) {
    message.add_authority(
        Record::new(
            Name::parse(owner).unwrap(),
            Rtype::A,
            Rclass::NONE,
            Ttl::ZERO,
            Rdata::A(address.parse().unwrap()),
        )
        .unwrap(),
    );
}

fn zone() -> MemoryTarget {
    let origin = Name::parse("example.com").unwrap();
    let mut target = MemoryTarget::new("example.com").with_soa(1);
    target.put(&ns_rrset(&origin, "ns1.example.com"));
    target
}

fn apply(target: &mut MemoryTarget, message: &Message) -> Result<UpdateOutcome, UpdateError> {
    let request = UpdateRequest::from_message(message).unwrap();
    apply_update(target, &request)
}

#[test]
fn add_a_and_bump_serial() {
    let mut target = zone();
    let mut message = request("example.com");
    add_a(&mut message, "www.example.com", "192.0.2.1", 300);
    let outcome = apply(&mut target, &message).unwrap();
    assert_eq!(outcome.serial, Serial::new(2));
    assert!(outcome.changed);
    let rrset = target.get("www.example.com", Rtype::A).unwrap();
    assert_eq!(rrset.ttl(), Ttl::new(300).unwrap());
    assert_eq!(rrset.len(), 1);
}

#[test]
fn add_to_existing_rrset_keeps_ttl_and_deduplicates() {
    let mut target = zone();
    let mut first = request("example.com");
    add_a(&mut first, "www.example.com", "192.0.2.1", 300);
    apply(&mut target, &first).unwrap();

    let mut second = request("example.com");
    add_a(&mut second, "www.example.com", "192.0.2.2", 60);
    add_a(&mut second, "www.example.com", "192.0.2.1", 60);
    apply(&mut target, &second).unwrap();
    let rrset = target.get("www.example.com", Rtype::A).unwrap();
    assert_eq!(rrset.ttl(), Ttl::new(300).unwrap());
    assert_eq!(rrset.len(), 2);
}

#[test]
fn delete_rr_rrset_and_name() {
    let mut target = zone();
    let mut setup = request("example.com");
    add_a(&mut setup, "a.example.com", "192.0.2.1", 300);
    add_a(&mut setup, "a.example.com", "192.0.2.2", 300);
    add_a(&mut setup, "b.example.com", "192.0.2.3", 300);
    apply(&mut target, &setup).unwrap();

    let mut delete_one = request("example.com");
    delete_a(&mut delete_one, "a.example.com", "192.0.2.1");
    apply(&mut target, &delete_one).unwrap();
    assert_eq!(target.get("a.example.com", Rtype::A).unwrap().len(), 1);

    let mut delete_set = request("example.com");
    meta(&mut delete_set, "a.example.com", Rtype::A, Rclass::ANY);
    apply(&mut target, &delete_set).unwrap();
    assert!(target.get("a.example.com", Rtype::A).is_none());

    let mut delete_name = request("example.com");
    meta(&mut delete_name, "b.example.com", Rtype::ANY, Rclass::ANY);
    apply(&mut target, &delete_name).unwrap();
    assert!(target.get("b.example.com", Rtype::A).is_none());
}

#[test]
fn prerequisites_map_to_rcodes() {
    let mut target = zone();
    let mut message = request("example.com");
    message.add_answer(Record::update_metavalue(
        Name::parse("absent.example.com").unwrap(),
        Rtype::ANY,
        Rclass::ANY,
    ));
    let error = apply(&mut target, &message).unwrap_err();
    assert_eq!(error.rcode(), Rcode::NXDOMAIN);

    let mut message = request("example.com");
    message.add_answer(Record::update_metavalue(
        Name::parse("example.com").unwrap(),
        Rtype::ANY,
        Rclass::NONE,
    ));
    let error = apply(&mut target, &message).unwrap_err();
    assert_eq!(error.rcode(), Rcode::YXDOMAIN);

    let mut message = request("example.com");
    message.add_answer(Record::update_metavalue(
        Name::parse("example.com").unwrap(),
        Rtype::A,
        Rclass::ANY,
    ));
    let error = apply(&mut target, &message).unwrap_err();
    assert_eq!(error.rcode(), Rcode::NXRRSET);

    let mut message = request("example.com");
    message.add_answer(Record::update_metavalue(
        Name::parse("example.com").unwrap(),
        Rtype::SOA,
        Rclass::NONE,
    ));
    let error = apply(&mut target, &message).unwrap_err();
    assert_eq!(error.rcode(), Rcode::YXRRSET);
}

#[test]
fn value_dependent_prerequisite_ignores_ttl() {
    let mut target = zone();
    let mut setup = request("example.com");
    add_a(&mut setup, "www.example.com", "192.0.2.1", 300);
    apply(&mut target, &setup).unwrap();

    let mut message = request("example.com");
    message.add_answer(
        Record::new(
            Name::parse("www.example.com").unwrap(),
            Rtype::A,
            Rclass::IN,
            Ttl::ZERO,
            Rdata::A("192.0.2.1".parse().unwrap()),
        )
        .unwrap(),
    );
    message.add_authority(Record::update_metavalue(
        Name::parse("www.example.com").unwrap(),
        Rtype::A,
        Rclass::ANY,
    ));
    apply(&mut target, &message).unwrap();
    assert!(target.get("www.example.com", Rtype::A).is_none());

    let mut mismatch = request("example.com");
    mismatch.add_answer(
        Record::new(
            Name::parse("www.example.com").unwrap(),
            Rtype::A,
            Rclass::IN,
            Ttl::ZERO,
            Rdata::A("192.0.2.9".parse().unwrap()),
        )
        .unwrap(),
    );
    let error = apply(&mut target, &mismatch).unwrap_err();
    assert_eq!(error.rcode(), Rcode::NXRRSET);
}

#[test]
fn cname_invariants_ignore_conflicting_add() {
    let mut target = zone();
    let mut a = request("example.com");
    add_a(&mut a, "alias.example.com", "192.0.2.1", 300);
    apply(&mut target, &a).unwrap();

    let mut cname = request("example.com");
    cname.add_authority(
        Record::new(
            Name::parse("alias.example.com").unwrap(),
            Rtype::CNAME,
            Rclass::IN,
            Ttl::new(60).unwrap(),
            Rdata::Cname(Name::parse("target.example.com").unwrap()),
        )
        .unwrap(),
    );
    apply(&mut target, &cname).unwrap();
    assert!(target.get("alias.example.com", Rtype::CNAME).is_none());
    assert!(target.get("alias.example.com", Rtype::A).is_some());

    let mut other = request("example.com");
    other.add_authority(
        Record::new(
            Name::parse("target.example.com").unwrap(),
            Rtype::CNAME,
            Rclass::IN,
            Ttl::new(60).unwrap(),
            Rdata::Cname(Name::parse("else.example.com").unwrap()),
        )
        .unwrap(),
    );
    apply(&mut target, &other).unwrap();
    let mut a_on_cname = request("example.com");
    add_a(&mut a_on_cname, "target.example.com", "192.0.2.2", 60);
    apply(&mut target, &a_on_cname).unwrap();
    assert!(target.get("target.example.com", Rtype::A).is_none());
}

#[test]
fn apex_soa_and_ns_are_protected() {
    let mut target = zone();
    let mut message = request("example.com");
    meta(&mut message, "example.com", Rtype::SOA, Rclass::ANY);
    meta(&mut message, "example.com", Rtype::NS, Rclass::ANY);
    meta(&mut message, "example.com", Rtype::ANY, Rclass::ANY);
    apply(&mut target, &message).unwrap();
    assert!(target.get("example.com", Rtype::SOA).is_some());
    assert!(target.get("example.com", Rtype::NS).is_some());

    let mut delete_ns = request("example.com");
    delete_ns.add_authority(
        Record::new(
            Name::parse("example.com").unwrap(),
            Rtype::NS,
            Rclass::NONE,
            Ttl::ZERO,
            Rdata::Ns(Name::parse("ns1.example.com").unwrap()),
        )
        .unwrap(),
    );
    apply(&mut target, &delete_ns).unwrap();
    assert!(target.get("example.com", Rtype::NS).is_some());
}

#[test]
fn soa_serial_is_bumped_explicitly_and_rejects_older() {
    let mut target = zone();
    let mut message = request("example.com");
    message.add_authority(
        Record::new(
            Name::parse("example.com").unwrap(),
            Rtype::SOA,
            Rclass::IN,
            Ttl::new(3600).unwrap(),
            Rdata::Soa(SoaData::new(
                Name::parse("ns1.example.com").unwrap(),
                Name::parse("hostmaster.example.com").unwrap(),
                Serial::new(10),
                7200,
                900,
                86_400,
                300,
            )),
        )
        .unwrap(),
    );
    let outcome = apply(&mut target, &message).unwrap();
    assert_eq!(outcome.serial, Serial::new(10));

    let mut older = request("example.com");
    older.add_authority(
        Record::new(
            Name::parse("example.com").unwrap(),
            Rtype::SOA,
            Rclass::IN,
            Ttl::new(3600).unwrap(),
            Rdata::Soa(SoaData::new(
                Name::parse("ns1.example.com").unwrap(),
                Name::parse("hostmaster.example.com").unwrap(),
                Serial::new(5),
                7200,
                900,
                86_400,
                300,
            )),
        )
        .unwrap(),
    );
    let outcome = apply(&mut target, &older).unwrap();
    assert_eq!(outcome.serial, Serial::new(11));
}

#[test]
fn noop_update_still_bumps_serial() {
    let mut target = zone();
    let message = request("example.com");
    let outcome = apply(&mut target, &message).unwrap();
    assert_eq!(outcome.serial, Serial::new(2));
    assert!(!outcome.changed);
}

#[test]
fn update_ops_are_sequential() {
    let mut target = zone();
    let mut message = request("example.com");
    add_a(&mut message, "x.example.com", "192.0.2.1", 300);
    meta(&mut message, "x.example.com", Rtype::ANY, Rclass::ANY);
    apply(&mut target, &message).unwrap();
    assert!(target.get("x.example.com", Rtype::A).is_none());
    assert_eq!(target.names(), 2); // SOA + apex NS
}

#[test]
fn managed_dnssec_types_are_refused() {
    let mut target = zone();
    let mut message = request("example.com");
    message.add_authority(Record::update_metavalue(
        Name::parse("example.com").unwrap(),
        Rtype::RRSIG,
        Rclass::ANY,
    ));
    let error = apply(&mut target, &message).unwrap_err();
    assert_eq!(error.rcode(), Rcode::REFUSED);
}

#[test]
fn programmatic_ops_can_target_zone() {
    let mut target = zone();
    let request = UpdateRequest::from_message(&request("example.com")).unwrap();
    assert_eq!(request.updates(), []);
    assert!(apply_update(&mut target, &request).is_ok());
}
