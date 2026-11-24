//! Denial of existence: NSEC и NSEC3 (включая векторы RFC 5155 Appendix B).

use pulse_dns::{Name, Nsec3Data, Rtype, TypeBitmap};
use pulse_dnssec::DenialError;
use pulse_dnssec::denial::{
    DenialLimits, DenialOutcome, Nsec3Params, Nsec3Proof, NsecProof, base32hex, nsec_nodata,
    nsec_nxdomain, nsec_wildcard_answer, nsec_wildcard_nodata, nsec3_ds_nodata, nsec3_nodata,
    nsec3_nxdomain, nsec3_wildcard_answer, nsec3_wildcard_nodata,
};

fn name(value: &str) -> Name {
    Name::parse(value).unwrap()
}

fn nsec(owner: &str, next: &str, types: &[Rtype]) -> NsecProof {
    NsecProof {
        owner: name(owner),
        next: name(next),
        types: TypeBitmap::from_types(types.iter().copied()),
    }
}

fn example_nsec_chain() -> Vec<NsecProof> {
    vec![
        nsec(
            "example.com",
            "a.example.com",
            &[Rtype::SOA, Rtype::NS, Rtype::DNSKEY, Rtype::RRSIG],
        ),
        nsec("a.example.com", "c.example.com", &[Rtype::A, Rtype::RRSIG]),
        nsec(
            "c.example.com",
            "wild.example.com",
            &[Rtype::NS, Rtype::RRSIG],
        ),
        nsec(
            "wild.example.com",
            "*.wild.example.com",
            &[Rtype::A, Rtype::RRSIG],
        ),
        nsec(
            "*.wild.example.com",
            "x.wild.example.com",
            &[Rtype::A, Rtype::RRSIG],
        ),
        nsec(
            "x.wild.example.com",
            "example.com",
            &[Rtype::A, Rtype::RRSIG],
        ),
    ]
}

fn zone() -> Name {
    name("example.com")
}

#[test]
fn nsec_nxdomain_proof() {
    let proofs = example_nsec_chain();
    let result = nsec_nxdomain(
        &name("b.example.com"),
        &zone(),
        &proofs,
        DenialLimits::new(),
    )
    .unwrap();
    assert_eq!(result.outcome, DenialOutcome::NxDomain);
    assert!(result.is_secure());

    // Существующее имя не может быть NXDOMAIN.
    assert!(matches!(
        nsec_nxdomain(
            &name("a.example.com"),
            &zone(),
            &proofs,
            DenialLimits::new()
        ),
        Err(DenialError::NameExists { .. })
    ));
    // Имя вне зоны.
    assert!(nsec_nxdomain(&name("b.other.net"), &zone(), &proofs, DenialLimits::new()).is_err());
}

#[test]
fn nsec_nxdomain_requires_wildcard_cover() {
    // Цепочка без покрытия *.example.com: example.com -> a.example.com
    // покрывает *.example.com фактически, поэтому убираем apex из proof.
    let proofs = vec![
        nsec("a.example.com", "c.example.com", &[Rtype::A]),
        nsec("c.example.com", "x.example.com", &[Rtype::A]),
        nsec("x.example.com", "example.com", &[Rtype::A]),
    ];
    assert!(matches!(
        nsec_nxdomain(
            &name("b.example.com"),
            &zone(),
            &proofs,
            DenialLimits::new()
        ),
        Err(DenialError::WildcardNotCovered { .. })
    ));
}

#[test]
fn nsec_nodata_proof() {
    let proofs = example_nsec_chain();
    let result = nsec_nodata(
        &name("a.example.com"),
        Rtype::AAAA,
        &zone(),
        &proofs,
        DenialLimits::new(),
    )
    .unwrap();
    assert_eq!(result.outcome, DenialOutcome::NoData);

    assert!(matches!(
        nsec_nodata(
            &name("a.example.com"),
            Rtype::A,
            &zone(),
            &proofs,
            DenialLimits::new()
        ),
        Err(DenialError::TypePresent { .. })
    ));
    assert!(matches!(
        nsec_nodata(
            &name("b.example.com"),
            Rtype::A,
            &zone(),
            &proofs,
            DenialLimits::new()
        ),
        Err(DenialError::NsecDoesNotMatch { .. })
    ));

    let with_cname = vec![nsec(
        "a.example.com",
        "c.example.com",
        &[Rtype::CNAME, Rtype::RRSIG],
    )];
    assert!(matches!(
        nsec_nodata(
            &name("a.example.com"),
            Rtype::AAAA,
            &zone(),
            &with_cname,
            DenialLimits::new()
        ),
        Err(DenialError::CnamePresent)
    ));
}

#[test]
fn nsec_wildcard_nodata_and_answer() {
    let proofs = example_nsec_chain();
    let qname = name("foo.wild.example.com");
    let result =
        nsec_wildcard_nodata(&qname, Rtype::AAAA, &zone(), &proofs, DenialLimits::new()).unwrap();
    assert_eq!(result.outcome, DenialOutcome::WildcardNoData);

    let result = nsec_wildcard_answer(
        &qname,
        &name("wild.example.com"),
        &zone(),
        &proofs,
        DenialLimits::new(),
    )
    .unwrap();
    assert_eq!(result.outcome, DenialOutcome::WildcardExpansion);

    assert!(matches!(
        nsec_wildcard_answer(
            &qname,
            &name("example.com"),
            &zone(),
            &proofs,
            DenialLimits::new()
        ),
        Err(DenialError::NextCloserNotCovered { .. })
    ));
}

#[test]
fn nsec_limits_and_zone_bounds() {
    let limits = DenialLimits::new().with_max_iterations(0);
    // Ограничение записей задаётся отдельно; здесь проверяем нулевой набор.
    assert!(nsec_nxdomain(&name("b.example.com"), &zone(), &[], limits).is_err());

    let foreign = vec![nsec("evil.other", "zzz.other", &[Rtype::A])];
    assert!(matches!(
        nsec_nodata(
            &name("evil.other"),
            Rtype::AAAA,
            &zone(),
            &foreign,
            DenialLimits::new()
        ),
        Err(DenialError::NsecOwnerOutsideZone { .. })
    ));
}

fn nsec3(hash_label: &str, next_label: &str, types: &[Rtype], limits: DenialLimits) -> Nsec3Proof {
    let owner = name(&format!("{hash_label}.example"));
    let data = Nsec3Data::new(
        1,
        1,
        12,
        hex::decode("aabbccdd").unwrap(),
        base32hex::decode(next_label.as_bytes()).unwrap(),
        TypeBitmap::from_types(types.iter().copied()),
    )
    .unwrap();
    Nsec3Proof::from_parts(&owner, &data, limits).unwrap()
}

/// Набор NSEC3 из RFC 5155 Appendix B (зона example., salt aabbccdd, 12).
fn rfc5155_proofs(limits: DenialLimits) -> Vec<Nsec3Proof> {
    vec![
        nsec3(
            "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
            &[
                Rtype::MX,
                Rtype::DNSKEY,
                Rtype::NS,
                Rtype::SOA,
                Rtype::NSEC3PARAM,
                Rtype::RRSIG,
            ],
            limits,
        ),
        nsec3(
            "b4um86eghhds6nea196smvmlo4ors995",
            "gjeqe526plbf1g8mklp59enfd789njgi",
            &[Rtype::MX, Rtype::RRSIG],
            limits,
        ),
        nsec3(
            "35mthgpgcu1qg68fab165klnsnk3dpvl",
            "b4um86eghhds6nea196smvmlo4ors995",
            &[Rtype::NS, Rtype::DS, Rtype::RRSIG],
            limits,
        ),
        nsec3(
            "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
            "2vptu5timamqttgl4luu9kg21e0aor3s",
            &[Rtype::A, Rtype::RRSIG],
            limits,
        ),
        nsec3(
            "q04jkcevqvmu85r014c7dkba38o0ji5r",
            "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
            &[Rtype::A, Rtype::RRSIG],
            limits,
        ),
    ]
}

fn example_zone() -> Name {
    name("example")
}

#[test]
fn rfc5155_name_error_proof() {
    let proofs = rfc5155_proofs(DenialLimits::new());
    let result = nsec3_nxdomain(
        &name("a.c.x.w.example"),
        &example_zone(),
        &proofs,
        DenialLimits::new(),
    )
    .unwrap();
    assert_eq!(result.outcome, DenialOutcome::NxDomain);
    // NSEC3 в примере помечены Opt-Out.
    assert!(result.opt_out);

    assert!(matches!(
        nsec3_nxdomain(
            &name("ns1.example"),
            &example_zone(),
            &proofs,
            DenialLimits::new()
        ),
        Err(DenialError::NameExists { .. })
    ));
}

#[test]
fn rfc5155_no_data_proof() {
    let proofs = rfc5155_proofs(DenialLimits::new());
    let result = nsec3_nodata(
        &name("ns1.example"),
        Rtype::MX,
        &example_zone(),
        &proofs,
        DenialLimits::new(),
    )
    .unwrap();
    assert_eq!(result.outcome, DenialOutcome::NoData);

    assert!(matches!(
        nsec3_nodata(
            &name("ns1.example"),
            Rtype::A,
            &example_zone(),
            &proofs,
            DenialLimits::new()
        ),
        Err(DenialError::TypePresent { .. })
    ));
    assert!(matches!(
        nsec3_nodata(
            &name("missing.example"),
            Rtype::A,
            &example_zone(),
            &proofs,
            DenialLimits::new()
        ),
        Err(DenialError::Nsec3NoMatch { .. })
    ));
}

#[test]
fn rfc5155_opt_out_referral_proof() {
    let proofs = rfc5155_proofs(DenialLimits::new());
    let result = nsec3_ds_nodata(
        &name("mc.c.example"),
        &example_zone(),
        &proofs,
        DenialLimits::new(),
    )
    .unwrap();
    assert_eq!(result.outcome, DenialOutcome::NoData);
    assert!(result.opt_out);

    // Signed delegation: NSEC3 матчит a.example и содержит DS.
    assert!(matches!(
        nsec3_ds_nodata(
            &name("a.example"),
            &example_zone(),
            &proofs,
            DenialLimits::new()
        ),
        Err(DenialError::DsPresent)
    ));
}

#[test]
fn rfc5155_wildcard_answer_proof() {
    let proofs = rfc5155_proofs(DenialLimits::new());
    let result = nsec3_wildcard_answer(
        &name("a.c.x.w.example"),
        &name("x.w.example"),
        &example_zone(),
        &proofs,
        DenialLimits::new(),
    )
    .unwrap();
    assert_eq!(result.outcome, DenialOutcome::WildcardExpansion);

    assert!(matches!(
        nsec3_wildcard_answer(
            &name("a.c.x.w.example"),
            &name("example"),
            &example_zone(),
            &proofs,
            DenialLimits::new()
        ),
        Err(DenialError::NextCloserNotCovered { .. })
    ));
}

#[test]
fn nsec3_wildcard_nodata_with_matching_wildcard() {
    let limits = DenialLimits::new();
    // Добавляем NSEC3 для *.x.w.example (hash 92pq...), у которого нет AAAA.
    let mut proofs = rfc5155_proofs(limits);
    proofs.push(nsec3(
        "92pqneegtaue7pjatc3l3qnk738c6v5m",
        "b4um86eghhds6nea196smvmlo4ors995",
        &[Rtype::A, Rtype::RRSIG],
        limits,
    ));
    let result = nsec3_wildcard_nodata(
        &name("a.c.x.w.example"),
        Rtype::AAAA,
        &example_zone(),
        &proofs,
        limits,
    )
    .unwrap();
    assert_eq!(result.outcome, DenialOutcome::WildcardNoData);
}

#[test]
fn nsec3_limits_and_consistency() {
    let limits = DenialLimits::new().with_max_iterations(10);
    let owner = name("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example");
    let data = Nsec3Data::new(
        1,
        0,
        12,
        hex::decode("aabbccdd").unwrap(),
        base32hex::decode(b"2t7b4g4vsa5smi47k61mv5bv1a22bojr").unwrap(),
        TypeBitmap::from_types([Rtype::A]),
    )
    .unwrap();
    assert!(matches!(
        Nsec3Proof::from_parts(&owner, &data, limits),
        Err(DenialError::Nsec3IterationsTooHigh { .. })
    ));

    let params =
        Nsec3Params::new(1, 12, hex::decode("aabbccdd").unwrap(), DenialLimits::new()).unwrap();
    assert_eq!(params.hash_algorithm(), 1);
    assert_eq!(params.iterations(), 12);

    // Несогласованные salt/iterations.
    let first = nsec3(
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
        &[Rtype::A],
        DenialLimits::new(),
    );
    let other_owner = name("b4um86eghhds6nea196smvmlo4ors995.example");
    let other_data = Nsec3Data::new(
        1,
        0,
        11,
        hex::decode("aabbccdd").unwrap(),
        base32hex::decode(b"gjeqe526plbf1g8mklp59enfd789njgi").unwrap(),
        TypeBitmap::from_types([Rtype::A]),
    )
    .unwrap();
    let other = Nsec3Proof::from_parts(&other_owner, &other_data, DenialLimits::new()).unwrap();
    assert!(matches!(
        nsec3_nodata(
            &name("ns1.example"),
            Rtype::MX,
            &example_zone(),
            &[first, other],
            DenialLimits::new()
        ),
        Err(DenialError::Nsec3InconsistentParams)
    ));
}
