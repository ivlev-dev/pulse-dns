//! E2E RFC 5011: манифест DNSKEY → add/revoke hold-down, идемпотентность,
//! откат кандидата и персистентность состояния.

use pulse_dns::{DnskeyData, Name, Rclass, Rdata, Rrset, Rtype, Ttl};
use pulse_dnssec::trust_update::DNSKEY_FLAG_REVOKE;
use pulse_dnssec::{
    Algorithm, AnchorStatus, DsPolicy, PrivateKey, TrustAnchor, TrustAnchorPolicy,
    TrustAnchorStore, ds_from_dnskey,
};

const HOLD_DOWN: u32 = 10;

fn key() -> PrivateKey {
    PrivateKey::generate(Algorithm::ED25519).expect("key")
}

fn dnskey(key: &PrivateKey, flags: u16) -> DnskeyData {
    key.dnskey(flags).expect("dnskey")
}

fn manifest(keys: &[(&PrivateKey, u16)]) -> Rrset {
    Rrset::new(
        Name::root(),
        Rtype::DNSKEY,
        Rclass::IN,
        Ttl::new(3600).expect("ttl"),
        keys.iter()
            .map(|(key, flags)| Rdata::Dnskey(dnskey(key, *flags))),
    )
    .expect("rrset")
}

fn anchor(key: &PrivateKey) -> TrustAnchor {
    let dnskey = dnskey(key, 257);
    let ds = ds_from_dnskey(&Name::root(), &dnskey, 2, DsPolicy::strict()).expect("ds");
    TrustAnchor::from_ds(&ds, Some(0), None).expect("anchor")
}

fn policy() -> TrustAnchorPolicy {
    TrustAnchorPolicy::new(HOLD_DOWN, HOLD_DOWN)
}

#[test]
fn add_hold_down_idempotency_and_rollback() {
    let root = Name::root();
    let seed = key();
    let candidate = key();
    let mut store = TrustAnchorStore::with_policy(policy());
    assert_eq!(store.seed(&[anchor(&seed)], 0), 1);

    // Манифест: действующий + новый KSK → новый pending.
    let manifest_keys = manifest(&[(&seed, 257), (&candidate, 257)]);
    let report = store.observe_validated_dnskey(&root, &manifest_keys, 100);
    assert_eq!(report.added, 1);
    assert_eq!(report.activated, 0);
    let pending = store
        .anchors()
        .into_iter()
        .find(|(entry, _, _)| entry.key_tag() != anchor(&seed).key_tag())
        .expect("candidate");
    assert_eq!(pending.1, AnchorStatus::AddPending);
    assert_eq!(pending.2, 110);

    // Идемпотентность: повторный манифест не продлевает hold-down.
    let repeat = store.observe_validated_dnskey(&root, &manifest_keys, 105);
    assert!(!repeat.changed());
    assert_eq!(
        store
            .anchors()
            .into_iter()
            .find(|(entry, _, _)| entry.key_tag() == pending.0.key_tag())
            .expect("candidate")
            .2,
        110
    );

    // До истечения hold-down кандидат не участвует в валидации.
    assert_eq!(store.active_set(109).len(), 1);
    let activated = store.observe_validated_dnskey(&root, &manifest_keys, 110);
    assert_eq!(activated.activated, 1);
    assert_eq!(store.active_set(110).len(), 2);

    // Rollback: ещё один кандидат исчез из зоны → удалён без ожидания.
    let rolled_back = key();
    let with_third = manifest(&[(&seed, 257), (&candidate, 257), (&rolled_back, 257)]);
    assert_eq!(
        store
            .observe_validated_dnskey(&root, &with_third, 120)
            .added,
        1
    );
    let without_third = manifest(&[(&seed, 257), (&candidate, 257)]);
    let report = store.observe_validated_dnskey(&root, &without_third, 121);
    assert_eq!(report.removed, 1);
    assert_eq!(store.active_set(121).len(), 2);
}

#[test]
fn revoke_hold_down_removes_anchor_after_propagation() {
    let root = Name::root();
    let ksk = key();
    let mut store = TrustAnchorStore::with_policy(policy());
    store.seed(&[anchor(&ksk)], 0);

    // REVOKE-бит меняет flags и key tag, но anchor сопоставляется по key material.
    let revoked = manifest(&[(&ksk, 0x0101 | DNSKEY_FLAG_REVOKE)]);
    let report = store.observe_validated_dnskey(&root, &revoked, 200);
    assert_eq!(report.revoked, 1);
    assert_eq!(
        store.anchors()[0].1,
        AnchorStatus::RevokePending,
        "anchor must enter revoke hold-down"
    );
    // Во время hold-down anchor ещё используется (кеши истекают).
    assert_eq!(store.active_set(205).len(), 1);

    // Идемпотентность: повторный revoke не сдвигает hold-down.
    let repeat = store.observe_validated_dnskey(&root, &revoked, 205);
    assert!(!repeat.changed());

    store.advance(210);
    assert!(store.active_set(210).is_empty());
    assert_eq!(store.anchors().len(), 0);
}

#[test]
fn state_survives_reopen_with_hold_down() {
    let directory = tempfile::tempdir().expect("dir");
    let path = directory.path().join("anchors/state.json");
    let root = Name::root();
    let current = key();
    let candidate = key();

    let mut store = TrustAnchorStore::open(&path, policy()).expect("open");
    store.seed(&[anchor(&current)], 1_000);
    store.observe_validated_dnskey(
        &root,
        &manifest(&[(&current, 257), (&candidate, 257)]),
        1_000,
    );
    store.persist().expect("persist");
    drop(store);

    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode, 0o600);

    let mut reopened = TrustAnchorStore::open(&path, policy()).expect("reopen");
    assert_eq!(reopened.anchors().len(), 2);
    // Hold-down продолжается после рестарта.
    let report = reopened.advance(1_010);
    assert_eq!(report.activated, 1);
    assert_eq!(reopened.active_set(1_010).len(), 2);
    // Отзыв после активации: anchor уходит в revoke hold-down и удаляется.
    let candidate_anchor = reopened
        .anchors()
        .into_iter()
        .find(|(a, _, _)| a.key_tag() != anchor(&current).key_tag())
        .expect("candidate")
        .0;
    let revoked = manifest(&[(&current, 257), (&candidate, 0x0101 | DNSKEY_FLAG_REVOKE)]);
    let report = reopened.observe_validated_dnskey(&root, &revoked, 1_020);
    assert_eq!(report.revoked, 1);
    assert_eq!(reopened.active_set(1_025).len(), 2);
    reopened.advance(1_030);
    assert!(
        reopened
            .anchors()
            .iter()
            .all(|(a, _, _)| a.key_tag() != candidate_anchor.key_tag())
    );
}
