//! Golden-векторы и property-тесты ключей (`zonefile-v1.md` §8, §9, §22.1).

use std::cmp::Ordering;

use proptest::prelude::*;

use pulse_zonefile::key::{
    CLASS_IN, ChildrenProbe, Key, NameRle, T_NODE, T_ZONE_ENTRY, ZoneEntryKey, compare_keys,
    name_cmp,
};

fn name(text: &str) -> NameRle {
    NameRle::from_ascii(text).unwrap()
}

fn compare(left: &str, right: &str) -> Ordering {
    name_cmp(name(left).as_rle(), name(right).as_rle()).unwrap()
}

#[test]
fn rle_golden_vectors() {
    assert_eq!(
        name("example.com").as_rle(),
        &[
            3, b'c', b'o', b'm', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0
        ]
    );
    assert_eq!(
        name("b.example.com").as_rle(),
        &[
            3, b'c', b'o', b'm', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 1, b'b', 0
        ]
    );
    assert_eq!(
        name("a.b.example.com").as_rle(),
        &[
            3, b'c', b'o', b'm', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 1, b'b', 1, b'a', 0
        ]
    );
    assert_eq!(name("example.com").len(), 13);
    assert_eq!(name("b.example.com").len(), 15);
    assert_eq!(name("a.b.example.com").len(), 17);
}

#[test]
fn key_golden_vectors() {
    let owner = name("b.example.com");
    let node_key = Key::new(&owner, T_NODE, 0, 0).unwrap();
    let a_key = Key::new(&owner, 1, CLASS_IN, 0).unwrap();
    assert_eq!(node_key.len(), 21);
    assert_eq!(
        node_key.as_bytes(),
        &[
            3, b'c', b'o', b'm', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 1, b'b', 0, 0, 0, 0,
            0, 0, 0
        ]
    );
    assert_eq!(
        a_key.as_bytes(),
        &[
            3, b'c', b'o', b'm', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 1, b'b', 0, 1, 0, 1,
            0, 0, 0
        ]
    );
    let catalog = ZoneEntryKey::new(&name("example.com")).unwrap();
    assert_eq!(catalog.key().len(), 19);
    assert_eq!(
        catalog.key().as_bytes(),
        &[
            3, b'c', b'o', b'm', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0xFE, 0xFF, 0, 0,
            0, 0
        ]
    );
}

#[test]
fn comparator_rfc_vectors() {
    assert_eq!(compare("aa", "b"), Ordering::Less);
    assert_eq!(compare("ab", "abc"), Ordering::Less);
    assert_eq!(compare("example.com", "a.example.com"), Ordering::Less);
    assert_eq!(compare("example.com", "example.org"), Ordering::Less);
    assert_eq!(compare("z.example.com", "example.com"), Ordering::Greater);
    assert_eq!(compare("example.com", "example.com"), Ordering::Equal);
    assert_eq!(compare("a.example", "a.example.com"), Ordering::Greater);
    assert_eq!(compare("*.example.com", "a.example.com"), Ordering::Less);
    assert_eq!(compare("_sip._tcp.example", "a.example"), Ordering::Less);
    assert_eq!(compare("*.example.com", "_x.example.com"), Ordering::Less);
}

#[test]
fn comparator_treats_high_bytes_as_unsigned() {
    // Метка из байта 0x80 больше метки "a" (0x61), но меньше "~" (0x7E)? Нет:
    // 0x80 > 0x7E — как беззнаковый байт.
    let high = NameRle::from_wire(&[1, 0x80, 0]).unwrap();
    let tilde = NameRle::from_wire(&[1, b'~', 0]).unwrap();
    assert_eq!(
        name_cmp(high.as_rle(), tilde.as_rle()).unwrap(),
        Ordering::Greater
    );
    let a = NameRle::from_wire(&[1, b'a', 0]).unwrap();
    assert_eq!(
        name_cmp(high.as_rle(), a.as_rle()).unwrap(),
        Ordering::Greater
    );
}

#[test]
fn names_are_lowercased_on_input_and_strict_on_read() {
    let normalized = NameRle::from_ascii("WWW.Example.COM").unwrap();
    assert_eq!(normalized, name("www.example.com"));
    let wire = NameRle::from_wire(&[
        3, b'W', b'W', b'W', 7, b'E', b'X', b'A', b'M', b'P', b'L', b'E', 3, b'C', b'O', b'M', 0,
    ])
    .unwrap();
    assert_eq!(wire, name("www.example.com"));
    assert!(NameRle::parse(normalized.as_rle()).is_ok());
    let mut bytes = normalized.as_rle().to_vec();
    if let Some(byte) = bytes.get_mut(1) {
        *byte = b'W';
    }
    assert!(NameRle::parse(&bytes).is_err());
}

#[test]
fn parent_and_labels() {
    let full = name("a.b.example.com");
    assert_eq!(full.label_count(), 4);
    assert_eq!(full.first_label().unwrap(), b"a");
    assert_eq!(full.parent().unwrap(), name("b.example.com"));
    assert_eq!(
        full.parent().unwrap().parent().unwrap(),
        name("example.com")
    );
    assert_eq!(
        full.labels().collect::<Vec<_>>(),
        vec![
            b"com".as_slice(),
            b"example".as_slice(),
            b"b".as_slice(),
            b"a".as_slice()
        ]
    );
    assert_eq!(
        full.labels_rev().collect::<Vec<_>>(),
        vec![
            b"a".as_slice(),
            b"b".as_slice(),
            b"example".as_slice(),
            b"com".as_slice()
        ]
    );
    let mut wire = [0_u8; 255];
    let written = full.write_wire(&mut wire).unwrap();
    assert_eq!(
        wire.get(..written).unwrap(),
        &[
            1, b'a', 1, b'b', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
        ]
    );
    assert!(!full.is_wildcard());
    assert!(name("*.example.com").is_wildcard());
}

#[test]
fn children_probe_s1_s6() {
    let example = name("example.com");
    let b = name("b.example.com");
    let a_b = name("a.b.example.com");
    let c_b = name("c.b.example.com");
    let x = name("x.example.com");

    let b_probe = ChildrenProbe::new(&b);
    let a_key = Key::new(&a_b, 1, CLASS_IN, 0).unwrap();
    let c_key = Key::new(&c_b, 1, CLASS_IN, 0).unwrap();
    let b_key = Key::new(&b, T_NODE, 0, 0).unwrap();
    assert_eq!(b_probe.compare_key(&a_key).unwrap(), Ordering::Greater);
    assert!(b_probe.matches(&a_key).unwrap());
    assert!(b_probe.matches(&c_key).unwrap());
    assert_eq!(b_probe.compare_key(&b_key).unwrap(), Ordering::Less);
    assert!(!b_probe.matches(&b_key).unwrap());

    let example_probe = ChildrenProbe::new(&example);
    let b_node = Key::new(&b, T_NODE, 0, 0).unwrap();
    assert!(example_probe.matches(&b_node).unwrap());

    let a_probe = ChildrenProbe::new(&a_b);
    let next = Key::new(&c_b, 1, CLASS_IN, 0).unwrap();
    assert!(!a_probe.matches(&next).unwrap());
    assert_eq!(a_probe.compare_key(&next).unwrap(), Ordering::Greater);
    let x_key = Key::new(&x, T_NODE, 0, 0).unwrap();
    assert!(!a_probe.matches(&x_key).unwrap());
}

#[test]
fn key_comparator_tail_order() {
    let owner = name("example.com");
    let node = Key::new(&owner, T_NODE, 0, 0).unwrap();
    let a = Key::new(&owner, 1, CLASS_IN, 0).unwrap();
    let a_again = Key::new(&owner, 1, CLASS_IN, 1).unwrap();
    let catalog = Key::new(&owner, T_ZONE_ENTRY, 0, 0).unwrap();
    assert_eq!(node.compare(&a), Ordering::Less);
    assert_eq!(a.compare(&a_again), Ordering::Less);
    assert_eq!(a.compare(&catalog), Ordering::Less);
    assert_eq!(
        compare_keys(node.as_bytes(), node.as_bytes()).unwrap(),
        Ordering::Equal
    );
}

fn reference_name_cmp(left: &[u8], right: &[u8]) -> Ordering {
    fn labels(rle: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut offset = 0_usize;
        while let Some(&length) = rle.get(offset) {
            if length == 0 {
                break;
            }
            let length = usize::from(length);
            out.push(rle.get(offset + 1..offset + 1 + length).unwrap().to_vec());
            offset += 1 + length;
        }
        out
    }
    let left = labels(left);
    let right = labels(right);
    for (a, b) in left.iter().zip(right.iter()) {
        match a.cmp(b) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    left.len().cmp(&right.len())
}

fn label_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop_oneof![
            Just(0x80_u8),
            Just(b'*'),
            Just(b'_'),
            Just(b'-'),
            Just(b'a'),
            Just(b'Z'.to_ascii_lowercase()),
            0x20..=0x7E_u8,
        ],
        1..=7,
    )
    .prop_map(|mut label| {
        for byte in &mut label {
            byte.make_ascii_lowercase();
        }
        label
    })
}

fn name_strategy() -> impl Strategy<Value = NameRle> {
    prop::collection::vec(label_strategy(), 1..=5).prop_map(|labels| {
        let mut wire = Vec::new();
        for label in &labels {
            wire.push(u8::try_from(label.len()).unwrap());
            wire.extend_from_slice(label);
        }
        wire.push(0);
        NameRle::from_wire(&wire).unwrap()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn comparator_matches_reference(left in name_strategy(), right in name_strategy()) {
        let actual = name_cmp(left.as_rle(), right.as_rle()).unwrap();
        let expected = reference_name_cmp(left.as_rle(), right.as_rle());
        prop_assert_eq!(actual, expected);
    }

    #[test]
    fn key_comparator_matches_reference(
        left_name in name_strategy(),
        right_name in name_strategy(),
        left_type in any::<u16>(),
        right_type in any::<u16>(),
        left_class in any::<u16>(),
        right_class in any::<u16>(),
        left_subtype in any::<u16>(),
        right_subtype in any::<u16>(),
    ) {
        let left = Key::new(&left_name, left_type, left_class, left_subtype).unwrap();
        let right = Key::new(&right_name, right_type, right_class, right_subtype).unwrap();
        let expected = reference_name_cmp(left_name.as_rle(), right_name.as_rle())
            .then(left_type.cmp(&right_type))
            .then(left_class.cmp(&right_class))
            .then(left_subtype.cmp(&right_subtype));
        prop_assert_eq!(left.compare(&right), expected);
    }

    #[test]
    fn children_probe_matches_prefix_scan(name in name_strategy(), child_label in label_strategy()) {
        let probe = ChildrenProbe::new(&name);
        // Строим потомка: name с добавленной левой меткой.
        let mut wire = Vec::new();
        wire.push(u8::try_from(child_label.len()).unwrap());
        wire.extend_from_slice(&child_label);
        // Метки name в forward-порядке.
        for label in name.labels_rev() {
            wire.push(u8::try_from(label.len()).unwrap());
            wire.extend_from_slice(label);
        }
        wire.push(0);
        let child = NameRle::from_wire(&wire).unwrap();
        let key = Key::new(&child, 1, CLASS_IN, 0).unwrap();
        prop_assert!(probe.matches(&key).unwrap());
        prop_assert_eq!(probe.compare_key(&key).unwrap(), Ordering::Greater);
        let owner_key = Key::new(&name, T_NODE, 0, 0).unwrap();
        prop_assert!(!probe.matches(&owner_key).unwrap());
        prop_assert_eq!(probe.compare_key(&owner_key).unwrap(), Ordering::Less);
    }
}
