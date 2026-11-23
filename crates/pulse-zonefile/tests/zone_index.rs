//! Индекс каталога зон и его инвалидация по поколению.

use pulse_zonefile::key::NameRle;
use pulse_zonefile::zone_index::{ZoneIndex, ZoneLocation};

fn name(text: &str) -> NameRle {
    NameRle::from_ascii(text).unwrap()
}

fn location(root: u32) -> ZoneLocation {
    ZoneLocation {
        root,
        level: 1,
        meta_root: root + 1,
        zone_seq: root,
        state: 1,
    }
}

#[test]
fn insert_get_and_invalidate() {
    let index = ZoneIndex::new();
    assert!(index.is_empty());
    index.insert(name("example.com"), location(14));
    index.insert(name("example.org"), location(20));
    assert_eq!(index.len(), 2);
    assert_eq!(index.get(&name("example.com")), Some(location(14)));
    assert_eq!(index.get(&name("example.org")), Some(location(20)));
    assert_eq!(index.get(&name("absent.net")), None);
    let stats = index.stats();
    assert_eq!(stats.hits, 2);
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.zones, 2);

    let generation = index.generation();
    index.invalidate();
    assert_eq!(index.generation(), generation + 1);
    assert!(index.is_empty());
    assert_eq!(index.get(&name("example.com")), None);

    // Новая запись в новом поколении видна.
    index.insert(name("example.com"), location(30));
    assert_eq!(index.get(&name("example.com")), Some(location(30)));
}

#[test]
fn overwrite_in_same_generation() {
    let index = ZoneIndex::new();
    index.insert(name("example.com"), location(1));
    index.insert(name("example.com"), location(2));
    assert_eq!(index.get(&name("example.com")), Some(location(2)));
    assert_eq!(index.len(), 1);
}
