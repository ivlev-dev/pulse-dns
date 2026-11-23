//! Негативные проверки декодера узлов: повреждённая страница → `Err`, не паника.

use pulse_zonefile::checksum;
use pulse_zonefile::consts::{PAGE_SIZE_DEFAULT, PAGE_TYPE_BRANCH, PAGE_TYPE_LEAF};

const CRC_OFFSET: usize = 32;
use pulse_zonefile::key::{CLASS_IN, Key, NameRle};
use pulse_zonefile::node::{
    DecodedBranch, DecodedLeaf, EncodeContext, ItemValue, LeafItem, LeafValue, ValueKind,
    encode_leaf,
};
use pulse_zonefile::{CorruptDetail, CorruptKind, ZoneFileError};

const TXN: u64 = 2;

fn item(rr_type: u16, rdata: &[u8]) -> LeafItem {
    let owner = NameRle::from_ascii("example.com").unwrap();
    let mut payload = vec![0_u8; 2];
    payload
        .get_mut(..2)
        .unwrap()
        .copy_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    payload.extend_from_slice(rdata);
    LeafItem::new(
        Key::new(&owner, rr_type, CLASS_IN, 0).unwrap(),
        ItemValue::inline(
            LeafValue {
                kind: ValueKind::Inline,
                flags: 0,
                rr_count: 1,
                ttl: 60,
                val_u32: 0,
                rdlen: u16::try_from(rdata.len()).unwrap(),
            },
            payload,
        )
        .unwrap(),
    )
}

fn valid_page() -> Vec<u8> {
    let items = [item(1, &[192, 0, 2, 1]), item(2, &[192, 0, 2, 2])];
    let mut page = vec![0_u8; PAGE_SIZE_DEFAULT as usize];
    encode_leaf(
        &mut page,
        EncodeContext {
            page_no: 13,
            page_size: PAGE_SIZE_DEFAULT,
            txn: TXN,
            lsn: 0,
        },
        &items,
    )
    .unwrap();
    page
}

fn write_u16(page: &mut [u8], offset: usize, value: u16) {
    page.get_mut(offset..offset + 2)
        .unwrap()
        .copy_from_slice(&value.to_le_bytes());
}

fn fix_crc(page: &mut [u8]) {
    let crc = checksum::page_crc32c(page, CRC_OFFSET).unwrap();
    page.get_mut(CRC_OFFSET..CRC_OFFSET + 4)
        .unwrap()
        .copy_from_slice(&crc.to_le_bytes());
}

fn expect_corrupt(page: &[u8]) -> ZoneFileError {
    DecodedLeaf::decode(page, 13, TXN, PAGE_SIZE_DEFAULT).unwrap_err()
}

#[test]
fn control_page_decodes() {
    let page = valid_page();
    let leaf = DecodedLeaf::decode(&page, 13, TXN, PAGE_SIZE_DEFAULT).unwrap();
    assert_eq!(leaf.len(), 2);
}

#[test]
fn rejects_wrong_page_type_and_level() {
    let mut page = valid_page();
    page.get_mut(0..4)
        .unwrap()
        .copy_from_slice(&PAGE_TYPE_BRANCH.to_le_bytes());
    fix_crc(&mut page);
    assert!(matches!(
        expect_corrupt(&page),
        ZoneFileError::Corrupt {
            kind: CorruptKind::Bounds,
            detail: CorruptDetail::PageType,
            ..
        }
    ));

    let mut page = valid_page();
    write_u16(&mut page, 40, 1);
    fix_crc(&mut page);
    assert!(expect_corrupt(&page).to_string().contains("corrupt"));
}

#[test]
fn rejects_uppercase_key() {
    let mut page = valid_page();
    // Суффикс первого ключа начинается с RLE(example.com); 'c' → 'C'.
    // items_start = 4096 - (49+36) = 4011; суффикс с 4011+4 = 4015.
    *page.get_mut(4016).unwrap() = b'C';
    fix_crc(&mut page);
    assert!(matches!(
        expect_corrupt(&page),
        ZoneFileError::Corrupt {
            kind: CorruptKind::BadName,
            ..
        }
    ));
}

#[test]
fn rejects_shared_len_larger_than_previous_key() {
    let mut page = valid_page();
    // slot[1] = 4060; shared_len item1.
    write_u16(&mut page, 4060, 300);
    fix_crc(&mut page);
    assert!(expect_corrupt(&page).to_string().contains("corrupt"));
}

#[test]
fn rejects_broken_restart_and_slots() {
    let mut page = valid_page();
    write_u16(&mut page, 44, 2); // n_restarts = 2 при одном item'е на restart
    fix_crc(&mut page);
    assert!(expect_corrupt(&page).to_string().contains("corrupt"));

    let mut page = valid_page();
    // Переставляем слоты местами: монотонность нарушена.
    let first = u16::from_le_bytes(page.get(58..60).unwrap().try_into().unwrap());
    let second = u16::from_le_bytes(page.get(60..62).unwrap().try_into().unwrap());
    write_u16(&mut page, 58, second);
    write_u16(&mut page, 60, first);
    fix_crc(&mut page);
    assert!(expect_corrupt(&page).to_string().contains("corrupt"));
}

#[test]
fn rejects_bad_free_bytes_and_items_start() {
    let mut page = valid_page();
    page.get_mut(48..52)
        .unwrap()
        .copy_from_slice(&1_u32.to_le_bytes());
    fix_crc(&mut page);
    assert!(expect_corrupt(&page).to_string().contains("corrupt"));

    let mut page = valid_page();
    page.get_mut(52..56)
        .unwrap()
        .copy_from_slice(&60_u32.to_le_bytes());
    fix_crc(&mut page);
    assert!(expect_corrupt(&page).to_string().contains("corrupt"));

    let mut page = valid_page();
    page.get_mut(0..4)
        .unwrap()
        .copy_from_slice(&PAGE_TYPE_LEAF.to_le_bytes());
    // payload_len не равен page_size.
    page.get_mut(36..40)
        .unwrap()
        .copy_from_slice(&4095_u32.to_le_bytes());
    fix_crc(&mut page);
    assert!(expect_corrupt(&page).to_string().contains("corrupt"));
}

#[test]
fn rejects_rdata_sum_mismatch() {
    let mut page = valid_page();
    // Первый item: items_start=4011, value_off=4011+4+19=4034,
    // rdlen по смещению +16 = 4050, payload — 4054.
    page.get_mut(4054..4056).unwrap().copy_from_slice(&[0, 5]);
    fix_crc(&mut page);
    assert!(matches!(
        expect_corrupt(&page),
        ZoneFileError::Corrupt {
            kind: CorruptKind::BadRdata,
            ..
        }
    ));
}

#[test]
fn rejects_page_newer_than_snapshot() {
    let page = valid_page();
    assert!(
        DecodedLeaf::decode(&page, 13, TXN - 1, PAGE_SIZE_DEFAULT).is_err(),
        "txn newer than snapshot must be rejected"
    );
    assert!(DecodedBranch::decode(&page, 13, TXN, PAGE_SIZE_DEFAULT).is_err());
}

#[test]
fn rejects_bad_slot_bounds() {
    let mut page = valid_page();
    write_u16(&mut page, 58, 0);
    fix_crc(&mut page);
    assert!(expect_corrupt(&page).to_string().contains("corrupt"));
    let mut page = valid_page();
    write_u16(
        &mut page,
        60,
        u16::try_from(PAGE_SIZE_DEFAULT + 10).unwrap(),
    );
    fix_crc(&mut page);
    assert!(expect_corrupt(&page).to_string().contains("corrupt"));
}
