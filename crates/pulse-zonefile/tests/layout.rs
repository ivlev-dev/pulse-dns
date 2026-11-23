//! Размеры структур и golden-параметры геометрии (§22).

use static_assertions::{assert_eq_size, const_assert_eq};

use pulse_zonefile::SectionDescriptor;
use pulse_zonefile::consts::*;

#[repr(C)]
#[allow(dead_code)]
struct ReaderSlotWire {
    owner: u64,
    active: u64,
    heartbeat: u64,
    flags: u64,
}

#[repr(C)]
#[allow(dead_code)]
struct ReaderPageDescriptorWire {
    page_type: u32,
    version: u16,
    page_flags: u16,
    page_no: u32,
    slots_used: u32,
    crc32c: u32,
    reserved0: u32,
    reserved1: u64,
}

assert_eq_size!(SectionDescriptor, [u8; 32]);
assert_eq_size!(ReaderSlotWire, [u8; 32]);
assert_eq_size!(ReaderPageDescriptorWire, [u8; 32]);
assert_eq_size!([u8; 4096], [u8; SUPERBLOCK_RECORD_SIZE as usize]);

const_assert_eq!(SUPERBLOCK_RECORD_SIZE, 4096);
const_assert_eq!(PAGE_HEADER_SIZE, 40);
const_assert_eq!(NODE_HEADER_SIZE, 56);
const_assert_eq!(LEAF_VALUE_SIZE, 20);
const_assert_eq!(OVERFLOW_HEADER_SIZE, 48);
const_assert_eq!(FREELIST_HEADER_SIZE, 64);
const_assert_eq!(ZONE_META_HEADER_SIZE, 80);
const_assert_eq!(READER_SLOT_SIZE, 32);
const_assert_eq!(READER_PAGE_DESC_SIZE, 32);
const_assert_eq!(READER_SLOTS, 1024);
const_assert_eq!(PAGE_SUPERBLOCK_A, 0);
const_assert_eq!(PAGE_SUPERBLOCK_B, 1);
const_assert_eq!(PAGE_META_A, 2);
const_assert_eq!(PAGE_META_B, 3);
const_assert_eq!(PAGE_READER_TABLE, 4);
const_assert_eq!(MAX_FILE_PAGES, 0xFFFF_FFFE);
const_assert_eq!(std::mem::offset_of!(SectionDescriptor, id), 0);
const_assert_eq!(std::mem::offset_of!(SectionDescriptor, version), 2);
const_assert_eq!(std::mem::offset_of!(SectionDescriptor, first_page), 4);
const_assert_eq!(std::mem::offset_of!(SectionDescriptor, page_count), 8);
const_assert_eq!(std::mem::offset_of!(SectionDescriptor, pad), 12);
const_assert_eq!(std::mem::offset_of!(SectionDescriptor, flags), 16);
const_assert_eq!(std::mem::offset_of!(SectionDescriptor, reserved), 24);
const_assert_eq!(MAX_ZONE_META_PAGES_DEFAULT, 65);
const_assert_eq!(max_zone_meta_pages(4096), 65);
const_assert_eq!(max_zone_meta_pages(8192), 33);
const_assert_eq!(max_zone_meta_pages(16384), 17);

#[test]
fn reader_geometry_table_from_spec() {
    let cases = [(4096, 9, 36_864), (8192, 5, 40_960), (16384, 3, 49_152)];
    for (page_size, pages, region_len) in cases {
        let geometry = ReaderGeometry::for_page_size(page_size).unwrap();
        assert_eq!(geometry.pages, pages);
        assert_eq!(geometry.region_len, region_len);
        assert_eq!(geometry.region_off, 4 * u64::from(page_size));
        assert_eq!(geometry.region_off % 64, 0);
        assert_eq!(geometry.region_len % 64, 0);
        assert_eq!(geometry.data_first(), 4 + pages);
        assert!(geometry.capacity() >= READER_SLOTS);
    }
}
