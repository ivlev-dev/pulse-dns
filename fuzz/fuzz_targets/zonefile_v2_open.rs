#![no_main]

//! `ParallelStore::open` + структурный `read`/`fsck` на мутированном
//! v2-файле. Seed-корпус генерируется `cargo run --bin gen_seeds`.

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use pulse_zonefile::parallel::{OpenConfigV2, ParallelStore};

/// Больше 2 МиБ мутаций не нужно: валидный seed ~64–256 КиБ.
const MAX_INPUT: usize = 2 * 1024 * 1024;
/// Не даём вредоносному прологу раздуть битсеты/аллокации `fsck`.
const MAX_ZONES: u32 = 65_536;
const MAX_DURABLE_PAGES: u64 = 1 << 20;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4096 || data.len() > MAX_INPUT {
        return;
    }
    let Ok(mut file) = tempfile::NamedTempFile::new() else {
        return;
    };
    if file.write_all(data).is_err() {
        return;
    }
    let config = OpenConfigV2 {
        read_only: true,
        writer_lock: false,
        multi_process: false,
        page_cache_entries: 0,
    };
    let Ok(store) = ParallelStore::open(file.path(), config) else {
        return;
    };
    let geometry = store.geometry();
    if geometry.max_zones() > MAX_ZONES || store.durable_page_limit() > MAX_DURABLE_PAGES {
        return;
    }
    let _ = store.fsck_lite();
    let _ = store.fsck_graph();
    let _ = store.leak_report();
    if let Ok(head) = store.select_root(0, u64::MAX)
        && head.root_page != 0
        && head.root_page >= geometry.page_data_first()
    {
        let _ = store.read_raw_page(head.root_page);
    }
});
