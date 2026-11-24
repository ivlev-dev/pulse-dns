#![no_main]

//! RFC 1035 master-файл: `pulse_master::parse_zone` на тексте ≤ 64 КиБ.

use libfuzzer_sys::fuzz_target;
use pulse_dns::Name;
use pulse_master::parse_zone;

/// Лимит задачи: больше 64 КиБ зона не принимается.
const MAX_INPUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(origin) = Name::parse("example.com.") else {
        return;
    };
    let _ = parse_zone(origin, text);
});
