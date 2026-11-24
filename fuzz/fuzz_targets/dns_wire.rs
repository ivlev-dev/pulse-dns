#![no_main]

//! Wire-декодер `pulse_dns::Message`: произвольные байты, только лимиты
//! (размер UDP + `DecodeLimits`), без паник/зависаний/квадратичных аллокаций.

use libfuzzer_sys::fuzz_target;
use pulse_dns::{DecodeLimits, Message};

/// Верхняя граница входа: больше DNS-over-UDP/TCP-сообщения не бывает.
const MAX_INPUT: usize = 65_535;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let limits = DecodeLimits::default();
    let _ = Message::decode(data, &limits);
});
