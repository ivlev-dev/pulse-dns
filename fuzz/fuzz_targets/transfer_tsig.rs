#![no_main]

//! TSIG/AXFR: разбор TSIG-конверта и TCP length-prefixed сообщений.

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use pulse_dns::{DecodeLimits, Message};
use pulse_transfer::{parse_tsig, read_message};

const MAX_INPUT: usize = 65_535;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let limits = DecodeLimits::default();
    let _ = parse_tsig(data);

    let mut cursor = Cursor::new(data);
    for _ in 0..8 {
        let Ok(message) = read_message(&mut cursor) else {
            break;
        };
        let _ = Message::decode(&message, &limits);
        let _ = parse_tsig(&message);
    }
});
