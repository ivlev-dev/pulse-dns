//! Минимальное структурное логирование в stderr.
//!
//! Формат — одна JSON-строка на событие: `ts`, `level`, `event`, `msg`.
//! Строки создаются только на старте, ошибках и остановке; на каждый
//! DNS-запрос ничего не пишется.

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::config::LogLevel;

static LEVEL: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

pub(crate) fn init(level: LogLevel) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

fn enabled(level: LogLevel) -> bool {
    (level as u8) <= LEVEL.load(Ordering::Relaxed)
}

fn timestamp() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", elapsed.as_secs(), elapsed.subsec_millis())
}

fn event(level: LogLevel, event: &str, message: &str) {
    if !enabled(level) {
        return;
    }
    eprintln!(
        "{}",
        json!({
            "ts": timestamp(),
            "level": level.to_string(),
            "event": event,
            "msg": message,
        })
    );
}

pub(crate) fn error(event: &str, message: &str) {
    self::event(LogLevel::Error, event, message);
}

pub(crate) fn warn(event: &str, message: &str) {
    self::event(LogLevel::Warn, event, message);
}

pub(crate) fn info(event: &str, message: &str) {
    self::event(LogLevel::Info, event, message);
}

pub(crate) fn debug(event: &str, message: &str) {
    self::event(LogLevel::Debug, event, message);
}
