//! Паника внутри обработчика: изоляция без потока stderr на каждую датаграмму.
//!
//! Глобальный hook один раз оборачивается вокруг предыдущего (обычно это hook
//! test-harness/приложения). Пока поток находится внутри `catch` обработчика,
//! вывод подавляется, а счётчик `handler_panics` инкрементируется вызывающим.

use std::cell::Cell;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};

thread_local! {
    static IN_HANDLER: Cell<bool> = const { Cell::new(false) };
}

static INSTALL: Once = Once::new();
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Установить hook (идемпотентно, один раз на процесс).
pub(crate) fn install() {
    INSTALL.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if IN_HANDLER.with(Cell::get) {
                SUPPRESSED.fetch_add(1, Ordering::Relaxed);
                return;
            }
            previous(info);
        }));
    });
}

struct Reset;

impl Drop for Reset {
    fn drop(&mut self) {
        IN_HANDLER.with(|flag| flag.set(false));
    }
}

/// Выполнить обработчик с подавлением вывода паники на время unwinding.
pub(crate) fn catch<R>(handler: impl FnOnce() -> R) -> std::thread::Result<R> {
    install();
    IN_HANDLER.with(|flag| flag.set(true));
    let reset = Reset;
    let result = panic::catch_unwind(AssertUnwindSafe(handler));
    drop(reset);
    result
}

#[cfg(test)]
pub(crate) fn suppressed_count() -> u64 {
    SUPPRESSED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_inside_handler_is_suppressed_and_counted() {
        install();
        let before = suppressed_count();
        let result = catch(|| panic!("expected panic inside handler"));
        assert!(result.is_err());
        assert!(suppressed_count() > before);
    }
}
