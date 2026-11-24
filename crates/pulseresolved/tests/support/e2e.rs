//! Общие утилиты e2e-тестов: единый дедлайн, таймауты сокетов, повторы
//! с экспоненциальной паузой и обработка `EINTR`.
//!
//! Тесты не должны падать из-за планировщика ОС или `EINTR` под нагрузкой,
//! поэтому любая сетевая операция, где ожидается ответ, выполняется через
//! [`retry`]/[`wait_until`], а блокирующие вызовы — через обёртки,
//! перезапускающие `read`/`write`/`recv_from` при прерывании сигналом.

#![allow(dead_code)]

use std::future::Future;
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Дедлайн одного e2e-шага, включая все повторные попытки.
pub const E2E_DEADLINE: Duration = Duration::from_secs(30);

/// Таймаут блокирующих операций на сокете (щедрый: debug-сборка под нагрузкой).
pub const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

/// Начальная пауза между попытками.
const INITIAL_BACKOFF: Duration = Duration::from_millis(50);

/// Максимальная пауза между попытками.
const MAX_BACKOFF: Duration = Duration::from_millis(1_000);

/// Результат одной попытки: значение или человекочитаемая причина.
pub type Attempt<T> = Result<T, String>;

/// Форматирует ошибку ввода-вывода с контекстом.
pub fn io_error(context: &str, error: &io::Error) -> String {
    format!("{context}: {error} ({:?})", error.kind())
}

/// `recv_from` с повтором при `EINTR`.
///
/// # Errors
///
/// Любая ошибка сокета, кроме [`ErrorKind::Interrupted`].
pub fn recv_from(socket: &UdpSocket, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buffer) {
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// `send_to` с повтором при `EINTR`.
///
/// # Errors
///
/// Любая ошибка сокета, кроме [`ErrorKind::Interrupted`].
pub fn send_to(socket: &UdpSocket, buffer: &[u8], target: SocketAddr) -> io::Result<usize> {
    loop {
        match socket.send_to(buffer, target) {
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// `read`, перезапускаемый при `EINTR`.
///
/// # Errors
///
/// Любая ошибка чтения, кроме [`ErrorKind::Interrupted`].
pub fn read(reader: &mut impl io::Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

/// `write_all`, перезапускаемый при `EINTR`.
///
/// # Errors
///
/// Любая ошибка записи, кроме [`ErrorKind::Interrupted`].
pub fn write_all(writer: &mut impl io::Write, buffer: &[u8]) -> io::Result<()> {
    let mut written = 0_usize;
    while written < buffer.len() {
        let chunk = buffer.get(written..).unwrap_or_default();
        match writer.write(chunk) {
            Ok(0) => return Err(io::Error::from(ErrorKind::WriteZero)),
            Ok(count) => written = written.saturating_add(count),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Дочитывает ровно `buffer.len()` байт, повторяя `EINTR` и короткие чтения.
///
/// # Errors
///
/// [`ErrorKind::UnexpectedEof`], если поток закрылся раньше времени; иные
/// ошибки чтения пробрасываются.
pub fn read_exact(reader: &mut impl io::Read, buffer: &mut [u8]) -> io::Result<()> {
    let mut filled = 0_usize;
    while filled < buffer.len() {
        let chunk = buffer.get_mut(filled..).unwrap_or_default();
        match read(reader, chunk) {
            Ok(0) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Ok(count) => filled = filled.saturating_add(count),
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Повторяет `op` с экспоненциальной паузой, пока не истечёт [`E2E_DEADLINE`].
///
/// `diagnostics` вызывается только при итоговом падении, поэтому дорогие
/// снимки статистики не снимаются на каждой попытке. Паника содержит число
/// попыток, последнюю ошибку и диагностику сервера.
///
/// # Panics
///
/// Если `op` не вернул `Ok` до дедлайна.
pub fn retry<T>(
    label: &str,
    diagnostics: impl Fn() -> String,
    mut op: impl FnMut() -> Attempt<T>,
) -> T {
    let deadline = Instant::now() + E2E_DEADLINE;
    let mut backoff = INITIAL_BACKOFF;
    let mut attempts = 0_u32;
    loop {
        attempts = attempts.saturating_add(1);
        match op() {
            Ok(value) => return value,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "{label}: не удалось за {attempts} попыток и {E2E_DEADLINE:?}; \
                     последняя ошибка: {error}; диагностика: {}",
                    diagnostics()
                );
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(backoff.min(remaining));
        backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
    }
}

/// Ждёт выполнения условия с экспоненциальной паузой до [`E2E_DEADLINE`].
///
/// # Panics
///
/// Если условие не выполнилось до дедлайна.
pub fn wait_until(
    label: &str,
    diagnostics: impl Fn() -> String,
    mut condition: impl FnMut() -> bool,
) {
    retry(label, diagnostics, || {
        if condition() {
            Ok(())
        } else {
            Err("условие ещё не выполнено".to_owned())
        }
    });
}

/// Проверяет счётчик транспорта, допуская лишние запросы только при повторах.
///
/// В штатном прогоне `min == max` и проверка остаётся точной. При повторе
/// запрос мог быть доставлен серверу, поэтому счётчик может вырасти до
/// `max` (число фактических отправок), но не больше.
///
/// # Panics
///
/// Если `actual` вне диапазона `min..=max`.
pub fn assert_counter(label: &str, actual: u64, min: u64, max: u64) {
    assert!(
        actual >= min,
        "{label}: ожидалось не меньше {min}, получено {actual}"
    );
    assert!(
        actual <= max,
        "{label}: ожидалось не больше {max} (фактических отправок), получено {actual}"
    );
}

/// Пауза перед проверкой условия (для тестов, которым нужен явный сон).
pub fn short_pause() {
    std::thread::sleep(INITIAL_BACKOFF);
}

/// Асинхронный аналог [`retry`] для tokio-тестов (DoH/2, DoQ, H2).
///
/// # Panics
///
/// Если `op` не вернул `Ok` до [`E2E_DEADLINE`].
pub async fn retry_async<T, F, Fut>(label: &str, diagnostics: impl Fn() -> String, mut op: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Attempt<T>>,
{
    let deadline = tokio::time::Instant::now() + E2E_DEADLINE;
    let mut backoff = INITIAL_BACKOFF;
    let mut attempts = 0_u32;
    loop {
        attempts = attempts.saturating_add(1);
        match op().await {
            Ok(value) => return value,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{label}: не удалось за {attempts} попыток и {E2E_DEADLINE:?}; \
                     последняя ошибка: {error}; диагностика: {}",
                    diagnostics()
                );
            }
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::time::sleep(backoff.min(remaining)).await;
        backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
    }
}
