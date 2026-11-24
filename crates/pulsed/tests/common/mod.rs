//! Общие помощники e2e: временный zonefile, импорт master-файла бинарником и
//! retry-примитивы для тестов с реальной сетью и фоновыми потоками.

#![allow(dead_code)]

use std::fmt;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pulsed::config::{Config, Durability, TcpConfig};

/// Дедлайн ожиданий, где участвуют реальная сеть и фоновые потоки.
///
/// Полный `cargo test --workspace --all-features` идёт десятками параллельных
/// процессов/потоков, поэтому 5–10 с «на глаз» недостаточно: планировщик может
/// не отдать CPU ни тесту, ни фоновому потоку сервера.
pub const E2E_DEADLINE: Duration = Duration::from_secs(30);

/// Таймаут сокета в e2e: с запасом на загруженный CPU.
pub const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

/// Базовая пауза retry-цикла.
const RETRY_BASE: Duration = Duration::from_millis(25);

/// Потолок экспоненциальной паузы.
const RETRY_CAP: Duration = Duration::from_millis(500);

/// Экспоненциальная пауза после попытки `attempt` (0-based).
#[must_use]
pub fn retry_delay(attempt: u32) -> Duration {
    let factor = 1_u32 << attempt.min(5);
    (RETRY_BASE * factor).min(RETRY_CAP)
}

/// Повторяет `probe` до истечения `timeout` с экспоненциальной паузой.
///
/// В отличие от `assert!` внутри цикла не паникует: возвращает `false`, чтобы
/// вызывающий добавил в сообщение диагностику сервера.
pub fn wait_until(timeout: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    let mut attempt = 0;
    loop {
        if probe() {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        std::thread::sleep(retry_delay(attempt).min(deadline - now));
        attempt += 1;
    }
}

/// Повторяет `operation` до `attempts` раз.
///
/// Пауза растёт экспоненциально от `base` (потолок — `4 * base`). Возвращает
/// последнюю ошибку, чтобы вызывающий мог положить её в `panic!` вместе с
/// диагностикой. `attempt` (0-based) передаётся в операцию для логов.
pub fn retry<T, E>(
    label: &str,
    attempts: u32,
    base: Duration,
    mut operation: impl FnMut(u32) -> Result<T, E>,
) -> Result<T, E>
where
    E: fmt::Display,
{
    let mut attempt = 0;
    loop {
        match operation(attempt) {
            Ok(value) => return Ok(value),
            Err(error) => {
                attempt += 1;
                if attempt >= attempts {
                    eprintln!("{label}: попытка {attempts}/{attempts} не удалась: {error}");
                    return Err(error);
                }
                let delay = (base * (1_u32 << (attempt - 1).min(2))).max(base);
                eprintln!(
                    "{label}: попытка {attempt}/{attempts} не удалась: {error}; пауза {delay:?}"
                );
                std::thread::sleep(delay);
            }
        }
    }
}

/// Резервирует TCP-адрес на loopback.
///
/// UDP-порты так резервировать нельзя: `pulse-runtime` биндит UDP-сокеты с
/// `SO_REUSEPORT`, поэтому «свободный» UDP-порт можно молча разделить с другим
/// сервером. Для UDP используйте `port = 0` и адрес из `Server::*_addr()`.
///
/// TCP-bind эксклюзивен, поэтому коллизия здесь видна как `EADDRINUSE` при
/// старте сервера — её нужно ретраить (см. `start_pair` в `secondary.rs`).
#[must_use]
pub fn reserved_tcp_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve tcp port");
    listener.local_addr().expect("reserved tcp addr")
}

/// `recv_from`, переживающий `EINTR`.
///
/// В одном тест-бинарнике параллельно живут десятки потоков (TLS, `DNSCrypt`,
/// tokio-рантаймы); обработчики сигналов, установленные чужим кодом, прерывают
/// блокирующий `recvfrom`. `EINTR` — не таймаут и не «тишина», его нужно
/// повторять, иначе тест падает по случайной причине.
pub fn udp_recv_from(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
    loop {
        match socket.recv_from(buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// `send_to`, переживающий `EINTR`.
pub fn udp_send_to(
    socket: &UdpSocket,
    payload: &[u8],
    target: SocketAddr,
) -> std::io::Result<usize> {
    loop {
        match socket.send_to(payload, target) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

pub struct TempZone {
    _dir: tempfile::TempDir,
    pub data: PathBuf,
}

impl TempZone {
    pub fn empty(label: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("pulsed-{label}-{}-", std::process::id()))
            .tempdir()
            .expect("temp dir");
        let data = dir.path().join("zones.pulse");
        Self { _dir: dir, data }
    }

    pub fn with_import(label: &str, origin: &str, zone: &Path) -> Self {
        let temp = Self::empty(label);
        import(&temp.data, origin, zone);
        temp
    }

    pub fn path(&self) -> &Path {
        &self.data
    }
}

pub fn example_zone() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/example.com.zone")
}

pub fn write_text(label: &str, name: &str, text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix(&format!("pulsed-{label}-{}-", std::process::id()))
        .tempdir()
        .expect("temp dir");
    let path = dir.path().join(name);
    std::fs::write(&path, text).expect("write zone");
    (dir, path)
}

pub fn import(data: &Path, origin: &str, zone: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_pulsed"))
        .arg("import")
        .arg("--data")
        .arg(data)
        .arg("--origin")
        .arg(origin)
        .arg(zone)
        .env_remove("PULSED_API_TOKEN")
        .output()
        .expect("run pulsed import");
    assert!(
        output.status.success(),
        "import failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn base_config(data: &Path) -> Config {
    Config {
        listen_udp: Some("127.0.0.1:0".parse().expect("udp")),
        listen_tcp: Some("127.0.0.1:0".parse().expect("tcp")),
        workers: 1,
        tcp: TcpConfig {
            idle_timeout_ms: 2000,
            ..TcpConfig::default()
        },
        zonefile: Some(data.to_path_buf()),
        durability: Durability::Flush,
        map_size: 64 * 1024 * 1024,
        ..Config::default()
    }
}

pub fn unique_serial() -> u32 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    u32::try_from(seconds % 4_000_000_000).unwrap_or(1).max(1)
}
