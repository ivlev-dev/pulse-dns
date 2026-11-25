//! Общие помощники e2e: временный zonefile, импорт master-файла бинарником и
//! retry-примитивы для тестов с реальной сетью и фоновыми потоками.

#![allow(dead_code)]

use std::fmt;
use std::io::Read;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
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

/// Сколько ждать готовности дочернего `pulsed` (API/порт) до паники сценария.
pub const CHILD_READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Сколько ждать подтверждения смерти после `SIGKILL`, прежде чем считать
/// процесс «неубранным» (на практике `kill` + `wait` укладываются в миллисекунды).
pub const CHILD_KILL_TIMEOUT: Duration = Duration::from_secs(5);

/// Потолок для CLI-команд (`import`, `convert`, `fsck`, `dnscrypt-gencert`).
///
/// Обычный прогон занимает секунды; 60 с — это страховка от вечного зависания,
/// которое оставило бы процесс после падения/таймаута тест-раннера.
pub const CLI_TIMEOUT: Duration = Duration::from_secs(60);

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
    let mut command = pulsed();
    command
        .arg("import")
        .arg("--data")
        .arg(data)
        .arg("--origin")
        .arg(origin)
        .arg(zone)
        .env_remove("PULSED_API_TOKEN");
    let output = run_cli("pulsed import", &mut command, CLI_TIMEOUT);
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

/// Команда запуска тестируемого бинарника.
#[must_use]
pub fn pulsed() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pulsed"))
}

/// Запускает CLI-команду с таймаутом и гарантированным `SIGKILL` при зависании.
///
/// `Command::output()` ждёт вечно: если `pulsed` завис (дедлок, недоступный
/// ресурс), тест-раннер убивает только тест, а дочерний процесс остаётся
/// сиротой. Здесь stdout/stderr вычитываются параллельными потоками, а по
/// истечении `timeout` процесс убивается и переиспользуется, после чего тест
/// падает с PID и накопленным выводом.
pub fn run_cli(label: &str, command: &mut Command, timeout: Duration) -> Output {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("{label}: spawn pulsed: {error}"));
    let pid = child.id();
    let stdout = child.stdout.take().expect("stdout pipe");
    let stderr = child.stderr.take().expect("stderr pipe");
    let stdout_reader = thread::spawn(move || drain(stdout));
    let stderr_reader = thread::spawn(move || drain(stderr));

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                panic!("{label}: try_wait for pid {pid}: {error}");
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let stdout = stdout_reader.join().unwrap_or_default();
            let stderr = stderr_reader.join().unwrap_or_default();
            panic!(
                "{label}: pulsed pid {pid} не завершился за {timeout:?}; отправлен SIGKILL\n\
                 stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    };

    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    Output {
        status,
        stdout,
        stderr,
    }
}

fn drain(mut pipe: impl Read) -> Vec<u8> {
    let mut buffer = Vec::new();
    let _ = pipe.read_to_end(&mut buffer);
    buffer
}

/// RAII-guard долгоживущего дочернего `pulsed`.
///
/// Гарантирует, что процесс будет убит (`SIGKILL`) и переиспользован (`wait`)
/// при любом выходе из сценария, включая панику по `assert!`. В `Drop` при
/// обнаружении живого процесса после сценария тест падает с PID — так утечка
/// не может «пройти незамеченной».
pub struct PulsedChild {
    label: String,
    pid: u32,
    child: Option<Child>,
    status: Option<ExitStatus>,
}

impl PulsedChild {
    /// Запускает `pulsed` под guard'ом. Аргументы/stdio задаёт вызывающий.
    pub fn spawn(label: impl Into<String>, command: &mut Command) -> Self {
        let label = label.into();
        let child = command
            .spawn()
            .unwrap_or_else(|error| panic!("{label}: spawn pulsed: {error}"));
        let pid = child.id();
        eprintln!("[pulsed-test] {label}: запущен pid {pid}");
        Self {
            label,
            pid,
            child: Some(child),
            status: None,
        }
    }

    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// `true`, пока процесс жив; завершившийся процесс переиспользуется.
    pub fn is_running(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                self.status = Some(status);
                self.child = None;
                false
            }
            Ok(None) => true,
            Err(error) => panic!("{}: try_wait для pid {}: {error}", self.label, self.pid),
        }
    }

    /// Ждёт готовности (`probe`) или смерти процесса.
    pub fn wait_ready(&mut self, timeout: Duration, mut probe: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if probe() {
                return true;
            }
            if !self.is_running() {
                return false;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// Ждёт завершения процесса до `timeout`; возвращает статус, если он умер.
    pub fn wait_for_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if !self.is_running() {
                return self.status;
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// `SIGKILL` + `wait` с таймаутом. Идемпотентно.
    pub fn kill(&mut self) -> Option<ExitStatus> {
        if let Some(status) = self.status {
            return Some(status);
        }
        let child = self.child.as_mut()?;
        if let Err(error) = child.kill() {
            eprintln!(
                "[pulsed-test] {}: kill pid {}: {error} (возможно, уже завершился)",
                self.label, self.pid
            );
        }
        let status = self.reap_with_timeout();
        if status.is_none() {
            eprintln!(
                "[pulsed-test] {}: pid {} не переиспользован за {:?} после SIGKILL",
                self.label, self.pid, CHILD_KILL_TIMEOUT
            );
        }
        status
    }

    /// Проверяет, что после сценария процесс мёртв. При утечке — `SIGKILL` и
    /// паника с PID (чтобы тест не прошёл, а процесс не остался висеть).
    pub fn assert_dead(&mut self) {
        if !self.is_running() {
            return;
        }
        let pid = self.pid;
        let _ = self.kill();
        panic!(
            "{}: дочерний pulsed (pid {pid}) остался жив после сценария; отправлен SIGKILL",
            self.label
        );
    }

    fn reap_with_timeout(&mut self) -> Option<ExitStatus> {
        let deadline = Instant::now() + CHILD_KILL_TIMEOUT;
        loop {
            let Some(child) = self.child.as_mut() else {
                return self.status;
            };
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.status = Some(status);
                    self.child = None;
                    return Some(status);
                }
                Ok(None) => {}
                Err(error) => {
                    eprintln!("{}: try_wait для pid {}: {error}", self.label, self.pid);
                    return None;
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for PulsedChild {
    fn drop(&mut self) {
        if self.child.is_none() {
            return;
        }
        let pid = self.pid;
        let label = self.label.clone();
        eprintln!("[pulsed-test] {label}: утечка pid {pid} — SIGKILL в Drop");
        let _ = self.kill();
        assert!(
            thread::panicking(),
            "{label}: дочерний pulsed (pid {pid}) не был остановлен сценарием"
        );
    }
}
