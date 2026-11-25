//! Самопроверка тест-харнеса: RAII-guard и CLI-таймаут обязаны убивать
//! дочерний процесс даже при панике сценария и сообщать PID при утечке.

#![cfg(target_os = "linux")]

mod common;

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

/// `true`, пока ядро держит запись процесса (зомби после `wait` уже исчезает).
fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => match payload.downcast::<&'static str>() {
            Ok(message) => (*message).to_owned(),
            Err(_) => "<не строковая паника>".to_owned(),
        },
    }
}

fn pid_from_message(message: &str) -> u32 {
    let rest = message
        .split("pid ")
        .nth(1)
        .unwrap_or_else(|| panic!("в панике нет PID: {message}"));
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits
        .parse()
        .unwrap_or_else(|error| panic!("не разобрал PID из «{message}»: {error}"))
}

fn sleeper() -> Command {
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("exec sleep 120")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

#[test]
fn guard_kills_child_when_scenario_panics() {
    let pid = Arc::new(AtomicU32::new(0));
    let observed = Arc::clone(&pid);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let child = common::PulsedChild::spawn("self-test/panic", &mut sleeper());
        observed.store(child.pid(), Ordering::SeqCst);
        panic!("injected panic inside guarded scenario");
    }));
    assert!(result.is_err(), "сценарий обязан был упасть");
    let pid = pid.load(Ordering::SeqCst);
    assert_ne!(pid, 0, "guard не вернул PID");
    assert!(
        !alive(pid),
        "RAII-guard оставил процесс pid {pid} после паники сценария"
    );
}

#[test]
fn guard_reports_leak_with_pid_and_kills() {
    let mut child = common::PulsedChild::spawn("self-test/leak", &mut sleeper());
    let pid = child.pid();
    assert!(alive(pid), "процесс pid {pid} должен быть жив до проверки");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        child.assert_dead();
    }));
    let message = panic_message(result.expect_err("assert_dead обязан паниковать"));
    assert!(
        message.contains(&pid.to_string()),
        "паника должна содержать PID {pid}: {message}"
    );
    assert!(
        !alive(pid),
        "assert_dead обязан убить процесс pid {pid} перед паникой"
    );
}

#[test]
fn cli_timeout_kills_hanging_process() {
    let mut command = Command::new("sh");
    command.arg("-c").arg("exec sleep 120").stdin(Stdio::null());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = common::run_cli(
            "self-test/timeout",
            &mut command,
            Duration::from_millis(300),
        );
    }));
    let message = panic_message(result.expect_err("таймаут обязан паниковать"));
    let pid = pid_from_message(&message);
    assert!(
        !alive(pid),
        "CLI-таймаут оставил процесс pid {pid}: {message}"
    );
}

/// Реальный `pulsed`, а не подставной `sleep`: guard обязан убрать именно его.
#[test]
fn real_pulsed_is_killed_when_scenario_panics() {
    let dir = tempfile::tempdir().expect("temp dir");
    let data = dir.path().join("panic.v2");
    let config = dir.path().join("pulsed.json");
    std::fs::write(
        &config,
        r#"{"listen_udp":"127.0.0.1:0","listen_tcp":null,"workers":1}"#,
    )
    .expect("config");

    let pid = Arc::new(AtomicU32::new(0));
    let observed = Arc::clone(&pid);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let mut command = common::pulsed();
        command
            .arg("--config")
            .arg(&config)
            .arg("--data")
            .arg(&data)
            .env_remove("PULSED_API_TOKEN")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = common::PulsedChild::spawn("self-test/real-pulsed", &mut command);
        observed.store(child.pid(), Ordering::SeqCst);
        assert!(
            child.wait_for_exit(Duration::from_millis(500)).is_none(),
            "pulsed завершился до инъекции паники"
        );
        panic!("injected panic with a live pulsed child");
    }));
    assert!(result.is_err(), "сценарий обязан был упасть");
    let pid = pid.load(Ordering::SeqCst);
    assert_ne!(pid, 0, "guard не вернул PID");
    assert!(
        !alive(pid),
        "RAII-guard оставил реальный pulsed pid {pid} после паники"
    );
}
