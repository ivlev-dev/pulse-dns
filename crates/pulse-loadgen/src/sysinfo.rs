//! Счётчики хоста и ядра: UDP drops, CPU, loadavg.
//!
//! `SO_RXQ_OVFL` требует `unsafe` (cmsg + setsockopt), поэтому в этом харнессе
//! не используется: потери оцениваются по `UdpInErrors`/`UdpRcvbufErrors`
//! (`/proc/net/snmp`) и, если доступен, `nstat -az`. Это глобальные счётчики
//! namespace — на шумном хосте их нужно читать вместе с loadavg.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// UDP-счётчики из `/proc/net/snmp`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UdpCounters {
    /// Принято датаграмм.
    pub in_datagrams: u64,
    /// Нет слушателя.
    pub no_ports: u64,
    /// Ошибки приёма (включая переполнение буфера).
    pub in_errors: u64,
    /// Отправлено датаграмм.
    pub out_datagrams: u64,
    /// Переполнение receive buffer.
    pub rcvbuf_errors: u64,
    /// Переполнение send buffer.
    pub sndbuf_errors: u64,
    /// Ошибки checksum.
    pub in_csum_errors: u64,
}

/// Дельта UDP-счётчиков за прогон.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KernelDelta {
    /// `UdpInErrors` до.
    pub in_errors_before: u64,
    /// `UdpInErrors` после.
    pub in_errors_after: u64,
    /// `UdpRcvbufErrors` до.
    pub rcvbuf_errors_before: u64,
    /// `UdpRcvbufErrors` после.
    pub rcvbuf_errors_after: u64,
    /// `UdpInDatagrams` до.
    pub in_datagrams_before: u64,
    /// `UdpInDatagrams` после.
    pub in_datagrams_after: u64,
    /// `UdpOutDatagrams` до.
    pub out_datagrams_before: u64,
    /// `UdpOutDatagrams` после.
    pub out_datagrams_after: u64,
    /// `nstat UdpRcvbufErrors` до (если `nstat` доступен).
    pub nstat_rcvbuf_before: Option<u64>,
    /// `nstat UdpRcvbufErrors` после.
    pub nstat_rcvbuf_after: Option<u64>,
}

impl KernelDelta {
    /// Разница `UdpInErrors`.
    #[must_use]
    pub const fn in_errors(self) -> u64 {
        self.in_errors_after.saturating_sub(self.in_errors_before)
    }

    /// Разница `UdpRcvbufErrors`.
    #[must_use]
    pub const fn rcvbuf_errors(self) -> u64 {
        self.rcvbuf_errors_after
            .saturating_sub(self.rcvbuf_errors_before)
    }

    /// Разница `UdpInDatagrams` (все UDP-сокеты namespace).
    #[must_use]
    pub const fn in_datagrams(self) -> u64 {
        self.in_datagrams_after
            .saturating_sub(self.in_datagrams_before)
    }

    /// Разница `UdpOutDatagrams`.
    #[must_use]
    pub const fn out_datagrams(self) -> u64 {
        self.out_datagrams_after
            .saturating_sub(self.out_datagrams_before)
    }

    /// Разница `nstat UdpRcvbufErrors`, если доступен.
    #[must_use]
    pub fn nstat_rcvbuf(self) -> Option<u64> {
        Some(
            self.nstat_rcvbuf_after?
                .saturating_sub(self.nstat_rcvbuf_before?),
        )
    }
}

/// Снимок UDP-счётчиков.
#[must_use]
pub fn read_udp() -> UdpCounters {
    read_udp_from(Path::new("/proc/net/snmp")).unwrap_or_default()
}

fn read_udp_from(path: &Path) -> Option<UdpCounters> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut header: Option<Vec<String>> = None;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("Udp: ") else {
            continue;
        };
        let fields: Vec<String> = rest.split_whitespace().map(str::to_owned).collect();
        if fields
            .first()
            .is_some_and(|field| field.parse::<u64>().is_ok())
        {
            let header = header.take()?;
            let mut counters = UdpCounters::default();
            for (name, value) in header.iter().zip(fields.iter()) {
                let value: u64 = value.parse().ok()?;
                match name.as_str() {
                    "InDatagrams" => counters.in_datagrams = value,
                    "NoPorts" => counters.no_ports = value,
                    "InErrors" => counters.in_errors = value,
                    "OutDatagrams" => counters.out_datagrams = value,
                    "RcvbufErrors" => counters.rcvbuf_errors = value,
                    "SndbufErrors" => counters.sndbuf_errors = value,
                    "InCsumErrors" => counters.in_csum_errors = value,
                    _ => {}
                }
            }
            return Some(counters);
        }
        header = Some(fields);
    }
    None
}

/// `nstat -az` как map (пусто, если утилита недоступна).
#[must_use]
pub fn nstat_counters() -> Option<BTreeMap<String, u64>> {
    let output = Command::new("nstat").arg("-az").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut counters = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        if name.starts_with('#') {
            continue;
        }
        let Some(value) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        counters.insert(name.to_owned(), value);
    }
    Some(counters)
}

/// Снимок счётчиков до/после прогона.
#[must_use]
pub fn snapshot() -> (UdpCounters, Option<BTreeMap<String, u64>>) {
    (read_udp(), nstat_counters())
}

/// Дельта между снимками.
#[must_use]
pub fn delta(
    before: &(UdpCounters, Option<BTreeMap<String, u64>>),
    after: &(UdpCounters, Option<BTreeMap<String, u64>>),
) -> KernelDelta {
    let nstat_before = before
        .1
        .as_ref()
        .and_then(|map| map.get("UdpRcvbufErrors").copied());
    let nstat_after = after
        .1
        .as_ref()
        .and_then(|map| map.get("UdpRcvbufErrors").copied());
    KernelDelta {
        in_errors_before: before.0.in_errors,
        in_errors_after: after.0.in_errors,
        rcvbuf_errors_before: before.0.rcvbuf_errors,
        rcvbuf_errors_after: after.0.rcvbuf_errors,
        in_datagrams_before: before.0.in_datagrams,
        in_datagrams_after: after.0.in_datagrams,
        out_datagrams_before: before.0.out_datagrams,
        out_datagrams_after: after.0.out_datagrams,
        nstat_rcvbuf_before: nstat_before,
        nstat_rcvbuf_after: nstat_after,
    }
}

/// Информация о хосте (для честной пометки шума).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct HostInfo {
    /// Число online CPU.
    pub cpus: usize,
    /// Модель CPU.
    pub model: String,
    /// Версия ядра.
    pub kernel: String,
    /// `loadavg` на момент старта.
    pub loadavg: [f64; 3],
    /// SMT siblings (например `0-1`).
    pub smt: String,
    /// SMT-группы: `core0: 0-1, core1: 2-3, ...`.
    #[serde(default)]
    pub siblings: Vec<String>,
    /// Имя хоста.
    pub hostname: String,
}

/// Снимает информацию о хосте.
#[must_use]
pub fn host_info() -> HostInfo {
    let cpus = std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get);
    let model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("model name\t: ").map(str::to_owned))
        })
        .unwrap_or_default();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|text| text.trim().to_owned())
        .unwrap_or_default();
    let loadavg = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| {
            let mut fields = text.split_whitespace();
            let one = fields.next()?.parse().ok()?;
            let five = fields.next()?.parse().ok()?;
            let fifteen = fields.next()?.parse().ok()?;
            Some([one, five, fifteen])
        })
        .unwrap_or([0.0; 3]);
    let smt = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list")
        .map(|text| text.trim().to_owned())
        .unwrap_or_default();
    let siblings = crate::affinity::topology()
        .iter()
        .map(|group| group.cpus.as_list())
        .collect();
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|text| text.trim().to_owned())
        .unwrap_or_default();
    HostInfo {
        cpus,
        model,
        kernel,
        loadavg,
        smt,
        siblings,
        hostname,
    }
}

/// CPU-тики процесса (`utime + stime`) из `/proc/<pid>/stat`.
#[must_use]
pub fn process_cpu_ticks(pid: u32) -> Option<u64> {
    let (user, system) = process_cpu_ticks_split(pid)?;
    Some(user.saturating_add(system))
}

/// `utime`/`stime` процесса в тиках из `/proc/<pid>/stat`.
#[must_use]
pub fn process_cpu_ticks_split(pid: u32) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = text.rfind(')')?;
    let fields: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
    // После comm и state: utime — 12-е поле из остатка (state=0).
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    Some((utime, stime))
}

/// `VmRSS` процесса, КиБ.
#[must_use]
pub fn process_rss_kb(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
}

/// `CLK_TCK` (на Linux почти всегда 100; читается из `getconf`).
#[must_use]
pub fn clock_ticks_per_sec() -> u64 {
    Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_udp_snmp() {
        let text = "\
Ip: Forwarding DefaultTTL InReceives
Ip: 1 64 100
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors
Udp: 10 2 3 11 4 5 6
";
        let dir = tempfile_dir();
        let path = dir.join("snmp");
        std::fs::write(&path, text).expect("write");
        let counters = read_udp_from(&path).expect("parse");
        assert_eq!(counters.in_datagrams, 10);
        assert_eq!(counters.no_ports, 2);
        assert_eq!(counters.in_errors, 3);
        assert_eq!(counters.out_datagrams, 11);
        assert_eq!(counters.rcvbuf_errors, 4);
        assert_eq!(counters.sndbuf_errors, 5);
        assert_eq!(counters.in_csum_errors, 6);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn delta_saturates() {
        let before = (
            UdpCounters {
                in_errors: 10,
                rcvbuf_errors: 5,
                ..UdpCounters::default()
            },
            None,
        );
        let after = (
            UdpCounters {
                in_errors: 13,
                rcvbuf_errors: 5,
                ..UdpCounters::default()
            },
            None,
        );
        let delta = delta(&before, &after);
        assert_eq!(delta.in_errors(), 3);
        assert_eq!(delta.rcvbuf_errors(), 0);
        assert_eq!(delta.nstat_rcvbuf(), None);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pulse-loadgen-sysinfo-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |value| value.as_nanos())
        ));
        std::fs::create_dir_all(&path).expect("tempdir");
        path
    }
}
