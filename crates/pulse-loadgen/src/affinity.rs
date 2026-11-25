//! CPU-списки, affinity потоков и SMT-topology.
//!
//! Харнесс пиннит сервер (`taskset -c ...`) и клиентские потоки
//! (`sched_setaffinity(0, ...)` для текущего потока). Это снимает
//! loopback+SMT-искажение: сервер и клиент не должны делить физическое
//! ядро с SMT-сиблингом.
//!
//! `unsafe` — ровно один вызов `sched_setaffinity`; он локализован в
//! [`set_current_thread_affinity`] и помечен `#[allow(unsafe_code)]`
//! (workspace-lint `unsafe_code = "deny"` остаётся для остального крейта).

use std::fmt;
use std::io;

/// Набор CPU (отсортирован, без дублей).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CpuSet {
    cpus: Vec<usize>,
}

impl CpuSet {
    /// Разбирает список вида `0,2,4-6`.
    ///
    /// # Errors
    ///
    /// Пустой список, нечисловой токен, обратный диапазон или CPU ≥ 4096.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("пустой список CPU".to_owned());
        }
        let mut cpus = Vec::new();
        for part in text.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(format!("пустой элемент в списке CPU {text:?}"));
            }
            if let Some((start, end)) = part.split_once('-') {
                let start = parse_cpu(start, text)?;
                let end = parse_cpu(end, text)?;
                if start > end {
                    return Err(format!("обратный диапазон {start}-{end} в {text:?}"));
                }
                cpus.extend(start..=end);
            } else {
                cpus.push(parse_cpu(part, text)?);
            }
        }
        cpus.sort_unstable();
        cpus.dedup();
        Ok(Self { cpus })
    }

    /// Создаёт набор из уже проверенных CPU.
    #[must_use]
    pub fn new(mut cpus: Vec<usize>) -> Self {
        cpus.sort_unstable();
        cpus.dedup();
        Self { cpus }
    }

    /// CPU в порядке возрастания.
    #[must_use]
    pub fn cpus(&self) -> &[usize] {
        &self.cpus
    }

    /// Число CPU.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cpus.len()
    }

    /// Пуст ли набор.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cpus.is_empty()
    }

    /// Содержит ли CPU.
    #[must_use]
    pub fn contains(&self, cpu: usize) -> bool {
        self.cpus.binary_search(&cpu).is_ok()
    }

    /// Пересекается ли с другим набором.
    #[must_use]
    pub fn intersects(&self, other: &Self) -> bool {
        self.cpus.iter().any(|cpu| other.contains(*cpu))
    }

    /// Половина набора (для split-ролей DNS/REST).
    #[must_use]
    pub fn split_at_half(&self) -> (Self, Self) {
        let middle = self.cpus.len() / 2;
        (
            Self::new(self.cpus[..middle].to_vec()),
            Self::new(self.cpus[middle..].to_vec()),
        )
    }

    /// Компактный вид: `0-2,5`.
    #[must_use]
    pub fn as_list(&self) -> String {
        format_cpus(&self.cpus)
    }
}

impl fmt::Display for CpuSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_list())
    }
}

fn parse_cpu(text: &str, whole: &str) -> Result<usize, String> {
    let cpu: usize = text
        .trim()
        .parse()
        .map_err(|_| format!("нечисловой CPU {text:?} в {whole:?}"))?;
    if cpu >= 4096 {
        return Err(format!("CPU {cpu} вне поддерживаемого диапазона 0..4095"));
    }
    Ok(cpu)
}

/// Компактный список CPU: `0-2,5`.
#[must_use]
pub fn format_cpus(cpus: &[usize]) -> String {
    if cpus.is_empty() {
        return String::new();
    }
    let mut sorted = cpus.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts = Vec::new();
    let mut start = sorted[0];
    let mut end = start;
    for &cpu in &sorted[1..] {
        if cpu == end + 1 {
            end = cpu;
        } else {
            parts.push(range_text(start, end));
            start = cpu;
            end = cpu;
        }
    }
    parts.push(range_text(start, end));
    parts.join(",")
}

fn range_text(start: usize, end: usize) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}

/// CPU, разрешённые текущему процессу (`Cpus_allowed_list`).
///
/// Читается `/proc/self/status` — без `unsafe` и без `sched_getaffinity`.
///
/// # Errors
///
/// Не удалось прочитать статус и разобрать список.
pub fn allowed_cpus() -> Result<CpuSet, String> {
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|error| format!("/proc/self/status: {error}"))?;
    status_cpu_list(&status)
        .ok_or_else(|| "Cpus_allowed_list не найден в /proc/self/status".to_owned())
}

/// CPU конкретного процесса (`Cpus_allowed_list` из `/proc/<pid>/status`).
#[must_use]
pub fn pid_cpus(pid: u32) -> Option<CpuSet> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status_cpu_list(&status)
}

fn status_cpu_list(status: &str) -> Option<CpuSet> {
    let line = status
        .lines()
        .find(|line| line.starts_with("Cpus_allowed_list:"))?;
    let value = line.split_once(':')?.1;
    CpuSet::parse(value).ok()
}

/// Проверяет, что серверный и клиентский наборы не пусты, входят в
/// разрешённый набор и не пересекаются.
///
/// # Errors
///
/// Нарушение любого из инвариантов; текст пригоден для вывода пользователю.
pub fn validate_partition(
    server: &CpuSet,
    client: &CpuSet,
    allowed: &CpuSet,
) -> Result<(), String> {
    if server.is_empty() || client.is_empty() {
        return Err("--server-cpus/--client-cpus не должны быть пустыми".to_owned());
    }
    let outside = |set: &CpuSet| -> Vec<usize> {
        set.cpus()
            .iter()
            .copied()
            .filter(|cpu| !allowed.contains(*cpu))
            .collect()
    };
    let server_outside = outside(server);
    let client_outside = outside(client);
    if !server_outside.is_empty() || !client_outside.is_empty() {
        return Err(format!(
            "CPU вне sched_getaffinity (allowed {}): server {:?}, client {:?}. \
             Уберите их или запустите под taskset/cgroup с более широким набором.",
            allowed.as_list(),
            server_outside,
            client_outside
        ));
    }
    if server.intersects(client) {
        let overlap: Vec<usize> = server
            .cpus()
            .iter()
            .copied()
            .filter(|cpu| client.contains(*cpu))
            .collect();
        return Err(format!(
            "наборы --server-cpus и --client-cpus пересекаются по CPU {overlap:?}; \
             для isolated-стенда они обязаны быть непересекающимися"
        ));
    }
    Ok(())
}

/// Прибивает текущий поток к одному CPU из списка (round-robin по индексу).
///
/// # Errors
///
/// `sched_setaffinity` завершился ошибкой (обычно EPERM в контейнере).
pub fn pin_thread(cpus: &[usize], index: usize) -> Result<(), String> {
    if cpus.is_empty() {
        return Ok(());
    }
    let cpu = cpus[index % cpus.len()];
    set_current_thread_affinity(&[cpu])
}

/// Прибивает текущий поток к набору CPU.
///
/// # Errors
///
/// `sched_setaffinity` завершился ошибкой.
#[allow(unsafe_code)]
pub fn set_current_thread_affinity(cpus: &[usize]) -> Result<(), String> {
    if cpus.is_empty() {
        return Err("пустой набор CPU".to_owned());
    }
    let max = cpus.iter().copied().max().unwrap_or(0);
    let words = max / 64 + 1;
    let mut mask = vec![0_u64; words];
    for &cpu in cpus {
        mask[cpu / 64] |= 1_u64 << (cpu % 64);
    }
    // SAFETY: `mask` — валидный указатель на `words * size_of::<u64>()` байт;
    // pid=0 означает «текущий поток». Ядро копирует ровно `size` байт и
    // игнорирует биты выше nr_cpu_ids. Буфер живёт до конца вызова.
    let result = unsafe {
        libc::sched_setaffinity(
            0,
            words * std::mem::size_of::<u64>(),
            mask.as_ptr().cast::<libc::cpu_set_t>(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "sched_setaffinity({}): {}",
            format_cpus(cpus),
            io::Error::last_os_error()
        ))
    }
}

/// Группа SMT-сиблингов (одно физическое ядро).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiblingGroup {
    /// Логические CPU одного физического ядра.
    pub cpus: CpuSet,
}

/// Читает `/sys/devices/system/cpu/cpu*/topology/thread_siblings_list`.
#[must_use]
pub fn topology() -> Vec<SiblingGroup> {
    let count = std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get);
    let mut entries = Vec::new();
    for cpu in 0..count {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
        if let Ok(text) = std::fs::read_to_string(path) {
            entries.push((cpu, text.trim().to_owned()));
        }
    }
    groups_from_entries(&entries)
}

fn groups_from_entries(entries: &[(usize, String)]) -> Vec<SiblingGroup> {
    let mut seen: Vec<Vec<usize>> = Vec::new();
    for (cpu, text) in entries {
        let mut cpus = CpuSet::parse(text).map_or_else(|_| vec![*cpu], |set| set.cpus().to_vec());
        if !cpus.contains(cpu) {
            cpus.push(*cpu);
            cpus.sort_unstable();
            cpus.dedup();
        }
        if !seen.contains(&cpus) {
            seen.push(cpus);
        }
    }
    seen.sort_by_key(|cpus| *cpus.first().unwrap_or(&usize::MAX));
    seen.into_iter()
        .map(|cpus| SiblingGroup {
            cpus: CpuSet::new(cpus),
        })
        .collect()
}

/// Группы, в которых есть CPU и сервера, и клиента (то есть они делят
/// физическое ядро через SMT).
#[must_use]
pub fn shared_groups(server: &CpuSet, client: &CpuSet, groups: &[SiblingGroup]) -> Vec<CpuSet> {
    groups
        .iter()
        .filter(|group| group.cpus.intersects(server) && group.cpus.intersects(client))
        .map(|group| group.cpus.clone())
        .collect()
}

/// Предлагает раскладку: сервер и клиент получают целые физические ядра
/// (все SMT-сиблинги каждой группы).
///
/// # Errors
///
/// Меньше двух физических ядер — изолировать сервер и клиент нельзя.
pub fn suggest_layout(groups: &[SiblingGroup]) -> Result<Suggestion, String> {
    if groups.len() < 2 {
        return Err(format!(
            "найдено {} физических ядер (SMT-групп); для isolated-стенда нужно ≥ 2",
            groups.len()
        ));
    }
    let split = groups.len() / 2;
    let server: Vec<usize> = groups[..split]
        .iter()
        .flat_map(|group| group.cpus.cpus().iter().copied())
        .collect();
    let client: Vec<usize> = groups[split..]
        .iter()
        .flat_map(|group| group.cpus.cpus().iter().copied())
        .collect();
    let note = format!(
        "Авто-раскладка: сервер — целые физические ядра {}, клиент — {}. \
         Каждая сторона владеет всеми SMT-сиблингами своих ядер. \
         Раскладка вида 0,2,4,6/1,3,5,7 оставляет сиблингов в разных ролях \
         и не изолирует ядро.",
        CpuSet::new(server.clone()).as_list(),
        CpuSet::new(client.clone()).as_list()
    );
    Ok(Suggestion {
        server: CpuSet::new(server),
        client: CpuSet::new(client),
        note,
    })
}

/// Результат [`suggest_layout`].
#[derive(Debug, Clone)]
pub struct Suggestion {
    /// Серверные CPU.
    pub server: CpuSet,
    /// Клиентские CPU.
    pub client: CpuSet,
    /// Пояснение.
    pub note: String,
}

/// Строка «физическое ядро → CPU» для отчёта.
#[must_use]
pub fn topology_report(groups: &[SiblingGroup]) -> String {
    groups
        .iter()
        .enumerate()
        .map(|(index, group)| format!("core{index}: {}", group.cpus.as_list()))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lists_and_ranges() {
        let set = CpuSet::parse("0,2,4-6,6").expect("set");
        assert_eq!(set.cpus(), &[0, 2, 4, 5, 6]);
        assert_eq!(set.as_list(), "0,2,4-6");
        assert!(set.contains(5));
        assert!(!set.contains(1));
    }

    #[test]
    fn rejects_bad_lists() {
        assert!(CpuSet::parse("").is_err());
        assert!(CpuSet::parse("0,,1").is_err());
        assert!(CpuSet::parse("4-2").is_err());
        assert!(CpuSet::parse("x").is_err());
        assert!(CpuSet::parse("5000").is_err());
    }

    #[test]
    fn partition_rules() {
        let allowed = CpuSet::parse("0-7").expect("allowed");
        let server = CpuSet::parse("0-3").expect("server");
        let client = CpuSet::parse("4-7").expect("client");
        assert!(validate_partition(&server, &client, &allowed).is_ok());
        assert!(validate_partition(&server, &CpuSet::parse("3-7").unwrap(), &allowed).is_err());
        assert!(validate_partition(&server, &CpuSet::parse("8").unwrap(), &allowed).is_err());
    }

    #[test]
    fn groups_deduplicate_siblings() {
        let entries = vec![
            (0, "0-1".to_owned()),
            (1, "0-1".to_owned()),
            (2, "2,3".to_owned()),
            (3, "2-3".to_owned()),
            (4, "4-5".to_owned()),
            (5, "4-5".to_owned()),
            (6, "6-7".to_owned()),
            (7, "6-7".to_owned()),
        ];
        let groups = groups_from_entries(&entries);
        assert_eq!(groups.len(), 4);
        assert_eq!(groups[0].cpus.as_list(), "0-1");
        assert_eq!(
            topology_report(&groups),
            "core0: 0-1, core1: 2-3, core2: 4-5, core3: 6-7"
        );
    }

    #[test]
    fn suggests_whole_core_split() {
        let groups = groups_from_entries(&[
            (0, "0-1".to_owned()),
            (1, "0-1".to_owned()),
            (2, "2-3".to_owned()),
            (3, "2-3".to_owned()),
            (4, "4-5".to_owned()),
            (5, "4-5".to_owned()),
            (6, "6-7".to_owned()),
            (7, "6-7".to_owned()),
        ]);
        let suggestion = suggest_layout(&groups).expect("layout");
        assert_eq!(suggestion.server.as_list(), "0-3");
        assert_eq!(suggestion.client.as_list(), "4-7");
        assert_eq!(
            shared_groups(&suggestion.server, &suggestion.client, &groups).len(),
            0
        );
    }

    #[test]
    fn detects_interleaved_sibling_sharing() {
        let groups = groups_from_entries(&[
            (0, "0-1".to_owned()),
            (1, "0-1".to_owned()),
            (2, "2-3".to_owned()),
            (3, "2-3".to_owned()),
        ]);
        let server = CpuSet::parse("0,2").expect("server");
        let client = CpuSet::parse("1,3").expect("client");
        let shared = shared_groups(&server, &client, &groups);
        assert_eq!(shared.len(), 2);
    }

    #[test]
    fn split_half_keeps_roles_disjoint() {
        let set = CpuSet::parse("4-7").expect("set");
        let (dns, rest) = set.split_at_half();
        assert_eq!(dns.as_list(), "4-5");
        assert_eq!(rest.as_list(), "6-7");
        assert!(!dns.intersects(&rest));
    }
}
