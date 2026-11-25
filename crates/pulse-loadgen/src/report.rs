//! Сборка JSON/Markdown baseline-отчёта.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use hdrhistogram::Histogram;

use crate::mem::MemoryReport;
use crate::sysinfo::HostInfo;
use crate::{Latency, RunResult};

/// Серверные счётчики, восстановленные из финального лога `pulsed`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ServerStats {
    /// UDP-запросов принято.
    pub queries_udp: u64,
    /// TCP-запросов принято.
    pub queries_tcp: u64,
    /// Ответов отправлено.
    pub responses: u64,
    /// Ошибок декодирования.
    pub decode_errors: u64,
    /// Ошибок кодирования.
    pub encode_errors: u64,
    /// Отброшено.
    pub dropped: u64,
    /// Принято UDP-датаграмм (worker).
    pub udp_received: u64,
    /// Отправлено UDP-датаграмм.
    pub udp_sent: u64,
    /// Ошибки приёма UDP.
    pub udp_recv_errors: u64,
    /// Ошибки отправки UDP.
    pub udp_send_errors: u64,
    /// Ответы, отброшенные обработчиком/слотами.
    pub udp_dropped: u64,
    /// Слишком большие датаграммы.
    pub udp_oversize: u64,
    /// NXDOMAIN.
    pub nxdomain: u64,
    /// NODATA.
    pub nodata: u64,
    /// REFUSED.
    pub refused: u64,
    /// SERVFAIL.
    pub servfail: u64,
    /// Серверный qps (responses / длительность прогона).
    pub qps: f64,
    /// Доля user CPU процесса сервера за прогон, % (100% = одно ядро).
    #[serde(default)]
    pub cpu_user_pct: f64,
    /// Доля sys CPU процесса сервера за прогон, %.
    #[serde(default)]
    pub cpu_sys_pct: f64,
    /// `VmRSS` сервера после прогона, КиБ.
    #[serde(default)]
    pub rss_kb: u64,
    /// Реальный `Cpus_allowed_list` сервера (проверка affinity).
    #[serde(default)]
    pub cpus: String,
}

/// CPU-время процесса в процентах от одного ядра.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct CpuUsage {
    /// user-время, %.
    pub user_pct: f64,
    /// sys-время, %.
    pub sys_pct: f64,
    /// Стена, с.
    pub wall_secs: f64,
}

/// Один сценарий: 3 прогона + медиана.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Scenario {
    /// Короткое имя (для таблиц).
    pub name: String,
    /// Что проверяет.
    pub description: String,
    /// Прогоны.
    pub runs: Vec<RunResult>,
    /// Серверные счётчики по прогонам.
    pub server: Vec<ServerStats>,
    /// Индекс медианного прогона.
    pub median: usize,
    /// Пометки о шуме/ограничениях.
    pub notes: Vec<String>,
    /// CPU-время клиентского процесса по прогонам.
    #[serde(default)]
    pub client_cpu: Vec<CpuUsage>,
}

/// `perf stat`-счётчики и hotspots.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PerfReport {
    /// Сценарий.
    pub label: String,
    /// Счётчики `perf stat` (имя → значение).
    pub counters: BTreeMap<String, f64>,
    /// Top-функции из `perf report`.
    pub hotspots: Vec<Hotspot>,
    /// Путь к flamegraph SVG, если удалось построить.
    pub flamegraph: Option<String>,
    /// Пояснение/ошибка.
    pub note: String,
}

/// Функция в профиле.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Hotspot {
    /// Символ.
    pub symbol: String,
    /// Доля, %.
    pub percent: f64,
}

/// Аллокации на операцию.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AllocRow {
    /// Операция (`encode`, `decode`, `lookup`, `lookup_ref`, `udp-e2e`).
    pub op: String,
    /// Число операций.
    pub ops: u64,
    /// Аллокаций всего.
    pub allocations: u64,
    /// Байт всего.
    pub bytes: u64,
    /// Аллокаций на операцию.
    pub allocs_per_op: f64,
    /// Байт на операцию.
    pub bytes_per_op: f64,
}

/// Дополнительный раздел (commit-бенч, заметки).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtraSection {
    /// Заголовок.
    pub title: String,
    /// Markdown-тело.
    pub body: String,
}

/// Полный baseline.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BaselineReport {
    /// Заголовок отчёта (по умолчанию — baseline на loopback).
    #[serde(default)]
    pub title: Option<String>,
    /// Вводная заметка о методике/ограничениях.
    #[serde(default)]
    pub scope_note: Option<String>,
    /// Unix-время генерации.
    pub generated_unix: u64,
    /// Версия `pulsed`.
    pub pulsed_version: String,
    /// Git-ревизия (если доступна), без изменения репозитория.
    pub git_rev: Option<String>,
    /// Хост.
    pub host: HostInfo,
    /// Сценарии нагрузки.
    pub scenarios: Vec<Scenario>,
    /// Memory-сценарии.
    pub memory: Vec<MemoryReport>,
    /// Аллокации.
    pub alloc: Vec<AllocRow>,
    /// Профили.
    pub perf: Vec<PerfReport>,
    /// Дополнительные разделы.
    pub extra: Vec<ExtraSection>,
    /// Рекомендации (markdown).
    pub recommendations: Vec<String>,
    /// Команды воспроизведения.
    pub commands: Vec<String>,
}

/// Переводит HDR-гистограмму в [`Latency`].
#[must_use]
pub fn latency_from_hist(histogram: &Histogram<u64>, scale_ns: f64) -> Latency {
    if histogram.is_empty() {
        return Latency::default();
    }
    #[allow(clippy::cast_precision_loss)]
    let scale = |value: u64| -> u64 { (value as f64 * scale_ns).round() as u64 };
    Latency {
        min: scale(histogram.min()),
        p50: scale(histogram.value_at_quantile(0.50)),
        p90: scale(histogram.value_at_quantile(0.90)),
        p99: scale(histogram.value_at_quantile(0.99)),
        p999: scale(histogram.value_at_quantile(0.999)),
        max: scale(histogram.max()),
        mean: histogram.mean() * scale_ns,
    }
}

/// Медиана `f64` (сортирует копию).
#[must_use]
pub fn median_f64(values: &[f64]) -> f64 {
    let mut values: Vec<f64> = values
        .iter()
        .copied()
        .filter(|value| value.is_finite())
        .collect();
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

/// Медиана `u64`.
#[must_use]
pub fn median_u64(values: &[u64]) -> u64 {
    let mut values: Vec<u64> = values.to_vec();
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[values.len() / 2]
}

/// Выбирает индекс прогона с медианным `client_qps`.
#[must_use]
pub fn median_run_index(runs: &[RunResult]) -> usize {
    if runs.is_empty() {
        return 0;
    }
    let mut order: Vec<usize> = (0..runs.len()).collect();
    order.sort_by(|&left, &right| runs[left].client_qps.total_cmp(&runs[right].client_qps));
    order[order.len() / 2]
}

/// Сохраняет JSON.
///
/// # Errors
///
/// Ошибка сериализации/записи.
pub fn write_json(report: &BaselineReport, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let json = serde_json::to_string_pretty(report).map_err(|error| error.to_string())?;
    std::fs::write(path, json).map_err(|error| error.to_string())
}

/// Сохраняет Markdown.
///
/// # Errors
///
/// Ошибка записи.
pub fn write_markdown(report: &BaselineReport, path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(path, render_markdown(report)).map_err(|error| error.to_string())
}

/// Рендерит Markdown.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_markdown(report: &BaselineReport) -> String {
    let mut out = String::new();
    let host = &report.host;
    let title = report
        .title
        .as_deref()
        .unwrap_or("Baseline: pulsed на loopback");
    let _ = writeln!(out, "# {title}");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Автогенерировано `pulse-bench`; JSON-версия — файл из `--json`.\n\
         Все числа — **медиана трёх прогонов**, если не сказано иное. Прогрев входит в \
         каждый прогон, но не в измерение."
    );
    let _ = writeln!(out);
    if let Some(scope) = &report.scope_note {
        let _ = writeln!(out, "{scope}");
        let _ = writeln!(out);
    }
    let _ = writeln!(out, "## Окружение");
    let _ = writeln!(out);
    let _ = writeln!(out, "| Параметр | Значение |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(out, "| Host | `{}` |", host.hostname);
    let _ = writeln!(out, "| CPU | {} |", host.model);
    let _ = writeln!(out, "| vCPU | {} |", host.cpus);
    let _ = writeln!(out, "| SMT siblings | `{}` |", host.smt);
    let _ = writeln!(
        out,
        "| Физические ядра (SMT-группы) | `{}` |",
        host.siblings.join("`, `")
    );
    let _ = writeln!(out, "| Kernel | `{}` |", host.kernel);
    let _ = writeln!(out, "| `pulsed` | {} |", report.pulsed_version);
    let _ = writeln!(
        out,
        "| Git | `{}` |",
        report.git_rev.as_deref().unwrap_or("(no .git)")
    );
    let _ = writeln!(
        out,
        "| loadavg на старте | {:.2} / {:.2} / {:.2} |",
        host.loadavg[0], host.loadavg[1], host.loadavg[2]
    );
    let _ = writeln!(out, "| Сгенерировано (unix) | {} |", report.generated_unix);
    let _ = writeln!(out);
    if title.contains("Baseline") {
        let _ = writeln!(
            out,
            "> **Шум хоста.** Замеры сделаны на loopback; клиент и сервер делят 8 vCPU \
             (4 физических ядра × SMT). Абсолютные qps ниже, чем на выделенном стенде; \
             сравнивать имеет смысл прогоны между собой и с этим baseline. Перед прогоном \
             проверяйте `loadavg` и `nstat -az | grep -E 'Udp(InErrors|RcvbufErrors)'`."
        );
    } else {
        let _ = writeln!(
            out,
            "> **Изоляция.** Сценарии `iso-*` пиннятся по CPU (`taskset` для сервера, \
             `sched_setaffinity` для клиентских потоков), `shared-*` — контроль на общем \
             наборе CPU. Перед прогоном проверяйте `loadavg` и governor; числа на одной \
             машине сравнимы между собой, но не с другим железом."
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Нагрузка");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Сценарий | Транспорт | Потоки | Цель qps | Клиент qps | Сервер qps | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | srv CPUs | p50 µs | p99 µs | p999 µs | max µs | sent | recv | timeout | rcvbuf Δ | REST qps |"
    );
    let _ = writeln!(
        out,
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    );
    for scenario in &report.scenarios {
        let Some(run) = scenario.runs.get(scenario.median) else {
            continue;
        };
        let server = scenario.server.get(scenario.median);
        let server_qps = server.map_or(0.0, |stats| stats.qps);
        let rcvbuf = run.kernel.rcvbuf_errors();
        let rest_qps = run.rest.as_ref().map_or(0.0, |rest| rest.qps);
        let client_cpu = scenario
            .client_cpu
            .get(scenario.median)
            .copied()
            .unwrap_or_default();
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.1} | `{}` | {:.2} | {:.2} | {:.2} | {:.2} | {} | {} | {} | {} | {:.1} |",
            scenario.name,
            run.mode.as_str(),
            run.threads,
            run.qps_target
                .map_or_else(|| "closed".to_owned(), |qps| format!("{qps:.0}")),
            run.client_qps,
            server_qps,
            client_cpu.user_pct,
            client_cpu.sys_pct,
            server.map_or(0.0, |stats| stats.cpu_user_pct),
            server.map_or(0.0, |stats| stats.cpu_sys_pct),
            server.map_or(0.0, |stats| stats.rss_kb as f64 / 1024.0),
            server.map_or("", |stats| stats.cpus.as_str()),
            ns_to_us(run.latency.p50),
            ns_to_us(run.latency.p99),
            ns_to_us(run.latency.p999),
            ns_to_us(run.latency.max),
            run.sent,
            run.received,
            run.timeouts,
            rcvbuf,
            rest_qps,
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "`rcvbuf Δ` — `UdpRcvbufErrors` namespace за прогон; если он > 0, сервер/ядро \
         теряли датаграммы и qps-число отражает не только сервер. Клиентский qps — \
         `received / время`; серверный — `responses` из финального лога \
         `udp_stats`/`stats` минус ответы прогрева, делённые на время измерения. \
         `cl/srv user%/sys%` — `utime/stime` процесса за прогон (100% = одно ядро; \
         включает прогрев и старт сервера), `srv RSS` — `VmRSS` после прогона."
    );
    let _ = writeln!(out);

    for scenario in &report.scenarios {
        let _ = writeln!(out, "### {}", scenario.name);
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", scenario.description);
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "| Прогон | Клиент qps | p50 µs | p99 µs | p999 µs | max µs | cl user% | cl sys% | srv user% | srv sys% | srv RSS MiB | sent | recv | timeout | invalid | suppressed | rcvbuf Δ | server qps |"
        );
        let _ = writeln!(
            out,
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
        );
        for (index, run) in scenario.runs.iter().enumerate() {
            let server = scenario.server.get(index);
            let client_cpu = scenario.client_cpu.get(index).copied().unwrap_or_default();
            let _ = writeln!(
                out,
                "| {} | {:.0} | {:.2} | {:.2} | {:.2} | {:.2} | {:.0} | {:.0} | {:.0} | {:.0} | {:.1} | {} | {} | {} | {} | {} | {} | {:.0} |",
                if index == scenario.median {
                    "**median**"
                } else {
                    "run"
                },
                run.client_qps,
                ns_to_us(run.latency.p50),
                ns_to_us(run.latency.p99),
                ns_to_us(run.latency.p999),
                ns_to_us(run.latency.max),
                client_cpu.user_pct,
                client_cpu.sys_pct,
                server.map_or(0.0, |stats| stats.cpu_user_pct),
                server.map_or(0.0, |stats| stats.cpu_sys_pct),
                server.map_or(0.0, |stats| stats.rss_kb as f64 / 1024.0),
                run.sent,
                run.received,
                run.timeouts,
                run.invalid,
                run.suppressed,
                run.kernel.rcvbuf_errors(),
                server.map_or(0.0, |stats| stats.qps),
            );
        }
        if !scenario.notes.is_empty() {
            let _ = writeln!(out);
            for note in &scenario.notes {
                let _ = writeln!(out, "- {note}");
            }
        }
        let _ = writeln!(out);
    }

    if !report.memory.is_empty() {
        let _ = writeln!(out, "## Память");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "| Зоны | RRset | Файл MiB | Диск MiB | RSS first MiB | RSS last MiB | Δ MiB | Δ % | RssAnon last MiB | RssFile last MiB | PageCache last MiB | mmap RSS last MiB | PSS last MiB | CPU % | Вердикт |"
        );
        let _ = writeln!(
            out,
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"
        );
        for memory in &report.memory {
            let summary = &memory.summary;
            let _ = writeln!(
                out,
                "| {} | {} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.2}% | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {:.1} | {} |",
                memory.zones,
                memory.rrsets,
                bytes_to_mib(summary.file_bytes),
                bytes_to_mib(summary.disk_bytes),
                kib_to_mib(summary.rss_first_kb),
                kib_to_mib(summary.rss_last_kb),
                summary.rss_growth_kb as f64 / 1024.0,
                summary.rss_growth_pct,
                kib_to_mib(summary.anon_last_kb),
                kib_to_mib(summary.file_last_kb),
                bytes_to_mib(summary.page_cache_last_bytes),
                kib_to_mib(summary.mmap_last_kb),
                kib_to_mib(
                    memory
                        .samples
                        .last()
                        .map_or(0, |sample| sample.smaps_pss_kb)
                ),
                summary.cpu_pct,
                if summary.leak_suspected {
                    "рост > 5%"
                } else {
                    "стабильно"
                },
            );
        }
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "v2 читает файл через `pread`/`pwrite` (`pulse-zonefile::map` используется только v1), \
         поэтому `mmap RSS` = 0 — это ожидаемо. `PageCache` — `fincore RES` файла зон; \
         `Диск MiB` — фактически занятые блоки (sparse-файл может быть больше). Рост \
         `RssAnon` — heap; рост `PageCache` — прогрев файла, не утечка. \
         Для серий < 60 с «Δ %» включает прогрев и не является вердиктом об утечке; \
         вердикт «стабильно/рост > 5%» выносится только для soak ≥ 60 с."
        );
        let _ = writeln!(out);
    }

    if !report.alloc.is_empty() {
        let _ = writeln!(out, "## Аллокации");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Глобальный counting allocator (`dhat`) в отдельном бинарнике `pulse-alloc`; \
             измеряется дельта `HeapStats` на N операций. `udp-e2e` включает клиентский \
             поток (он не аллоцирует на горячем пути) и фоновые потоки сервера."
        );
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "| Операция | ops | allocs | bytes | allocs/op | bytes/op |"
        );
        let _ = writeln!(out, "|---|---|---|---|---|---|");
        for row in &report.alloc {
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} | {:.4} | {:.2} |",
                row.op, row.ops, row.allocations, row.bytes, row.allocs_per_op, row.bytes_per_op
            );
        }
        let _ = writeln!(out);
    }

    if !report.perf.is_empty() {
        let _ = writeln!(out, "## Профиль");
        let _ = writeln!(out);
        for perf in &report.perf {
            let _ = writeln!(out, "### {}", perf.label);
            let _ = writeln!(out);
            if !perf.counters.is_empty() {
                let _ = writeln!(out, "| Счётчик | Значение |");
                let _ = writeln!(out, "|---|---|");
                for (name, value) in &perf.counters {
                    let _ = writeln!(out, "| `{name}` | {value:.3} |");
                }
                let _ = writeln!(out);
            }
            if !perf.hotspots.is_empty() {
                let _ = writeln!(out, "| Функция | % |");
                let _ = writeln!(out, "|---|---|");
                for hotspot in &perf.hotspots {
                    let _ = writeln!(out, "| `{}` | {:.2} |", hotspot.symbol, hotspot.percent);
                }
                let _ = writeln!(out);
            }
            if let Some(path) = &perf.flamegraph {
                let _ = writeln!(out, "Flamegraph: `{path}`");
                let _ = writeln!(out);
            }
            if !perf.note.is_empty() {
                let _ = writeln!(out, "{}", perf.note);
                let _ = writeln!(out);
            }
        }
    }

    for section in &report.extra {
        let _ = writeln!(out, "## {}", section.title);
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", section.body);
        let _ = writeln!(out);
    }

    if !report.recommendations.is_empty() {
        let _ = writeln!(out, "## Выводы и узкие места");
        let _ = writeln!(out);
        for item in &report.recommendations {
            let _ = writeln!(out, "- {item}");
        }
        let _ = writeln!(out);
    }

    if !report.commands.is_empty() {
        let _ = writeln!(out, "## Воспроизведение");
        let _ = writeln!(out);
        let _ = writeln!(out, "```bash");
        for command in &report.commands {
            let _ = writeln!(out, "{command}");
        }
        let _ = writeln!(out, "```");
    }
    out
}

fn ns_to_us(ns: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    {
        ns as f64 / 1000.0
    }
}

fn kib_to_mib(kib: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    {
        kib as f64 / 1024.0
    }
}

fn bytes_to_mib(bytes: u64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    {
        bytes as f64 / (1024.0 * 1024.0)
    }
}

/// Текущее unix-время.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn medians_are_stable() {
        assert_eq!(median_u64(&[3, 1, 2]), 2);
        assert!((median_f64(&[3.0, 1.0, 2.0]) - 2.0).abs() < f64::EPSILON);
        assert_eq!(median_u64(&[]), 0);
    }

    #[test]
    fn latency_scales() {
        let mut histogram = Histogram::<u64>::new_with_bounds(1, 1_000_000, 3).expect("histogram");
        for value in 1..=1000_u64 {
            histogram.record(value).expect("record");
        }
        let latency = latency_from_hist(&histogram, 1000.0);
        assert_eq!(latency.p50, 500_000);
        assert!(latency.max >= latency.p999);
        assert!(latency.min >= 1000);
    }
}
