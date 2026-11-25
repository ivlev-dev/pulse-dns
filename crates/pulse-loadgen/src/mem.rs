//! Динамика памяти сервера: `/proc/<pid>/status`, `smaps_rollup`, `smaps`
//! (вклад mmap-файла зон), fd и CPU.
//!
//! Сэмплер работает в отдельном потоке и не мешает нагрузке; интервал по
//! умолчанию 250 мс. `RssAnon`/`RssFile` показывают, растёт ли heap или
//! page cache mmap; `mmap_rss` — сколько страниц файла зон реально в памяти.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Один снимок памяти.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MemorySample {
    /// Время от старта сэмплера, мс.
    pub t_ms: u64,
    /// `VmRSS`, КиБ.
    pub vm_rss_kb: u64,
    /// `RssAnon`, КиБ.
    pub rss_anon_kb: u64,
    /// `RssFile`, КиБ.
    pub rss_file_kb: u64,
    /// `RssShmem`, КиБ.
    pub rss_shmem_kb: u64,
    /// `VmSize`, КиБ.
    pub vm_size_kb: u64,
    /// `VmData`, КиБ.
    pub vm_data_kb: u64,
    /// `VmSwap`, КиБ.
    pub vm_swap_kb: u64,
    /// Потоков.
    pub threads: u64,
    /// `Rss` из `smaps_rollup`, КиБ.
    pub smaps_rss_kb: u64,
    /// `Pss` из `smaps_rollup`, КиБ.
    pub smaps_pss_kb: u64,
    /// `Shared_Clean` из `smaps_rollup`, КиБ.
    pub shared_clean_kb: u64,
    /// `Shared_Dirty` из `smaps_rollup`, КиБ.
    pub shared_dirty_kb: u64,
    /// `Private_Clean` из `smaps_rollup`, КиБ.
    pub private_clean_kb: u64,
    /// `Private_Dirty` из `smaps_rollup`, КиБ.
    pub private_dirty_kb: u64,
    /// `Rss` mmap-файла зон, КиБ.
    pub mmap_rss_kb: u64,
    /// `Pss` mmap-файла зон, КиБ.
    pub mmap_pss_kb: u64,
    /// Страницы файла зон в page cache, байт (`fincore`).
    pub page_cache_bytes: u64,
    /// Размер файла зон (logical), байт.
    pub file_bytes: u64,
    /// Занято на диске (sparse учитывается), байт.
    pub disk_bytes: u64,
    /// Открытых fd.
    pub fds: u64,
    /// CPU-тики (`utime+stime`).
    pub cpu_ticks: u64,
}

/// Сводка по серии снимков.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MemorySummary {
    /// Число снимков.
    pub samples: usize,
    /// Длительность серии, мс.
    pub duration_ms: u64,
    /// Первый `VmRSS`, КиБ.
    pub rss_first_kb: u64,
    /// Последний `VmRSS`, КиБ.
    pub rss_last_kb: u64,
    /// Минимум `VmRSS`, КиБ.
    pub rss_min_kb: u64,
    /// Максимум `VmRSS`, КиБ.
    pub rss_max_kb: u64,
    /// Рост `VmRSS` от первого к последнему, КиБ.
    pub rss_growth_kb: i64,
    /// Рост `VmRSS`, %.
    pub rss_growth_pct: f64,
    /// Наклон `VmRSS` (КиБ/мин), линейная регрессия по всем снимкам.
    pub rss_slope_kib_per_min: f64,
    /// Первый/последний `RssAnon`.
    pub anon_first_kb: u64,
    /// Последний `RssAnon`.
    pub anon_last_kb: u64,
    /// Первый/последний `RssFile`.
    pub file_first_kb: u64,
    /// Последний `RssFile`.
    pub file_last_kb: u64,
    /// `mmap_rss` первого снимка, КиБ.
    pub mmap_first_kb: u64,
    /// `mmap_rss` последнего снимка, КиБ.
    pub mmap_last_kb: u64,
    /// Page cache файла зон в первом снимке, байт.
    pub page_cache_first_bytes: u64,
    /// Page cache файла зон в последнем снимке, байт.
    pub page_cache_last_bytes: u64,
    /// Размер файла зон (logical), байт.
    pub file_bytes: u64,
    /// Занято на диске, байт.
    pub disk_bytes: u64,
    /// CPU сервера, % (100 = одно ядро).
    pub cpu_pct: f64,
    /// Утечка по критерию (рост > 5% и положительный наклон).
    pub leak_suspected: bool,
}

/// Отчёт сэмплера.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MemoryReport {
    /// PID сервера.
    pub pid: u32,
    /// Путь к zonefile.
    pub data: String,
    /// Зон в файле (передаётся вызывающим).
    pub zones: u32,
    /// RRset в файле (передаётся вызывающим).
    pub rrsets: u64,
    /// Серия снимков.
    pub samples: Vec<MemorySample>,
    /// Сводка.
    pub summary: MemorySummary,
}

/// Запущенный сэмплер.
pub struct Sampler {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<Vec<MemorySample>>>,
    started: Instant,
}

impl Sampler {
    /// Запускает фоновый сэмплер.
    #[must_use]
    pub fn start(pid: u32, data: PathBuf, interval: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let started = Instant::now();
        let join = std::thread::spawn(move || {
            let mut samples = Vec::new();
            while !thread_stop.load(Ordering::Acquire) {
                samples.push(sample(pid, &data, started.elapsed()));
                std::thread::sleep(interval);
            }
            samples
        });
        Self {
            stop,
            join: Some(join),
            started,
        }
    }

    /// Останавливает сэмплер и строит отчёт.
    #[must_use]
    pub fn finish(mut self, zones: u32, rrsets: u64) -> MemoryReport {
        self.stop.store(true, Ordering::Release);
        let samples = self
            .join
            .take()
            .and_then(|join| join.join().ok())
            .unwrap_or_default();
        let summary = summarize(&samples, self.started.elapsed());
        MemoryReport {
            pid: 0,
            data: String::new(),
            zones,
            rrsets,
            samples,
            summary,
        }
    }
}

/// Один снимок.
#[must_use]
pub fn sample(pid: u32, data: &Path, elapsed: Duration) -> MemorySample {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let status = parse_key_kib(&status);
    let rollup = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).unwrap_or_default();
    let rollup = parse_key_kib(&rollup);
    let (mapped_rss, mapped_pss_total) = std::fs::read_to_string(format!("/proc/{pid}/smaps"))
        .map_or((0, 0), |text| sum_mapping(&text, data));
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd")).map_or(0, |entries| {
        u64::try_from(entries.flatten().count()).unwrap_or(u64::MAX)
    });
    let page_cache_bytes = page_cache_bytes(data);
    let (file_bytes, disk_bytes) = std::fs::metadata(data).map_or((0, 0), |meta| {
        #[cfg(unix)]
        let disk = {
            use std::os::unix::fs::MetadataExt;
            meta.blocks().saturating_mul(512)
        };
        #[cfg(not(unix))]
        let disk = meta.len();
        (meta.len(), disk)
    });
    MemorySample {
        t_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        vm_rss_kb: get(&status, "VmRSS"),
        rss_anon_kb: get(&status, "RssAnon"),
        rss_file_kb: get(&status, "RssFile"),
        rss_shmem_kb: get(&status, "RssShmem"),
        vm_size_kb: get(&status, "VmSize"),
        vm_data_kb: get(&status, "VmData"),
        vm_swap_kb: get(&status, "VmSwap"),
        threads: get(&status, "Threads"),
        smaps_rss_kb: get(&rollup, "Rss"),
        smaps_pss_kb: get(&rollup, "Pss"),
        shared_clean_kb: get(&rollup, "Shared_Clean"),
        shared_dirty_kb: get(&rollup, "Shared_Dirty"),
        private_clean_kb: get(&rollup, "Private_Clean"),
        private_dirty_kb: get(&rollup, "Private_Dirty"),
        mmap_rss_kb: mapped_rss,
        mmap_pss_kb: mapped_pss_total,
        page_cache_bytes,
        file_bytes,
        disk_bytes,
        fds,
        cpu_ticks: crate::sysinfo::process_cpu_ticks(pid).unwrap_or(0),
    }
}

fn get(map: &BTreeMap<String, u64>, key: &str) -> u64 {
    map.get(key).copied().unwrap_or(0)
}

/// Парсит строки `Key: 1234 kB`.
#[must_use]
pub fn parse_key_kib(text: &str) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        let number = value.split_whitespace().next().unwrap_or_default();
        if let Ok(number) = number.parse::<u64>() {
            map.insert(key.trim().to_owned(), number);
        }
    }
    map
}

/// Суммирует `Rss`/`Pss` VMA, в пути которых есть имя `data`.
#[must_use]
pub fn sum_mapping(text: &str, data: &Path) -> (u64, u64) {
    let needle = data
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let mut in_mapping = false;
    let mut rss = 0_u64;
    let mut pss = 0_u64;
    for line in text.lines() {
        let is_header = !line.starts_with(' ');
        if is_header {
            in_mapping = !needle.is_empty() && line.contains(needle);
            continue;
        }
        if !in_mapping {
            continue;
        }
        let Some((key, value)) = line.trim_start().split_once(':') else {
            continue;
        };
        let value = value.split_whitespace().next().unwrap_or_default();
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        match key {
            "Rss" => rss = rss.saturating_add(value),
            "Pss" => pss = pss.saturating_add(value),
            _ => {}
        }
    }
    (rss, pss)
}

/// Страницы файла в page cache через `fincore` (util-linux).
fn page_cache_bytes(data: &Path) -> u64 {
    if data.as_os_str().is_empty() {
        return 0;
    }
    let output = match std::process::Command::new("fincore")
        .args(["-b", "-n", "-o", "RES", "--"])
        .arg(data)
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return 0,
    };
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

/// Строит сводку по снимкам.
#[must_use]
pub fn summarize(samples: &[MemorySample], elapsed: Duration) -> MemorySummary {
    let Some(all_first) = samples.first() else {
        return MemorySummary::default();
    };
    // Для длинных серий отбрасываем первые 30 с: allocator/page cache ещё
    // прогреваются, и «рост» на этом отрезке — не утечка.
    let analysis = if elapsed.as_secs() >= 120 {
        let skip = samples
            .iter()
            .position(|sample| sample.t_ms >= 30_000)
            .unwrap_or(0);
        &samples[skip..]
    } else {
        samples
    };
    let Some(first) = analysis.first().or(Some(all_first)) else {
        return MemorySummary::default();
    };
    let last = analysis.last().unwrap_or(first);
    let min = analysis
        .iter()
        .map(|sample| sample.vm_rss_kb)
        .min()
        .unwrap_or(0);
    let max = analysis
        .iter()
        .map(|sample| sample.vm_rss_kb)
        .max()
        .unwrap_or(0);
    let growth = i64::try_from(last.vm_rss_kb).unwrap_or(i64::MAX)
        - i64::try_from(first.vm_rss_kb).unwrap_or(0);
    let pct = if first.vm_rss_kb == 0 {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            growth as f64 * 100.0 / first.vm_rss_kb as f64
        }
    };
    let slope = slope_per_min(analysis);
    let ticks_per_sec = crate::sysinfo::clock_ticks_per_sec().max(1);
    let cpu_pct = if elapsed.is_zero() || last.cpu_ticks <= first.cpu_ticks {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            (last.cpu_ticks - first.cpu_ticks) as f64 / ticks_per_sec as f64 / elapsed.as_secs_f64()
                * 100.0
        }
    };
    MemorySummary {
        samples: samples.len(),
        duration_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        rss_first_kb: first.vm_rss_kb,
        rss_last_kb: last.vm_rss_kb,
        rss_min_kb: min,
        rss_max_kb: max,
        rss_growth_kb: growth,
        rss_growth_pct: pct,
        rss_slope_kib_per_min: slope,
        anon_first_kb: first.rss_anon_kb,
        anon_last_kb: last.rss_anon_kb,
        file_first_kb: first.rss_file_kb,
        file_last_kb: last.rss_file_kb,
        mmap_first_kb: first.mmap_rss_kb,
        mmap_last_kb: last.mmap_rss_kb,
        page_cache_first_bytes: first.page_cache_bytes,
        page_cache_last_bytes: last.page_cache_bytes,
        file_bytes: last.file_bytes,
        disk_bytes: last.disk_bytes,
        cpu_pct,
        leak_suspected: pct > 5.0 && slope > 0.0 && elapsed.as_secs() >= 60,
    }
}

fn slope_per_min(samples: &[MemorySample]) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let n = samples.len() as f64;
    #[allow(clippy::cast_precision_loss)]
    let mean_x = samples.iter().map(|sample| sample.t_ms as f64).sum::<f64>() / n;
    #[allow(clippy::cast_precision_loss)]
    let mean_y = samples
        .iter()
        .map(|sample| sample.vm_rss_kb as f64)
        .sum::<f64>()
        / n;
    let mut covariance = 0.0;
    let mut variance = 0.0;
    for sample in samples {
        #[allow(clippy::cast_precision_loss)]
        let x = sample.t_ms as f64 - mean_x;
        #[allow(clippy::cast_precision_loss)]
        let y = sample.vm_rss_kb as f64 - mean_y;
        covariance += x * y;
        variance += x * x;
    }
    if variance == 0.0 {
        0.0
    } else {
        covariance / variance * 60_000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status() {
        let text = "Name:\tpulsed\nVmRSS:\t  1234 kB\nRssAnon:\t  1000 kB\nRssFile:\t   234 kB\nThreads:\t8\n";
        let map = parse_key_kib(text);
        assert_eq!(get(&map, "VmRSS"), 1234);
        assert_eq!(get(&map, "RssAnon"), 1000);
        assert_eq!(get(&map, "RssFile"), 234);
        assert_eq!(get(&map, "Threads"), 8);
    }

    #[test]
    fn sums_matching_mapping_only() {
        let text = "\
7f00-7f01 rw-s 00000000 00:01 1 /tmp/bench/zones.v2
 Rss:                 100 kB
 Pss:                  80 kB
 Private_Dirty:        20 kB
7f01-7f02 rw-p 00000000 00:00 0 [heap]
 Rss:                 500 kB
 Pss:                 500 kB
";
        let (rss, pss) = sum_mapping(text, Path::new("/tmp/bench/zones.v2"));
        assert_eq!((rss, pss), (100, 80));
    }

    #[test]
    fn summary_detects_growth() {
        let samples = vec![
            MemorySample {
                t_ms: 0,
                vm_rss_kb: 1000,
                ..MemorySample::default()
            },
            MemorySample {
                t_ms: 60_000,
                vm_rss_kb: 2000,
                ..MemorySample::default()
            },
        ];
        let summary = summarize(&samples, Duration::from_secs(60));
        assert_eq!(summary.rss_growth_kb, 1000);
        assert!((summary.rss_growth_pct - 100.0).abs() < 0.01);
        assert!((summary.rss_slope_kib_per_min - 1000.0).abs() < 0.01);
        assert!(summary.leak_suspected);
    }
}
