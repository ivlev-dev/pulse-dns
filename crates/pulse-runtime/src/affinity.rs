//! CPU-affinity: разбор списков CPU, пересечение с `sched_getaffinity`/cpuset,
//! пиннинг потоков.
//!
//! Правила (единые для всех ролей `pulse-dns`):
//!
//! * пустой список — «все CPU, разрешённые процессу» (cgroup cpuset и
//!   `sched_getaffinity` уже учтены ядром);
//! * явный список **всегда** пересекается с разрешёнными CPU: пинить поток на
//!   чужое ядро нельзя (ядро вернуло бы `EINVAL`, а после `sched_setaffinity`
//!   поток мог бы остаться на неожиданном CPU);
//! * пустое пересечение — ошибка старта, а не тихая деградация.
//!
//! Список в конфиге/CLI задаётся строкой `"0,2,4-7"` или массивом чисел
//! (TOML/JSON). [`parse_list`] понимает оба синтаксиса диапазонов.

use std::io;

use rustix::thread::{CpuSet, sched_getaffinity, sched_setaffinity};

/// Максимальный номер CPU, который помещается в [`CpuSet`] (`CPU_SETSIZE`).
pub const MAX_CPU: usize = CpuSet::MAX_CPU;

/// CPU, разрешённые текущему потоку (`sched_getaffinity(2)`).
///
/// Учитывает cgroup cpuset: ядро уже сузило маску до CPU, на которых процесс
/// вправе исполняться.
#[must_use]
pub fn current_cpus() -> Vec<usize> {
    sched_getaffinity(None).map_or_else(
        |_| Vec::new(),
        |set| (0..MAX_CPU).filter(|&cpu| set.is_set(cpu)).collect(),
    )
}

/// Разрешить запрошенный список CPU с учётом маски процесса.
///
/// * `requested` пуст → все разрешённые CPU;
/// * иначе — отсортированное пересечение `requested` с разрешёнными CPU.
///
/// # Errors
///
/// [`io::ErrorKind::InvalidInput`], если явный список не пересекается с
/// разрешёнными CPU (в том числе когда `sched_getaffinity` недоступен).
pub fn resolve(requested: &[usize]) -> io::Result<Vec<usize>> {
    let allowed = current_cpus();
    if requested.is_empty() {
        return Ok(allowed);
    }
    if allowed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sched_getaffinity returned an empty CPU mask",
        ));
    }
    let selected = intersection(&allowed, requested);
    if selected.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "requested CPUs {requested:?} do not intersect the allowed mask {allowed:?} \
                 (check cgroup cpuset / taskset)"
            ),
        ));
    }
    Ok(selected)
}

/// Отсортированное пересечение двух списков CPU без дубликатов.
#[must_use]
pub fn intersection(left: &[usize], right: &[usize]) -> Vec<usize> {
    let mut out: Vec<usize> = left
        .iter()
        .copied()
        .filter(|cpu| right.contains(cpu))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Прибить текущий поток к одному CPU.
///
/// # Errors
///
/// `EINVAL` для CPU вне [`MAX_CPU`], ошибка `sched_setaffinity` (например,
/// `EPERM` в ограниченном cgroup) — иначе.
pub fn pin_current(cpu: usize) -> io::Result<()> {
    pin_current_set(&[cpu])
}

/// Прибить текущий поток к набору CPU (маска `sched_setaffinity`).
///
/// Пустой набор — ошибка: пустая маска не «снимает» ограничение, а запрещает
/// потоку исполняться.
///
/// # Errors
///
/// `EINVAL`, если набор пуст или содержит CPU вне [`MAX_CPU`]; иначе ошибка
/// `sched_setaffinity`.
pub fn pin_current_set(cpus: &[usize]) -> io::Result<()> {
    if cpus.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CPU affinity set must not be empty",
        ));
    }
    let mut set = CpuSet::new();
    for &cpu in cpus {
        if cpu >= MAX_CPU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("CPU {cpu} is outside 0..{MAX_CPU}"),
            ));
        }
        set.set(cpu);
    }
    sched_setaffinity(None, &set)
        .map_err(|errno| io::Error::from_raw_os_error(errno.raw_os_error()))
}

/// Разобрать список CPU: `"0,2,4-7"` (пробелы игнорируются).
///
/// Пустая строка — пустой список. Дубликаты удаляются с сохранением порядка.
///
/// # Errors
///
/// Строка с нечисловым элементом, обратным диапазоном (`5-2`) или CPU за
/// пределом [`MAX_CPU`].
pub fn parse_list(spec: &str) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Ok(out);
    }
    for part in trimmed.split(',') {
        let item = part.trim();
        if item.is_empty() {
            return Err(format!("empty element in CPU list {spec:?}"));
        }
        let (start, end) = if let Some((start, end)) = item.split_once('-') {
            (parse_cpu(start, spec)?, parse_cpu(end, spec)?)
        } else {
            let cpu = parse_cpu(item, spec)?;
            (cpu, cpu)
        };
        if start > end {
            return Err(format!("descending CPU range {item:?} in {spec:?}"));
        }
        for cpu in start..=end {
            if !out.contains(&cpu) {
                out.push(cpu);
            }
        }
    }
    Ok(out)
}

fn parse_cpu(text: &str, spec: &str) -> Result<usize, String> {
    let cpu: usize = text
        .trim()
        .parse()
        .map_err(|_| format!("invalid CPU {text:?} in {spec:?}"))?;
    if cpu >= MAX_CPU {
        return Err(format!("CPU {cpu} is outside 0..{MAX_CPU} in {spec:?}"));
    }
    Ok(cpu)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lists_and_ranges() {
        assert_eq!(parse_list("").unwrap(), Vec::<usize>::new());
        assert_eq!(parse_list(" 3 ").unwrap(), vec![3]);
        assert_eq!(parse_list("0,2,4-7").unwrap(), vec![0, 2, 4, 5, 6, 7]);
        assert_eq!(parse_list("1-3,2,1").unwrap(), vec![1, 2, 3]);
        assert_eq!(parse_list("4-4").unwrap(), vec![4]);
    }

    #[test]
    fn rejects_bad_lists() {
        for spec in ["a", "1,,2", "5-2", "-1", "1-", "1024", "1--2"] {
            assert!(parse_list(spec).is_err(), "{spec:?} must be rejected");
        }
    }

    #[test]
    fn intersection_is_sorted_and_deduplicated() {
        assert_eq!(intersection(&[3, 1, 2], &[2, 3, 9]), vec![2, 3]);
        assert_eq!(intersection(&[0, 1], &[2, 3]), Vec::<usize>::new());
    }

    #[test]
    fn resolve_narrows_to_allowed_mask() {
        let allowed = current_cpus();
        assert!(!allowed.is_empty(), "process must have at least one CPU");
        // Пустой запрос = вся разрешённая маска.
        assert_eq!(resolve(&[]).unwrap(), allowed);
        // Чужой CPU не пинится: пересечение пустое → ошибка.
        let foreign = (0..MAX_CPU)
            .find(|cpu| !allowed.contains(cpu))
            .expect("test process cannot own every CPU");
        let error = resolve(&[foreign]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        // Разрешённый CPU остаётся в результате.
        assert_eq!(resolve(&[allowed[0]]).unwrap(), vec![allowed[0]]);
    }

    #[test]
    fn pinning_changes_the_actual_thread_mask() {
        let allowed = current_cpus();
        let target = allowed[0];
        std::thread::spawn(move || {
            pin_current(target).expect("pin to an allowed CPU");
            assert_eq!(current_cpus(), vec![target]);
        })
        .join()
        .expect("thread must not panic");
    }

    #[test]
    fn empty_set_and_foreign_cpu_are_rejected() {
        assert!(pin_current_set(&[]).is_err());
        assert!(pin_current(MAX_CPU).is_err());
    }
}
