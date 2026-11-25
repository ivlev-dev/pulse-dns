//! Huge pages для файловых отображений (`madvise(MADV_HUGEPAGE)`).
//!
//! [`HugePages`] — та же политика, что у `pulse-runtime`:
//!
//! * `auto` (по умолчанию) — best-effort подсказка ядру; ошибки не фатальны и
//!   не мешают открыть файл;
//! * `always` — подсказка обязательна: если THP глобально выключен
//!   (`.../transparent_hugepage/enabled = never`) или `madvise` вернул ошибку,
//!   открытие завершается [`ZoneFileError::MapAllocFailed`];
//! * `never` — регион явно помечается `MADV_NOHUGEPAGE`.
//!
//! # Ограничение ядра
//!
//! THP для **файловых** страниц (`MAP_SHARED`) поддерживается ядром только для
//! shmem/tmpfs. На ext4/xfs `madvise(MADV_HUGEPAGE)` принимается, но остаётся
//! no-op: страницы так и остаются 4 KiB. Поэтому дефолт — `auto`, а реальный
//! эффект проверяется по `RSS`/`AnonHugePages`/dTLB (см. `docs/ops/numa-affinity.md`).

#![allow(unsafe_code)]

use std::fmt;
use std::io;
use std::ptr::NonNull;
use std::str::FromStr;

use crate::errors::ZoneFileError;

/// Политика huge pages для отображений файла зон.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HugePages {
    /// Best-effort `madvise(MADV_HUGEPAGE)`; ошибки игнорируются.
    #[default]
    Auto,
    /// `madvise(MADV_HUGEPAGE)` обязателен; при неудаче — ошибка открытия.
    Always,
    /// THP для отображения выключен (`MADV_NOHUGEPAGE`).
    Never,
}

impl HugePages {
    /// Строковое представление для логов и конфигурации.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    const fn advice(self) -> libc::c_int {
        match self {
            Self::Auto | Self::Always => libc::MADV_HUGEPAGE,
            Self::Never => libc::MADV_NOHUGEPAGE,
        }
    }
}

impl fmt::Display for HugePages {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HugePages {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "always" | "on" | "yes" => Ok(Self::Always),
            "never" | "off" | "no" => Ok(Self::Never),
            other => Err(format!(
                "unknown huge_pages policy {other:?}; expected auto, always or never"
            )),
        }
    }
}

/// Глобальный режим THP (`/sys/kernel/mm/transparent_hugepage/enabled`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThpStatus {
    /// `[always]`.
    Always,
    /// `[madvise]`.
    Madvise,
    /// `[never]`.
    Never,
    /// sysfs недоступен (например, в контейнере без `/sys`).
    Unknown,
}

impl ThpStatus {
    /// Разрешены ли huge pages хотя бы по подсказке.
    #[must_use]
    pub const fn allows_madvise(self) -> bool {
        matches!(self, Self::Always | Self::Madvise | Self::Unknown)
    }
}

/// Прочитать глобальный режим THP.
#[must_use]
pub fn thp_status() -> ThpStatus {
    std::fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled").map_or(
        ThpStatus::Unknown,
        |text| {
            if text.contains("[always]") {
                ThpStatus::Always
            } else if text.contains("[madvise]") {
                ThpStatus::Madvise
            } else if text.contains("[never]") {
                ThpStatus::Never
            } else {
                ThpStatus::Unknown
            }
        },
    )
}

/// Выдать `madvise`-подсказку для живого отображения.
///
/// Диапазон выравнивается внутрь региона: `madvise` требует page-aligned
/// адрес (для `mmap` это выполнено, для тестовой арены — нет). Если целых
/// страниц не остаётся, подсказка не выдаётся.
///
/// # Errors
///
/// Только для [`HugePages::Always`]: `ENOTSUP` при выключенном THP, иначе
/// errno от `madvise`. Для `auto`/`never` подсказка best-effort.
pub(crate) fn advise(addr: NonNull<u8>, len: usize, policy: HugePages) -> io::Result<()> {
    advise_with(addr, len, policy, thp_status())
}

/// [`advise`] с явным статусом THP (детерминированные тесты без sysfs).
pub(crate) fn advise_with(
    addr: NonNull<u8>,
    len: usize,
    policy: HugePages,
    thp: ThpStatus,
) -> io::Result<()> {
    if policy == HugePages::Always && !thp.allows_madvise() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transparent huge pages are disabled globally",
        ));
    }
    let page = rustix::param::page_size();
    let start = addr.as_ptr() as usize;
    let aligned_start = (start + page - 1) & !(page - 1);
    let aligned_end = (start + len) & !(page - 1);
    if aligned_end <= aligned_start {
        return Ok(());
    }
    // SAFETY: `aligned_start..aligned_end` лежит внутри живого отображения и
    // выровнен на страницу; `madvise` не обращается к содержимому, только к
    // атрибутам отображённых страниц.
    let rc = unsafe {
        libc::madvise(
            aligned_start as *mut libc::c_void,
            aligned_end - aligned_start,
            policy.advice(),
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match policy {
        HugePages::Always => Err(error),
        HugePages::Auto | HugePages::Never => Ok(()),
    }
}

/// Преобразовать ошибку подсказки в ошибку открытия файла.
pub(crate) fn advise_error(size: u64, error: &io::Error) -> ZoneFileError {
    ZoneFileError::MapAllocFailed {
        size,
        errno: error.raw_os_error().unwrap_or(0),
        hint: "madvise(MADV_HUGEPAGE) failed with huge_pages = always; \
               set huge_pages = auto or enable THP",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policies() {
        assert_eq!("auto".parse::<HugePages>().unwrap(), HugePages::Auto);
        assert_eq!("Always".parse::<HugePages>().unwrap(), HugePages::Always);
        assert_eq!("off".parse::<HugePages>().unwrap(), HugePages::Never);
        assert!("maybe".parse::<HugePages>().is_err());
        assert_eq!(HugePages::default(), HugePages::Auto);
    }

    #[test]
    fn advises_mapping() {
        // Анонимный регион: те же syscall-семантики, что и у mmap-файла.
        let mut region = vec![0_u8; 2 * 1024 * 1024];
        let ptr = NonNull::new(region.as_mut_ptr()).unwrap();
        advise(ptr, region.len(), HugePages::Auto).unwrap();
        advise(ptr, region.len(), HugePages::Never).unwrap();
        let always = advise(ptr, region.len(), HugePages::Always);
        if thp_status() == ThpStatus::Never {
            assert!(always.is_err());
        } else {
            assert!(always.is_ok());
        }
    }

    #[test]
    fn disabled_thp_breaks_only_always() {
        let mut region = vec![0_u8; 2 * 1024 * 1024];
        let ptr = NonNull::new(region.as_mut_ptr()).unwrap();
        // `auto` и `never` на системе без THP не фатальны.
        advise_with(ptr, region.len(), HugePages::Auto, ThpStatus::Never).unwrap();
        advise_with(ptr, region.len(), HugePages::Never, ThpStatus::Never).unwrap();
        // `always` — требование, а не пожелание.
        let error = advise_with(ptr, region.len(), HugePages::Always, ThpStatus::Never)
            .expect_err("always must fail when THP is off");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        // Неизвестный статус (контейнер без /sys) считается «может быть».
        advise_with(ptr, region.len(), HugePages::Always, ThpStatus::Unknown).unwrap();
    }
}
