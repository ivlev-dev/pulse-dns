//! Huge pages (THP) для анонимных арен и `madvise`-подсказок.
//!
//! [`HugePages`] — пользовательская политика, общая для рантайма и файла зон:
//!
//! * `auto` (по умолчанию) — best-effort `madvise(MADV_HUGEPAGE)`; любые
//!   ошибки (старое ядро, `EINVAL`, THP выключен) не фатальны;
//! * `always` — подсказка обязательна: при выключенном THP или ошибке
//!   `madvise` возвращается ошибка старта;
//! * `never` — регион помечается `MADV_NOHUGEPAGE` (арены) или подсказка не
//!   выдаётся (файловые отображения).
//!
//! THP для **файловых** страниц (`MAP_SHARED`) ядро поддерживает только для
//! shmem/tmpfs; на ext4/xfs `madvise(MADV_HUGEPAGE)` принимается, но остаётся
//! no-op. Поэтому `auto` — единственный безопасный дефолт, а `always` имеет
//! смысл лишь после проверки `thp_status()`.

use std::fmt;
use std::io;
use std::ptr::NonNull;
use std::str::FromStr;
use std::sync::OnceLock;

/// Политика huge pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HugePages {
    /// Best-effort `madvise(MADV_HUGEPAGE)`; ошибки игнорируются.
    #[default]
    Auto,
    /// `madvise(MADV_HUGEPAGE)` обязателен; при неудаче — ошибка старта.
    Always,
    /// Не использовать THP (`MADV_NOHUGEPAGE` для арен, без подсказки для mmap).
    Never,
}

impl HugePages {
    /// Строковое представление для логов.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Always => "always",
            Self::Never => "never",
        }
    }

    /// `madvise`-подсказка для региона.
    #[must_use]
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
    /// `[always]`: THP выдаётся без подсказки.
    Always,
    /// `[madvise]`: THP только по `MADV_HUGEPAGE`.
    Madvise,
    /// `[never]`: THP выключен.
    Never,
    /// sysfs недоступен (контейнер без `/sys`) или файл не распознан.
    Unknown,
}

impl ThpStatus {
    /// Разрешены ли huge pages хотя бы по подсказке.
    #[must_use]
    pub const fn allows_madvise(self) -> bool {
        matches!(self, Self::Always | Self::Madvise | Self::Unknown)
    }
}

/// Прочитать глобальный режим THP (кэшируется на процесс).
#[must_use]
pub fn thp_status() -> ThpStatus {
    static STATUS: OnceLock<ThpStatus> = OnceLock::new();
    *STATUS.get_or_init(|| {
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
    })
}

/// Размер страницы (базовый, не huge).
#[must_use]
pub fn page_size() -> usize {
    rustix::param::page_size()
}

/// Выдать `madvise`-подсказку для диапазона `[addr, addr + len)`.
///
/// Диапазон выравнивается внутрь региона: `madvise` требует page-aligned
/// адрес, а арена, полученная из `Vec`, может начинаться с середины страницы.
/// Если после выравнивания не остаётся ни одной полной страницы, возвращается
/// `Ok(false)` — подсказывать нечего.
///
/// Возвращает `true`, если `madvise` реально применён.
///
/// # Errors
///
/// Для [`HugePages::Always`]: `ENOTSUP`, если THP глобально выключен;
/// иначе ошибка `madvise`. Для `auto`/`never` ошибки поглощаются (`Ok(false)`).
pub fn advise(addr: NonNull<u8>, len: usize, policy: HugePages) -> io::Result<bool> {
    advise_with(addr, len, policy, thp_status())
}

/// [`advise`] с явным статусом THP (детерминированные тесты без sysfs).
pub(crate) fn advise_with(
    addr: NonNull<u8>,
    len: usize,
    policy: HugePages,
    thp: ThpStatus,
) -> io::Result<bool> {
    let advice = policy.advice();
    if policy == HugePages::Always && !thp.allows_madvise() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "transparent huge pages are disabled globally \
             (/sys/kernel/mm/transparent_hugepage/enabled = never)",
        ));
    }
    let page = page_size();
    if page == 0 {
        return Err(io::Error::other("page size is zero"));
    }
    let start = addr.as_ptr() as usize;
    let aligned_start = start.checked_add(page - 1).map(|value| value & !(page - 1));
    let aligned_end = (start + len) & !(page - 1);
    let Some(aligned_start) = aligned_start else {
        return Ok(false);
    };
    if aligned_end <= aligned_start {
        // Регион меньше страницы или не содержит ни одной полной страницы.
        return Ok(false);
    }
    let bytes = aligned_end - aligned_start;
    // SAFETY: `aligned_start` лежит внутри `[addr, addr + len)` и выровнен на
    // page size; `aligned_end` — его верхняя граница внутри того же региона.
    // `madvise` не читает и не пишет память — он меняет только атрибуты
    // отображённых страниц, поэтому регион обязан быть валидным mmap/heap.
    let rc = unsafe { libc::madvise(aligned_start as *mut libc::c_void, bytes, advice) };
    if rc == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match policy {
        HugePages::Always => Err(error),
        HugePages::Auto | HugePages::Never => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policies() {
        assert_eq!("auto".parse::<HugePages>().unwrap(), HugePages::Auto);
        assert_eq!(" ALWAYS ".parse::<HugePages>().unwrap(), HugePages::Always);
        assert_eq!("never".parse::<HugePages>().unwrap(), HugePages::Never);
        assert!("sometimes".parse::<HugePages>().is_err());
        assert_eq!(HugePages::default(), HugePages::Auto);
    }

    #[test]
    fn thp_status_is_detected_or_unknown() {
        // На системах без /sys статус = Unknown; любое значение допустимо,
        // важен лишь инвариант «never запрещает always».
        let status = thp_status();
        if status == ThpStatus::Never {
            assert!(!status.allows_madvise());
        } else {
            assert!(status.allows_madvise());
        }
    }

    #[test]
    fn advises_anonymous_arena() {
        let mut arena = vec![0_u8; 4 * 1024 * 1024];
        let ptr = NonNull::new(arena.as_mut_ptr()).unwrap();
        // `never` — всегда успешно (MADV_NOHUGEPAGE есть везде).
        assert!(advise(ptr, arena.len(), HugePages::Never).is_ok());
        // `auto` не фатален даже без THP.
        assert!(advise(ptr, arena.len(), HugePages::Auto).is_ok());
    }

    #[test]
    fn tiny_region_has_nothing_to_advise() {
        let mut byte = [0_u8; 1];
        let ptr = NonNull::new(byte.as_mut_ptr()).unwrap();
        assert!(!advise(ptr, byte.len(), HugePages::Auto).unwrap());
    }

    #[test]
    fn disabled_thp_breaks_only_always() {
        let mut arena = vec![0_u8; 2 * 1024 * 1024];
        let ptr = NonNull::new(arena.as_mut_ptr()).unwrap();
        advise_with(ptr, arena.len(), HugePages::Auto, ThpStatus::Never).unwrap();
        advise_with(ptr, arena.len(), HugePages::Never, ThpStatus::Never).unwrap();
        let error = advise_with(ptr, arena.len(), HugePages::Always, ThpStatus::Never)
            .expect_err("always must fail when THP is off");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        advise_with(ptr, arena.len(), HugePages::Always, ThpStatus::Unknown).unwrap();
    }

    #[test]
    fn always_requires_enabled_thp() {
        let mut arena = vec![0_u8; 2 * 1024 * 1024];
        let ptr = NonNull::new(arena.as_mut_ptr()).unwrap();
        let result = advise(ptr, arena.len(), HugePages::Always);
        if thp_status() == ThpStatus::Never {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok());
        }
    }
}
