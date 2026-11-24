//! Явные лимиты ресурсов парсера (ADR 0004, SEC-DNS-001…003).

/// Лимиты разбора master-файла.
///
/// Значения по умолчанию рассчитаны на зону до нескольких миллионов записей
/// и не позволяют одному файлу исчерпать память процесса.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Максимальный размер одного текстового источника (в байтах).
    pub max_file_bytes: usize,
    /// Максимальное число записей во всей зоне (с учётом `$INCLUDE`).
    pub max_records: usize,
    /// Максимальная глубина вложенности `$INCLUDE`.
    pub max_include_depth: usize,
    /// Максимальное число загруженных `$INCLUDE`-файлов за один разбор.
    pub max_include_files: usize,
    /// Максимальное число токенов в одной логической строке.
    pub max_line_tokens: usize,
}

impl Limits {
    /// 32 MiB на источник, 1M записей, глубина 8, 64 include-файла,
    /// 65536 токенов в строке.
    pub const DEFAULT: Self = Self {
        max_file_bytes: 32 * 1024 * 1024,
        max_records: 1_000_000,
        max_include_depth: 8,
        max_include_files: 64,
        max_line_tokens: 65_536,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
