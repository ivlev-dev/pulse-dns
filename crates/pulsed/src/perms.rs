//! Проверка прав на файлы с секретами.
//!
//! Приватные ключи (TLS, DNSCrypt) не должны быть доступны группе или
//! остальным пользователям. На не-Unix платформах проверка ничего не делает.

use std::path::Path;

/// Проверяет, что файл не доступен группе и остальным (нет битов `0o077`).
///
/// # Errors
///
/// Строка с описанием проблемы: ошибка метаданных или слишком широкие права.
pub(crate) fn ensure_private(path: &Path, label: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = std::fs::metadata(path)
            .map_err(|error| format!("cannot stat {label} {}: {error}", path.display()))?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{label} {} has insecure permissions {mode:03o}; expected 0600 or stricter",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, label);
    }
    Ok(())
}

/// Выставляет права `mode` на файл (Unix) или ничего не делает.
///
/// # Errors
///
/// Ошибка `set_permissions`.
pub(crate) fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}
