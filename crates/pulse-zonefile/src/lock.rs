//! Эксклюзивная блокировка writer'а через отдельный lock-файл (SEC-ZF-009).

use std::ffi::OsString;
use std::fs::File;
use std::path::Path;

use rustix::fs::{FileType, Mode, OFlags, fchmod, flock, fstat, open};
use rustix::io::Errno;

use crate::consts::LOCK_FILE_SUFFIX;
use crate::errors::ZoneFileError;

/// Держатель эксклюзивной блокировки writer'а.
///
/// Блокировка снимается при `Drop` или смертью процесса.
#[derive(Debug)]
pub(crate) struct WriterLock {
    // Держит дескриптор открытым: блокировка снимается только при `Drop`.
    #[allow(dead_code)]
    file: File,
}

impl WriterLock {
    /// Путь lock-файла для файла зон `path`.
    pub(crate) fn path_for(path: &Path) -> OsString {
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(LOCK_FILE_SUFFIX);
        lock_path
    }

    /// Понижает удерживаемый `LOCK_EX` до `LOCK_SH`.
    ///
    /// Нужно `create` в межпроцессном режиме: создание сериализовано
    /// эксклюзивно, а дальнейшая жизнь файла допускает N `LOCK_SH`.
    pub(crate) fn downgrade_to_shared(&self) -> Result<(), ZoneFileError> {
        flock_retry(&self.file, rustix::fs::FlockOperation::LockShared)
            .map_err(|error| ZoneFileError::Io(std::io::Error::from(error)))
    }

    /// Пытается взять `LOCK_SH | LOCK_NB` (межпроцессные писатели/читатели).
    ///
    /// `Ok(None)` — файл занят эксклюзивным (single-process) writer'ом.
    pub(crate) fn acquire_shared(path: &Path) -> Result<Option<Self>, ZoneFileError> {
        let lock_path = Self::path_for(path);
        let fd = match open(
            lock_path.as_os_str(),
            OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => fd,
            Err(error) if error == Errno::LOOP || error == Errno::ISDIR => {
                return Err(ZoneFileError::NotRegularFile);
            }
            Err(error) => return Err(ZoneFileError::Io(std::io::Error::from(error))),
        };
        let file = File::from(fd);
        let stat = fstat(&file).map_err(std::io::Error::from)?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            return Err(ZoneFileError::NotRegularFile);
        }
        fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(std::io::Error::from)?;
        match flock_retry(&file, rustix::fs::FlockOperation::NonBlockingLockShared) {
            Ok(()) => Ok(Some(Self { file })),
            Err(Errno::WOULDBLOCK) => Ok(None),
            Err(error) => Err(ZoneFileError::Io(std::io::Error::from(error))),
        }
    }

    /// Пытается взять `LOCK_EX | LOCK_NB`.
    ///
    /// Возвращает `Ok(None)`, если блокировка занята другим writer'ом.
    ///
    /// # Errors
    ///
    /// `NotRegularFile` — lock-файл не является regular-файлом (FIFO, device,
    /// каталог или symlink после `O_NOFOLLOW`); `Io` — не удалось открыть
    /// lock-файл или выполнить `flock`.
    pub(crate) fn acquire(path: &Path) -> Result<Option<Self>, ZoneFileError> {
        let lock_path = Self::path_for(path);
        let fd = match open(
            lock_path.as_os_str(),
            OFlags::CREATE | OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => fd,
            // `O_NOFOLLOW` на symlink даёт ELOOP, `O_RDWR` на каталоге — EISDIR.
            Err(error) if error == Errno::LOOP || error == Errno::ISDIR => {
                return Err(ZoneFileError::NotRegularFile);
            }
            Err(error) => return Err(ZoneFileError::Io(std::io::Error::from(error))),
        };
        let file = File::from(fd);
        let stat = fstat(&file).map_err(std::io::Error::from)?;
        if !FileType::from_raw_mode(stat.st_mode).is_file() {
            return Err(ZoneFileError::NotRegularFile);
        }
        fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(std::io::Error::from)?;
        match flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Some(Self { file })),
            Err(Errno::WOULDBLOCK) => Ok(None),
            Err(error) => Err(ZoneFileError::Io(std::io::Error::from(error))),
        }
    }
}

/// `flock` с повтором на `EINTR`.
///
/// Под нагрузкой (много дочерних процессов) `SIGCHLD` может прервать
/// non-blocking `flock`; без повтора это выглядело бы как ложный `Busy`.
fn flock_retry(file: &File, operation: rustix::fs::FlockOperation) -> Result<(), Errno> {
    loop {
        match flock(file, operation) {
            Err(Errno::INTR) => {}
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn acquires_regular_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zones.zonefile");
        let lock = WriterLock::acquire(&path).unwrap();
        assert!(lock.is_some());
        assert!(Path::new(&WriterLock::path_for(&path)).exists());
    }

    #[test]
    fn rejects_directory_as_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zones.zonefile");
        let lock_path = PathBuf::from(WriterLock::path_for(&path));
        std::fs::create_dir(&lock_path).unwrap();
        assert!(matches!(
            WriterLock::acquire(&path),
            Err(ZoneFileError::NotRegularFile)
        ));
    }

    #[test]
    fn rejects_symlink_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zones.zonefile");
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        let lock_path = PathBuf::from(WriterLock::path_for(&path));
        std::os::unix::fs::symlink(&target, &lock_path).unwrap();
        assert!(matches!(
            WriterLock::acquire(&path),
            Err(ZoneFileError::NotRegularFile)
        ));
    }

    #[test]
    fn rejects_fifo_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zones.zonefile");
        let lock_path = PathBuf::from(WriterLock::path_for(&path));
        rustix::fs::mkfifoat(rustix::fs::CWD, &lock_path, Mode::RUSR | Mode::WUSR).unwrap();
        assert!(matches!(
            WriterLock::acquire(&path),
            Err(ZoneFileError::NotRegularFile)
        ));
    }
}
