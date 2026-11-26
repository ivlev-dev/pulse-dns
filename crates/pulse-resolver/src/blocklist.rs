//! Blocklist: домены, hosts-формат, wildcard и allowlist.
//!
//! Поиск идёт по суффиксному дереву меток (справа налево), поэтому стоимость
//! зависит от числа меток имени, а не от размера списка. Запись `example.com`
//! блокирует само имя и все поддомены; `*.example.com` — только поддомены;
//! allowlist имеет приоритет над blocklist.
//!
//! Источники по URL (HTTPS, кэш, условные запросы) реализованы в
//! [`remote`]; они возвращают текст, который объединяется с локальными
//! файлами через [`Blocklist::load_combined`].

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use pulse_dns::Name;
use thiserror::Error;

pub mod remote;

pub use remote::{
    DEFAULT_BACKOFF, DEFAULT_MAX_BYTES, DEFAULT_REFRESH_SECS, DEFAULT_RETRIES, DEFAULT_TIMEOUT,
    RemoteBlocklist, RemoteBlocklistConfig, RemoteError, RemoteRefreshReport, RemoteSource,
    RemoteSourceError, RemoteSourceStatus, SourceFormat, default_cache_dir,
};

/// Максимальный размер файла blocklist (64 MiB, SEC-API-010).
pub const MAX_BLOCKLIST_BYTES: u64 = 64 * 1024 * 1024;

/// Ошибка загрузки blocklist.
#[derive(Debug, Error)]
pub enum BlocklistError {
    /// Ошибка чтения файла.
    #[error("blocklist i/o error: {0}")]
    Io(#[from] io::Error),
    /// Файл больше допустимого размера.
    #[error("blocklist file is {size} bytes (max {MAX_BLOCKLIST_BYTES})")]
    TooLarge {
        /// Размер файла.
        size: u64,
    },
}

/// Статистика загруженного blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BlocklistStats {
    /// Сколько блокирующих записей принято.
    pub blocked: usize,
    /// Сколько allowlist-записей принято.
    pub allowed: usize,
    /// Сколько строк пропущено как невалидные/неподдерживаемые.
    pub skipped: usize,
}

/// Суффиксное дерево меток.
#[derive(Debug, Default)]
struct Node {
    terminal: bool,
    wildcard: bool,
    children: HashMap<Vec<u8>, Node>,
}

impl Node {
    fn insert(&mut self, labels: &[Vec<u8>], wildcard: bool) {
        let mut node = self;
        for label in labels.iter().rev() {
            node = node.children.entry(label.clone()).or_default();
        }
        if wildcard {
            node.wildcard = true;
        } else {
            node.terminal = true;
        }
    }

    fn contains(&self, name: &Name) -> bool {
        self.contains_wire(name.as_wire())
    }

    fn contains_wire(&self, wire: &[u8]) -> bool {
        // Метки складываются в стековый массив: поиск на горячем пути не
        // аллоцирует даже при глубоких именах.
        let mut labels = [&[][..]; pulse_dns::MAX_LABELS];
        let mut count = 0_usize;
        for label in pulse_dns::NameRef::from_validated(wire).labels() {
            let Some(slot) = labels.get_mut(count) else {
                break;
            };
            *slot = label;
            count = count.saturating_add(1);
        }
        let mut node = self;
        // Идём от корневой метки к левой. На каждом шаге проверяем, не
        // покрывает ли уже пройденный узел все оставшиеся метки.
        for label in labels.get(..count).unwrap_or(&[]).iter().rev() {
            if node.terminal || node.wildcard {
                return true;
            }
            let Some(child) = node.children.get(*label) else {
                return false;
            };
            node = child;
        }
        node.terminal
    }

    fn count(&self) -> usize {
        let own = usize::from(self.terminal || self.wildcard);
        own + self.children.values().map(Node::count).sum::<usize>()
    }
}

/// Неизменяемый снимок blocklist.
#[derive(Debug)]
pub struct Blocklist {
    block: Node,
    allow: Node,
    stats: BlocklistStats,
}

impl Blocklist {
    /// Пустой список с заданным allowlist.
    #[must_use]
    pub fn empty(allowlist: &[String]) -> Self {
        let mut allow = Node::default();
        let mut allowed = 0_usize;
        for entry in allowlist {
            if let Some((labels, wildcard)) = parse_entry(entry) {
                allow.insert(&labels, wildcard);
                allowed += 1;
            }
        }
        Self {
            block: Node::default(),
            allow,
            stats: BlocklistStats {
                blocked: 0,
                allowed,
                skipped: 0,
            },
        }
    }

    /// Загружает blocklist из файла.
    ///
    /// Поддерживаются: `domain`, `*.domain`, hosts-строки
    /// (`0.0.0.0 domain [domain…]`), adblock-подобные `||domain^` и
    /// allowlist-строки `@@domain` / домены из `allowlist`.
    ///
    /// # Errors
    ///
    /// [`BlocklistError::Io`] или [`BlocklistError::TooLarge`].
    pub fn load(path: impl AsRef<Path>, allowlist: &[String]) -> Result<Self, BlocklistError> {
        let text = read_limited(path.as_ref())?;
        Ok(Self::parse(&text, allowlist))
    }

    /// Загружает и объединяет несколько файлов blocklist в один снимок.
    ///
    /// Файлы читаются по порядку; allowlist применяется один раз к
    /// объединённому дереву. Дубликаты записей не увеличивают `stats`.
    ///
    /// # Errors
    ///
    /// [`BlocklistError::Io`] или [`BlocklistError::TooLarge`] для любого файла.
    pub fn load_paths(paths: &[PathBuf], allowlist: &[String]) -> Result<Self, BlocklistError> {
        let mut list = Self::empty(allowlist);
        for path in paths {
            list.add_path(path)?;
        }
        Ok(list)
    }

    /// Объединяет локальные файлы и уже скачанные удалённые источники.
    ///
    /// `sources` — пары «формат, текст» в порядке объединения. Allowlist
    /// применяется один раз к итоговому дереву.
    ///
    /// # Errors
    ///
    /// [`BlocklistError::Io`] или [`BlocklistError::TooLarge`] для любого файла.
    pub fn load_combined(
        paths: &[PathBuf],
        sources: &[(SourceFormat, &str)],
        allowlist: &[String],
    ) -> Result<Self, BlocklistError> {
        let mut list = Self::load_paths(paths, allowlist)?;
        for (format, text) in sources {
            list.add_source(text, *format);
        }
        Ok(list)
    }

    /// Разбирает blocklist из текста.
    #[must_use]
    pub fn parse(text: &str, allowlist: &[String]) -> Self {
        let mut list = Self::empty(allowlist);
        list.add_text(text);
        list
    }

    /// Добавляет файл к снимку.
    ///
    /// # Errors
    ///
    /// [`BlocklistError::Io`] или [`BlocklistError::TooLarge`].
    pub fn add_path(&mut self, path: impl AsRef<Path>) -> Result<(), BlocklistError> {
        let text = read_limited(path.as_ref())?;
        self.add_text(&text);
        Ok(())
    }

    /// Добавляет текст удалённого источника с учётом объявленного формата.
    pub fn add_source(&mut self, text: &str, format: SourceFormat) {
        self.add_text_with(text, format);
    }

    fn add_text(&mut self, text: &str) {
        self.add_text_with(text, SourceFormat::Auto);
    }

    fn add_text_with(&mut self, text: &str, format: SourceFormat) {
        for raw_line in text.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (is_allow, rest) = if let Some(rest) = line.strip_prefix("@@") {
                (true, rest.trim())
            } else {
                (false, line)
            };
            let selected = match format {
                SourceFormat::Auto => Some(rest),
                SourceFormat::Hosts => hosts_line(rest, is_allow),
                SourceFormat::Domains => domains_line(rest, is_allow),
            };
            let Some(selected) = selected else {
                self.stats.skipped += 1;
                continue;
            };
            let mut accepted = 0_usize;
            for token in domains_in_line(selected) {
                if let Some((labels, wildcard)) = parse_entry(token) {
                    if is_allow {
                        self.allow.insert(&labels, wildcard);
                    } else {
                        self.block.insert(&labels, wildcard);
                    }
                    accepted += 1;
                }
            }
            if accepted == 0 {
                self.stats.skipped += 1;
            } else if is_allow {
                self.stats.allowed += accepted;
            } else {
                self.stats.blocked += accepted;
            }
        }
    }

    /// Заблокировано ли имя.
    #[must_use]
    pub fn is_blocked(&self, name: &Name) -> bool {
        self.is_blocked_wire(name.as_wire())
    }

    /// `is_blocked` по канонической wire-форме (горячий путь без [`Name`]).
    #[must_use]
    pub fn is_blocked_wire(&self, wire: &[u8]) -> bool {
        if self.stats.blocked == 0 && self.stats.allowed == 0 {
            return false;
        }
        self.block.contains_wire(wire) && !self.allow.contains_wire(wire)
    }

    /// Заблокировано ли имя без учёта allowlist (для диагностики).
    #[must_use]
    pub fn matched_rule(&self, name: &Name) -> bool {
        self.block.contains(name)
    }
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::empty(&[])
    }
}

fn read_limited(path: &Path) -> Result<String, BlocklistError> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_BLOCKLIST_BYTES {
        return Err(BlocklistError::TooLarge {
            size: metadata.len(),
        });
    }
    Ok(fs::read_to_string(path)?)
}

fn domains_in_line(line: &str) -> Vec<&str> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let Some(first) = tokens.first() else {
        return Vec::new();
    };
    if first.parse::<std::net::IpAddr>().is_ok() {
        return tokens.get(1..).unwrap_or(&[]).to_vec();
    }
    if tokens.len() == 1 {
        return tokens;
    }
    Vec::new()
}

/// Строка hosts-формата: `IP domain [domain…]`; allow-директивы остаются
/// доменными, чтобы `@@allow` работал и в hosts-источниках.
fn hosts_line(line: &str, is_allow: bool) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    let first = tokens.next()?;
    if first.parse::<std::net::IpAddr>().is_ok() {
        return Some(line);
    }
    if is_allow && tokens.next().is_none() {
        return Some(line);
    }
    None
}

/// Строка формата plain-доменов: ровно один токен (allow-директивы тоже).
fn domains_line(line: &str, _is_allow: bool) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    let first = tokens.next()?;
    if tokens.next().is_some() {
        return None;
    }
    Some(first)
}

fn parse_entry(entry: &str) -> Option<(Vec<Vec<u8>>, bool)> {
    let mut value = entry.trim().trim_end_matches('^').trim();
    if value.is_empty() || value.starts_with('!') || value.starts_with('[') {
        return None;
    }
    value = value.trim_start_matches("||");
    value = value.trim_start_matches('.');
    value = value.trim_end_matches('.');
    if value.is_empty() {
        return None;
    }
    let (wildcard, value) = if let Some(rest) = value.strip_prefix("*.") {
        (true, rest)
    } else {
        if value.contains('*') || value.contains('/') {
            return None;
        }
        (false, value)
    };
    if value.is_empty() {
        return None;
    }
    let name = Name::parse(value).ok()?;
    let labels = name.labels().map(<[u8]>::to_vec).collect();
    Some((labels, wildcard))
}

impl Blocklist {
    /// Число записей в списке (block + allow).
    #[must_use]
    pub fn len(&self) -> usize {
        self.block.count() + self.allow.count()
    }

    /// Пуст ли список.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Статистика загрузки.
    #[must_use]
    pub const fn stats(&self) -> BlocklistStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> Name {
        Name::parse(value).unwrap()
    }

    #[test]
    fn exact_domain_blocks_subdomains() {
        let list = Blocklist::parse("example.com\n", &[]);
        assert!(list.is_blocked(&name("example.com")));
        assert!(list.is_blocked(&name("www.example.com")));
        assert!(!list.is_blocked(&name("notexample.com")));
        assert!(!list.is_blocked(&name("com")));
    }

    #[test]
    fn wildcard_does_not_block_apex() {
        let list = Blocklist::parse("*.example.com\n", &[]);
        assert!(!list.is_blocked(&name("example.com")));
        assert!(list.is_blocked(&name("www.example.com")));
        assert!(list.is_blocked(&name("a.b.example.com")));
    }

    #[test]
    fn allowlist_wins() {
        let list = Blocklist::parse("example.com\n", &["allowed.example.com".to_owned()]);
        assert!(list.is_blocked(&name("example.com")));
        assert!(!list.is_blocked(&name("allowed.example.com")));
        assert!(!list.is_blocked(&name("x.allowed.example.com")));
    }

    #[test]
    fn hosts_and_adblock_formats() {
        let list = Blocklist::parse(
            "0.0.0.0 ads.example.com tracker.example.net\n\
             127.0.0.1 localhost.example\n\
             ||bad.example^\n\
             @@good.example\n",
            &[],
        );
        assert!(list.is_blocked(&name("ads.example.com")));
        assert!(list.is_blocked(&name("tracker.example.net")));
        assert!(list.is_blocked(&name("localhost.example")));
        assert!(list.is_blocked(&name("bad.example")));
        assert!(!list.is_blocked(&name("good.example")));
    }

    #[test]
    fn empty_list_blocks_nothing() {
        let list = Blocklist::default();
        assert!(list.is_empty());
        assert!(!list.is_blocked(&name("example.com")));
    }

    #[test]
    fn load_paths_merges_files_and_applies_allowlist_once() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.txt");
        let second = directory.path().join("second.txt");
        fs::write(&first, "one.test\nshared.test\n").unwrap();
        fs::write(&second, "two.test\n@@allowed.two.test\n").unwrap();
        let list = Blocklist::load_paths(
            &[first, second],
            &["safe.one.test".to_owned(), "shared.test".to_owned()],
        )
        .unwrap();
        assert!(list.is_blocked(&name("one.test")));
        assert!(list.is_blocked(&name("two.test")));
        assert!(!list.is_blocked(&name("safe.one.test")));
        assert!(!list.is_blocked(&name("allowed.two.test")));
        assert!(!list.is_blocked(&name("shared.test")));
        assert_eq!(list.stats().blocked, 3);
    }

    #[test]
    fn remote_formats_filter_lines() {
        let hosts = "0.0.0.0 ads.test\n127.0.0.1 tracker.test\nplain.test\n";
        let mut list = Blocklist::empty(&[]);
        list.add_source(hosts, SourceFormat::Hosts);
        assert!(list.is_blocked(&name("ads.test")));
        assert!(list.is_blocked(&name("tracker.test")));
        assert!(!list.is_blocked(&name("plain.test")));

        let mut list = Blocklist::empty(&[]);
        list.add_source("plain.test\n0.0.0.0 ads.test\n", SourceFormat::Domains);
        assert!(list.is_blocked(&name("plain.test")));
        assert!(!list.is_blocked(&name("ads.test")));

        let mut list = Blocklist::empty(&[]);
        list.add_source("0.0.0.0 ads.test\nplain.test\n", SourceFormat::Auto);
        assert!(list.is_blocked(&name("ads.test")));
        assert!(list.is_blocked(&name("plain.test")));
    }

    #[test]
    fn load_combined_merges_files_sources_and_allowlist() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("local.txt");
        fs::write(&path, "local.test\n").unwrap();
        let remote = "0.0.0.0 remote.test\n*.wild.test\n";
        let list = Blocklist::load_combined(
            &[path],
            &[(SourceFormat::Auto, remote)],
            &["safe.remote.test".to_owned()],
        )
        .unwrap();
        assert!(list.is_blocked(&name("local.test")));
        assert!(list.is_blocked(&name("remote.test")));
        assert!(!list.is_blocked(&name("safe.remote.test")));
        assert!(list.is_blocked(&name("a.wild.test")));
        assert!(!list.is_blocked(&name("wild.test")));
    }
}
