//! Доменное имя (`domain-model.md` §2.1, INV-11).

use std::cmp::Ordering;
use std::fmt;
use std::fmt::Write as _;
use std::io::Write;
use std::str::FromStr;

use thiserror::Error;

/// Максимальная длина wire-формы имени, включая терминальный ноль (RFC 1035).
pub const MAX_NAME_WIRE_LEN: usize = 255;
/// Максимальная длина одной метки (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;
/// Максимальное количество меток в имени.
pub const MAX_LABELS: usize = 127;
/// Разумный предел презентационной строки имени: до 4 символов на октет
/// (`\DDD`) для 255 октетов wire-формы.
pub const MAX_NAME_TEXT_LEN: usize = 1024;

/// Ошибка разбора или валидации [`Name`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NameError {
    /// Пустая строка вместо имени.
    #[error("empty name")]
    EmptyName,
    /// Презентационная строка длиннее [`MAX_NAME_TEXT_LEN`].
    #[error("text name is {len} bytes long (max {MAX_NAME_TEXT_LEN})")]
    TextTooLong {
        /// Длина входной строки.
        len: usize,
    },
    /// Пустая метка (например, `a..b`).
    #[error("empty label")]
    EmptyLabel,
    /// Метка длиннее 63 октетов.
    #[error("label is {len} octets long (max {MAX_LABEL_LEN})")]
    LabelTooLong {
        /// Фактическая длина метки.
        len: usize,
    },
    /// Имя в wire-форме длиннее 255 октетов.
    #[error("name is {len} octets long (max {MAX_NAME_WIRE_LEN})")]
    TooLong {
        /// Фактическая длина wire-формы.
        len: usize,
    },
    /// Недопустимый октет во входной строке.
    #[error("invalid character 0x{byte:02x} at byte offset {offset}")]
    BadCharacter {
        /// Октет.
        byte: u8,
        /// Позиция во входной строке.
        offset: usize,
    },
    /// Некорректная escape-последовательность.
    #[error("invalid escape sequence at byte offset {offset}")]
    BadEscape {
        /// Позиция во входной строке.
        offset: usize,
    },
    /// `*` встречается не в левой метке или более одного раза.
    ///
    /// Относится только к валидации владельца зоны
    /// ([`Name::validate_zone_owner`]), а не к wire-разбору: в DNS-запросе
    /// `*` — обычная метка.
    #[error("wildcard label is allowed only once and only as the leftmost label")]
    WildcardNotLeftmost,
    /// Более 127 меток.
    #[error("too many labels: {count} (max {MAX_LABELS})")]
    TooManyLabels {
        /// Количество меток.
        count: usize,
    },
    /// Некорректная несжатая wire-форма.
    #[error("malformed wire-format name")]
    MalformedWire,
}

/// Каноническое абсолютное доменное имя.
///
/// Хранит несжатую wire-форму с терминальным нулём. ASCII-буквы приведены к
/// нижнему регистру, что делает равенство и хеширование каноническими.
///
/// Тип намеренно **не реализует** [`Ord`]/[`PartialOrd`]: для DNSSEC-порядка
/// используйте [`Name::cmp_canonical`] (RFC 4034 §6.1).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Name {
    /// Валидированная несжатая wire-форма, всегда с терминальным нулём.
    wire: Vec<u8>,
}

impl Name {
    /// Корень (`.`), wire-форма `[0]`.
    #[must_use]
    pub fn root() -> Self {
        Self { wire: vec![0] }
    }

    /// Разбирает имя в презентационном формате.
    ///
    /// Принимаются имена с завершающей точкой и без неё; `.` — корень.
    /// Поддерживаются escape-последовательности `\.`, `\\` и `\DDD`
    /// (ровно три десятичные цифры). Незаэкранированные октеты должны быть
    /// печатным ASCII (0x21..=0x7E).
    ///
    /// `*` разбирается как обычная метка в любой позиции: это имя запроса, а
    /// не wildcard-владелец зоны. Для зоны используйте
    /// [`Name::validate_zone_owner`].
    ///
    /// # Errors
    ///
    /// [`NameError`] при пустом имени/метке, слишком длинном имени или метке,
    /// недопустимом символе или некорректной escape-последовательности.
    pub fn parse(input: &str) -> Result<Self, NameError> {
        if input.is_empty() {
            return Err(NameError::EmptyName);
        }
        if input.len() > MAX_NAME_TEXT_LEN {
            return Err(NameError::TextTooLong { len: input.len() });
        }
        if input == "." {
            return Ok(Self::root());
        }

        let bytes = input.as_bytes();
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        let mut index = 0_usize;

        while let Some(&byte) = bytes.get(index) {
            match byte {
                b'.' => {
                    if current.is_empty() {
                        return Err(NameError::EmptyLabel);
                    }
                    labels.push(std::mem::take(&mut current));
                    index += 1;
                }
                b'\\' => {
                    let (value, next) = parse_escape(bytes, index)?;
                    current.push(value.to_ascii_lowercase());
                    index = next;
                }
                b'A'..=b'Z' => {
                    current.push(byte.to_ascii_lowercase());
                    index += 1;
                }
                0x21..=0x7E => {
                    current.push(byte);
                    index += 1;
                }
                _ => {
                    return Err(NameError::BadCharacter {
                        byte,
                        offset: index,
                    });
                }
            }
        }

        if !current.is_empty() {
            labels.push(current);
        }
        Self::from_label_bytes(labels)
    }

    /// Создаёт имя из несжатой wire-формы, канонизируя регистр.
    ///
    /// На вход подаётся последовательность `len label … 0` без указателей
    /// сжатия. Хвостовые байты после терминатора запрещены. Метка `*`
    /// принимается в любой позиции как обычная метка wire-формата.
    ///
    /// # Errors
    ///
    /// [`NameError`] при некорректной wire-форме или нарушении лимитов.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, NameError> {
        if bytes.is_empty() {
            return Err(NameError::EmptyName);
        }
        if bytes.len() > MAX_NAME_WIRE_LEN {
            return Err(NameError::TooLong { len: bytes.len() });
        }
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut index = 0_usize;
        loop {
            let Some(&length) = bytes.get(index) else {
                return Err(NameError::MalformedWire);
            };
            if length == 0 {
                index += 1;
                break;
            }
            if length > u8::try_from(MAX_LABEL_LEN).unwrap_or(u8::MAX) {
                return Err(NameError::MalformedWire);
            }
            let start = index + 1;
            let end = start
                .checked_add(length as usize)
                .ok_or(NameError::MalformedWire)?;
            let label = bytes.get(start..end).ok_or(NameError::MalformedWire)?;
            labels.push(label.to_ascii_lowercase());
            index = end;
        }
        if index != bytes.len() {
            return Err(NameError::MalformedWire);
        }
        Self::from_label_bytes(labels)
    }

    /// Собирает имя из уже проверенных меток.
    pub(crate) fn from_labels(labels: Vec<Vec<u8>>) -> Result<Self, NameError> {
        Self::from_label_bytes(labels)
    }

    /// Собирает имя из уже проверенных меток.
    fn from_label_bytes(labels: Vec<Vec<u8>>) -> Result<Self, NameError> {
        if labels.is_empty() {
            return Ok(Self::root());
        }
        if labels.len() > MAX_LABELS {
            return Err(NameError::TooManyLabels {
                count: labels.len(),
            });
        }

        let mut total = 1_usize;
        for label in &labels {
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(NameError::LabelTooLong { len: label.len() });
            }
            total = total
                .checked_add(label.len() + 1)
                .ok_or(NameError::TooLong { len: usize::MAX })?;
        }
        if total > MAX_NAME_WIRE_LEN {
            return Err(NameError::TooLong { len: total });
        }

        let mut wire = Vec::with_capacity(total);
        for label in labels {
            // Длина проверена выше (1..=63).
            wire.push(
                u8::try_from(label.len()).unwrap_or(u8::try_from(MAX_LABEL_LEN).unwrap_or(u8::MAX)),
            );
            wire.extend_from_slice(&label);
        }
        wire.push(0);
        Ok(Self { wire })
    }

    /// Итератор по меткам (без терминального нуля).
    #[must_use]
    pub fn labels(&self) -> Labels<'_> {
        Labels {
            wire: &self.wire,
            position: 0,
        }
    }

    /// Количество меток (у корня — 0).
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Первая (левая) метка, если имя не корневое.
    #[must_use]
    pub fn first_label(&self) -> Option<&[u8]> {
        self.labels().next()
    }

    /// Несжатая wire-форма, включая терминальный ноль.
    #[must_use]
    pub fn as_wire(&self) -> &[u8] {
        &self.wire
    }

    /// Длина несжатой wire-формы в октетах.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.wire.len()
    }

    /// Копия несжатой wire-формы.
    #[must_use]
    pub fn to_wire_uncompressed(&self) -> Vec<u8> {
        self.wire.clone()
    }

    /// Записывает несжатую wire-форму в `out`.
    ///
    /// # Errors
    ///
    /// Возвращает ошибку ввода-вывода `out`.
    pub fn write_wire(&self, out: &mut impl Write) -> std::io::Result<usize> {
        out.write_all(&self.wire)?;
        Ok(self.wire.len())
    }

    /// Родительское имя; `None` для корня.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let mut labels = self.labels();
        labels.next()?;
        let mut wire = Vec::with_capacity(self.wire.len().saturating_sub(1));
        for label in labels {
            wire.push(
                u8::try_from(label.len()).unwrap_or(u8::try_from(MAX_LABEL_LEN).unwrap_or(u8::MAX)),
            );
            wire.extend_from_slice(label);
        }
        wire.push(0);
        Some(Self { wire })
    }

    /// Является ли имя поддоменом `ancestor` (включая равенство).
    #[must_use]
    pub fn is_subdomain_of(&self, ancestor: &Self) -> bool {
        let own_labels: Vec<&[u8]> = self.labels().collect();
        let ancestor_labels: Vec<&[u8]> = ancestor.labels().collect();
        if ancestor_labels.len() > own_labels.len() {
            return false;
        }
        own_labels
            .iter()
            .rev()
            .zip(ancestor_labels.iter().rev())
            .all(|(own, expected)| own == expected)
    }

    /// Является ли имя wildcard-владельцем зоны.
    ///
    /// Wildcard-владелец — имя, у которого ровно первая метка равна `*`
    /// и других меток `*` нет. Метка `*a` не является wildcard.
    #[must_use]
    pub fn is_wildcard_owner(&self) -> bool {
        let mut labels = self.labels();
        let first_is_star = labels.next().is_some_and(|label| label == b"*");
        first_is_star && !labels.any(|label| label == b"*")
    }

    /// Проверяет имя как владельца RRset в зоне (INV-11).
    ///
    /// В зоне метка `*` допустима только как единственная левая метка:
    /// `*.example.com` — валидный wildcard-владелец, `a.*.example.com` и
    /// `*.*.example.com` — нет. К именам из wire-запросов это правило
    /// **не применяется**: там `*` — обычная метка (RFC 1035).
    ///
    /// # Errors
    ///
    /// [`NameError::WildcardNotLeftmost`], если `*` встречается не в первой
    /// метке.
    pub fn validate_zone_owner(&self) -> Result<(), NameError> {
        for (position, label) in self.labels().enumerate() {
            if label == b"*" && position != 0 {
                return Err(NameError::WildcardNotLeftmost);
            }
        }
        Ok(())
    }

    /// Каноническое сравнение имён по RFC 4034 §6.1.
    ///
    /// Метки сравниваются с младшей (правой) к старшей; регистр уже
    /// нормализован. Предок сортируется перед потомком.
    #[must_use]
    pub fn cmp_canonical(&self, other: &Self) -> Ordering {
        let mut left: Vec<&[u8]> = self.labels().collect();
        let mut right: Vec<&[u8]> = other.labels().collect();
        left.reverse();
        right.reverse();

        for (a, b) in left.iter().zip(right.iter()) {
            match a.cmp(b) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        left.len().cmp(&right.len())
    }

    /// Проверяет инварианты (для данных, собранных внутри крейта).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        Self::from_wire(&self.wire).is_ok()
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wire == [0] {
            return f.write_str(".");
        }
        for label in self.labels() {
            write_escaped_label(f, label)?;
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

impl FromStr for Name {
    type Err = NameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<&str> for Name {
    type Error = NameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

/// Итератор по меткам имени.
#[derive(Debug, Clone)]
pub struct Labels<'a> {
    wire: &'a [u8],
    position: usize,
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let length = *self.wire.get(self.position)?;
        if length == 0 {
            return None;
        }
        let start = self.position + 1;
        let end = start.checked_add(length as usize)?;
        let label = self.wire.get(start..end)?;
        self.position = end;
        Some(label)
    }
}

/// Свободная функция канонического сравнения имён (RFC 4034 §6.1).
#[must_use]
pub fn name_cmp(left: &Name, right: &Name) -> Ordering {
    left.cmp_canonical(right)
}

fn parse_escape(bytes: &[u8], backslash: usize) -> Result<(u8, usize), NameError> {
    let next = backslash + 1;
    let Some(&first) = bytes.get(next) else {
        return Err(NameError::BadEscape { offset: backslash });
    };
    match first {
        b'.' => Ok((b'.', next + 1)),
        b'\\' => Ok((b'\\', next + 1)),
        b'0'..=b'9' => {
            let second = bytes
                .get(next + 1)
                .copied()
                .ok_or(NameError::BadEscape { offset: backslash })?;
            let third = bytes
                .get(next + 2)
                .copied()
                .ok_or(NameError::BadEscape { offset: backslash })?;
            if !second.is_ascii_digit() || !third.is_ascii_digit() {
                return Err(NameError::BadEscape { offset: backslash });
            }
            let value = u16::from(first - b'0') * 100
                + u16::from(second - b'0') * 10
                + u16::from(third - b'0');
            let value =
                u8::try_from(value).map_err(|_| NameError::BadEscape { offset: backslash })?;
            Ok((value, next + 3))
        }
        _ => Err(NameError::BadEscape { offset: backslash }),
    }
}

fn write_escaped_label(f: &mut fmt::Formatter<'_>, label: &[u8]) -> fmt::Result {
    for &byte in label {
        match byte {
            b'.' => f.write_str("\\.")?,
            b'\\' => f.write_str("\\\\")?,
            0x21..=0x7E => f.write_char(char::from(byte))?,
            _ => write!(f, "\\{byte:03}")?,
        }
    }
    Ok(())
}
