//! Доменное имя (`domain-model.md` §2.1, INV-11).

use std::borrow::Borrow;
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
        // Одна аллокация под каноническую wire-форму вместо `Vec<Vec<u8>>`
        // промежуточных меток: имя на горячем пути декодируется на каждый
        // запрос.
        let mut wire = Vec::with_capacity(bytes.len());
        let mut index = 0_usize;
        let mut labels = 0_usize;
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
            labels = labels.saturating_add(1);
            if labels > MAX_LABELS {
                return Err(NameError::TooManyLabels { count: labels });
            }
            wire.push(length);
            wire.extend(label.iter().map(u8::to_ascii_lowercase));
            index = end;
        }
        if index != bytes.len() {
            return Err(NameError::MalformedWire);
        }
        wire.push(0);
        Ok(Self { wire })
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
        is_wire_subdomain(&self.wire, &ancestor.wire)
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
        // Метки собираются в стековые массивы: `Vec` на каждый вызов
        // недопустим на горячем пути.
        let mut left = [&[][..]; MAX_LABELS];
        let mut right = [&[][..]; MAX_LABELS];
        let left_len = collect_labels(&self.wire, &mut left);
        let right_len = collect_labels(&other.wire, &mut right);

        for index in 0..left_len.min(right_len) {
            let Some(a) = left.get(left_len - 1 - index) else {
                break;
            };
            let Some(b) = right.get(right_len - 1 - index) else {
                break;
            };
            match a.cmp(b) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        left_len.cmp(&right_len)
    }

    /// Проверяет инварианты (для данных, собранных внутри крейта).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        Self::from_wire(&self.wire).is_ok()
    }
}

/// Заимствованное каноническое имя (`&[u8]` в несжатой wire-форме).
///
/// Используется на горячем пути ответа: `NameRef` не владеет буфером и не
/// аллоцирует при сравнении/проверке суффикса. Байты должны быть в нижнем
/// регистре и завершаться нулём — это гарантирует [`NameRef::from_wire`] и
/// [`NameRef::from_name`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NameRef<'a> {
    wire: &'a [u8],
}

impl<'a> NameRef<'a> {
    /// Оборачивает уже провалидированную каноническую wire-форму.
    #[must_use]
    pub const fn from_validated(wire: &'a [u8]) -> Self {
        Self { wire }
    }

    /// Проверяет и оборачивает wire-форму без копирования.
    ///
    /// Принимаются только имена в каноническом нижнем регистре: иначе
    /// сравнение `NameRef` с [`Name`] было бы некорректным.
    ///
    /// # Errors
    ///
    /// [`NameError`] при некорректной wire-форме или наличии `A..=Z`.
    pub fn from_wire(wire: &'a [u8]) -> Result<Self, NameError> {
        if wire.is_empty() {
            return Err(NameError::EmptyName);
        }
        if wire.len() > MAX_NAME_WIRE_LEN {
            return Err(NameError::TooLong { len: wire.len() });
        }
        let mut index = 0_usize;
        let mut labels = 0_usize;
        loop {
            let Some(&length) = wire.get(index) else {
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
            let label = wire.get(start..end).ok_or(NameError::MalformedWire)?;
            if label.iter().any(u8::is_ascii_uppercase) {
                return Err(NameError::MalformedWire);
            }
            labels = labels.saturating_add(1);
            if labels > MAX_LABELS {
                return Err(NameError::TooManyLabels { count: labels });
            }
            index = end;
        }
        if index != wire.len() {
            return Err(NameError::MalformedWire);
        }
        Ok(Self { wire })
    }

    /// Ссылается на каноническую wire-форму владеющего имени.
    #[must_use]
    pub fn from_name(name: &'a Name) -> Self {
        Self {
            wire: name.as_wire(),
        }
    }

    /// Несжатая wire-форма.
    #[must_use]
    pub const fn as_wire(self) -> &'a [u8] {
        self.wire
    }

    /// Длина wire-формы.
    #[must_use]
    pub const fn wire_len(self) -> usize {
        self.wire.len()
    }

    /// Итератор по меткам.
    #[must_use]
    pub fn labels(self) -> Labels<'a> {
        Labels {
            wire: self.wire,
            position: 0,
        }
    }

    /// Первая (левая) метка.
    #[must_use]
    pub fn first_label(self) -> Option<&'a [u8]> {
        self.labels().next()
    }

    /// Число меток.
    #[must_use]
    pub fn label_count(self) -> usize {
        self.labels().count()
    }

    /// Родительское имя.
    #[must_use]
    pub fn parent(self) -> Option<Self> {
        let first = self.first_label()?;
        let offset = first.len().saturating_add(1);
        self.wire.get(offset..).map(Self::from_validated)
    }

    /// Является ли имя поддоменом `ancestor`.
    #[must_use]
    pub fn is_subdomain_of(self, ancestor: Self) -> bool {
        is_wire_subdomain(self.wire, ancestor.wire)
    }

    /// Является ли имя поддоменом владеющего [`Name`].
    #[must_use]
    pub fn is_subdomain_of_name(self, ancestor: &Name) -> bool {
        is_wire_subdomain(self.wire, ancestor.as_wire())
    }

    /// Каноническое сравнение (RFC 4034 §6.1) без аллокаций.
    #[must_use]
    pub fn cmp_canonical(self, other: Self) -> Ordering {
        let mut left = [&[][..]; MAX_LABELS];
        let mut right = [&[][..]; MAX_LABELS];
        let left_len = collect_labels(self.wire, &mut left);
        let right_len = collect_labels(other.wire, &mut right);
        for index in 0..left_len.min(right_len) {
            let Some(a) = left.get(left_len - 1 - index) else {
                break;
            };
            let Some(b) = right.get(right_len - 1 - index) else {
                break;
            };
            match a.cmp(b) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        left_len.cmp(&right_len)
    }

    /// Материализует владеющее имя (единственная аллокация — при переходе на
    /// APIs, которым нужен [`Name`]).
    ///
    /// # Errors
    ///
    /// [`NameError`], если имя не помещается в лимиты.
    pub fn to_name(self) -> Result<Name, NameError> {
        Name::from_wire(self.wire)
    }
}

impl core::fmt::Debug for NameRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = self.to_name();
        match name {
            Ok(name) => write!(f, "NameRef({name})"),
            Err(_) => write!(f, "NameRef(<invalid>)"),
        }
    }
}

impl PartialEq<Name> for NameRef<'_> {
    fn eq(&self, other: &Name) -> bool {
        self.wire == other.as_wire()
    }
}

impl PartialEq<NameRef<'_>> for Name {
    fn eq(&self, other: &NameRef<'_>) -> bool {
        self.as_wire() == other.as_wire()
    }
}

impl Borrow<[u8]> for Name {
    fn borrow(&self) -> &[u8] {
        self.as_wire()
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

/// Проверяет, что `ancestor` — суффикс `name` ровно по границе метки.
///
/// Сравнение `ends_with` недостаточно: байты метки могут сами образовывать
/// валидную wire-форму, начинающуюся в середине метки. Функция не аллоцирует.
fn is_wire_subdomain(name: &[u8], ancestor: &[u8]) -> bool {
    let Some(start) = name.len().checked_sub(ancestor.len()) else {
        return false;
    };
    if name.get(start..) != Some(ancestor) {
        return false;
    }
    let mut position = 0_usize;
    while position < start {
        let Some(&length) = name.get(position) else {
            return false;
        };
        if length == 0 {
            return false;
        }
        position = position.saturating_add(1 + usize::from(length));
    }
    position == start
}

/// Свободная функция канонического сравнения имён (RFC 4034 §6.1).
#[must_use]
pub fn name_cmp(left: &Name, right: &Name) -> Ordering {
    left.cmp_canonical(right)
}

/// Собирает метки wire-формы в стековый массив; возвращает их число.
fn collect_labels<'a>(wire: &'a [u8], out: &mut [&'a [u8]; MAX_LABELS]) -> usize {
    let mut count = 0_usize;
    let mut position = 0_usize;
    while let Some(&length) = wire.get(position) {
        if length == 0 {
            break;
        }
        let start = position + 1;
        let end = start.saturating_add(usize::from(length));
        let Some(label) = wire.get(start..end) else {
            break;
        };
        let Some(slot) = out.get_mut(count) else {
            break;
        };
        *slot = label;
        count = count.saturating_add(1);
        position = end;
    }
    count
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomain_does_not_match_inside_label() {
        // Левая метка содержит байты, которые сами образуют валидное имя
        // `\x01a\x00`; суффикс не должен считаться поддоменом.
        let parent = Name::from_wire(b"\x02\x01a\x00").unwrap();
        let ancestor = Name::from_wire(b"\x01a\x00").unwrap();
        assert!(!parent.is_subdomain_of(&ancestor));
        let parent_ref = NameRef::from_name(&parent);
        let ancestor_ref = NameRef::from_name(&ancestor);
        assert!(!parent_ref.is_subdomain_of(ancestor_ref));
    }

    #[test]
    fn name_ref_matches_owned_name() {
        let owned = Name::parse("WWW.Example.COM.").unwrap();
        let reference = NameRef::from_name(&owned);
        assert_eq!(reference.as_wire(), b"\x03www\x07example\x03com\x00");
        assert_eq!(reference.to_name().unwrap(), owned);
        assert!(reference.is_subdomain_of_name(&Name::parse("example.com.").unwrap()));
        assert_eq!(reference.label_count(), 3);
        assert_eq!(
            reference.parent().unwrap().as_wire(),
            b"\x07example\x03com\x00"
        );
    }

    #[test]
    fn canonical_cmp_matches_owned() {
        let left = Name::parse("a.example.com.").unwrap();
        let right = Name::parse("b.example.com.").unwrap();
        let left_ref = NameRef::from_name(&left);
        let right_ref = NameRef::from_name(&right);
        assert_eq!(
            left.cmp_canonical(&right),
            left_ref.cmp_canonical(right_ref)
        );
    }

    #[test]
    fn name_ref_rejects_uppercase_wire() {
        assert!(NameRef::from_wire(b"\x03WWW\x00").is_err());
    }
}
