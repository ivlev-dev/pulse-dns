//! Ключи B+tree: RLE-имена и составной ключ записи (`zonefile-v1.md` §8, §9).
//!
//! Имя хранится в RLE-форме с обратным порядком меток:
//! `len(label_n) label_n … len(label_1) label_1 0x00`, где `name = label_n … label_1`.
//! Такой порядок делает канонический порядок RFC 4034 §6.1 порядком «слева направо»
//! и позволяет фронт-кодированию сжимать общий суффикс домена.
//!
//! Составной ключ записи:
//!
//! ```text
//! key = RLE(name) || u16 type || u16 class || u16 subtype
//! ```
//!
//! Максимальная длина ключа — `MAX_KEY_SIZE` (261 байт). Компаратор
//! ([`compare_keys`]) сравнивает имена по меткам как беззнаковые байты
//! (предок раньше потомка), а затем числовые `type`/`class`/`subtype`.
//! `*` (0x2A) и `_` (0x5F) — обычные октеты метки.

use std::cmp::Ordering;
use std::fmt;

use crate::consts::MAX_NAME_WIRE;
use crate::errors::{CorruptDetail, CorruptKind, ZoneFileError};
use crate::wire;

/// Тип ключа каталога зон (`T_ZONE_ENTRY`).
pub const T_ZONE_ENTRY: u16 = 0xFFFE;
/// Тип ключа-маркера имени (`T_NODE`). Всегда первый ключ имени.
pub const T_NODE: u16 = 0x0000;
/// Тип записи `RRSIG`; различается по `subtype` (covered type).
pub const T_RRSIG: u16 = 46;
/// Класс `IN`.
pub const CLASS_IN: u16 = 1;

/// Размер хвоста ключа: `type`, `class`, `subtype`.
pub const KEY_TAIL_SIZE: usize = 6;
/// Максимальная длина RLE-имени в байтах, включая терминатор.
pub const NAME_MAX: usize = 255;
/// Максимальная длина ключа в байтах.
pub const KEY_MAX: usize = NAME_MAX + KEY_TAIL_SIZE;
/// Максимальная длина метки.
pub const LABEL_MAX: usize = 63;
/// Максимальное число меток в имени.
pub const LABELS_MAX: usize = 127;

const _: () = assert!(NAME_MAX == MAX_NAME_WIRE as usize);
const _: () = assert!(KEY_MAX == crate::consts::MAX_KEY_SIZE as usize);

fn corrupt_name(detail: CorruptDetail) -> ZoneFileError {
    ZoneFileError::corrupt(CorruptKind::BadName, None, detail)
}

fn bad_name() -> ZoneFileError {
    corrupt_name(CorruptDetail::BadNameEncoding)
}

/// Проверяет RLE-имя и возвращает его длину вместе с терминатором (§8.4).
///
/// Разрешено передавать префикс (для `has_children`), поэтому проверяется
/// только первый терминатор. Строгая проверка «терминатор — последний байт»
/// выполняется вызывающими, которым нужен полный ключ.
///
/// # Errors
///
/// `Corrupt(BadName)` — метка длиннее 63 (включая байты компрессии
/// `0xC0..=0xFF`), имя длиннее 255 байт, больше 127 меток или отсутствует
/// терминатор.
pub fn rle_len(bytes: &[u8]) -> Result<usize, ZoneFileError> {
    let mut offset = 0_usize;
    let mut labels = 0_usize;
    loop {
        if offset >= NAME_MAX {
            return Err(bad_name());
        }
        let Some(&label_len) = bytes.get(offset) else {
            return Err(bad_name());
        };
        if label_len == 0 {
            return Ok(offset + 1);
        }
        if usize::from(label_len) > LABEL_MAX {
            return Err(bad_name());
        }
        let next = offset
            .checked_add(1 + usize::from(label_len))
            .filter(|&next| next <= NAME_MAX)
            .ok_or_else(bad_name)?;
        offset = next;
        labels += 1;
        if labels > LABELS_MAX {
            return Err(bad_name());
        }
    }
}

pub(crate) fn validate_name_rle(
    bytes: &[u8],
    require_lowercase: bool,
) -> Result<(), ZoneFileError> {
    let name_len = rle_len(bytes)?;
    if name_len != bytes.len() {
        return Err(corrupt_name(CorruptDetail::BadNameEncoding));
    }
    let mut offset = 0_usize;
    let mut labels = 0_usize;
    while let Some(&label_len) = bytes.get(offset) {
        if label_len == 0 {
            break;
        }
        let start = offset + 1;
        let end = start + usize::from(label_len);
        let label = bytes
            .get(start..end)
            .ok_or_else(|| corrupt_name(CorruptDetail::BadNameEncoding))?;
        if require_lowercase && label.iter().any(u8::is_ascii_uppercase) {
            return Err(corrupt_name(CorruptDetail::BadNameEncoding));
        }
        offset = end;
        labels += 1;
    }
    if labels == 0 {
        return Err(corrupt_name(CorruptDetail::BadNameEncoding));
    }
    Ok(())
}

/// RLE-имя в обратном порядке меток (TLD → owner), lowercase.
///
/// Значение проверено: метки 1..63 байт, терминатор ровно один и последний,
/// суммарная длина ≤ 255, байты компрессии запрещены, имя непустое.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NameRle {
    buf: [u8; NAME_MAX],
    len: u8,
}

impl NameRle {
    /// Разбирает RLE-имя из файла: проверяет структуру и lowercase.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadName)` — невалидное RLE, не-lowercase байты, лишние байты
    /// после терминатора или пустое имя.
    pub fn parse(bytes: &[u8]) -> Result<Self, ZoneFileError> {
        validate_name_rle(bytes, true)?;
        let mut buf = [0_u8; NAME_MAX];
        let dst = buf
            .get_mut(..bytes.len())
            .ok_or_else(|| corrupt_name(CorruptDetail::BadNameEncoding))?;
        dst.copy_from_slice(bytes);
        let len =
            u8::try_from(bytes.len()).map_err(|_| corrupt_name(CorruptDetail::BadNameEncoding))?;
        Ok(Self { buf, len })
    }

    /// Копирует уже провалидированное RLE-имя без повторной проверки.
    ///
    /// Используется на горячем пути чтения: байты имени прошли валидацию
    /// страницы/ключа раньше. `None` — имя не помещается в [`NAME_MAX`].
    #[must_use]
    pub(crate) fn from_validated(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > NAME_MAX {
            return None;
        }
        let mut buf = [0_u8; NAME_MAX];
        buf.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Self {
            buf,
            len: u8::try_from(bytes.len()).ok()?,
        })
    }

    /// Нормализует RLE-имя: проверяет структуру и приводит метки к lowercase.
    ///
    /// Используется для входных имён, а не для чтения файла.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadName)` — невалидная структура RLE или пустое имя.
    pub fn normalize(bytes: &[u8]) -> Result<Self, ZoneFileError> {
        validate_name_rle(bytes, false)?;
        let mut buf = [0_u8; NAME_MAX];
        let dst = buf
            .get_mut(..bytes.len())
            .ok_or_else(|| corrupt_name(CorruptDetail::BadNameEncoding))?;
        dst.copy_from_slice(bytes);
        for byte in dst.iter_mut() {
            byte.make_ascii_lowercase();
        }
        let len =
            u8::try_from(bytes.len()).map_err(|_| corrupt_name(CorruptDetail::BadNameEncoding))?;
        Ok(Self { buf, len })
    }

    /// Строит имя из forward-wire (`owner → TLD`, длины + терминатор),
    /// разворачивает метки и нормализует регистр.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadName)` — невалидный wire, компрессионный байт, пустое имя
    /// или имя длиннее 255 байт.
    pub fn from_wire(wire_name: &[u8]) -> Result<Self, ZoneFileError> {
        let mut ranges = [(0_usize, 0_usize); LABELS_MAX];
        let mut count = 0_usize;
        let mut offset = 0_usize;
        loop {
            let Some(&label_len) = wire_name.get(offset) else {
                return Err(corrupt_name(CorruptDetail::BadNameEncoding));
            };
            let label_len = usize::from(label_len);
            if label_len == 0 {
                if offset + 1 != wire_name.len() {
                    return Err(corrupt_name(CorruptDetail::BadNameEncoding));
                }
                break;
            }
            if label_len > LABEL_MAX || label_len >= 0xC0 {
                return Err(corrupt_name(CorruptDetail::CompressionByte));
            }
            let start = offset + 1;
            let end = start
                .checked_add(label_len)
                .filter(|&end| end <= wire_name.len())
                .ok_or_else(bad_name)?;
            let slot = ranges
                .get_mut(count)
                .ok_or_else(|| corrupt_name(CorruptDetail::BadNameEncoding))?;
            *slot = (start, label_len);
            count += 1;
            offset = end;
        }
        if count == 0 || count > LABELS_MAX {
            return Err(corrupt_name(CorruptDetail::BadNameEncoding));
        }
        let mut buf = [0_u8; NAME_MAX];
        let mut out = 0_usize;
        for &(start, label_len) in ranges.iter().take(count).rev() {
            let label = wire_name
                .get(start..start + label_len)
                .ok_or_else(|| corrupt_name(CorruptDetail::BadNameEncoding))?;
            let label_len_u8 = u8::try_from(label_len).map_err(|_| bad_name())?;
            *buf.get_mut(out)
                .ok_or_else(|| corrupt_name(CorruptDetail::BadNameEncoding))? = label_len_u8;
            out += 1;
            let dst = buf
                .get_mut(out..out + label_len)
                .ok_or_else(|| corrupt_name(CorruptDetail::BadNameEncoding))?;
            dst.copy_from_slice(label);
            for byte in dst.iter_mut() {
                byte.make_ascii_lowercase();
            }
            out += label_len;
        }
        if out + 1 > NAME_MAX {
            return Err(corrupt_name(CorruptDetail::BadNameEncoding));
        }
        let len = u8::try_from(out + 1).map_err(|_| bad_name())?;
        Ok(Self { buf, len })
    }

    /// Строит имя из текстовой формы (`www.example.com` или с точкой на конце).
    ///
    /// # Errors
    ///
    /// `LabelTooLong` / `NameTooLong` — метка или имя превышают лимиты;
    /// `Corrupt(BadName)` — пустая метка или пустое имя.
    pub fn from_ascii(text: &str) -> Result<Self, ZoneFileError> {
        let trimmed = text.strip_suffix('.').unwrap_or(text);
        if trimmed.is_empty() {
            return Err(ZoneFileError::NameTooLong);
        }
        let mut total = 1_usize;
        for label in trimmed.split('.') {
            if label.is_empty() {
                return Err(corrupt_name(CorruptDetail::BadNameEncoding));
            }
            if label.len() > LABEL_MAX {
                return Err(ZoneFileError::LabelTooLong);
            }
            total = total
                .checked_add(1 + label.len())
                .ok_or(ZoneFileError::NameTooLong)?;
        }
        if total > NAME_MAX {
            return Err(ZoneFileError::NameTooLong);
        }
        let mut buf = [0_u8; NAME_MAX];
        let mut out = 0_usize;
        for label in trimmed.split('.').rev() {
            *buf.get_mut(out).ok_or(ZoneFileError::NameTooLong)? =
                u8::try_from(label.len()).map_err(|_| ZoneFileError::LabelTooLong)?;
            out += 1;
            let dst = buf
                .get_mut(out..out + label.len())
                .ok_or(ZoneFileError::NameTooLong)?;
            dst.copy_from_slice(label.as_bytes());
            for byte in dst.iter_mut() {
                byte.make_ascii_lowercase();
            }
            out += label.len();
        }
        let len = u8::try_from(out + 1).map_err(|_| ZoneFileError::NameTooLong)?;
        Ok(Self { buf, len })
    }

    /// Длина RLE в байтах, включая терминатор.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Всегда `false`: имя непустое по построению.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// RLE-срез (обратный порядок меток, терминатор включён).
    #[must_use]
    pub fn as_rle(&self) -> &[u8] {
        self.buf.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// RLE-срез без терминатора.
    #[must_use]
    pub fn without_terminal(&self) -> &[u8] {
        let end = usize::from(self.len).saturating_sub(1);
        self.buf.get(..end).unwrap_or(&[])
    }

    /// Число меток.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Метки в порядке хранения: TLD → owner.
    #[must_use]
    pub fn labels(&self) -> Labels<'_> {
        Labels {
            rle: self.as_rle(),
            offset: 0,
        }
    }

    /// Метки в порядке owner → TLD (обратный к хранению).
    #[must_use]
    pub fn labels_rev(&self) -> LabelsRev<'_> {
        LabelsRev::new(self.as_rle())
    }

    /// Левая метка имени (owner label).
    #[must_use]
    pub fn first_label(&self) -> Option<&[u8]> {
        self.labels().last()
    }

    /// Истина, если имя начинается с `*` (wildcard owner).
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.first_label() == Some(b"*".as_slice())
    }

    /// Имя-родитель (без левой метки); `None` для одно-меточного имени.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let mut offset = 0_usize;
        let mut last_start = None;
        while let Some(&label_len) = self.buf.get(offset) {
            if label_len == 0 {
                break;
            }
            last_start = Some(offset);
            offset += 1 + usize::from(label_len);
        }
        let start = last_start?;
        if start == 0 {
            return None;
        }
        let mut buf = [0_u8; NAME_MAX];
        let prefix = self.buf.get(..start)?;
        buf.get_mut(..start)?.copy_from_slice(prefix);
        let len = u8::try_from(start + 1).ok()?;
        Some(Self { buf, len })
    }

    /// Пишет forward-wire (`owner → TLD`, длины + терминатор) в `out`.
    ///
    /// Возвращает число записанных байт; `out` должен вмещать [`NameRle::len`].
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — выходной буфер меньше RLE-длины.
    pub fn write_wire(&self, out: &mut [u8]) -> Result<usize, ZoneFileError> {
        let mut pos = 0_usize;
        for label in self.labels_rev() {
            let len = u8::try_from(label.len()).map_err(|_| bad_name())?;
            *out.get_mut(pos)
                .ok_or_else(|| corrupt_name(CorruptDetail::OffsetOutOfRange))? = len;
            pos += 1;
            let dst = out
                .get_mut(pos..pos + label.len())
                .ok_or_else(|| corrupt_name(CorruptDetail::OffsetOutOfRange))?;
            dst.copy_from_slice(label);
            pos += label.len();
        }
        *out.get_mut(pos)
            .ok_or_else(|| corrupt_name(CorruptDetail::OffsetOutOfRange))? = 0;
        Ok(pos + 1)
    }
}

impl std::hash::Hash for NameRle {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_rle().hash(state);
    }
}

impl fmt::Debug for NameRle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NameRle({self})")
    }
}

impl fmt::Display for NameRle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for label in self.labels_rev() {
            if !first {
                f.write_str(".")?;
            }
            first = false;
            for &byte in label {
                if byte.is_ascii_graphic() && byte != b'\\' && byte != b'.' {
                    f.write_str(&char::from(byte).to_string())?;
                } else {
                    write!(f, "\\{byte:03}")?;
                }
            }
        }
        Ok(())
    }
}

/// Итератор меток в порядке хранения (TLD → owner).
#[derive(Debug, Clone)]
pub struct Labels<'a> {
    rle: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let label_len = usize::from(*self.rle.get(self.offset)?);
        if label_len == 0 {
            return None;
        }
        let start = self.offset + 1;
        let end = start + label_len;
        let label = self.rle.get(start..end)?;
        self.offset = end;
        Some(label)
    }
}

/// Итератор меток в порядке owner → TLD.
#[derive(Debug, Clone)]
pub struct LabelsRev<'a> {
    rle: &'a [u8],
    starts: [usize; LABELS_MAX],
    lens: [u8; LABELS_MAX],
    count: usize,
    next: usize,
}

impl<'a> LabelsRev<'a> {
    fn new(rle: &'a [u8]) -> Self {
        let mut starts = [0_usize; LABELS_MAX];
        let mut lens = [0_u8; LABELS_MAX];
        let mut offset = 0_usize;
        let mut count = 0_usize;
        while count < LABELS_MAX {
            let Some(&label_len) = rle.get(offset) else {
                break;
            };
            if label_len == 0 {
                break;
            }
            let Some(slot) = starts.get_mut(count) else {
                break;
            };
            *slot = offset + 1;
            if let Some(len_slot) = lens.get_mut(count) {
                *len_slot = label_len;
            }
            count += 1;
            offset += 1 + usize::from(label_len);
        }
        Self {
            rle,
            starts,
            lens,
            count,
            next: count,
        }
    }
}

impl<'a> Iterator for LabelsRev<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == 0 {
            return None;
        }
        self.next -= 1;
        let start = *self.starts.get(self.next)?;
        let len = usize::from(*self.lens.get(self.next)?);
        self.rle.get(start..start + len)
    }
}

impl DoubleEndedIterator for LabelsRev<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.next >= self.count {
            return None;
        }
        let start = *self.starts.get(self.next)?;
        let len = usize::from(*self.lens.get(self.next)?);
        self.next += 1;
        self.rle.get(start..start + len)
    }
}

/// Канонический компаратор имён (RFC 4034 §6.1, §8.3).
///
/// Сравнивает метки как беззнаковые байты; если метки равны, более короткое
/// имя (предок) меньше. `*` и `_` — обычные октеты.
///
/// # Errors
///
/// `Corrupt(BadName)` — любое из имён не является валидным lowercase RLE.
pub fn name_cmp(a: &[u8], b: &[u8]) -> Result<Ordering, ZoneFileError> {
    validate_name_rle(a, true)?;
    validate_name_rle(b, true)?;
    Ok(cmp_rle(a, b))
}

fn cmp_rle(a: &[u8], b: &[u8]) -> Ordering {
    let mut ai = 0_usize;
    let mut bi = 0_usize;
    loop {
        let a_len = a.get(ai).copied().unwrap_or(0);
        let b_len = b.get(bi).copied().unwrap_or(0);
        match (a_len, b_len) {
            (0, 0) => return Ordering::Equal,
            (0, _) => return Ordering::Less,
            (_, 0) => return Ordering::Greater,
            _ => {}
        }
        let a_len = usize::from(a_len);
        let b_len = usize::from(b_len);
        let a_start = ai + 1;
        let b_start = bi + 1;
        let common = a_len.min(b_len);
        for offset in 0..common {
            let left = a.get(a_start + offset).copied().unwrap_or(0);
            let right = b.get(b_start + offset).copied().unwrap_or(0);
            if left != right {
                return left.cmp(&right);
            }
        }
        if a_len != b_len {
            return a_len.cmp(&b_len);
        }
        ai = a_start + a_len;
        bi = b_start + b_len;
    }
}

/// Сравнивает полные ключи записи.
///
/// Имена сравниваются канонически, затем `type`, `class`, `subtype` как
/// беззнаковые `u16`. Функция валидирует оба ключа.
///
/// # Errors
///
/// `Corrupt(BadName)` / `Corrupt(Bounds)` — ключ не является
/// `RLE(name) || u16 || u16 || u16` с валидным lowercase-именем.
pub fn compare_keys(a: &[u8], b: &[u8]) -> Result<Ordering, ZoneFileError> {
    let (a_name, a_tail) = split_key(a)?;
    let (b_name, b_tail) = split_key(b)?;
    let name_order = cmp_rle(a_name, b_name);
    if name_order != Ordering::Equal {
        return Ok(name_order);
    }
    for index in 0..3_usize {
        let a_value = wire::read_u16(a_tail, index * 2).ok_or_else(corrupt_key_bounds)?;
        let b_value = wire::read_u16(b_tail, index * 2).ok_or_else(corrupt_key_bounds)?;
        match a_value.cmp(&b_value) {
            Ordering::Equal => {}
            other => return Ok(other),
        }
    }
    Ok(Ordering::Equal)
}

fn corrupt_key_bounds() -> ZoneFileError {
    ZoneFileError::corrupt(CorruptKind::Bounds, None, CorruptDetail::OffsetOutOfRange)
}

fn split_key(bytes: &[u8]) -> Result<(&[u8], &[u8]), ZoneFileError> {
    let name_len = rle_len(bytes)?;
    let total = name_len
        .checked_add(KEY_TAIL_SIZE)
        .ok_or_else(corrupt_key_bounds)?;
    if total != bytes.len() {
        return Err(corrupt_key_bounds());
    }
    let name = bytes.get(..name_len).ok_or_else(corrupt_key_bounds)?;
    validate_name_rle(name, true)?;
    let tail = bytes.get(name_len..).ok_or_else(corrupt_key_bounds)?;
    Ok((name, tail))
}

/// Длина имени в уже валидированном ключе (без проверок).
pub(crate) fn name_len_unchecked(bytes: &[u8]) -> usize {
    let mut offset = 0_usize;
    loop {
        match bytes.get(offset).copied().unwrap_or(0) {
            0 => return offset + 1,
            length => offset += 1 + usize::from(length),
        }
    }
}

/// Сравнивает сырые байты провалидированного ключа с [`Key`] без копирования,
/// используя заранее известную длину имени кандидата.
pub(crate) fn compare_raw_to_key_len(
    candidate: &[u8],
    candidate_name_len: usize,
    target: &Key,
) -> Ordering {
    compare_raw_keys(
        candidate,
        candidate_name_len,
        target.as_bytes(),
        usize::from(target.name_len),
    )
}

/// Сравнивает два уже провалидированных RLE-имени без повторной проверки.
pub(crate) fn name_cmp_validated(left: &[u8], right: &[u8]) -> Ordering {
    cmp_rle(left, right)
}

/// Сравнивает два провалидированных ключа, заданных байтами и длиной имени.
///
/// Не копирует ключи и не валидирует RLE повторно: обе стороны уже прошли
/// проверку страницы/входа. Порядок совпадает с [`compare_keys`].
pub(crate) fn compare_raw_keys(
    left: &[u8],
    left_name_len: usize,
    right: &[u8],
    right_name_len: usize,
) -> Ordering {
    let name_order = cmp_rle(
        left.get(..left_name_len).unwrap_or(&[]),
        right.get(..right_name_len).unwrap_or(&[]),
    );
    if name_order != Ordering::Equal {
        return name_order;
    }
    for index in 0..3_usize {
        let left_value = wire::read_u16(left, left_name_len + index * 2).unwrap_or(0);
        let right_value = wire::read_u16(right, right_name_len + index * 2).unwrap_or(0);
        match left_value.cmp(&right_value) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// Имя из провалидированных байтов ключа без материализации [`Key`].
pub(crate) fn owner_from_raw(bytes: &[u8], name_len: usize) -> Option<NameRle> {
    NameRle::from_validated(bytes.get(..name_len)?)
}

/// Длина байтово-сравнимого префикса ключа ([`OrderKey`]).
///
/// 32 байта покрывают имя до ~12 байт RLE (`com.` + `example.`) вместе с
/// хвостом `type/class/subtype`. Для более длинных имён хвост префикса
/// сравнивается полностью ([`compare_raw_keys`]).
pub(crate) const ORDER_KEY_BYTES: usize = 32;

/// Байтово-сравнимый префикс ключа для `memcmp`-поиска.
///
/// Кодирование сохраняет канонический порядок [`compare_keys`] для первых
/// [`ORDER_KEY_BYTES`] байт:
///
/// * метки идут в порядке хранения (TLD → owner);
/// * содержимое метки кодируется как есть, байт `0x00` экранируется в
///   `0x00 0xFF` (экранирование сохраняет порядок), после метки — `0x00`;
/// * после последней метки — ещё один `0x00` (терминатор имени), поэтому
///   предок всегда меньше потомка;
/// * затем `type`, `class`, `subtype` как big-endian `u16`;
/// * короткий ключ добивается нулями.
///
/// Равенство префиксов **не** означает равенства ключей: в этом случае
/// вызывающий обязан сравнить ключи полностью. Префикс — производная в
/// памяти, на диске его нет.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) struct OrderKey {
    bytes: [u8; ORDER_KEY_BYTES],
}

impl std::fmt::Debug for OrderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OrderKey({:02x?})", self.bytes)
    }
}

impl OrderKey {
    /// Префикс провалидированного [`Key`].
    #[must_use]
    pub(crate) fn of_key(key: &Key) -> Self {
        Self::from_validated(key.as_bytes(), key.owner_len())
    }

    /// Префикс провалидированного ключа `RLE(name) || u16 || u16 || u16`.
    #[must_use]
    pub(crate) fn from_validated(bytes: &[u8], name_len: usize) -> Self {
        let mut out = [0_u8; ORDER_KEY_BYTES];
        let mut written = 0_usize;
        let mut offset = 0_usize;
        while written < ORDER_KEY_BYTES {
            let Some(&label_len) = bytes.get(offset) else {
                break;
            };
            offset += 1;
            if label_len == 0 {
                push_order_byte(&mut out, &mut written, 0);
                break;
            }
            let end = offset.saturating_add(usize::from(label_len));
            let Some(label) = bytes.get(offset..end) else {
                break;
            };
            offset = end;
            for &byte in label {
                if written >= ORDER_KEY_BYTES {
                    break;
                }
                if byte == 0 {
                    push_order_byte(&mut out, &mut written, 0);
                    push_order_byte(&mut out, &mut written, 0xFF);
                } else {
                    push_order_byte(&mut out, &mut written, byte);
                }
            }
            push_order_byte(&mut out, &mut written, 0);
        }
        if written < ORDER_KEY_BYTES && name_len <= bytes.len() {
            for index in 0..3_usize {
                let value = wire::read_u16(bytes, name_len + index * 2).unwrap_or(0);
                for byte in value.to_be_bytes() {
                    push_order_byte(&mut out, &mut written, byte);
                }
            }
        }
        Self { bytes: out }
    }

    /// Порядок префиксов (`memcmp`).
    #[must_use]
    pub(crate) fn cmp(&self, other: &Self) -> Ordering {
        let left = be_u64::<0>(&self.bytes);
        let right = be_u64::<0>(&other.bytes);
        if left != right {
            return left.cmp(&right);
        }
        let left = be_u64::<8>(&self.bytes);
        let right = be_u64::<8>(&other.bytes);
        if left != right {
            return left.cmp(&right);
        }
        let left = be_u64::<16>(&self.bytes);
        let right = be_u64::<16>(&other.bytes);
        if left != right {
            return left.cmp(&right);
        }
        be_u64::<24>(&self.bytes).cmp(&be_u64::<24>(&other.bytes))
    }
}

fn push_order_byte(out: &mut [u8; ORDER_KEY_BYTES], written: &mut usize, byte: u8) {
    if let Some(slot) = out.get_mut(*written) {
        *slot = byte;
        *written += 1;
    }
}

fn be_u64<const OFFSET: usize>(bytes: &[u8; ORDER_KEY_BYTES]) -> u64 {
    u64::from_be_bytes([
        bytes.get(OFFSET).copied().unwrap_or(0),
        bytes.get(OFFSET + 1).copied().unwrap_or(0),
        bytes.get(OFFSET + 2).copied().unwrap_or(0),
        bytes.get(OFFSET + 3).copied().unwrap_or(0),
        bytes.get(OFFSET + 4).copied().unwrap_or(0),
        bytes.get(OFFSET + 5).copied().unwrap_or(0),
        bytes.get(OFFSET + 6).copied().unwrap_or(0),
        bytes.get(OFFSET + 7).copied().unwrap_or(0),
    ])
}

/// Сравнивает два уже валидированных ключа без повторной RLE-проверки.
pub(crate) fn compare_validated(left: &Key, right: &Key) -> Ordering {
    let name_order = cmp_rle(left.owner_bytes(), right.owner_bytes());
    if name_order != Ordering::Equal {
        return name_order;
    }
    for index in 0..3_usize {
        let left_value =
            wire::read_u16(left.as_bytes(), usize::from(left.name_len) + index * 2).unwrap_or(0);
        let right_value =
            wire::read_u16(right.as_bytes(), usize::from(right.name_len) + index * 2).unwrap_or(0);
        match left_value.cmp(&right_value) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

/// Частичный компаратор: `prefix` — полная последовательность меток без
/// терминатора, `name` — валидное RLE-имя.
///
/// Возвращает порядок `prefix` относительно `name` в каноническом порядке
/// имён. Используется предикатом `has_children` (§13.3).
///
/// # Errors
///
/// `Corrupt(BadName)` — `name` не является валидным RLE-именем.
pub fn prefix_cmp(prefix: &[u8], name: &[u8]) -> Result<Ordering, ZoneFileError> {
    validate_name_rle(name, true)?;
    Ok(cmp_prefix(prefix, name))
}

fn cmp_prefix(prefix: &[u8], name: &[u8]) -> Ordering {
    let mut pi = 0_usize;
    let mut ni = 0_usize;
    loop {
        let Some(&p_len) = prefix.get(pi) else {
            // Префикс исчерпан на границе метки: имя-владелец меньше префикса,
            // потомок — больше (см. §13.3: `p || 0x01`).
            return match name.get(ni) {
                Some(0) | None => Ordering::Greater,
                Some(_) => Ordering::Less,
            };
        };
        let n_len = name.get(ni).copied().unwrap_or(0);
        if n_len == 0 {
            // Имя закончилось раньше префикса: имя — предок префикса.
            return Ordering::Greater;
        }
        let p_label = prefix
            .get(pi + 1..pi + 1 + usize::from(p_len))
            .unwrap_or(&[]);
        let n_label = name.get(ni + 1..ni + 1 + usize::from(n_len)).unwrap_or(&[]);
        let content = p_label.cmp(n_label);
        if content != Ordering::Equal {
            return content;
        }
        pi += 1 + usize::from(p_len);
        ni += 1 + usize::from(n_len);
    }
}

/// Составной ключ записи фиксированного размера.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    buf: [u8; KEY_MAX],
    len: u16,
    name_len: u16,
}

impl Key {
    /// Строит ключ `RLE(name) || type || class || subtype`.
    ///
    /// # Errors
    ///
    /// `NameTooLong` — ключ превышает [`MAX_KEY_SIZE`](crate::consts::MAX_KEY_SIZE).
    pub fn new(
        name: &NameRle,
        rr_type: u16,
        class: u16,
        subtype: u16,
    ) -> Result<Self, ZoneFileError> {
        let name_len = name.len();
        let total = name_len
            .checked_add(KEY_TAIL_SIZE)
            .filter(|&total| total <= KEY_MAX)
            .ok_or(ZoneFileError::NameTooLong)?;
        let mut buf = [0_u8; KEY_MAX];
        let prefix = name.as_rle();
        buf.get_mut(..name_len)
            .ok_or(ZoneFileError::NameTooLong)?
            .copy_from_slice(prefix);
        let tail = buf
            .get_mut(name_len..total)
            .ok_or(ZoneFileError::NameTooLong)?;
        tail.get_mut(..2)
            .ok_or(ZoneFileError::NameTooLong)?
            .copy_from_slice(&rr_type.to_le_bytes());
        tail.get_mut(2..4)
            .ok_or(ZoneFileError::NameTooLong)?
            .copy_from_slice(&class.to_le_bytes());
        tail.get_mut(4..6)
            .ok_or(ZoneFileError::NameTooLong)?
            .copy_from_slice(&subtype.to_le_bytes());
        Ok(Self {
            buf,
            len: u16::try_from(total).map_err(|_| ZoneFileError::NameTooLong)?,
            name_len: u16::try_from(name_len).map_err(|_| ZoneFileError::NameTooLong)?,
        })
    }

    /// Разбирает и валидирует ключ из байтов.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadName)` / `Corrupt(Bounds)` — невалидный ключ.
    pub fn parse(bytes: &[u8]) -> Result<Self, ZoneFileError> {
        let (name, _) = split_key(bytes)?;
        let name_len = name.len();
        let mut buf = [0_u8; KEY_MAX];
        buf.get_mut(..bytes.len())
            .ok_or_else(corrupt_key_bounds)?
            .copy_from_slice(bytes);
        Ok(Self {
            buf,
            len: u16::try_from(bytes.len()).map_err(|_| corrupt_key_bounds())?,
            name_len: u16::try_from(name_len).map_err(|_| corrupt_key_bounds())?,
        })
    }

    /// Создаёт ключ из уже провалидированных байтов без повторной проверки.
    pub(crate) fn from_validated(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > KEY_MAX {
            return None;
        }
        let name_len = name_len_unchecked(bytes);
        if name_len + KEY_TAIL_SIZE != bytes.len() {
            return None;
        }
        let mut buf = [0_u8; KEY_MAX];
        buf.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Self {
            buf,
            len: u16::try_from(bytes.len()).ok()?,
            name_len: u16::try_from(name_len).ok()?,
        })
    }

    /// Пустой ключ-заглушка для «первого ключа нет» в пути записи.
    ///
    /// Нулевая длина: сравнения с ним в горячем поиске не используются.
    pub(crate) const fn placeholder() -> Self {
        Self {
            buf: [0_u8; KEY_MAX],
            len: 0,
            name_len: 0,
        }
    }

    /// Длина ключа в байтах.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Всегда `false`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Байты ключа.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Байты RLE-имени с терминатором.
    #[must_use]
    pub fn owner_bytes(&self) -> &[u8] {
        self.buf.get(..usize::from(self.name_len)).unwrap_or(&[])
    }

    /// Длина RLE-имени с терминатором.
    #[must_use]
    pub const fn owner_len(&self) -> usize {
        self.name_len as usize
    }

    /// Имя-владелец.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadName)` — имя в ключе невалидно (недостижимо для ключа,
    /// созданного через [`Key::new`]/[`Key::parse`]).
    pub fn owner(&self) -> Result<NameRle, ZoneFileError> {
        NameRle::parse(self.owner_bytes())
    }

    /// Тип записи.
    #[must_use]
    pub fn rr_type(&self) -> u16 {
        wire::read_u16(self.as_bytes(), usize::from(self.name_len)).unwrap_or(0)
    }

    /// Класс записи.
    #[must_use]
    pub fn class(&self) -> u16 {
        wire::read_u16(self.as_bytes(), usize::from(self.name_len) + 2).unwrap_or(0)
    }

    /// `subtype` (covered type для `RRSIG`).
    #[must_use]
    pub fn subtype(&self) -> u16 {
        wire::read_u16(self.as_bytes(), usize::from(self.name_len) + 4).unwrap_or(0)
    }

    /// Ключ с другим `subtype` (например, для обхода `RRSIG`).
    ///
    /// # Errors
    ///
    /// `NameTooLong` — недостижимо, длина не меняется.
    pub fn with_subtype(&self, subtype: u16) -> Result<Self, ZoneFileError> {
        let mut buf = self.buf;
        buf.get_mut(usize::from(self.name_len) + 4..usize::from(self.len))
            .ok_or(ZoneFileError::NameTooLong)?
            .copy_from_slice(&subtype.to_le_bytes());
        Ok(Self {
            buf,
            len: self.len,
            name_len: self.name_len,
        })
    }

    /// Канонический порядок ключей.
    ///
    /// Оба ключа уже валидны по построению, поэтому повторная RLE-валидация
    /// не выполняется.
    #[must_use]
    pub fn compare(&self, other: &Self) -> Ordering {
        compare_validated(self, other)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("name", &self.owner_bytes())
            .field("type", &self.rr_type())
            .field("class", &self.class())
            .field("subtype", &self.subtype())
            .finish()
    }
}

/// Ключ каталога зон: `RLE(apex) || T_ZONE_ENTRY || 0 || 0` (§9, §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ZoneEntryKey(Key);

impl ZoneEntryKey {
    /// Строит ключ каталога для apex.
    ///
    /// # Errors
    ///
    /// `NameTooLong` — apex длиннее лимита ключа.
    pub fn new(apex: &NameRle) -> Result<Self, ZoneFileError> {
        Ok(Self(Key::new(apex, T_ZONE_ENTRY, 0, 0)?))
    }

    /// Разбирает ключ каталога и проверяет тип/класс/subtype.
    ///
    /// # Errors
    ///
    /// `Corrupt(Bounds)` — ключ не является ключом каталога.
    pub fn parse(bytes: &[u8]) -> Result<Self, ZoneFileError> {
        let key = Key::parse(bytes)?;
        if key.rr_type() != T_ZONE_ENTRY || key.class() != 0 || key.subtype() != 0 {
            return Err(corrupt_key_bounds());
        }
        Ok(Self(key))
    }

    /// Внутренний ключ.
    #[must_use]
    pub const fn key(&self) -> &Key {
        &self.0
    }

    /// Apex зоны.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadName)` — недостижимо для валидного ключа.
    pub fn apex(&self) -> Result<NameRle, ZoneFileError> {
        self.0.owner()
    }
}

/// Предикат `has_children` (§13.3): проба `lower_bound(p || 0x01)`.
///
/// `p` — `RLE(name)` без терминатора. [`ChildrenProbe::compare_key`] даёт порядок
/// пробы относительно ключа, [`ChildrenProbe::matches`] проверяет, что
/// найденный ключ — потомок.
#[derive(Clone)]
pub struct ChildrenProbe {
    prefix: NameRle,
    prefix_len: usize,
    needle: [u8; NAME_MAX + 1],
    needle_len: usize,
}

impl ChildrenProbe {
    /// Готовит пробу для имени.
    #[must_use]
    pub fn new(name: &NameRle) -> Self {
        let prefix = *name;
        let prefix_len = name.without_terminal().len();
        let mut needle = [0_u8; NAME_MAX + 1];
        let mut needle_len = 0_usize;
        if let Some(dst) = needle.get_mut(..prefix_len) {
            dst.copy_from_slice(name.without_terminal());
            needle_len = prefix_len;
        }
        if let Some(slot) = needle.get_mut(needle_len) {
            *slot = 0x01;
            needle_len += 1;
        }
        Self {
            prefix,
            prefix_len,
            needle,
            needle_len,
        }
    }

    /// Имя, для которого построена проба.
    #[must_use]
    pub const fn name(&self) -> &NameRle {
        &self.prefix
    }

    /// Ключ-проба `p || 0x01`.
    #[must_use]
    pub fn needle(&self) -> &[u8] {
        self.needle.get(..self.needle_len).unwrap_or(&[])
    }

    /// Порядок ключа относительно пробы (для `lower_bound`).
    ///
    /// # Errors
    ///
    /// `Corrupt(BadName)` — префикс не является валидной последовательностью
    /// меток (недостижимо: построен из валидного имени).
    pub fn compare_key(&self, key: &Key) -> Result<Ordering, ZoneFileError> {
        let owner = key.owner_bytes();
        if owner.starts_with(self.prefix.without_terminal()) {
            // Владелец имеет здесь 0x00 и меньше пробы; потомок — больше.
            return Ok(match owner.get(self.prefix_len) {
                Some(0) | None => Ordering::Less,
                Some(_) => Ordering::Greater,
            });
        }
        prefix_cmp(self.prefix.without_terminal(), owner).map(Ordering::reverse)
    }

    /// Проверяет, что ключ — потомок имени.
    ///
    /// # Errors
    ///
    /// `Corrupt(BadName)` — недостижимо для валидного ключа.
    pub fn matches(&self, key: &Key) -> Result<bool, ZoneFileError> {
        let owner = key.owner_bytes();
        if !owner.starts_with(self.prefix.without_terminal()) {
            return Ok(false);
        }
        Ok(matches!(
            owner.get(self.prefix_len),
            Some(&byte) if (1..=63).contains(&byte)
        ))
    }
}

impl fmt::Debug for ChildrenProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChildrenProbe")
            .field("name", &self.prefix)
            .field("needle_len", &self.needle_len)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn random_name() -> impl Strategy<Value = NameRle> {
        let label = prop::collection::vec(
            prop::sample::select(vec![0x00_u8, 0x01, 0x2A, 0x41, 0x5F, 0x61, 0x7A, 0xFF]),
            1..=6,
        );
        prop::collection::vec(label, 1..=4).prop_map(|labels| {
            let mut bytes = Vec::new();
            for label in &labels {
                bytes.push(u8::try_from(label.len()).unwrap());
                bytes.extend_from_slice(label);
            }
            bytes.push(0);
            NameRle::normalize(&bytes).unwrap()
        })
    }

    fn random_key() -> impl Strategy<Value = Key> {
        (random_name(), any::<u16>(), any::<u16>(), any::<u16>()).prop_map(
            |(name, rr_type, class, subtype)| Key::new(&name, rr_type, class, subtype).unwrap(),
        )
    }

    proptest! {
        /// Если префиксы различаются, их порядок обязан совпадать с полным
        /// компаратором; при длинных именах допустимо равенство префиксов,
        /// но не инверсия.
        #[test]
        fn order_key_is_monotone_against_full_comparator(
            left in random_key(),
            right in random_key(),
        ) {
            let full = compare_validated(&left, &right);
            let prefix = OrderKey::of_key(&left).cmp(&OrderKey::of_key(&right));
            prop_assert!(prefix == Ordering::Equal || prefix == full);
        }
    }

    #[test]
    fn rejects_long_and_empty_names() {
        assert!(NameRle::parse(&[0]).is_err());
        assert!(NameRle::parse(&[64]).is_err());
        assert!(NameRle::parse(&[0xC0, 0]).is_err());
        assert!(NameRle::parse(&[1, b'a']).is_err());
        assert!(NameRle::parse(&[1, b'A', 0]).is_err());
        assert!(NameRle::normalize(&[1, b'A', 0]).is_ok());
    }

    fn rle(labels: &[&[u8]]) -> NameRle {
        let mut bytes = Vec::new();
        for label in labels {
            bytes.push(u8::try_from(label.len()).unwrap());
            bytes.extend_from_slice(label);
        }
        bytes.push(0);
        NameRle::parse(&bytes).unwrap()
    }

    /// Если префиксы различаются, их порядок обязан совпадать с полным
    /// компаратором (включая метки с `0x00`, предков и длинные имена).
    #[test]
    fn order_key_matches_full_comparator() {
        let names = [
            rle(&[b"com"]),
            rle(&[b"com", b"example"]),
            rle(&[b"com", b"example", b"www"]),
            rle(&[b"com", b"example", b"a"]),
            rle(&[b"com", b"example", b"ab"]),
            rle(&[b"com", b"example", b"b"]),
            rle(&[b"com", b"example", &[0x00]]),
            rle(&[b"com", b"example", &[0x00, 0x00]]),
            rle(&[b"com", b"example", &[0x00, 0x01]]),
            rle(&[b"com", b"example", &[0x01]]),
            rle(&[b"com", b"example", &[0x00, 0xFF]]),
            rle(&[b"org"]),
            rle(&[
                b"org",
                b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ]),
        ];
        let mut keys = Vec::new();
        for name in &names {
            for rr_type in [T_NODE, 1, 16, 46] {
                for subtype in [0, 1, 24] {
                    keys.push(Key::new(name, rr_type, CLASS_IN, subtype).unwrap());
                    keys.push(Key::new(name, rr_type, 0, subtype).unwrap());
                }
            }
        }
        for left in &keys {
            for right in &keys {
                let full = compare_validated(left, right);
                let prefix = OrderKey::of_key(left).cmp(&OrderKey::of_key(right));
                if prefix != Ordering::Equal {
                    assert_eq!(
                        prefix, full,
                        "префикс разошёлся с полным компаратором: {left:?} vs {right:?}"
                    );
                }
            }
        }
    }
}
