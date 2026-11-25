//! Сборка и валидация DNS-сообщений.
//!
//! Запросы строятся один раз в [`QuerySet`] (рабочий набор на поток); на
//! горячем пути клиент только подменяет ID. Валидация ответа по умолчанию
//! header-only (ID/QR/RCODE) — без аллокаций; каждая N-я выборка проверяется
//! полным `decode` и сверкой вопроса.

use pulse_dns::{DecodeLimits, EncodeOptions, Message, Name, Question, Rclass, Rtype};

use crate::mix::{Class, Mix, Rng};

/// Один заранее собранный запрос.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Wire-байты; ID в первых двух байтах подменяется на лету.
    pub bytes: Vec<u8>,
    /// Класс профиля.
    pub class: Class,
    /// Ожидаемое имя вопроса (для выборочной полной валидации).
    pub name: Name,
    /// Ожидаемый тип вопроса.
    pub qtype: Rtype,
}

/// Рабочий набор пакетов по классам.
#[derive(Debug)]
pub struct QuerySet {
    /// Пакеты по индексу [`Class::index`].
    pub by_class: [Vec<Packet>; 5],
}

impl QuerySet {
    /// Собирает рабочий набор из `working_set` пакетов.
    ///
    /// Имена: `r{record:07}.z{zone}.bench.test.` (тип записи циклится A/AAAA/MX/TXT)
    /// и `nx{n}.z{zone}.bench.test.` для NXDOMAIN. `rrsets_per_zone`
    /// соответствует числу RRset, сгенерированных [`crate::storegen`].
    ///
    /// # Errors
    ///
    /// Ошибка кодирования DNS-сообщения.
    pub fn build(
        zones: u32,
        rrsets_per_zone: u32,
        mix: Mix,
        working_set: usize,
        seed: u64,
    ) -> Result<Self, String> {
        let zones = zones.max(1);
        let rrsets = rrsets_per_zone.max(4);
        let working_set = working_set.max(5);
        let mut rng = Rng::new(seed);
        let mut by_class: [Vec<Packet>; 5] = std::array::from_fn(|_| Vec::new());
        for index in 0..working_set {
            let class = mix.pick(u64::from(u32::try_from(index).unwrap_or(u32::MAX)));
            let zone = rng.below(u64::from(zones));
            let packet = if class == Class::Nx {
                let name = format!("nx{}.z{zone}.bench.test.", rng.below(u64::from(rrsets)));
                build_packet(class, &name, Rtype::A)?
            } else {
                let (qtype, type_index) = match class {
                    Class::A => (Rtype::A, 0_u64),
                    Class::Aaaa => (Rtype::AAAA, 1),
                    Class::Mx => (Rtype::MX, 2),
                    Class::Txt => (Rtype::TXT, 3),
                    Class::Nx => unreachable!(),
                };
                let per_type = u64::from(rrsets) / 4;
                let record = rng.below(per_type.max(1)) * 4 + type_index;
                let record = record.min(u64::from(rrsets) - 1);
                let name = format!("r{record:07}.z{zone}.bench.test.");
                build_packet(class, &name, qtype)?
            };
            by_class[class.index()].push(packet);
        }
        Ok(Self { by_class })
    }

    /// Суммарное число пакетов.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_class.iter().map(Vec::len).sum()
    }

    /// Пуст ли набор.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn build_packet(class: Class, name: &str, qtype: Rtype) -> Result<Packet, String> {
    let name = Name::parse(name).map_err(|error| format!("query name {name:?}: {error}"))?;
    let message = Message::query(0, Question::new(name.clone(), qtype, Rclass::IN))
        .encode(&EncodeOptions::compressed())
        .map_err(|error| format!("encode query: {error}"))?;
    Ok(Packet {
        bytes: message,
        class,
        name,
        qtype,
    })
}

/// Подменяет ID в wire-запросе.
#[inline]
pub fn set_id(bytes: &mut [u8], id: u16) {
    if let [high, low, ..] = bytes {
        let [id_high, id_low] = id.to_be_bytes();
        *high = id_high;
        *low = id_low;
    }
}

/// Быстрая проверка ответа без декодирования.
///
/// Проверяет длину, ID, `QR=1`, отсутствие `TC` и ожидаемый RCODE.
///
/// # Errors
///
/// Строка с причиной отказа.
#[inline]
pub fn validate_header(
    bytes: &[u8],
    expected_id: u16,
    expected_rcode: u16,
) -> Result<(), &'static str> {
    if bytes.len() < 12 {
        return Err("short");
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    if id != expected_id {
        return Err("id");
    }
    if bytes[2] & 0x80 == 0 {
        return Err("not-response");
    }
    if bytes[2] & 0x02 != 0 {
        return Err("truncated");
    }
    if u16::from(bytes[3] & 0x0f) != expected_rcode {
        return Err("rcode");
    }
    Ok(())
}

/// Полная проверка: `decode`, сверка вопроса и RCODE.
///
/// Дороже header-only (аллокации), поэтому вызывается для каждой N-й выборки.
///
/// # Errors
///
/// Строка с причиной отказа.
pub fn validate_full(
    bytes: &[u8],
    expected_id: u16,
    expected_name: &Name,
    expected_type: Rtype,
    expected_rcode: u16,
) -> Result<(), String> {
    let message = Message::decode(bytes, &DecodeLimits::default())
        .map_err(|error| format!("decode: {error}"))?;
    if message.id() != expected_id {
        return Err("id".to_owned());
    }
    if message.rcode().as_u16() != expected_rcode {
        return Err(format!("rcode {}", message.rcode().as_u16()));
    }
    let question = message
        .questions()
        .first()
        .ok_or_else(|| "missing question".to_owned())?;
    if question.qname() != expected_name || question.qtype() != expected_type {
        return Err("question mismatch".to_owned());
    }
    Ok(())
}

/// Проверка «ответ на запрос» для DoH: decode + сверка ID.
///
/// # Errors
///
/// Строка с причиной отказа.
pub fn validate_any_response(
    bytes: &[u8],
    expected_id: u16,
    expected_rcode: u16,
) -> Result<(), String> {
    validate_header(bytes, expected_id, expected_rcode).map_err(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_set_is_deterministic() {
        let left = QuerySet::build(2, 40, Mix::default(), 200, 7).expect("set");
        let right = QuerySet::build(2, 40, Mix::default(), 200, 7).expect("set");
        assert_eq!(left.len(), 200);
        for (left, right) in left.by_class.iter().zip(right.by_class.iter()) {
            assert_eq!(left.len(), right.len());
            for (left, right) in left.iter().zip(right.iter()) {
                assert_eq!(left.bytes, right.bytes);
            }
        }
    }

    #[test]
    fn header_validation_rejects_garbage() {
        let mut bytes = vec![0_u8; 12];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[2] = 0x80;
        assert!(validate_header(&bytes, 0x1234, 0).is_ok());
        assert!(validate_header(&bytes, 0x9999, 0).is_err());
        bytes[2] = 0;
        assert!(validate_header(&bytes, 0x1234, 0).is_err());
        bytes[2] = 0x80;
        bytes[3] = 3;
        assert!(validate_header(&bytes, 0x1234, 3).is_ok());
        assert!(validate_header(&bytes, 0x1234, 0).is_err());
        assert!(validate_header(&bytes[..5], 0x1234, 3).is_err());
    }

    #[test]
    fn id_is_patched_in_place() {
        let mut bytes = vec![0_u8; 12];
        set_id(&mut bytes, 0xabcd);
        assert_eq!(&bytes[..2], &[0xab, 0xcd]);
    }
}
