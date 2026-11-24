//! Стабильная текстовая сериализация записей (export / round-trip).

use pulse_dns::{Name, Record, Ttl};

use crate::present::{name_to_text, rdata_to_text};

/// Настройки сериализации.
///
/// По умолчанию выводятся абсолютные имена владельцев, TTL каждой записи и
/// класс `IN`; `$ORIGIN`/`$TTL` не добавляются.
#[derive(Debug, Clone, Default)]
pub struct TextOptions {
    /// Если задан, печатается `$ORIGIN` и владелец apex сокращается до `@`.
    pub origin: Option<Name>,
    /// Если задан, печатается `$TTL`, а совпадающий TTL записей опускается.
    pub default_ttl: Option<Ttl>,
    /// Сортировать записи по `(owner, type, canonical rdata)`.
    pub sort: bool,
}

/// Сериализует записи в стабильный master-текст.
///
/// Повторяющийся подряд владелец опускается и заменяется табуляцией, что
/// соответствует наследованию owner в RFC 1035 §5.1. Имена абсолютные, поэтому
/// результат разбирается без знания `$ORIGIN`.
#[must_use]
pub fn to_text(records: &[Record], options: &TextOptions) -> String {
    let mut out = String::new();
    if let Some(origin) = &options.origin {
        out.push_str("$ORIGIN ");
        out.push_str(&name_to_text(origin));
        out.push('\n');
    }
    if let Some(ttl) = options.default_ttl {
        out.push_str("$TTL ");
        out.push_str(&ttl.to_string());
        out.push('\n');
    }
    if options.origin.is_some() || options.default_ttl.is_some() {
        out.push('\n');
    }

    let mut ordered: Vec<&Record> = records.iter().collect();
    if options.sort {
        ordered.sort_by(|left, right| {
            left.owner()
                .cmp_canonical(right.owner())
                .then_with(|| left.rr_type().as_u16().cmp(&right.rr_type().as_u16()))
                .then_with(|| {
                    left.rdata()
                        .to_canonical_wire()
                        .cmp(&right.rdata().to_canonical_wire())
                })
        });
    }

    let mut previous_owner: Option<&Name> = None;
    for record in ordered {
        let mut fields: Vec<String> = Vec::new();
        if options.default_ttl != Some(record.ttl()) {
            fields.push(record.ttl().to_string());
        }
        fields.push(record.class().to_string());
        fields.push(record.rr_type().to_string());
        fields.push(rdata_to_text(record.rdata()));

        if previous_owner == Some(record.owner()) {
            out.push('\t');
        } else {
            if options.origin.as_ref() == Some(record.owner()) {
                out.push('@');
            } else {
                out.push_str(&name_to_text(record.owner()));
            }
            out.push(' ');
        }
        out.push_str(&fields.join(" "));
        out.push('\n');
        previous_owner = Some(record.owner());
    }
    out
}
