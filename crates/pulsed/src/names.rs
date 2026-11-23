//! Квалификация имён относительно origin зоны.

use pulse_dns::Name;

/// Преобразует имя из конфигурации в абсолютное каноническое имя.
///
/// `@` и пустая строка означают apex. Имя с завершающей точкой считается
/// абсолютным, иначе добавляется суффикс `origin` (zone-file семантика).
pub(crate) fn qualify(text: &str, origin: &Name) -> Result<Name, String> {
    let text = text.trim();
    if text == "@" {
        return Ok(origin.clone());
    }
    if text.is_empty() {
        return Err("name must not be empty (use \"@\" for the zone apex)".to_owned());
    }
    if text.ends_with('.') {
        return Name::parse(text)
            .map_err(|error| format!("invalid absolute name {text:?}: {error}"));
    }
    let absolute = if origin.label_count() == 0 {
        format!("{text}.")
    } else {
        format!("{text}.{origin}")
    };
    Name::parse(&absolute).map_err(|error| {
        format!("invalid relative name {text:?} (qualified as {absolute}): {error}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Name {
        Name::parse("example.com.").unwrap()
    }

    #[test]
    fn apex_and_relative_names() {
        assert_eq!(qualify("@", &origin()).unwrap(), origin());
        assert_eq!(
            qualify("www", &origin()).unwrap(),
            Name::parse("www.example.com.").unwrap()
        );
        assert_eq!(
            qualify("www.example.com.", &origin()).unwrap(),
            Name::parse("www.example.com.").unwrap()
        );
    }

    #[test]
    fn root_zone_relative_name() {
        let root = Name::root();
        assert_eq!(qualify("com", &root).unwrap(), Name::parse("com.").unwrap());
    }

    #[test]
    fn empty_name_is_rejected() {
        assert!(qualify("", &origin()).is_err());
    }
}
