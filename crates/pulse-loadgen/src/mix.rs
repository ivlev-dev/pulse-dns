//! Профиль запросов: A/AAAA/MX/TXT/NXDOMAIN с детерминированным выбором.
//!
//! Клиент строит рабочий набор пакетов заранее (см. [`crate::wire::QuerySet`]),
//! поэтому на горячем пути нет ни `format!`, ни аллокаций под имя — только
//! подмена ID в первых двух байтах.

use std::fmt;

/// Класс запроса.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// Существующее имя, тип A.
    A,
    /// Существующее имя, тип AAAA.
    Aaaa,
    /// Существующее имя, тип MX.
    Mx,
    /// Существующее имя, тип TXT.
    Txt,
    /// Несуществующее имя (NXDOMAIN).
    Nx,
}

impl Class {
    /// Все классы в порядке индексов.
    pub const ALL: [Self; 5] = [Self::A, Self::Aaaa, Self::Mx, Self::Txt, Self::Nx];

    /// Индекс в массивах профиля.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::Aaaa => 1,
            Self::Mx => 2,
            Self::Txt => 3,
            Self::Nx => 4,
        }
    }

    /// Имя для отчёта.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Nx => "NXDOMAIN",
        }
    }

    /// Ожидаемый RCODE (младшие 4 бита): 0 для hit, 3 для NXDOMAIN.
    #[must_use]
    pub const fn expected_rcode(self) -> u16 {
        match self {
            Self::Nx => 3,
            _ => 0,
        }
    }
}

/// Взвешенный профиль.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mix {
    weights: [u32; 5],
}

impl Default for Mix {
    fn default() -> Self {
        Self {
            weights: [40, 20, 15, 10, 15],
        }
    }
}

impl Mix {
    /// Разбирает `a=40,aaaa=20,mx=15,txt=10,nx=15`.
    ///
    /// # Errors
    ///
    /// Неизвестный класс, нечисловой вес или все веса нулевые.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut weights = [0_u32; 5];
        for part in spec.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (name, value) = part
                .split_once('=')
                .ok_or_else(|| format!("mix: expected key=weight, got {part:?}"))?;
            let class = match name.trim().to_ascii_lowercase().as_str() {
                "a" => Class::A,
                "aaaa" => Class::Aaaa,
                "mx" => Class::Mx,
                "txt" => Class::Txt,
                "nx" | "nxdomain" => Class::Nx,
                other => return Err(format!("mix: unknown class {other:?}")),
            };
            let weight: u32 = value
                .trim()
                .parse()
                .map_err(|_| format!("mix: bad weight {value:?}"))?;
            weights[class.index()] = weight;
        }
        if weights.iter().all(|&weight| weight == 0) {
            return Err("mix: total weight is zero".to_owned());
        }
        Ok(Self { weights })
    }

    /// Вес класса.
    #[must_use]
    pub const fn weight(self, class: Class) -> u32 {
        self.weights[class.index()]
    }

    /// Суммарный вес.
    #[must_use]
    pub fn total(self) -> u64 {
        self.weights.iter().map(|&weight| u64::from(weight)).sum()
    }

    /// Выбирает класс по детерминированному числу `draw` (`0..total`).
    #[must_use]
    pub fn pick(self, draw: u64) -> Class {
        let mut remaining = draw % self.total().max(1);
        for class in Class::ALL {
            let weight = u64::from(self.weight(class));
            if remaining < weight {
                return class;
            }
            remaining -= weight;
        }
        Class::A
    }
}

impl fmt::Display for Mix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, class) in Class::ALL.into_iter().enumerate() {
            if index > 0 {
                formatter.write_str(",")?;
            }
            write!(
                formatter,
                "{}={}",
                class.as_str().to_ascii_lowercase(),
                self.weight(class)
            )?;
        }
        Ok(())
    }
}

/// Детерминированный xorshift64* (не криптография; нужен воспроизводимый
/// поток запросов).
#[derive(Debug, Clone, Copy)]
pub struct Rng(u64);

impl Rng {
    /// Создаёт генератор с ненулевым seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9e37_79b9_7f4a_7c15
        } else {
            seed
        })
    }

    /// Следующее 64-битное значение.
    #[must_use]
    pub fn next_u64(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        self.0 = value;
        value.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Значение в `0..bound` (bound > 0).
    #[must_use]
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound <= 1 {
            0
        } else {
            self.next_u64() % bound
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_mix_is_well_formed() {
        let mix = Mix::default();
        assert_eq!(mix.total(), 100);
        assert_eq!(mix.weight(Class::A), 40);
        assert_eq!(mix.weight(Class::Nx), 15);
    }

    #[test]
    fn parse_custom_mix() {
        let mix = Mix::parse("a=1, aaaa=0,mx=2,txt=3,nx=4").expect("mix");
        assert_eq!(mix.weight(Class::Aaaa), 0);
        assert_eq!(mix.total(), 10);
        assert!(Mix::parse("a=0,aaaa=0,mx=0,txt=0,nx=0").is_err());
        assert!(Mix::parse("bogus=1").is_err());
    }

    #[test]
    fn pick_respects_weights_and_is_stable() {
        let mix = Mix::parse("a=1,aaaa=0,mx=0,txt=0,nx=1").expect("mix");
        assert_eq!(mix.pick(0), Class::A);
        assert_eq!(mix.pick(1), Class::Nx);
        let mut left = Rng::new(42);
        let mut right = Rng::new(42);
        for _ in 0..1_000 {
            assert_eq!(left.next_u64(), right.next_u64());
        }
        assert!(left.below(7) < 7);
    }
}
