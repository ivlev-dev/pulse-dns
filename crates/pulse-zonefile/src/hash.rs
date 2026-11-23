//! Быстрый не-криптографический хеш для внутренних индексов.
//!
//! Ключи кеша/каталога — короткие (`page_no`/`txn`, RLE-имя ≤255 Б).
//! `SipHash` здесь не нужен: значения не выходят наружу и не атакуются
//! подбором коллизий со стороны пользователя.

use std::hash::{BuildHasherDefault, Hasher};

/// FNV-1a-подобный 64-битный хеш (быстрый для коротких ключей).
#[derive(Default)]
pub(crate) struct FastHasher(u64);

impl FastHasher {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    #[inline]
    fn mix(&mut self, value: u64) {
        self.0 = (self.0 ^ value).wrapping_mul(Self::PRIME);
    }
}

impl Hasher for FastHasher {
    #[inline]
    fn finish(&self) -> u64 {
        // Финальный лавинный шаг: без него младшие биты FNV зависят только
        // от последних байтов, а HashMap использует именно младшие биты.
        let mut value = self.0;
        value ^= value >> 30;
        value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        if self.0 == 0 {
            self.0 = Self::OFFSET;
        }
        for chunk in bytes.chunks(8) {
            let mut word = [0_u8; 8];
            if let Some(dst) = word.get_mut(..chunk.len()) {
                dst.copy_from_slice(chunk);
            }
            self.mix(u64::from_le_bytes(word));
        }
    }

    #[inline]
    fn write_u8(&mut self, value: u8) {
        self.mix(u64::from(value));
    }

    #[inline]
    fn write_u16(&mut self, value: u16) {
        self.mix(u64::from(value));
    }

    #[inline]
    fn write_u32(&mut self, value: u32) {
        self.mix(u64::from(value));
    }

    #[inline]
    fn write_u64(&mut self, value: u64) {
        self.mix(value);
    }

    #[inline]
    fn write_usize(&mut self, value: usize) {
        self.mix(value as u64);
    }
}

/// `HashMap` с [`FastHasher`].
pub(crate) type FastMap<K, V> = std::collections::HashMap<K, V, BuildHasherDefault<FastHasher>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::{BuildHasher, BuildHasherDefault};

    #[test]
    fn distribution_is_sane() {
        use crate::key::NameRle;
        let builder = BuildHasherDefault::<FastHasher>::default();
        let mut buckets = std::collections::HashMap::<u64, usize>::new();
        for index in 0..10_000_u32 {
            let name = NameRle::from_ascii(&format!("z{index:05}.example")).unwrap();
            let hash = builder.hash_one(name);
            *buckets.entry(hash & 1023).or_default() += 1;
        }
        let max = buckets.values().copied().max().unwrap_or(0);
        println!("distinct={} max_bucket={max}", buckets.len());
        assert!(max < 200, "max bucket {max}");
    }
}
