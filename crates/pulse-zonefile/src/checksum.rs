//! Контрольные суммы CRC-32C (Castagnoli) для страниц и superblock.

/// CRC-32C (Castagnoli, reflected, init/final `0xFFFFFFFF`).
///
/// Аппаратное ускорение (SSE4.2 / `ARMv8` CRC) предоставляет крейт `crc32c`.
///
/// # Примеры
///
/// ```
/// assert_eq!(pulse_zonefile::checksum::crc32c(b"123456789"), 0xE306_9283);
/// ```
#[must_use]
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

/// CRC-32C диапазона, в котором 4-байтовое поле `crc32c` по смещению
/// `crc_offset` считается нулевым.
///
/// Возвращает `None`, если поле не помещается в `data`.
#[must_use]
pub fn page_crc32c(data: &[u8], crc_offset: usize) -> Option<u32> {
    let (head, tail) = data.split_at_checked(crc_offset)?;
    let (_, body) = tail.split_at_checked(4)?;
    let mut crc = crc32c::crc32c(head);
    crc = crc32c::crc32c_append(crc, &[0, 0, 0, 0]);
    crc = crc32c::crc32c_append(crc, body);
    Some(crc)
}

/// Проверяет CRC-32C страницы с исключённым полем.
///
/// `stored` — значение, прочитанное из поля.
#[must_use]
pub fn verify_page_crc(data: &[u8], crc_offset: usize, stored: u32) -> bool {
    page_crc32c(data, crc_offset) == Some(stored)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_test_vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn page_crc_ignores_crc_field() {
        let mut page = vec![0x5A_u8; 64];
        page[20..24].copy_from_slice(&[0, 0, 0, 0]);
        let expected = page_crc32c(&page, 20).unwrap();
        page[20..24].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(page_crc32c(&page, 20), Some(expected));
        assert!(verify_page_crc(&page, 20, expected));
        assert!(!verify_page_crc(&page, 20, expected ^ 1));
    }

    #[test]
    fn page_crc_rejects_out_of_bounds() {
        assert_eq!(page_crc32c(&[0; 3], 0), None);
        assert_eq!(page_crc32c(&[0; 4], 1), None);
        assert_eq!(page_crc32c(&[0; 4], 4), None);
    }
}
