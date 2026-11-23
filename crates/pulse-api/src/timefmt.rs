//! Форматирование времени без внешних зависимостей.
//!
//! API использует RFC 3339 UTC с миллисекундами (`2026-11-23T18:04:05.123Z`),
//! HTTP — IMF-fixdate.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SECONDS_PER_DAY: u64 = 86_400;

/// RFC 3339 UTC с миллисекундами.
pub(crate) fn rfc3339(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let seconds = since_epoch.as_secs();
    let days = seconds / SECONDS_PER_DAY;
    let remainder = seconds % SECONDS_PER_DAY;
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(i64::MAX));
    let hour = remainder / 3600;
    let minute = (remainder % 3600) / 60;
    let second = remainder % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        since_epoch.subsec_millis()
    )
}

/// IMF-fixdate для заголовка `Date`.
pub(crate) fn http_date(time: SystemTime) -> String {
    const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let seconds = since_epoch.as_secs();
    let days = seconds / SECONDS_PER_DAY;
    let remainder = seconds % SECONDS_PER_DAY;
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(i64::MAX));
    let weekday_index = usize::try_from((days + 4) % 7).unwrap_or(0);
    let weekday = WEEKDAYS.get(weekday_index).copied().unwrap_or("Thu");
    let month_name = MONTHS
        .get(usize::try_from(month.saturating_sub(1)).unwrap_or(0))
        .copied()
        .unwrap_or("Jan");
    let hour = remainder / 3600;
    let minute = (remainder % 3600) / 60;
    let second = remainder % 60;
    format!("{weekday}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} GMT")
}

/// Гражданская дата из числа дней от Unix epoch (Howard Hinnant).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted / 146_097
    } else {
        (shifted - 146_096) / 146_097
    };
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn known_timestamp() {
        let time = UNIX_EPOCH + Duration::from_millis(1_764_000_000_123);
        assert_eq!(rfc3339(time), "2025-11-24T16:00:00.123Z");
    }
}
