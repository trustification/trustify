use chrono::{DateTime, Utc};
use std::time::SystemTime;
use time::OffsetDateTime;

/// Convert a [`chrono::DateTime<Utc>`] into a [`time::OffsetDateTime`].
///
/// There is a more convenient way to perform this using the [`ChronoExt`] trait:
///
/// ```rust
/// # use chrono::Utc;
/// use trustify_common::time::ChronoExt;
///
/// let chrono = Utc::now();
/// let time3 = chrono.into_time();
/// ```
pub fn chrono_to_time3(input: DateTime<Utc>) -> OffsetDateTime {
    let ts: SystemTime = input.into();
    OffsetDateTime::from(ts)
}

pub trait ChronoExt {
    /// Turn into a [`time::OffsetDateTime`].
    fn into_time(self) -> OffsetDateTime;
}

impl ChronoExt for DateTime<Utc> {
    fn into_time(self) -> OffsetDateTime {
        chrono_to_time3(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
    use time::macros::datetime;

    fn input(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> DateTime<Utc> {
        NaiveDate::from_ymd_opt(year, month, day)
            .expect("must be valid")
            .and_hms_opt(hour, min, sec)
            .expect("must be valid")
            .and_utc()
    }

    #[test_log::test(rstest::rstest)]
    #[case(input(2024, 12, 24, 15, 16, 17), datetime!(2024-12-24 15:16:17 UTC))]
    fn test(#[case] input: DateTime<Utc>, #[case] output: OffsetDateTime) {
        assert_eq!(input.into_time(), output)
    }
}
