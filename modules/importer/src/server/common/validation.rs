use crate::server::report::ScannerError;
use std::time::SystemTime;
use time::{Date, Month, UtcOffset};
use walker_common::validate::ValidationOptions;

pub fn options(v3_signatures: bool) -> Result<ValidationOptions, ScannerError> {
    let mut options = ValidationOptions::new();

    if v3_signatures {
        options = options.validation_date(SystemTime::from(
            Date::from_calendar_date(2007, Month::January, 1)
                .map_err(|err| ScannerError::Critical(err.into()))?
                .midnight()
                .assume_offset(UtcOffset::UTC),
        ));
    }

    Ok(options)
}
