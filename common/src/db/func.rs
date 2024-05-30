use migration::Iden;
use std::fmt::Write;

/// PostgreSQL's `array_agg` function.
///
/// See: <https://www.postgresql.org/docs/current/functions-aggregate.html>
pub struct ArrayAgg;

impl Iden for ArrayAgg {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        s.write_str("array_agg").unwrap();
    }
}

/// PostgreSQL's `json_build_object` function.
///
/// See: <https://www.postgresql.org/docs/current/functions-json.html>
pub struct JsonBuildObject;

impl Iden for JsonBuildObject {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        s.write_str("json_build_object").unwrap();
    }
}

/// PostgreSQL's `json_build_object` function.
///
/// See: <https://www.postgresql.org/docs/current/functions-json.html>
pub struct ToJson;

impl Iden for ToJson {
    #[allow(clippy::unwrap_used)]
    fn unquoted(&self, s: &mut dyn Write) {
        s.write_str("to_json").unwrap();
    }
}

pub struct Cvss3Score;

impl Iden for Cvss3Score {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "cvss3_score").unwrap()
    }
}

pub struct VersionMatches;

impl Iden for VersionMatches {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "version_matches").unwrap()
    }
}
