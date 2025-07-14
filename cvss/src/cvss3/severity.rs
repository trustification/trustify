use crate::cvss3::Cvss3Error;
use serde::{Deserialize, Serialize, de, ser};
use std::fmt;
use std::str::FromStr;
use utoipa::ToSchema;

/// Qualitative Severity Rating Scale
///
/// Described in CVSS v3.1 Specification: Section 5:
/// <https://www.first.org/cvss/specification-document#t17>
///
/// > For some purposes it is useful to have a textual representation of the
/// > numeric Base, Temporal and Environmental scores.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, ToSchema)]
#[schema(rename_all = "snake_case")]
pub enum Severity {
    /// None: CVSS Score 0.0
    None,

    /// Low: CVSS Score 0.1 - 3.9
    Low,

    /// Medium: CVSS Score 4.0 - 6.9
    Medium,

    /// High: CVSS Score 7.0 - 8.9
    High,

    /// Critical: CVSS Score 9.0 - 10.0
    Critical,
}

impl Severity {
    /// Get a `str` describing the severity level
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn from_f64(value: f64) -> Severity {
        match value {
            x if x < 0.1 => Severity::None,
            x if x < 4.0 => Severity::Low,
            x if x < 7.0 => Severity::Medium,
            x if x < 9.0 => Severity::High,
            _ => Severity::Critical,
        }
    }
}

impl From<f64> for Severity {
    fn from(value: f64) -> Self {
        Self::from_f64(value)
    }
}

impl FromStr for Severity {
    type Err = Cvss3Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Ok(Severity::None),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(Cvss3Error::InvalidSeverity { name: s.to_owned() }),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl Serialize for Severity {
    fn serialize<S: ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_str().serialize(serializer)
    }
}
