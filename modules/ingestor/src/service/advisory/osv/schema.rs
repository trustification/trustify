use std::fmt::{Display, Formatter};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Package identifies the code library or command that
/// is potentially affected by a particular vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Package {
    Purl { purl: String },
    Named { name: String, ecosystem: Ecosystem },
}

/// A commit is a full SHA1 Git hash in hex format.
//pub type Commit = String;

/// Version is arbitrary string representing the version of a package.
//pub type Version = String;

/// The package ecosystem that the vulnerabilities in the OSV database
/// are associated with.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
#[allow(clippy::upper_case_acronyms)]
pub enum Ecosystem {
    Go,
    #[serde(rename = "npm")]
    Npm,
    JavaScript,
    #[serde(rename = "OSS-Fuzz")]
    OssFuzz,
    PyPI,
    RubyGems,
    #[serde(rename = "crates.io")]
    CratesIO,
    Packagist,
    Maven,
    NuGet,
    Linux,
    Debian,
    #[serde(rename = "Debian:3.0")]
    Debian3_0,
    #[serde(rename = "Debian:3.1")]
    Debian3_1,
    #[serde(rename = "Debian:4.0")]
    Debian4_0,
    #[serde(rename = "Debian:5.0")]
    Debian5_0,
    #[serde(rename = "Debian:6.0")]
    Debian6_0,
    #[serde(rename = "Debian:7")]
    Debian7,
    #[serde(rename = "Debian:8")]
    Debian8,
    #[serde(rename = "Debian:9")]
    Debian9,
    #[serde(rename = "Debian:10")]
    Debian10,
    #[serde(rename = "Debian:11")]
    Debian11,
    Hex,
    Android,
    #[serde(rename = "GitHub Actions")]
    GitHubActions,
    Pub,
    ConanCenter,
    Alpine,
    #[serde(rename = "Alpine:v3.10")]
    AlpineV3_10,
    #[serde(rename = "Alpine:v3.11")]
    AlpineV3_11,
    #[serde(rename = "Alpine:v3.12")]
    AlpineV3_12,
    #[serde(rename = "Alpine:v3.13")]
    AlpineV3_13,
    #[serde(rename = "Alpine:v3.14")]
    AlpineV3_14,
    #[serde(rename = "Alpine:v3.15")]
    AlpineV3_15,
    #[serde(rename = "Alpine:v3.16")]
    AlpineV3_16,
    #[serde(rename = "Alpine:v3.17")]
    AlpineV3_17,
    #[serde(rename = "Alpine:v3.2")]
    AlpineV3_2,
    #[serde(rename = "Alpine:v3.3")]
    AlpineV3_3,
    #[serde(rename = "Alpine:v3.4")]
    AlpineV3_4,
    #[serde(rename = "Alpine:v3.5")]
    AlpineV3_5,
    #[serde(rename = "Alpine:v3.6")]
    AlpineV3_6,
    #[serde(rename = "Alpine:v3.7")]
    AlpineV3_7,
    #[serde(rename = "Alpine:v3.8")]
    AlpineV3_8,
    #[serde(rename = "Alpine:v3.9")]
    AlpineV3_9,
    DWF,
    GSD,
    UVI,
    #[serde(rename = "Rocky Linux")]
    RockyLinux,
    AlmaLinux,
}

/// Type of the affected range supplied. This can be an ecosystem
/// specific value, semver, or a git commit hash.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum RangeType {
    /// Default for the case where a range type is omitted.
    Unspecified,

    /// The versions introduced and fixed are full-length Git commit hashes.
    Git,

    /// The versions introduced and fixed are semantic versions as defined by SemVer 2.0.0.
    Semver,

    /// The versions introduced and fixed are arbitrary, uninterpreted strings specific to the
    /// package ecosystem
    Ecosystem,
}

/// The event captures information about the how and when
/// the package was affected by the vulnerability.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Event {
    /// The version or commit in which the vulnerability was
    /// introduced.
    Introduced(String),

    /// The version which the vulnerability was fixed.
    Fixed(String),

    /// Describes the last known affected version
    #[serde(rename = "last_affected")]
    LastAffected(String),

    /// The upper limit on the range being described.
    Limit(String),
}

/// The range of versions of a package for which
/// it is affected by the vulnerability.
#[derive(Debug, Serialize, Deserialize)]
pub struct Range {
    /// The format that the range events are specified in, for
    /// example SEMVER or GIT.
    #[serde(rename = "type")]
    pub range_type: RangeType,

    /// The ranges object’s repo field is the URL of the package’s code repository. The value
    /// should be in a format that’s directly usable as an argument for the version control
    /// system’s clone command
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,

    /// Represent a status timeline for how the vulnerability affected the package. For
    /// example when the vulnerability was first introduced into the codebase.
    pub events: Vec<Event>,
}

/// The versions of the package that are affected
/// by a particular vulnerability. The affected ranges can include
/// when the vulnerability was first introduced and also when it
/// was fixed.
#[derive(Debug, Serialize, Deserialize)]
pub struct Affected {
    /// The package that is affected by the vulnerability
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,

    /// This `severity` field applies to a specific package, in cases where affected
    /// packages have differing severities for the same vulnerability. If any package
    /// level `severity` fields are set, the top level [`severity`](#severity-field)
    /// must not be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,

    /// The range of versions or git commits that this vulnerability
    /// was first introduced and/or version that it was fixed in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<Range>>,

    /// Each string is a single affected version in whatever version syntax is
    /// used by the given package ecosystem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,

    /// A JSON object that holds any additional information about the
    /// vulnerability as defined by the ecosystem for which the record applies.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem_specific: Option<serde_json::Value>,

    /// A JSON object to hold any additional information about the range
    /// from which this record was obtained. The meaning of the values within
    /// the object is entirely defined by the database.
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<serde_json::Value>,
}

/// The type of reference information that has been provided. Examples include
/// links to the original report, external advisories, or information about the
/// fix.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum ReferenceType {
    #[serde(rename = "NONE")]
    Undefined,
    Web,
    Advisory,
    Report,
    Fix,
    Package,
    Article,
    Detection,
    Introduced,
    Evidence,
    Git,
}

//impl ReferenceType {
impl Display for ReferenceType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ReferenceType::Undefined => "NONE",
                ReferenceType::Web => "WEB",
                ReferenceType::Advisory => "ADVISORY",
                ReferenceType::Report => "REPORT",
                ReferenceType::Fix => "FIX",
                ReferenceType::Package => "PACKAGE",
                ReferenceType::Article => "ARTICLE",
                ReferenceType::Detection => "DETECTION",
                ReferenceType::Introduced => "INTRODUCED",
                ReferenceType::Evidence => "EVIDENCE",
                ReferenceType::Git => "GIT",
            }
        )
    }
}

/// Reference to additional information about the vulnerability.
#[derive(Debug, Serialize, Deserialize)]
pub struct Reference {
    /// The type of reference this URL points to.
    #[serde(rename = "type")]
    pub reference_type: ReferenceType,

    /// The url where more information can be obtained about
    /// the vulnerability or associated the fix.
    pub url: String,
}

/// The [`SeverityType`](SeverityType) describes the quantitative scoring method used to rate the
/// severity of the vulnerability.
#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SeverityType {
    /// The severity score was arrived at by using an unspecified
    /// scoring method.
    #[serde(rename = "UNSPECIFIED")]
    Unspecified,

    /// A CVSS vector string representing the unique characteristics and severity of the
    /// vulnerability using a version of the Common Vulnerability Scoring System notation that is
    /// >= 3.0 and < 4.0 (e.g.`"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N"`).
    #[serde(rename = "CVSS_V3")]
    CVSSv3,

    /// A CVSS vector string representing the unique characteristics and severity of the vulnerability
    /// using a version of the [Common Vulnerability Scoring System notation](https://www.first.org/cvss/v2/)
    /// that is == 2.0 (e.g.`"AV:L/AC:M/Au:N/C:N/I:P/A:C"`).
    #[serde(rename = "CVSS_V2")]
    CVSSv2,
}

/// The type and score used to describe the severity of a vulnerability using one
/// or more quantitative scoring methods.
#[derive(Debug, Serialize, Deserialize)]
pub struct Severity {
    /// The severity type property must be a [`SeverityType`](SeverityType), which describes the
    /// quantitative method used to calculate the associated score.
    #[serde(rename = "type")]
    pub severity_type: SeverityType,

    /// The score property is a string representing the severity score based on the
    /// selected severity type.
    pub score: String,
}

/// The [`CreditType`](CreditType) this optional field should specify
/// the type or role of the individual or entity being credited.
///
/// These values and their definitions correspond directly to the [MITRE CVE specification](https://cveproject.github.io/cve-schema/schema/v5.0/docs/#collapseDescription_oneOf_i0_containers_cna_credits_items_type).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum CreditType {
    /// Identified the vulnerability
    Finder,

    /// Notified the vendor of the vulnerability to a CNA.
    Reporter,

    /// Validated the vulnerability to ensure accruacy or severity.
    Analyst,

    /// Facilitated the corredinated response process.
    Coordinator,

    /// Prepared a code change or other remediation plans.
    RemediationDeveloper,

    /// Reviewed vulnerability remediation plans or code changes
    /// for effectiveness and completeness.
    RemediationReviewer,

    /// Tested and verified the vulnerability or its remediation.
    RemediationVerifier,

    /// Names of tools used in vulnerability discovery or identification.
    Tool,

    /// Supported the vulnerability identification or remediation activities.
    Sponsor,

    /// Any other type or role that does not fall under the categories
    /// described above.
    Other,
}

/// Provides a way to give credit for the discovery, confirmation, patch or other events in the
/// life cycle of a vulnerability.
#[derive(Debug, Serialize, Deserialize)]
pub struct Credit {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit_type: Option<CreditType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVulnerability {
    /// The id field is a unique identifier for the vulnerability entry. It is a string of the
    /// format <DB>-<ENTRYID>, where DB names the database and ENTRYID is in the format used by the
    /// database. For example: “OSV-2020-111”, “CVE-2021-3114”, or “GHSA-vp9c-fpxx-744v”.
    pub id: String,

    /// The modified field gives the time the entry was last modified, as an RFC3339-formatted
    /// timestamptime stamp in UTC (ending in “Z”).
    pub modified: DateTime<Utc>,
}

/// A vulnerability is the standard exchange format that is
/// defined by the OSV schema <https://ossf.github.io/osv-schema/>.
///
/// This is the entity that is returned when vulnerable data exists for
/// a given package or when requesting information about a specific vulnerability
/// by unique identifier.
#[derive(Debug, Serialize, Deserialize)]
pub struct Vulnerability {
    /// The schema_version field is used to indicate which version of the OSV schema a particular
    /// vulnerability was exported with.
    pub schema_version: Option<String>,
    /// The id field is a unique identifier for the vulnerability entry. It is a string of the
    /// format <DB>-<ENTRYID>, where DB names the database and ENTRYID is in the format used by the
    /// database. For example: “OSV-2020-111”, “CVE-2021-3114”, or “GHSA-vp9c-fpxx-744v”.
    pub id: String,

    /// The published field gives the time the entry should be considered to have been published,
    /// as an RFC3339-formatted time stamp in UTC (ending in “Z”).
    pub published: DateTime<Utc>,

    /// The modified field gives the time the entry was last modified, as an RFC3339-formatted
    /// timestamptime stamp in UTC (ending in “Z”).
    pub modified: DateTime<Utc>,

    /// The withdrawn field gives the time the entry should be considered to have been withdrawn,
    /// as an RFC3339-formatted timestamp in UTC (ending in “Z”). If the field is missing, then the
    /// entry has not been withdrawn. Any rationale for why the vulnerability has been withdrawn
    /// should go into the summary text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<DateTime<Utc>>,

    /// The aliases field gives a list of IDs of the same vulnerability in other databases, in the
    /// form of the id field. This allows one database to claim that its own entry describes the
    /// same vulnerability as one or more entries in other databases. Or if one database entry has
    /// been deduplicated into another in the same database, the duplicate entry could be written
    /// using only the id, modified, and aliases field, to point to the canonical one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,

    /// The related field gives a list of IDs of closely related vulnerabilities, such as the same
    /// problem in alternate ecosystems.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related: Option<Vec<String>>,

    /// The summary field gives a one-line, English textual summary of the vulnerability. It is
    /// recommended that this field be kept short, on the order of no more than 120 characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// The details field gives additional English textual details about the vulnerability. The
    /// details field is CommonMark markdown (a subset of GitHub-Flavored Markdown). Display code
    /// may at its discretion sanitize the input further, such as stripping raw HTML and links that
    /// do not start with http:// or https://. Databases are encouraged not to include those in the
    /// first place. (The goal is to balance flexibility of presentation with not exposing
    /// vulnerability database display sites to unnecessary vulnerabilities.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,

    /// Indicates the specific package ranges that are affected by this vulnerability.
    pub affected: Vec<Affected>,

    /// An optional list of external reference's that provide more context about this
    /// vulnerability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<Reference>>,

    /// The severity field is a JSON array that allows generating systems to describe the severity
    /// of a vulnerability using one or more quantitative scoring methods. Each severity item is a
    /// object specifying a type and score property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Vec<Severity>>,

    /// Provides a way to give credit for the discovery, confirmation, patch or other events in the
    /// life cycle of a vulnerability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credits: Option<Vec<Credit>>,

    /// Top level field to hold any additional information about the vulnerability as defined
    /// by the database from which the record was obtained.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use test_log::test;

    use super::*;

    #[test(tokio::test)]
    async fn test_package_serialization() -> Result<(), anyhow::Error> {
        let package = Package::Purl {
            purl: "pkg://foo/bar".into(),
        };

        let json = serde_json::to_string(&package).unwrap();
        log::debug!("{json}");
        assert_eq!(
            serde_json::to_string(&json! {
                {
                    "purl": "pkg://foo/bar"
                }
            })
            .unwrap(),
            json
        );

        let package = Package::Named {
            name: "log4j".into(),
            ecosystem: Ecosystem::Maven,
        };
        let json = serde_json::to_string(&package).unwrap();

        log::debug!("{json}");
        assert!(json.contains(r#""ecosystem":"Maven""#));
        assert!(json.contains(r#""name":"log4j""#));

        Ok(())
    }

    #[test(tokio::test)]
    async fn test_no_serialize_null_fields() -> Result<(), anyhow::Error> {
        let vuln = Vulnerability {
            schema_version: Some("1.3.0".to_string()),
            id: "OSV-2020-484".to_string(),
            published: chrono::Utc::now(),
            modified: chrono::Utc::now(),
            withdrawn: None,
            aliases: None,
            related: None,
            summary: None,
            details: None,
            affected: vec![],
            references: None,
            severity: None,
            credits: None,
            database_specific: None,
        };

        let as_json = serde_json::json!(vuln);
        let str_json = as_json.to_string();
        assert!(!str_json.contains("withdrawn"));
        assert!(!str_json.contains("aliases"));
        assert!(!str_json.contains("related"));
        assert!(!str_json.contains("summary"));
        assert!(!str_json.contains("details"));
        assert!(!str_json.contains("references"));
        assert!(!str_json.contains("severity"));
        assert!(!str_json.contains("credits"));
        assert!(!str_json.contains("database_specific"));

        Ok(())
    }
}
