mod clearly_defined_curation;

mod clearly_defined;
mod csaf;
mod cve;
mod cwe;
mod osv;
mod sbom;

pub use clearly_defined::*;
pub use clearly_defined_curation::*;
pub use csaf::*;
pub use cve::*;
pub use cwe::*;
pub use osv::*;
pub use sbom::*;

use crate::runner::report::Report;
use std::{
    ops::{Deref, DerefMut},
    time::Duration,
};
use time::OffsetDateTime;
use trustify_common::model::Revisioned;
use trustify_entity::{
    importer::{self, Model},
    importer_report,
    labels::Labels,
};
use url::Url;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct Importer {
    pub name: String,
    #[serde(flatten)]
    pub data: ImporterData,
}

impl Importer {
    pub fn from_revisioned(value: Model) -> Result<Revisioned<Importer>, serde_json::Error> {
        let revision = value.revision.to_string();
        Ok(Revisioned {
            value: value.try_into()?,
            revision,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum State {
    Waiting,
    Running,
}

impl From<importer::State> for State {
    fn from(value: importer::State) -> Self {
        match value {
            importer::State::Waiting => Self::Waiting,
            importer::State::Running => Self::Running,
        }
    }
}

impl From<State> for importer::State {
    fn from(value: State) -> Self {
        match value {
            State::Waiting => Self::Waiting,
            State::Running => Self::Running,
        }
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImporterData {
    pub configuration: ImporterConfiguration,

    /// The current state of the importer
    pub state: State,

    /// The last state change
    #[serde(with = "time::serde::rfc3339")]
    pub last_change: OffsetDateTime,

    /// The last successful run
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_success: Option<OffsetDateTime>,

    /// The last run (successful or not)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_run: Option<OffsetDateTime>,

    /// The error of the last run (empty if successful)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,

    /// The current progress, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,

    /// The continuation token of the importer.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub continuation: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    /// The current processed items.
    pub current: u32,
    /// The total number of items to be processed.
    pub total: u32,
    /// Progress in percent (0..=1)
    pub percent: f32,
    /// The average processing rate (per second).
    pub rate: f32,
    /// The estimated remaining time in seconds.
    pub estimated_seconds_remaining: u64,
    /// The estimated time of completion.
    #[serde(with = "time::serde::rfc3339")]
    pub estimated_completion: OffsetDateTime,
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub enum ImporterConfiguration {
    Sbom(SbomImporter),
    Csaf(CsafImporter),
    Osv(OsvImporter),
    Cve(CveImporter),
    ClearlyDefined(ClearlyDefinedImporter),
    ClearlyDefinedCuration(ClearlyDefinedCurationImporter),
    Cwe(CweImporter),
}

impl Deref for ImporterConfiguration {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Sbom(importer) => &importer.common,
            Self::Csaf(importer) => &importer.common,
            Self::Osv(importer) => &importer.common,
            Self::Cve(importer) => &importer.common,
            Self::ClearlyDefined(importer) => &importer.common,
            Self::ClearlyDefinedCuration(importer) => &importer.common,
            Self::Cwe(importer) => &importer.common,
        }
    }
}

impl DerefMut for ImporterConfiguration {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Sbom(importer) => &mut importer.common,
            Self::Csaf(importer) => &mut importer.common,
            Self::Osv(importer) => &mut importer.common,
            Self::Cve(importer) => &mut importer.common,
            Self::ClearlyDefined(importer) => &mut importer.common,
            Self::ClearlyDefinedCuration(importer) => &mut importer.common,
            Self::Cwe(importer) => &mut importer.common,
        }
    }
}

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    ToSchema,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct CommonImporter {
    /// A flag to disable the importer, without deleting it.
    #[serde(default)]
    pub disabled: bool,

    /// The period the importer should be run.
    #[serde(with = "humantime_serde")]
    #[schemars(with = "HumantimeSerde")]
    pub period: Duration,

    /// A description for users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Labels which will be applied to the ingested documents.
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
}

// Just here to create a schema for humantime_serde.
#[derive(schemars::JsonSchema)]
struct HumantimeSerde(#[allow(unused)] String);

impl TryFrom<Model> for Importer {
    type Error = serde_json::Error;

    fn try_from(
        Model {
            name,
            configuration,
            state,
            last_change,
            last_success,
            last_run,
            last_error,
            progress_current,
            progress_total,
            continuation,
            revision: _,
        }: Model,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            name,
            data: ImporterData {
                state: state.into(),
                last_change,
                last_success,
                last_run,
                last_error,
                progress: into_progress(
                    last_change,
                    OffsetDateTime::now_utc(),
                    progress_current,
                    progress_total,
                ),
                continuation: continuation.unwrap_or_default(),
                configuration: serde_json::from_value(configuration)?,
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImporterReport {
    /// The ID of the report
    pub id: String,

    /// The name of the importer this report belongs to
    pub importer: String,
    /// The time the report was created
    #[serde(with = "time::serde::rfc3339")]
    pub creation: OffsetDateTime,

    /// Errors captured by the report
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Detailed report information
    pub report: Option<Report>,
}

impl From<importer_report::Model> for ImporterReport {
    fn from(value: importer_report::Model) -> Self {
        let importer_report::Model {
            id,
            importer,
            creation,
            error,
            report,
        } = value;
        Self {
            id: id.to_string(),
            importer,
            creation,
            error,
            report: serde_json::from_value(report).ok(),
        }
    }
}

/// Create the progress information from the progress state
fn into_progress(
    start: OffsetDateTime,
    now: OffsetDateTime,
    current: Option<i32>,
    total: Option<i32>,
) -> Option<Progress> {
    // elapsed time in seconds
    let elapsed = (now - start).as_seconds_f32();

    // current and total progress information
    let current = current? as u32;
    let total = total? as u32;

    if current > total || total == 0 {
        return None;
    }

    // calculate rate and ETA
    let total_f = total as f32;
    let rate = current as f32 / elapsed;
    let remaining = (total - current) as f32;
    let estimated_seconds_remaining = (remaining / rate) as u64;

    // return result
    Some(Progress {
        current,
        total,
        percent: current as f32 / total_f,
        rate,
        estimated_seconds_remaining,
        estimated_completion: now + Duration::from_secs(estimated_seconds_remaining),
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn progress() {
        let start = datetime!(2024-01-01 00:00:00 UTC);
        let now = datetime!(2024-01-01 00:00:10 UTC);
        assert_eq!(
            into_progress(start, now, Some(15), Some(100)),
            Some(Progress {
                current: 15,
                total: 100,
                percent: 0.15,
                rate: 1.5,
                estimated_seconds_remaining: 56,
                estimated_completion: datetime!(2024-01-01 00:01:06 UTC),
            })
        )
    }

    #[test]
    fn progress_none() {
        let start = datetime!(2024-01-01 00:00:00 UTC);
        let now = datetime!(2024-01-01 00:00:10 UTC);
        assert_eq!(into_progress(start, now, None, None), None);
        assert_eq!(into_progress(start, now, Some(1), None), None);
        assert_eq!(into_progress(start, now, None, Some(1)), None);

        assert_eq!(into_progress(start, now, Some(10), Some(1)), None);
        assert_eq!(into_progress(start, now, Some(0), Some(0)), None);
    }
}
