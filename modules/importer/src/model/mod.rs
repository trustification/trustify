mod csaf;
mod cve;
mod osv;
mod sbom;

pub use csaf::*;
pub use cve::*;
pub use osv::*;
pub use sbom::*;

use std::ops::{Deref, DerefMut};
use std::time::Duration;
use time::OffsetDateTime;
use trustify_common::{model::Revisioned, paginated, revisioned};
use trustify_entity::labels::Labels;
use trustify_entity::{
    importer::{self, Model},
    importer_report,
};
use url::Url;
use utoipa::ToSchema;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
pub struct Importer {
    pub name: String,
    #[serde(flatten)]
    pub data: ImporterData,
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
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

    /// The continuation token of the importer.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub continuation: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ImporterConfiguration {
    Sbom(SbomImporter),
    Csaf(CsafImporter),
    Osv(OsvImporter),
    Cve(CveImporter),
}

impl Deref for ImporterConfiguration {
    type Target = CommonImporter;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Sbom(importer) => &importer.common,
            Self::Csaf(importer) => &importer.common,
            Self::Osv(importer) => &importer.common,
            Self::Cve(importer) => &importer.common,
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
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CommonImporter {
    /// A flag to disable the importer, without deleting it.
    #[serde(default)]
    pub disabled: bool,

    /// The period the importer should be run.
    #[serde(with = "humantime_serde")]
    pub period: Duration,

    /// A description for users.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Labels which will be applied to the ingested documents.
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
}

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
                continuation: continuation.unwrap_or_default(),
                configuration: serde_json::from_value(configuration)?,
            },
        })
    }
}

revisioned!(Importer);

impl TryFrom<Model> for RevisionedImporter {
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
            continuation,
            revision,
        }: Model,
    ) -> Result<Self, Self::Error> {
        Ok(Self(Revisioned {
            value: Importer {
                name,
                data: ImporterData {
                    state: state.into(),
                    last_change,
                    last_success,
                    last_run,
                    last_error,
                    continuation: continuation.unwrap_or_default(),
                    configuration: serde_json::from_value(configuration)?,
                },
            },
            revision: revision.to_string(),
        }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImporterReport {
    pub id: String,

    pub importer: String,
    #[serde(with = "time::serde::rfc3339")]
    pub creation: OffsetDateTime,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub report: serde_json::Value,
}

paginated!(ImporterReport);

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
            report,
        }
    }
}
