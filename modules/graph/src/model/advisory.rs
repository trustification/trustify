use crate::graph::vulnerability::VulnerabilityContext;
use serde::Serialize;
use time::OffsetDateTime;
use trustify_common::advisory::AdvisoryVulnerabilityAssertions;
use trustify_cvss::cvss3::Cvss3Base;
use trustify_cvss::cvss4::Cvss4Base;
use trustify_entity::advisory::Model;
use trustify_entity::advisory_vulnerability;
use utoipa::ToSchema;

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct AdvisorySummary {
    pub identifier: String,
    pub sha256: String,
    pub published: Option<OffsetDateTime>,
    pub modified: Option<OffsetDateTime>,
    pub withdrawn: Option<OffsetDateTime>,
    pub title: Option<String>,
}

impl From<Model> for AdvisorySummary {
    fn from(value: Model) -> Self {
        Self {
            identifier: value.identifier,
            sha256: value.sha256,
            published: value.published,
            modified: value.modified,
            withdrawn: value.withdrawn,
            title: value.title,
        }
    }
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct AdvisoryDetails {
    pub identifier: String,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub vulnerabilities: Vec<AdvisoryVulnerability>,
}

impl AdvisoryDetails {
    pub fn new_summary(advisory: Model, vulnerabilities: Vec<AdvisoryVulnerability>) -> Self {
        Self {
            identifier: advisory.identifier,
            sha256: advisory.sha256,
            published: advisory.published,
            modified: advisory.modified,
            withdrawn: advisory.withdrawn,
            title: advisory.title,
            vulnerabilities,
        }
    }
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct AdvisoryVulnerability {
    pub vulnerability_id: String,
    #[schema(value_type = Vec<String>)]
    pub cvss3_scores: Vec<Cvss3Base>,
    #[serde(flatten)]
    pub assertions: AdvisoryVulnerabilityAssertions,
}
