use crate::model::vulnerability::{VulnerabilityDetails, VulnerabilityHead, VulnerabilitySummary};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_common::advisory::AdvisoryVulnerabilityAssertions;
use trustify_common::paginated;
use trustify_cvss::cvss3::Cvss3Base;
use trustify_cvss::cvss4::Cvss4Base;
use trustify_entity::advisory::Model;
use trustify_entity::advisory_vulnerability;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryHead {
    pub identifier: String,
    pub sha256: String,
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub modified: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub withdrawn: Option<OffsetDateTime>,
    pub title: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisorySummary {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub vulnerabilities: Vec<AdvisoryVulnerabilityHead>,
}

paginated!(AdvisorySummary);

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryDetails {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub vulnerabilities: Vec<AdvisoryVulnerabilitySummary>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryVulnerabilityHead {
    #[serde(flatten)]
    pub head: VulnerabilityHead,
    pub severity: String,
    pub score: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryVulnerabilitySummary {
    #[serde(flatten)]
    pub head: AdvisoryVulnerabilityHead,
    #[schema(default, value_type = Vec < String >)]
    pub cvss3_scores: Vec<String>,
    #[serde(flatten)]
    pub assertions: AdvisoryVulnerabilityAssertions,
}
