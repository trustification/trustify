use crate::model::vulnerability::{VulnerabilityDetails, VulnerabilitySummary};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_common::advisory::AdvisoryVulnerabilityAssertions;
use trustify_cvss::cvss3::Cvss3Base;
use trustify_cvss::cvss4::Cvss4Base;
use trustify_entity::advisory::Model;
use trustify_entity::advisory_vulnerability;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisorySummary {
    pub identifier: String,
    pub sha256: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<VulnerabilitySummary>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryDetails {
    #[serde(flatten)]
    pub summary: AdvisorySummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vulnerabilities: Vec<VulnerabilityDetails>,
}
