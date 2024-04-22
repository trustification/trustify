use crate::graph::vulnerability::VulnerabilityContext;
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
    pub vulnerabilities: Vec<AdvisoryVulnerabilitySummary>,
}

impl AdvisorySummary {
    pub fn new(advisory: Model, vulnerabilities: Vec<AdvisoryVulnerabilitySummary>) -> Self {
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

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryDetails {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub vulnerabilities: Vec<AdvisoryVulnerabilityDetails>,
}

impl AdvisoryDetails {
    pub fn new(advisory: Model, vulnerabilities: Vec<AdvisoryVulnerabilityDetails>) -> Self {
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

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryVulnerabilitySummary {
    pub vulnerability_id: String,
    pub severity: String,
    pub score: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryVulnerabilityDetails {
    pub vulnerability_id: String,
    #[schema(default, value_type = Vec < String >)]
    pub cvss3_scores: Vec<String>,
    #[serde(flatten)]
    pub assertions: AdvisoryVulnerabilityAssertions,
}
