use crate::model::advisory::AdvisoryVulnerabilitySummary;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_common::paginated;
use trustify_entity::{relationship::Relationship, sbom};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomSummary {
    pub id: i32,
    pub sha256: String,

    pub document_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,
}

paginated!(SbomSummary);

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomPackage {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub purl: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpe: Vec<String>,
}

paginated!(SbomPackage);

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomPackageRelation {
    pub package: String,
    pub relationship: Relationship,
}

paginated!(SbomPackageRelation);
