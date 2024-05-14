use crate::service::sbom::SbomPackageReference;
use sea_orm::prelude::Uuid;
use sea_orm::FromQueryResult;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_common::paginated;
use trustify_entity::{relationship::Relationship, sbom};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomSummary {
    pub id: Uuid,
    pub sha256: String,

    pub document_id: String,

    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authors: Vec<String>,
}

paginated!(SbomSummary);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SbomPackage {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub purl: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpe: Vec<String>,
}

impl<'a> From<&'a SbomPackage> for SbomPackageReference<'a> {
    fn from(value: &'a SbomPackage) -> Self {
        Self::Package(&value.id)
    }
}

paginated!(SbomPackage);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SbomPackageRelation {
    pub relationship: Relationship,
    pub package: SbomPackage,
}

paginated!(SbomPackageRelation);
