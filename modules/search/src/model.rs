use time::OffsetDateTime;
use trustify_common::model::PaginatedResults;
use trustify_entity::{advisory, sbom};
use utoipa::IntoParams;

#[derive(
    IntoParams, Clone, Default, Debug, serde::Deserialize, serde::Serialize, utoipa::ToSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct SearchOptions {
    /// The search filter
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    /// Sort options
    pub sort: String,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FoundAdvisory {
    pub id: i32,

    pub document_id: String,
    pub location: String,
    pub sha256: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub modified: Option<OffsetDateTime>,
}

impl From<advisory::Model> for FoundAdvisory {
    fn from(value: advisory::Model) -> Self {
        Self {
            id: value.id,
            document_id: value.identifier,
            location: value.location,
            sha256: value.sha256,
            title: value.title,
            published: value.published,
            modified: value.modified,
        }
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct FoundSbom {
    pub id: i32,

    pub document_id: String,
    pub location: String,
    pub sha256: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,
}

impl From<sbom::Model> for FoundSbom {
    fn from(value: sbom::Model) -> Self {
        Self {
            id: value.id,
            document_id: value.document_id,
            location: value.location,
            sha256: value.sha256,
            title: value.title,
            published: value.published,
        }
    }
}

pub struct PaginatedAdvisories(pub PaginatedResults<FoundAdvisory>);
pub struct PaginatedSBOMs(pub PaginatedResults<FoundSbom>);
