use time::OffsetDateTime;
use trustify_common::model::PaginatedResults;
use trustify_entity::advisory;
use utoipa::IntoParams;

#[derive(IntoParams, Clone, Debug, serde::Deserialize, serde::Serialize, utoipa::ToSchema)]
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
            title: value.title,
            published: value.published,
            modified: value.modified,
        }
    }
}

pub struct PaginatedAdvisories(pub PaginatedResults<FoundAdvisory>);
