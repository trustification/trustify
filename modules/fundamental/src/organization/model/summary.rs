use crate::organization::model::OrganizationHead;
use serde::{Deserialize, Serialize};
use trustify_entity::organization;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema, PartialEq, Eq)]
pub struct OrganizationSummary {
    #[serde(flatten)]
    pub head: OrganizationHead,
}

impl OrganizationSummary {
    pub fn from_entity(organization: &organization::Model) -> Self {
        Self {
            head: OrganizationHead::from_entity(organization),
        }
    }

    pub fn from_entities(organizations: &[organization::Model]) -> Vec<Self> {
        organizations
            .iter()
            .map(OrganizationSummary::from_entity)
            .collect()
    }
}
