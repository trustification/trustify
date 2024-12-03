use crate::organization::model::OrganizationHead;
use crate::Error;
use serde::{Deserialize, Serialize};
use trustify_entity::organization;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema, PartialEq, Eq)]
pub struct OrganizationSummary {
    #[serde(flatten)]
    pub head: OrganizationHead,
}

impl OrganizationSummary {
    pub async fn from_entity(organization: &organization::Model) -> Result<Self, Error> {
        Ok(OrganizationSummary {
            head: OrganizationHead::from_entity(organization).await?,
        })
    }

    pub async fn from_entities(organizations: &[organization::Model]) -> Result<Vec<Self>, Error> {
        let mut summaries = Vec::new();

        for org in organizations {
            summaries.push(OrganizationSummary {
                head: OrganizationHead::from_entity(org).await?,
            });
        }

        Ok(summaries)
    }
}
