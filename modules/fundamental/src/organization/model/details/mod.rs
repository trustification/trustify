use crate::{Error, advisory::model::AdvisoryHead, organization::model::OrganizationHead};
use sea_orm::{ConnectionTrait, ModelTrait};
use serde::{Deserialize, Serialize};
use trustify_entity::{advisory, organization};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
pub struct OrganizationDetails {
    #[serde(flatten)]
    head: OrganizationHead,

    /// Advisories issued by the organization, if any.
    advisories: Vec<AdvisoryHead>,
}

impl OrganizationDetails {
    pub async fn from_entity<C: ConnectionTrait>(
        org: &organization::Model,
        tx: &C,
    ) -> Result<Self, Error> {
        let advisories = org.find_related(advisory::Entity).all(tx).await?;
        Ok(OrganizationDetails {
            head: OrganizationHead::from_entity(org),
            advisories: AdvisoryHead::from_entities(&advisories, tx).await?,
        })
    }
}
