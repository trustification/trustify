use sea_orm::ModelTrait;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::advisory::model::AdvisoryHead;
use advisory_vulnerability::AdvisoryVulnerabilitySummary;
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{advisory, organization, vulnerability};

use crate::Error;

pub mod advisory_vulnerability;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryDetails {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub vulnerabilities: Vec<AdvisoryVulnerabilitySummary>,
}

impl AdvisoryDetails {
    pub async fn from_entity(
        advisory: &advisory::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let vulnerabilities = advisory.find_related(vulnerability::Entity).all(tx).await?;

        let vulnerabilities =
            AdvisoryVulnerabilitySummary::from_entities(advisory, &vulnerabilities, tx).await?;

        let issuer = advisory.find_related(organization::Entity).one(tx).await?;

        Ok(AdvisoryDetails {
            head: AdvisoryHead::from_entity(advisory, issuer, tx).await?,
            vulnerabilities,
        })
    }
}
