use sea_orm::ModelTrait;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use advisory_vulnerability::AdvisoryVulnerabilitySummary;
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{advisory, organization, vulnerability};

use crate::advisory::AdvisoryHead;
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
    ) -> Result<Option<Self>, Error> {
        let vulnerabilities = advisory.find_related(vulnerability::Entity).all(tx).await?;

        let vulnerabilities =
            AdvisoryVulnerabilitySummary::from_entities(advisory, &vulnerabilities, tx).await?;

        let issuer = advisory.find_related(organization::Entity).one(tx).await?;

        Ok(Some(AdvisoryDetails {
            head: AdvisoryHead {
                identifier: advisory.identifier.clone(),
                sha256: advisory.sha256.clone(),
                issuer: issuer.map(|inner| inner.name),
                published: advisory.published,
                modified: advisory.modified,
                withdrawn: advisory.withdrawn,
                title: advisory.title.clone(),
            },
            vulnerabilities,
        }))
    }
}
