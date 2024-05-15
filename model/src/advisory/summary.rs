use crate::advisory::AdvisoryHead;
use crate::advisory::AdvisoryVulnerabilityHead;
use crate::Error;
use sea_orm::LoaderTrait;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_common::paginated;
use trustify_entity::{advisory, advisory_vulnerability, organization, vulnerability};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisorySummary {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    pub vulnerabilities: Vec<AdvisoryVulnerabilityHead>,
}

paginated!(AdvisorySummary);

impl AdvisorySummary {
    pub async fn from_entities(
        entities: &[advisory::Model],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut vulnerabilities = entities
            .load_many_to_many(vulnerability::Entity, advisory_vulnerability::Entity, tx)
            .await?;

        let mut issuers = entities.load_one(organization::Entity, tx).await?;

        let mut summaries = Vec::new();

        for ((advisory, vulnerabilities), issuer) in entities
            .iter()
            .zip(vulnerabilities.drain(..))
            .zip(issuers.drain(..))
        {
            let vulnerabilities =
                AdvisoryVulnerabilityHead::from_entities(advisory, &vulnerabilities, tx).await?;

            summaries.push(AdvisorySummary {
                head: AdvisoryHead::from_entity(advisory, issuer, tx).await?,
                vulnerabilities,
            })
        }

        Ok(summaries)
    }
}
