use crate::advisory::model::{AdvisoryHead, AdvisoryVulnerabilityHead};
use crate::Error;
use sea_orm::{ColumnTrait, EntityTrait, LoaderTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_common::paginated;
use trustify_cvss::cvss3::score::Score;
use trustify_cvss::cvss3::Cvss3Base;
use trustify_entity::{advisory, advisory_vulnerability, cvss3, organization, vulnerability};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisorySummary {
    #[serde(flatten)]
    pub head: AdvisoryHead,
    /// Average (arithmetic mean) severity of the advisory aggregated from *all* related vulnerability assertions.
    pub average_severity: Option<String>,
    /// Average (arithmetic mean) score of the advisory aggregated from *all* related vulnerability assertions.
    pub average_score: Option<f64>,
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
            let cvss3 = cvss3::Entity::find()
                .filter(cvss3::Column::AdvisoryId.eq(advisory.id))
                .all(tx)
                .await?;

            let total_score = cvss3
                .iter()
                .map(|e| {
                    let base = Cvss3Base::from(e.clone());
                    base.score().value()
                })
                .reduce(|accum, e| accum + e);

            let average_score = total_score.map(|total| Score::new(total / cvss3.len() as f64));

            let vulnerabilities =
                AdvisoryVulnerabilityHead::from_entities(advisory, &vulnerabilities, tx).await?;

            summaries.push(AdvisorySummary {
                head: AdvisoryHead::from_entity(advisory, issuer, tx).await?,
                average_severity: average_score.map(|score| score.severity().to_string()),
                average_score: average_score.map(|score| score.value()),
                vulnerabilities,
            })
        }

        Ok(summaries)
    }
}
