use sea_orm::LoaderTrait;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use trustify_common::db::ConnectionOrTransaction;
use trustify_common::paginated;
use trustify_cvss::cvss3::score::Score;
use trustify_entity::cvss3::Severity;
use trustify_entity::{advisory, advisory_vulnerability, organization, vulnerability};

use crate::advisory::model::{AdvisoryHead, AdvisoryVulnerabilityHead};
use crate::Error;

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
        averages: &[(Option<f64>, Option<Severity>)],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let vulnerabilities = entities
            .load_many_to_many(vulnerability::Entity, advisory_vulnerability::Entity, tx)
            .await?;

        let issuers = entities.load_one(organization::Entity, tx).await?;

        let mut summaries = Vec::with_capacity(issuers.len());

        for (((advisory, vulnerabilities), issuer), (average_score, average_severity)) in entities
            .iter()
            .zip(vulnerabilities.into_iter())
            .zip(issuers.into_iter())
            .zip(averages)
        {
            let vulnerabilities =
                AdvisoryVulnerabilityHead::from_entities(advisory, &vulnerabilities, tx).await?;

            let average_score = average_score.map(|score| Score::new(score).roundup());

            summaries.push(AdvisorySummary {
                head: AdvisoryHead::from_entity(advisory, issuer, tx).await?,
                average_severity: average_severity
                    .as_ref()
                    .map(|severity| severity.to_string()),
                average_score: average_score.map(|score| score.value()),
                vulnerabilities,
            })
        }

        Ok(summaries)
    }
}
