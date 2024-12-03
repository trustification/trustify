use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};
use serde::{Deserialize, Serialize};
use trustify_common::memo::Memo;
use trustify_cvss::cvss3::score::Score;
use trustify_entity::{advisory_vulnerability, vulnerability};
use utoipa::ToSchema;

use crate::advisory::model::{AdvisoryHead, AdvisoryVulnerabilityHead};
use crate::advisory::service::AdvisoryCatcher;
use crate::source_document::model::SourceDocument;
use crate::Error;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisorySummary {
    #[serde(flatten)]
    pub head: AdvisoryHead,

    /// Information pertaning to the underlying source document, if any.
    #[serde(flatten)]
    pub source_document: Option<SourceDocument>,

    /// Average (arithmetic mean) severity of the advisory aggregated from *all* related vulnerability assertions.
    #[schema(required)]
    pub average_severity: Option<String>,

    /// Average (arithmetic mean) score of the advisory aggregated from *all* related vulnerability assertions.
    #[schema(required)]
    pub average_score: Option<f64>,

    /// Vulnerabilities addressed within this advisory.
    pub vulnerabilities: Vec<AdvisoryVulnerabilityHead>,
}

impl AdvisorySummary {
    pub async fn from_entities<C: ConnectionTrait>(
        entities: &[AdvisoryCatcher],
        tx: &C,
    ) -> Result<Vec<Self>, Error> {
        let mut summaries = Vec::with_capacity(entities.len());

        for each in entities {
            let vulnerabilities = vulnerability::Entity::find()
                .right_join(advisory_vulnerability::Entity)
                .column_as(
                    advisory_vulnerability::Column::VulnerabilityId,
                    vulnerability::Column::Id,
                )
                .filter(advisory_vulnerability::Column::AdvisoryId.eq(each.advisory.id))
                .all(tx)
                .await?;

            let vulnerabilities =
                AdvisoryVulnerabilityHead::from_entities(&each.advisory, &vulnerabilities, tx)
                    .await?;

            let average_score = each.average_score.map(|score| Score::new(score).roundup());

            summaries.push(AdvisorySummary {
                head: AdvisoryHead::from_advisory(
                    &each.advisory,
                    Memo::Provided(each.issuer.clone()),
                    tx,
                )
                .await?,
                source_document: if let Some(doc) = &each.source_document {
                    Some(SourceDocument::from_entity(doc).await?)
                } else {
                    None
                },
                average_severity: each
                    .average_severity
                    .as_ref()
                    .map(|severity| severity.to_string()),
                average_score: average_score.map(|score| score.value()),
                vulnerabilities,
            })
        }

        Ok(summaries)
    }
}
