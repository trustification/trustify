pub mod advisory_vulnerability;

use crate::advisory::service::AdvisoryCatcher;
use crate::source_document::model::SourceDocument;
use crate::{advisory::model::AdvisoryHead, Error};
use advisory_vulnerability::AdvisoryVulnerabilitySummary;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_common::memo::Memo;
use trustify_cvss::cvss3::severity::Severity;
use trustify_entity::{self as entity};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryDetails {
    #[serde(flatten)]
    pub head: AdvisoryHead,

    #[serde(flatten)]
    pub source_document: Option<SourceDocument>,

    /// Vulnerabilities addressed within this advisory.
    pub vulnerabilities: Vec<AdvisoryVulnerabilitySummary>,

    /// Average (arithmetic mean) severity of the advisory aggregated from *all* related vulnerability assertions.
    #[schema(required)]
    pub average_severity: Option<Severity>,

    /// Average (arithmetic mean) score of the advisory aggregated from *all* related vulnerability assertions.
    #[schema(required)]
    pub average_score: Option<f64>,
}

impl AdvisoryDetails {
    pub async fn from_entity(
        advisory: &AdvisoryCatcher,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let vulnerabilities = entity::vulnerability::Entity::find()
            .right_join(entity::advisory_vulnerability::Entity)
            .column_as(
                entity::advisory_vulnerability::Column::VulnerabilityId,
                entity::vulnerability::Column::Id,
            )
            .filter(entity::advisory_vulnerability::Column::AdvisoryId.eq(advisory.advisory.id))
            .all(tx)
            .await?;

        let vulnerabilities =
            AdvisoryVulnerabilitySummary::from_entities(&advisory.advisory, &vulnerabilities, tx)
                .await?;

        Ok(AdvisoryDetails {
            head: AdvisoryHead::from_advisory(
                &advisory.advisory,
                Memo::Provided(advisory.issuer.clone()),
                tx,
            )
            .await?,
            source_document: if let Some(doc) = &advisory.source_document {
                Some(SourceDocument::from_entity(doc, tx).await?)
            } else {
                None
            },
            vulnerabilities,
            average_severity: advisory.average_severity.map(|sev| sev.into()),
            average_score: advisory.average_score,
        })
    }
}
