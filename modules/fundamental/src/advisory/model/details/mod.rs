pub mod advisory_vulnerability;

use crate::{advisory::model::AdvisoryHead, Error};
use advisory_vulnerability::AdvisoryVulnerabilitySummary;
use sea_orm::{ColumnTrait, EntityTrait, ModelTrait, QueryFilter, QuerySelect};
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
        advisory: &entity::advisory::Model,
        average_score: Option<f64>,
        average_severity: Option<Severity>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let vulnerabilities = entity::vulnerability::Entity::find()
            .right_join(entity::advisory_vulnerability::Entity)
            .column_as(
                entity::advisory_vulnerability::Column::VulnerabilityId,
                entity::vulnerability::Column::Id,
            )
            .filter(entity::advisory_vulnerability::Column::AdvisoryId.eq(advisory.id))
            .all(tx)
            .await?;

        let vulnerabilities =
            AdvisoryVulnerabilitySummary::from_entities(advisory, &vulnerabilities, tx).await?;

        let issuer = advisory
            .find_related(entity::organization::Entity)
            .one(tx)
            .await?;

        Ok(AdvisoryDetails {
            head: AdvisoryHead::from_advisory(advisory, Memo::Provided(issuer), tx).await?,
            vulnerabilities,
            average_severity,
            average_score,
        })
    }
}
