use sea_orm::{LoaderTrait, ModelTrait};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::organization::OrganizationSummary;
use crate::Error;
pub use details::advisory_vulnerability::*;
pub use details::*;
pub use summary::*;
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{advisory, organization};

mod details;
mod summary;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryHead {
    pub identifier: String,
    pub sha256: String,
    pub issuer: Option<OrganizationSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub modified: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub withdrawn: Option<OffsetDateTime>,
    pub title: Option<String>,
}

impl AdvisoryHead {
    pub async fn from_entity(
        entity: &advisory::Model,
        issuer: Option<organization::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let issuer = if let Some(issuer) = issuer {
            Some(OrganizationSummary::from_entity(&issuer, tx).await?)
        } else if let Some(issuer) = entity.find_related(organization::Entity).one(tx).await? {
            Some(OrganizationSummary::from_entity(&issuer, tx).await?)
        } else {
            None
        };

        Ok(Self {
            identifier: entity.identifier.clone(),
            sha256: entity.sha256.clone(),
            issuer,
            published: entity.published,
            modified: entity.modified,
            withdrawn: entity.withdrawn,
            title: entity.title.clone(),
        })
    }

    pub async fn from_entities(
        entities: &[advisory::Model],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut heads = Vec::new();

        let issuers = entities.load_one(organization::Entity, tx).await?;

        for (advisory, issuer) in entities.iter().zip(issuers) {
            let issuer = if let Some(issuer) = issuer {
                Some(OrganizationSummary::from_entity(&issuer, tx).await?)
            } else {
                None
            };

            heads.push(Self {
                identifier: advisory.identifier.clone(),
                sha256: advisory.sha256.clone(),
                issuer,
                published: advisory.published,
                modified: advisory.modified,
                withdrawn: advisory.withdrawn,
                title: advisory.title.clone(),
            })
        }

        Ok(heads)
    }
}
