mod details;
mod summary;

pub use details::advisory_vulnerability::*;
pub use details::*;
pub use summary::*;

use crate::{organization::model::OrganizationSummary, Error};
use sea_orm::{prelude::Uuid, LoaderTrait, ModelTrait};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_common::{db::ConnectionOrTransaction, id::Id};
use trustify_entity::{advisory, labels::Labels, organization};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AdvisoryHead {
    #[serde(with = "uuid::serde::urn")]
    pub uuid: Uuid,
    pub identifier: String,
    pub hashes: Vec<Id>,
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
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
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
            uuid: entity.id,
            identifier: entity.identifier.clone(),
            hashes: vec![Id::Sha256(entity.sha256.clone())],
            issuer,
            published: entity.published,
            modified: entity.modified,
            withdrawn: entity.withdrawn,
            title: entity.title.clone(),
            labels: entity.labels.clone(),
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
                uuid: advisory.id,
                identifier: advisory.identifier.clone(),
                hashes: vec![Id::Sha256(advisory.sha256.clone())],
                issuer,
                published: advisory.published,
                modified: advisory.modified,
                withdrawn: advisory.withdrawn,
                title: advisory.title.clone(),
                labels: advisory.labels.clone(),
            })
        }

        Ok(heads)
    }
}
