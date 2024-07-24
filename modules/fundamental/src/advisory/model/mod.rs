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
    /// The opaque UUID of the advisory.
    #[serde(with = "uuid::serde::urn")]
    pub uuid: Uuid,

    /// The identifier of the advisory, as assigned by the issuing organization.
    pub identifier: String,

    /// Hashes of the underlying original document as ingested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hashes: Vec<Id>,

    /// The issuer of the advisory, if known. If no issuer is able to be
    /// determined, this field will not be included in a response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<OrganizationSummary>,

    /// The date (in RFC3339 format) of when the advisory was published, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,

    /// The date (in RFC3339 format) of when the advisory was last modified, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub modified: Option<OffsetDateTime>,

    /// The date (in RFC3339 format) of when the advisory was withdrawn, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "time::serde::rfc3339::option")]
    pub withdrawn: Option<OffsetDateTime>,

    /// The title of the advisory as assigned by the issuing organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Informational labels attached by the system or users to this advisory.
    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
}

impl AdvisoryHead {
    pub async fn from_advisory(
        entity: &advisory::Model,
        issuer: Option<Option<organization::Model>>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let issuer = match &issuer {
            Some(Some(issuer)) => Some(OrganizationSummary::from_entity(issuer, tx).await?),
            Some(None) => None,
            None => {
                if let Some(issuer) = entity.find_related(organization::Entity).one(tx).await? {
                    Some(OrganizationSummary::from_entity(&issuer, tx).await?)
                } else {
                    None
                }
            }
        };

        Ok(Self {
            uuid: entity.id,
            identifier: entity.identifier.clone(),
            hashes: Id::build_vec(
                entity.sha256.clone(),
                entity.sha384.clone(),
                entity.sha512.clone(),
            ),
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
                hashes: Id::build_vec(
                    advisory.sha256.clone(),
                    advisory.sha384.clone(),
                    advisory.sha512.clone(),
                ),
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
