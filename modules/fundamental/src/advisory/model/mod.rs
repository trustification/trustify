mod details;
mod summary;

pub use details::advisory_vulnerability::*;
pub use details::*;
pub use summary::*;

use crate::{organization::model::OrganizationSummary, Error};
use sea_orm::{prelude::Uuid, LoaderTrait, ModelTrait};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use trustify_common::db::ConnectionOrTransaction;
use trustify_common::memo::Memo;
use trustify_entity::{advisory, labels::Labels, organization};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, PartialEq, Eq)]
pub struct AdvisoryHead {
    /// The opaque UUID of the advisory.
    #[serde(with = "uuid::serde::urn")]
    #[schema(value_type=String)]
    pub uuid: Uuid,

    /// The identifier of the advisory, as assigned by the issuing organization.
    pub identifier: String,

    /// The issuer of the advisory, if known. If no issuer is able to be
    /// determined, this field will not be included in a response.
    #[schema(required)]
    pub issuer: Option<OrganizationSummary>,

    /// The date (in RFC3339 format) of when the advisory was published, if any.
    #[schema(required)]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,

    /// The date (in RFC3339 format) of when the advisory was last modified, if any.
    #[serde(with = "time::serde::rfc3339::option")]
    pub modified: Option<OffsetDateTime>,

    /// The date (in RFC3339 format) of when the advisory was withdrawn, if any.
    #[schema(required)]
    #[serde(with = "time::serde::rfc3339::option")]
    pub withdrawn: Option<OffsetDateTime>,

    /// The title of the advisory as assigned by the issuing organization.
    #[schema(required)]
    pub title: Option<String>,

    /// Informational labels attached by the system or users to this advisory.
    pub labels: Labels,
}

impl AdvisoryHead {
    pub async fn from_advisory(
        advisory: &advisory::Model,
        issuer: Memo<organization::Model>,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let issuer = match &issuer {
            Memo::Provided(Some(issuer)) => {
                Some(OrganizationSummary::from_entity(issuer, tx).await?)
            }
            Memo::Provided(None) => None,
            Memo::NotProvided => {
                if let Some(issuer) = advisory.find_related(organization::Entity).one(tx).await? {
                    Some(OrganizationSummary::from_entity(&issuer, tx).await?)
                } else {
                    None
                }
            }
        };

        Ok(Self {
            uuid: advisory.id,
            identifier: advisory.identifier.clone(),
            issuer,
            published: advisory.published,
            modified: advisory.modified,
            withdrawn: advisory.withdrawn,
            title: advisory.title.clone(),
            labels: advisory.labels.clone(),
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
