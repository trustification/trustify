mod signature;
mod trust_anchor;

pub use signature::*;
pub use trust_anchor::*;

use crate::error::Error;
use sea_orm::{ConnectionTrait, EntityTrait, QueryFilter};
use trustify_common::id::{Id, TryFilterForId};
use trustify_entity::{advisory, sbom, source_document};

#[derive(Copy, Clone, Eq, PartialEq, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum DocumentType {
    Advisory,
    Sbom,
}

impl DocumentType {
    pub async fn find_source_document(
        &self,
        id: Id,
        db: &impl ConnectionTrait,
    ) -> Result<Option<source_document::Model>, Error> {
        Ok(match self {
            DocumentType::Advisory => {
                source_document::Entity::find()
                    .reverse_join(advisory::Entity)
                    .filter(advisory::Entity::try_filter(id)?)
                    .one(db)
                    .await?
            }
            DocumentType::Sbom => {
                source_document::Entity::find()
                    .reverse_join(sbom::Entity)
                    .filter(sbom::Entity::try_filter(id)?)
                    .one(db)
                    .await?
            }
        })
    }
}
