use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

pub mod details;
pub mod summary;

use crate::Error;
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{product, product_version};

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ProductHead {
    #[serde(with = "uuid::serde::urn")]
    #[schema(value_type=String)]
    pub id: Uuid,
    pub name: String,
}

impl ProductHead {
    pub async fn from_entity(
        product: &product::Model,
        _tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(ProductHead {
            id: product.id,
            name: product.name.clone(),
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ProductVersionHead {
    #[serde(with = "uuid::serde::urn")]
    #[schema(value_type=String)]
    pub id: Uuid,
    pub version: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "trustify_common::uuid::serde::urn"
    )]
    #[schema(value_type=String)]
    pub sbom_id: Option<Uuid>,
}

impl ProductVersionHead {
    pub async fn from_entity(
        product_version: &product_version::Model,
        _tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(ProductVersionHead {
            id: product_version.id,
            version: product_version.version.clone(),
            sbom_id: product_version.sbom_id,
        })
    }

    pub async fn from_entities(
        product_versions: &[product_version::Model],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut heads = Vec::new();

        for entity in product_versions {
            heads.push(ProductVersionHead::from_entity(entity, tx).await?);
        }

        Ok(heads)
    }
}
