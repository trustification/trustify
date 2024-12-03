use std::fmt::{Debug, Formatter};

use crate::graph::{error::Error, sbom::SbomContext};
use entity::{product_version, sbom};
use sea_orm::{ActiveModelTrait, ConnectionTrait, EntityTrait, Set};
use trustify_entity as entity;
use uuid::Uuid;

use super::ProductContext;

/// Live context for a product version.
#[derive(Clone)]
pub struct ProductVersionContext<'g> {
    pub product: ProductContext<'g>,
    pub product_version: entity::product_version::Model,
}

impl Debug for ProductVersionContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.product_version.fmt(f)
    }
}

impl<'g> ProductVersionContext<'g> {
    pub fn new(
        product: &ProductContext<'g>,
        product_version: entity::product_version::Model,
    ) -> Self {
        Self {
            product: product.clone(),
            product_version,
        }
    }

    pub async fn link_to_sbom<C: ConnectionTrait>(
        mut self,
        sbom_id: Uuid,
        connection: &C,
    ) -> Result<ProductVersionContext<'g>, Error> {
        let mut product_version: product_version::ActiveModel = self.product_version.clone().into();
        product_version.sbom_id = Set(Some(sbom_id));

        let ver = product_version.update(connection).await?;
        self.product_version.sbom_id = ver.sbom_id;

        Ok(self)
    }

    pub async fn get_sbom<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<Option<SbomContext>, Error> {
        match self.product_version.sbom_id {
            Some(sbom_id) => Ok(sbom::Entity::find_by_id(sbom_id)
                .one(connection)
                .await?
                .map(|sbom| SbomContext::new(self.product.graph, sbom))),
            None => Ok(None),
        }
    }
}
