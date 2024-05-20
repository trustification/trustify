use std::fmt::{Debug, Formatter};

use crate::graph::{error::Error, sbom::SbomContext};
use entity::{product_version, sbom};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use trustify_common::db::Transactional;
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

    pub async fn link_to_sbom<TX: AsRef<Transactional>>(
        &self,
        sbom_id: Uuid,
        tx: TX,
    ) -> Result<ProductVersionContext, Error> {
        let mut product_version: product_version::ActiveModel = self.product_version.clone().into();

        product_version.sbom_id = Set(Some(sbom_id));

        let ver = product_version
            .update(&self.product.graph.connection(&tx))
            .await?;

        Ok(ProductVersionContext::new(&self.product.clone(), ver))
    }

    pub async fn get_sbom<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Option<SbomContext>, Error> {
        match self.product_version.sbom_id {
            Some(sbom_id) => Ok(sbom::Entity::find_by_id(sbom_id)
                .one(&self.product.graph.connection(&tx))
                .await?
                .map(|sbom| SbomContext::new(self.product.graph, sbom))),
            None => Ok(None),
        }
    }
}
