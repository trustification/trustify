pub mod product_version;

use entity::organization;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set};
use trustify_common::db::Transactional;
use trustify_entity as entity;
use trustify_entity::product;

use crate::graph::{error::Error, Graph};

use self::product_version::ProductVersionContext;

use super::organization::OrganizationContext;

#[derive(Clone)]
pub struct ProductContext<'g> {
    graph: &'g Graph,
    pub product: product::Model,
}

impl<'g> ProductContext<'g> {
    pub fn new(graph: &'g Graph, product: product::Model) -> Self {
        Self { graph, product }
    }

    pub async fn ingest_product_version<TX: AsRef<Transactional>>(
        &self,
        version: String,
        tx: TX,
    ) -> Result<ProductVersionContext<'g>, Error> {
        let model = entity::product_version::ActiveModel {
            id: Default::default(),
            product_id: Set(self.product.id),
            sbom_id: Set(None),
            version: Set(version.clone()),
        };

        Ok(ProductVersionContext::new(
            self,
            model.insert(&self.graph.connection(&tx)).await?,
        ))
    }

    pub async fn get_vendor<TX: AsRef<Transactional>>(
        &self,
        tx: TX,
    ) -> Result<Option<OrganizationContext>, Error> {
        match self
            .product
            .find_related(organization::Entity)
            .one(&self.graph.connection(&tx))
            .await?
        {
            Some(org) => Ok(Some(OrganizationContext::new(self.graph, org))),
            None => Ok(None),
        }
    }
}

#[derive(Clone, Default)]
pub struct ProductInformation {
    pub vendor: Option<String>,
}

impl ProductInformation {
    pub fn has_data(&self) -> bool {
        self.vendor.is_some()
    }
}

impl From<()> for ProductInformation {
    fn from(_value: ()) -> Self {
        Self::default()
    }
}

impl super::Graph {
    pub async fn ingest_product<TX: AsRef<Transactional>>(
        &self,
        name: impl Into<String>,
        information: impl Into<ProductInformation>,
        tx: TX,
    ) -> Result<ProductContext, Error> {
        let name = name.into();
        let information = information.into();

        let vendor = if let Some(vendor) = information.vendor {
            Some(self.ingest_organization(vendor, (), &tx).await?)
        } else {
            None
        };

        let entity = product::ActiveModel {
            id: Default::default(),
            name: Set(name),
            vendor_id: Set(vendor.map(|org| org.organization.id)),
        };

        Ok(ProductContext::new(
            self,
            entity.insert(&self.connection(&tx)).await?,
        ))
    }

    pub async fn get_product_by_name<TX: AsRef<Transactional>>(
        &self,
        name: impl Into<String>,
        tx: TX,
    ) -> Result<Option<ProductContext>, Error> {
        Ok(product::Entity::find()
            .filter(product::Column::Name.eq(name.into()))
            .one(&self.connection(&tx))
            .await?
            .map(|product| ProductContext::new(self, product)))
    }
}
