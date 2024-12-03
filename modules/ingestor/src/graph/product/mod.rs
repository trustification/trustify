pub mod product_version;

use entity::organization;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, ModelTrait, QueryFilter, Set,
};
use std::fmt::Debug;
use tracing::instrument;
use trustify_common::cpe::Cpe;
use trustify_entity as entity;
use trustify_entity::product;
use uuid::Uuid;

use crate::graph::{error::Error, organization::OrganizationInformation, Graph};

use self::product_version::ProductVersionContext;

use super::{advisory::advisory_vulnerability::VersionInfo, organization::OrganizationContext};

#[derive(Clone)]
pub struct ProductContext<'g> {
    graph: &'g Graph,
    pub product: product::Model,
}

impl<'g> ProductContext<'g> {
    pub fn new(graph: &'g Graph, product: product::Model) -> Self {
        Self { graph, product }
    }

    pub async fn ingest_product_version<C: ConnectionTrait>(
        &self,
        version: String,
        sbom_id: Option<Uuid>,
        connection: &C,
    ) -> Result<ProductVersionContext<'g>, Error> {
        if let Some(found) = self.get_version(version.clone(), connection).await? {
            let product_version = ProductVersionContext::new(self, found.product_version.clone());

            if let Some(id) = sbom_id {
                // If sbom is not yet set, link to the SBOM and update the context
                if found.product_version.sbom_id.is_none() {
                    Ok(product_version.link_to_sbom(id, connection).await?)
                } else {
                    Ok(product_version)
                }
            } else {
                Ok(product_version)
            }
        } else {
            let model = entity::product_version::ActiveModel {
                id: Default::default(),
                product_id: Set(self.product.id),
                sbom_id: Set(None),
                version: Set(version.clone()),
            };

            let product_version = ProductVersionContext::new(self, model.insert(connection).await?);

            // If there's an sbom_id, link to the SBOM and update the context
            if let Some(id) = sbom_id {
                Ok(product_version.link_to_sbom(id, connection).await?)
            } else {
                Ok(product_version)
            }
        }
    }

    pub async fn ingest_product_version_range<C: ConnectionTrait>(
        &self,
        info: VersionInfo,
        cpe_key: Option<String>,
        connection: &C,
    ) -> Result<entity::product_version_range::Model, Error> {
        let version_range = info.into_active_model();
        let version_range = version_range.insert(connection).await?;

        let model = entity::product_version_range::ActiveModel {
            id: Default::default(),
            product_id: Set(self.product.id),
            version_range_id: Set(version_range.id),
            cpe_key: Set(cpe_key),
        };

        Ok(model.insert(connection).await?)
    }

    pub async fn get_vendor<C: ConnectionTrait>(
        &self,
        connection: &C,
    ) -> Result<Option<OrganizationContext>, Error> {
        match self
            .product
            .find_related(organization::Entity)
            .one(connection)
            .await?
        {
            Some(org) => Ok(Some(OrganizationContext::new(self.graph, org))),
            None => Ok(None),
        }
    }

    pub async fn get_version<C: ConnectionTrait>(
        &self,
        version: String,
        connection: &C,
    ) -> Result<Option<ProductVersionContext>, Error> {
        match self
            .product
            .find_related(entity::product_version::Entity)
            .filter(entity::product_version::Column::Version.eq(version))
            .one(connection)
            .await?
        {
            Some(ver) => Ok(Some(ProductVersionContext::new(self, ver))),
            None => Ok(None),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct ProductInformation {
    pub vendor: Option<String>,
    pub cpe: Option<Cpe>,
}

impl ProductInformation {
    pub fn has_data(&self) -> bool {
        self.vendor.is_some() || self.cpe.is_some()
    }
}

impl From<()> for ProductInformation {
    fn from(_value: ()) -> Self {
        Self::default()
    }
}

impl Graph {
    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn ingest_product<C: ConnectionTrait>(
        &self,
        name: impl Into<String> + Debug,
        information: impl Into<ProductInformation> + Debug,
        connection: &C,
    ) -> Result<ProductContext, Error> {
        let name = name.into();
        let information = information.into();
        let cpe_key = information
            .cpe
            .clone()
            .map(|cpe| cpe.product().as_ref().to_string());

        let entity = if let Some(vendor) = information.vendor {
            if let Some(found) = self
                .get_product_by_organization(vendor.clone(), &name, connection)
                .await?
            {
                return Ok(found);
            } else {
                let organization_cpe_key = information
                    .cpe
                    .clone()
                    .map(|cpe| cpe.vendor().as_ref().to_string());
                let org = OrganizationInformation {
                    cpe_key: organization_cpe_key,
                    website: None,
                };
                let org = self.ingest_organization(vendor, org, connection).await?;

                product::ActiveModel {
                    id: Default::default(),
                    name: Set(name),
                    cpe_key: Set(cpe_key),
                    vendor_id: Set(Some(org.organization.id)),
                }
            }
        } else {
            product::ActiveModel {
                id: Default::default(),
                name: Set(name),
                vendor_id: Set(None),
                cpe_key: Set(cpe_key),
            }
        };

        Ok(ProductContext::new(self, entity.insert(connection).await?))
    }

    #[instrument(skip(self, connection), err(level=tracing::Level::INFO))]
    pub async fn get_products(
        &self,
        connection: &impl ConnectionTrait,
    ) -> Result<Vec<ProductContext>, Error> {
        Ok(product::Entity::find()
            .all(connection)
            .await?
            .into_iter()
            .map(|product| ProductContext::new(self, product))
            .collect())
    }

    #[instrument(skip(self, connection), err)]
    pub async fn get_product_by_name<C: ConnectionTrait>(
        &self,
        name: impl Into<String> + Debug,
        connection: &C,
    ) -> Result<Option<ProductContext>, Error> {
        Ok(product::Entity::find()
            .filter(product::Column::Name.eq(name.into()))
            .one(connection)
            .await?
            .map(|product| ProductContext::new(self, product)))
    }

    #[instrument(skip(self, connection), err)]
    pub async fn get_product_by_organization<C: ConnectionTrait>(
        &self,
        org: impl Into<String> + Debug,
        name: impl Into<String> + Debug,
        connection: &C,
    ) -> Result<Option<ProductContext>, Error> {
        if let Some(found) = self.get_organization_by_name(org, connection).await? {
            Ok(found
                .organization
                .find_related(product::Entity)
                .filter(product::Column::Name.eq(name.into()))
                .one(connection)
                .await?
                .map(|product| ProductContext::new(self, product)))
        } else {
            Ok(None)
        }
    }
}
