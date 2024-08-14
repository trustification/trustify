pub mod product_version;

use entity::organization;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, ModelTrait, QueryFilter, Set};
use std::fmt::Debug;
use tracing::instrument;
use trustify_common::db::Transactional;
use trustify_entity as entity;
use trustify_entity::product;
use uuid::Uuid;

use crate::graph::{error::Error, Graph};

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

    pub async fn ingest_product_version<TX: AsRef<Transactional>>(
        &self,
        version: String,
        sbom_id: Option<Uuid>,
        tx: TX,
    ) -> Result<ProductVersionContext<'g>, Error> {
        if let Some(found) = self.get_version(version.clone(), &tx).await? {
            let product_version = ProductVersionContext::new(self, found.product_version.clone());

            if let Some(id) = sbom_id {
                // If sbom is not yet set, link to the SBOM and update the context
                if found.product_version.sbom_id.is_none() {
                    Ok(product_version.link_to_sbom(id, &tx).await?)
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

            let product_version =
                ProductVersionContext::new(self, model.insert(&self.graph.connection(&tx)).await?);

            // If there's an sbom_id, link to the SBOM and update the context
            if let Some(id) = sbom_id {
                Ok(product_version.link_to_sbom(id, &tx).await?)
            } else {
                Ok(product_version)
            }
        }
    }

    pub async fn ingest_product_version_range<TX: AsRef<Transactional>>(
        &self,
        info: VersionInfo,
        cpe_key: Option<String>,
        tx: TX,
    ) -> Result<entity::product_version_range::Model, Error> {
        let version_range = info.into_active_model();
        let version_range = version_range.insert(&self.graph.connection(&tx)).await?;

        let model = entity::product_version_range::ActiveModel {
            id: Default::default(),
            product_id: Set(self.product.id),
            version_range_id: Set(version_range.id),
            cpe_key: Set(cpe_key),
        };

        Ok(model.insert(&self.graph.connection(&tx)).await?)
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

    pub async fn get_version<TX: AsRef<Transactional>>(
        &self,
        version: String,
        tx: TX,
    ) -> Result<Option<ProductVersionContext>, Error> {
        match self
            .product
            .find_related(entity::product_version::Entity)
            .filter(entity::product_version::Column::Version.eq(version))
            .one(&self.graph.connection(&tx))
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

impl Graph {
    #[instrument(skip(self, tx), err)]
    pub async fn ingest_product<TX: AsRef<Transactional>>(
        &self,
        name: impl Into<String> + Debug,
        information: impl Into<ProductInformation> + Debug,
        tx: TX,
    ) -> Result<ProductContext, Error> {
        let name = name.into();
        let information = information.into();

        if let Some(vendor) = information.vendor {
            if let Some(found) = self
                .get_product_by_organization(vendor.clone(), &name, &tx)
                .await?
            {
                Ok(found)
            } else {
                let org = self.ingest_organization(vendor, (), &tx).await?;

                let entity = product::ActiveModel {
                    id: Default::default(),
                    name: Set(name),
                    vendor_id: Set(Some(org.organization.id)),
                };

                Ok(ProductContext::new(
                    self,
                    entity.insert(&self.connection(&tx)).await?,
                ))
            }
        } else {
            let entity = product::ActiveModel {
                id: Default::default(),
                name: Set(name),
                vendor_id: Set(None),
            };

            Ok(ProductContext::new(
                self,
                entity.insert(&self.connection(&tx)).await?,
            ))
        }
    }

    #[instrument(skip(self, tx), err)]
    pub async fn get_products(
        &self,
        tx: impl AsRef<Transactional>,
    ) -> Result<Vec<ProductContext>, Error> {
        Ok(product::Entity::find()
            .all(&self.connection(&tx))
            .await?
            .into_iter()
            .map(|product| ProductContext::new(self, product))
            .collect())
    }

    #[instrument(skip(self, tx), err)]
    pub async fn get_product_by_name<TX: AsRef<Transactional>>(
        &self,
        name: impl Into<String> + Debug,
        tx: TX,
    ) -> Result<Option<ProductContext>, Error> {
        Ok(product::Entity::find()
            .filter(product::Column::Name.eq(name.into()))
            .one(&self.connection(&tx))
            .await?
            .map(|product| ProductContext::new(self, product)))
    }

    #[instrument(skip(self, tx), err)]
    pub async fn get_product_by_organization<TX: AsRef<Transactional>>(
        &self,
        org: impl Into<String> + Debug,
        name: impl Into<String> + Debug,
        tx: TX,
    ) -> Result<Option<ProductContext>, Error> {
        if let Some(found) = self.get_organization_by_name(org, &tx).await? {
            Ok(found
                .organization
                .find_related(product::Entity)
                .filter(product::Column::Name.eq(name.into()))
                .one(&self.connection(&tx))
                .await?
                .map(|product| ProductContext::new(self, product)))
        } else {
            Ok(None)
        }
    }
}
