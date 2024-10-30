use crate::organization::model::OrganizationSummary;
use crate::product::model::{ProductHead, ProductVersionHead};
use crate::Error;
use itertools::izip;
use sea_orm::LoaderTrait;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::{organization, product, product_version};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
pub struct ProductSummary {
    #[serde(flatten)]
    pub head: ProductHead,
    pub versions: Vec<ProductVersionHead>,
    #[schema(required)]
    pub vendor: Option<OrganizationSummary>,
}

impl ProductSummary {
    pub async fn from_entity(
        product: &product::Model,
        org: Option<organization::Model>,
        versions: &[product_version::Model],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let vendor = if let Some(org) = org {
            Some(OrganizationSummary::from_entity(&org, tx).await?)
        } else {
            None
        };
        Ok(ProductSummary {
            head: ProductHead::from_entity(product, tx).await?,
            versions: ProductVersionHead::from_entities(versions, tx).await?,
            vendor,
        })
    }

    pub async fn from_entities(
        products: &[product::Model],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let versions = products.load_many(product_version::Entity, tx).await?;
        let orgs = products.load_one(organization::Entity, tx).await?;

        let mut summaries = Vec::new();

        for (product, org, version) in izip!(products, orgs, versions) {
            summaries.push(ProductSummary::from_entity(product, org, &version, tx).await?);
        }

        Ok(summaries)
    }
}
