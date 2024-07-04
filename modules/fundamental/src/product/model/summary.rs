use crate::organization::model::OrganizationSummary;
use crate::product::model::{ProductHead, ProductVersionHead};
use crate::Error;
use sea_orm::ModelTrait;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_common::paginated;
use trustify_entity::{organization, product, product_version};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
pub struct ProductSummary {
    #[serde(flatten)]
    pub head: ProductHead,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<ProductVersionHead>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<OrganizationSummary>,
}

paginated!(ProductSummary);

impl ProductSummary {
    pub async fn from_entity(
        product: &product::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        let product_versions = product
            .find_related(product_version::Entity)
            .all(tx)
            .await?;
        let org = product.find_related(organization::Entity).one(tx).await?;
        let vendor = if let Some(org) = org {
            Some(OrganizationSummary::from_entity(&org, tx).await?)
        } else {
            None
        };
        Ok(ProductSummary {
            head: ProductHead::from_entity(product, tx).await?,
            versions: ProductVersionHead::from_entities(product_versions, tx).await?,
            vendor,
        })
    }

    pub async fn from_entities(
        products: &[product::Model],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut summaries = Vec::new();

        for product in products {
            summaries.push(ProductSummary::from_entity(product, tx).await?);
        }

        Ok(summaries)
    }
}
