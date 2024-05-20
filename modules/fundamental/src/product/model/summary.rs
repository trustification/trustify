use crate::product::model::ProductHead;
use crate::Error;
use serde::{Deserialize, Serialize};
use trustify_common::db::ConnectionOrTransaction;
use trustify_common::paginated;
use trustify_entity::product;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
pub struct ProductSummary {
    #[serde(flatten)]
    pub head: ProductHead,
}

paginated!(ProductSummary);

impl ProductSummary {
    pub async fn from_entity(
        product: &product::Model,
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Self, Error> {
        Ok(ProductSummary {
            head: ProductHead::from_entity(product, tx).await?,
        })
    }

    pub async fn from_entities(
        products: &[product::Model],
        tx: &ConnectionOrTransaction<'_>,
    ) -> Result<Vec<Self>, Error> {
        let mut summaries = Vec::new();

        for org in products {
            summaries.push(ProductSummary {
                head: ProductHead::from_entity(org, tx).await?,
            });
        }

        Ok(summaries)
    }
}
