use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

mod summary;
pub use summary::*;

use crate::Error;
use trustify_common::db::ConnectionOrTransaction;
use trustify_entity::product;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ProductHead {
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
