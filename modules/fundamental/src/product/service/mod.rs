use crate::Error;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use trustify_common::db::limiter::LimiterTrait;
use trustify_common::db::query::{Filtering, Query};
use trustify_common::db::{Database, Transactional};
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_entity::product;
use uuid::Uuid;

use super::model::{ProductHead, ProductSummary};

pub struct ProductService {
    db: Database,
}

impl ProductService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn fetch_products<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        search: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<ProductSummary>, Error> {
        let connection = self.db.connection(&tx);

        let limiter = product::Entity::find().filtering(search)?.limiting(
            &connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            total,
            items: ProductSummary::from_entities(&limiter.fetch().await?, &connection).await?,
        })
    }

    pub async fn fetch_product<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        id: Uuid,
        tx: TX,
    ) -> Result<Option<ProductHead>, Error> {
        let connection = self.db.connection(&tx);

        if let Some(product) = product::Entity::find()
            .filter(product::Column::Id.eq(id))
            .one(&connection)
            .await?
        {
            Ok(Some(ProductHead::from_entity(&product, &connection).await?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod test;
