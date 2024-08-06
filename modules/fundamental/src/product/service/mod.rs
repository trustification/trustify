use super::model::summary::ProductSummary;
use crate::product::model::details::ProductDetails;
use crate::Error;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use trustify_common::db::limiter::LimiterTrait;
use trustify_common::db::query::{Filtering, Query};
use trustify_common::db::{Database, Transactional};
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_entity::product;
use uuid::Uuid;

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
    ) -> Result<Option<ProductDetails>, Error> {
        let connection = self.db.connection(&tx);

        if let Some(product) = product::Entity::find()
            .find_also_related(trustify_entity::organization::Entity)
            .filter(product::Column::Id.eq(id))
            .one(&connection)
            .await?
        {
            Ok(Some(
                ProductDetails::from_entity(&product.0, product.1, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_product<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        id: Uuid,
        tx: TX,
    ) -> Result<u64, Error> {
        let connection = self.db.connection(&tx);

        let query = product::Entity::delete_by_id(id);

        let result = query.exec(&connection).await?;

        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod test;
