use super::model::summary::ProductSummary;
use crate::{product::model::details::ProductDetails, Error};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use trustify_common::{
    db::{
        limiter::LimiterTrait,
        query::{Filtering, Query},
    },
    model::{Paginated, PaginatedResults},
};
use trustify_entity::product;
use uuid::Uuid;

#[derive(Default)]
pub struct ProductService {}

impl ProductService {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn fetch_products<C: ConnectionTrait + Sync + Send>(
        &self,
        search: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<ProductSummary>, Error> {
        let limiter = product::Entity::find().filtering(search)?.limiting(
            connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            total,
            items: ProductSummary::from_entities(&limiter.fetch().await?, connection).await?,
        })
    }

    pub async fn fetch_product<C: ConnectionTrait + Sync + Send>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<Option<ProductDetails>, Error> {
        if let Some(product) = product::Entity::find()
            .find_also_related(trustify_entity::organization::Entity)
            .filter(product::Column::Id.eq(id))
            .one(connection)
            .await?
        {
            Ok(Some(
                ProductDetails::from_entity(&product.0, product.1, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    pub async fn delete_product<C: ConnectionTrait + Sync + Send>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<u64, Error> {
        let query = product::Entity::delete_by_id(id);

        let result = query.exec(connection).await?;

        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod test;
