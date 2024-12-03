use crate::{
    organization::model::{OrganizationDetails, OrganizationSummary},
    Error,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use trustify_common::{
    db::{
        limiter::LimiterTrait,
        query::{Filtering, Query},
    },
    model::{Paginated, PaginatedResults},
};
use trustify_entity::organization;
use uuid::Uuid;

#[derive(Default)]
pub struct OrganizationService {}

impl OrganizationService {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn fetch_organizations<C: ConnectionTrait>(
        &self,
        search: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<OrganizationSummary>, Error> {
        let limiter = organization::Entity::find().filtering(search)?.limiting(
            connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            total,
            items: OrganizationSummary::from_entities(&limiter.fetch().await?).await?,
        })
    }
    pub async fn fetch_organization<C: ConnectionTrait>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<Option<OrganizationDetails>, Error> {
        if let Some(organization) = organization::Entity::find()
            .filter(organization::Column::Id.eq(id))
            .one(connection)
            .await?
        {
            Ok(Some(
                OrganizationDetails::from_entity(&organization, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod test;
