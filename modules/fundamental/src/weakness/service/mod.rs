use crate::{
    weakness::model::{WeaknessDetails, WeaknessSummary},
    Error,
};
use sea_orm::EntityTrait;
use trustify_common::{
    db::{
        limiter::LimiterTrait,
        query::{Filtering, Query},
        Database,
    },
    model::{Paginated, PaginatedResults},
};
use trustify_entity::weakness;

pub struct WeaknessService {
    db: Database,
}

impl WeaknessService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn list_weaknesses(
        &self,
        query: Query,
        paginated: Paginated,
    ) -> Result<PaginatedResults<WeaknessSummary>, Error> {
        let limiter = weakness::Entity::find().filtering(query)?.limiting(
            &self.db,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;
        let items = limiter.fetch().await?;

        Ok(PaginatedResults {
            items: WeaknessSummary::from_entities(&items).await?,
            total,
        })
    }

    pub async fn get_weakness(&self, id: &str) -> Result<Option<WeaknessDetails>, Error> {
        if let Some(found) = weakness::Entity::find_by_id(id).one(&self.db).await? {
            Ok(Some(WeaknessDetails::from_entity(&found).await?))
        } else {
            Ok(None)
        }
    }
}
