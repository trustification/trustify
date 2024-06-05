use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::advisory::model::{AdvisoryDetails, AdvisorySummary};
use crate::Error;
use trustify_common::db::limiter::LimiterTrait;
use trustify_common::db::query::{Filtering, Query};
use trustify_common::db::{Database, Transactional};
use trustify_common::hash::HashOrUuidKey;
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_entity::advisory;

pub struct AdvisoryService {
    db: Database,
}

impl AdvisoryService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn fetch_advisories<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        search: Query,
        paginated: Paginated,
        tx: TX,
    ) -> Result<PaginatedResults<AdvisorySummary>, Error> {
        let connection = self.db.connection(&tx);

        let limiter = advisory::Entity::find().filtering(search)?.limiting(
            &connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;

        Ok(PaginatedResults {
            total,
            items: AdvisorySummary::from_entities(&limiter.fetch().await?, &connection).await?,
        })
    }

    pub async fn fetch_advisory<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        hash_key: HashOrUuidKey,
        tx: TX,
    ) -> Result<Option<AdvisoryDetails>, Error> {
        let connection = self.db.connection(&tx);

        let results = advisory::Entity::find()
            .filter(match hash_key {
                HashOrUuidKey::Uuid(uuid) => advisory::Column::Id.eq(uuid),
                HashOrUuidKey::Sha256(hash) => advisory::Column::Sha256.eq(hash),
                _ => return Err(Error::UnsupportedHashAlgorithm),
            })
            .one(&connection)
            .await?;

        if let Some(advisory) = results {
            Ok(Some(
                AdvisoryDetails::from_entity(&advisory, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod test;
