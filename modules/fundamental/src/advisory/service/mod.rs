use sea_orm::{
    ColumnTrait, ColumnTypeTrait, EntityTrait, FromQueryResult, IntoIdentity, QueryFilter,
    QuerySelect, QueryTrait,
};
use sea_query::{ColumnType, Func, IntoColumnRef, SimpleExpr};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::advisory::model::{AdvisoryDetails, AdvisorySummary};
use crate::Error;
use trustify_common::db::limiter::LimiterAsModelTrait;
use trustify_common::db::query::{Columns, Filtering, Query};
use trustify_common::db::{Database, Transactional};
use trustify_common::id::Id;
use trustify_common::model::{Paginated, PaginatedResults};
use trustify_entity::{advisory, cvss3};

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
        #[derive(FromQueryResult, Debug)]
        pub(crate) struct AdvisoryCatcher {
            pub id: Uuid,
            pub identifier: String,
            pub issuer_id: Option<i32>,
            pub location: String,
            pub sha256: String,
            pub published: Option<OffsetDateTime>,
            pub modified: Option<OffsetDateTime>,
            pub withdrawn: Option<OffsetDateTime>,
            pub title: Option<String>,
            // all of advisory, plus some.
            pub average_score: Option<f64>,
        }

        let connection = self.db.connection(&tx);

        // To be able to ORDER or WHERE using a synthetic column, we must first
        // SELECT col, extra_col FROM (SELECT col, random as extra_col FROM...)
        // which involves mucking about inside the Select<E> to re-target from
        // the original underlying table it expects the entity to live in.
        let inner_query = advisory::Entity::find()
            .left_join(cvss3::Entity)
            .expr_as_(
                SimpleExpr::FunctionCall(Func::avg(SimpleExpr::Column(
                    cvss3::Column::Score.into_column_ref(),
                ))),
                "average_score",
            )
            .group_by(advisory::Column::Id);

        let mut outer_query = advisory::Entity::find();

        // Alias the inner query as exactly the table the entity is expecting
        // so that column aliases link up correctly.
        QueryTrait::query(&mut outer_query)
            .from_clear()
            .from_subquery(inner_query.into_query(), "advisory".into_identity());

        // And then proceed as usual.
        let limiter = outer_query
            .filtering_with(
                search,
                Columns::from_entity::<advisory::Entity>()
                    .add_column("average_score", ColumnType::Decimal(None).def()),
            )?
            .limiting_as::<AdvisoryCatcher>(&connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;

        let items = limiter.fetch().await?;

        let averages: Vec<_> = items.iter().map(|e| e.average_score).collect();

        let entities: Vec<_> = items
            .into_iter()
            .map(|e| advisory::Model {
                id: e.id,
                identifier: e.identifier,
                issuer_id: e.issuer_id,
                location: e.location,
                sha256: e.sha256,
                published: e.published,
                modified: e.modified,
                withdrawn: e.withdrawn,
                title: e.title,
            })
            .collect();

        Ok(PaginatedResults {
            total,
            items: AdvisorySummary::from_entities(&entities, &averages, &connection).await?,
        })
    }

    pub async fn fetch_advisory<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        hash_key: Id,
        tx: TX,
    ) -> Result<Option<AdvisoryDetails>, Error> {
        let connection = self.db.connection(&tx);

        let results = advisory::Entity::find()
            .filter(match hash_key {
                Id::Uuid(uuid) => advisory::Column::Id.eq(uuid),
                Id::Sha256(hash) => advisory::Column::Sha256.eq(hash),
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
