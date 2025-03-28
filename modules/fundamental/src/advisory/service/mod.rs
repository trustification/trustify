use crate::{
    Error,
    advisory::model::{AdvisoryDetails, AdvisorySummary},
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectionTrait, DatabaseBackend, DbErr, EntityTrait,
    FromQueryResult, IntoActiveModel, QueryResult, QuerySelect, QueryTrait, RelationTrait, Select,
    Statement, TransactionTrait,
};
use sea_query::{Alias, Expr, JoinType};
use trustify_common::db::query::Filtering;
use trustify_common::{
    db::{
        Database, UpdateDeprecatedAdvisory,
        limiter::LimiterAsModelTrait,
        multi_model::{FromQueryResultMultiModel, SelectIntoMultiModel},
        query::{Columns, Query},
    },
    id::{Id, TrySelectForId},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{advisory, labels::Labels, organization, source_document};
use trustify_module_ingestor::common::{Deprecation, DeprecationExt};
use uuid::Uuid;

pub struct AdvisoryService {
    db: Database,
}

impl AdvisoryService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn fetch_advisories<C: ConnectionTrait + Sync + Send>(
        &self,
        search: Query,
        paginated: Paginated,
        deprecation: Deprecation,
        connection: &C,
    ) -> Result<PaginatedResults<AdvisorySummary>, Error> {
        let limiter = advisory::Entity::find()
            .with_deprecation(deprecation)
            .left_join(source_document::Entity)
            .join(JoinType::LeftJoin, advisory::Relation::Issuer.def())
            .filtering_with(
                search,
                Columns::from_entity::<advisory::Entity>()
                    .add_columns(source_document::Entity)
                    .translator(|f, op, v| match (f, v) {
                        // v = "" for all sort fields
                        ("advisory$average_severity", "") => Some(format!("average_score:{op}")),
                        _ => None,
                    }),
            )?
            .expr_as(
                Expr::col((
                    trustify_entity::advisory::Entity,
                    trustify_entity::advisory::Column::AverageSeverity,
                ))
                .cast_as(Alias::new("TEXT")),
                "advisory$average_severity",
            )
            .try_limiting_as_multi_model::<AdvisoryCatcher>(
                connection,
                paginated.offset,
                paginated.limit,
            )?;

        let total = limiter.total().await?;

        let items = limiter.fetch().await?;

        Ok(PaginatedResults {
            total,
            items: AdvisorySummary::from_entities(&items, connection).await?,
        })
    }

    pub async fn fetch_advisory<C: ConnectionTrait + Sync + Send>(
        &self,
        id: Id,
        connection: &C,
    ) -> Result<Option<AdvisoryDetails>, Error> {
        let results = advisory::Entity::find()
            .left_join(source_document::Entity)
            .join(JoinType::LeftJoin, advisory::Relation::Issuer.def())
            .try_filter(id)?
            .expr_as(
                Expr::col((
                    trustify_entity::advisory::Entity,
                    trustify_entity::advisory::Column::AverageSeverity,
                ))
                .cast_as(Alias::new("TEXT")),
                "advisory$average_severity",
            )
            .try_into_multi_model::<AdvisoryCatcher>()?
            .one(connection)
            .await?;

        if let Some(catcher) = results {
            Ok(Some(
                AdvisoryDetails::from_entity(&catcher, connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    /// delete one advisory
    pub async fn delete_advisory<C: ConnectionTrait>(
        &self,
        id: Uuid,
        connection: &C,
    ) -> Result<u64, Error> {
        let stmt = Statement::from_sql_and_values(
            connection.get_database_backend(),
            r#"DELETE FROM advisory WHERE id=$1 RETURNING identifier"#,
            [id.into()],
        );

        let result = connection.query_all(stmt).await?;
        let rows_affected = result.len();

        for row in result {
            let identifier = row.try_get_by_index::<String>(0)?;
            UpdateDeprecatedAdvisory::execute(connection, &identifier).await?;
        }

        Ok(rows_affected as u64)
    }

    /// Set the labels of an advisory
    ///
    /// Returns `Ok(Some(()))` if a document was found and updated. If no document was found, it will
    /// return `Ok(None)`.
    pub async fn set_labels<C: ConnectionTrait>(
        &self,
        id: Id,
        labels: Labels,
        connection: &C,
    ) -> Result<Option<()>, Error> {
        let result = advisory::Entity::update_many()
            .try_filter(id)?
            .col_expr(advisory::Column::Labels, Expr::value(labels))
            .exec(connection)
            .await?;

        Ok((result.rows_affected > 0).then_some(()))
    }

    /// Update the labels of an advisory
    ///
    /// Returns `Ok(Some(()))` if a document was found and updated. If no document was found, it will
    /// return `Ok(None)`.
    ///
    /// The function will handle its own transaction.
    pub async fn update_labels<F>(&self, id: Id, mutator: F) -> Result<Option<()>, Error>
    where
        F: FnOnce(Labels) -> Labels,
    {
        let tx = self.db.begin().await?;

        // work around missing "FOR UPDATE" issue

        let mut query = advisory::Entity::find()
            .try_filter(id)?
            .build(DatabaseBackend::Postgres);

        query.sql.push_str(" FOR UPDATE");

        // find the current entry

        let Some(result) = advisory::Entity::find()
            .from_raw_sql(query)
            .one(&tx)
            .await?
        else {
            // return early, nothing found
            return Ok(None);
        };

        // perform the mutation

        let labels = result.labels.clone();
        let mut result = result.into_active_model();
        result.labels = Set(mutator(labels));

        // store

        result.update(&tx).await?;

        // commit

        tx.commit().await?;

        // return

        Ok(Some(()))
    }
}

#[derive(Debug)]
pub struct AdvisoryCatcher {
    pub source_document: Option<source_document::Model>,
    pub advisory: advisory::Model,
    pub issuer: Option<organization::Model>,
}

impl FromQueryResult for AdvisoryCatcher {
    fn from_query_result(res: &QueryResult, _pre: &str) -> Result<Self, DbErr> {
        Ok(Self {
            source_document: Self::from_query_result_multi_model_optional(
                res,
                "",
                source_document::Entity,
            )?,
            advisory: Self::from_query_result_multi_model(res, "", advisory::Entity)?,
            issuer: Self::from_query_result_multi_model_optional(res, "", organization::Entity)?,
        })
    }
}

impl FromQueryResultMultiModel for AdvisoryCatcher {
    fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr> {
        select
            .try_model_columns_excluding(advisory::Entity, &[advisory::Column::AverageSeverity])?
            .try_model_columns(organization::Entity)?
            .try_model_columns(source_document::Entity)
    }
}

#[cfg(test)]
pub mod test;
