use crate::{
    advisory::model::{AdvisoryDetails, AdvisorySummary},
    Error,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTypeTrait, DatabaseBackend, DbErr, EntityTrait,
    FromQueryResult, IntoActiveModel, IntoIdentity, QueryResult, QuerySelect, QueryTrait,
    RelationTrait, Select, TransactionTrait,
};
use sea_query::{ColumnRef, ColumnType, Expr, Func, IntoColumnRef, IntoIden, JoinType, SimpleExpr};
use trustify_common::db::multi_model::{FromQueryResultMultiModel, SelectIntoMultiModel};
use trustify_common::{
    db::{
        limiter::LimiterAsModelTrait,
        query::{Columns, Filtering, Query},
        Database, Transactional,
    },
    id::{Id, TrySelectForId},
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{
    advisory,
    cvss3::{self, Severity},
    labels::Labels,
    organization, source_document,
};
use uuid::Uuid;

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
            .expr_as_(
                SimpleExpr::FunctionCall(Func::cust("cvss3_severity".into_identity()).arg(
                    SimpleExpr::FunctionCall(Func::avg(SimpleExpr::Column(
                        cvss3::Column::Score.into_column_ref(),
                    ))),
                )),
                "average_severity",
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
            .left_join(source_document::Entity)
            .join(JoinType::LeftJoin, advisory::Relation::Issuer.def())
            .column_as(
                SimpleExpr::Column(ColumnRef::Column(
                    "average_score".into_identity().into_iden(),
                )),
                "average_score",
            )
            .column_as(
                SimpleExpr::Column(ColumnRef::Column(
                    "average_severity".into_identity().into_iden(),
                ))
                .cast_as("TEXT".into_identity()),
                "average_severity",
            )
            .filtering_with(
                search,
                Columns::from_entity::<advisory::Entity>()
                    .add_column("average_score", ColumnType::Decimal(None).def())
                    .add_column(
                        "average_severity",
                        ColumnType::Enum {
                            name: "cvss3_severity".into_identity().into_iden(),
                            variants: vec![
                                "none".into_identity().into_iden(),
                                "low".into_identity().into_iden(),
                                "medium".into_identity().into_iden(),
                                "high".into_identity().into_iden(),
                                "critical".into_identity().into_iden(),
                            ],
                        }
                        .def(),
                    )
                    .translator(|f, op, v| match (f, v) {
                        // v = "" for all sort fields
                        ("average_severity", "") => Some(format!("average_score:{op}")),
                        _ => None,
                    }),
            )?
            .try_limiting_as_multi_model::<AdvisoryCatcher>(
                &connection,
                paginated.offset,
                paginated.limit,
            )?;

        let total = limiter.total().await?;

        let items = limiter.fetch().await?;

        Ok(PaginatedResults {
            total,
            items: AdvisorySummary::from_entities(&items, &connection).await?,
        })
    }

    pub async fn fetch_advisory<TX: AsRef<Transactional> + Sync + Send>(
        &self,
        id: Id,
        tx: TX,
    ) -> Result<Option<AdvisoryDetails>, Error> {
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
            .expr_as_(
                SimpleExpr::FunctionCall(Func::cust("cvss3_severity".into_identity()).arg(
                    SimpleExpr::FunctionCall(Func::avg(SimpleExpr::Column(
                        cvss3::Column::Score.into_column_ref(),
                    ))),
                )),
                "average_severity",
            )
            .group_by(advisory::Column::Id);

        let mut outer_query = advisory::Entity::find();

        // Alias the inner query as exactly the table the entity is expecting
        // so that column aliases link up correctly.
        QueryTrait::query(&mut outer_query)
            .from_clear()
            .from_subquery(inner_query.into_query(), "advisory".into_identity());

        let results = outer_query
            .left_join(source_document::Entity)
            .join(JoinType::LeftJoin, advisory::Relation::Issuer.def())
            .column_as(
                SimpleExpr::Column(ColumnRef::Column(
                    "average_score".into_identity().into_iden(),
                )),
                "average_score",
            )
            .column_as(
                SimpleExpr::Column(ColumnRef::Column(
                    "average_severity".into_identity().into_iden(),
                ))
                .cast_as("TEXT".into_identity()),
                "average_severity",
            )
            .try_filter(id)?
            .try_into_multi_model::<AdvisoryCatcher>()?
            .one(&connection)
            .await?;

        if let Some(catcher) = results {
            Ok(Some(
                AdvisoryDetails::from_entity(&catcher, &connection).await?,
            ))
        } else {
            Ok(None)
        }
    }

    /// delete one sbom
    pub async fn delete_advisory<TX: AsRef<Transactional>>(
        &self,
        id: Uuid,
        tx: TX,
    ) -> Result<u64, Error> {
        let connection = self.db.connection(&tx);

        let query = advisory::Entity::delete_by_id(id);

        let result = query.exec(&connection).await?;

        Ok(result.rows_affected)
    }

    /// Set the labels of an advisory
    ///
    /// Returns `Ok(Some(()))` if a document was found and updated. If no document was found, it will
    /// return `Ok(None)`.
    pub async fn set_labels(
        &self,
        id: Id,
        labels: Labels,
        tx: impl AsRef<Transactional>,
    ) -> Result<Option<()>, Error> {
        let db = self.db.connection(&tx);

        let result = advisory::Entity::update_many()
            .try_filter(id)?
            .col_expr(advisory::Column::Labels, Expr::value(labels))
            .exec(&db)
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
    pub average_score: Option<f64>,
    pub average_severity: Option<Severity>,
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
            average_score: res.try_get("", "average_score")?,
            average_severity: res.try_get("", "average_severity")?,
        })
    }
}

impl FromQueryResultMultiModel for AdvisoryCatcher {
    fn try_into_multi_model<E: EntityTrait>(select: Select<E>) -> Result<Select<E>, DbErr> {
        select
            .try_model_columns(advisory::Entity)?
            .try_model_columns(organization::Entity)?
            .try_model_columns(source_document::Entity)
    }
}

#[cfg(test)]
pub mod test;
