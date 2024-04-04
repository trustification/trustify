use crate::model::{AdvisorySearch, AdvisorySearchSortable, FoundAdvisory};
use actix_web::{body::BoxBody, HttpResponse, ResponseError};
use sea_orm::sea_query::extension::postgres::PgExpr;
use sea_orm::sea_query::IntoCondition;
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder};
use sikula::prelude::*;
use sikula::sea_orm::{translate_term, TranslateOrdered};
use trustify_common::{
    db::{limiter::LimiterTrait, Database},
    error::ErrorInformation,
    model::{Paginated, PaginatedResults},
};
use trustify_entity::advisory;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("query syntax error: {0}")]
    SearchSyntax(String),
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),
}

impl From<sikula::prelude::Error<'_>> for Error {
    fn from(value: sikula::prelude::Error) -> Self {
        Self::SearchSyntax(value.to_string())
    }
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse<BoxBody> {
        match self {
            Self::SearchSyntax(_) => HttpResponse::BadRequest().json(ErrorInformation {
                error: "SearchSyntax".into(),
                message: self.to_string(),
                details: None,
            }),
            _ => HttpResponse::InternalServerError().json(ErrorInformation {
                error: "Internal".into(),
                message: self.to_string(),
                details: None,
            }),
        }
    }
}

pub struct SearchService {
    db: Database,
}

impl SearchService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn search_advisories<'a>(
        &self,
        Query { term, sorting }: Query<'a, AdvisorySearch<'a>>,
        paginated: Paginated,
    ) -> Result<PaginatedResults<FoundAdvisory>, Error> {
        let mut select = advisory::Entity::find();

        select = select.filter(translate_term(term, &translate));

        for sort in sorting {
            let col = match sort.qualifier {
                AdvisorySearchSortable::Modified => advisory::Column::Modified,
                AdvisorySearchSortable::Published => advisory::Column::Published,
            };
            select = select.order_by(col, sort.direction.into());
        }

        // we always sort by ID last, so that we have a stable order for pagination

        select = select.order_by_desc(advisory::Column::Id);

        let limiting = select.limiting(&self.db, paginated.offset, paginated.limit);

        Ok(PaginatedResults {
            total: limiting.total().await?,
            items: limiting
                .fetch()
                .await?
                .into_iter()
                .map(FoundAdvisory::from)
                .collect(),
        })
    }
}

fn translate(term: AdvisorySearch) -> Condition {
    match term {
        AdvisorySearch::Title(Primary::Equal(value)) => {
            advisory::Column::Title.eq(value).into_condition()
        }
        AdvisorySearch::Title(Primary::Partial(value)) => advisory::Column::Title
            .into_expr()
            .ilike(format!(
                "%{}%",
                value.replace('%', "\\%").replace('_', "\\_")
            ))
            .into_condition(),
        AdvisorySearch::Published(value) => value.translate(advisory::Column::Published),
        AdvisorySearch::Modified(value) => value.translate(advisory::Column::Modified),
    }
}
