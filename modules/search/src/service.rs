use std::str::FromStr;

use crate::{
    model::FoundAdvisory,
    query::{Filter, Sort},
};
use actix_web::{body::BoxBody, HttpResponse, ResponseError};
use sea_orm::{EntityTrait, QueryFilter, QueryOrder};
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

    // `filters` should be of the form, "full text search({field}{op}{value})*", e.g.
    // "some text&published>=2020/11/11&location=localhost&severity=low|high&modified=true"
    pub async fn search_advisories<'a>(
        &self,
        filters: String,
        sort: String,
        paginated: Paginated,
    ) -> Result<PaginatedResults<FoundAdvisory>, Error> {
        let mut select = advisory::Entity::find()
            .filter(Filter::<advisory::Entity>::from_str(&filters)?.into_condition());

        // comma-delimited sort param, e.g. 'field1:asc,field2:desc'
        for s in sort
            .split(',')
            .map(Sort::<advisory::Entity>::from_str)
            .collect::<Result<Vec<_>, _>>()?
            .iter()
        {
            select = select.order_by(s.field, s.order.clone());
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
