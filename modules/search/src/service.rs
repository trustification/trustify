use crate::{
    model::{FoundAdvisory, FoundSbom, SearchOptions},
    query::Query,
};
use actix_web::{body::BoxBody, HttpResponse, ResponseError};
use sea_orm::EntityTrait;
use trustify_common::{
    db::{limiter::LimiterTrait, Database},
    error::ErrorInformation,
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{advisory, sbom};

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
        search: SearchOptions,
        paginated: Paginated,
    ) -> Result<PaginatedResults<FoundAdvisory>, Error> {
        let limiting = advisory::Entity::find().filtering(search)?.limiting(
            &self.db,
            paginated.offset,
            paginated.limit,
        );
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

    // `filters` should be of the form, "full text search({field}{op}{value})*", e.g.
    // "some text&published>=2020/11/11&location=localhost&severity=low|high&modified=true"
    pub async fn search_sboms<'a>(
        &self,
        search: SearchOptions,
        paginated: Paginated,
    ) -> Result<PaginatedResults<FoundSbom>, Error> {
        let limiting = sbom::Entity::find().filtering(search)?.limiting(
            &self.db,
            paginated.offset,
            paginated.limit,
        );
        Ok(PaginatedResults {
            total: limiting.total().await?,
            items: limiting
                .fetch()
                .await?
                .into_iter()
                .map(FoundSbom::from)
                .collect(),
        })
    }
}
