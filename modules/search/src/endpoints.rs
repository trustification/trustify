use crate::model::{AdvisorySearch, SearchOptions};
use crate::service::{Error, SearchService};
use actix_web::{get, web, Responder};
use sikula::prelude::Search;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use utoipa::OpenApi;

/// mount the "search" module
pub fn configure(svc: &mut web::ServiceConfig, db: Database) {
    svc.app_data(web::Data::new(SearchService::new(db)));
    svc.service(web::scope("/api/v1/search").service(search_advisories));
}

#[derive(OpenApi)]
#[openapi(paths(search_advisories), components(schemas()), tags())]
pub struct ApiDoc;

#[utoipa::path(
    context_path = "/api/v1/search/advisory",
    tag = "search",
    params(
        ("q", Query, description = "The query expression"),
    ),
    responses(
        (status = 200, description = "Advisory search result", body = [crate::model::PaginatedAdvisories])
    )
)]
#[get("/advisory")]
/// Search for advisories
async fn search_advisories(
    web::Query(SearchOptions { q }): web::Query<SearchOptions>,
    web::Query(paginated): web::Query<Paginated>,
    service: web::Data<SearchService>,
) -> Result<impl Responder, Error> {
    let search = AdvisorySearch::parse(&q)?;
    Ok(web::Json(
        service.search_advisories(search, paginated).await?,
    ))
}
