use crate::{
    endpoints::Deprecation,
    purl::{
        model::{details::purl::PurlDetails, summary::purl::PurlSummary},
        service::PurlService,
    },
};
use actix_web::{HttpResponse, Responder, get, post, web};
use trustify_auth::{ReadSbom, authorizer::Require};
use trustify_common::{db::Database, db::query::Query, model::Paginated, model::PaginatedResults};

use super::model::details::purl::{PurlsRequest, PurlsResponse};

mod base;
mod r#type;
mod version;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let purl_service = PurlService::new();

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(purl_service))
        .service(r#type::all_purl_types)
        .service(r#type::get_purl_type)
        .service(r#type::get_base_purl_of_type)
        .service(r#type::get_versioned_purl_of_type)
        .service(base::get_base_purl)
        .service(base::all_base_purls)
        .service(version::get_versioned_purl)
        .service(get)
        .service(get_multiple)
        .service(all);
}

#[utoipa::path(
    operation_id = "getPurl",
    tag = "purl",
    params(
        Deprecation,
        ("key" = String, Path, description = "opaque identifier for a fully-qualified PURL, or URL-encoded pURL itself")
    ),
    responses(
        (status = 200, description = "Details for the qualified PURL", body = PurlDetails),
    ),
)]
#[get("/v2/purl/{key}")]
/// Retrieve details of a fully-qualified pURL
pub async fn get(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    key: web::Path<String>,
    web::Query(Deprecation { deprecated }): web::Query<Deprecation>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let result_key = key.into_inner();
    let identifiers = vec![result_key.clone()];
    match service
        .fetch_purl_details(&identifiers, deprecated, db.as_ref())
        .await
    {
        Ok(details) => match details.get(&result_key) {
            Some(detail) => Ok(HttpResponse::Ok().json(detail)),
            None => Ok(HttpResponse::NotFound().body("Identifier not found")),
        },
        Err(error) => Ok(HttpResponse::InternalServerError()
            .body(format!("Error fetching purl {result_key}: {}", error))),
    }
}

#[utoipa::path(
    operation_id = "getPurls",
    tag = "purl",
    params(
        Deprecation
    ),
    request_body = PurlsRequest,
    responses(
        (status = 200, description = "Details for the qualified PURLs", body = PurlsResponse),
    ),
)]
#[post("/v2/purl")]
/// Retrieve details for multiple qualified PURLs
pub async fn get_multiple(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    request: web::Json<PurlsRequest>,
    web::Query(Deprecation { deprecated }): web::Query<Deprecation>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    match service
        .fetch_purl_details(&request.items, deprecated, db.as_ref())
        .await
    {
        Ok(details) => Ok(HttpResponse::Ok().json(details)),
        Err(error) => Ok(
            HttpResponse::InternalServerError().body(format!("Error fetching purls: {}", error))
        ),
    }
}

#[utoipa::path(
    operation_id = "listPurl",
    tag = "purl",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "All relevant matching qualified PURLs", body = PaginatedResults<PurlSummary>),
    ),
)]
#[get("/v2/purl")]
/// List fully-qualified pURLs
pub async fn all(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.purls(search, paginated, db.as_ref()).await?))
}

#[cfg(test)]
mod test;
