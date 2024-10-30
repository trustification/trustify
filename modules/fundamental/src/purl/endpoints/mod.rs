use crate::{
    endpoints::Deprecation,
    purl::{
        model::{details::purl::PurlDetails, summary::purl::PurlSummary},
        service::PurlService,
    },
    Error,
};
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;
use std::str::FromStr;
use trustify_common::{
    db::query::Query, db::Database, id::IdError, model::Paginated, model::PaginatedResults,
    purl::Purl,
};

mod base;
mod r#type;
mod version;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let purl_service = PurlService::new(db);

    config
        .app_data(web::Data::new(purl_service))
        .service(r#type::all_purl_types)
        .service(r#type::get_purl_type)
        .service(r#type::get_base_purl_of_type)
        .service(r#type::get_versioned_purl_of_type)
        .service(base::get_base_purl)
        .service(base::all_base_purls)
        .service(version::get_versioned_purl)
        .service(get)
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
#[get("/v1/purl/{key}")]
/// Retrieve details of a fully-qualified pURL
pub async fn get(
    service: web::Data<PurlService>,
    key: web::Path<String>,
    web::Query(Deprecation { deprecated }): web::Query<Deprecation>,
) -> actix_web::Result<impl Responder> {
    if key.starts_with("pkg") {
        let purl = Purl::from_str(&key).map_err(Error::Purl)?;
        Ok(HttpResponse::Ok().json(service.purl_by_purl(&purl, deprecated, ()).await?))
    } else {
        let id = Uuid::from_str(&key).map_err(|e| Error::IdKey(IdError::InvalidUuid(e)))?;
        Ok(HttpResponse::Ok().json(service.purl_by_uuid(&id, deprecated, ()).await?))
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
#[get("/v1/purl")]
/// List fully-qualified pURLs
pub async fn all(
    service: web::Data<PurlService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.purls(search, paginated, ()).await?))
}

#[cfg(test)]
mod test;
