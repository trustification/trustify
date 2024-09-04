use crate::purl::service::PurlService;
use crate::Error;
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;
use std::str::FromStr;
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::id::IdError;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use utoipa::OpenApi;

mod base;
mod r#type;
mod version;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
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

#[derive(OpenApi)]
#[openapi(
    paths(
        r#type::all_purl_types,
        r#type::get_purl_type,
        r#type::get_base_purl_of_type,
        r#type::get_versioned_purl_of_type,
        base::all_base_purls,
        base::get_base_purl,
        version::get_versioned_purl,
        get,
        all,
    ),
    components(schemas(
        crate::purl::model::TypeHead,
        crate::purl::model::PurlHead,
        crate::purl::model::VersionedPurlHead,
        crate::purl::model::BasePurlHead,
        crate::purl::model::summary::r#type::TypeSummary,
        crate::purl::model::summary::r#type::TypeCounts,
        crate::purl::model::summary::base_purl::BasePurlSummary,
        crate::purl::model::details::base_purl::BasePurlDetails,
        crate::purl::model::summary::base_purl::PaginatedBasePurlSummary,
        crate::purl::model::summary::versioned_purl::VersionedPurlSummary,
        crate::purl::model::details::versioned_purl::VersionedPurlDetails,
        crate::purl::model::details::versioned_purl::VersionedPurlAdvisory,
        crate::purl::model::details::versioned_purl::VersionedPurlStatus,
        crate::purl::model::details::purl::PurlDetails,
        crate::purl::model::details::purl::PurlAdvisory,
        crate::purl::model::details::purl::PurlStatus,
        crate::purl::model::details::purl::PurlLicenseSummary,
        crate::purl::model::summary::purl::PurlSummary,
        crate::purl::model::summary::purl::PaginatedPurlSummary,
        trustify_common::purl::Purl,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    context_path= "/api",
    operation_id = "getPurl",
    tag = "purl",
    params(
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
) -> actix_web::Result<impl Responder> {
    if key.starts_with("pkg") {
        let purl = Purl::from_str(&key).map_err(Error::Purl)?;
        Ok(HttpResponse::Ok().json(service.purl_by_purl(&purl, ()).await?))
    } else {
        let id = Uuid::from_str(&key).map_err(|e| Error::IdKey(IdError::InvalidUuid(e)))?;
        Ok(HttpResponse::Ok().json(service.purl_by_uuid(&id, ()).await?))
    }
}

#[utoipa::path(
    context_path= "/api",
    operation_id = "listPurl",
    tag = "purl",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "All relevant matching qualified PURLs", body = PaginatedPurlSummary),
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
