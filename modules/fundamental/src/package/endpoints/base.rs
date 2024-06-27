use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;
use trustify_common::db::query::Query;
use trustify_common::model::Paginated;

#[utoipa::path(
    context_path= "/api",
    tag = "package",
    params(
        ("id" = String, Path, description = "opaque identifier for a base PURL")
    ),
    responses(
        (status = 200, description = "Details for the versionless base PURL", body = PackageDetails),
    ),
)]
#[get("/v1/package/by-purl/base/{id}")]
pub async fn get(
    service: web::Data<PackageService>,
    id: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.package_by_uuid(&id, ()).await?))
}

#[utoipa::path(
    context_path= "/api",
    tag = "purl",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "All relevant matching versionless base PURL", body = PaginatedPackageSummary),
    ),
)]
#[get("/v1/package/by-purl/base")]
pub async fn all(
    service: web::Data<PackageService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.packages(search, paginated, ()).await?))
}
