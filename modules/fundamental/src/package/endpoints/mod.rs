use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use utoipa::OpenApi;

mod base;
mod r#type;
mod version;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let package_service = PackageService::new(db);

    config
        .app_data(web::Data::new(package_service))
        .service(r#type::all)
        .service(r#type::get)
        .service(r#type::get_purl)
        .service(r#type::get_purl_version)
        .service(base::get)
        .service(base::all)
        .service(version::get)
        .service(get)
        .service(all);
}

#[derive(OpenApi)]
#[openapi(
    paths(
        r#type::all,
        r#type::get,
        r#type::get_purl,
        r#type::get_purl_version,
        base::get,
        version::get,
        get,
        all,
    ),
    components(schemas(
        crate::package::model::TypeHead,
        crate::package::model::QualifiedPackageHead,
        crate::package::model::PackageVersionHead,
        crate::package::model::PackageHead,
        crate::package::model::summary::r#type::TypeSummary,
        crate::package::model::summary::package::PackageSummary,
        crate::package::model::summary::package::PaginatedPackageSummary,
        crate::package::model::summary::package_version::PackageVersionSummary,
        crate::package::model::summary::qualified_package::PaginatedQualifiedPackageSummary,
        crate::package::model::details::package::PackageDetails,
        crate::package::model::details::package_version::PackageVersionDetails,
        crate::package::model::details::qualified_package::QualifiedPackageDetails,
        crate::package::model::details::qualified_package::QualifiedPackageAdvisory,
        crate::package::model::details::qualified_package::QualifiedPackageStatus,
        trustify_common::purl::Purl,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    context_path= "/api",
    tag = "purl",
    params(
        ("id" = String, Path, description = "opaque identifier for a fully-qualified PURL")
    ),
    responses(
        (status = 200, description = "Details for the qualified PURL", body = QualifiedPackageDetails),
    ),
)]
#[get("/v1/package/by-purl/{id}")]
pub async fn get(
    service: web::Data<PackageService>,
    id: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.qualified_package_by_uuid(&id, ()).await?))
}

#[utoipa::path(
    context_path= "/api",
    tag = "purl",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "All relevant matching qualified PURLs", body = PaginatedQualifiedPackageSummary),
    ),
)]
#[get("/v1/package/by-purl")]
pub async fn all(
    service: web::Data<PackageService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.qualified_packages(search, paginated, ()).await?))
}

#[cfg(test)]
mod test;
