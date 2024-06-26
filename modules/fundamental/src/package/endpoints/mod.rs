use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use utoipa::OpenApi;

mod r#type;

mod base;

mod version;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let advisory_service = PackageService::new(db);

    config
        .app_data(web::Data::new(advisory_service))
        .service(r#type::all)
        .service(r#type::get)
        .service(r#type::get_package)
        .service(r#type::get_package_version)
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
        r#type::get_package,
        r#type::get_package_version,
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
    tag = "package",
    params(
        ("uuid" = String, Path, description = "opaque UUID identifier for a fully-qualified package")
    ),
    responses(
        (status = 200, description = "Details for the qualified package", body = QualifiedPackageDetails),
    ),
)]
#[get("/v1/package/{uuid}")]
pub async fn get(
    service: web::Data<PackageService>,
    uuid: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.qualified_package_by_uuid(&uuid, ()).await?))
}

#[utoipa::path(
    context_path= "/api",
    tag = "package",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "All relevant matching qualified packages", body = PaginatedQualifiedPackageSummary),
    ),
)]
#[get("/v1/package")]
pub async fn all(
    service: web::Data<PackageService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.qualified_packages(search, paginated, ()).await?))
}

#[cfg(test)]
mod test;
