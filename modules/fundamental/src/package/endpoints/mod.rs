use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;
use trustify_common::db::Database;
use utoipa::OpenApi;

mod ecosystem;

mod base;

mod version;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let advisory_service = PackageService::new(db);

    config
        .app_data(web::Data::new(advisory_service))
        .service(ecosystem::all)
        .service(ecosystem::get)
        .service(ecosystem::get_package)
        .service(ecosystem::get_package_version)
        .service(base::get)
        .service(version::get)
        .service(get);
}

#[derive(OpenApi)]
#[openapi(
    paths(
        ecosystem::all,
        ecosystem::get,
        ecosystem::get_package,
        ecosystem::get_package_version,
        base::get,
        version::get,
        get,
    ),
    components(schemas(
        crate::package::model::QualifiedPackageHead,
        crate::package::model::PackageVersionHead,
        crate::package::model::PackageHead,
        crate::package::model::summary::package::PackageSummary,
        crate::package::model::summary::package::PaginatedPackageSummary,
        crate::package::model::details::package::PackageDetails,
        crate::package::model::details::package_version::PackageVersionDetails,
        crate::package::model::details::qualified_package::QualifiedPackageDetails,
        trustify_common::purl::Purl,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "package",
    params(
    ),
    responses(
        (status = 200, description = "Details for the qualified package", body = QualifiedPackageDetails),
    ),
)]
#[get("/api/v1/package/{uuid}")]
pub async fn get(
    service: web::Data<PackageService>,
    uuid: web::Path<Uuid>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.qualified_package_by_uuid(&uuid, ()).await?))
}

#[cfg(test)]
mod test;
