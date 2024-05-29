use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use sea_orm::prelude::Uuid;
use trustify_common::db::Database;
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
        .service(version::get)
        .service(get);
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
        crate::package::model::details::package::PackageDetails,
        crate::package::model::details::package_version::PackageVersionDetails,
        crate::package::model::details::qualified_package::QualifiedPackageDetails,
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

#[cfg(test)]
mod test;
