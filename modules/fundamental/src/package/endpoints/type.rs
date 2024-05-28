use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::db::query::Query;
use trustify_common::model::Paginated;

#[utoipa::path(
    tag = "package",
    params(
    ),
    responses(
        (status = 200, description = "List of all known package types", body = Vec<EcosystemSummary>),
    ),
)]
#[get("/api/v1/package/type")]
pub async fn all(service: web::Data<PackageService>) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.types(()).await?))
}

#[utoipa::path(
    tag = "package",
    params(
        Query,
        Paginated,
        ("type" = String, Path, description = "pURL identifier of a type")
    ),
    responses(
        (status = 200, description = "Information regarding packages within an type", body = PaginatedPackageSummary),
    ),
)]
#[get("/api/v1/package/type/{type}")]
pub async fn get(
    service: web::Data<PackageService>,
    r#type: web::Path<String>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .packages_for_type(&r#type, search, paginated, ())
            .await?,
    ))
}

#[utoipa::path(
    tag = "package",
    params(
        ("type" = String, Path, description = "pURL identifier of a type"),
        ("namespace_and_name" = String, Path, description = "name of the package optionally preceeded by its namespace"),

    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PackageDetails),
    ),
)]
#[get("/api/v1/package/type/{type}/{namespace_and_name:[^@]+}")]
pub async fn get_package(
    service: web::Data<PackageService>,
    path: web::Path<(String, String)>,
) -> actix_web::Result<impl Responder> {
    let (r#type, namespace_and_name) = path.into_inner();

    let (namespace, name) = if let Some((namespace, name)) = namespace_and_name.split_once('/') {
        (Some(namespace.to_string()), name.to_string())
    } else {
        (None, namespace_and_name)
    };

    Ok(HttpResponse::Ok().json(service.package(&r#type, namespace, &name, ()).await?))
}

#[utoipa::path(
    tag = "package",
    params(
        ("type" = String, Path, description = "pURL identifier of a type"),
        ("namespace_and_name" = String, Path, description = "name of the package optionally preceeded by its namespace"),
        ("version" = String, Path, description = "version of the package"),
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PackageVersionDetails),
    ),
)]
#[get("/api/v1/package/type/{type}/{namespace_and_name:[^@]+}@{version}")]
pub async fn get_package_version(
    service: web::Data<PackageService>,
    path: web::Path<(String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (r#type, namespace_and_name, version) = path.into_inner();

    let (namespace, name) = if let Some((namespace, name)) = namespace_and_name.split_once('/') {
        (Some(namespace.to_string()), name.to_string())
    } else {
        (None, namespace_and_name)
    };

    Ok(HttpResponse::Ok().json(
        service
            .package_version(&r#type, namespace, &name, &version, ())
            .await?,
    ))
}
