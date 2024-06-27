use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::db::query::Query;
use trustify_common::model::Paginated;

#[utoipa::path(
    tag = "purl",
    context_path= "/api",
    params(
    ),
    responses(
        (status = 200, description = "List of all known PURL types", body = Vec<EcosystemSummary>),
    ),
)]
#[get("/v1/package/by-purl/type")]
pub async fn all(service: web::Data<PackageService>) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.purl_types(()).await?))
}

#[utoipa::path(
    tag = "purl",
    context_path= "/api",
    params(
        Query,
        Paginated,
        ("type" = String, Path, description = "PURL identifier of a type")
    ),
    responses(
        (status = 200, description = "Information regarding PURLs within an type", body = PaginatedPackageSummary),
    ),
)]
#[get("/v1/package/by-purl/type/{type}")]
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
    tag = "purl",
    context_path= "/api",
    params(
        ("type" = String, Path, description = "PURL identifier of a type"),
        ("namespace_and_name" = String, Path, description = "name of the package optionally preceded by its namespace"),

    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PackageDetails),
    ),
)]
#[get("/v1/package/by-purl/type/{type}/{namespace_and_name:[^@]+}")]
pub async fn get_purl(
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
    tag = "purl",
    context_path= "/api",
    params(
        ("type" = String, Path, description = "PURL identifier of a type"),
        ("namespace_and_name" = String, Path, description = "name of the package optionally preceded by its namespace"),
        ("version" = String, Path, description = "version of the package"),
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PackageVersionDetails),
    ),
)]
#[get("/v1/package/by-purl/type/{type}/{namespace_and_name:[^@]+}@{version}")]
pub async fn get_purl_version(
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
