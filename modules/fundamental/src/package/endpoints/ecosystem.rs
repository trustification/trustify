use crate::package::service::PackageService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::db::query::Query;
use trustify_common::model::Paginated;

#[utoipa::path(
    tag = "package",
    params(
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PaginatedAdvisorySummary),
    ),
)]
#[get("/api/v1/package/ecosystem")]
pub async fn all(service: web::Data<PackageService>) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.ecosystems(()).await?))
}

#[utoipa::path(
    tag = "package",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PaginatedAdvisorySummary),
    ),
)]
#[get("/api/v1/package/ecosystem/{ecosystem}")]
pub async fn get(
    service: web::Data<PackageService>,
    ecosystem: web::Path<String>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .packages_for_ecosystem(&ecosystem, search, paginated, ())
            .await?,
    ))
}

#[utoipa::path(
    tag = "package",
    params(
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PaginatedAdvisorySummary),
    ),
)]
#[get("/api/v1/package/ecosystem/{ecosystem}/{rest:[^@]+}")]
pub async fn get_package(
    service: web::Data<PackageService>,
    path: web::Path<(String, String)>,
) -> actix_web::Result<impl Responder> {
    let (ecosys, rest) = path.into_inner();

    let (namespace, name) = if let Some((namespace, name)) = rest.split_once('/') {
        (Some(namespace.to_string()), name.to_string())
    } else {
        (None, rest)
    };

    Ok(HttpResponse::Ok().json(service.package(&ecosys, namespace, &name, ()).await?))
}

#[utoipa::path(
    tag = "package",
    params(
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PaginatedAdvisorySummary),
    ),
)]
#[get("/api/v1/package/ecosystem/{ecosystem}/{rest:[^@]+}@{version}")]
pub async fn get_package_version(
    service: web::Data<PackageService>,
    path: web::Path<(String, String, String)>,
) -> actix_web::Result<impl Responder> {
    let (ecosys, rest, version) = path.into_inner();

    let (namespace, name) = if let Some((namespace, name)) = rest.split_once('/') {
        (Some(namespace.to_string()), name.to_string())
    } else {
        (None, rest)
    };

    Ok(HttpResponse::Ok().json(
        service
            .package_version(&ecosys, namespace, &name, &version, ())
            .await?,
    ))
}
