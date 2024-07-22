use crate::purl::service::PurlService;
use actix_web::{get, web, HttpResponse, Responder};
use trustify_common::db::query::Query;
use trustify_common::model::Paginated;

#[utoipa::path(
    tag = "purl",
    operation_id = "listPurlTypes",
    context_path= "/api",
    params(
    ),
    responses(
        (status = 200, description = "List of all known PURL types", body = Vec<TypeSummary>),
    ),
)]
#[get("/v1/purl/type")]
pub async fn all_purl_types(service: web::Data<PurlService>) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.purl_types(()).await?))
}

#[utoipa::path(
    tag = "purl",
    operation_id = "getPurlType",
    context_path= "/api",
    params(
        Query,
        Paginated,
        ("type" = String, Path, description = "PURL identifier of a type")
    ),
    responses(
        (status = 200, description = "Information regarding PURLs within an type", body = PaginatedBasePurlSummary),
    ),
)]
#[get("/v1/purl/type/{type}")]
pub async fn get_purl_type(
    service: web::Data<PurlService>,
    r#type: web::Path<String>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .base_purls_by_type(&r#type, search, paginated, ())
            .await?,
    ))
}

#[utoipa::path(
    tag = "purl",
    operation_id = "getBasePurlOfType",
    context_path= "/api",
    params(
        ("type" = String, Path, description = "PURL identifier of a type"),
        ("namespace_and_name" = String, Path, description = "name of the package optionally preceded by its namespace"),

    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = BasePurlDetails),
    ),
)]
#[get("/v1/purl/type/{type}/{namespace_and_name:[^@]+}")]
pub async fn get_base_purl_of_type(
    service: web::Data<PurlService>,
    path: web::Path<(String, String)>,
) -> actix_web::Result<impl Responder> {
    let (r#type, namespace_and_name) = path.into_inner();

    let (namespace, name) = if let Some((namespace, name)) = namespace_and_name.split_once('/') {
        (Some(namespace.to_string()), name.to_string())
    } else {
        (None, namespace_and_name)
    };

    Ok(HttpResponse::Ok().json(service.base_purl(&r#type, namespace, &name, ()).await?))
}

#[utoipa::path(
    tag = "purl",
    operation_id = "getVersionedPurlOfType",
    context_path= "/api",
    params(
        ("type" = String, Path, description = "PURL identifier of a type"),
        ("namespace_and_name" = String, Path, description = "name of the package optionally preceded by its namespace"),
        ("version" = String, Path, description = "version of the package"),
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = VersionedPurlDetails),
    ),
)]
#[get("/v1/purl/type/{type}/{namespace_and_name:[^@]+}@{version}")]
pub async fn get_versioned_purl_of_type(
    service: web::Data<PurlService>,
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
            .versioned_purl(&r#type, namespace, &name, &version, ())
            .await?,
    ))
}
