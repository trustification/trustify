use crate::purl::{
    model::{
        details::{base_purl::BasePurlDetails, versioned_purl::VersionedPurlDetails},
        summary::{base_purl::BasePurlSummary, r#type::TypeSummary},
    },
    service::PurlService,
};
use actix_web::{get, web, HttpResponse, Responder};
use trustify_auth::{authorizer::Require, ReadSbom};
use trustify_common::{
    db::{query::Query, Database},
    model::{Paginated, PaginatedResults},
};

#[utoipa::path(
    tag = "purl type",
    operation_id = "listPurlTypes",
    params(
    ),
    responses(
        (status = 200, description = "List of all known PURL types", body = Vec<TypeSummary>),
    ),
)]
#[get("/v1/purl/type")]
/// List known pURL types
pub async fn all_purl_types(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(service.purl_types(db.as_ref()).await?))
}

#[utoipa::path(
    tag = "purl type",
    operation_id = "getPurlType",
    params(
        Query,
        Paginated,
        ("type" = String, Path, description = "PURL identifier of a type")
    ),
    responses(
        (status = 200, description = "Information regarding PURLs within an type", body = PaginatedResults<BasePurlSummary>),
    ),
)]
#[get("/v1/purl/type/{type}")]
/// Retrieve details about a pURL type
pub async fn get_purl_type(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    r#type: web::Path<String>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(
        service
            .base_purls_by_type(&r#type, search, paginated, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "purl type",
    operation_id = "getBasePurlOfType",
    params(
        ("type" = String, Path, description = "PURL identifier of a type"),
        ("namespace_and_name" = String, Path, description = "name of the package optionally preceded by its namespace"),

    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = BasePurlDetails),
    ),
)]
#[get("/v1/purl/type/{type}/{namespace_and_name:[^@]+}")]
/// Retrieve base pURL details of a type
pub async fn get_base_purl_of_type(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    path: web::Path<(String, String)>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let (r#type, namespace_and_name) = path.into_inner();

    let (namespace, name) = if let Some((namespace, name)) = namespace_and_name.split_once('/') {
        (Some(namespace.to_string()), name.to_string())
    } else {
        (None, namespace_and_name)
    };

    Ok(HttpResponse::Ok().json(
        service
            .base_purl(&r#type, namespace, &name, db.as_ref())
            .await?,
    ))
}

#[utoipa::path(
    tag = "purl",
    operation_id = "getVersionedPurlOfType",
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
/// Retrieve versioned pURL details of a type
pub async fn get_versioned_purl_of_type(
    service: web::Data<PurlService>,
    db: web::Data<Database>,
    path: web::Path<(String, String, String)>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let (r#type, namespace_and_name, version) = path.into_inner();

    let (namespace, name) = if let Some((namespace, name)) = namespace_and_name.split_once('/') {
        (Some(namespace.to_string()), name.to_string())
    } else {
        (None, namespace_and_name)
    };

    Ok(HttpResponse::Ok().json(
        service
            .versioned_purl(&r#type, namespace, &name, &version, db.as_ref())
            .await?,
    ))
}
