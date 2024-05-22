use actix_web::{get, post, web, HttpResponse, Responder};
use futures_util::TryStreamExt;
use sea_orm::prelude::Uuid;
use std::str::FromStr;
use utoipa::OpenApi;

use trustify_auth::authenticator::user::UserInformation;
use trustify_auth::authorizer::Authorizer;
use trustify_auth::Permission;
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::hash::HashKey;
use trustify_common::model::Paginated;
use trustify_entity::relationship::Relationship;
use trustify_module_ingestor::service::IngestorService;
use trustify_module_storage::service::StorageBackend;

use crate::sbom::model::{SbomPackageReference, Which};
use crate::sbom::service::SbomService;
use crate::Error;

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let sbom_service = SbomService::new(db);

    config
        .app_data(web::Data::new(sbom_service))
        .service(all)
        .service(packages)
        .service(related)
        .service(upload)
        .service(download);
}

#[derive(OpenApi)]
#[openapi(
    paths(all, packages, related, upload, download,),
    components(schemas(
        crate::sbom::model::PaginatedSbomPackage,
        crate::sbom::model::PaginatedSbomPackageRelation,
        crate::sbom::model::PaginatedSbomSummary,
        crate::sbom::model::SbomPackage,
        crate::sbom::model::SbomPackageRelation,
        crate::sbom::model::SbomSummary,
        crate::sbom::model::Which,
        trustify_common::advisory::AdvisoryVulnerabilityAssertions,
        trustify_common::advisory::Assertion,
        trustify_common::purl::Purl,
        trustify_entity::relationship::Relationship,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "sbom",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching SBOMs", body = PaginatedSbomSummary),
    ),
)]
#[get("/api/v1/sbom")]
pub async fn all(
    fetch: web::Data<SbomService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let result = fetch.fetch_sboms(search, paginated, ()).await?;

    Ok(HttpResponse::Ok().json(result))
}

/// Search for packages of an SBOM
#[utoipa::path(
    params(
        ("id", Path, description = "ID of the SBOM to get packages for"),
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedSbomPackage),
    ),
)]
#[get("/api/v1/sbom/{id}/packages")]
pub async fn packages(
    fetch: web::Data<SbomService>,
    id: web::Path<Uuid>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let result = fetch
        .fetch_sbom_packages(id.into_inner(), search, paginated, ())
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct RelatedQuery {
    /// The Package to use as reference
    pub reference: Option<String>,
    /// Which side the reference should be on
    #[serde(default)]
    pub which: Which,
    /// Optional relationship filter
    #[serde(default)]
    pub relationship: Option<Relationship>,
}

/// Search for related packages in an SBOM
#[utoipa::path(
    params(
        ("id", Path, description = "ID of SBOM to search packages in"),
        RelatedQuery,
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedSbomPackageRelation),
    ),
)]
#[get("/api/v1/sbom/{id}/related")]
pub async fn related(
    fetch: web::Data<SbomService>,
    id: web::Path<Uuid>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(related): web::Query<RelatedQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let id = id.into_inner();

    let result = fetch
        .fetch_related_packages(
            id,
            search,
            paginated,
            related.which,
            match &related.reference {
                None => SbomPackageReference::Root,
                Some(id) => SbomPackageReference::Package(id),
            },
            related.relationship,
            (),
        )
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct UploadSbomQuery {
    /// The source of the document.
    ///
    /// Only the base source, not the full document URL.
    pub location: String,
}

#[utoipa::path(
    tag = "sbom",
    request_body = Vec <u8>,
    params(
    ("location" = String, Query, description = "Source the document came from"),
    ),
    responses(
    (status = 201, description = "Upload an SBOM"),
    (status = 400, description = "The file could not be parsed as an advisory"),
    )
)]
#[post("/api/v1/sbom")]
/// Upload a new SBOM
pub async fn upload(
    service: web::Data<IngestorService>,
    payload: web::Payload,
    web::Query(UploadSbomQuery { location }): web::Query<UploadSbomQuery>,
) -> Result<impl Responder, Error> {
    let sbom_id = service.ingest_sbom(&location, payload).await?;
    Ok(HttpResponse::Created().json(sbom_id))
}

#[utoipa::path(
    tag = "sbom",
    params(
        ("key" = String, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>'"),
    ),
    responses(
        (status = 200, description = "Download a an SBOM", body = Vec<u8>),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/api/v1/sbom/{key}/download")]
pub async fn download(
    service: web::Data<IngestorService>,
    key: web::Path<String>,
) -> Result<impl Responder, Error> {
    let hash_key = HashKey::from_str(&key).map_err(Error::HashKey)?;

    let stream = service
        .get_ref()
        .storage()
        .clone()
        .retrieve(hash_key)
        .await
        .map_err(Error::Storage)?
        .map(|stream| stream.map_err(Error::Storage));

    Ok(match stream {
        Some(s) => HttpResponse::Ok().streaming(s),
        None => HttpResponse::NotFound().finish(),
    })
}
