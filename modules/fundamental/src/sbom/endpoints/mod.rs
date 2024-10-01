mod config;
mod label;
#[cfg(test)]
mod test;

use crate::{
    purl::service::PurlService,
    sbom::{
        model::{SbomPackageReference, Which},
        service::SbomService,
    },
    Error::{self, Internal},
};
use actix_web::{delete, get, http::header, post, web, HttpResponse, Responder};
use config::Config;
use futures_util::TryStreamExt;
use sea_orm::prelude::Uuid;
use std::str::FromStr;
use trustify_auth::{authenticator::user::UserInformation, authorizer::Authorizer, Permission};
use trustify_common::{
    db::{query::Query, Database},
    decompress::decompress_async,
    error::ErrorInformation,
    id::Id,
    model::Paginated,
    purl::Purl,
};
use trustify_entity::{labels::Labels, relationship::Relationship};
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::StorageBackend;
use utoipa::OpenApi;

pub fn configure(config: &mut web::ServiceConfig, db: Database, upload_limit: usize) {
    let sbom_service = SbomService::new(db);

    config
        .app_data(web::Data::new(sbom_service))
        .app_data(web::Data::new(Config { upload_limit }))
        .service(all)
        .service(all_related)
        .service(get)
        .service(get_sbom_advisories)
        .service(delete)
        .service(packages)
        .service(related)
        .service(upload)
        .service(download)
        .service(label::set)
        .service(label::update);
}

#[derive(OpenApi)]
#[openapi(
    paths(
        all,
        all_related,
        get,
        get_sbom_advisories,
        delete,
        packages,
        related,
        upload,
        download,
        label::set,
        label::update,
    ),
    components(schemas(
        crate::purl::model::details::purl::StatusContext,
        crate::sbom::model::PaginatedSbomPackage,
        crate::sbom::model::PaginatedSbomPackageRelation,
        crate::sbom::model::PaginatedSbomSummary,
        crate::sbom::model::SbomHead,
        crate::sbom::model::SbomPackage,
        crate::sbom::model::SbomPackageRelation,
        crate::sbom::model::SbomSummary,
        crate::sbom::model::Which,
        crate::sbom::model::details::SbomAdvisory,
        crate::sbom::model::details::SbomDetails,
        crate::sbom::model::details::SbomStatus,
        crate::purl::model::details::purl::StatusContext,
        crate::source_document::model::SourceDocument,
        trustify_common::advisory::AdvisoryVulnerabilityAssertions,
        trustify_common::advisory::Assertion,
        trustify_common::id::Id,
        trustify_common::purl::Purl,
        trustify_entity::labels::Labels,
        trustify_entity::relationship::Relationship,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "sbom",
    operation_id = "listSboms",
    context_path = "/api",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching SBOMs", body = PaginatedSbomSummary),
    ),
)]
#[get("/v1/sbom")]
pub async fn all(
    fetch: web::Data<SbomService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let result = fetch.fetch_sboms(search, paginated, (), ()).await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct AllRelatedQuery {
    /// Find by PURL
    #[serde(default)]
    pub purl: Option<Purl>,
    /// Find by a ID of a package
    #[serde(default)]
    pub id: Option<Uuid>,
}

/// Find all SBOMs containing the provided package.
///
/// The package can be provided either via a PURL or using the ID of a package as returned by
/// other APIs, but not both.
#[utoipa::path(
    tag = "sbom",
    operation_id = "listRelatedSboms",
    context_path = "/api",
    params(
        Query,
        Paginated,
        AllRelatedQuery,
    ),
    responses(
        (status = 200, description = "Matching SBOMs", body = PaginatedSbomSummary),
    ),
)]
#[get("/v1/sbom/by-package")]
pub async fn all_related(
    sbom: web::Data<SbomService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(all_related): web::Query<AllRelatedQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let id = match (&all_related.purl, &all_related.id) {
        (Some(purl), None) => purl.qualifier_uuid(),
        (None, Some(id)) => *id,
        _ => {
            return Ok(HttpResponse::BadRequest().json(ErrorInformation {
                error: "IdOrPurl".into(),
                message: "Requires either `purl` or `id`".to_string(),
                details: Some(format!(
                    "Received - PURL: {:?}, ID: {:?}",
                    all_related.purl, all_related.id
                )),
            }));
        }
    };

    let result = sbom.find_related_sboms(id, paginated, search, ()).await?;

    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    tag = "sbom",
    operation_id = "getSbom",
    context_path = "/api",
    params(
        ("id" = string, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 200, description = "Matching SBOM", body = SbomSummary),
        (status = 404, description = "Matching SBOM not found"),
    ),
)]
#[get("/v1/sbom/{id}")]
pub async fn get(
    fetcher: web::Data<SbomService>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
    id: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let id = Id::from_str(&id).map_err(Error::IdKey)?;
    match fetcher.fetch_sbom_summary(id, ()).await? {
        Some(v) => Ok(HttpResponse::Ok().json(v)),
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

#[utoipa::path(
    tag = "sbom",
    operation_id = "getSbomAdvisories",
    context_path = "/api",
    params(
        ("id" = string, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 200, description = "Matching SBOM", body = Vec<SbomAdvisory>),
        (status = 404, description = "Matching SBOM not found"),
    ),
)]
#[get("/v1/sbom/{id}/advisory")]
pub async fn get_sbom_advisories(
    fetcher: web::Data<SbomService>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
    id: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;
    authorizer.require(&user, Permission::ReadVex)?;

    let id = Id::from_str(&id).map_err(Error::IdKey)?;
    match fetcher.fetch_sbom_details(id, ()).await? {
        Some(v) => Ok(HttpResponse::Ok().json(v.advisories)),
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

#[utoipa::path(
    tag = "sbom",
    operation_id = "deleteSbom",
    context_path = "/api",
    params(
        ("id" = string, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 200, description = "Matching SBOM", body = SbomSummary),
        (status = 404, description = "Matching SBOM not found"),
    ),
)]
#[delete("/v1/sbom/{id}")]
pub async fn delete(
    service: web::Data<SbomService>,
    purl_service: web::Data<PurlService>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
    id: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::DeleteSbom)?;

    let id = Id::from_str(&id).map_err(Error::IdKey)?;
    match service.fetch_sbom_summary(id.clone(), ()).await? {
        Some(v) => {
            let rows_affected = service.delete_sbom(v.head.id, ()).await?;
            match rows_affected {
                0 => Ok(HttpResponse::NotFound().finish()),
                1 => {
                    _ = purl_service.gc_purls(()).await; // ignore gc failure..
                    Ok(HttpResponse::Ok().json(v))
                }
                _ => Err(Internal("Unexpected number of rows affected".into()).into()),
            }
        }
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

/// Search for packages of an SBOM
#[utoipa::path(
    tag = "sbom",
    context_path = "/api",
    operation_id = "listPackages",
    params(
        ("id", Path, description = "ID of the SBOM to get packages for"),
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedSbomPackage),
    ),
)]
#[get("/v1/sbom/{id}/packages")]
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
    tag = "sbom",
    operation_id = "listRelatedPackages",
    context_path = "/api",
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
#[get("/v1/sbom/{id}/related")]
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
                None => SbomPackageReference::All,
                Some(id) => SbomPackageReference::Package(id),
            },
            related.relationship,
            (),
        )
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct UploadQuery {
    /// Optional labels.
    ///
    /// Only use keys with a prefix of `labels.`
    #[serde(flatten, with = "trustify_entity::labels::prefixed")]
    labels: Labels,
}

#[utoipa::path(
    tag = "sbom",
    operation_id = "uploadSbom",
    context_path = "/api",
    request_body = Vec <u8>,
    params(
        UploadQuery,
        ("location" = String, Query, description = "Source the document came from"),
    ),
    responses(
        (status = 201, description = "Upload an SBOM", body = IngestResult),
        (status = 400, description = "The file could not be parsed as an advisory"),
    )
)]
#[post("/v1/sbom")]
/// Upload a new SBOM
pub async fn upload(
    service: web::Data<IngestorService>,
    config: web::Data<Config>,
    web::Query(UploadQuery { labels }): web::Query<UploadQuery>,
    content_type: Option<web::Header<header::ContentType>>,
    bytes: web::Bytes,
) -> Result<impl Responder, Error> {
    let bytes = decompress_async(bytes, content_type.map(|ct| ct.0), config.upload_limit).await??;
    let result = service.ingest(&bytes, Format::SBOM, labels, None).await?;
    log::info!("Uploaded SBOM: {}", result.id);
    Ok(HttpResponse::Created().json(result))
}

#[utoipa::path(
    tag = "sbom",
    operation_id = "downloadSbom",
    context_path = "/api",
    params(
        ("key" = String, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>'"),
    ),
    responses(
        (status = 200, description = "Download a an SBOM", body = Vec<u8>),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/v1/sbom/{key}/download")]
pub async fn download(
    ingestor: web::Data<IngestorService>,
    sbom: web::Data<SbomService>,
    key: web::Path<String>,
) -> Result<impl Responder, Error> {
    let id = Id::from_str(&key).map_err(Error::IdKey)?;

    let Some(sbom) = sbom.fetch_sbom_summary(id, ()).await? else {
        return Ok(HttpResponse::NotFound().finish());
    };

    if let Some(doc) = &sbom.source_document {
        let storage_key = doc.try_into()?;

        let stream = ingestor
            .storage()
            .clone()
            .retrieve(storage_key)
            .await
            .map_err(Error::Storage)?
            .map(|stream| stream.map_err(Error::Storage));

        Ok(match stream {
            Some(s) => HttpResponse::Ok().streaming(s),
            None => HttpResponse::NotFound().finish(),
        })
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
