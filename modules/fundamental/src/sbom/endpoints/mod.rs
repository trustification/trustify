mod config;
mod label;
mod query;
#[cfg(test)]
mod test;

pub use query::*;

use crate::{
    Error::{self, Internal},
    purl::service::PurlService,
    sbom::{
        model::{
            SbomExternalPackageReference, SbomNodeReference, SbomPackage, SbomPackageRelation,
            SbomSummary, Which, details::SbomAdvisory,
        },
        service::SbomService,
    },
};
use actix_web::{HttpResponse, Responder, delete, get, http::header, post, web};
use config::Config;
use futures_util::TryStreamExt;
use sea_orm::{TransactionTrait, prelude::Uuid};
use std::str::FromStr;
use trustify_auth::{
    CreateSbom, DeleteSbom, Permission, ReadAdvisory, ReadSbom, all,
    authenticator::user::UserInformation,
    authorizer::{Authorizer, Require},
};
use trustify_common::{
    db::{Database, query::Query},
    decompress::decompress_async,
    id::Id,
    model::{BinaryData, Paginated, PaginatedResults},
};
use trustify_entity::{labels::Labels, relationship::Relationship};
use trustify_module_ingestor::{
    model::IngestResult,
    service::{Format, IngestorService},
};
use trustify_module_storage::service::StorageBackend;

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db: Database,
    upload_limit: usize,
) {
    let sbom_service = SbomService::new(db.clone());
    let purl_service = PurlService::new();

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(sbom_service))
        .app_data(web::Data::new(purl_service))
        .app_data(web::Data::new(Config { upload_limit }))
        .service(all)
        .service(all_related)
        .service(count_related)
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

/// Search for SBOMs
#[utoipa::path(
    tag = "sbom",
    operation_id = "listSboms",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching SBOMs", body = PaginatedResults<SbomSummary>),
    ),
)]
#[get("/v2/sbom")]
pub async fn all(
    fetch: web::Data<SbomService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let result = fetch
        .fetch_sboms(search, paginated, (), db.as_ref())
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

/// Find all SBOMs containing the provided package.
///
/// The package can be provided either via a PURL or using the ID of a package as returned by
/// other APIs, but not both.
#[utoipa::path(
    tag = "sbom",
    operation_id = "listRelatedSboms",
    params(
        Query,
        Paginated,
        ExternalReferenceQuery,
    ),
    responses(
        (status = 200, description = "Matching SBOMs", body = PaginatedResults<SbomSummary>),
    ),
)]
#[get("/v2/sbom/by-package")]
pub async fn all_related(
    sbom: web::Data<SbomService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(all_related): web::Query<ExternalReferenceQuery>,
    authorizer: web::Data<Authorizer>,
    user: UserInformation,
) -> actix_web::Result<impl Responder> {
    authorizer.require(&user, Permission::ReadSbom)?;

    let id = (&all_related).try_into()?;

    let result = sbom
        .find_related_sboms(id, paginated, search, db.as_ref())
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

/// Count all SBOMs containing the provided packages.
///
/// The packages can be provided either via a PURL or using the ID of a package as returned by
/// other APIs, but not both.
#[utoipa::path(
    tag = "sbom",
    operation_id = "countRelatedSboms",
    params(
        ExternalReferenceQuery,
    ),
    responses(
        (status = 200, description = "Number of matching SBOMs per package", body = Vec<i64>),
    ),
)]
#[get("/v2/sbom/count-by-package")]
pub async fn count_related(
    sbom: web::Data<SbomService>,
    db: web::Data<Database>,
    web::Json(ids): web::Json<Vec<ExternalReferenceQuery>>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let ids = ids
        .iter()
        .map(SbomExternalPackageReference::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    let result = sbom.count_related_sboms(ids, db.as_ref()).await?;

    Ok(HttpResponse::Ok().json(result))
}

/// Get information about an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "getSbom",
    params(
        ("id" = Id, Path),
    ),
    responses(
        (status = 200, description = "Matching SBOM", body = SbomSummary),
        (status = 404, description = "Matching SBOM not found"),
    ),
)]
#[get("/v2/sbom/{id}")]
pub async fn get(
    fetcher: web::Data<SbomService>,
    db: web::Data<Database>,
    id: web::Path<String>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let id = Id::from_str(&id).map_err(Error::IdKey)?;
    match fetcher.fetch_sbom_summary(id, db.as_ref()).await? {
        Some(v) => Ok(HttpResponse::Ok().json(v)),
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

/// Get advisories for an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "getSbomAdvisories",
    params(
        ("id" = Id, Path),
    ),
    responses(
        (status = 200, description = "Matching SBOM", body = Vec<SbomAdvisory>),
        (status = 404, description = "Matching SBOM not found"),
    ),
)]
#[get("/v2/sbom/{id}/advisory")]
pub async fn get_sbom_advisories(
    fetcher: web::Data<SbomService>,
    db: web::Data<Database>,
    id: web::Path<String>,
    _: Require<GetSbomAdvisories>,
) -> actix_web::Result<impl Responder> {
    let id = Id::from_str(&id).map_err(Error::IdKey)?;
    let statuses: Vec<String> = vec!["affected".to_string()];
    match fetcher
        .fetch_sbom_details(id, statuses, db.as_ref())
        .await?
    {
        Some(v) => Ok(HttpResponse::Ok().json(v.advisories)),
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

all!(GetSbomAdvisories -> ReadSbom, ReadAdvisory);

/// Delete an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "deleteSbom",
    params(
        ("id" = Id, Path),
    ),
    responses(
        (status = 200, description = "Matching SBOM", body = SbomSummary),
        (status = 404, description = "Matching SBOM not found"),
    ),
)]
#[delete("/v2/sbom/{id}")]
pub async fn delete(
    service: web::Data<SbomService>,
    db: web::Data<Database>,
    purl_service: web::Data<PurlService>,
    id: web::Path<String>,
    _: Require<DeleteSbom>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;

    let id = Id::from_str(&id)?;
    match service.fetch_sbom_summary(id.clone(), &tx).await? {
        Some(v) => {
            let rows_affected = service.delete_sbom(v.head.id, &tx).await?;
            match rows_affected {
                0 => Ok(HttpResponse::NotFound().finish()),
                1 => {
                    let _ = purl_service.gc_purls(&tx).await; // ignore gc failure..
                    tx.commit().await?;
                    Ok(HttpResponse::Ok().json(v))
                }
                _ => Err(Internal("Unexpected number of rows affected".into())),
            }
        }
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

/// Search for packages of an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "listPackages",
    params(
        ("id", Path, description = "ID of the SBOM to get packages for"),
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedResults<SbomPackage>),
    ),
)]
#[get("/v2/sbom/{id}/packages")]
pub async fn packages(
    fetch: web::Data<SbomService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let result = fetch
        .fetch_sbom_packages(id.into_inner(), search, paginated, db.as_ref())
        .await?;

    Ok(HttpResponse::Ok().json(result))
}

#[derive(Clone, Debug, serde::Deserialize, utoipa::IntoParams)]
struct RelatedQuery {
    /// The Package to use as reference
    pub reference: Option<String>,
    /// Which side the reference should be on
    #[serde(default)]
    #[param(inline)]
    pub which: Which,
    /// Optional relationship filter
    #[serde(default)]
    pub relationship: Option<Relationship>,
}

/// Search for related packages in an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "listRelatedPackages",
    params(
        ("id", Path, description = "ID of SBOM to search packages in"),
        RelatedQuery,
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Packages", body = PaginatedResults<SbomPackageRelation>),
    ),
)]
#[get("/v2/sbom/{id}/related")]
pub async fn related(
    fetch: web::Data<SbomService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(related): web::Query<RelatedQuery>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let id = id.into_inner();

    let result = fetch
        .fetch_related_packages(
            id,
            search,
            paginated,
            related.which,
            match &related.reference {
                None => SbomNodeReference::All,
                Some(id) => SbomNodeReference::Package(id),
            },
            related.relationship,
            db.as_ref(),
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
    request_body = Vec <u8>,
    params(
        UploadQuery,
    ),
    responses(
        (status = 201, description = "Upload an SBOM", body = IngestResult),
        (status = 400, description = "The file could not be parsed as an advisory"),
    )
)]
#[post("/v2/sbom")]
/// Upload a new SBOM
pub async fn upload(
    service: web::Data<IngestorService>,
    config: web::Data<Config>,
    web::Query(UploadQuery { labels }): web::Query<UploadQuery>,
    content_type: Option<web::Header<header::ContentType>>,
    bytes: web::Bytes,
    _: Require<CreateSbom>,
) -> Result<impl Responder, Error> {
    let bytes = decompress_async(bytes, content_type.map(|ct| ct.0), config.upload_limit).await??;
    let result = service.ingest(&bytes, Format::SBOM, labels, None).await?;
    log::info!("Uploaded SBOM: {}", result.id);
    Ok(HttpResponse::Created().json(result))
}

/// Download an SBOM
#[utoipa::path(
    tag = "sbom",
    operation_id = "downloadSbom",
    params(
        ("key" = Id, Path),
    ),
    responses(
        (status = 200, description = "Download a an SBOM", body = inline(BinaryData)),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/v2/sbom/{key}/download")]
pub async fn download(
    ingestor: web::Data<IngestorService>,
    db: web::Data<Database>,
    sbom: web::Data<SbomService>,
    key: web::Path<String>,
    _: Require<ReadSbom>,
) -> Result<impl Responder, Error> {
    let id = Id::from_str(&key).map_err(Error::IdKey)?;

    let Some(sbom) = sbom.fetch_sbom_summary(id, db.as_ref()).await? else {
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
