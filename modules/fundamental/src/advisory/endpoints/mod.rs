mod label;
#[cfg(test)]
mod test;

use crate::{
    advisory::service::AdvisoryService, purl::service::PurlService, Error, Error::Internal,
};
use actix_web::{delete, get, http::header, post, web, HttpResponse, Responder};
use futures_util::TryStreamExt;
use std::str::FromStr;
use trustify_common::{
    db::{query::Query, Database},
    decompress::decompress_async,
    id::Id,
    model::Paginated,
};
use trustify_entity::labels::Labels;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::StorageBackend;
use utoipa::{IntoParams, OpenApi};

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let advisory_service = AdvisoryService::new(db);

    config
        .app_data(web::Data::new(advisory_service))
        .service(all)
        .service(get)
        .service(delete)
        .service(upload)
        .service(download)
        .service(label::set)
        .service(label::update);
}

#[derive(OpenApi)]
#[openapi(
    paths(all, get, delete, upload, download, label::set, label::update),
    components(schemas(
        crate::advisory::model::AdvisoryDetails,
        crate::advisory::model::AdvisoryHead,
        crate::advisory::model::AdvisorySummary,
        crate::advisory::model::AdvisoryVulnerabilityHead,
        crate::advisory::model::AdvisoryVulnerabilitySummary,
        crate::advisory::model::PaginatedAdvisorySummary,
        crate::source_document::model::SourceDocument,
        trustify_common::advisory::AdvisoryVulnerabilityAssertions,
        trustify_common::advisory::Assertion,
        trustify_common::purl::Purl,
        trustify_common::id::Id,
        trustify_entity::labels::Labels,
        trustify_cvss::cvss3::severity::Severity,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "advisory",
    operation_id = "listAdvisories",
    context_path = "/api",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PaginatedAdvisorySummary),
    ),
)]
#[get("/v1/advisory")]
/// List advisories
pub async fn all(
    state: web::Data<AdvisoryService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.fetch_advisories(search, paginated, ()).await?))
}

#[utoipa::path(
    tag = "advisory",
    operation_id = "getAdvisory",
    context_path = "/api",
    params(
        ("key" = string, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 200, description = "Matching advisory", body = AdvisoryDetails),
        (status = 404, description = "Matching advisory not found"),
    ),
)]
#[get("/v1/advisory/{key}")]
/// Get an advisory
pub async fn get(
    state: web::Data<AdvisoryService>,
    key: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    let hash_key = Id::from_str(&key).map_err(Error::IdKey)?;
    let fetched = state.fetch_advisory(hash_key, ()).await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[utoipa::path(
    tag = "advisory",
    operation_id = "deleteAdvisory",
    context_path = "/api",
    params(
        ("key" = string, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>' or 'urn:uuid:<uuid>'"),
    ),
    responses(
        (status = 200, description = "Matching advisory", body = AdvisoryDetails),
        (status = 404, description = "Matching advisory not found"),
    ),
)]
#[delete("/v1/advisory/{key}")]
/// Delete an advisory
pub async fn delete(
    state: web::Data<AdvisoryService>,
    purl_service: web::Data<PurlService>,
    key: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    let hash_key = Id::from_str(&key).map_err(Error::IdKey)?;
    let fetched = state.fetch_advisory(hash_key, ()).await?;

    if let Some(fetched) = fetched {
        let rows_affected = state.delete_advisory(fetched.head.uuid, ()).await?;
        match rows_affected {
            0 => Ok(HttpResponse::NotFound().finish()),
            1 => {
                _ = purl_service.gc_purls(()).await; // ignore gc failure..
                Ok(HttpResponse::Ok().json(fetched))
            }
            _ => Err(Internal("Unexpected number of rows affected".into()).into()),
        }
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[derive(
    IntoParams, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
struct UploadParams {
    /// Optional issuer if it cannot be determined from advisory contents.
    #[serde(default)]
    issuer: Option<String>,
    /// Optional labels.
    ///
    /// Only use keys with a prefix of `labels.`
    #[serde(flatten, with = "trustify_entity::labels::prefixed")]
    labels: Labels,
}

#[utoipa::path(
    tag = "advisory",
    operation_id = "uploadAdvisory",
    context_path = "/api",
    request_body = Vec<u8>,
    params(UploadParams),
    responses(
        (status = 201, description = "Upload a file"),
        (status = 400, description = "The file could not be parsed as an advisory"),
    )
)]
#[post("/v1/advisory")]
/// Upload a new advisory
pub async fn upload(
    service: web::Data<IngestorService>,
    web::Query(UploadParams { issuer, labels }): web::Query<UploadParams>,
    content_type: Option<web::Header<header::ContentType>>,
    bytes: web::Bytes,
) -> Result<impl Responder, Error> {
    let bytes = decompress_async(bytes, content_type.map(|ct| ct.0)).await??;
    let result = service
        .ingest(&bytes, Format::Advisory, labels, issuer)
        .await?;
    log::info!("Uploaded Advisory: {}", result.id);
    Ok(HttpResponse::Created().json(result))
}

#[utoipa::path(
    tag = "advisory",
    operation_id = "downloadAdvisory",
    context_path = "/api",
    params(
        ("key" = String, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>'"),
    ),
    responses(
        (status = 200, description = "Download a an advisory", body = Vec<u8>),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/v1/advisory/{key}/download")]
/// Download an advisory document
pub async fn download(
    ingestor: web::Data<IngestorService>,
    advisory: web::Data<AdvisoryService>,
    key: web::Path<String>,
) -> Result<impl Responder, Error> {
    // the user requested id
    let id = Id::from_str(&key).map_err(Error::IdKey)?;

    // look up document by id
    let Some(advisory) = advisory.fetch_advisory(id, ()).await? else {
        return Ok(HttpResponse::NotFound().finish());
    };

    if let Some(doc) = &advisory.source_document {
        let stream = ingestor
            .get_ref()
            .storage()
            .clone()
            .retrieve(doc.try_into()?)
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
