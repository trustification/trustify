use crate::advisory::service::{AdvisoryKey, AdvisoryService};
use crate::Error;
use actix_web::{get, post, web, HttpResponse, Responder};
use futures_util::TryStreamExt;
use tokio_util::io::ReaderStream;
use trustify_common::db::query::Query;
use trustify_common::db::Database;
use trustify_common::model::Paginated;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::StorageBackend;
use utoipa::{IntoParams, OpenApi};

pub fn configure(config: &mut web::ServiceConfig, db: Database) {
    let advisory_service = AdvisoryService::new(db);

    config
        .app_data(web::Data::new(advisory_service))
        .service(all)
        .service(get)
        .service(upload)
        .service(download);
}

#[derive(OpenApi)]
#[openapi(
    paths(all, get, upload, download),
    components(schemas(
        crate::advisory::model::AdvisoryDetails,
        crate::advisory::model::AdvisoryHead,
        crate::advisory::model::AdvisorySummary,
        crate::advisory::model::AdvisoryVulnerabilityHead,
        crate::advisory::model::AdvisoryVulnerabilitySummary,
        crate::advisory::model::PaginatedAdvisorySummary,
        trustify_common::advisory::AdvisoryVulnerabilityAssertions,
        trustify_common::advisory::Assertion,
        trustify_common::purl::Purl,
    )),
    tags()
)]
pub struct ApiDoc;

#[utoipa::path(
    tag = "advisory",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching vulnerabilities", body = PaginatedAdvisorySummary),
    ),
)]
#[get("/api/v1/advisory")]
pub async fn all(
    state: web::Data<AdvisoryService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.fetch_advisories(search, paginated, ()).await?))
}

#[utoipa::path(
    tag = "advisory",
    params(
        ("sha256", Path, description = "SHA256 of the advisory")
    ),
    responses(
        (status = 200, description = "Matching advisory", body = AdvisoryDetails),
        (status = 404, description = "Matching advisory not found"),
    ),
)]
#[get("/api/v1/advisory/{sha256}")]
pub async fn get(
    state: web::Data<AdvisoryService>,
    sha256: web::Path<String>,
) -> actix_web::Result<impl Responder> {
    let fetched = state
        .fetch_advisory(AdvisoryKey::Sha256(sha256.to_string()), ())
        .await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[derive(
    IntoParams, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
struct UploadParams {
    /// Optional issuer if it cannot be determined from advisory contents.
    issuer: Option<String>,
}

#[utoipa::path(
    tag = "advisory",
    request_body = Vec <u8>,
    params( UploadParams ),
    responses(
    (status = 201, description = "Upload a file"),
    (status = 400, description = "The file could not be parsed as an advisory"),
    )
)]
#[post("/api/v1/advisory")]
/// Upload a new advisory
pub async fn upload(
    service: web::Data<IngestorService>,
    web::Query(UploadParams { issuer }): web::Query<UploadParams>,
    bytes: web::Bytes,
) -> Result<impl Responder, Error> {
    let fmt = Format::from_bytes(&bytes)?;
    let payload = ReaderStream::new(&*bytes);
    let advisory_id = service.ingest("rest-api", issuer, fmt, payload).await?;
    Ok(HttpResponse::Created().json(advisory_id))
}

#[utoipa::path(
    tag = "advisory",
    params(
        ("key" = String, Path, description = "Digest/hash of the document, prefixed by hash type, such as 'sha256:<hash>'"),
    ),
    responses(
        (status = 200, description = "Download a an advisory", body = Vec<u8>),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/api/v1/advisory/{key}/download")]
pub async fn download(
    service: web::Data<IngestorService>,
    key: web::Path<String>,
) -> Result<impl Responder, Error> {
    // TODO support various hashes
    let hash = key.into_inner();

    let Some(hash) = hash.strip_prefix("sha256:") else {
        return Err(Error::UnsupportedHashAlgorithm);
    };

    let stream = service
        .get_ref()
        .storage()
        .clone()
        .retrieve(hash.to_string())
        .await
        .map_err(Error::Storage)?
        .map(|stream| stream.map_err(Error::Storage));

    Ok(match stream {
        Some(s) => HttpResponse::Ok().streaming(s),
        None => HttpResponse::NotFound().finish(),
    })
}

#[cfg(test)]
mod test;
