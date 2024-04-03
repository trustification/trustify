use crate::service::{Error, IngestorService};
use actix_web::{get, post, web, HttpResponse, Responder};

#[derive(Clone, Debug, serde::Deserialize)]
pub struct UploadSbomQuery {
    /// The source of the document.
    ///
    /// Only the base source, not the full document URL.
    pub location: String,
}

#[utoipa::path(
    tag = "ingestor",
    request_body = Vec <u8>,
    params(
        ("location" = String, Query, description = "Source the document came from"),
    ),
    responses(
        (status = 201, description = "Upload an SBOM"),
        (status = 400, description = "The file could not be parsed as an advisory"),
    )
)]
#[post("/sboms")]
/// Upload a new advisory
pub async fn upload_sbom(
    service: web::Data<IngestorService>,
    payload: web::Payload,
    web::Query(UploadSbomQuery { location }): web::Query<UploadSbomQuery>,
) -> Result<impl Responder, Error> {
    let sbom_id = service.ingest_sbom(&location, payload).await?;
    Ok(HttpResponse::Created().json(sbom_id))
}

#[utoipa::path(
    tag = "ingestor",
    responses(
        (status = 200, description = "Download a an SBOM", body = Vec<u8>),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/sboms/{id}")]
/// Download an SBOM
pub async fn download_sbom(
    service: web::Data<IngestorService>,
    path: web::Path<i32>,
) -> Result<impl Responder, Error> {
    let id = path.into_inner();

    Ok(match service.retrieve_sbom(id).await? {
        Some(stream) => HttpResponse::Ok().streaming(stream),
        None => HttpResponse::NotFound().finish(),
    })
}
