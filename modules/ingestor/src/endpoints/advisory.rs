use std::str::FromStr;

use crate::service::{advisory::Format, Error, IngestorService};
use actix_web::{get, post, web, HttpResponse, Responder};

#[derive(Clone, Debug, serde::Deserialize)]
pub struct UploadAdvisoryQuery {
    /// The source of the document.
    ///
    /// Only the base source, not the full document URL.
    pub location: String,
    pub format: Option<String>,
}

#[utoipa::path(
    tag = "ingestor",
    request_body = Vec <u8>,
    params(
        ("advisory_format" = String, Path, description = "Format of the submitted advisory document (`casf`, `osv`, ...)"),
    ),
    responses(
        (status = 201, description = "Upload a file"),
        (status = 400, description = "The file could not be parsed as an advisory"),
    )
)]
#[post("/advisories")]
/// Upload a new advisory
pub async fn upload_advisory(
    service: web::Data<IngestorService>,
    payload: web::Payload,
    web::Query(UploadAdvisoryQuery { location, format }): web::Query<UploadAdvisoryQuery>,
) -> Result<impl Responder, Error> {
    let fmt = format
        .map(|f| Format::from_str(&f))
        .unwrap_or(Ok(Format::CSAF))?;
    let advisory_id = service.ingest(&location, fmt, payload).await?;
    Ok(HttpResponse::Created().json(advisory_id))
}

#[utoipa::path(
    tag = "ingestor",
    responses(
        (status = 200, description = "Download a an advisory", body = Vec<u8>,),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/advisories/{id}")]
/// Download an advisory
pub async fn download_advisory(
    service: web::Data<IngestorService>,
    path: web::Path<i32>,
) -> Result<impl Responder, Error> {
    let id = path.into_inner();

    Ok(match service.retrieve(id).await? {
        Some(stream) => HttpResponse::Ok().streaming(stream),
        None => HttpResponse::NotFound().finish(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::configure;

    use actix_web::{test, test::TestRequest, App};
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;
    use trustify_common::db::Database;
    use trustify_module_storage::service::fs::FileSystemBackend;

    #[test_log::test(actix_web::test)]
    async fn upload_csaf() -> Result<(), anyhow::Error> {
        let db = Database::for_test("upload_advisory_csaf").await?;
        let (storage, _temp) = FileSystemBackend::for_test().await?;

        let app = test::init_service(App::new().configure(|svc| configure(svc, db, storage))).await;

        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../../etc/test-data");

        let advisory = test_data.join("cve-2023-33201.json");

        let payload = fs::read_to_string(advisory).expect("File not found");
        let uri = "/advisories?location=test-csaf";
        let request = TestRequest::post()
            .uri(uri)
            .set_payload(payload)
            .to_request();

        let response = test::call_service(&app, request).await;
        log::info!("response: {response:?}");

        assert!(response.status().is_success());

        Ok(())
    }

    #[test_log::test(actix_web::test)]
    async fn upload_osv() -> Result<(), anyhow::Error> {
        let db = Database::for_test("upload_advisory_osv").await?;
        let (storage, _temp) = FileSystemBackend::for_test().await?;

        let app = test::init_service(App::new().configure(|svc| configure(svc, db, storage))).await;

        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../../etc/test-data/osv");

        let advisory = test_data.join("RUSTSEC-2021-0079.json");

        let payload = fs::read_to_string(advisory).expect("File not found");
        let uri = "/advisories?location=test-osv&format=osv";
        let request = TestRequest::post()
            .uri(uri)
            .set_payload(payload)
            .to_request();

        let response = test::call_service(&app, request).await;
        log::info!("response: {response:?}");

        assert!(response.status().is_success());

        Ok(())
    }
}
