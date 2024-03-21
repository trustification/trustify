use crate::service::{Error, IngestorService};
use actix_web::{post, web, HttpResponse, Responder};

#[derive(Clone, Debug, serde::Deserialize)]
pub struct UploadAdvisoryQuery {
    /// The source of the document.
    ///
    /// Only the base source, not the full document URL.
    pub location: String,
}

#[utoipa::path(
    tag = "ingestor",
    request_body = Vec<u8>,
    responses(
        (status = 200, description = "Upload a file"),
        (status = 400, description = "The file could not be parsed as a CSAF document"),
    )
)]
#[post("/advisories")]
/// Upload a new advisory
pub async fn upload_advisory(
    service: web::Data<IngestorService>,
    payload: web::Payload,
    web::Query(UploadAdvisoryQuery { location }): web::Query<UploadAdvisoryQuery>,
) -> Result<impl Responder, Error> {
    let advisory_id = service.ingest(&location, payload).await?;

    Ok(HttpResponse::Created().json(advisory_id))
}

#[cfg(test)]
mod tests {
    use super::super::configure;

    use crate::service::IngestorService;
    use actix_web::test::TestRequest;
    use actix_web::web::Data;
    use actix_web::{test, App};
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;
    use trustify_common::db::Database;
    use trustify_module_graph::graph::Graph;
    use trustify_module_storage::service::fs::FileSystemBackend;

    #[test_log::test(actix_web::test)]
    async fn upload_advisory() -> Result<(), anyhow::Error> {
        let graph = Graph::new(Database::for_test("upload_advisory").await?);
        let (storage, _temp) = FileSystemBackend::for_test().await?;
        let ingestor = IngestorService::new(graph, storage);

        let app = test::init_service(
            App::new()
                .app_data(Data::new(ingestor))
                .configure(configure),
        )
        .await;

        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../../etc/test-data");

        let advisory = test_data.join("cve-2023-33201.json");

        let payload = fs::read_to_string(advisory).expect("File not found");
        let uri = "/advisories?location=test";
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
