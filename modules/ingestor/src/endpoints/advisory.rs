use crate::service::advisory::csaf::loader::CsafLoader;
use crate::service::advisory::osv::loader::OsvLoader;
use actix_web::http::StatusCode;
use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use std::io::BufReader;
use trustify_module_graph::endpoints::Error;
use trustify_module_graph::graph::Graph;

#[utoipa::path(
tag = "ingestor",
request_body = Vec < u8 >,
responses(
(status = 200, description = "Upload a file"),
(status = 400, description = "The file could not be parsed as an advisory document"),
)
)]
#[post("/advisories/{advisory_format}")]
/// Upload a new advisory
pub async fn upload_advisory(
    graph: web::Data<Graph>,
    req: HttpRequest,
    path: web::Path<String>,
    payload: web::Payload,
) -> Result<impl Responder, Error> {
    let advisory_format = path.into_inner().to_lowercase();

    let payload_bytes = payload.to_bytes().await?;
    let payload = BufReader::new(payload_bytes.as_ref());

    if advisory_format == "csaf" {
        let loader = CsafLoader::new(&graph);

        let advisory_id = loader
            .load(req.path(), payload)
            .await
            .map_err(anyhow::Error::new)?;
        Ok(HttpResponse::Created().json(advisory_id))
    } else if advisory_format == "osv" {
        let loader = OsvLoader::new(&graph);

        let advisory_id = loader
            .load(req.path(), payload)
            .await
            .map_err(anyhow::Error::new)?;
        Ok(HttpResponse::Created().json(advisory_id))
    } else {
        Err(Error::BadRequest {
            msg: "Unsupported advisory format".to_string(),
            status: StatusCode::EXPECTATION_FAILED,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::configure;

    use actix_web::test::TestRequest;
    use actix_web::web::Data;
    use actix_web::{test, App};
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::Arc;
    use trustify_common::db::Database;
    use trustify_module_graph::graph::Graph;

    #[actix_web::test]
    async fn upload_advisory() -> Result<(), anyhow::Error> {
        let state = Arc::new(Graph::new(Database::for_test("upload_advisory").await?));

        let app = test::init_service(
            App::new()
                .app_data(Data::from(state.clone()))
                .configure(configure),
        )
        .await;

        let pwd = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))?;
        let test_data = pwd.join("../../etc/test-data");

        let advisory = test_data.join("cve-2023-33201.json");

        let payload = fs::read_to_string(advisory).expect("File not found");
        let uri = "/advisories/csaf";
        let request = TestRequest::post()
            .uri(uri)
            .set_payload(payload)
            .to_request();

        let response = test::call_service(&app, request).await;

        assert!(response.status().is_success());

        Ok(())
    }
}
