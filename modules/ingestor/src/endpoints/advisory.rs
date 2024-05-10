use crate::service::{Error, Format, IngestorService};
use actix_web::{post, web, HttpResponse, Responder};
use tokio_util::io::ReaderStream;
use utoipa::IntoParams;

#[derive(
    IntoParams, Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
struct UploadParams {
    /// Optional issuer if it cannot be determined from advisory contents.
    issuer: Option<String>,
}

#[utoipa::path(
    tag = "advisory",
    request_body = Vec < u8 >,
    params( UploadParams ),
    responses(
        (status = 201, description = "Upload a file"),
        (status = 400, description = "The file could not be parsed as an advisory"),
    )
)]
#[post("/api/v1/advisory")]
/// Upload a new advisory
pub async fn upload_advisory(
    service: web::Data<IngestorService>,
    web::Query(UploadParams { issuer }): web::Query<UploadParams>,
    bytes: web::Bytes,
) -> Result<impl Responder, Error> {
    let fmt = Format::from_bytes(&bytes)?;
    let payload = ReaderStream::new(&*bytes);
    let advisory_id = service.ingest("rest-api", issuer, fmt, payload).await?;
    Ok(HttpResponse::Created().json(advisory_id))
}

#[cfg(test)]
mod tests {
    use super::super::configure;

    use actix_web::{http::StatusCode, test, test::TestRequest, App};
    use test_context::test_context;
    use trustify_common::db::test::TrustifyContext;
    use trustify_module_storage::service::fs::FileSystemBackend;

    #[test_context(TrustifyContext, skip_teardown)]
    #[test_log::test(actix_web::test)]
    async fn upload_default_csaf_format(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let (storage, _temp) = FileSystemBackend::for_test().await?;
        let app = test::init_service(App::new().configure(|svc| configure(svc, db, storage))).await;
        let payload = include_str!("../../../../etc/test-data/cve-2023-33201.json");

        let uri = "/api/v1/advisory";
        let request = TestRequest::post()
            .uri(uri)
            .set_payload(payload)
            .to_request();

        let response = test::call_service(&app, request).await;
        assert!(response.status().is_success());
        let id: String = test::read_body_json(response).await;
        assert_eq!(id, "CVE-2023-33201");

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test_log::test(actix_web::test)]
    async fn upload_osv_format(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let (storage, _temp) = FileSystemBackend::for_test().await?;
        let app = test::init_service(App::new().configure(|svc| configure(svc, db, storage))).await;
        let payload = include_str!("../../../../etc/test-data/osv/RUSTSEC-2021-0079.json");

        let uri = "/api/v1/advisory";
        let request = TestRequest::post()
            .uri(uri)
            .set_payload(payload)
            .to_request();

        let response = test::call_service(&app, request).await;
        assert!(response.status().is_success());
        let id: String = test::read_body_json(response).await;
        assert_eq!(id, "RUSTSEC-2021-0079");

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test_log::test(actix_web::test)]
    async fn upload_cve_format(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let (storage, _temp) = FileSystemBackend::for_test().await?;
        let app = test::init_service(App::new().configure(|svc| configure(svc, db, storage))).await;
        let payload = include_str!("../../../../etc/test-data/mitre/CVE-2024-27088.json");

        let uri = "/api/v1/advisory";
        let request = TestRequest::post()
            .uri(uri)
            .set_payload(payload)
            .to_request();

        let response = test::call_service(&app, request).await;
        assert!(response.status().is_success());
        let id: String = test::read_body_json(response).await;
        assert_eq!(id, "CVE-2024-27088");

        Ok(())
    }

    #[test_context(TrustifyContext, skip_teardown)]
    #[test_log::test(actix_web::test)]
    async fn upload_unknown_format(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
        let db = ctx.db;
        let (storage, _temp) = FileSystemBackend::for_test().await?;
        let app = test::init_service(App::new().configure(|svc| configure(svc, db, storage))).await;

        let uri = "/api/v1/advisory";
        let request = TestRequest::post().uri(uri).to_request();

        let response = test::call_service(&app, request).await;
        log::debug!("response: {response:?}");

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Wrong HTTP response status"
        );

        Ok(())
    }
}
