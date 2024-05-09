use super::Error;
use crate::service::StorageBackend;
use actix_web::{get, web, HttpResponse, Responder};
use futures::TryStreamExt;

use crate::service::dispatch::DispatchBackend;

#[utoipa::path(
    tag = "advisory",
    responses(
        (status = 200, description = "Download a an advisory", body = Vec<u8>),
        (status = 404, description = "The document could not be found"),
    )
)]
#[get("/api/v1/advisory/{sha256}/download")]
pub async fn download_advisory(
    service: web::Data<DispatchBackend>,
    path: web::Path<String>,
) -> Result<impl Responder, Error> {
    let hash = path.into_inner();
    let stream = service
        .get_ref()
        .clone()
        .retrieve(hash)
        .await
        .map_err(Error::Storage)?
        .map(|stream| stream.map_err(Error::Storage));

    Ok(match stream {
        Some(s) => HttpResponse::Ok().streaming(s),
        None => HttpResponse::NotFound().finish(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::configure;

    use crate::service::fs::FileSystemBackend;
    use crate::service::StorageBackend;
    use actix_web::{test, test::TestRequest, App};
    use hex::ToHex;
    use serde_json::Value;
    use tokio_util::io::ReaderStream;

    #[test_log::test(actix_web::test)]
    async fn download_advisory() -> Result<(), anyhow::Error> {
        let (storage, _) = FileSystemBackend::for_test().await?;
        let app = test::init_service(App::new().configure(|s| configure(s, storage.clone()))).await;

        let data: &[u8] = include_bytes!("../../../../etc/test-data/cve-2023-33201.json");
        let digest: String = storage.store(ReaderStream::new(data)).await?.encode_hex();

        let uri = format!("/api/v1/advisory/{digest}/download");
        let request = TestRequest::get().uri(&uri).to_request();

        let response = test::call_service(&app, request).await;
        assert!(response.status().is_success());
        let doc: Value = test::read_body_json(response).await;
        assert_eq!(doc["document"]["tracking"]["id"], "CVE-2023-33201");

        Ok(())
    }
}
