use crate::{
    sbom::model::SbomPackage,
    test::{caller, CallService},
};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_common::{id::Id, model::PaginatedResults};
use trustify_entity::labels::Labels;
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::{document_bytes, TrustifyContext};
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;

    let request = TestRequest::post()
        .uri("/api/v1/sbom")
        .set_payload(document_bytes("quarkus-bom-2.13.8.Final-redhat-00004.json").await?)
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::CREATED);
    let result: IngestResult = actix_web::test::read_body_json(response).await;
    log::debug!("ID: {result:?}");
    assert!(matches!(result.id, Id::Uuid(_)));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn filter_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    async fn query(app: &impl CallService, id: &str, q: &str) -> PaginatedResults<SbomPackage> {
        let uri = format!("/api/v1/sbom/{id}/packages?q={}", urlencoding::encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        app.call_and_read_body_json(req).await
    }

    let app = caller(ctx).await?;
    let id = ctx
        .ingest_document("zookeeper-3.9.2-cyclonedx.json")
        .await?
        .id
        .to_string();

    let result = query(&app, &id, "").await;
    assert_eq!(result.total, 41);

    let result = query(&app, &id, "netty-common").await;
    assert_eq!(result.total, 1);
    assert_eq!(result.items[0].name, "netty-common");

    let result = query(&app, &id, r"type\=jar").await;
    assert_eq!(result.total, 41);

    let result = query(&app, &id, "version=4.1.105.Final").await;
    assert_eq!(result.total, 9);

    Ok(())
}

/// Test setting labels
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn set_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let result = ctx
        .ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;
    let request = TestRequest::patch()
        .uri(&format!("/api/v1/sbom/{}/label", result.id))
        .set_json(Labels::new().extend([("foo", "1"), ("bar", "2")]))
        .to_request();
    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    Ok(())
}

/// Test setting labels, for a document that does not exists
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn set_labels_not_found(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;
    let request = TestRequest::patch()
        .uri(&format!("/api/v1/sbom/{}/label", Id::Uuid(Uuid::now_v7())))
        .set_json(Labels::new().extend([("foo", "1"), ("bar", "2")]))
        .to_request();
    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}
