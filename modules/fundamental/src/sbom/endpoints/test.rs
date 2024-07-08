use crate::{configure, sbom::model::SbomPackage, test::CallService};
use actix_http::{Request, StatusCode};
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceResponse},
    test::TestRequest,
    web, App, Error,
};
use futures_util::future::LocalBoxFuture;
use test_context::test_context;
use test_log::test;
use trustify_auth::authorizer::Authorizer;
use trustify_common::{id::Id, model::PaginatedResults};
use trustify_entity::labels::Labels;
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

async fn query<S, B>(app: &S, id: &str, q: &str) -> PaginatedResults<SbomPackage>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    let uri = format!("/api/v1/sbom/{id}/packages?q={}", urlencoding::encode(q));
    let req = TestRequest::get().uri(&uri).to_request();
    actix_web::test::call_and_read_body_json(app, req).await
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn filter_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = actix_web::test::init_service(
        App::new()
            .service(
                web::scope("/api")
                    .configure(|config| configure(config, ctx.db.clone(), ctx.storage.clone())),
            )
            .app_data(web::Data::new(Authorizer::new(None))),
    )
    .await;

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

/// This will upload [`DOC`], and then call the test function, providing the upload id of the document.
async fn with_upload<F>(ctx: &TrustifyContext, f: F) -> anyhow::Result<()>
where
    for<'a> F: FnOnce(IngestResult, &'a dyn CallService) -> LocalBoxFuture<'a, anyhow::Result<()>>,
{
    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::PayloadConfig::default().limit(5 * 1024 * 1024))
            .service(
                web::scope("/api")
                    .configure(|svc| configure(svc, ctx.db.clone(), ctx.storage.clone())),
            ),
    )
    .await;

    // upload

    let request = TestRequest::post()
        .uri("/api/v1/sbom")
        .set_payload(
            ctx.document_bytes("quarkus-bom-2.13.8.Final-redhat-00004.json")
                .await?,
        )
        .to_request();

    let response = actix_web::test::call_service(&app, request).await;

    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::CREATED);
    let result: IngestResult = actix_web::test::read_body_json(response).await;

    log::debug!("ID: {result:?}");
    assert!(matches!(result.id, Id::Uuid(_)));

    f(result, &app).await?;

    // download

    Ok(())
}

/// Test setting labels
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn set_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    with_upload(ctx, |result, app| {
        Box::pin(async move {
            // update labels

            let request = TestRequest::patch()
                .uri(&format!("/api/v1/sbom/{}/label", result.id))
                .set_json(Labels::new().extend([("foo", "1"), ("bar", "2")]))
                .to_request();

            let response = app.call_service(request).await;

            log::debug!("Code: {}", response.status());
            assert_eq!(response.status(), StatusCode::NO_CONTENT);

            Ok(())
        })
    })
    .await
}

/// Test setting labels, for a document that does not exists
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn set_labels_not_found(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    with_upload(ctx, |_result, app| {
        Box::pin(async move {
            // update labels

            let request = TestRequest::patch()
                .uri(&format!("/api/v1/sbom/{}/label", Id::Uuid(Uuid::now_v7())))
                .set_json(Labels::new().extend([("foo", "1"), ("bar", "2")]))
                .to_request();

            let response = app.call_service(request).await;

            log::debug!("Code: {}", response.status());
            assert_eq!(response.status(), StatusCode::NOT_FOUND);

            Ok(())
        })
    })
    .await
}
