use crate::{configure, sbom::model::SbomPackage};
use actix_http::Request;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceResponse},
    test::TestRequest,
    web, App, Error,
};
use test_context::test_context;
use test_log::test;
use tokio_util::io::ReaderStream;
use trustify_auth::authorizer::Authorizer;
use trustify_common::{db::test::TrustifyContext, model::PaginatedResults};
use trustify_module_ingestor::{graph::Graph, model::IngestResult, service::IngestorService};
use trustify_module_storage::service::fs::FileSystemBackend;

async fn query<S, B>(app: &S, id: &str, q: &str) -> PaginatedResults<SbomPackage>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    let uri = format!("/api/v1/sbom/{id}/packages?q={}", urlencoding::encode(q));
    let req = TestRequest::get().uri(&uri).to_request();
    actix_web::test::call_and_read_body_json(app, req).await
}

async fn ingest(service: &IngestorService, data: &[u8]) -> IngestResult {
    use trustify_module_ingestor::service::Format;
    service
        .ingest(
            ("source", "unit-test"),
            None,
            Format::from_bytes(data).unwrap(),
            ReaderStream::new(data),
        )
        .await
        .unwrap()
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn filter_packages(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _) = FileSystemBackend::for_test().await?;
    let ingestor = IngestorService::new(graph, storage.clone());
    let app = actix_web::test::init_service(
        App::new()
            .service(web::scope("/api").configure(|config| configure(config, db, storage.clone())))
            .app_data(web::Data::new(Authorizer::new(None))),
    )
    .await;

    let data = include_bytes!("../../../../../etc/test-data/zookeeper-3.9.2-cyclonedx.json");
    let id = ingest(&ingestor, data).await.id.to_string();

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
