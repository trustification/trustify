use crate::product::endpoints::configure;
use actix_web::test::TestRequest;
use actix_web::{web, App};
use jsonpath_rust::JsonPathQuery;
use serde_json::{json, Value};
use test_context::test_context;
use test_log::test;
use trustify_common::db::query::Query;
use trustify_common::db::test::TrustifyContext;
use trustify_common::model::Paginated;
use trustify_module_ingestor::graph::product::ProductInformation;
use trustify_module_ingestor::graph::Graph;

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn all_products(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db.clone()))),
    )
    .await;

    graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
            },
            (),
        )
        .await?;

    graph
        .ingest_product(
            "AMQ Broker",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
            },
            (),
        )
        .await?;

    let uri = "/api/v1/product?sort=name";

    let request = TestRequest::get().uri(uri).to_request();

    let response: Value = actix_web::test::call_and_read_body_json(&app, request).await;

    let names = response.path("$.items[*].name").unwrap();

    assert_eq!(names, json!(["AMQ Broker", "Trusted Profile Analyzer",]));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn one_product(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db.clone()))),
    )
    .await;

    graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
            },
            (),
        )
        .await?;

    let service = crate::product::service::ProductService::new(db);

    let products = service
        .fetch_products(Query::default(), Paginated::default(), ())
        .await?;

    assert_eq!(1, products.total);

    let first_product = &products.items[0];
    let product_id = first_product.head.id;

    let uri = format!("/api/v1/product/{}", product_id);

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = actix_web::test::call_and_read_body_json(&app, request).await;

    let name = response.clone().path("$.name").unwrap();

    assert_eq!(name, json!(["Trusted Profile Analyzer"]));

    Ok(())
}
