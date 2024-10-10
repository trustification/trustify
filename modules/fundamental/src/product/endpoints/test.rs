use crate::test::caller;
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use jsonpath_rust::JsonPathQuery;
use serde_json::{json, Value};
use test_context::test_context;
use test_log::test;
use trustify_common::db::query::Query;
use trustify_common::model::Paginated;
use trustify_module_ingestor::graph::product::ProductInformation;
use trustify_test_context::{call::CallService, TrustifyContext};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_products(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
                cpe: None,
            },
            (),
        )
        .await?;

    ctx.graph
        .ingest_product(
            "AMQ Broker",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
                cpe: None,
            },
            (),
        )
        .await?;

    let uri = "/api/v1/product?sort=name";

    let request = TestRequest::get().uri(uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    let names = response.path("$.items[*].name").unwrap();

    assert_eq!(names, json!(["AMQ Broker", "Trusted Profile Analyzer",]));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn one_product(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
                cpe: None,
            },
            (),
        )
        .await?;

    let service = crate::product::service::ProductService::new(ctx.db.clone());

    let products = service
        .fetch_products(Query::default(), Paginated::default(), ())
        .await?;

    assert_eq!(1, products.total);

    let first_product = &products.items[0];
    let product_id = first_product.head.id;

    let uri = format!("/api/v1/product/{}", product_id);

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    let name = response.clone().path("$.name").unwrap();

    assert_eq!(name, json!(["Trusted Profile Analyzer"]));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn delete_product(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
                cpe: None,
            },
            (),
        )
        .await?;

    let service = crate::product::service::ProductService::new(ctx.db.clone());

    let products = service
        .fetch_products(Query::default(), Paginated::default(), ())
        .await?;

    assert_eq!(1, products.total);

    let first_product = &products.items[0];
    let product_id = first_product.head.id;

    let uri = format!("/api/v1/product/{}", product_id);

    let request = TestRequest::delete().uri(&uri).to_request();

    let response = app.call_service(request).await;

    assert_eq!(response.status(), StatusCode::OK);

    let products = service
        .fetch_products(Query::default(), Paginated::default(), ())
        .await?;

    assert_eq!(0, products.total);

    let request = TestRequest::delete().uri(&uri).to_request();

    let response = app.call_service(request).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}
