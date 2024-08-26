use crate::test::{caller, CallService};

use actix_http::Request;
use actix_web::test::TestRequest;
use serde_json::Value;
use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_retrieve_analysis_endpoint(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    //should match multiple components
    let uri = "/api/v1/analysis/root-component?q=B";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    if response["items"][0]["component"] == "pkg://rpm/redhat/BB@0.0.0"
        || response["items"][1]["component"] == "pkg://rpm/redhat/BB@0.0.0"
    {
        assert_eq!(&response["total"], 2);
    } else {
        panic!("one of the items component should have matched.");
    }

    //should match a single component
    let uri = "/api/v1/analysis/root-component?q=BB";
    let request: Request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(
        response["items"][0]["component"],
        "pkg://rpm/redhat/BB@0.0.0"
    );
    assert_eq!(
        response["items"][0]["ancestors"][1]["purl"],
        "pkg://rpm/redhat/AA@0.0.0"
    );
    Ok(assert_eq!(&response["total"], 1))
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_retrieve_by_name_analysis_endpoint(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let uri = "/api/v1/analysis/root-component/B";

    let request: Request = TestRequest::get().uri(uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    assert_eq!(
        response["items"][0]["component"],
        "pkg://rpm/redhat/B@0.0.0"
    );
    assert_eq!(
        response["items"][0]["ancestors"][1]["purl"],
        "pkg://rpm/redhat/A@0.0.0"
    );
    Ok(assert_eq!(&response["total"], 1))
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_simple_retrieve_by_purl_analysis_endpoint(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let uri = "/api/v1/analysis/root-component/pkg%3A%2F%2Frpm%2Fredhat%2FB%400.0.0";

    let request: Request = TestRequest::get().uri(uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    assert_eq!(
        response["items"][0]["component"],
        "pkg://rpm/redhat/B@0.0.0"
    );
    assert_eq!(
        response["items"][0]["ancestors"][1]["purl"],
        "pkg://rpm/redhat/A@0.0.0"
    );
    Ok(assert_eq!(&response["total"], 1))
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_quarkus_retrieve_analysis_endpoint(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_documents([
        "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
        "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
    ])
    .await?;

    let uri = "/api/v1/analysis/root-component?q=spymemcached";

    let request: Request = TestRequest::get().uri(uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    println!("{:?}", &response["items"]);
    assert_eq!(
        response["items"][0]["component"],
        "pkg://maven/net.spy/spymemcached@2.12.1?type=jar"
    );
    assert_eq!(
        response["items"][0]["ancestors"][0]["purl"],
        "pkg://maven/com.redhat.quarkus.platform/quarkus-bom@3.2.11.Final-redhat-00001?type=pom&repository_url=https://maven.repository.redhat.com/ga/"
    );

    Ok(assert_eq!(&response["total"], 1))
}
