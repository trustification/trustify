use crate::ai::model::ChatState;
use crate::ai::service::test::{ingest_fixtures, sanitize_uuid_field, sanitize_uuid_urn};
use crate::ai::service::AiService;
use crate::test::caller;
use actix_http::StatusCode;
use actix_web::dev::ServiceResponse;
use actix_web::test::TestRequest;
use serde_json::json;
use test_context::test_context;
use test_log::test;
use trustify_test_context::call::CallService;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn configure(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = AiService::new(ctx.db.clone());
    if !service.completions_enabled() {
        return Ok(()); // skip test
    }

    ingest_fixtures(ctx).await?;

    let app = caller(ctx).await?;
    let mut req = ChatState::new();
    req.add_human_message("Give me information about the SBOMs available for quarkus reporting its name, SHA and URL.".into());

    let request = TestRequest::post()
        .uri("/api/v1/ai/completions")
        .set_json(req)
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let result: ChatState = actix_web::test::read_body_json(response).await;
    log::info!("result: {:?}", result);
    assert!(result
        .messages
        .last()
        .unwrap()
        .content
        .contains("quarkus-bom"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn flags(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let request = TestRequest::get().uri("/api/v1/ai/flags").to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = actix_web::test::read_body_json(response).await;
    log::info!("result: {:?}", result);

    let service = AiService::new(ctx.db.clone());

    assert_eq!(
        result,
        json!({
            "completions": service.completions_enabled(),
        }),
        "result:\n{}",
        serde_json::to_string_pretty(&result)?
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn tools(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let request = TestRequest::get().uri("/api/v1/ai/tools").to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = actix_web::test::read_body_json(response).await;
    log::info!("result: {:?}", result);

    let expected: serde_json::Value =
        serde_json::from_str(include_str!("expected_tools_result.json"))?;
    assert_eq!(
        result,
        expected,
        "result:\n{}",
        serde_json::to_string_pretty(&result)?
    );

    Ok(())
}

async fn read_text(response: ServiceResponse) -> anyhow::Result<String> {
    let body = actix_web::test::read_body(response).await;
    let res = std::str::from_utf8(&body)?;
    Ok(res.to_string())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn tools_call(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document("quarkus/v1/quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    let app = caller(ctx).await?;

    let request = TestRequest::post()
        .uri("/api/v1/ai/tools/unknown")
        .set_json(json!("bad tool call"))
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let request = TestRequest::post()
        .uri("/api/v1/ai/tools/sbom-info")
        .set_json(json!("quarkus"))
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let result = sanitize_uuid_urn(sanitize_uuid_field(read_text(response).await?));
    log::info!("result: {:?}", result);

    assert_eq!(
        result.trim(),
        r#"
{
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "source_document_sha256": "sha256:5a370574a991aa42f7ecc5b7d88754b258f81c230a73bea247c0a6fcc6f608ab",
  "name": "quarkus-bom",
  "published": "2023-11-13T00:10:00Z",
  "authors": [
    "Organization: Red Hat Product Security (secalert@redhat.com)"
  ],
  "labels": [
    [
      "source",
      "TrustifyContext"
    ],
    [
      "type",
      "spdx"
    ]
  ],
  "advisories": [],
  "link": "http://localhost:3000/sboms/urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
"#
            .trim()
    );

    Ok(())
}
