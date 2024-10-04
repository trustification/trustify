use crate::ai::model::ChatState;
use crate::ai::service::test::{ingest_fixtures, sanitize_uuid};
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
    req.add_human_message("What is the latest version of Trusted Profile Analyzer?".into());

    let request = TestRequest::post()
        .uri("/api/v1/ai/completions")
        .set_json(req)
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let result: ChatState = actix_web::test::read_body_json(response).await;
    log::info!("result: {:?}", result);
    assert!(result.messages.last().unwrap().content.contains("37.17.9"));

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

    assert_eq!(
        result,
        json!([
          {
            "name": "product-info",
            "description": "This tool can be used to get information about a product.\nThe input should be the name of the product to search for.\nWhen the input is a full name, the tool will provide information about the product.\nWhen the input is a partial name, the tool will provide a list of possible matches.",
            "parameters": {
              "type": "object",
              "properties": {
                "input": {
                  "type": "string",
                  "description": "This tool can be used to get information about a product.\nThe input should be the name of the product to search for.\nWhen the input is a full name, the tool will provide information about the product.\nWhen the input is a partial name, the tool will provide a list of possible matches."
                }
              },
              "required": [
                "input"
              ]
            }
          },
          {
            "name": "cve-info",
            "description": "This tool can be used to get information about a Vulnerability.\nThe input should be the partial name of the Vulnerability to search for.\nWhen the input is a full CVE ID, the tool will provide information about the vulnerability.\nWhen the input is a partial name, the tool will provide a list of possible matches.",
            "parameters": {
              "type": "object",
              "properties": {
                "input": {
                  "type": "string",
                  "description": "This tool can be used to get information about a Vulnerability.\nThe input should be the partial name of the Vulnerability to search for.\nWhen the input is a full CVE ID, the tool will provide information about the vulnerability.\nWhen the input is a partial name, the tool will provide a list of possible matches."
                }
              },
              "required": [
                "input"
              ]
            }
          },
          {
            "name": "advisory-info",
            "description": "This tool can be used to get information about an Advisory.\nThe input should be the name of the Advisory to search for.\nWhen the input is a full name, the tool will provide information about the Advisory.\nWhen the input is a partial name, the tool will provide a list of possible matches.",
            "parameters": {
              "type": "object",
              "properties": {
                "input": {
                  "type": "string",
                  "description": "This tool can be used to get information about an Advisory.\nThe input should be the name of the Advisory to search for.\nWhen the input is a full name, the tool will provide information about the Advisory.\nWhen the input is a partial name, the tool will provide a list of possible matches."
                }
              },
              "required": [
                "input"
              ]
            }
          },
          {
            "name": "package-info",
            "description": "This tool can be used to get information about a Package.\nThe input should be the name of the package, it's Identifier uri or internal UUID.",
            "parameters": {
              "type": "object",
              "properties": {
                "input": {
                  "type": "string",
                  "description": "This tool can be used to get information about a Package.\nThe input should be the name of the package, it's Identifier uri or internal UUID."
                }
              },
              "required": [
                "input"
              ]
            }
          },
          {
            "name": "sbom-info",
            "description": "This tool can be used to get information about an SBOM.\nThe input should be the SBOM Identifier.",
            "parameters": {
              "type": "object",
              "properties": {
                "input": {
                  "type": "string",
                  "description": "This tool can be used to get information about an SBOM.\nThe input should be the SBOM Identifier."
                }
              },
              "required": [
                "input"
              ]
            }
          }
        ]),
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
    ingest_fixtures(ctx).await?;

    let app = caller(ctx).await?;

    let request = TestRequest::post()
        .uri("/api/v1/ai/tools/unknown")
        .set_json(json!("bad tool call"))
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let request = TestRequest::post()
        .uri("/api/v1/ai/tools/product-info")
        .set_json(json!("Trusted Profile Analyzer"))
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let result = sanitize_uuid(read_text(response).await?);
    log::info!("result: {:?}", result);

    assert_eq!(
        result.trim(),
        r#"
{
  "items": [
    {
      "name": "Trusted Profile Analyzer",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "vendor": "Red Hat",
      "versions": [
        "37.17.9"
      ]
    }
  ],
  "total": 1
}
"#
        .trim()
    );

    Ok(())
}
