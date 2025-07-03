use crate::ai::model::{ChatMessage, ChatState, Conversation, ConversationSummary};
use crate::ai::service::AiService;
use crate::ai::service::test::{ingest_fixtures, sanitize_uuid_field, sanitize_uuid_urn};
use crate::test::caller;
use actix_http::StatusCode;
use actix_web::dev::ServiceResponse;
use actix_web::test::{TestRequest, read_body_json};
use serde_json::json;
use test_context::test_context;
use test_log::test;
use trustify_common::model::PaginatedResults;
use trustify_test_context::TrustifyContext;
use trustify_test_context::auth::TestAuthentication;
use trustify_test_context::call::CallService;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn configure(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = AiService::new(ctx.db.clone());
    if !service.completions_enabled() {
        return Ok(()); // skip test
    }

    ingest_fixtures(ctx).await?;

    let app = caller(ctx).await?;
    let mut req = ChatState::default();
    req.messages.push(ChatMessage::human("Give me information about the SBOMs available for quarkus reporting its name, SHA and URL.".into()));

    let request = TestRequest::post()
        .uri("/api/v2/ai/completions")
        .set_json(req)
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let result: ChatState = actix_web::test::read_body_json(response).await;
    log::info!("result: {result:?}");
    assert!(
        result
            .messages
            .last()
            .unwrap()
            .content
            .contains("quarkus-bom")
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn flags(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let request = TestRequest::get().uri("/api/v2/ai/flags").to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = actix_web::test::read_body_json(response).await;
    log::info!("result: {result:?}");

    let service = AiService::new(ctx.db.clone());

    assert_eq!(
        result,
        json!({
            "completions": service.completions_enabled(),
        }),
        "result:\n{result:#?}"
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn tools(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let app = caller(ctx).await?;
    let request = TestRequest::get().uri("/api/v2/ai/tools").to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let result: serde_json::Value = actix_web::test::read_body_json(response).await;
    log::info!("result: {result:?}");

    let expected: serde_json::Value =
        serde_json::from_str(include_str!("expected_tools_result.json"))?;
    assert_eq!(result, expected, "result:\n{result:#?}");

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
        .uri("/api/v2/ai/tools/unknown")
        .set_json(json!({"input":"quarkus"}))
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let request = TestRequest::post()
        .uri("/api/v2/ai/tools/sbom-info")
        .set_json(json!({"input":"quarkus"}))
        .to_request();

    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    let result = sanitize_uuid_urn(sanitize_uuid_field(read_text(response).await?));
    log::info!("result: {result:?}");

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

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn conversation_crud(ctx: &TrustifyContext) -> anyhow::Result<()> {
    if !AiService::new(ctx.db.clone()).completions_enabled() {
        return Ok(()); // skip test
    }

    ctx.ingest_document("quarkus/v1/quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    let app = caller(ctx).await?;

    // Verify that there are no conversations
    let request = TestRequest::get()
        .uri("/api/v2/ai/conversations")
        .to_request()
        .test_auth("user-a");

    let response = app.call_service(request).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "response: {:?}",
        read_text(response).await
    );

    let result: PaginatedResults<ConversationSummary> = read_body_json(response).await;
    assert_eq!(result.total, 0);
    assert_eq!(result.items.len(), 0);

    // Create a conversation
    let request = TestRequest::post()
        .uri("/api/v2/ai/conversations")
        .to_request()
        .test_auth("user-a");

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let conversation_v1: Conversation = read_body_json(response).await;
    assert_eq!(conversation_v1.seq, 0);
    assert_eq!(
        conversation_v1.messages.len(),
        0,
        "empty conversation should have no messages"
    );

    // Add first message to the conversation
    let mut update1 = conversation_v1.messages.clone();
    update1.push(ChatMessage::human(
        "What is the latest version of Quarks?".into(),
    ));

    let request = TestRequest::put()
        .uri(format!("/api/v2/ai/conversations/{}", conversation_v1.id).as_str())
        .set_json(update1.clone())
        .to_request()
        .test_auth("user-a");

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let conversation_v2: Conversation = read_body_json(response).await;
    assert_eq!(conversation_v2.seq, 1);
    assert!(
        conversation_v2.messages.len() > update1.len(),
        "assistant should add more messages"
    );

    // Verify that the conversation can be listed
    let request = TestRequest::get()
        .uri("/api/v2/ai/conversations")
        .to_request()
        .test_auth("user-a");

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let result: PaginatedResults<ConversationSummary> = read_body_json(response).await;
    assert_eq!(result.total, 1);
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].id, conversation_v1.id);

    // Verify that we can retrieve the conversation by ID
    let request = TestRequest::get()
        .uri(format!("/api/v2/ai/conversations/{}", conversation_v1.id).as_str())
        .to_request()
        .test_auth("user-a");

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let result: Conversation = read_body_json(response).await;
    assert_eq!(result, conversation_v2);

    // Verify that we can update the conversation
    let mut update2 = conversation_v2.messages.clone();
    update2.push(ChatMessage::human(
        "Are there any related CVEs affecting it?".into(),
    ));

    let request = TestRequest::put()
        .uri(format!("/api/v2/ai/conversations/{}", conversation_v1.id).as_str())
        .append_header(("if-match", format!("\"{}\"", conversation_v2.seq).as_str()))
        .set_json(update2.clone())
        .to_request()
        .test_auth("user-a");

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let conversation_v3: Conversation = read_body_json(response).await;
    assert_eq!(conversation_v3.seq, conversation_v2.seq + 1);
    assert!(
        conversation_v3.messages.len() > update2.len(),
        "assistant should add more messages"
    );

    // Verify that we can retrieve the updated conversation by ID
    let request = TestRequest::get()
        .uri(format!("/api/v2/ai/conversations/{}", conversation_v1.id).as_str())
        .to_request()
        .test_auth("user-a");

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let result: Conversation = read_body_json(response).await;
    assert_eq!(result, conversation_v3);

    // Verify that we can delete the conversation
    let request = TestRequest::delete()
        .uri(format!("/api/v2/ai/conversations/{}", conversation_v1.id).as_str())
        .to_request()
        .test_auth("user-a");

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // Verify that the conversation is deleted
    let request = TestRequest::get()
        .uri("/api/v2/ai/conversations")
        .to_request()
        .test_auth("user-a");

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let result: PaginatedResults<ConversationSummary> = read_body_json(response).await;
    assert_eq!(result.total, 0);
    assert_eq!(result.items.len(), 0);

    Ok(())
}
