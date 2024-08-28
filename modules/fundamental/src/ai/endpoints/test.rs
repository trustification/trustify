use crate::ai::model::ChatState;
use crate::ai::service::test::ingest_fixtures;
use crate::ai::service::AiService;
use crate::test::caller;
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_test_context::call::CallService;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn configure(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let service = AiService::new(ctx.db.clone());
    if !service.enabled() {
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
