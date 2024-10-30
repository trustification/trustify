use actix_web::{web, App};
use trustify_auth::authorizer::Authorizer;
use trustify_module_ingestor::endpoints::{configure, Config};
use trustify_test_context::{call::CallService, TrustifyContext};
use utoipa_actix_web::AppExt;

#[allow(unused)]
pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService> {
    caller_with(ctx, Config::default()).await
}

pub async fn caller_with(
    ctx: &TrustifyContext,
    config: Config,
) -> anyhow::Result<impl CallService> {
    Ok(actix_web::test::init_service(
        App::new()
            .into_utoipa_app()
            .app_data(web::PayloadConfig::default().limit(5 * 1024 * 1024))
            .app_data(web::Data::new(Authorizer::new(None)))
            .service(
                utoipa_actix_web::scope("/api")
                    .configure(|svc| configure(svc, config, ctx.db.clone(), ctx.storage.clone())),
            )
            .into_app(),
    )
    .await)
}
