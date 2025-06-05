use trustify_module_analysis::config::AnalysisConfig;
use trustify_module_analysis::service::AnalysisService;
use trustify_test_context::{
    TrustifyContext,
    call::{self, CallService},
};

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    caller_with(ctx, Config::default()).await
}

async fn caller_with(
    ctx: &TrustifyContext,
    config: Config,
) -> anyhow::Result<impl CallService + '_> {
    let analysis = AnalysisService::new(AnalysisConfig::default(), ctx.db.clone());
    call::caller(|svc| {
        configure(
            svc,
            config,
            ctx.db.clone(),
            ctx.storage.clone(),
            analysis.clone(),
        );
        trustify_module_analysis::endpoints::configure(svc, ctx.db.clone(), analysis);
        trustify_module_signature::endpoints::configure(svc, ctx.db.clone());
    })
    .await
}
