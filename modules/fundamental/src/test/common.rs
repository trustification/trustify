use trustify_module_analysis::service::AnalysisService;
use trustify_test_context::{
    call::{self, CallService},
    TrustifyContext,
};

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    caller_with(ctx, Config::default()).await
}

async fn caller_with(
    ctx: &TrustifyContext,
    config: Config,
) -> anyhow::Result<impl CallService + '_> {
    let analysis = AnalysisService::new();
    call::caller(|svc| configure(svc, config, ctx.db.clone(), ctx.storage.clone(), analysis)).await
}
