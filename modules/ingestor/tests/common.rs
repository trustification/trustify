use trustify_module_ingestor::endpoints::{configure, Config};
use trustify_test_context::{
    call::{self, CallService},
    TrustifyContext,
};

pub async fn caller_with(
    ctx: &TrustifyContext,
    config: Config,
) -> anyhow::Result<impl CallService + '_> {
    call::caller(|svc| configure(svc, config, ctx.db.clone(), ctx.storage.clone())).await
}
