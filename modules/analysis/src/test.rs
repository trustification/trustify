use crate::endpoints::configure;
use trustify_test_context::{
    call::{self, CallService},
    TrustifyContext,
};

pub async fn caller(ctx: &TrustifyContext) -> anyhow::Result<impl CallService + '_> {
    call::caller(|svc| configure(svc, ctx.db.clone())).await
}
