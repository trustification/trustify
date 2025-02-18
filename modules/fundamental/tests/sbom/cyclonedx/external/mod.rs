#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

mod rh;

/// A simple test for ingesting two CDX SBOMs with external references
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_ext_1(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple-ext-a.json", "cyclonedx/simple-ext-b.json"])
        .await?;

    // TODO: query once that side is implemented

    Ok(())
}
