#![allow(clippy::expect_used)]

use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

/// A simple test for ingesting two SPDX SBOMs with external references
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_ext_1(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple-ext-a.json", "spdx/simple-ext-b.json"])
        .await?;

    // TODO: query once that side is implemented

    Ok(())
}
