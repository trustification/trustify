use test_context::test_context;
use test_log::test;
use trustify_common::id::Id;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
/// Ingested SBOM should not fail
async fn issue_1492(ctx: &TrustifyContext) -> anyhow::Result<()> {
    let result = ctx
        .ingest_document("spdx/issues/1492/sbom.spdx.json")
        .await?;

    assert!(matches!(result.id, Id::Uuid(_)));

    Ok(())
}
