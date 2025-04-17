use test_context::test_context;
use test_log::test;
use trustify_module_ingestor::service::Format;
use trustify_test_context::TrustifyContext;

/// This is a test for issue #1535
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn not_really_clearly_defined(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_document_as("csaf/timeout/rhsa-2024_5363.json.xz", Format::SBOM)
        .await;

    assert!(result.is_err());

    Ok(())
}
