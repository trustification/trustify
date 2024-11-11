use test_context::test_context;
use test_log::test;
use trustify_module_ingestor::service::Format;
use trustify_test_context::TrustifyContext;

/// Test for <https://github.com/gcmurphy/osv/pull/51>
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn pypa_yaml(ctx: &TrustifyContext) -> anyhow::Result<()> {
    ctx.ingest_document_as("osv/PYSEC-2024-55.yaml", Format::OSV)
        .await?;

    Ok(())
}
