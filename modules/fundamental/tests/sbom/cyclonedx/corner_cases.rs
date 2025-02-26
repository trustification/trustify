use test_context::test_context;
use test_log::test;
use trustify_test_context::TrustifyContext;

/// test to see some error message, instead of plain failure
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn ingest_broken_refs(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx
        .ingest_document("cyclonedx/broken-refs.json")
        .await
        .expect_err("must fail");

    assert_eq!(result.to_string(), "Invalid reference: b");

    Ok(())
}
