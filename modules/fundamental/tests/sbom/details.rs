use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_cvss::cvss3::severity::Severity;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[instrument]
#[test(tokio::test)]
async fn sbom_details_cyclonedx_osv(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = SbomService::new(ctx.db.clone());

    // ingest the SBOM
    let result1 = ctx.ingest_document("cyclonedx/pypi_aiohttp.json").await?;

    assert_eq!(
        result1.document_id,
        Some("urn:uuid:a5ddee00-4b86-498c-b7fd-b001b77479d1".to_string())
    );

    // ingest the advisory
    let result2 = ctx.ingest_document("osv/GHSA-45c4-8wx5-qw6w.json").await?;

    assert_eq!(result2.document_id, Some("GHSA-45c4-8wx5-qw6w".to_string()));

    let sbom1 = sbom
        .fetch_sbom_details(result1.id, vec![], &ctx.db)
        .await?
        .expect("SBOM details must be found");
    log::info!("SBOM1: {sbom1:?}");

    assert_eq!(1, sbom1.advisories.len());
    assert_eq!("GHSA-45c4-8wx5-qw6w", sbom1.advisories[0].head.document_id);
    assert_eq!(1, sbom1.advisories[0].status.len());
    assert_eq!(
        "CVE-2023-37276",
        sbom1.advisories[0].status[0].vulnerability.identifier
    );
    assert_eq!(
        Severity::Medium,
        sbom1.advisories[0].status[0].average_severity
    );
    assert_eq!("affected", sbom1.advisories[0].status[0].status);
    Ok(())
}
