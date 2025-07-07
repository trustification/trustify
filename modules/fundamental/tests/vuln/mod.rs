use itertools::Itertools;
use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::vulnerability::service::VulnerabilityService;
use trustify_test_context::{Dataset, TrustifyContext};

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn issue_1840(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_dataset(Dataset::DS3).await?;

    let service = VulnerabilityService::new();

    let result = service
        .analyze_purls(["pkg:rpm/redhat/gnutls@3.7.6-23.el9?arch=aarch64"], &ctx.db)
        .await?;

    println!("{:#?}", result);

    assert_eq!(result.len(), 1);

    let entry = &result["pkg:rpm/redhat/gnutls@3.7.6-23.el9?arch=aarch64"];

    let ids = entry
        .iter()
        .map(|vuln| &vuln.head.identifier)
        .sorted()
        .collect::<Vec<_>>();

    // TODO: find out why we return four times the same
    assert_eq!(
        ids,
        vec![
            "CVE-2024-28834",
            "CVE-2024-28834",
            "CVE-2024-28834",
            "CVE-2024-28834"
        ]
    );

    Ok(())
}
