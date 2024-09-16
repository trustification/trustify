use crate::sbom::service::SbomService;
use test_context::test_context;
use test_log::test;
use trustify_common::db::Transactional;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn sbom_details_status(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let results = ctx
        .ingest_documents([
            "cve/CVE-2024-29025.json",
            "csaf/rhsa-2024-2705.json",
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

    let service = SbomService::new(ctx.db.clone());

    let id_3_2_12 = results[3].id.clone();

    let details = service
        .fetch_sbom_details(id_3_2_12, Transactional::None)
        .await?;

    assert!(details.is_some());

    let details = details.unwrap();

    log::debug!("{}", serde_json::to_string_pretty(&details)?);

    Ok(())
}
