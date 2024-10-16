use crate::sbom::service::SbomService;
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::db::Transactional;
use trustify_common::id::Id;
use trustify_common::purl::Purl;
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

    let details = service
        .fetch_sbom_details(Id::Uuid(details.summary.head.id), Transactional::None)
        .await?;

    assert!(details.is_some());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn count_sboms(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let _ = ctx
        .ingest_documents([
            "spdx/quarkus-bom-3.2.11.Final-redhat-00001.json",
            "spdx/quarkus-bom-3.2.12.Final-redhat-00002.json",
        ])
        .await?;

    let service = SbomService::new(ctx.db.clone());

    let neither = Purl::from_str("pkg:maven/io.smallrye/smallrye-graphql@0.0.0.redhat-00000?repository_url=https://maven.repository.redhat.com/ga/&type=jar")?;
    let both = Purl::from_str("pkg:maven/io.smallrye/smallrye-graphql@2.2.3.redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=jar")?;
    let one = Purl::from_str("pkg:maven/io.quarkus/quarkus-kubernetes-service-binding-deployment@3.2.12.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=jar")?;
    let counts = service
        .count_related_sboms(
            vec![
                neither.qualifier_uuid(),
                both.qualifier_uuid(),
                one.qualifier_uuid(),
            ],
            (),
        )
        .await?;

    assert_eq!(counts, vec![0, 2, 1]);

    Ok(())
}
