use crate::{sbom::model::SbomExternalPackageReference, sbom::service::SbomService};
use std::collections::HashMap;
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::cpe::Cpe;
use trustify_common::{id::Id, purl::Purl};
use trustify_entity::labels::Labels;
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
        .fetch_sbom_details(id_3_2_12, vec![], &ctx.db)
        .await?;

    assert!(details.is_some());

    let details = details.unwrap();

    log::debug!("{details:#?}");

    let details = service
        .fetch_sbom_details(Id::Uuid(details.summary.head.id), vec![], &ctx.db)
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

    let neither_purl = Purl::from_str(
        "pkg:maven/io.smallrye/smallrye-graphql@0.0.0.redhat-00000?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
    )?;
    let both_purl = Purl::from_str(
        "pkg:maven/io.smallrye/smallrye-graphql@2.2.3.redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
    )?;
    let one_purl = Purl::from_str(
        "pkg:maven/io.quarkus/quarkus-kubernetes-service-binding-deployment@3.2.12.Final-redhat-00001?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
    )?;

    let neither_cpe = Cpe::from_str("cpe:/a:redhat:quarkus:0.0::el8")?;
    let both_cpe = Cpe::from_str("cpe:/a:redhat:quarkus:3.2::el8")?;

    assert_ne!(neither_cpe.uuid(), both_cpe.uuid());

    let counts = service
        .count_related_sboms(
            vec![
                SbomExternalPackageReference::Cpe(&neither_cpe),
                SbomExternalPackageReference::Cpe(&both_cpe),
                SbomExternalPackageReference::Purl(&neither_purl),
                SbomExternalPackageReference::Purl(&both_purl),
                SbomExternalPackageReference::Purl(&one_purl),
            ],
            &ctx.db,
        )
        .await?;

    assert_eq!(counts, vec![0, 2, 0, 2, 1]);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn sbom_set_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
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

    let mut map = HashMap::new();
    map.insert("label_1".to_string(), "First Label".to_string());
    map.insert("label_2".to_string(), "Second Label".to_string());
    let new_labels = Labels(map);
    service
        .set_labels(id_3_2_12.clone(), new_labels, &ctx.db)
        .await?;

    let details = service
        .fetch_sbom_details(id_3_2_12.clone(), vec![], &ctx.db)
        .await?;

    assert!(details.is_some());

    let details = details.unwrap();
    assert_eq!(details.summary.head.labels.len(), 2);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn sbom_update_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
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

    let mut map = HashMap::new();
    map.insert("label_1".to_string(), "First Label".to_string());
    map.insert("label_2".to_string(), "Second Label".to_string());
    let new_labels = Labels(map);
    service
        .set_labels(id_3_2_12.clone(), new_labels, &ctx.db)
        .await?;

    let mut update_map = HashMap::new();
    update_map.insert("label_2".to_string(), "Label no 2".to_string());
    update_map.insert("label_3".to_string(), "Third Label".to_string());
    let update_labels = Labels(update_map);
    let update = trustify_entity::labels::Update::new();
    service
        .update_labels(id_3_2_12.clone(), |_| update.apply_to(update_labels))
        .await?;

    let details = service
        .fetch_sbom_details(id_3_2_12.clone(), vec![], &ctx.db)
        .await?;
    let details = details.unwrap();
    //update only alters values of pre-existing keys - it won't add in an entirely new key/value pair
    assert_eq!(details.summary.head.labels.clone().len(), 2);
    assert_eq!(
        details.summary.head.labels.0.get("label_2"),
        Some("Label no 2".to_string()).as_ref()
    );

    Ok(())
}
