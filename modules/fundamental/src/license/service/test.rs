use crate::license::service::LicenseService;
use test_context::test_context;
use test_log::test;
use trustify_common::db::query::{q, Query};
use trustify_common::model::Paginated;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new(ctx.db.clone());

    let results = service
        .list_licenses(q("apache"), Paginated::default())
        .await?;

    assert_eq!(3, results.total);
    assert_eq!(3, results.items.len());

    assert!(results.items.iter().any(|e| {
        e.license == "Apache License 1.0" && e.spdx_licenses.contains(&"Apache-1.0".to_string())
    }));
    assert!(results.items.iter().any(|e| {
        e.license == "Apache License 1.1" && e.spdx_licenses.contains(&"Apache-1.1".to_string())
    }));
    assert!(results.items.iter().any(|e| {
        e.license == "Apache License 2.0" && e.spdx_licenses.contains(&"Apache-2.0".to_string())
    }));

    let results = service
        .list_licenses(
            q("apache"),
            Paginated {
                offset: 0,
                limit: 1,
            },
        )
        .await?;

    assert_eq!(3, results.total);
    assert_eq!(1, results.items.len());

    assert!(results
        .items
        .iter()
        .any(|e| e.license == "Apache License 1.0"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_license_purls(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;

    let service = LicenseService::new(ctx.db.clone());

    let lgplv2_ish = service
        .list_licenses(q("LGPLV2+"), Paginated::default())
        .await?;

    let lgpl = lgplv2_ish.items.iter().find(|e| e.license == "LGPLV2+");

    assert!(lgpl.is_some());

    let lgpl = lgpl.unwrap();

    let uuid = lgpl.id;

    let _licensed_purls = service
        .get_license_purls(uuid, Query::default(), Paginated::default())
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_spdx_licenses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new(ctx.db.clone());

    let results = service
        .list_spdx_licenses(q("apache"), Paginated::default())
        .await?;

    assert_eq!(3, results.total);
    assert_eq!(3, results.items.len());

    assert!(results.items.iter().any(|e| e.id == "Apache-1.0"));
    assert!(results.items.iter().any(|e| e.id == "Apache-1.1"));
    assert!(results.items.iter().any(|e| e.id == "Apache-2.0"));

    let results = service
        .list_spdx_licenses(
            q("apache"),
            Paginated {
                offset: 0,
                limit: 1,
            },
        )
        .await?;

    assert_eq!(3, results.total);
    assert_eq!(1, results.items.len());

    assert!(results.items.iter().any(|e| e.id == "Apache-1.0"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_spdx_license(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new(ctx.db.clone());

    let results = service.get_spdx_license("apache-2.0").await?;

    assert!(results.is_some());

    let details = results.unwrap();

    assert_eq!("Apache-2.0", details.summary.id);
    assert_eq!("Apache License 2.0", details.summary.name);
    assert!(!details.text.is_empty());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn verify_clearly_defined(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = LicenseService::new(ctx.db.clone());

    ctx.ingest_document("clearly-defined/chrono.yaml").await?;

    let sought_license = service
        .list_licenses(q("Apache-2.0 OR MIT"), Paginated::default())
        .await?;

    assert_eq!(1, sought_license.items.len());

    let sought_license = &sought_license.items[0];

    let license_details = service
        .get_license_purls(sought_license.id, Query::default(), Paginated::default())
        .await?;

    assert_eq!(7, license_details.items.len());

    let mut seen_versions = Vec::new();

    for each in license_details.items {
        assert!(each
            .sbom
            .authors
            .contains(&"ClearlyDefined: Community-Curated".to_string()));
        assert!(each.purl.purl.to_string().starts_with("pkg:crate/chrono@"));
        seen_versions.push(each.purl.version);
    }

    assert!(seen_versions.contains(&"0.4.10".to_string()));
    assert!(seen_versions.contains(&"0.4.11".to_string()));
    assert!(seen_versions.contains(&"0.4.12".to_string()));
    assert!(seen_versions.contains(&"0.4.13".to_string()));
    assert!(seen_versions.contains(&"0.4.19".to_string()));
    assert!(seen_versions.contains(&"0.4.7".to_string()));
    assert!(seen_versions.contains(&"0.4.9".to_string()));

    Ok(())
}
