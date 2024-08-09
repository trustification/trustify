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

    let licensed_purls = service
        .get_license_purls(uuid, Query::default(), Paginated::default())
        .await?;

    println!("{:#?}", licensed_purls);

    println!("{:#?}", lgpl);

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
