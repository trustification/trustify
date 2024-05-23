use crate::package::service::PackageService;
use std::str::FromStr;
use std::sync::Arc;
use test_context::test_context;
use test_log::test;
use trustify_common::db::query::{q, Query};
use trustify_common::db::test::TrustifyContext;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use trustify_module_ingestor::graph::Graph;

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn ecosystems(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));
    let service = PackageService::new(db);

    let log4j = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, ())
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?, ())
        .await?;

    log4j_123
        .ingest_qualified_package(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?, ())
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?repository_url=http://jboss.org")?,
            (),
        )
        .await?;

    graph
        .ingest_package(&Purl::from_str("pkg:maven/org.myspace/tom")?, ())
        .await?;
    graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, ())
        .await?;

    let ecosystems = service.ecosystems(()).await?;

    assert_eq!(2, ecosystems.len());

    let rpm = ecosystems.iter().find(|e| e.head.name == "rpm");
    let maven = ecosystems.iter().find(|e| e.head.name == "maven");

    assert!(rpm.is_some());
    assert!(maven.is_some());

    let rpm = rpm.unwrap();
    let maven = maven.unwrap();

    assert_eq!(rpm.base, 1);
    assert_eq!(rpm.version, 0);
    assert_eq!(rpm.package, 0);

    assert_eq!(maven.base, 2);
    assert_eq!(maven.version, 1);
    assert_eq!(maven.package, 2);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn packages_for_ecosystems(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));
    let service = PackageService::new(db);

    let log4j = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, ())
        .await?;

    log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?, ())
        .await?;

    log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.4")?, ())
        .await?;

    log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.5")?, ())
        .await?;

    graph
        .ingest_package(&Purl::from_str("pkg:maven/org.myspace/tom")?, ())
        .await?;
    graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, ())
        .await?;

    let packages = service
        .packages_for_ecosystem("maven", Query::default(), Paginated::default(), ())
        .await?;

    assert_eq!(packages.total, 2);

    assert!(packages
        .items
        .iter()
        .any(|e| e.head.purl.to_string() == "pkg://maven/org.apache/log4j"));

    assert!(packages
        .items
        .iter()
        .any(|e| e.head.purl.to_string() == "pkg://maven/org.myspace/tom"));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn packages_for_ecosystems_with_filtering(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));
    let service = PackageService::new(db);

    let log4j = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, ())
        .await?;

    log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?, ())
        .await?;

    log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.4")?, ())
        .await?;

    log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.5")?, ())
        .await?;

    graph
        .ingest_package(&Purl::from_str("pkg:maven/org.myspace/tom")?, ())
        .await?;
    graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, ())
        .await?;

    let packages = service
        .packages_for_ecosystem("maven", q("myspace"), Paginated::default(), ())
        .await?;

    assert_eq!(packages.total, 1);

    assert!(packages
        .items
        .iter()
        .any(|e| e.head.purl.to_string() == "pkg://maven/org.myspace/tom"));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn package(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));
    let service = PackageService::new(db);

    let log4j = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, ())
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?, ())
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?repository_url=http://maven.org")?,
            (),
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?repository_url=http://jboss.org")?,
            (),
        )
        .await?;

    let _log4j_124 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.4")?, ())
        .await?;

    log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.5")?, ())
        .await?;

    let tom = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.myspace/tom")?, ())
        .await?;

    tom.ingest_package_version(&Purl::from_str("pkg:maven/org.myspace/tom@1.1.1")?, ())
        .await?;

    tom.ingest_package_version(&Purl::from_str("pkg:maven/org.myspace/tom@9.9.9")?, ())
        .await?;

    graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, ())
        .await?;

    let bind = graph
        .ingest_package(&Purl::from_str("pkg:rpm/bind")?, ())
        .await?;

    bind.ingest_package_version(&Purl::from_str("pkg:rpm/bind@4.4.4")?, ())
        .await?;

    let results = service
        .package("maven", Some("org.apache".to_string()), "log4j", ())
        .await?;

    assert!(results.is_some());

    let log4j = results.unwrap();

    assert_eq!("pkg://maven/org.apache/log4j", log4j.head.purl.to_string());

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn package_version(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));
    let service = PackageService::new(db);

    let log4j = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, ())
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?, ())
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            (),
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            (),
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?, ())
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            (),
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            (),
        )
        .await?;

    let results = service
        .package_version(
            "maven",
            Some("org.apache".to_string()),
            "log4j",
            "1.2.3",
            (),
        )
        .await?;

    assert!(results.is_some());

    let log4j_123 = results.unwrap();

    assert_eq!(
        "pkg://maven/org.apache/log4j@1.2.3",
        log4j_123.head.purl.to_string()
    );

    assert_eq!(2, log4j_123.packages.len());

    assert!(log4j_123
        .packages
        .iter()
        .any(|e| e.purl.to_string() == "pkg://maven/org.apache/log4j@1.2.3?jdk=11"));

    assert!(log4j_123
        .packages
        .iter()
        .any(|e| e.purl.to_string() == "pkg://maven/org.apache/log4j@1.2.3?jdk=17"));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn package_version_by_uuid(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));
    let service = PackageService::new(db);

    let log4j = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, ())
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?, ())
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            (),
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            (),
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?, ())
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            (),
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            (),
        )
        .await?;

    let result = service
        .package_version_by_uuid(&log4j_123.package_version.id, ())
        .await?;

    assert!(result.is_some());

    let log4j_123 = result.unwrap();

    assert_eq!(
        "pkg://maven/org.apache/log4j@1.2.3",
        log4j_123.head.purl.to_string()
    );

    assert_eq!(2, log4j_123.packages.len());

    assert!(log4j_123
        .packages
        .iter()
        .any(|e| e.purl.to_string() == "pkg://maven/org.apache/log4j@1.2.3?jdk=11"));

    assert!(log4j_123
        .packages
        .iter()
        .any(|e| e.purl.to_string() == "pkg://maven/org.apache/log4j@1.2.3?jdk=17"));

    Ok(())
}
