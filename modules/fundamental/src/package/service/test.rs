use crate::package::service::PackageService;
use std::str::FromStr;
use std::sync::Arc;
use test_context::test_context;
use test_log::test;
use tokio_util::io::ReaderStream;
use trustify_common::db::query::{q, Query};
use trustify_common::db::test::TrustifyContext;
use trustify_common::db::Transactional;
use trustify_common::model::Paginated;
use trustify_common::purl::Purl;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::fs::FileSystemBackend;

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn types(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
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

    let types = service.types(()).await?;

    assert_eq!(2, types.len());

    let rpm = types.iter().find(|e| e.head.name == "rpm");
    let maven = types.iter().find(|e| e.head.name == "maven");

    assert!(rpm.is_some());
    assert!(maven.is_some());

    let rpm = rpm.unwrap();
    let maven = maven.unwrap();

    assert_eq!(rpm.counts.base, 1);
    assert_eq!(rpm.counts.version, 0);
    assert_eq!(rpm.counts.package, 0);

    assert_eq!(maven.counts.base, 2);
    assert_eq!(maven.counts.version, 1);
    assert_eq!(maven.counts.package, 2);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn packages_for_type(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
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
        .packages_for_type("maven", Query::default(), Paginated::default(), ())
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
async fn packages_for_type_with_filtering(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
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
        .packages_for_type("maven", q("myspace"), Paginated::default(), ())
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

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn packages(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
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

    let quarkus = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.jboss/quarkus")?, ())
        .await?;

    let quarkus_123 = quarkus
        .ingest_package_version(&Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3")?, ())
        .await?;

    quarkus_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3?repository_url=http://jboss.org/")?,
            (),
        )
        .await?;

    let results = service
        .packages(q("log4j"), Paginated::default(), ())
        .await?;

    assert_eq!(1, results.items.len());

    let results = service
        .packages(q("quarkus"), Paginated::default(), ())
        .await?;

    assert_eq!(1, results.items.len());

    let results = service
        .packages(q("jboss"), Paginated::default(), ())
        .await?;

    assert_eq!(1, results.items.len());

    let results = service
        .packages(q("maven"), Paginated::default(), ())
        .await?;

    assert_eq!(2, results.items.len());

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn qualified_packages(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
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

    let quarkus = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.jboss/quarkus")?, ())
        .await?;

    let quarkus_123 = quarkus
        .ingest_package_version(&Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3")?, ())
        .await?;

    quarkus_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.jboss/quarkus@1.2.3?repository_url=http://jboss.org/")?,
            (),
        )
        .await?;

    let results = service
        .qualified_packages(q("log4j"), Paginated::default(), ())
        .await?;

    log::debug!("{:#?}", results);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn statuses(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let service = PackageService::new(db.clone());
    let (storage, _tmp) = FileSystemBackend::for_test().await?;

    let ingestor = IngestorService::new(Graph::new(db.clone()), storage);

    // ingest an advisory
    let data = include_bytes!("../../../../../etc/test-data/osv/RUSTSEC-2021-0079.json");
    let data = ReaderStream::new(&data[..]);

    ingestor
        .ingest(
            ("source", "test"),
            Some("RUSTSEC".to_string()),
            Format::OSV,
            data,
        )
        .await?;

    // backfill ingest the CVE record
    let data = include_bytes!("../../../../../etc/test-data/cve/CVE-2021-32714.json");
    let data = ReaderStream::new(&data[..]);

    ingestor
        .ingest(("source", "test"), None, Format::CVE, data)
        .await?;

    // finally ingest a specific known-affected version.

    ingestor
        .graph()
        .ingest_qualified_package(
            &Purl::from_str("pkg:cargo/hyper@0.14.1")?,
            Transactional::None,
        )
        .await?;

    let results = service
        .qualified_packages(Query::default(), Paginated::default(), Transactional::None)
        .await?;

    assert_eq!(1, results.items.len());

    let uuid = results.items[0].head.uuid;

    let _results = service
        .qualified_package_by_uuid(&uuid, Transactional::None)
        .await?;

    //println!("{:#?}", _results);

    Ok(())
}
