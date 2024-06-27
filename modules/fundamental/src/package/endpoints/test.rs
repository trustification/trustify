use crate::package::endpoints::configure;
use crate::package::model::details::package::PackageDetails;
use crate::package::model::details::package_version::PackageVersionDetails;
use crate::package::model::details::qualified_package::QualifiedPackageDetails;
use crate::package::model::summary::package::{PackageSummary, PaginatedPackageSummary};
use crate::package::model::summary::qualified_package::PaginatedQualifiedPackageSummary;
use crate::package::model::summary::r#type::TypeSummary;
use actix_web::test::TestRequest;
use actix_web::{web, App};
use serde_json::Value;
use std::str::FromStr;
use std::sync::Arc;
use test_context::test_context;
use test_log::test;
use tokio_util::io::ReaderStream;
use trustify_common::db::test::TrustifyContext;
use trustify_common::db::{Database, Transactional};
use trustify_common::model::PaginatedResults;
use trustify_common::purl::Purl;
use trustify_module_ingestor::graph::Graph;
use trustify_module_ingestor::service::{Format, IngestorService};
use trustify_module_storage::service::fs::FileSystemBackend;

async fn setup(db: &Database) -> Result<(), anyhow::Error> {
    let graph = Arc::new(Graph::new(db.clone()));

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

    let sendmail = graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, ())
        .await?;

    let _sendmail_444 = sendmail
        .ingest_package_version(&Purl::from_str("pkg:rpm/sendmail@4.4.4")?, ())
        .await?;

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn types(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    setup(&db).await?;

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl/type";

    let request = TestRequest::get().uri(uri).to_request();

    let response: Vec<TypeSummary> = actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(2, response.len());

    let maven = &response[0];

    assert_eq!(1, maven.counts.base);
    assert_eq!(2, maven.counts.version);
    assert_eq!(3, maven.counts.package);

    let rpm = &response[1];
    assert_eq!(1, rpm.counts.base);
    assert_eq!(1, rpm.counts.version);
    assert_eq!(0, rpm.counts.package);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn r#type(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    setup(&db).await?;

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl/type/maven";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<PackageSummary> =
        actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(1, response.items.len());

    let log4j = &response.items[0];
    assert_eq!("pkg://maven/org.apache/log4j", log4j.head.purl.to_string());

    let uri = "/api/v1/package/by-purl/type/rpm";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<PackageSummary> =
        actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(1, response.items.len());

    let sendmail = &response.items[0];
    assert_eq!("pkg://rpm/sendmail", sendmail.head.purl.to_string());

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn type_package(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    setup(&db).await?;

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl/type/maven/org.apache/log4j";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PackageDetails = actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(
        "pkg://maven/org.apache/log4j",
        response.head.purl.to_string()
    );

    assert_eq!(2, response.versions.len());

    let log4j_123 = response.versions.iter().find(|e| e.head.version == "1.2.3");
    assert!(log4j_123.is_some());

    let log4j_345 = response.versions.iter().find(|e| e.head.version == "3.4.5");
    assert!(log4j_345.is_some());

    let log4j_123 = log4j_123.unwrap();
    let log4j_345 = log4j_345.unwrap();

    assert_eq!(2, log4j_123.packages.len());
    assert_eq!(1, log4j_345.packages.len());

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn type_package_version(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    setup(&db).await?;

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl/type/maven/org.apache/log4j@1.2.3";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PackageVersionDetails =
        actix_web::test::call_and_read_body_json(&app, request).await;
    assert_eq!(2, response.packages.len());
    assert!(response
        .packages
        .iter()
        .any(|e| e.purl.to_string() == "pkg://maven/org.apache/log4j@1.2.3?jdk=11"));
    assert!(response
        .packages
        .iter()
        .any(|e| e.purl.to_string() == "pkg://maven/org.apache/log4j@1.2.3?jdk=17"));

    let uri = "/api/v1/package/by-purl/type/rpm/sendmail@4.4.4";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PackageVersionDetails =
        actix_web::test::call_and_read_body_json(&app, request).await;
    assert_eq!(0, response.packages.len());

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn package(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    setup(&db).await?;

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl/type/maven/org.apache/log4j@1.2.3";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PackageVersionDetails =
        actix_web::test::call_and_read_body_json(&app, request).await;
    assert_eq!(2, response.packages.len());

    let jdk17 = response
        .packages
        .iter()
        .find(|e| e.purl.to_string() == "pkg://maven/org.apache/log4j@1.2.3?jdk=17");

    assert!(jdk17.is_some());
    let jdk17 = jdk17.unwrap();

    let uri = format!("/api/v1/package/by-purl/{}", jdk17.uuid);
    let request = TestRequest::get().uri(&uri).to_request();
    let response: QualifiedPackageDetails =
        actix_web::test::call_and_read_body_json(&app, request).await;

    log::debug!("{:#?}", response);

    assert_eq!(jdk17.uuid, response.head.uuid);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn version(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    setup(&db).await?;

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl/type/maven/org.apache/log4j@1.2.3";
    let request = TestRequest::get().uri(uri).to_request();
    let log4j_123: PackageVersionDetails =
        actix_web::test::call_and_read_body_json(&app, request).await;
    assert_eq!(2, log4j_123.packages.len());

    let uri = format!("/api/v1/package/by-purl/version/{}", log4j_123.head.uuid);
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PackageVersionDetails =
        actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(log4j_123.head.uuid, response.head.uuid);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn base(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    setup(&db).await?;

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl/type/maven/org.apache/log4j";
    let request = TestRequest::get().uri(uri).to_request();
    let log4j: PackageDetails = actix_web::test::call_and_read_body_json(&app, request).await;
    assert_eq!(2, log4j.versions.len());

    let uri = format!("/api/v1/package/by-purl/base/{}", log4j.head.uuid);
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PackageDetails = actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(log4j.head.uuid, response.head.uuid);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn base_packages(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    setup(&db).await?;

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl/base?q=log4j";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedPackageSummary =
        actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(1, response.items.len());

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn qualified_packages(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    setup(&db).await?;

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl?q=log4j";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedQualifiedPackageSummary =
        actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(3, response.items.len());

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn qualified_packages_filtering(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;

    setup(&db).await?;

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl?q=type=maven";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedQualifiedPackageSummary =
        actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(3, response.items.len());

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn package_with_status(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let (storage, _tmp) = FileSystemBackend::for_test().await?;

    let ingestor = IngestorService::new(Graph::new(db.clone()), storage);

    ingestor
        .graph()
        .ingest_qualified_package(
            &Purl::from_str("pkg:cargo/hyper@0.14.1")?,
            Transactional::None,
        )
        .await?;

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

    let app = actix_web::test::init_service(
        App::new().service(web::scope("/api").configure(|config| configure(config, db))),
    )
    .await;

    let uri = "/api/v1/package/by-purl?q=hyper";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedQualifiedPackageSummary =
        actix_web::test::call_and_read_body_json(&app, request).await;

    assert_eq!(1, response.items.len());

    let uuid = response.items[0].head.uuid;

    let uri = format!("/api/v1/package/by-purl/{uuid}");

    let request = TestRequest::get().uri(&uri).to_request();
    let response: Value = actix_web::test::call_and_read_body_json(&app, request).await;

    log::debug!("{}", serde_json::to_string_pretty(&response)?);

    Ok(())
}
