use crate::purl::model::details::purl::{PurlDetails, PurlsResponse};
use crate::purl::model::details::versioned_purl::VersionedPurlDetails;
use crate::purl::model::details::{base_purl::BasePurlDetails, purl::PurlsRequest};
use crate::purl::model::summary::base_purl::BasePurlSummary;
use crate::purl::model::summary::purl::PurlSummary;
use crate::purl::model::summary::r#type::TypeSummary;
use crate::test::caller;
use actix_web::test::TestRequest;
use serde_json::Value;
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::db::Database;
use trustify_common::model::PaginatedResults;
use trustify_common::purl::Purl;
use trustify_module_ingestor::graph::Graph;
use trustify_test_context::{TrustifyContext, call::CallService};
use urlencoding::encode;
use uuid::Uuid;

async fn setup(db: &Database, graph: &Graph) -> Result<(), anyhow::Error> {
    let log4j = graph
        .ingest_package(&Purl::from_str("pkg:maven/org.apache/log4j")?, db)
        .await?;

    let log4j_123 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@1.2.3")?, db)
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=11")?,
            db,
        )
        .await?;

    log4j_123
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@1.2.3?jdk=17")?,
            db,
        )
        .await?;

    let log4j_345 = log4j
        .ingest_package_version(&Purl::from_str("pkg:maven/org.apache/log4j@3.4.5")?, db)
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            db,
        )
        .await?;

    log4j_345
        .ingest_qualified_package(
            &Purl::from_str("pkg:maven/org.apache/log4j@3.4.5?repository_url=http://jboss.org/")?,
            db,
        )
        .await?;

    let sendmail = graph
        .ingest_package(&Purl::from_str("pkg:rpm/sendmail")?, db)
        .await?;

    let _sendmail_444 = sendmail
        .ingest_package_version(&Purl::from_str("pkg:rpm/sendmail@4.4.4")?, db)
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn types(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl/type";

    let request = TestRequest::get().uri(uri).to_request();

    let response: Vec<TypeSummary> = app.call_and_read_body_json(request).await;

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

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn r#type(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl/type/maven";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<BasePurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(1, response.items.len());

    let log4j = &response.items[0];
    assert_eq!("pkg:maven/org.apache/log4j", log4j.head.purl.to_string());

    let uri = "/api/v2/purl/type/rpm";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<BasePurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(1, response.items.len());

    let sendmail = &response.items[0];
    assert_eq!("pkg:rpm/sendmail", sendmail.head.purl.to_string());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn type_package(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl/type/maven/org.apache/log4j";

    let request = TestRequest::get().uri(uri).to_request();

    let response: BasePurlDetails = app.call_and_read_body_json(request).await;

    assert_eq!("pkg:maven/org.apache/log4j", response.head.purl.to_string());

    assert_eq!(2, response.versions.len());

    let log4j_123 = response.versions.iter().find(|e| e.head.version == "1.2.3");
    assert!(log4j_123.is_some());

    let log4j_345 = response.versions.iter().find(|e| e.head.version == "3.4.5");
    assert!(log4j_345.is_some());

    let log4j_123 = log4j_123.unwrap();
    let log4j_345 = log4j_345.unwrap();

    assert_eq!(2, log4j_123.purls.len());
    assert_eq!(1, log4j_345.purls.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn type_package_version(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl/type/maven/org.apache/log4j@1.2.3";
    let request = TestRequest::get().uri(uri).to_request();
    let response: VersionedPurlDetails = app.call_and_read_body_json(request).await;
    assert_eq!(2, response.purls.len());
    assert!(
        response
            .purls
            .iter()
            .any(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=11")
    );
    assert!(
        response
            .purls
            .iter()
            .any(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=17")
    );

    let uri = "/api/v2/purl/type/rpm/sendmail@4.4.4";
    let request = TestRequest::get().uri(uri).to_request();
    let response: VersionedPurlDetails = app.call_and_read_body_json(request).await;
    assert_eq!(0, response.purls.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl/type/maven/org.apache/log4j@1.2.3";
    let request = TestRequest::get().uri(uri).to_request();
    let response: VersionedPurlDetails = app.call_and_read_body_json(request).await;
    assert_eq!(2, response.purls.len());

    let jdk17 = response
        .purls
        .iter()
        .find(|e| e.purl.to_string() == "pkg:maven/org.apache/log4j@1.2.3?jdk=17");

    assert!(jdk17.is_some());
    let jdk17 = jdk17.unwrap();

    let uri = format!("/api/v2/purl/{}", jdk17.uuid);
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PurlDetails = app.call_and_read_body_json(request).await;

    log::debug!("{:#?}", response);

    assert_eq!(jdk17.uuid, response.head.uuid);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn version(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl/type/maven/org.apache/log4j@1.2.3";
    let request = TestRequest::get().uri(uri).to_request();
    let log4j_123: VersionedPurlDetails = app.call_and_read_body_json(request).await;
    assert_eq!(2, log4j_123.purls.len());

    let uri = format!("/api/v2/purl/version/{}", log4j_123.head.uuid);
    let request = TestRequest::get().uri(&uri).to_request();
    let response: VersionedPurlDetails = app.call_and_read_body_json(request).await;

    assert_eq!(log4j_123.head.uuid, response.head.uuid);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn base(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl/type/maven/org.apache/log4j";
    let request = TestRequest::get().uri(uri).to_request();
    let log4j: BasePurlDetails = app.call_and_read_body_json(request).await;
    assert_eq!(2, log4j.versions.len());

    let uri = format!("/api/v2/purl/base/{}", log4j.head.uuid);
    let request = TestRequest::get().uri(&uri).to_request();
    let response: BasePurlDetails = app.call_and_read_body_json(request).await;
    assert_eq!(log4j.head.uuid, response.head.uuid);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn base_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl/base?q=log4j";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<BasePurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(1, response.items.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn qualified_packages(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = "/api/v2/purl?q=log4j";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(3, response.items.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn qualified_packages_filtering(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    setup(&ctx.db, &ctx.graph).await?;
    let app = caller(ctx).await?;

    let uri = format!("/api/v2/purl?q={}", encode("type=maven"));
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;
    assert_eq!(3, response.items.len());

    ctx.ingestor
        .graph()
        .ingest_qualified_package(
            &Purl::from_str("pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386")?,
            &ctx.db,
        )
        .await?;
    let uri = format!("/api/v2/purl?q={}", encode("type=rpm&arch=i386"));
    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;
    assert_eq!(1, response.items.len());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package_with_status(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingestor
        .graph()
        .ingest_qualified_package(&Purl::from_str("pkg:cargo/hyper@0.14.1")?, &ctx.db)
        .await?;

    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json", "cve/CVE-2021-32714.json"])
        .await?;

    let app = caller(ctx).await?;

    let uri = "/api/v2/purl?q=hyper";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(1, response.items.len());

    let uuid = response.items[0].head.uuid;

    let uri = format!("/api/v2/purl/{uuid}");

    let request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    tracing::debug!(test = "", "{response:#?}");

    assert_eq!(uuid, Uuid::parse_str(response["uuid"].as_str().unwrap())?);
    assert_eq!(
        "critical",
        response["advisories"][0]["status"][0]["average_severity"]
    );
    assert_eq!(
        "CVE-2021-32714",
        response["advisories"][0]["status"][0]["vulnerability"]["identifier"]
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn multiple_purls(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingestor
        .graph()
        .ingest_qualified_package(&Purl::from_str("pkg:cargo/hyper@0.14.1")?, &ctx.db)
        .await?;

    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json", "cve/CVE-2021-32714.json"])
        .await?;

    let app = caller(ctx).await?;
    let uri = "/api/v2/purl/type/cargo/hyper@0.14.1";
    let request = TestRequest::get().uri(uri).to_request();
    let hyper_0_14_1: VersionedPurlDetails = app.call_and_read_body_json(request).await;

    let purls = vec![
        hyper_0_14_1.head.uuid.to_string(),
        hyper_0_14_1.head.purl.to_string(),
        String::from("pkg:maven/org.example/notfound@1.2.3?jdk=11"),
    ];

    let uri = "/api/v2/purl";
    let request_body = PurlsRequest {
        items: purls.clone(),
    };
    let request = TestRequest::post()
        .set_json(request_body)
        .uri(uri)
        .to_request();
    let response: PurlsResponse = app.call_and_read_body_json(request).await;

    assert_eq!(2, response.len());
    assert!(response.get(purls[0].as_str()).is_some());
    assert!(response.get(purls[1].as_str()).is_some());
    assert!(response.get(purls[2].as_str()).is_none());

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn purl_queries(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let purl = Purl::from_str("pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25")?;
    let uuid = ctx
        .ingestor
        .graph()
        .ingest_qualified_package(&purl, &ctx.db)
        .await?
        .qualified_package
        .id;
    let query = async |query| {
        let app = caller(ctx).await.unwrap();
        let uri = format!("/api/v2/purl?q={}", urlencoding::encode(query));
        let request = TestRequest::get().uri(&uri).to_request();
        let response: PaginatedResults<PurlSummary> = app.call_and_read_body_json(request).await;
        tracing::debug!(test = "", "{response:#?}");
        assert_eq!(1, response.items.len(), "'q={query}'");
        assert_eq!(uuid, response.items[0].head.uuid, "'q={query}'");
        assert_eq!(purl, response.items[0].head.purl, "'q={query}'");
    };

    for each in [
        r"purl=pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386\&distro=fedora-25",
        "type=rpm",
        "curl",
        "fedora",
        "purl~pkg:rpm",
        "purl~pkg:rpm/fedora",
        "purl~/curl@",
        "purl~fedora/curl",
        "purl~@7.50.3-1.fc25?",
        "purl>=pkg:rpm/fedora/curl@7.49",
        "purl<=pkg:rpm/fedora/curl@7.51",
        "purl>pkg:rpm/fedora/curl@6",
        "purl<pkg:rpm/fedora/curl@8",
        "purl~pkg:rpm/fedora/curl@7.50.3-1.fc25&arch=i386&distro=fedora-25",
        "purl~curl@7.50.3-1.fc25&arch=i386",
        "purl~curl@7.50.3-1&distro=fedora-25",
        "distro~fedora",
        "arch=i386&curl",
    ] {
        query(each).await;
    }

    Ok(())
}
