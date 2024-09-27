use crate::advisory::service::AdvisoryService;
use crate::ai::model::ChatState;
use crate::ai::service::tools::{AdvisoryInfo, CVEInfo, PackageInfo, ProductInfo};
use crate::ai::service::AiService;
use crate::product::service::ProductService;
use crate::purl::service::PurlService;
use crate::vulnerability::service::VulnerabilityService;
use langchain_rust::tools::Tool;
use serde_json::Value;
use std::error::Error;
use test_context::test_context;
use test_log::test;
use trustify_common::db::Transactional;
use trustify_common::hashing::Digests;
use trustify_module_ingestor::graph::product::ProductInformation;
use trustify_test_context::TrustifyContext;

pub async fn ingest_fixtures(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = ctx
        .graph
        .ingest_sbom(
            ("source", "http://redhat.com/test.json"),
            &Digests::digest("RHSA-1"),
            "a",
            (),
            Transactional::None,
        )
        .await?;

    let pr = ctx
        .graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
            },
            (),
        )
        .await?;

    pr.ingest_product_version("37.17.9".to_string(), Some(sbom.sbom.sbom_id), ())
        .await?;

    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json", "cve/CVE-2021-32714.json"])
        .await?;

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn completions(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = AiService::new(ctx.db.clone());
    if !service.enabled() {
        return Ok(()); // skip test
    }

    ingest_fixtures(ctx).await?;

    let mut req = ChatState::new();
    req.add_human_message("What is the latest version of Trusted Profile Analyzer?".into());

    let result = service.completions(&req, ()).await?;

    log::info!("result: {:?}", result);
    assert!(result.messages.last().unwrap().content.contains("37.17.9"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn cve_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_fixtures(ctx).await?;
    let tool = CVEInfo(VulnerabilityService::new(ctx.db.clone()));
    let result = cleanup_tool_result(tool.run(Value::String("CVE-2021-32714".to_string())).await);
    assert!(result.contains(r#"
Identifier: CVE-2021-32714
Title: Integer Overflow in Chunked Transfer-Encoding
Description: hyper is an HTTP library for Rust. In versions prior to 0.14.10, hyper's HTTP server and client code had a flaw that could trigger an integer overflow when decoding chunk sizes that are too big. This allows possible data loss, or if combined with an upstream HTTP proxy that allows chunk sizes larger than hyper does, can result in "request smuggling" or "desync attacks." The vulnerability is patched in version 0.14.10. Two possible workarounds exist. One may reject requests manually that contain a `Transfer-Encoding` header or ensure any upstream proxy rejects `Transfer-Encoding` chunk sizes greater than what fits in 64-bit unsigned integers.
Severity: 9.1
Score: 9.1
Affected Packages:
  * Name: pkg://cargo/hyper
    Version: [0.0.0-0,0.14.10)
"#.trim()));

    Ok(())
}

fn cleanup_tool_result(s: Result<String, Box<dyn Error>>) -> String {
    let re = regex::Regex::new(r"UUID: \b[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}\b").unwrap();
    let s = s.unwrap().trim().to_string();
    re.replace_all(&s, "UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
        .to_string()
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn product_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_fixtures(ctx).await?;
    let tool = ProductInfo(ProductService::new(ctx.db.clone()));
    let result = cleanup_tool_result(
        tool.run(Value::String("Trusted Profile Analyzer".to_string()))
            .await,
    );
    assert!(
        result.contains(
            r#"
Found one matching product:
  * Name: Trusted Profile Analyzer
    UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    Vendor: Red Hat
    Versions:
      * 37.17.9
"#
            .trim()
        ),
        "expecting:\n{}",
        result
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn advisory_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    crate::advisory::service::test::ingest_and_link_advisory(ctx).await?;
    crate::advisory::service::test::ingest_sample_advisory(ctx, "RHSA-2").await?;

    let tool = AdvisoryInfo(AdvisoryService::new(ctx.db.clone()));
    let result = cleanup_tool_result(tool.run(Value::String("RHSA-1".to_string())).await);
    assert!(
        result.contains(
            r#"
Identifier: RHSA-1
Title: RHSA-1
Score: 9.1
Severity: critical
Vulnerabilities:
 * Identifier: CVE-123
"#
            .trim()
        ),
        "expecting:\n{}",
        result
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;
    ctx.ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    let tool = PackageInfo(PurlService::new(ctx.db.clone()));
    let result = cleanup_tool_result(
        tool.run(Value::String(
            "pkg:rpm/redhat/libsepol@3.5-1.el9?arch=s390x".to_string(),
        ))
        .await,
    );
    assert!(
        result.contains(
            r#"
There is one package that matches:
Identifier: pkg://rpm/redhat/libsepol@3.5-1.el9?arch=ppc64le
UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Name: libsepol
Version: 3.5-1.el9
Licenses:
 * Name: LGPLV2+
"#
            .trim()
        ),
        "expecting:\n{}",
        result
    );

    let result = cleanup_tool_result(
        tool.run(Value::String(
            "1ca731c3-9596-534c-98eb-8dcc6ff7fef9".to_string(),
        ))
        .await,
    );
    assert!(
        result.contains(
            r#"
There is one package that matches:
Identifier: pkg://rpm/redhat/libsepol@3.5-1.el9?arch=ppc64le
UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Name: libsepol
Version: 3.5-1.el9
Licenses:
 * Name: LGPLV2+
"#
            .trim()
        ),
        "expecting:\n{}",
        result
    );

    let result = cleanup_tool_result(
        tool.run(Value::String(
            "pkg:maven/org.jboss.logging/commons-logging-jboss-logging@1.0.0.Final-redhat-1?repository_url=https://maven.repository.redhat.com/ga/&type=jar".to_string(),
        ))
            .await,
    );
    assert!(
        result.contains(
            r#"
There is one package that matches:
Identifier: pkg://maven/org.jboss.logging/commons-logging-jboss-logging@1.0.0.Final-redhat-1?repository_url=https://maven.repository.redhat.com/ga/&type=jar
UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Name: commons-logging-jboss-logging
Version: 1.0.0.Final-redhat-1
Licenses:
 * Name: APACHE-2.0
"#
                .trim()
        ),
        "expecting:\n{}",
        result
    );

    let result = cleanup_tool_result(
        tool.run(Value::String("commons-logging-jboss-logging".to_string()))
            .await,
    );
    assert!(
        result.contains(
            r#"
There is one package that matches:
Identifier: pkg://maven/org.jboss.logging/commons-logging-jboss-logging@1.0.0.Final-redhat-1?repository_url=https://maven.repository.redhat.com/ga/&type=jar
UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Name: commons-logging-jboss-logging
Version: 1.0.0.Final-redhat-1
Licenses:
 * Name: APACHE-2.0
"#
                .trim()
        ),
        "expecting:\n{}",
        result
    );

    let result = cleanup_tool_result(
        tool.run(Value::String("quarkus-resteasy-reactive-json".to_string()))
            .await,
    );
    assert!(
        result.contains(
            r#"
There are multiple packages that match:
 * Identifier: pkg://maven/io.quarkus/quarkus-resteasy-reactive-jsonb-common@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar
   UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   Name: quarkus-resteasy-reactive-jsonb-common
   Version: 2.13.8.Final-redhat-00004
 * Identifier: pkg://maven/io.quarkus/quarkus-resteasy-reactive-jsonb@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar
   UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   Name: quarkus-resteasy-reactive-jsonb
   Version: 2.13.8.Final-redhat-00004
 * Identifier: pkg://maven/io.quarkus/quarkus-resteasy-reactive-jsonb-common-deployment@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar
   UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   Name: quarkus-resteasy-reactive-jsonb-common-deployment
   Version: 2.13.8.Final-redhat-00004
 * Identifier: pkg://maven/io.quarkus/quarkus-resteasy-reactive-jsonb-deployment@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar
   UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   Name: quarkus-resteasy-reactive-jsonb-deployment
   Version: 2.13.8.Final-redhat-00004
"#
                .trim()
        ),
        "expecting:\n{}",
        result
    );

    Ok(())
}
