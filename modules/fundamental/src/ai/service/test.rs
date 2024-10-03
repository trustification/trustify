use crate::advisory::service::AdvisoryService;
use crate::ai::model::ChatState;
use crate::ai::service::tools::{AdvisoryInfo, CVEInfo, PackageInfo, ProductInfo, SbomInfo};
use crate::ai::service::AiService;
use crate::product::service::ProductService;
use crate::purl::service::PurlService;
use crate::sbom::service::SbomService;
use crate::vulnerability::service::VulnerabilityService;
use langchain_rust::tools::Tool;
use serde_json::Value;
use std::error::Error;
use std::rc::Rc;
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

fn cleanup_tool_result(s: Result<String, Box<dyn Error>>) -> String {
    sanitize_uuid(s.unwrap().trim().to_string())
}

pub fn sanitize_uuid(value: String) -> String {
    let re = regex::Regex::new(r#""uuid": "\b[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}\b""#).unwrap();
    re.replace_all(
        value.as_str(),
        r#""uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx""#,
    )
    .to_string()
}

async fn assert_tool_contains(
    tool: Rc<dyn Tool>,
    input: &str,
    expected: &str,
) -> Result<(), anyhow::Error> {
    let actual = cleanup_tool_result(tool.run(Value::String(input.to_string())).await);
    assert!(
        actual.contains(expected.trim()),
        "actual:\n{}\nexpected:\n{}\n",
        actual,
        expected
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn completions(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = AiService::new(ctx.db.clone());
    if !service.completions_enabled() {
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
    let tool = Rc::new(CVEInfo(VulnerabilityService::new(ctx.db.clone())));
    assert_tool_contains(
        tool.clone(),
        "CVE-2021-32714",
        r#"
{
  "title": "Integer Overflow in Chunked Transfer-Encoding",
  "description": "hyper is an HTTP library for Rust. In versions prior to 0.14.10, hyper's HTTP server and client code had a flaw that could trigger an integer overflow when decoding chunk sizes that are too big. This allows possible data loss, or if combined with an upstream HTTP proxy that allows chunk sizes larger than hyper does, can result in \"request smuggling\" or \"desync attacks.\" The vulnerability is patched in version 0.14.10. Two possible workarounds exist. One may reject requests manually that contain a `Transfer-Encoding` header or ensure any upstream proxy rejects `Transfer-Encoding` chunk sizes greater than what fits in 64-bit unsigned integers.",
  "severity": 9.1,
  "score": 9.1,
  "released": null,
  "affected_packages": [
    {
      "name": "pkg://cargo/hyper",
      "version": "[0.0.0-0,0.14.10)"
    }
  ]
}
"#).await
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn product_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_fixtures(ctx).await?;
    let tool = Rc::new(ProductInfo(ProductService::new(ctx.db.clone())));
    assert_tool_contains(
        tool.clone(),
        "Trusted Profile Analyzer",
        r#"
{
  "items": [
    {
      "name": "Trusted Profile Analyzer",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "vendor": "Red Hat",
      "versions": [
        "37.17.9"
      ]
    }
  ],
  "total": 1
}
"#,
    )
    .await
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn advisory_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    crate::advisory::service::test::ingest_and_link_advisory(ctx).await?;
    crate::advisory::service::test::ingest_sample_advisory(ctx, "RHSA-2").await?;

    let tool = Rc::new(AdvisoryInfo(AdvisoryService::new(ctx.db.clone())));

    assert_tool_contains(
        tool.clone(),
        "RHSA-1",
        r#"
{
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "identifier": "RHSA-1",
  "issuer": null,
  "title": "RHSA-1",
  "score": 9.1,
  "severity": "critical",
  "vulnerabilities": [
    {
      "identifier": "CVE-123",
      "title": null,
      "description": null,
      "released": null
    }
  ]
}
"#,
    )
    .await
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn package_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;
    ctx.ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    let tool = Rc::new(PackageInfo(PurlService::new(ctx.db.clone())));

    assert_tool_contains(
        tool.clone(),
        "pkg:rpm/redhat/libsepol@3.5-1.el9?arch=s390x",
        r#"
{
  "identifier": "pkg://rpm/redhat/libsepol@3.5-1.el9?arch=ppc64le",
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "name": "libsepol",
  "version": "3.5-1.el9",
  "advisories": [],
  "licenses": [
    "LGPLV2+"
  ]
}
"#,
    )
    .await?;

    assert_tool_contains(
        tool.clone(),
        "1ca731c3-9596-534c-98eb-8dcc6ff7fef9",
        r#"
{
  "identifier": "pkg://rpm/redhat/libsepol@3.5-1.el9?arch=ppc64le",
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "name": "libsepol",
  "version": "3.5-1.el9",
  "advisories": [],
  "licenses": [
    "LGPLV2+"
  ]
}
"#,
    )
    .await?;

    assert_tool_contains(
        tool.clone(),
        "pkg:maven/org.jboss.logging/commons-logging-jboss-logging@1.0.0.Final-redhat-1?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
        r#"
{
  "identifier": "pkg://maven/org.jboss.logging/commons-logging-jboss-logging@1.0.0.Final-redhat-1?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "name": "commons-logging-jboss-logging",
  "version": "1.0.0.Final-redhat-1",
  "advisories": [],
  "licenses": [
    "APACHE-2.0"
  ]
}
"#).await?;

    assert_tool_contains(
        tool.clone(),
        "commons-logging-jboss-logging",
        r#"
{
  "identifier": "pkg://maven/org.jboss.logging/commons-logging-jboss-logging@1.0.0.Final-redhat-1?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "name": "commons-logging-jboss-logging",
  "version": "1.0.0.Final-redhat-1",
  "advisories": [],
  "licenses": [
    "APACHE-2.0"
  ]
}
"#).await?;

    assert_tool_contains(
        tool.clone(),
        "quarkus-resteasy-reactive-json",
        r#"
There are multiple that match:

{
  "items": [
    {
      "identifier": "pkg://maven/io.quarkus/quarkus-resteasy-reactive-jsonb-common@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "quarkus-resteasy-reactive-jsonb-common",
      "version": "2.13.8.Final-redhat-00004"
    },
    {
      "identifier": "pkg://maven/io.quarkus/quarkus-resteasy-reactive-jsonb@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "quarkus-resteasy-reactive-jsonb",
      "version": "2.13.8.Final-redhat-00004"
    },
    {
      "identifier": "pkg://maven/io.quarkus/quarkus-resteasy-reactive-jsonb-common-deployment@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "quarkus-resteasy-reactive-jsonb-common-deployment",
      "version": "2.13.8.Final-redhat-00004"
    },
    {
      "identifier": "pkg://maven/io.quarkus/quarkus-resteasy-reactive-jsonb-deployment@2.13.8.Final-redhat-00004?repository_url=https://maven.repository.redhat.com/ga/&type=jar",
      "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "name": "quarkus-resteasy-reactive-jsonb-deployment",
      "version": "2.13.8.Final-redhat-00004"
    }
  ],
  "total": 4
}
"#).await
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn sbom_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;
    ctx.ingest_document("quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;

    let tool = Rc::new(SbomInfo(SbomService::new(ctx.db.clone())));

    assert_tool_contains(
        tool.clone(),
        "quarkus",
        r#"
{
  "uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "source_document_sha256": "sha256:5a370574a991aa42f7ecc5b7d88754b258f81c230a73bea247c0a6fcc6f608ab",
  "name": "quarkus-bom",
  "published": "2023-11-13T00:10:00Z",
  "authors": [
    "Organization: Red Hat Product Security (secalert@redhat.com)"
  ],
  "labels": [
    [
      "source",
      "TrustifyContext"
    ],
    [
      "type",
      "spdx"
    ]
  ],
  "advisories": []
}
"#,
    )
        .await
}
