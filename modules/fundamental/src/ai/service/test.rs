use crate::advisory::service::AdvisoryService;
use crate::ai::model::ChatState;
use crate::ai::service::tools::{AdvisoryInfo, CVEInfo, ProductInfo};
use crate::ai::service::AiService;
use crate::product::service::ProductService;
use crate::vulnerability::service::VulnerabilityService;
use langchain_rust::tools::Tool;
use serde_json::Value;
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
    let result = tool.run(Value::String("CVE-2021-32714".to_string())).await;
    assert!(result.is_ok(), "result: {:?}", result);
    assert!(result.unwrap().contains(r#"
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

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn product_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ingest_fixtures(ctx).await?;
    let tool = ProductInfo(ProductService::new(ctx.db.clone()));
    let result = tool
        .run(Value::String("Trusted Profile Analyzer".to_string()))
        .await;
    assert!(result.is_ok(), "result: {:?}", result);
    assert!(result.unwrap().contains(
        r#"
Found one matching product:
  * Name: Trusted Profile Analyzer
    Vendor: Red Hat
    Versions:
      * 37.17.9
"#
        .trim()
    ));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn advisory_info_tool(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    crate::advisory::service::test::ingest_and_link_advisory(ctx).await?;
    crate::advisory::service::test::ingest_sample_advisory(ctx, "RHSA-2").await?;

    let tool = AdvisoryInfo(AdvisoryService::new(ctx.db.clone()));
    let result = tool.run(Value::String("RHSA-1".to_string())).await.unwrap();
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
