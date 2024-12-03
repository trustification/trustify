use crate::ai::model::ChatState;
use crate::ai::service::AiService;

use test_context::test_context;
use test_log::test;
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
            &ctx.db,
        )
        .await?;

    let pr = ctx
        .graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
                cpe: None,
            },
            &ctx.db,
        )
        .await?;

    pr.ingest_product_version("37.17.9".to_string(), Some(sbom.sbom.sbom_id), &ctx.db)
        .await?;

    ctx.ingest_documents(["osv/RUSTSEC-2021-0079.json", "cve/CVE-2021-32714.json"])
        .await?;
    ctx.ingest_document("quarkus/v1/quarkus-bom-2.13.8.Final-redhat-00004.json")
        .await?;
    ctx.ingest_document("csaf/rhsa-2024_3666.json").await?;

    Ok(())
}

pub fn sanitize_uuid_field(value: String) -> String {
    let re = regex::Regex::new(r#""uuid": "\b[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}\b""#).unwrap();
    re.replace_all(
        value.as_str(),
        r#""uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx""#,
    )
    .to_string()
}

pub fn sanitize_uuid_urn(value: String) -> String {
    let re = regex::Regex::new(r#"urn:uuid:\b[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}\b"#).unwrap();
    re.replace_all(
        value.as_str(),
        r#"urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"#,
    )
    .to_string()
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_completions_sbom_info(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = AiService::new(ctx.db.clone());
    if !service.completions_enabled() {
        return Ok(()); // skip test
    }

    ingest_fixtures(ctx).await?;

    let mut req = ChatState::new();
    req.add_human_message(
        "Give me information about the SBOMs available for quarkus reporting its name, SHA and URL."
            .into(),
    );

    let result = service.completions(&req, &ctx.db).await?;

    log::info!("result: {:#?}", result);
    let last_message_content = result.messages.last().unwrap().content.clone();
    println!(
        "Test formatted output:\n\n{}\n",
        termimad::inline(last_message_content.as_str())
    );
    assert!(last_message_content.contains("quarkus-bom"));
    assert!(last_message_content
        .contains("5a370574a991aa42f7ecc5b7d88754b258f81c230a73bea247c0a6fcc6f608ab"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_completions_package_info(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = AiService::new(ctx.db.clone());
    if !service.completions_enabled() {
        return Ok(()); // skip test
    }

    ingest_fixtures(ctx).await?;

    let mut req = ChatState::new();
    req.add_human_message("List the httpclient packages with their identifiers".into());

    let result = service.completions(&req, &ctx.db).await?;

    log::info!("result: {:#?}", result);
    let last_message_content = result.messages.last().unwrap().content.clone();
    println!(
        "Test formatted output:\n\n{}\n",
        termimad::inline(last_message_content.as_str())
    );
    assert!(last_message_content.contains("httpclient@4.5.13.redhat-00002"));
    assert!(last_message_content
        .contains("quarkus-apache-httpclient-deployment@2.13.8.Final-redhat-00004"));
    assert!(last_message_content.contains("quarkus-apache-httpclient@2.13.8.Final-redhat-00004"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_completions_cve_info(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = AiService::new(ctx.db.clone());
    if !service.completions_enabled() {
        return Ok(()); // skip test
    }

    ingest_fixtures(ctx).await?;

    let mut req = ChatState::new();
    req.add_human_message("Give me details for CVE-2021-32714".into());

    let result = service.completions(&req, &ctx.db).await?;

    log::info!("result: {:#?}", result);
    let last_message_content = result.messages.last().unwrap().content.clone();
    println!(
        "Test formatted output:\n\n{}\n",
        termimad::inline(last_message_content.as_str())
    );
    assert!(last_message_content.contains("CVE-2021-32714"));
    assert!(last_message_content.contains("hyper"));
    assert!(last_message_content.contains("0.14.10"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_completions_advisory_info(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = AiService::new(ctx.db.clone());
    if !service.completions_enabled() {
        return Ok(()); // skip test
    }

    ingest_fixtures(ctx).await?;

    let mut req = ChatState::new();
    req.add_human_message("Give me details for the RHSA-2024_3666 advisory".into());

    let result = service.completions(&req, &ctx.db).await?;

    log::info!("result: {:#?}", result);
    let last_message_content = result.messages.last().unwrap().content.clone();
    println!(
        "Test formatted output:\n\n{}\n",
        termimad::inline(last_message_content.as_str())
    );
    assert!(last_message_content.contains("RHSA-2024_3666"));
    assert!(last_message_content.contains("Apache Tomcat"));
    assert!(last_message_content.contains("CVE-2024-23672"));
    assert!(last_message_content.contains("CVE-2024-24549"));
    assert!(last_message_content.contains("DoS"));

    Ok(())
}
