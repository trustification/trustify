use crate::ai::model::{ChatMessage, ChatState};
use crate::ai::service::AiService;

use test_context::test_context;
use test_log::test;
use trustify_common::db::query::Query;
use trustify_common::hashing::Digests;
use trustify_common::model::Paginated;
use trustify_module_ingestor::graph::product::ProductInformation;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

pub async fn ingest_fixtures(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let sbom = ctx
        .graph
        .ingest_sbom(
            ("source", "http://redhat.com/test.json"),
            &Digests::digest("RHSA-1"),
            Some("a".to_string()),
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

    let mut req = ChatState::default();
    req.messages.push(ChatMessage::human(
        "Give me information about the SBOMs available for quarkus reporting its name, SHA and URL."
            .into(),
    ));

    let result = service.completions(&req).await?;

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

    let mut req = ChatState::default();
    req.messages.push(ChatMessage::human(
        "List the httpclient packages with their identifiers".into(),
    ));

    let result = service.completions(&req).await?;

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

    let mut req = ChatState::default();
    req.messages.push(ChatMessage::human(
        "Give me details for CVE-2021-32714".into(),
    ));

    let result = service.completions(&req).await?;

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

    let mut req = ChatState::default();
    req.messages.push(ChatMessage::human(
        "Give me details for the RHSA-2024_3666 advisory".into(),
    ));

    let result = service.completions(&req).await?;

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

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn conversation_crud(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = AiService::new(ctx.db.clone());
    if !service.completions_enabled() {
        return Ok(()); // skip test
    }

    // create a conversation
    let conversation_id = Uuid::now_v7();
    let mut state = ChatState::default();
    state.messages.push(ChatMessage::human("hello".into()));

    let (conversation, _internal_state) = service
        .upsert_conversation(
            conversation_id,
            "user_a".into(),
            &state.messages,
            Some(0),
            &ctx.db,
        )
        .await?;

    assert_eq!("user_a", conversation.user_id);
    assert_eq!("hello", conversation.summary);
    assert_eq!(1i32, conversation.seq);

    // get the created conversation
    let fetched = service
        .fetch_conversation(conversation_id, &ctx.db)
        .await?
        .map(|x| x.0);

    assert_eq!(Some(conversation.clone()), fetched);

    // list the conversations of the user
    let converstations = service
        .fetch_conversations(
            "user_a".into(),
            Query::default(),
            Paginated {
                offset: 0,
                limit: 10,
            },
            &ctx.db,
        )
        .await?;

    assert_eq!(1, converstations.total);
    assert_eq!(1, converstations.items.len());
    assert_eq!(conversation, converstations.items[0]);

    state
        .messages
        .push(ChatMessage::human("hello again".into()));

    let value2 = service
        .upsert_conversation(
            conversation_id,
            "user_a".into(),
            &state.messages,
            Some(1),
            &ctx.db,
        )
        .await?
        .0;

    // get the updated conversation
    let fetched = service
        .fetch_conversation(conversation_id, &ctx.db)
        .await?
        .unwrap()
        .0;

    assert_eq!(value2, fetched);

    // verify that the update fails due to old seq
    service
        .upsert_conversation(conversation_id, "user_a".into(), &vec![], Some(0), &ctx.db)
        .await
        .expect_err("should fail due to old seq");

    // delete the conversation
    let delete_count = service
        .delete_conversation(conversation_id, &ctx.db)
        .await?;
    assert_eq!(delete_count, 1u64);

    // get the deleted conversation
    let fetched = service
        .fetch_conversation(conversation_id, &ctx.db)
        .await?
        .map(|x| x.0);

    assert_eq!(None, fetched);

    Ok(())
}
