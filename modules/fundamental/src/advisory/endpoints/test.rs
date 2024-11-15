use crate::{
    advisory::model::{AdvisoryDetails, AdvisorySummary},
    test::caller,
};
use actix_http::StatusCode;
use actix_web::test::TestRequest;
use hex::ToHex;
use jsonpath_rust::JsonPathQuery;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use trustify_common::{db::Transactional, hashing::Digests, id::Id, model::PaginatedResults};
use trustify_cvss::cvss3::{
    AttackComplexity, AttackVector, Availability, Confidentiality, Cvss3Base, Integrity,
    PrivilegesRequired, Scope, UserInteraction,
};
use trustify_entity::labels::Labels;
use trustify_module_ingestor::{graph::advisory::AdvisoryInformation, model::IngestResult};
use trustify_test_context::{call::CallService, document_bytes, TrustifyContext};
use uuid::Uuid;

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_advisories(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let advisory = ctx
        .graph
        .ingest_advisory(
            "RHSA-1",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                version: None,
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory_vuln = advisory
        .link_to_vulnerability("CVE-123", None, Transactional::None)
        .await?;
    advisory_vuln
        .ingest_cvss3_score(
            Cvss3Base {
                minor_version: 0,
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                pr: PrivilegesRequired::None,
                ui: UserInteraction::None,
                s: Scope::Unchanged,
                c: Confidentiality::None,
                i: Integrity::None,
                a: Availability::None,
            },
            (),
        )
        .await?;

    ctx.graph
        .ingest_advisory(
            "RHSA-2",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-2"),
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
                version: None,
                issuer: None,
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let uri = "/api/v1/advisory";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<AdvisorySummary> = app.call_and_read_body_json(request).await;

    assert_eq!(2, response.items.len());

    let rhsa_1 = &response
        .items
        .iter()
        .find(|e| e.head.identifier == "RHSA-1");

    assert!(rhsa_1.is_some());

    let rhsa_1 = rhsa_1.unwrap();

    assert!(rhsa_1
        .vulnerabilities
        .iter()
        .any(|e| e.head.identifier == "CVE-123"));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn one_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let advisory1 = ctx
        .graph
        .ingest_advisory(
            "RHSA-1",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                version: None,
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory2 = ctx
        .graph
        .ingest_advisory(
            "RHSA-2",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-2"),
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
                version: None,
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory_vuln = advisory2
        .link_to_vulnerability("CVE-123", None, Transactional::None)
        .await?;
    advisory_vuln
        .ingest_cvss3_score(
            Cvss3Base {
                minor_version: 0,
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                pr: PrivilegesRequired::High,
                ui: UserInteraction::None,
                s: Scope::Changed,
                c: Confidentiality::High,
                i: Integrity::None,
                a: Availability::None,
            },
            (),
        )
        .await?;

    let uri = format!("/api/v1/advisory/urn:uuid:{}", advisory2.advisory.id);

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    assert_eq!(
        response.clone().path("$.issuer.name").unwrap(),
        json!(["Red Hat Product Security"])
    );

    let cvss3_scores = response
        .path("$.vulnerabilities[*].cvss3_scores.*")
        .unwrap();

    log::debug!("{:#?}", cvss3_scores);

    assert_eq!(
        cvss3_scores,
        json!(["CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N"])
    );

    let uri = format!("/api/v1/advisory/urn:uuid:{}", advisory1.advisory.id);

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    let vulns = response.path("$.vulnerabilities").unwrap();

    assert_eq!(vulns, json!([[]]));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn one_advisory_by_uuid(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.graph
        .ingest_advisory(
            "RHSA-1",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                version: None,
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory = ctx
        .graph
        .ingest_advisory(
            "RHSA-2",
            ("source", "http://redhat.com/"),
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
                version: None,
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let uuid = advisory.advisory.id;

    let advisory_vuln = advisory
        .link_to_vulnerability("CVE-123", None, Transactional::None)
        .await?;
    advisory_vuln
        .ingest_cvss3_score(
            Cvss3Base {
                minor_version: 0,
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                pr: PrivilegesRequired::High,
                ui: UserInteraction::None,
                s: Scope::Changed,
                c: Confidentiality::High,
                i: Integrity::None,
                a: Availability::None,
            },
            (),
        )
        .await?;

    let uri = format!("/api/v1/advisory/{}", uuid.urn());

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    log::debug!("{:#?}", response);

    assert_eq!(
        response.clone().path("$.issuer.name").unwrap(),
        json!(["Red Hat Product Security"])
    );

    let cvss3_scores = response
        .path("$.vulnerabilities[*].cvss3_scores.*")
        .unwrap();

    log::debug!("{:#?}", cvss3_scores);

    assert_eq!(
        cvss3_scores,
        json!(["CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:N/A:N"])
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn search_advisories(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    async fn query(app: &impl CallService, q: &str) -> PaginatedResults<AdvisorySummary> {
        let uri = format!("/api/v1/advisory?q={}", urlencoding::encode(q));
        let req = TestRequest::get().uri(&uri).to_request();
        app.call_and_read_body_json(req).await
    }
    let app = caller(ctx).await?;

    // No results before ingestion
    let result = query(&app, "").await;
    assert_eq!(result.total, 0);

    // ingest some advisories
    ctx.ingest_documents(["mitre/CVE-2024-27088.json", "mitre/CVE-2024-28111.json"])
        .await?;

    let result = query(&app, "").await;
    assert_eq!(result.total, 2);
    let result = query(&app, "csv").await;
    assert_eq!(result.total, 1);
    assert_eq!(result.items[0].head.identifier, "CVE-2024-28111");
    let result = query(&app, "function#copy").await;
    assert_eq!(result.total, 1);
    assert_eq!(result.items[0].head.identifier, "CVE-2024-27088");
    let result = query(&app, "tostringtokens").await;
    assert_eq!(result.total, 1);
    assert_eq!(result.items[0].head.identifier, "CVE-2024-27088");
    let result = query(&app, "es5-ext").await;
    assert_eq!(result.items[0].head.identifier, "CVE-2024-27088");
    assert_eq!(result.total, 1);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_default_csaf_format(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let payload = document_bytes("csaf/cve-2023-33201.json").await?;

    let uri = "/api/v1/advisory";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let result: IngestResult = app.call_and_read_body_json(request).await;
    log::debug!("{result:?}");
    assert!(matches!(result.id, Id::Uuid(_)));
    assert_eq!(result.document_id, "https://www.redhat.com/#CVE-2023-33201");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_default_csaf_format_multiple(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let files = vec![
        "csaf/cve-2023-0044.json",
        "csaf/rhsa-2023_5835.json",
        "csaf/rhsa-2024_2776.json",
        "csaf/CVE-2023-20862.json",
        "csaf/rhsa-2024_2049.json",
        "csaf/cve-2023-33201.json",
        "csaf/rhsa-2024_2784.json",
        "csaf/rhsa-2024_2054.json",
        "csaf/rhsa-2024_3351.json",
        "csaf/CVE-2024-5154.json",
        "csaf/rhsa-2024_2071.json",
        "csaf/rhsa-2024_3666.json",
        "csaf/RHBA-2024_1440.json",
        "csaf/rhsa-2024-2705.json",
    ];

    let uri = "/api/v1/advisory";

    for file in files {
        let payload = document_bytes(file).await?;

        let request = TestRequest::post()
            .uri(uri)
            .set_payload(payload)
            .to_request();

        let result: IngestResult = app.call_and_read_body_json(request).await;
        log::debug!("{result:?}");
        assert!(matches!(result.id, Id::Uuid(_)));
    }

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_osv_format(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let payload = document_bytes("osv/RUSTSEC-2021-0079.json").await?;

    let uri = "/api/v1/advisory";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let result: IngestResult = app.call_and_read_body_json(request).await;
    assert!(matches!(result.id, Id::Uuid(_)));
    assert_eq!(result.document_id, "RUSTSEC-2021-0079");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_cve_format(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let payload = document_bytes("mitre/CVE-2024-27088.json").await?;

    let uri = "/api/v1/advisory";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let result: IngestResult = app.call_and_read_body_json(request).await;
    assert!(matches!(result.id, Id::Uuid(_)));
    assert_eq!(result.document_id, "CVE-2024-27088");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_unknown_format(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = "/api/v1/advisory";
    let request = TestRequest::post().uri(uri).to_request();

    let response = app.call_service(request).await;
    log::debug!("response: {response:?}");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Wrong HTTP response status"
    );

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn upload_with_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let payload = document_bytes("csaf/cve-2023-33201.json").await?;

    let uri = "/api/v1/advisory?labels.foo=bar&labels.bar=baz";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let result: IngestResult = app.call_and_read_body_json(request).await;
    log::debug!("{result:?}");
    assert!(matches!(result.id, Id::Uuid(_)));
    assert_eq!(result.document_id, "https://www.redhat.com/#CVE-2023-33201");

    // now check the labels

    let request = TestRequest::get()
        .uri(&format!("/api/v1/advisory/{}", result.id))
        .to_request();
    let result: AdvisoryDetails = app.call_and_read_body_json(request).await;

    assert_eq!(
        result.head.labels,
        Labels::new()
            .add("foo", "bar")
            .add("bar", "baz")
            .add("type", "csaf")
    );

    // done

    Ok(())
}

const DOC: &str = "csaf/cve-2023-33201.json";

/// Test downloading a document by its SHA256 digest
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn download_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let digest: String = Sha256::digest(document_bytes(DOC).await?).encode_hex();
    let app = caller(ctx).await?;
    ctx.ingest_document(DOC).await?;
    let uri = format!("/api/v1/advisory/sha256:{digest}/download");
    let request = TestRequest::get().uri(&uri).to_request();
    let doc: Value = app.call_and_read_body_json(request).await;
    assert_eq!(doc["document"]["tracking"]["id"], "CVE-2023-33201");

    Ok(())
}

/// Test downloading a document by its upload ID
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn download_advisory_by_id(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let result = ctx.ingest_document(DOC).await?;
    let uri = format!("/api/v1/advisory/{}/download", result.id);
    let request = TestRequest::get().uri(&uri).to_request();
    let doc: Value = app.call_and_read_body_json(request).await;
    assert_eq!(doc["document"]["tracking"]["id"], "CVE-2023-33201");

    Ok(())
}

/// Test setting labels
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn set_labels(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let result = ctx.ingest_document(DOC).await?;
    let request = TestRequest::patch()
        .uri(&format!("/api/v1/advisory/{}/label", result.id))
        .set_json(Labels::new().extend([("foo", "1"), ("bar", "2")]))
        .to_request();
    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    Ok(())
}

/// Test setting labels, for a document that does not exists
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn set_labels_not_found(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    ctx.ingest_document(DOC).await?;
    let request = TestRequest::patch()
        .uri(&format!(
            "/api/v1/advisory/{}/label",
            Id::Uuid(Uuid::now_v7())
        ))
        .set_json(Labels::new().extend([("foo", "1"), ("bar", "2")]))
        .to_request();
    let response = app.call_service(request).await;
    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

/// Test deleing an advisory
#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn delete_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;
    let doc = ctx.ingest_document(DOC).await?;

    let advisory_list: PaginatedResults<AdvisorySummary> = app
        .call_and_read_body_json(TestRequest::get().uri("/api/v1/advisory").to_request())
        .await;
    assert_eq!(advisory_list.total, 1);

    // first delete should succeed
    let response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v1/advisory/{}", doc.id))
                .to_request(),
        )
        .await;

    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::OK);

    // check that the document is gone
    let advisory_list: PaginatedResults<AdvisorySummary> = app
        .call_and_read_body_json(TestRequest::get().uri("/api/v1/advisory").to_request())
        .await;
    assert_eq!(advisory_list.total, 0);

    // second delete should fail
    let response = app
        .call_service(
            TestRequest::delete()
                .uri(&format!("/api/v1/advisory/{}", doc.id))
                .to_request(),
        )
        .await;

    log::debug!("Code: {}", response.status());
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}
