use crate::{advisory::model::AdvisorySummary, configure, test::CallService};
use actix_http::{Request, StatusCode};
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceResponse},
    test::TestRequest,
    web, App, Error,
};
use bytesize::ByteSize;
use futures_util::future::LocalBoxFuture;
use hex::ToHex;
use jsonpath_rust::JsonPathQuery;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use test_context::test_context;
use test_log::test;
use time::OffsetDateTime;
use tokio_util::io::ReaderStream;
use trustify_common::hashing::Digests;
use trustify_common::{
    db::{test::TrustifyContext, Transactional},
    id::Id,
    model::PaginatedResults,
};
use trustify_cvss::cvss3::{
    AttackComplexity, AttackVector, Availability, Confidentiality, Cvss3Base, Integrity,
    PrivilegesRequired, Scope, UserInteraction,
};
use trustify_module_ingestor::{
    graph::{advisory::AdvisoryInformation, Graph},
    model::IngestResult,
    service::IngestorService,
};
use trustify_module_storage::service::fs::FileSystemBackend;

async fn query<S, B>(app: &S, q: &str) -> PaginatedResults<AdvisorySummary>
where
    S: Service<Request, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    let uri = format!("/api/v1/advisory?q={}", urlencoding::encode(q));
    let req = TestRequest::get().uri(&uri).to_request();
    actix_web::test::call_and_read_body_json(app, req).await
}

async fn ingest(service: &IngestorService, data: &[u8]) -> IngestResult {
    use trustify_module_ingestor::service::Format;
    service
        .ingest(
            "unit-test",
            Some("Capt Pickles Industrial Conglomerate".to_string()),
            Format::from_bytes(data).unwrap(),
            ReaderStream::new(data),
        )
        .await
        .unwrap()
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn all_advisories(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _) = FileSystemBackend::for_test().await?;

    let app = actix_web::test::init_service(
        App::new()
            .service(web::scope("/api").configure(|config| configure(config, db, storage.clone()))),
    )
    .await;

    let advisory = graph
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/",
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
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

    graph
        .ingest_advisory(
            "RHSA-2",
            "http://redhat.com/",
            &Digests::digest("RHSA-2"),
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
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

    let response: PaginatedResults<AdvisorySummary> =
        actix_web::test::call_and_read_body_json(&app, request).await;

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

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn one_advisory(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _) = FileSystemBackend::for_test().await?;

    let app = actix_web::test::init_service(
        App::new().service(
            web::scope("/api")
                .configure(|config| crate::endpoints::configure(config, db, storage.clone())),
        ),
    )
    .await;

    let advisory1 = graph
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/",
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory2 = graph
        .ingest_advisory(
            "RHSA-2",
            "http://redhat.com/",
            &Digests::digest("RHSA-2"),
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
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

    let response: Value = actix_web::test::call_and_read_body_json(&app, request).await;

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

    let uri = format!("/api/v1/advisory/urn:uuid:{}", advisory1.advisory.id);

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = actix_web::test::call_and_read_body_json(&app, request).await;

    let vulns = response.path("$.vulnerabilities").unwrap();

    assert_eq!(vulns, json!([[]]));

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn one_advisory_by_uuid(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _) = FileSystemBackend::for_test().await?;

    let app = actix_web::test::init_service(
        App::new().service(
            web::scope("/api")
                .configure(|config| crate::endpoints::configure(config, db, storage.clone())),
        ),
    )
    .await;

    graph
        .ingest_advisory(
            "RHSA-1",
            "http://redhat.com/",
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                title: Some("RHSA-1".to_string()),
                issuer: Some("Red Hat Product Security".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let advisory = graph
        .ingest_advisory(
            "RHSA-2",
            "http://redhat.com/",
            &Digests::digest("RHSA-1"),
            AdvisoryInformation {
                title: Some("RHSA-2".to_string()),
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

    let response: Value = actix_web::test::call_and_read_body_json(&app, request).await;

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

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn search_advisories(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    use actix_web::test::init_service;
    use trustify_module_storage::service::fs::FileSystemBackend;

    let db = ctx.db;
    let graph = Graph::new(db.clone());
    let (storage, _) = FileSystemBackend::for_test().await?;
    let ingestor = IngestorService::new(graph, storage.clone());
    let app = init_service(
        App::new()
            .service(web::scope("/api").configure(|config| configure(config, db, storage.clone()))),
    )
    .await;
    let _response: PaginatedResults<AdvisorySummary>;

    // No results before ingestion
    let result = query(&app, "").await;
    assert_eq!(result.total, 0);

    // ingest some advisories
    let data = include_bytes!("../../../../../etc/test-data/mitre/CVE-2024-27088.json");
    let _id = ingest(&ingestor, data).await;
    let data = include_bytes!("../../../../../etc/test-data/mitre/CVE-2024-28111.json");
    let _id = ingest(&ingestor, data).await;

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

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn upload_default_csaf_format(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let (storage, _temp) = FileSystemBackend::for_test().await?;
    let app = actix_web::test::init_service(App::new().configure(|svc| {
        let limit = ByteSize::gb(1).as_u64() as usize;
        svc.app_data(web::PayloadConfig::default().limit(limit))
            .service(web::scope("/api").configure(|svc| configure(svc, db, storage)));
    }))
    .await;
    let payload = include_str!("../../../../../etc/test-data/csaf/cve-2023-33201.json");

    let uri = "/api/v1/advisory";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let response = actix_web::test::call_service(&app, request).await;
    let result: IngestResult = actix_web::test::read_body_json(response).await;
    log::debug!("{result:?}");
    assert!(matches!(result.id, Id::Uuid(_)));
    assert_eq!(result.document_id, "CVE-2023-33201");

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn upload_osv_format(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let (storage, _temp) = FileSystemBackend::for_test().await?;
    let app = actix_web::test::init_service(App::new().service(
        web::scope("/api").configure(|svc| crate::endpoints::configure(svc, db, storage)),
    ))
    .await;
    let payload = include_str!("../../../../../etc/test-data/osv/RUSTSEC-2021-0079.json");

    let uri = "/api/v1/advisory";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let response = actix_web::test::call_service(&app, request).await;
    assert!(response.status().is_success());
    let result: IngestResult = actix_web::test::read_body_json(response).await;
    assert!(matches!(result.id, Id::Uuid(_)));
    assert_eq!(result.document_id, "RUSTSEC-2021-0079");

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn upload_cve_format(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let (storage, _temp) = FileSystemBackend::for_test().await?;
    let app = actix_web::test::init_service(App::new().service(
        web::scope("/api").configure(|svc| crate::endpoints::configure(svc, db, storage)),
    ))
    .await;
    let payload = include_str!("../../../../../etc/test-data/mitre/CVE-2024-27088.json");

    let uri = "/api/v1/advisory";
    let request = TestRequest::post()
        .uri(uri)
        .set_payload(payload)
        .to_request();

    let response = actix_web::test::call_service(&app, request).await;
    assert!(response.status().is_success());
    let result: IngestResult = actix_web::test::read_body_json(response).await;
    assert!(matches!(result.id, Id::Uuid(_)));
    assert_eq!(result.document_id, "CVE-2024-27088");

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn upload_unknown_format(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let (storage, _temp) = FileSystemBackend::for_test().await?;
    let app = actix_web::test::init_service(App::new().configure(|svc| {
        let limit = ByteSize::gb(1).as_u64() as usize;
        svc.app_data(web::PayloadConfig::default().limit(limit))
            .service(
                web::scope("/api").configure(|svc| crate::endpoints::configure(svc, db, storage)),
            );
    }))
    .await;

    let uri = "/api/v1/advisory";
    let request = TestRequest::post().uri(uri).to_request();

    let response = actix_web::test::call_service(&app, request).await;
    log::debug!("response: {response:?}");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "Wrong HTTP response status"
    );

    Ok(())
}

const DOC: &[u8] = include_bytes!("../../../../../etc/test-data/csaf/cve-2023-33201.json");

/// This will upload [`DOC`], and then call the test function, providing the upload id of the document.
async fn with_upload<F>(ctx: TrustifyContext, f: F) -> anyhow::Result<()>
where
    for<'a> F: FnOnce(IngestResult, &'a dyn CallService) -> LocalBoxFuture<'a, anyhow::Result<()>>,
{
    let db = ctx.db;
    let (storage, _) = FileSystemBackend::for_test().await?;
    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::PayloadConfig::default().limit(1024 * 1024))
            .service(web::scope("/api").configure(|svc| configure(svc, db, storage.clone()))),
    )
    .await;

    // upload

    let request = TestRequest::post()
        .uri("/api/v1/advisory")
        .set_payload(DOC)
        .to_request();

    let response = actix_web::test::call_service(&app, request).await;

    log::debug!("Code: {}", response.status());
    assert!(response.status().is_success());
    let result: IngestResult = actix_web::test::read_body_json(response).await;

    log::debug!("ID: {result:?}");
    assert!(matches!(result.id, Id::Uuid(_)));

    f(result, &app).await?;

    // download

    Ok(())
}

/// Test downloading a document by its SHA256 digest
#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn download_advisory(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let digest: String = Sha256::digest(DOC).encode_hex();

    with_upload(ctx, move |_id, app| {
        Box::pin(async move {
            let uri = format!("/api/v1/advisory/sha256:{digest}/download");
            let request = TestRequest::get().uri(&uri).to_request();

            let response = app.call_service(request).await;

            assert!(response.status().is_success());
            let doc: Value = actix_web::test::read_body_json(response).await;
            assert_eq!(doc["document"]["tracking"]["id"], "CVE-2023-33201");

            Ok(())
        })
    })
    .await
}

/// Test downloading a document by its upload ID
#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn download_advisory_by_id(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    with_upload(ctx, |result, app| {
        Box::pin(async move {
            let uri = format!("/api/v1/advisory/{}/download", result.id);
            let request = TestRequest::get().uri(&uri).to_request();

            let response = app.call_service(request).await;

            log::debug!("Code: {}", response.status());
            assert!(response.status().is_success());
            let doc: Value = actix_web::test::read_body_json(response).await;
            assert_eq!(doc["document"]["tracking"]["id"], "CVE-2023-33201");

            Ok(())
        })
    })
    .await
}
