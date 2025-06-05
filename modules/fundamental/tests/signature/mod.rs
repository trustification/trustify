use crate::{caller, common::create_zip};
use actix_http::StatusCode;
use actix_web::test::{TestRequest, read_body_json};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_module_ingestor::service::dataset::DatasetIngestResult;
use trustify_module_signature::service::DocumentType;
use trustify_test_context::{TrustifyContext, call::CallService, document_bytes};
use urlencoding::encode;

async fn ensure_one_signature(
    app: &impl CallService,
    r#type: DocumentType,
    id: &str,
    signature: &[u8],
) {
    let request = TestRequest::get()
        .uri(&format!("/api/v2/{type}/{}/signature", encode(id)))
        .to_request();

    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let result: Value = read_body_json(response).await;
    assert_eq!(
        result,
        json!({
            "total": 1,
            "items": [
                {
                    "id": result["items"][0]["id"].clone(),
                    "type": "pgp",
                    "payload": STANDARD.encode(signature),
                }
            ]
        })
    );
}

async fn ensure_valid_signature(
    app: &impl CallService,
    r#type: DocumentType,
    id: &str,
    signature: &[u8],
    expected_trust_anchors: Value,
) {
    let request = TestRequest::get()
        .uri(&format!("/api/v2/{type}/{}/verify", encode(id)))
        .to_request();
    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let result: Value = read_body_json(response).await;
    assert_eq!(
        result,
        json!({
            "items": [
                {
                    "signature": {
                        "id": result["items"][0]["signature"]["id"].clone(),
                        "type": "pgp",
                        "payload": STANDARD.encode(signature),
                    },
                    "trustAnchors": expected_trust_anchors
                }
            ],
            "total": 1,
        })
    );
}

async fn add_trust_anchor(app: &impl CallService, trust_anchor: &[u8]) {
    let request = TestRequest::post()
        .uri("/api/v2/trust-anchor/test")
        .set_json(json!({
            "type": "pgp",
            "payload": STANDARD.encode(trust_anchor),
        }))
        .to_request();
    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

async fn ingest_ds6(ctx: &TrustifyContext) -> anyhow::Result<DatasetIngestResult> {
    let data = create_zip(ctx.absolute_path("../datasets/ds6")?)?;
    let result = ctx.ingestor.ingest_dataset(&data, (), 0).await?;

    Ok(result)
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_advisory(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // create zip and ingest (ds6 has signatures)

    let result = ingest_ds6(ctx).await?;

    // get data

    let trust_anchor = document_bytes("trust_anchor/97f5eac4.txt").await?;
    let sig = document_bytes("../datasets/ds6/csaf/2022/cve-2022-45787.json.asc").await?;
    let id = result.files["csaf/2022/cve-2022-45787.json"].id.to_string();

    // get the signatures

    ensure_one_signature(&app, DocumentType::Advisory, &id, &sig).await;

    // verify (without trust anchors)

    ensure_valid_signature(&app, DocumentType::Advisory, &id, &sig, json!([])).await;

    // add a matching trust anchor

    add_trust_anchor(&app, &trust_anchor).await;

    // verify (with a matching trust anchor)

    ensure_valid_signature(
        &app,
        DocumentType::Advisory,
        &id,
        &sig,
        json!([{
            "id": "test",
            "type": "pgp",
            "disabled": false,
            "description": "",
            "payload": STANDARD.encode(&trust_anchor),
        }]),
    )
    .await;

    // done

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_sbom(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // create zip and ingest (ds6 has signatures)

    let result = ingest_ds6(ctx).await?;

    // get data

    let trust_anchor = document_bytes("trust_anchor/97f5eac4.txt").await?;
    let sig =
        document_bytes("../datasets/ds6/spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2.asc")
            .await?;
    let id = result.files["spdx/quarkus-bom-2.13.8.Final-redhat-00004.json.bz2"]
        .id
        .to_string();

    // get the signatures

    ensure_one_signature(&app, DocumentType::Sbom, &id, &sig).await;

    // verify (without trust anchors)

    ensure_valid_signature(&app, DocumentType::Sbom, &id, &sig, json!([])).await;

    // add a matching trust anchor

    add_trust_anchor(&app, &trust_anchor).await;

    // verify (with a matching trust anchor)

    ensure_valid_signature(
        &app,
        DocumentType::Sbom,
        &id,
        &sig,
        // we don't expect a valid signature here, since the signature is for the compressed file
        json!([]),
    )
    .await;

    // done

    Ok(())
}
