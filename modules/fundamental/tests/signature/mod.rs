use crate::caller;
use crate::common::create_zip;
use actix_http::StatusCode;
use actix_web::test::{TestRequest, read_body_json};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService, document_bytes};
use urlencoding::encode;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    // create zip and ingest (ds6 has signatures)

    let sig = document_bytes("../datasets/ds6/csaf/2022/cve-2022-45787.json.asc").await?;
    let trust_anchor = document_bytes("trust_anchor/97f5eac4.txt").await?;

    let data = create_zip(ctx.absolute_path("../datasets/ds6")?)?;
    let result = ctx.ingestor.ingest_dataset(&data, (), 0).await?;

    let id = result.files["csaf/2022/cve-2022-45787.json"].id.to_string();

    // get the signatures

    let request = TestRequest::get()
        .uri(&format!("/api/v2/advisory/{}/signature", encode(&id)))
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
                    "payload": STANDARD.encode(&sig),
                }
            ]
        })
    );

    // verify (without trust anchors)

    let request = TestRequest::get()
        .uri(&format!("/api/v2/advisory/{}/verify", encode(&id)))
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
                        "payload": STANDARD.encode(&sig),
                    },
                    "trustAnchors": []
                }
            ],
            "total": 1,
        })
    );

    // add a matching trust anchor

    let request = TestRequest::post()
        .uri("/api/v2/trust-anchor/test")
        .set_json(json!({
            "type": "pgp",
            "payload": STANDARD.encode(&trust_anchor),
        }))
        .to_request();
    let response = app.call_service(request).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // verify (with a matching trust anchor)

    let request = TestRequest::get()
        .uri(&format!("/api/v2/advisory/{}/verify", encode(&id)))
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
                        "payload": STANDARD.encode(&sig),
                    },
                    "trustAnchors": [
                        {
                            "id": "test",
                            "type": "pgp",
                            "disabled": false,
                            "description": "",
                            "payload": STANDARD.encode(&trust_anchor),
                        }
                    ]
                }
            ],
            "total": 1,
        })
    );

    // done

    Ok(())
}
