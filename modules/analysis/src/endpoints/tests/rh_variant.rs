use crate::test::caller;
use actix_http::Request;
use actix_web::test::TestRequest;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService, subset::ContainsSubset};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_prod_comp_spdx_external_reference(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("spdx/rh/product_component/rhel-9.2-eus.spdx.json")
        .await?;
    let uri =
        "/api/v2/analysis/component/SPDXRef-openssl-3.0.7-18.el9-2?descendants=10".to_string();
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(200, response.response().status());

    ctx.ingest_document("spdx/rh/product_component/openssl-3.0.7-18.el9_2.spdx.json")
        .await?;
    let uri =
        "/api/v2/analysis/component/SPDXRef-openssl-3.0.7-18.el9-2?descendants=10".to_string();
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    //ensure we match on external node DocumentRef-ext-b:SPDXRef-A
    assert!(response.contains_subset(json!({
        "items": [ {
          "node_id": "SPDXRef-RHEL-9.2-EUS:SPDXRef-openssl-3.0.7-18.el9-2",
          "name": "SPDXRef-openssl-3.0.7-18.el9-2",
          "document_id": "https://www.redhat.com/rhel-9.2-eus.spdx.json",
          "descendants":[
                {
                    "name":"openssl-perl",
                    "document_id": "https://www.redhat.com/openssl-3.0.7-18.el9_2.spdx.json",
                    "relationship": "generates",
                }
            ]
        }]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_prod_comp_cdx_external_reference(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("cyclonedx/rh/product_component/rhel-9.2-eus.cdx.json")
        .await?;
    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode("cpe:/a:redhat:rhel_eus:9.2::appstream")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(200, response.response().status());

    ctx.ingest_document("cyclonedx/rh/product_component/openssl-3.0.7-18.el9_2.cdx.json")
        .await?;
    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode("cpe:/a:redhat:rhel_eus:9.2::appstream")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    assert!(response.contains_subset(json!({
      "items": [
        {
          "node_id": "Red Hat Enterprise Linux 9.2 EUS",
          "document_id": "urn:uuid:337d9115-4e7c-4e76-b389-51f7aed6eba8/1",
          "name": "Red Hat Enterprise Linux",
          "descendants": [
            {
              "node_id": "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
              "name": "openssl",
              "document_id": "urn:uuid:337d9115-4e7c-4e76-b389-51f7aed6eba8/1",
              "product_name": "Red Hat Enterprise Linux",
              "product_version": "9.2 EUS",
              "relationship": "generates",
              "descendants": [
                {
                    "node_id": "Red Hat Enterprise Linux 9.2 EUS:pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
                    "document_id": "urn:uuid:337d9115-4e7c-4e76-b389-51f7aed6eba8/1",
                    "relationship": "package",
                    "descendants": [{
                        "node_id": "pkg:rpm/redhat/openssl-perl@3.0.7-18.el9_2?arch=s390x",
                        "name": "openssl-perl",
                        "document_id": "urn:uuid:223234df-bb5b-49af-a896-143736f7d806/1"
                    }]
                }
              ]
            }
          ]
        }
      ]
    })));

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_prod_comp_cdx_external_reference_curl(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("cyclonedx/rh/product_component/RHEL-8.10.0.Z.MAIN+EUS.json")
        .await?;
    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode("cpe:/o:redhat:enterprise_linux:8.10::baseos")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(200, response.response().status());

    ctx.ingest_document(
        "cyclonedx/rh/product_component/RHEL-8.10.0.Z_curl@7.61.1-34.el8_10.2.json",
    )
    .await?;
    let uri = format!(
        "/api/v2/analysis/component/{}?descendants=10",
        urlencoding::encode("cpe:/o:redhat:enterprise_linux:8.10::baseos")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;

    log::warn!("{:?}", response);

    assert!(response.contains_subset(json!({
      "items": [
        {
          "node_id": "RHEL-8.10.0.Z.MAIN+EUS",
          "document_id": "urn:uuid:6895f8e0-2bfd-331c-97f9-97369ef1f3ee/1",
          "name": "Red Hat Enterprise Linux 8",
          "descendants": [
            {
              "node_id": "pkg:rpm/redhat/curl@7.61.1-34.el8_10.2?arch=src",
              "name": "curl",
              "document_id": "urn:uuid:6895f8e0-2bfd-331c-97f9-97369ef1f3ee/1",
              "relationship": "generates",
            }]
        }
      ]
    })));

    Ok(())
}
