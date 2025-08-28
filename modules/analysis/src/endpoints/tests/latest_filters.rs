use std::collections::HashSet;

use crate::test::caller;

use actix_http::Request;
use actix_web::test::TestRequest;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_test_context::{TrustifyContext, call::CallService, subset::ContainsSubset};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_latest_filter_container_cdx(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents([
        "cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-02-24/quay-builder-qemu-rhcos-rhel-8-product.json",
        "cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-02-24/quay-builder-qemu-rhcos-rhel-8-image-index.json",
        "cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-02-24/quay-builder-qemu-rhcos-rhel-8-amd64.json",
        "cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-04-02/quay-v3.14.0-product.json",
        "cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-04-02/quay-builder-qemu-rhcos-rhel8-v3.14.0-4-index.json",
        "cyclonedx/rh/latest_filters/container/quay_builder_qemu_rhcos_rhel8_2025-04-02/quay-builder-qemu-rhcos-rhel8-v3.14.0-4-binary.json",
    ])
        .await?;

    let uri: String = "/api/v2/analysis/component".to_string();
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(200, response.response().status());

    // cpe search
    let uri: String = format!(
        "/api/v2/analysis/component/{}",
        urlencoding::encode("cpe:/a:redhat:quay:3::el8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(
        response.contains_subset(json!({
          "total":2
        })),
        "response was: {response:#?}"
    );

    // cpe latest search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("cpe:/a:redhat:quay:3::el8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(
        response.contains_subset(json!({
          "total":1
        })),
        "response was: {response:#?}"
    );

    // purl partial search
    let uri: String = format!(
        "/api/v2/analysis/component?q={}&ancestors=10",
        urlencoding::encode("pkg:oci/quay-builder-qemu-rhcos-rhel8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(18, response["total"]);

    // purl partial search latest
    let uri: String = format!(
        "/api/v2/analysis/latest/component?q={}&ancestors=10",
        urlencoding::encode("pkg:oci/quay-builder-qemu-rhcos-rhel8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::warn!("{:?}", response.get("total"));
    assert!(
        response.contains_subset(json!({
          "total":7
        })),
        "response was: {response:#?}"
    );

    // purl partial search latest
    let uri: String = format!(
        "/api/v2/analysis/latest/component?q={}&ancestors=10",
        urlencoding::encode("purl:name~quay-builder-qemu-rhcos-rhel8&purl:ty=oci")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::warn!("{:?}", response.get("total"));
    assert!(
        response.contains_subset(json!({
          "total":6
        })),
        "response was: {response:#?}"
    );
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_latest_filter_rpms_cdx(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents([
        "cyclonedx/rh/latest_filters/rpm/NetworkManager/network_manager_2025-02-17/1.46.0-26.el9_4-product.json",
        "cyclonedx/rh/latest_filters/rpm/NetworkManager/network_manager_2025-02-17/1.46.0-26.el9_4-release.json",
        "cyclonedx/rh/latest_filters/rpm/NetworkManager/network_manager_2025-04-08/1.46.0-27.el9_4-product.json",
        "cyclonedx/rh/latest_filters/rpm/NetworkManager/network_manager_2025-04-08/1.46.0-27.el9_4-release.json",
    ])
        .await?;

    let uri: String = "/api/v2/analysis/component".to_string();
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(200, response.response().status());

    // cpe search
    let uri: String = format!(
        "/api/v2/analysis/component/{}",
        urlencoding::encode("cpe:/a:redhat:rhel_eus:9.4::crb")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 2);

    // cpe latest search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("cpe:/a:redhat:rhel_eus:9.4::crb")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 1);

    // purl partial search
    let uri: String = format!(
        "/api/v2/analysis/component?q={}&ancestors=10",
        urlencoding::encode("pkg:rpm/redhat/NetworkManager-libnm")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 30);

    // purl partial latest search
    let uri: String = format!(
        "/api/v2/analysis/latest/component?q={}",
        urlencoding::encode("pkg:rpm/redhat/NetworkManager-libnm")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 15);

    // name exact search
    let uri: String = format!(
        "/api/v2/analysis/component/{}",
        urlencoding::encode("NetworkManager-libnm")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 10);

    // latest name exact search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("NetworkManager-libnm")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 5);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn resolve_rh_variant_latest_filter_middleware_cdx(
    ctx: &TrustifyContext,
) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents([
        "cyclonedx/rh/latest_filters/middleware/maven/quarkus/3.15.4/product-3.15.4.json",
        "cyclonedx/rh/latest_filters/middleware/maven/quarkus/3.15.4/quarkus-camel-bom-3.15.4.json",
        "cyclonedx/rh/latest_filters/middleware/maven/quarkus/3.15.4/quarkus-cxf-bom-3.15.4.json",
        "cyclonedx/rh/latest_filters/middleware/maven/quarkus/3.20/product-3.20.json",
        "cyclonedx/rh/latest_filters/middleware/maven/quarkus/3.20/quarkus-camel-bom-3.20.json",
        "cyclonedx/rh/latest_filters/middleware/maven/quarkus/3.20/quarkus-cxf-bom-3.20.json",
    ])
    .await?;

    let uri: String = "/api/v2/analysis/component".to_string();
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(200, response.response().status());

    // cpe search
    let uri: String = format!(
        "/api/v2/analysis/component/{}",
        urlencoding::encode("cpe:/a:redhat:camel_quarkus:3")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 2);

    // cpe latest search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("cpe:/a:redhat:camel_quarkus:3")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 1);

    // purl partial search
    let uri: String = format!(
        "/api/v2/analysis/component?q={}&ancestors=10",
        urlencoding::encode("pkg:maven/io.vertx/vertx-core@")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 6);

    // purl partial latest search
    let uri: String = format!(
        "/api/v2/analysis/latest/component?q={}",
        urlencoding::encode("pkg:maven/io.vertx/vertx-core@")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 3);
    let items = response["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["product_name"].as_str())
        .collect::<HashSet<_>>();

    assert!(items.contains("quarkus-camel-bom"));
    assert!(items.contains("quarkus-cxf-bom"));

    // name exact search
    let uri: String = format!(
        "/api/v2/analysis/component/{}",
        urlencoding::encode("vertx-core")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 6);

    // latest name exact search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("vertx-core")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 3);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
#[ignore = "Unclear what the expectation is. Three SBOMs share the same name/CPE combination and are thus reduced to a single, latest one."]
async fn test_tc2606(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents([
        "cyclonedx/rh/latest_filters/TC-2606/1F5B983228BA420.json",
        "cyclonedx/rh/latest_filters/TC-2606/401A4500E49D44D.json",
        "cyclonedx/rh/latest_filters/TC-2606/74092FCBFD294FC.json",
        "cyclonedx/rh/latest_filters/TC-2606/80138DC9368C4D3.json",
        "cyclonedx/rh/latest_filters/TC-2606/B67E38F00200413.json",
        "cyclonedx/rh/latest_filters/TC-2606/CE8E7B92C4BD452.json",
    ])
    .await?;

    let uri: String = "/api/v2/analysis/component".to_string();
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(200, response.response().status());

    // latest cpe search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}?descendants=1",
        urlencoding::encode("cpe:/a:redhat:rhel_eus:9.4::appstream")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::info!("{response:#?}");
    assert_eq!(response["total"], 2);

    assert!(response.contains_subset(json!(
            {
      "items": [
        {
          "node_id": "RHEL-9.4.0.Z.EUS",
          "name": "Red Hat Enterprise Linux 9.4 Extended Update Support",
          "version": "RHEL-9.4.0.Z.EUS",
          "published": "2025-06-09 10:18:20+00",
          "document_id": "urn:uuid:501c2eae-1514-3252-a7ce-b6beed26fe62/1",
          "descendants": [
            {
              "node_id": "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src",
              "purl": [
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-s390x-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-aarch64-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-x86_64-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-s390x-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-x86_64-appstream-aus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-ppc64le-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-x86_64-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-ppc64le-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/grafana@9.2.10-23.el9_4?arch=src&repository_id=rhel-9-for-aarch64-appstream-e4s-source-rpms__9_DOT_4"
              ],
              "name": "grafana",
              "version": "9.2.10-23.el9_4",
              "published": "2025-06-09 10:18:20+00",
              "document_id": "urn:uuid:501c2eae-1514-3252-a7ce-b6beed26fe62/1",
              "relationship": "generates"
            }
          ],
        },
        {
          "node_id": "RHEL-9.4.0.Z.EUS",
          "name": "Red Hat Enterprise Linux 9.4 Extended Update Support",
          "version": "RHEL-9.4.0.Z.EUS",
          "published": "2025-06-09 03:29:53+00",
          "document_id": "urn:uuid:b84b0b69-6d39-3b23-86c6-5c258fc730b7/1",
          "descendants": [
            {
              "node_id": "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src",
              "purl": [
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-s390x-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-aarch64-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-x86_64-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-ppc64le-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-s390x-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-ppc64le-appstream-e4s-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-x86_64-appstream-aus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-x86_64-appstream-eus-source-rpms__9_DOT_4",
                "pkg:rpm/redhat/podman@4.9.4-18.el9_4.1?arch=src&repository_id=rhel-9-for-aarch64-appstream-eus-source-rpms__9_DOT_4"
              ],
              "name": "podman",
              "version": "4.9.4-18.el9_4.1",
              "published": "2025-06-09 03:29:53+00",
              "document_id": "urn:uuid:b84b0b69-6d39-3b23-86c6-5c258fc730b7/1",
              "relationship": "generates"
            }
          ],
        }
      ],
      "total": 2
    })));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_tc2677(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents([
        "cyclonedx/rh/latest_filters/TC-2677/54FE396D61CE4E1.json",
        "cyclonedx/rh/latest_filters/TC-2677/A875C1FFA263483.json",
        "cyclonedx/rh/latest_filters/TC-2677/D52B5B9527D4447.json",
    ])
    .await?;

    let uri: String = "/api/v2/analysis/component".to_string();
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(200, response.response().status());

    // latest cpe search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}?descendants=10",
        urlencoding::encode("cpe:/a:redhat:3scale:2.15::el9")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::info!("{response:#?}");
    assert_eq!(response["total"], 1);

    assert!(response.contains_subset(json!(
    {
  "items": [
    {
      "node_id": "3SCALE-2.15-RHEL-9",
      "cpe": [
        "cpe:/a:redhat:3scale:2.15:*:el9:*"
      ],
      "name": "3scale API Management 2.15 on RHEL 9",
      "version": "3SCALE-2.15-RHEL-9",
      "published": "2025-05-27 20:11:20+00",
      "document_id": "urn:uuid:57334e7f-c34c-3e4e-a565-d83d45fd4399/1",
      "product_name": "3scale API Management 2.15 on RHEL 9",
      "product_version": "3SCALE-2.15-RHEL-9",
      "descendants": [
        {
          "node_id": "pkg:oci/authorino-rhel9@sha256%3Aa473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87",
          "purl": [
            "pkg:oci/authorino-rhel9@sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87?repository_url=registry.access.redhat.com/3scale-tech-preview/authorino-rhel9&tag=3scale2.15.0",
            "pkg:oci/authorino-rhel9@sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87?repository_url=registry.access.redhat.com/3scale-tech-preview/authorino-rhel9&tag=1.1.3",
            "pkg:oci/authorino-rhel9@sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87?repository_url=registry.access.redhat.com/3scale-tech-preview/authorino-rhel9&tag=1.1.3-1",
            "pkg:oci/authorino-rhel9@sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87",
            "pkg:oci/authorino-rhel9@sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87?repository_url=registry.access.redhat.com/3scale-tech-preview/authorino-rhel9&tag=3scale2.15"
          ],
          "name": "3scale-tech-preview/authorino-rhel9",
          "version": "sha256:a473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87",
          "published": "2025-05-27 20:11:20+00",
          "document_id": "urn:uuid:57334e7f-c34c-3e4e-a565-d83d45fd4399/1",
          "product_name": "3scale API Management 2.15 on RHEL 9",
          "product_version": "3SCALE-2.15-RHEL-9",
          "relationship": "generates",
          "descendants": [
            {
              "node_id": "3SCALE-2.15-RHEL-9:pkg:oci/authorino-rhel9@sha256%3Aa473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87",
              "name": "pkg:oci/authorino-rhel9@sha256%3Aa473dae20e71e3e813ac30ba978f2ab3c5e19d7d39b501ae9103dca892107c87",
              "version": "",
              "published": "2025-05-27 20:11:20+00",
              "document_id": "urn:uuid:57334e7f-c34c-3e4e-a565-d83d45fd4399/1",
              "product_name": "3scale API Management 2.15 on RHEL 9",
              "product_version": "3SCALE-2.15-RHEL-9",
              "relationship": "package",
            }
          ]
        }
      ]
    }
  ],
  "total": 1
})));
    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn test_tc2717(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_documents([
        "cyclonedx/rh/latest_filters/middleware/maven/quarkus/3.15.4/quarkus-camel-bom-3.15.4.json",
        "cyclonedx/rh/latest_filters/middleware/maven/quarkus/3.15.4/quarkus-cxf-bom-3.15.4.json",
    ])
    .await?;

    let uri: String = "/api/v2/analysis/component".to_string();
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response = app.call_service(request).await;
    assert_eq!(200, response.response().status());

    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("pkg:maven/io.vertx/vertx-core")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(response["total"], 3, "response was: {response:#?}");

    Ok(())
}
