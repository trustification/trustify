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
    assert!(response.contains_subset(json!({
      "total":2
    })));

    // cpe latest search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("cpe:/a:redhat:quay:3::el8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":1
    })));

    // purl partial search
    let uri: String = format!(
        "/api/v2/analysis/component?q={}&ancestors=10",
        urlencoding::encode("pkg:oci/quay-builder-qemu-rhcos-rhel8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert_eq!(64, response["total"]);

    // purl partial search latest
    let uri: String = format!(
        "/api/v2/analysis/latest/component?q={}&ancestors=10",
        urlencoding::encode("pkg:oci/quay-builder-qemu-rhcos-rhel8")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::warn!("{:?}", response.get("total"));
    assert!(response.contains_subset(json!({
      "total":16
    })));

    // purl partial search latest
    let uri: String = format!(
        "/api/v2/analysis/latest/component?q={}&ancestors=10",
        urlencoding::encode("purl:name~quay-builder-qemu-rhcos-rhel8&purl:ty=oci")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    log::warn!("{:?}", response.get("total"));
    assert!(response.contains_subset(json!({
      "total":19
    })));
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
    assert!(response.contains_subset(json!({
      "total":2
    })));

    // cpe latest search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("cpe:/a:redhat:rhel_eus:9.4::crb")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":1
    })));

    // purl partial search
    let uri: String = format!(
        "/api/v2/analysis/component?q={}&ancestors=10",
        urlencoding::encode("pkg:rpm/redhat/NetworkManager-libnm")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":90
    })));

    // purl partial latest search
    let uri: String = format!(
        "/api/v2/analysis/latest/component?q={}",
        urlencoding::encode("pkg:rpm/redhat/NetworkManager-libnm")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":45
    })));

    // name exact search
    let uri: String = format!(
        "/api/v2/analysis/component/{}",
        urlencoding::encode("NetworkManager-libnm")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":50
    })));

    // latest name exact search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("NetworkManager-libnm")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":15
    })));

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
    assert!(response.contains_subset(json!({
      "total":2
    })));

    // cpe latest search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("cpe:/a:redhat:camel_quarkus:3")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":1
    })));

    // purl partial search
    let uri: String = format!(
        "/api/v2/analysis/component?q={}&ancestors=10",
        urlencoding::encode("pkg:maven/io.vertx/vertx-core@")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":30
    })));

    // purl partial latest search
    let uri: String = format!(
        "/api/v2/analysis/latest/component?q={}",
        urlencoding::encode("pkg:maven/io.vertx/vertx-core@")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":8
    })));

    // name exact search
    let uri: String = format!(
        "/api/v2/analysis/component/{}",
        urlencoding::encode("vertx-core")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":42
    })));

    // latest name exact search
    let uri: String = format!(
        "/api/v2/analysis/latest/component/{}",
        urlencoding::encode("vertx-core")
    );
    let request: Request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    assert!(response.contains_subset(json!({
      "total":8
    })));

    Ok(())
}
