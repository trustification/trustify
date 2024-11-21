use crate::license::model::{
    LicenseDetailsPurlSummary, LicenseSummary, SpdxLicenseDetails, SpdxLicenseSummary,
};
use crate::test::caller;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_common::model::PaginatedResults;
use trustify_test_context::{call::CallService, TrustifyContext};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_spdx_licenses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = "/api/v1/license/spdx/license";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<SpdxLicenseSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(673, response.total);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_spdx_license(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = "/api/v1/license/spdx/license/GLWTPL";
    let request = TestRequest::get().uri(uri).to_request();
    let response: SpdxLicenseDetails = app.call_and_read_body_json(request).await;
    assert_eq!(response.summary.id, "GLWTPL");

    let uri = "/api/v1/license/spdx/license/GlwtPL";
    let request = TestRequest::get().uri(uri).to_request();
    let response: SpdxLicenseDetails = app.call_and_read_body_json(request).await;
    assert_eq!(response.summary.id, "GLWTPL");

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_licenses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = "/api/v1/license?q=LGPL";

    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseSummary> = app.call_and_read_body_json(request).await;
    assert_eq!(0, response.total);

    ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;

    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseSummary> = app.call_and_read_body_json(request).await;
    assert_eq!(25, response.total);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_license_purls(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.ingest_document("ubi9-9.2-755.1697625012.json").await?;

    let uri = "/api/v1/license?q=LGPL&limit=0";
    let request = TestRequest::get().uri(uri).to_request();
    let response: PaginatedResults<LicenseSummary> = app.call_and_read_body_json(request).await;

    let lgpl = response.items.iter().find(|e| e.license == "LGPLV2+");

    assert!(lgpl.is_some());

    let lgpl = lgpl.unwrap();

    let uri = format!("/api/v1/license/{}/purl", lgpl.id.urn());

    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<LicenseDetailsPurlSummary> =
        app.call_and_read_body_json(request).await;

    assert_eq!(29, response.total);

    let uri = format!("/api/v1/license/{}/purl?offset=25", lgpl.id.urn());

    let request = TestRequest::get().uri(&uri).to_request();
    let response: PaginatedResults<LicenseDetailsPurlSummary> =
        app.call_and_read_body_json(request).await;

    assert_eq!(4, response.items.len());
    assert_eq!(29, response.total);

    Ok(())
}
