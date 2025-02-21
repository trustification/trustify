use crate::license::model::{SpdxLicenseDetails, SpdxLicenseSummary};
use crate::test::caller;
use actix_web::test::TestRequest;
use test_context::test_context;
use test_log::test;
use trustify_common::model::PaginatedResults;
use trustify_test_context::{TrustifyContext, call::CallService};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn list_spdx_licenses(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = "/api/v2/license/spdx/license";

    let request = TestRequest::get().uri(uri).to_request();

    let response: PaginatedResults<SpdxLicenseSummary> = app.call_and_read_body_json(request).await;

    assert_eq!(687, response.total);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn get_spdx_license(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let uri = "/api/v2/license/spdx/license/GLWTPL";
    let request = TestRequest::get().uri(uri).to_request();
    let response: SpdxLicenseDetails = app.call_and_read_body_json(request).await;
    assert_eq!(response.summary.id, "GLWTPL");

    let uri = "/api/v2/license/spdx/license/GlwtPL";
    let request = TestRequest::get().uri(uri).to_request();
    let response: SpdxLicenseDetails = app.call_and_read_body_json(request).await;
    assert_eq!(response.summary.id, "GLWTPL");

    Ok(())
}
