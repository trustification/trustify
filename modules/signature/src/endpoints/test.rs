#![cfg(test)]

use super::*;
use actix_http::{Request, body::BoxBody};
use actix_web::{
    App,
    dev::{Service, ServiceResponse},
    http::StatusCode,
    test as actix,
};
use test_context::test_context;
use test_log::test;
use trustify_entity::signature_type::SignatureType;
use trustify_test_context::{TrustifyContext, app::TestApp};
use utoipa_actix_web::AppExt;

fn mock_data(payload: impl Into<Vec<u8>>) -> TrustAnchorData {
    TrustAnchorData {
        disabled: false,
        description: "".to_string(),
        r#type: SignatureType::Pgp,
        payload: payload.into(),
    }
}

fn mock_trust_anchor(payload: impl Into<Vec<u8>>) -> TrustAnchor {
    TrustAnchor {
        id: "foo".into(),
        data: mock_data(payload),
    }
}

async fn app(
    ctx: &TrustifyContext,
) -> impl Service<Request, Response = ServiceResponse<BoxBody>, Error = actix_web::Error> {
    let db = ctx.db.clone();
    actix::init_service(
        App::new()
            .into_utoipa_app()
            .add_test_authorizer()
            .service(utoipa_actix_web::scope("/api").configure(|svc| super::configure(svc, db)))
            .into_app(),
    )
    .await
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn default(ctx: TrustifyContext) {
    let app = app(&ctx).await;

    // create one

    let req = actix::TestRequest::post()
        .uri("/api/v2/trust-anchor/foo")
        .set_json(mock_data("bar"))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // now list all

    let req = actix::TestRequest::get()
        .uri("/api/v2/trust-anchor")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: PaginatedResults<TrustAnchor> = actix::read_body_json(resp).await;
    assert_eq!(
        result,
        PaginatedResults {
            total: 1,
            items: vec![TrustAnchor {
                id: "foo".into(),
                data: mock_data("bar")
            }]
        }
    );

    // update it

    let req = actix::TestRequest::put()
        .uri("/api/v2/trust-anchor/foo")
        .set_json(mock_data("baz"))
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get it

    let req = actix::TestRequest::get()
        .uri("/api/v2/trust-anchor/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: TrustAnchor = actix::read_body_json(resp).await;
    assert_eq!(result, mock_trust_anchor("baz"));

    // delete it

    let req = actix::TestRequest::delete()
        .uri("/api/v2/trust-anchor/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get none

    let req = actix::TestRequest::get()
        .uri("/api/v2/trust-anchor/foo")
        .to_request();

    let resp = actix::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
