#![cfg(test)]

use super::*;
use crate::server::importer::model::ImportConfiguration;
use crate::Graph;
use actix_web::http::StatusCode;
use actix_web::{http::header::ContentType, test, App};
use serde_json::json;

#[actix_web::test]
async fn test_default() {
    let grap = Graph::for_test("test_default").await.unwrap();
    let app = test::init_service(App::new().configure(|svc| super::configure(svc, grap))).await;

    // create one

    let req = test::TestRequest::post()
        .uri("/api/v1/importer/foo")
        .set_json(json!({"foo":"bar"}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // now list all

    let req = test::TestRequest::get()
        .uri("/api/v1/importer")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: Vec<ImportConfiguration> = test::read_body_json(resp).await;
    assert_eq!(
        result,
        vec![ImportConfiguration {
            name: "foo".into(),
            configuration: json!({"foo":"bar"})
        }]
    );

    // update it

    let req = test::TestRequest::put()
        .uri("/api/v1/importer/foo")
        .set_json(json!({"foo":"baz"}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get it

    let req = test::TestRequest::get()
        .uri("/api/v1/importer/foo")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result: ImportConfiguration = test::read_body_json(resp).await;
    assert_eq!(
        result,
        ImportConfiguration {
            name: "foo".into(),
            configuration: json!({"foo":"baz"})
        }
    );

    // delete it

    let req = test::TestRequest::delete()
        .uri("/api/v1/importer/foo")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // get none

    let req = test::TestRequest::get()
        .uri("/api/v1/importer/foo")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
