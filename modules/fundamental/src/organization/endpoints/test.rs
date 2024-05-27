use crate::organization::endpoints::configure;
use actix_web::cookie::time::OffsetDateTime;
use actix_web::test::TestRequest;
use actix_web::App;
use jsonpath_rust::JsonPathQuery;
use serde_json::{json, Value};
use test_context::test_context;
use test_log::test;
use trustify_common::db::query::Query;
use trustify_common::db::test::TrustifyContext;
use trustify_common::db::Transactional;
use trustify_common::model::Paginated;
use trustify_module_ingestor::graph::advisory::AdvisoryInformation;
use trustify_module_ingestor::graph::Graph;

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn all_organizations(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());

    let app = actix_web::test::init_service(
        App::new().configure(|config| configure(config, db.clone(), None)),
    )
    .await;

    graph
        .ingest_advisory(
            "CAPT-1",
            "http://captpickles.com/",
            "8675309",
            AdvisoryInformation {
                title: Some("CAPT-1".to_string()),
                issuer: Some("Capt Pickles Industrial Conglomerate".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    graph
        .ingest_advisory(
            "EMPORIUM-1",
            "http://captpickles.com/",
            "8675319",
            AdvisoryInformation {
                title: Some("EMPORIUM-1".to_string()),
                issuer: Some("Capt Pickles Boutique Emporium".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    let uri = "/api/v1/organization?sort=name";

    let request = TestRequest::get().uri(uri).to_request();

    let response: Value = actix_web::test::call_and_read_body_json(&app, request).await;

    let names = response.path("$.items[*].name").unwrap();

    assert_eq!(
        names,
        json!([
            "Capt Pickles Boutique Emporium",
            "Capt Pickles Industrial Conglomerate",
        ])
    );

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn one_organization(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Graph::new(db.clone());

    let app = actix_web::test::init_service(
        App::new().configure(|config| configure(config, db.clone(), None)),
    )
    .await;

    let advisory = graph
        .ingest_advisory(
            "CAPT-1",
            "http://captpickles.com/",
            "8675309",
            AdvisoryInformation {
                title: Some("Pickles can experience a buffer overflow".to_string()),
                issuer: Some("Capt Pickles Industrial Conglomerate".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    advisory
        .link_to_vulnerability("CVE-123", None, Transactional::None)
        .await?;

    let service = crate::organization::service::OrganizationService::new(db);

    let orgs = service
        .fetch_organizations(Query::default(), Paginated::default(), ())
        .await?;

    assert_eq!(1, orgs.total);

    let first_org = &orgs.items[0];
    let org_id = first_org.head.id;

    let uri = format!("/api/v1/organization/{}", org_id);

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = actix_web::test::call_and_read_body_json(&app, request).await;

    let name = response.clone().path("$.name").unwrap();

    assert_eq!(name, json!(["Capt Pickles Industrial Conglomerate"]));

    Ok(())
}
