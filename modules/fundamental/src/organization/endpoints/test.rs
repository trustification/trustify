use crate::test::caller;
use actix_web::cookie::time::OffsetDateTime;
use actix_web::test::TestRequest;
use jsonpath_rust::JsonPathQuery;
use serde_json::{json, Value};
use test_context::test_context;
use test_log::test;
use trustify_common::db::query::Query;
use trustify_common::db::Transactional;
use trustify_common::hashing::Digests;
use trustify_common::model::Paginated;
use trustify_module_ingestor::graph::advisory::AdvisoryInformation;
use trustify_test_context::{call::CallService, TrustifyContext};

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn all_organizations(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    ctx.graph
        .ingest_advisory(
            "CAPT-1",
            ("source", "http://captpickles.com/"),
            &Digests::digest("CAPT-1"),
            AdvisoryInformation {
                id: "CAPT-1".to_string(),
                title: Some("CAPT-1".to_string()),
                version: None,
                issuer: Some("Capt Pickles Industrial Conglomerate".to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            (),
        )
        .await?;

    ctx.graph
        .ingest_advisory(
            "EMPORIUM-1",
            ("source", "http://captpickles.com/"),
            &Digests::digest("EMPORIUM-1"),
            AdvisoryInformation {
                id: "EMPORIUM-1".to_string(),
                title: Some("EMPORIUM-1".to_string()),
                version: None,
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

    let response: Value = app.call_and_read_body_json(request).await;

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

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn one_organization(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let app = caller(ctx).await?;

    let advisory = ctx
        .graph
        .ingest_advisory(
            "CAPT-1",
            ("source", "http://captpickles.com/"),
            &Digests::digest("CAPT-1"),
            AdvisoryInformation {
                id: "CAPT-1".to_string(),
                title: Some("Pickles can experience a buffer overflow".to_string()),
                version: None,
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

    let service = crate::organization::service::OrganizationService::new(ctx.db.clone());

    let orgs = service
        .fetch_organizations(Query::default(), Paginated::default(), ())
        .await?;

    assert_eq!(1, orgs.total);

    let first_org = &orgs.items[0];
    let org_id = first_org.head.id;

    let uri = format!("/api/v1/organization/{}", org_id);

    let request = TestRequest::get().uri(&uri).to_request();

    let response: Value = app.call_and_read_body_json(request).await;

    let name = response.clone().path("$.name").unwrap();

    assert_eq!(name, json!(["Capt Pickles Industrial Conglomerate"]));

    Ok(())
}
