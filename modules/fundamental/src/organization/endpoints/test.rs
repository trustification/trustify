use crate::test::caller;
use actix_web::cookie::time::OffsetDateTime;
use actix_web::test::TestRequest;
use jsonpath_rust::JsonPath;
use serde_json::{Value, json};
use test_context::test_context;
use test_log::test;
use trustify_common::db::query::Query;
use trustify_common::hashing::Digests;
use trustify_common::model::Paginated;
use trustify_module_ingestor::graph::{
    Outcome,
    advisory::{AdvisoryContext, AdvisoryInformation},
};
use trustify_test_context::{TrustifyContext, call::CallService};

async fn ingest_advisory<'ctx>(
    ctx: &'ctx TrustifyContext,
    id: &str,
    issuer: &str,
) -> Result<Outcome<AdvisoryContext<'ctx>>, anyhow::Error> {
    let advisory = ctx
        .graph
        .ingest_advisory(
            id,
            ("source", "http://captpickles.com/"),
            &Digests::digest(id),
            AdvisoryInformation {
                id: id.to_string(),
                title: Some(id.to_string()),
                version: None,
                issuer: Some(issuer.to_string()),
                published: Some(OffsetDateTime::now_utc()),
                modified: None,
                withdrawn: None,
            },
            &ctx.db,
        )
        .await?;

    Ok(advisory)
}

#[test_context(TrustifyContext)]
#[test(actix_web::test)]
async fn organization_tests(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    // test all organizations

    let db = &ctx.db;
    let app = caller(ctx).await?;

    ingest_advisory(ctx, "CAPT-1", "Capt Pickles Industrial Conglomerate").await?;
    ingest_advisory(ctx, "EMPORIUM-1", "Capt Pickles Boutique Emporium").await?;

    let uri = "/api/v2/organization?sort=name";
    let request = TestRequest::get().uri(uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    let names = response.query("$.items[*].name").unwrap();

    assert_eq!(
        names,
        [
            &json!("Capt Pickles Boutique Emporium"),
            &json!("Capt Pickles Industrial Conglomerate")
        ]
    );

    db.refresh().await?;

    // test one organization

    let advisory = ingest_advisory(ctx, "CAPT-9", "Foo Bar").await?;
    advisory
        .link_to_vulnerability("CVE-123", None, &ctx.db)
        .await?;

    let service = crate::organization::service::OrganizationService::new();

    let orgs = service
        .fetch_organizations(Query::default(), Paginated::default(), &ctx.db)
        .await?;

    assert_eq!(1, orgs.total);

    let first_org = &orgs.items[0];
    let org_id = first_org.head.id;

    let uri = format!("/api/v2/organization/{}", org_id);
    let request = TestRequest::get().uri(&uri).to_request();
    let response: Value = app.call_and_read_body_json(request).await;
    let name = response.query("$.name")?;

    assert_eq!(name, [&json!("Foo Bar")]);

    Ok(())
}
