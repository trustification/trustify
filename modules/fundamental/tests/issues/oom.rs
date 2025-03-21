//! Testing the OOM issue with some large SBOMs

use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use tracing::instrument;
use trustify_common::id::Id;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext, skip_teardown)]
#[test(tokio::test)]
#[instrument]
#[ignore = "Only works with a pre-existing database and a specific dump"]
async fn fetch(ctx: TrustifyContext) -> anyhow::Result<()> {
    // this requires an imported dataset

    let service = SbomService::new(ctx.db.clone());
    let id =
        Id::from_str("sha256:e2fba0cf6d3c79cf6994b31e172b5f11ee5e3f9dd7629ac0f1a5ae5cae2d6135")?;
    let statuses: Vec<String> = vec!["affected".to_string()];

    let result = service.fetch_sbom_details(id, statuses, &ctx.db).await?;

    assert!(
        result.is_some(),
        "We must find this in the dataset. Otherwise, it's probably a wrong dataset, or you didn't use an existing DB dump"
    );

    Ok(())
}
