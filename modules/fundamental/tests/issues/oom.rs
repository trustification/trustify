//! Testing the OOM issue with some large SBOMs

use std::str::FromStr;
use test_context::test_context;
use trustify_common::id::Id;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::{TrustifyContext, flame::setup_global_subscriber};

#[test_context(TrustifyContext, skip_teardown)]
#[tokio::test]
#[ignore = "Only works with a pre-existing database and a specific dump"]
async fn fetch(ctx: TrustifyContext) -> anyhow::Result<()> {
    let _guard = setup_global_subscriber();

    // this requires an imported dataset

    let service = SbomService::new(ctx.db.clone());
    // update this digest to point to a "large SBOM"
    let id =
        Id::from_str("sha256:f293eb898192085804419f9dd40a738f20d67dd81846e88c6720f692ec5f3081")?;
    let statuses: Vec<String> = vec!["affected".to_string()];

    let result = service.fetch_sbom_details(id, statuses, &ctx.db).await?;

    assert!(
        result.is_some(),
        "We must find this in the dataset. Otherwise, it's probably a wrong dataset, or you didn't use an existing DB dump"
    );

    Ok(())
}
