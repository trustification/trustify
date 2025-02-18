#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn prod_comp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let mut result = ctx
        .ingest_documents([
            "cyclonedx/product_component/example_product_quarkus.json",
            "cyclonedx/product_component/example_component_quarkus.json",
        ])
        .await?;

    let _prod = result
        .pop()
        .unwrap()
        .id
        .try_as_uid()
        .expect("must have a uid");
    let _comp = result
        .pop()
        .unwrap()
        .id
        .try_as_uid()
        .expect("must have a uid");

    let _service = SbomService::new(ctx.db.clone());

    Ok(())
}
