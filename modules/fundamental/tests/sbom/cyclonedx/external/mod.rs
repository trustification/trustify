use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn prod_comp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("cyclonedx/simple_cpe.json").await?;

    let service = SbomService::new(ctx.db.clone());

    let packages = service
        .describes_packages(
            result.id.try_as_uid().expect("Must be a UID"),
            Default::default(),
            &ctx.db,
        )
        .await?;

    assert_eq!(packages.total, 1);
    assert_eq!(packages.items.len(), 1);

    let package = &packages.items[0];
    assert_eq!(package.cpe, vec!["cpe:/a:redhat:simple:0.0:*:*:*"]);

    Ok(())
}
