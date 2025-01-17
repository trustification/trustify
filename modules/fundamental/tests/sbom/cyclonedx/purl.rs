use test_context::test_context;
use test_log::test;
use trustify_module_fundamental::{
    purl::model::summary::purl::PurlSummary, sbom::service::SbomService,
};
use trustify_test_context::TrustifyContext;

fn to_string(purl: &PurlSummary) -> String {
    purl.head.purl.to_string()
}

fn to_strings(purls: &[PurlSummary]) -> Vec<String> {
    purls.iter().map(to_string).collect()
}

/// test with multiple purls
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_ref(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = SbomService::new(ctx.db.clone());

    let result = ctx
        .ingest_document("cyclonedx/openssl-3.0.7-18.el9_2.cdx_1.6_aliases.sbom.json")
        .await?;

    let sbom_id = result.id.try_as_uid().expect("Must be a UID");

    // fetch describes

    let packages = service
        .describes_packages(sbom_id, Default::default(), &ctx.db)
        .await?;

    assert_eq!(packages.total, 1);
    assert_eq!(packages.items.len(), 1);

    let package = &packages.items[0];
    assert_eq!(
        to_strings(&package.purl),
        // must find one, but only one purl. despite having two with the same value.
        vec![
            "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src",
            "pkg:rpm/redhat/openssl@3.0.7-18.el9_2?arch=src&foo=bar"
        ]
    );

    // done

    Ok(())
}
