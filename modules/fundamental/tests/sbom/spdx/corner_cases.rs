#![allow(clippy::expect_used)]

use anyhow::bail;
use strum::VariantArray;
use test_context::test_context;
use test_log::test;
use trustify_common::{id::Id, purl::Purl};
use trustify_entity::relationship::Relationship;
use trustify_module_fundamental::sbom::model::SbomPackageReference;
use trustify_module_fundamental::sbom::service::SbomService;
use trustify_test_context::TrustifyContext;

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn infinite_loop(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let service = SbomService::new(ctx.db.clone());

    let result = ctx.ingest_document("spdx/loop.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };

    let sbom = ctx
        .graph
        .get_sbom_by_id(id, ())
        .await?
        .expect("must be found");

    let packages = service
        .fetch_sbom_packages(id, Default::default(), Default::default(), ())
        .await?;

    assert_eq!(packages.total, 3);

    let purl = Purl::try_from("pkg:cargo/A@0.0.0").expect("must parse");
    let packages = sbom
        .related_packages_transitively(Relationship::VARIANTS, &purl, ())
        .await?;

    assert_eq!(packages.len(), 3);

    let packages = service
        .describes_packages(id, Default::default(), ())
        .await?;

    assert_eq!(packages.total, 1);

    let packages = service
        .related_packages(id, None, SbomPackageReference::All, ())
        .await?;

    log::info!("Packages: {packages:#?}");

    assert_eq!(packages.len(), 3);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn double_ref(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("spdx/double-ref.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };
    let sbom = ctx
        .graph
        .get_sbom_by_id(id, ())
        .await?
        .expect("must be found");

    let service = SbomService::new(ctx.db.clone());
    let packages = service
        .fetch_sbom_packages(id, Default::default(), Default::default(), ())
        .await?;

    assert_eq!(packages.total, 3);

    let purl = Purl::try_from("pkg:cargo/A@0.0.0").expect("must parse");
    let packages = sbom
        .related_packages_transitively(Relationship::VARIANTS, &purl, ())
        .await?;

    assert_eq!(packages.len(), 3);

    let packages = service
        .related_packages(id, None, SbomPackageReference::All, ())
        .await?;

    log::info!("Packages: {packages:#?}");

    assert_eq!(packages.len(), 3);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn self_ref(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("spdx/self.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };
    let sbom = ctx
        .graph
        .get_sbom_by_id(id, ())
        .await?
        .expect("must be found");

    let service = SbomService::new(ctx.db.clone());
    let packages = service
        .fetch_sbom_packages(id, Default::default(), Default::default(), ())
        .await?;

    assert_eq!(packages.total, 0);

    let purl = Purl::try_from("pkg:cargo/A@0.0.0").expect("must parse");
    let packages = sbom
        .related_packages_transitively(Relationship::VARIANTS, &purl, ())
        .await?;

    assert_eq!(packages.len(), 0);

    let packages = service
        .related_packages(id, None, SbomPackageReference::All, ())
        .await?;

    log::info!("Packages: {packages:#?}");

    assert_eq!(packages.len(), 0);

    Ok(())
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn self_ref_package(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    let result = ctx.ingest_document("spdx/self-package.json").await?;

    let Id::Uuid(id) = result.id else {
        bail!("must be an id")
    };
    let sbom = ctx
        .graph
        .get_sbom_by_id(id, ())
        .await?
        .expect("must be found");

    let service = SbomService::new(ctx.db.clone());
    let packages = service
        .fetch_sbom_packages(id, Default::default(), Default::default(), ())
        .await?;

    assert_eq!(packages.total, 1);

    let purl = Purl::try_from("pkg:cargo/A@0.0.0").expect("must parse");
    let packages = sbom
        .related_packages_transitively(Relationship::VARIANTS, &purl, ())
        .await?;

    assert_eq!(packages.len(), 1);

    let packages = service
        .related_packages(id, None, SbomPackageReference::All, ())
        .await?;

    log::info!("Packages: {packages:#?}");

    assert_eq!(packages.len(), 1);

    let packages = service
        .related_packages(id, None, SbomPackageReference::Package("SPDXRef-A"), ())
        .await?;

    log::info!("Packages: {packages:#?}");

    assert_eq!(packages.len(), 1);

    Ok(())
}
