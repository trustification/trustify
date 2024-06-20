use std::sync::Arc;
use test_context::test_context;
use test_log::test;
use trustify_common::db::query::Query;
use trustify_common::db::test::TrustifyContext;
use trustify_common::db::Transactional;
use trustify_common::hashing::Digests;
use trustify_common::model::Paginated;
use trustify_module_ingestor::graph::product::ProductInformation;
use trustify_module_ingestor::graph::Graph;

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn all_products(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));

    let pr = graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
            },
            (),
        )
        .await?;

    let ver = pr.ingest_product_version("1.0.0".to_string(), ()).await?;

    let service = crate::product::service::ProductService::new(db);

    let prods = service
        .fetch_products(Query::default(), Paginated::default(), ())
        .await?;

    assert_eq!(1, prods.total);
    assert_eq!(1, prods.items.len());

    let sbom = graph
        .ingest_sbom(
            ("source", "http://redhat.com/test.json"),
            &Digests::digest("RHSA-1"),
            "a",
            (),
            Transactional::None,
        )
        .await?;

    let prv = ver
        .link_to_sbom(sbom.sbom.sbom_id, Transactional::None)
        .await?;

    let ver_sbom = prv
        .get_sbom(Transactional::None)
        .await?
        .expect("No sbom found");
    assert_eq!(ver_sbom.sbom.sbom_id, sbom.sbom.sbom_id);

    Ok(())
}

#[test_context(TrustifyContext, skip_teardown)]
#[test(actix_web::test)]
async fn link_sbom_to_product(ctx: TrustifyContext) -> Result<(), anyhow::Error> {
    let db = ctx.db;
    let graph = Arc::new(Graph::new(db.clone()));

    let pr = graph
        .ingest_product(
            "Trusted Profile Analyzer",
            ProductInformation {
                vendor: Some("Red Hat".to_string()),
            },
            (),
        )
        .await?;

    let prv = pr.ingest_product_version("1.0.0".to_string(), ()).await?;

    let sbom = graph
        .ingest_sbom(
            ("source", "http://redhat.com/test.json"),
            &Digests::digest("RHSA-1"),
            "a",
            (),
            Transactional::None,
        )
        .await?;

    let prv = sbom.link_to_product(prv, Transactional::None).await?;

    assert_eq!(
        sbom.sbom.sbom_id,
        prv.product_version.sbom_id.expect("no sbom")
    );

    let product = sbom
        .get_product(Transactional::None)
        .await?
        .expect("No product");

    assert_eq!("Trusted Profile Analyzer", product.product.product.name);
    assert_eq!("1.0.0", product.product_version.version);
    assert_eq!(
        sbom.sbom.sbom_id,
        product.product_version.sbom_id.expect("No sbom")
    );

    let org = product
        .product
        .get_vendor(Transactional::None)
        .await?
        .expect("no organization");
    assert_eq!("Red Hat", org.organization.name);

    Ok(())
}
