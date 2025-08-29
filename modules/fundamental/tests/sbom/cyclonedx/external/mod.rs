#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use test_context::test_context;
use test_log::test;
use trustify_entity::sbom_external_node;
use trustify_module_ingestor::model::IngestResult;
use trustify_test_context::TrustifyContext;
use uuid::Uuid;

mod rh;

/// Take the result vec and turn it into an array of UIDs.
///
/// **NOTE:** This will panic if either the vec does not contain enough results, or the result's ID
/// does not have a UID.
fn split_uid<const N: usize>(result: Vec<IngestResult>) -> [Uuid; N] {
    std::array::from_fn(|i| result[i].id.try_as_uid().expect("must have a uid"))
}

/// A simple test for ingesting two CDX SBOMs with external references
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_ext_1(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["cyclonedx/simple-ext-a.json", "cyclonedx/simple-ext-b.json"])
        .await?;

    let results = sbom_external_node::Entity::find()
        .filter(
            sbom_external_node::Column::NodeId
                .eq("urn:cdx:a4f16b62-fea9-42c1-8365-d72d3cef37d1/2#a"),
        )
        .all(&ctx.db)
        .await?;

    assert_eq!(
        results[0].external_type,
        sbom_external_node::ExternalType::CycloneDx
    );
    assert_eq!(
        results[0].external_doc_ref,
        "a4f16b62-fea9-42c1-8365-d72d3cef37d1".to_string()
    );
    assert_eq!(results[0].external_node_ref, "a".to_string());
    assert_eq!(results[0].discriminator_value, Some("2".to_string()));

    Ok(())
}
