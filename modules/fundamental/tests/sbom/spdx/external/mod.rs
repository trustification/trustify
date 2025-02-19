#![allow(clippy::expect_used)]
mod rh;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use test_context::test_context;
use test_log::test;
use trustify_entity::sbom_external_node;
use trustify_test_context::TrustifyContext;

/// A simple test for ingesting two SPDX SBOMs with external references
#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn simple_ext_1(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple-ext-a.json", "spdx/simple-ext-b.json"])
        .await?;

    let results = sbom_external_node::Entity::find()
        .filter(sbom_external_node::Column::NodeId.eq("DocumentRef-ext-b:SPDXRef-A"))
        .all(&ctx.db)
        .await?;

    assert_eq!(
        results[0].external_type,
        sbom_external_node::ExternalType::SPDX
    );
    assert_eq!(results[0].external_doc_ref, "uri:simple-ext-b".to_string());
    assert_eq!(results[0].external_node_ref, "SPDXRef-A".to_string());
    assert_eq!(
        results[0].discriminator_value,
        Some("60bf029859f5927eafba8dd02c73b9075e40a2089c92da9c1062b01dcd2b300c".to_string())
    );

    Ok(())
}
