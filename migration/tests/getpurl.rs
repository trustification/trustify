use migration::sea_orm::{EntityTrait, Statement};
use migration::ConnectionTrait;
use std::str::FromStr;
use test_context::test_context;
use test_log::test;
use trustify_common::db::Database;
use trustify_common::purl::Purl;
use trustify_test_context::TrustifyContext;

async fn get_purl(
    db: &Database,
    qualified_purl_id: String,
) -> Result<Option<String>, anyhow::Error> {
    let result = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            format!(
                r#"
                    SELECT * FROM get_purl('{qualified_purl_id}');
                "#,
            ),
        ))
        .await?;

    if let Some(result) = result {
        Ok(result.try_get_by_index(0)?)
    } else {
        Ok(None)
    }
}

#[test_context(TrustifyContext)]
#[test(tokio::test)]
async fn test_getpurl(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    ctx.ingest_documents(["spdx/simple.json"]).await?;

    let sbom_package_purl_refs = trustify_entity::sbom_package_purl_ref::Entity::find()
        .all(&ctx.db)
        .await?;

    for sbom_package_purl_ref in sbom_package_purl_refs {
        let sbom_node = trustify_entity::sbom_node::Entity::find_by_id((
            sbom_package_purl_ref.sbom_id,
            sbom_package_purl_ref.node_id,
        ))
        .one(&ctx.db)
        .await?;

        let sbom_node_name = match sbom_node {
            Some(node) => node.name,
            None => return Err(anyhow::anyhow!("expected sbom node name in test")),
        };

        match get_purl(&ctx.db, sbom_package_purl_ref.qualified_purl_id.to_string()).await {
            Ok(Some(purl)) => {
                let parse_purl: Purl = Purl::from_str(purl.as_str())?;
                assert!(parse_purl.name == sbom_node_name);
            }
            Ok(None) => panic!("getpurl() test should match"),
            Err(e) => panic!("error testing getpurl() pg function. {}", e),
        }
    }

    Ok(())
}
