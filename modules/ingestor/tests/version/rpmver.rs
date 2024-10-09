use sea_orm::{ConnectionTrait, Statement};
use test_context::test_context;
use test_log::test;
use trustify_common::db::Database;
use trustify_test_context::TrustifyContext;

#[path = "common.rs"]
mod common;

async fn rpmver_cmp(db: &Database, left: &str, right: &str) -> Result<Option<i32>, anyhow::Error> {
    let result = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            format!(
                r#"
        SELECT * FROM rpmver_cmp( '{left}', '{right}' )
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
async fn test_rpmver_cmp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    assert_eq!(Some(-1), rpmver_cmp(&ctx.db, "1.8.3", "2.9.0").await?);

    assert_eq!(Some(0), rpmver_cmp(&ctx.db, "1.8.3", "1.8.3").await?);

    assert_eq!(Some(1), rpmver_cmp(&ctx.db, "1.8.3", "1.8.2").await?);

    Ok(())
}
