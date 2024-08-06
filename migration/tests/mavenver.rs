use migration::sea_orm::Statement;
use migration::ConnectionTrait;
use test_context::test_context;
use test_log::test;
use trustify_common::db::Database;
use trustify_test_context::TrustifyContext;

#[path = "./version_common.rs"]
mod version_common;

async fn mavenver_cmp(
    db: &Database,
    left: &str,
    right: &str,
) -> Result<Option<i32>, anyhow::Error> {
    let result = db
        .query_one(Statement::from_string(
            db.get_database_backend(),
            format!(
                r#"
        SELECT * FROM mavenver_cmp( '{left}', '{right}' )
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
async fn test_mavenver_cmp(ctx: &TrustifyContext) -> Result<(), anyhow::Error> {
    assert_eq!(Some(-1), mavenver_cmp(&ctx.db, "1.8.3", "2.9.0").await?);

    assert_eq!(Some(0), mavenver_cmp(&ctx.db, "1.8.3", "1.8.3").await?);

    assert_eq!(Some(1), mavenver_cmp(&ctx.db, "1.8.3", "1.8.2").await?);

    assert_eq!(Some(1), mavenver_cmp(&ctx.db, "1.8.3", "1.8").await?);
    assert_eq!(Some(-1), mavenver_cmp(&ctx.db, "1.8", "1.8.3").await?);
    assert_eq!(Some(0), mavenver_cmp(&ctx.db, "1.8", "1.8.0").await?);

    assert_eq!(
        Some(-1),
        mavenver_cmp(&ctx.db, "1.8-beta3", "1.8-beta4").await?
    );
    assert_eq!(
        Some(-1),
        mavenver_cmp(&ctx.db, "1.8-beta-3", "1.8-beta-4").await?
    );
    assert_eq!(
        Some(1),
        mavenver_cmp(&ctx.db, "1.8-beta4", "1.8-beta3").await?
    );
    assert_eq!(
        Some(1),
        mavenver_cmp(&ctx.db, "1.8-beta-4", "1.8-beta-3").await?
    );

    assert_eq!(Some(-1), mavenver_cmp(&ctx.db, "1.8-beta3", "1.8").await?);
    assert_eq!(Some(1), mavenver_cmp(&ctx.db, "1.8", "1.8-beta-3").await?);

    assert_eq!(Some(-1), mavenver_cmp(&ctx.db, "1.8-1", "1.8-3").await?);
    assert_eq!(Some(1), mavenver_cmp(&ctx.db, "1.8-3", "1.8-1").await?);

    assert_eq!(Some(-1), mavenver_cmp(&ctx.db, "1.8-1", "1.8.0-3").await?);
    assert_eq!(Some(1), mavenver_cmp(&ctx.db, "1.8-3", "1.8.0-1").await?);

    Ok(())
}
