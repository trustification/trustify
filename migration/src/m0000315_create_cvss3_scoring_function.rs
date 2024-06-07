use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000315_create_cvss3_scoring_function.sql"))
            .await
            .map(|_| ())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_score"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_exploitability"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_impact"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_av_score"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_ac_score"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_pr_scoped_score"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_ui_score"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_scope_changed"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_c_score"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_i_score"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(r#"drop function cvss3_a_score"#)
            .await?;

        Ok(())
    }
}
