use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000670_version_cmp/version_matches.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000670_version_cmp/generic_version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(r#"DROP FUNCTION generic_version_matches"#)
            .await
            .map(|_| ())?;

        Ok(())
    }
}
