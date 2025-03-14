use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "
                    DROP INDEX IF EXISTS advisory_vulnerability_vulnerability_id_gist;
                ",
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "
                    CREATE INDEX advisory_vulnerability_vulnerability_id_gist ON advisory_vulnerability USING GIST (vulnerability_id gist_trgm_ops);
                ")
            .await
            .map(|_| ())?;
        Ok(())
    }
}
