use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // use rpm version range scheme as it covers more usecases
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000800_alter_product_version_range_scheme/migration_up.sql"
            ))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // return to semver version range scheme
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000800_alter_product_version_range_scheme/migration_down.sql"
            ))
            .await?;

        Ok(())
    }
}
