use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // use rpm version range scheme as it covers more usecases
        manager
            .get_connection()
            .execute_unprepared(r#"UPDATE version_range SET version_scheme_id = 'rpm' WHERE id IN (SELECT version_range_id FROM product_version_range)"#)
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // return to semver version range scheme
        manager
            .get_connection()
            .execute_unprepared(r#"UPDATE version_range SET version_scheme_id = 'semver' WHERE id IN (SELECT version_range_id FROM product_version_range)"#)
            .await?;

        Ok(())
    }
}
