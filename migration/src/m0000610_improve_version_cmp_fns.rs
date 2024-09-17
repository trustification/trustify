use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000610_improve_version_cmp_fns/mavenver_cmp.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000610_improve_version_cmp_fns/semver_cmp.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000600_remove_raise_notice_fns/semver_cmp.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000510_create_maven_cmp_fns/mavenver_cmp.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }
}
