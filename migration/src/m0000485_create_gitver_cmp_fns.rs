use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000485_create_gitver_cmp_fns/gitver_version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000485_create_gitver_cmp_fns/version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {

        manager
            .get_connection()
            .execute_unprepared("drop function gitver_version_matches")
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000480_create_rpmver_cmp_fns/version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000475_improve_version_comparison_fns/semver_version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000475_improve_version_comparison_fns/version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }
}
