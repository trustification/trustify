use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("is_numeric.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("semver_cmp.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("semver_version_matches.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("version_matches.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("semver_gt.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("semver_gte.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("semver_lt.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("semver_lte.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("semver_eq.sql"))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("drop function semver_gt")
            .await?;

        manager
            .get_connection()
            .execute_unprepared("drop function semver_gte")
            .await?;

        manager
            .get_connection()
            .execute_unprepared("drop function semver_lt")
            .await?;

        manager
            .get_connection()
            .execute_unprepared("drop function semver_lte")
            .await?;

        manager
            .get_connection()
            .execute_unprepared("drop function semver_eq")
            .await?;

        manager
            .get_connection()
            .execute_unprepared("drop function semver_cmp")
            .await?;

        manager
            .get_connection()
            .execute_unprepared("drop function semver_version_matches")
            .await?;

        manager
            .get_connection()
            .execute_unprepared("drop function version_matches")
            .await?;

        Ok(())
    }
}
