use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/rpmver_version_matches.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_cmp.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_version_matches.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_version_matches.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/is_numeric.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/is_numeric.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_eq.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_gt.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_gte.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_lt.sql"))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_lte.sql"))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000345_create_version_comparison_fns/semver_lte.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000345_create_version_comparison_fns/semver_lt.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000345_create_version_comparison_fns/semver_gte.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000345_create_version_comparison_fns/semver_gt.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000345_create_version_comparison_fns/semver_eq.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000345_create_version_comparison_fns/is_numeric.sql"
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
                "m0000475_improve_version_comparison_fns/semver_cmp.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000480_create_rpmver_cmp_fns/rpmver_version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }
}
