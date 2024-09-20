use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/gitver_version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/is_numeric.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/maven_version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/mavenver_cmp.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/rpmver_cmp.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/rpmver_version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/semver_cmp.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/semver_eq.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/semver_gt.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/semver_gte.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/semver_lt.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/semver_lte.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/semver_version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000620_parallel_unsafe_pg_fns/version_matches.sql"
            ))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000510_create_maven_cmp_fns/version_matches.sql"
            ))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_version_matches.sql"))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_lte.sql"))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_lt.sql"))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_gte.sql"))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_gt.sql"))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/semver_eq.sql"))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000610_improve_version_cmp_fns/semver_cmp.sql"
            ))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/rpmver_version_matches.sql"))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000480_create_rpmver_cmp_fns/rpmver_cmp.sql"
            ))
            .await
            .map(|_| ())?;
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
                "m0000510_create_maven_cmp_fns/maven_version_matches.sql"
            ))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000580_mark_fns/is_numeric.sql"))
            .await
            .map(|_| ())?;
        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000485_create_gitver_cmp_fns/gitver_version_matches.sql"
            ))
            .await
            .map(|_| ())?;
        Ok(())
    }
}
