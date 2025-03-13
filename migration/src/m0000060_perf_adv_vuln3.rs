use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // This is a stable change eg. no need for rollback
        manager
            .get_connection()
            .execute_unprepared(
                "
                    ALTER FUNCTION generic_version_matches IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION is_numeric IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION maven_version_matches IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION mavenver_cmp IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION python_version_matches IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION pythonver_cmp IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION rpmver_cmp IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION rpmver_version_matches IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION semver_cmp IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION semver_eq IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION semver_gt IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION semver_gte IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION semver_lt IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION semver_lte IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION semver_version_matches IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION version_matches IMMUTABLE PARALLEL SAFE;
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
                    ALTER FUNCTION generic_version_matches IMMUTABLE;
                    ALTER FUNCTION is_numeric IMMUTABLE;
                    ALTER FUNCTION maven_version_matches IMMUTABLE;
                    ALTER FUNCTION mavenver_cmp IMMUTABLE;
                    ALTER FUNCTION python_version_matches IMMUTABLE;
                    ALTER FUNCTION pythonver_cmp IMMUTABLE;
                    ALTER FUNCTION rpmver_cmp IMMUTABLE;
                    ALTER FUNCTION rpmver_version_matches IMMUTABLE;
                    ALTER FUNCTION semver_cmp IMMUTABLE;
                    ALTER FUNCTION semver_eq IMMUTABLE;
                    ALTER FUNCTION semver_gt IMMUTABLE;
                    ALTER FUNCTION semver_gte IMMUTABLE;
                    ALTER FUNCTION semver_lt IMMUTABLE;
                    ALTER FUNCTION semver_lte IMMUTABLE;
                    ALTER FUNCTION semver_version_matches IMMUTABLE;
                    ALTER FUNCTION version_matches IMMUTABLE;
                ",
            )
            .await
            .map(|_| ())?;

        Ok(())
    }
}
