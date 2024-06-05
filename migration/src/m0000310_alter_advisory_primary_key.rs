use crate::UuidV4;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add `uuid` to Advisory table
        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_column(
                        ColumnDef::new(Advisory::Uuid)
                            .uuid()
                            .unique_key()
                            .default(Func::cust(UuidV4)),
                    )
                    .to_owned(),
            )
            .await?;

        // Add `advisory_uuid` to all appropriate related tables
        // and execute the linking query to populate

        manager
            .alter_table(
                Table::alter()
                    .table(AdvisoryVulnerability::Table)
                    .add_column(
                        ColumnDef::new(AdvisoryVulnerability::AdvisoryUuid)
                            .uuid()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE advisory_vulnerability
                SET advisory_uuid = advisory.uuid
                FROM advisory
                WHERE advisory_vulnerability.advisory_id = advisory.id
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss3::Table)
                    .add_column(ColumnDef::new(Cvss3::AdvisoryUuid).uuid().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE cvss3
                SET advisory_uuid = advisory.uuid
                FROM advisory
                WHERE cvss3.advisory_id = advisory.id
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss4::Table)
                    .add_column(ColumnDef::new(Cvss4::AdvisoryUuid).uuid().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE cvss4
                SET advisory_uuid = advisory.uuid
                FROM advisory
                WHERE cvss4.advisory_id = advisory.id
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(AffectedPackageVersionRange::Table)
                    .add_column(
                        ColumnDef::new(AffectedPackageVersionRange::AdvisoryUuid)
                            .uuid()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE affected_package_version_range
                SET advisory_uuid = advisory.uuid
                FROM advisory
                WHERE affected_package_version_range.advisory_id = advisory.id
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(NotAffectedPackageVersion::Table)
                    .add_column(
                        ColumnDef::new(NotAffectedPackageVersion::AdvisoryUuid)
                            .uuid()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE not_affected_package_version
                SET advisory_uuid = advisory.uuid
                FROM advisory
                WHERE not_affected_package_version.advisory_id = advisory.id
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(FixedPackageVersion::Table)
                    .add_column(
                        ColumnDef::new(FixedPackageVersion::AdvisoryUuid)
                            .uuid()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE fixed_package_version
                SET advisory_uuid = advisory.uuid
                FROM advisory
                WHERE fixed_package_version.advisory_id = advisory.id
                "#,
            )
            .await?;

        // remove old FK columns

        manager
            .alter_table(
                Table::alter()
                    .table(AdvisoryVulnerability::Table)
                    .drop_column(AdvisoryVulnerability::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss3::Table)
                    .drop_column(Cvss3::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP INDEX IF EXISTS cvss3_pkey CASCADE
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss4::Table)
                    .drop_column(Cvss4::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP INDEX IF EXISTS cvss4_pkey CASCADE
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(AffectedPackageVersionRange::Table)
                    .drop_column(AffectedPackageVersionRange::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(NotAffectedPackageVersion::Table)
                    .drop_column(NotAffectedPackageVersion::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(FixedPackageVersion::Table)
                    .drop_column(FixedPackageVersion::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        // drop original PK constraint and index

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE advisory DROP CONSTRAINT advisory_pkey CASCADE
                "#,
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP INDEX IF EXISTS advisory_pkey
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .drop_column(Advisory::Id)
                    .to_owned(),
            )
            .await?;

        // drop the auto-increment sequence if it's still hanging around

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP SEQUENCE IF EXISTS advisory_id_seq
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .modify_column(ColumnDef::new(Advisory::Uuid).primary_key())
                    .to_owned(),
            )
            .await?;

        // rename the PK column back to `id`

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .rename_column(Advisory::Uuid, Advisory::Id)
                    .to_owned(),
            )
            .await?;

        // rename all FKs columns back to `_id`

        manager
            .alter_table(
                Table::alter()
                    .table(AdvisoryVulnerability::Table)
                    .rename_column(
                        AdvisoryVulnerability::AdvisoryUuid,
                        AdvisoryVulnerability::AdvisoryId,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss3::Table)
                    .rename_column(Cvss3::AdvisoryUuid, Cvss3::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss4::Table)
                    .rename_column(Cvss4::AdvisoryUuid, Cvss4::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(AffectedPackageVersionRange::Table)
                    .rename_column(
                        AffectedPackageVersionRange::AdvisoryUuid,
                        AffectedPackageVersionRange::AdvisoryId,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(NotAffectedPackageVersion::Table)
                    .rename_column(
                        NotAffectedPackageVersion::AdvisoryUuid,
                        NotAffectedPackageVersion::AdvisoryId,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(FixedPackageVersion::Table)
                    .rename_column(
                        FixedPackageVersion::AdvisoryUuid,
                        FixedPackageVersion::AdvisoryId,
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add `idx` to Advisory table
        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_column(
                        ColumnDef::new(Advisory::Idx)
                            .integer()
                            .unique_key()
                            .auto_increment(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add `advisory_id` to all appropriate related tables
        // and execute the linking query to populate

        manager
            .alter_table(
                Table::alter()
                    .table(AdvisoryVulnerability::Table)
                    .add_column(
                        ColumnDef::new(AdvisoryVulnerability::AdvisoryIdx)
                            .integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE advisory_vulnerability
                SET advisory_idx = advisory.idx
                FROM advisory
                WHERE advisory_vulnerability.advisory_id = advisory.id
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss3::Table)
                    .add_column(ColumnDef::new(Cvss3::AdvisoryIdx).integer().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE cvss3
                SET advisory_idx = advisory.idx
                FROM advisory
                WHERE cvss3.advisory_id = advisory.id
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss4::Table)
                    .add_column(ColumnDef::new(Cvss4::AdvisoryIdx).integer().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE cvss4
                SET advisory_idx = advisory.idx
                FROM advisory
                WHERE cvss4.advisory_id = advisory.id
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(AffectedPackageVersionRange::Table)
                    .add_column(
                        ColumnDef::new(AffectedPackageVersionRange::AdvisoryIdx)
                            .integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE affected_package_version_range
                SET advisory_idx = advisory.idx
                FROM advisory
                WHERE affected_package_version_range.advisory_id = advisory.id
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(NotAffectedPackageVersion::Table)
                    .add_column(
                        ColumnDef::new(NotAffectedPackageVersion::AdvisoryIdx)
                            .integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE not_affected_package_version
                SET advisory_idx = advisory.idx
                FROM advisory
                WHERE not_affected_package_version.advisory_id = advisory.id
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(FixedPackageVersion::Table)
                    .add_column(
                        ColumnDef::new(FixedPackageVersion::AdvisoryIdx)
                            .integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE fixed_package_version
                SET advisory_idx = advisory.idx
                FROM advisory
                WHERE fixed_package_version.advisory_id = advisory.id
                "#,
            )
            .await?;

        // remove old FK columns

        manager
            .alter_table(
                Table::alter()
                    .table(AdvisoryVulnerability::Table)
                    .drop_column(AdvisoryVulnerability::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss3::Table)
                    .drop_column(Cvss3::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP INDEX IF EXISTS cvss3_pkey CASCADE
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss4::Table)
                    .drop_column(Cvss4::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP INDEX IF EXISTS cvss4_pkey CASCADE
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(AffectedPackageVersionRange::Table)
                    .drop_column(AffectedPackageVersionRange::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(NotAffectedPackageVersion::Table)
                    .drop_column(NotAffectedPackageVersion::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(FixedPackageVersion::Table)
                    .drop_column(FixedPackageVersion::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        // drop original PK constraint and index

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                ALTER TABLE advisory DROP CONSTRAINT advisory_pkey CASCADE
                "#,
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
                DROP INDEX IF EXISTS advisory_pkey
                "#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .drop_column(Advisory::Id)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .modify_column(ColumnDef::new(Advisory::Idx).primary_key())
                    .to_owned(),
            )
            .await?;

        // rename the PK column back to `id`

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .rename_column(Advisory::Idx, Advisory::Id)
                    .to_owned(),
            )
            .await?;

        // rename all FKs columns back to `_id`

        manager
            .alter_table(
                Table::alter()
                    .table(AdvisoryVulnerability::Table)
                    .rename_column(
                        AdvisoryVulnerability::AdvisoryIdx,
                        AdvisoryVulnerability::AdvisoryId,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss3::Table)
                    .rename_column(Cvss3::AdvisoryIdx, Cvss3::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss4::Table)
                    .rename_column(Cvss4::AdvisoryIdx, Cvss4::AdvisoryId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(AffectedPackageVersionRange::Table)
                    .rename_column(
                        AffectedPackageVersionRange::AdvisoryIdx,
                        AffectedPackageVersionRange::AdvisoryId,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(NotAffectedPackageVersion::Table)
                    .rename_column(
                        NotAffectedPackageVersion::AdvisoryIdx,
                        NotAffectedPackageVersion::AdvisoryId,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(FixedPackageVersion::Table)
                    .rename_column(
                        FixedPackageVersion::AdvisoryIdx,
                        FixedPackageVersion::AdvisoryId,
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Advisory {
    Table,
    Id,
    Idx,
    Uuid,
}

#[derive(DeriveIden)]
pub enum AdvisoryVulnerability {
    Table,
    AdvisoryId,
    AdvisoryIdx,
    AdvisoryUuid,
}

#[derive(DeriveIden)]
pub enum Cvss3 {
    Table,
    AdvisoryId,
    AdvisoryIdx,
    AdvisoryUuid,
}

#[derive(DeriveIden)]
pub enum Cvss4 {
    Table,
    AdvisoryId,
    AdvisoryIdx,
    AdvisoryUuid,
}

#[derive(DeriveIden)]
pub enum AffectedPackageVersionRange {
    Table,
    AdvisoryId,
    AdvisoryIdx,
    AdvisoryUuid,
}

#[derive(DeriveIden)]
pub enum NotAffectedPackageVersion {
    Table,
    AdvisoryId,
    AdvisoryIdx,
    AdvisoryUuid,
}

#[derive(DeriveIden)]
pub enum FixedPackageVersion {
    Table,
    AdvisoryId,
    AdvisoryIdx,
    AdvisoryUuid,
}
