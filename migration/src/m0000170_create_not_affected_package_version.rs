use crate::m0000040_create_vulnerability::Vulnerability;
use crate::m0000060_create_advisory::Advisory;
use crate::m0000120_create_package_version::PackageVersion;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(NotAffectedPackageVersion::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(NotAffectedPackageVersion::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(NotAffectedPackageVersion::AdvisoryId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(NotAffectedPackageVersion::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .col(
                        ColumnDef::new(NotAffectedPackageVersion::VulnerabilityId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(NotAffectedPackageVersion::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .col(
                        ColumnDef::new(NotAffectedPackageVersion::PackageVersionId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(NotAffectedPackageVersion::PackageVersionId)
                            .to(PackageVersion::Table, PackageVersion::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(NotAffectedPackageVersion::Table)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum NotAffectedPackageVersion {
    Table,
    Id,
    //Timestamp,
    // --
    AdvisoryId,
    VulnerabilityId,
    PackageVersionId,
}
