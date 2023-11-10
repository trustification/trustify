use crate::m0000030_create_advisory::Advisory;
use crate::m0000042_create_package_version::PackageVersion;
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
                    .table(FixedPackageVersion::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(FixedPackageVersion::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(FixedPackageVersion::AdvisoryId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(FixedPackageVersion::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .col(
                        ColumnDef::new(FixedPackageVersion::PackageVersionId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(FixedPackageVersion::PackageVersionId)
                            .to(PackageVersion::Table, PackageVersion::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(FixedPackageVersion::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum FixedPackageVersion {
    Table,
    Id,
    //Timestamp,
    // --
    AdvisoryId,
    PackageVersionId,
}
