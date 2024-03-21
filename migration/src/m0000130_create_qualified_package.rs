use crate::m0000120_create_package_version::PackageVersion;
use sea_orm_migration::prelude::*;

use crate::Now;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(QualifiedPackage::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(QualifiedPackage::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(QualifiedPackage::Timestamp)
                            .timestamp_with_time_zone()
                            .default(Func::cust(Now)),
                    )
                    .col(
                        ColumnDef::new(QualifiedPackage::PackageVersionId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(QualifiedPackage::PackageVersionId)
                            .to(PackageVersion::Table, PackageVersion::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(QualifiedPackage::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum QualifiedPackage {
    Table,
    Id,
    Timestamp,
    // --
    PackageVersionId,
}
