use crate::m0000040_create_package::Package;
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
                    .table(PackageVersionRange::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PackageVersionRange::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(PackageVersionRange::Timestamp)
                            .timestamp_with_time_zone()
                            .default(Func::cust(Now)),
                    )
                    .col(
                        ColumnDef::new(PackageVersionRange::PackageId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageVersionRange::PackageId)
                            .to(Package::Table, Package::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(PackageVersionRange::Start)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(PackageVersionRange::End).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PackageVersionRange::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum PackageVersionRange {
    Table,
    Id,
    Timestamp,
    // --
    PackageId,
    Start,
    End,
}
