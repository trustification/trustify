use crate::m0000100_create_package::Package;
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
                    .table(PackageVersion::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PackageVersion::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(PackageVersion::Timestamp)
                            .timestamp_with_time_zone()
                            .default(Func::cust(Now)),
                    )
                    .col(
                        ColumnDef::new(PackageVersion::PackageId)
                            .integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(PackageVersion::Version).string().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageVersion::PackageId)
                            .to(Package::Table, Package::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(PackageVersion::Table)
                    .name(INDEX_BY_PID_V)
                    .if_not_exists()
                    .unique()
                    .col(PackageVersion::PackageId)
                    .col(PackageVersion::Version)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(PackageVersion::Table)
                    .name(INDEX_BY_PID_V)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(PackageVersion::Table).to_owned())
            .await?;

        Ok(())
    }
}

const INDEX_BY_PID_V: &str = "by_pid_v";

#[derive(DeriveIden)]
pub enum PackageVersion {
    Table,
    Id,
    Timestamp,
    // --
    PackageId,
    Version,
}
