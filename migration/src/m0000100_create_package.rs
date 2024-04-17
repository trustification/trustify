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
                    .table(Package::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Package::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Package::Timestamp)
                            .timestamp_with_time_zone()
                            .default(Func::cust(Now)),
                    )
                    .col(ColumnDef::new(Package::Type).string().not_null())
                    .col(ColumnDef::new(Package::Namespace).string())
                    .col(ColumnDef::new(Package::Name).string().not_null())
                    .index(
                        Index::create()
                            .unique()
                            .if_not_exists()
                            .col(Package::Type)
                            .col(Package::Namespace)
                            .col(Package::Name),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Package::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Package {
    Table,
    Id,
    Timestamp,
    // --
    Type,
    Namespace,
    Name,
}
