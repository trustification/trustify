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
                    .table(Cve::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Cve::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Cve::Timestamp)
                            .timestamp_with_time_zone()
                            .default(Func::cust(Now)),
                    )
                    .col(ColumnDef::new(Cve::Identifier).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Cve::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Cve {
    Table,
    Id,
    Timestamp,
    // --
    Identifier,
}
