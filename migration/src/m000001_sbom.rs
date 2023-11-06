use crate::m000002_create_package::Package;
use crate::m000004_create_vulnerability::Vulnerability;
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
                    .table(Sbom::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Sbom::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Sbom::Location).string().not_null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Sbom::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    Id,
    Location,
}
