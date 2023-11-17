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
                    .table(Cpe22::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Cpe22::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Cpe22::Part).string())
                    .col(ColumnDef::new(Cpe22::Vendor).string())
                    .col(ColumnDef::new(Cpe22::Product).string())
                    .col(ColumnDef::new(Cpe22::Version).string())
                    .col(ColumnDef::new(Cpe22::Update).string())
                    .col(ColumnDef::new(Cpe22::Edition).string())
                    .col(ColumnDef::new(Cpe22::Language).string())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Cpe22::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Cpe22 {
    Table,
    Id,
    // --
    Part,
    Vendor,
    Product,
    Version,
    Update,
    Edition,
    Language,
}
