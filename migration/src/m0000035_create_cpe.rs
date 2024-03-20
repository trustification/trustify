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
                    .table(Cpe::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Cpe::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Cpe::Part).string())
                    .col(ColumnDef::new(Cpe::Vendor).string())
                    .col(ColumnDef::new(Cpe::Product).string())
                    .col(ColumnDef::new(Cpe::Version).string())
                    .col(ColumnDef::new(Cpe::Update).string())
                    .col(ColumnDef::new(Cpe::Edition).string())
                    .col(ColumnDef::new(Cpe::Language).string())
                    .col(ColumnDef::new(Cpe::SwEdition).string())
                    .col(ColumnDef::new(Cpe::TargetSw).string())
                    .col(ColumnDef::new(Cpe::TargetHw).string())
                    .col(ColumnDef::new(Cpe::Other).string())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Cpe::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Cpe {
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
    SwEdition,
    TargetSw,
    TargetHw,
    Other,
}
