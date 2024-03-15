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
                    .table(Advisory::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Advisory::Id)
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Advisory::Identifier).string().not_null())
                    .col(ColumnDef::new(Advisory::Location).string().not_null())
                    .col(ColumnDef::new(Advisory::Sha256).string().not_null())
                    .col(ColumnDef::new(Advisory::Title).string())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Advisory::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Advisory {
    Table,
    Id,
    Identifier,
    Location,
    Sha256,
    Title,
}
