use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Importer::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Importer::Name)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Importer::Revision).uuid().not_null())
                    .col(ColumnDef::new(Importer::Configuration).json_binary())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Importer::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Importer {
    Table,
    Name,
    Revision,
    Configuration,
}
