use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        //create jsonb meta column
        manager
            .alter_table(
                Table::alter()
                    .table(SourceDocument::Table)
                    .add_column(ColumnDef::new(SourceDocument::Meta).json_binary())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop jsonb meta column
        manager
            .alter_table(
                Table::alter()
                    .table(SourceDocument::Table)
                    .drop_column(SourceDocument::Meta)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SourceDocument {
    Table,
    Meta,
}
