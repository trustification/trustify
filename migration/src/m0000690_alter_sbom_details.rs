use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(SourceDocument::Table)
                    .add_column(
                        ColumnDef::new(SourceDocument::Size)
                            .big_integer()
                            .default(0)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .add_column(
                        ColumnDef::new(Sbom::DataLicenses)
                            .array(ColumnType::Text)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .drop_column(Sbom::DataLicenses)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(SourceDocument::Table)
                    .drop_column(SourceDocument::Size)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SourceDocument {
    Table,
    Size,
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    DataLicenses,
}
