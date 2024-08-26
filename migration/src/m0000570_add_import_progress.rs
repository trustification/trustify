use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for col in [Importer::ProgressCurrent, Importer::ProgressTotal] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Importer::Table)
                        .add_column(ColumnDef::new(col).integer().null())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for col in [Importer::ProgressCurrent, Importer::ProgressTotal] {
            manager
                .alter_table(
                    Table::alter()
                        .table(Importer::Table)
                        .drop_column(col)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Importer {
    Table,
    ProgressCurrent,
    ProgressTotal,
}
