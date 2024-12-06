use crate::Now;
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
                        ColumnDef::new(SourceDocument::Ingested)
                            .timestamp_with_time_zone()
                            .default(Func::cust(Now))
                            .not_null()
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
                    .table(SourceDocument::Table)
                    .drop_column(SourceDocument::Ingested)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SourceDocument {
    Table,
    Ingested,
}
