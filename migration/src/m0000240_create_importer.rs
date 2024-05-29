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
                    .col(ColumnDef::new(Importer::State).integer().not_null())
                    .col(ColumnDef::new(Importer::LastChange).timestamp_with_time_zone())
                    .col(ColumnDef::new(Importer::LastError).string())
                    .col(ColumnDef::new(Importer::LastSuccess).timestamp_with_time_zone())
                    .col(ColumnDef::new(Importer::LastRun).timestamp_with_time_zone())
                    .col(ColumnDef::new(Importer::Continuation).json_binary())
                    .col(ColumnDef::new(Importer::Configuration).json_binary())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ImporterReport::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ImporterReport::Id)
                            .primary_key()
                            .uuid()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ImporterReport::Importer).string().not_null())
                    .col(
                        ColumnDef::new(ImporterReport::Creation)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ImporterReport::Error).string())
                    .col(
                        ColumnDef::new(ImporterReport::Report)
                            .json_binary()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .from_tbl(ImporterReport::Table)
                            .from_col(ImporterReport::Importer)
                            .to_tbl(Importer::Table)
                            .to_col(Importer::Name)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ImporterReport::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Importer::Table).if_exists().to_owned())
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Importer {
    Table,
    Name,
    Revision,

    State,
    LastChange,

    LastError,
    LastRun,
    LastSuccess,

    Continuation,

    Configuration,
}

#[derive(DeriveIden)]
pub enum ImporterReport {
    Table,

    Id,
    Importer,
    Creation,
    Error,
    Report,
}
