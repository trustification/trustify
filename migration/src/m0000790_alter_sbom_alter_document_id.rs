use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // modify, allow null

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .modify_column(ColumnDef::new(Sbom::DocumentId).string().null().to_owned())
                    .to_owned(),
            )
            .await?;

        // bring back the null value, or consider it null if we already did not have a real value

        manager
            .get_connection()
            .execute_unprepared(r#"UPDATE sbom SET document_id = NULL where document_id=''"#)
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // set an empty string, works and is required

        manager
            .get_connection()
            .execute_unprepared(r#"UPDATE sbom SET document_id = '' where document_id IS NULL"#)
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .modify_column(ColumnDef::new(Sbom::DocumentId).string().not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    DocumentId,
}
