use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .add_column(ColumnDef::new(Sbom::Labels).json_binary())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_column(ColumnDef::new(Advisory::Labels).json_binary())
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000355_labels_up.sql"))
            .await
            .map(|_| ())?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .modify_column(ColumnDef::new(Sbom::Labels).not_null())
                    .drop_column(Sbom::Location)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .modify_column(ColumnDef::new(Advisory::Labels).not_null())
                    .drop_column(Advisory::Location)
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
                    .add_column(ColumnDef::new(Sbom::Location).string().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_column(ColumnDef::new(Advisory::Location).string().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!("m0000355_labels_down.sql"))
            .await
            .map(|_| ())?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .drop_column(Sbom::Labels)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .drop_column(Advisory::Labels)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    Location,
    Labels,
}

#[derive(DeriveIden)]
pub enum Advisory {
    Table,
    Location,
    Labels,
}
