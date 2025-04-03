use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
UPDATE SBOM SET SUPPLIERS='{}' WHERE SUPPLIERS IS NULL;
"#,
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .modify_column(
                        ColumnDef::new(Sbom::Suppliers)
                            .array(ColumnType::Text)
                            .not_null(),
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
                    .modify_column(
                        ColumnDef::new(Sbom::Suppliers)
                            .array(ColumnType::Text)
                            .null()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    Suppliers,
}
