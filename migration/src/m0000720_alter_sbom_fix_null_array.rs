use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .modify_column(
                        ColumnDef::new(Sbom::DataLicenses)
                            .array(ColumnType::Text)
                            .not_null()
                            .default(Value::Array(ArrayType::String, None))
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    DataLicenses,
}
