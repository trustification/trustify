use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(License::Table)
                    .add_column(ColumnDef::new(License::CustomLicenseRefs).array(ColumnType::Text))
                    .add_column(
                        ColumnDef::new(License::CustomDocumentLicenseRefs).array(ColumnType::Text),
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
                    .table(License::Table)
                    .drop_column(License::CustomLicenseRefs)
                    .drop_column(License::CustomDocumentLicenseRefs)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum License {
    Table,
    CustomLicenseRefs,
    CustomDocumentLicenseRefs,
}
