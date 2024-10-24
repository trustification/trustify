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
                    .table(ProductStatus::Table)
                    .drop_column(ProductStatus::BasePurlId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ProductStatus::Table)
                    .add_column(ColumnDef::new(ProductStatus::Component).string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ProductStatus::Table)
                    .drop_column(ProductStatus::Component)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ProductStatus::Table)
                    .add_column(ColumnDef::new(ProductStatus::BasePurlId).uuid())
                    .add_foreign_key(
                        TableForeignKey::new()
                            .from_tbl(ProductStatus::Table)
                            .from_col(ProductStatus::BasePurlId)
                            .to_tbl(BasePurl::Table)
                            .to_col(BasePurl::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum ProductStatus {
    Table,
    BasePurlId,
    Component,
}

#[derive(DeriveIden)]
enum BasePurl {
    Table,
    Id,
}
