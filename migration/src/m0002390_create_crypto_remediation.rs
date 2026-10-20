use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CryptoRemediation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CryptoRemediation::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CryptoRemediation::AlgorithmName)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CryptoRemediation::AlgorithmPrimitive)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(CryptoRemediation::ReplacementName)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CryptoRemediation::ReplacementStandard)
                            .text()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(CryptoRemediation::ReplacementPrimitive)
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Unique index with NULLS NOT DISTINCT so that NULLs compare equal for conflict detection.
        manager
            .create_index(
                Index::create()
                    .table(CryptoRemediation::Table)
                    .col(CryptoRemediation::AlgorithmName)
                    .col(CryptoRemediation::AlgorithmPrimitive)
                    .unique()
                    .nulls_not_distinct()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(CryptoRemediation::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum CryptoRemediation {
    Table,
    Id,
    AlgorithmName,
    AlgorithmPrimitive,
    ReplacementName,
    ReplacementStandard,
    ReplacementPrimitive,
}
