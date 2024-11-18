use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .table(ProductStatus::Table)
                    .name(Indexes::ProductStatusIdx.to_string())
                    .col(ProductStatus::ContextCpeId)
                    .col(ProductStatus::StatusId)
                    .col(ProductStatus::Package)
                    .col(ProductStatus::VulnerabilityId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(ProductStatus::Table)
                    .name(Indexes::ProductStatusIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum ProductStatus {
    Table,
    VulnerabilityId,
    StatusId,
    Package,
    ContextCpeId,
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    ProductStatusIdx,
}
