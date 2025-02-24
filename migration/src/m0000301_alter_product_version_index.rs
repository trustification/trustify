use sea_orm_migration::prelude::*;

use crate::m0000300_create_product_version::{INDEX_BY_PID_V, ProductVersion};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(ProductVersion::Table)
                    .name(INDEX_BY_PID_V)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(ProductVersion::Table)
                    .name(INDEX_BY_PID_V)
                    .if_not_exists()
                    .unique()
                    .col(ProductVersion::ProductId)
                    .col(ProductVersion::Version)
                    .col(ProductVersion::SbomId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(ProductVersion::Table)
                    .name(INDEX_BY_PID_V)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(ProductVersion::Table)
                    .name(INDEX_BY_PID_V)
                    .if_not_exists()
                    .unique()
                    .col(ProductVersion::ProductId)
                    .col(ProductVersion::Version)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
