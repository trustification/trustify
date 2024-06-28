use sea_orm_migration::prelude::*;

use crate::{m0000030_create_sbom::Sbom, m0000290_create_product::Product, Now, UuidV4};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(ProductVersion::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProductVersion::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ProductVersion::Timestamp)
                            .timestamp_with_time_zone()
                            .default(Func::cust(Now)),
                    )
                    .col(ColumnDef::new(ProductVersion::ProductId).uuid().not_null())
                    .col(ColumnDef::new(ProductVersion::SbomId).uuid())
                    .col(ColumnDef::new(ProductVersion::Version).string().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(ProductVersion::ProductId)
                            .to(Product::Table, Product::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(ProductVersion::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::SetNull),
                    )
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
            .drop_table(Table::drop().table(ProductVersion::Table).to_owned())
            .await?;

        Ok(())
    }
}

pub const INDEX_BY_PID_V: &str = "by_productid_v";

#[derive(DeriveIden)]
pub enum ProductVersion {
    Table,
    Id,
    Timestamp,
    // --
    ProductId,
    SbomId,
    Version,
}
