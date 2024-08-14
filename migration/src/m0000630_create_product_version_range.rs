use sea_orm_migration::prelude::*;

use crate::{m0000290_create_product::Product, UuidV4};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ProductVersionRange::Table)
                    .col(
                        ColumnDef::new(ProductVersionRange::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(ProductVersionRange::ProductId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProductVersionRange::VersionRangeId)
                            .uuid()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ProductVersionRange::CpeKey).string())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(ProductVersionRange::ProductId)
                            .to(Product::Table, Product::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(ProductVersionRange::VersionRangeId)
                            .to(VersionRange::Table, VersionRange::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ProductVersionRange::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum ProductVersionRange {
    Table,
    Id,
    // --
    ProductId,
    VersionRangeId,
    CpeKey,
}

#[derive(DeriveIden)]
enum VersionRange {
    Table,
    Id,
}
