use sea_orm_migration::prelude::*;

use crate::m0000022_create_organization::Organization;
use crate::UuidV4;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(Product::Table)
                    .col(
                        ColumnDef::new(Product::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Product::Name).string().not_null())
                    .col(ColumnDef::new(Product::VendorId).uuid() /* allowed to be null if not known */)
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(Product::VendorId)
                            .to(Organization::Table, Organization::Id)
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Product::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Product {
    Table,
    Id,
    Name,
    VendorId,
}
