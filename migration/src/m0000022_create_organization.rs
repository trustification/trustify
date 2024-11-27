use crate::UuidV4;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(Organization::Table)
                    .col(
                        ColumnDef::new(Organization::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Organization::Name)
                            .unique_key()
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Organization::CpeKey).string())
                    .col(ColumnDef::new(Organization::Website).string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Organization::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Organization {
    Table,
    Id,
    Name,
    CpeKey,
    Website,
}
