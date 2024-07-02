use crate::m0000022_create_organization::Organization;
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
                    .table(Advisory::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Advisory::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Advisory::IssuerId).uuid() /* allowed to be null if not known */)
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(Advisory::IssuerId)
                            .to(Organization::Table, Organization::Id)
                    )
                    .col(ColumnDef::new(Advisory::Published).timestamp_with_time_zone())
                    .col(ColumnDef::new(Advisory::Modified).timestamp_with_time_zone())
                    .col(ColumnDef::new(Advisory::Withdrawn).timestamp_with_time_zone())
                    .col(ColumnDef::new(Advisory::Identifier).string().not_null())
                    .col(ColumnDef::new(Advisory::Location).string().not_null())
                    .col(ColumnDef::new(Advisory::Sha256).string().not_null())
                    .col(ColumnDef::new(Advisory::Title).string())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Advisory::Table).if_exists().to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum Advisory {
    Table,
    Id,
    IssuerId,
    Published,
    Modified,
    Withdrawn,
    Identifier,
    Location,
    Sha256,
    Title,
}
