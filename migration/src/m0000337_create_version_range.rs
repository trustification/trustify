use crate::UuidV4;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(VersionRange::Table)
                    .col(
                        ColumnDef::new(VersionRange::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(VersionRange::VersionSchemeId)
                            .string()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(VersionRange::VersionSchemeId)
                            .to(VersionScheme::Table, VersionScheme::Id),
                    )
                    .col(ColumnDef::new(VersionRange::LowVersion).string())
                    .col(ColumnDef::new(VersionRange::LowInclusive).boolean())
                    .col(ColumnDef::new(VersionRange::HighVersion).string())
                    .col(ColumnDef::new(VersionRange::HighInclusive).boolean())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(VersionRange::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum VersionRange {
    Table,
    Id,
    VersionSchemeId,
    LowVersion,
    LowInclusive,
    HighVersion,
    HighInclusive,
}

#[derive(DeriveIden)]
enum VersionScheme {
    Table,
    Id,
}
