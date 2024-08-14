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
                    .table(ProductStatus::Table)
                    .col(
                        ColumnDef::new(ProductStatus::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ProductStatus::AdvisoryId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(ProductStatus::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(ProductStatus::VulnerabilityId)
                            .string()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(ProductStatus::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .col(ColumnDef::new(ProductStatus::StatusId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(ProductStatus::StatusId)
                            .to(Status::Table, Status::Id),
                    )
                    .col(ColumnDef::new(ProductStatus::BasePurlId).uuid())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(ProductStatus::BasePurlId)
                            .to(BasePurl::Table, BasePurl::Id),
                    )
                    .col(
                        ColumnDef::new(ProductStatus::ProductVersionRangeId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(ProductStatus::ProductVersionRangeId)
                            .to(ProductVersionRange::Table, ProductVersionRange::Id),
                    )
                    .col(ColumnDef::new(ProductStatus::ContextCpeId).uuid())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(ProductStatus::ContextCpeId)
                            .to(Cpe::Table, Cpe::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ProductStatus::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum ProductStatus {
    Table,
    Id,
    AdvisoryId,
    VulnerabilityId,
    StatusId,
    BasePurlId,
    ProductVersionRangeId,
    ContextCpeId,
}

#[derive(DeriveIden)]
enum Advisory {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Vulnerability {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Status {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum BasePurl {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum ProductVersionRange {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Cpe {
    Table,
    Id,
}
