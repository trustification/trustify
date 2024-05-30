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
                    .table(PackageStatus::Table)
                    .col(
                        ColumnDef::new(PackageStatus::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(ColumnDef::new(PackageStatus::AdvisoryId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageStatus::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .col(
                        ColumnDef::new(PackageStatus::VulnerabilityId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageStatus::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .col(ColumnDef::new(PackageStatus::StatusId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageStatus::StatusId)
                            .to(Status::Table, Status::Id),
                    )
                    .col(ColumnDef::new(PackageStatus::PackageId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageStatus::PackageId)
                            .to(Package::Table, Package::Id),
                    )
                    .col(
                        ColumnDef::new(PackageStatus::VersionRangeId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageStatus::VersionRangeId)
                            .to(VersionRange::Table, VersionRange::Id),
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
                    .table(PackageStatus::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum PackageStatus {
    Table,
    Id,
    AdvisoryId,
    VulnerabilityId,
    StatusId,
    PackageId,
    VersionRangeId,
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
enum Package {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum VersionRange {
    Table,
    Id,
}
