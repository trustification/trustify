use crate::{Now, UuidV4};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(AffectedPackageVersionRange::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(NotAffectedPackageVersion::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(FixedPackageVersion::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(PackageVersionRange::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(PackageVersionRange::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PackageVersionRange::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(PackageVersionRange::Timestamp)
                            .timestamp_with_time_zone()
                            .default(Func::cust(Now)),
                    )
                    .col(
                        ColumnDef::new(PackageVersionRange::PackageId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageVersionRange::PackageId)
                            .to(Package::Table, Package::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(PackageVersionRange::Start)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(PackageVersionRange::End).string().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AffectedPackageVersionRange::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AffectedPackageVersionRange::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(AffectedPackageVersionRange::AdvisoryId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(AffectedPackageVersionRange::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .col(
                        ColumnDef::new(AffectedPackageVersionRange::VulnerabilityId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(AffectedPackageVersionRange::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .col(
                        ColumnDef::new(AffectedPackageVersionRange::PackageVersionRangeId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(AffectedPackageVersionRange::PackageVersionRangeId)
                            .to(PackageVersionRange::Table, PackageVersionRange::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(NotAffectedPackageVersion::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(NotAffectedPackageVersion::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(NotAffectedPackageVersion::AdvisoryId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(NotAffectedPackageVersion::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .col(
                        ColumnDef::new(NotAffectedPackageVersion::VulnerabilityId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(NotAffectedPackageVersion::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .col(
                        ColumnDef::new(NotAffectedPackageVersion::PackageVersionId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(NotAffectedPackageVersion::PackageVersionId)
                            .to(PackageVersion::Table, PackageVersion::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(FixedPackageVersion::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(FixedPackageVersion::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(FixedPackageVersion::AdvisoryId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(FixedPackageVersion::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id),
                    )
                    .col(
                        ColumnDef::new(FixedPackageVersion::VulnerabilityId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(FixedPackageVersion::VulnerabilityId)
                            .to(Vulnerability::Table, Vulnerability::Id),
                    )
                    .col(
                        ColumnDef::new(FixedPackageVersion::PackageVersionId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(FixedPackageVersion::PackageVersionId)
                            .to(PackageVersion::Table, PackageVersion::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum AffectedPackageVersionRange {
    Table,
    Id,
    AdvisoryId,
    VulnerabilityId,
    PackageVersionRangeId,
}

#[derive(DeriveIden)]
enum FixedPackageVersion {
    Table,
    Id,
    AdvisoryId,
    VulnerabilityId,
    PackageVersionId,
}

#[derive(DeriveIden)]
enum NotAffectedPackageVersion {
    Table,
    Id,
    AdvisoryId,
    VulnerabilityId,
    PackageVersionId,
}

#[derive(DeriveIden)]
enum PackageVersion {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum PackageVersionRange {
    Table,
    Id,
    Timestamp,
    PackageId,
    Start,
    End,
}

#[derive(DeriveIden)]
enum Vulnerability {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Advisory {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Package {
    Table,
    Id,
}
