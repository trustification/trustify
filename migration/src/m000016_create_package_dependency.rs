use crate::m000001_sbom::Sbom;
use crate::m000004_create_package::Package;
use crate::Now;
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
                    .table(PackageDependency::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PackageDependency::Timestamp)
                            .timestamp_with_time_zone()
                            .default(Func::cust(Now)),
                    )
                    .col(
                        ColumnDef::new(PackageDependency::SbomId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("sbom_id")
                            .from(PackageDependency::Table, PackageDependency::SbomId)
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .col(
                        ColumnDef::new(PackageDependency::DependentPackageId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dependent_package_id")
                            .from(
                                PackageDependency::Table,
                                PackageDependency::DependentPackageId,
                            )
                            .to(Package::Table, Package::Id),
                    )
                    .col(
                        ColumnDef::new(PackageDependency::DependencyPackageId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dependency_package_id")
                            .from(
                                PackageDependency::Table,
                                PackageDependency::DependencyPackageId,
                            )
                            .to(Package::Table, Package::Id),
                    )
                    .primary_key(
                        Index::create()
                            .name("package_dependency_dependent")
                            .col(PackageDependency::DependentPackageId)
                            .col(PackageDependency::DependencyPackageId)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PackageDependency::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum PackageDependency {
    Table,
    Timestamp,
    SbomId,
    DependentPackageId,
    DependencyPackageId,
}
