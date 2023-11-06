use crate::m000002_create_package::Package;
use crate::Now;
use sea_orm_migration::prelude::*;
use crate::m000001_sbom::Sbom;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(SbomDependency::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SbomDependency::SbomId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("sbom_id")
                            .from(
                                SbomDependency::Table,
                                SbomDependency::SbomId,
                            )
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .col(
                        ColumnDef::new(SbomDependency::PackageId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dependency_package_id")
                            .from(
                                SbomDependency::Table,
                                SbomDependency::PackageId,
                            )
                            .to(Package::Table, Package::Id),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-sbom-package")
                            .col(SbomDependency::SbomId)
                            .col(SbomDependency::PackageId)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SbomDependency::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomDependency {
    Table,
    SbomId,
    PackageId,
}
