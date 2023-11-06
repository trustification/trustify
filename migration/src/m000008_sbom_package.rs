use crate::m000002_create_package::Package;
use crate::m000004_create_vulnerability::Vulnerability;
use crate::m000001_sbom::Sbom;
use crate::m000007_sbom_cpe::SbomCpe::SbomId;
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
                    .table(SbomPackage::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SbomPackage::SbomId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("sbom_id")
                            .from(SbomPackage::Table, SbomPackage::SbomId)
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .col(ColumnDef::new(SbomPackage::PackageId).integer().not_null())
                    .primary_key(
                        Index::create()
                            .name("pk-sbom_package_id")
                            .col(SbomPackage::SbomId)
                            .col(SbomPackage::PackageId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("package_id")
                            .from(SbomPackage::Table, SbomPackage::PackageId)
                            .to(Package::Table, Package::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(SbomPackage::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomPackage {
    Table,
    SbomId,
    PackageId,
}
