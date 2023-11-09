use crate::m0000010_create_sbom::Sbom;
use crate::m0000040_create_package::Package;
use crate::m0000044_create_qualified_package::QualifiedPackage;
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
                    .table(SbomContainsPackage::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SbomContainsPackage::SbomId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("sbom_id")
                            .from(SbomContainsPackage::Table, SbomContainsPackage::SbomId)
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .col(
                        ColumnDef::new(SbomContainsPackage::QualifiedPackageId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("dependency_package_id")
                            .from(
                                SbomContainsPackage::Table,
                                SbomContainsPackage::QualifiedPackageId,
                            )
                            .to(QualifiedPackage::Table, QualifiedPackage::Id),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-sbom-package")
                            .col(SbomContainsPackage::SbomId)
                            .col(SbomContainsPackage::QualifiedPackageId)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SbomContainsPackage::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomContainsPackage {
    Table,
    SbomId,
    QualifiedPackageId,
}
