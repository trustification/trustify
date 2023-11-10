use crate::m0000010_create_sbom::Sbom;
use crate::m0000044_create_qualified_package::QualifiedPackage;
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
                    .table(SbomDescribesPackage::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SbomDescribesPackage::SbomId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("sbom_id")
                            .from(SbomDescribesPackage::Table, SbomDescribesPackage::SbomId)
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .col(
                        ColumnDef::new(SbomDescribesPackage::QualifiedPackageId)
                            .integer()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-sbom_package_id")
                            .col(SbomDescribesPackage::SbomId)
                            .col(SbomDescribesPackage::QualifiedPackageId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("qualified_package_id")
                            .from(
                                SbomDescribesPackage::Table,
                                SbomDescribesPackage::QualifiedPackageId,
                            )
                            .to(QualifiedPackage::Table, QualifiedPackage::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(SbomDescribesPackage::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomDescribesPackage {
    Table,
    SbomId,
    QualifiedPackageId,
}
