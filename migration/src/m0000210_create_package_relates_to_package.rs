use crate::m0000010_create_sbom::Sbom;
use crate::m0000044_create_qualified_package::QualifiedPackage;
use crate::m0000200_create_relationship::Relationship;
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
                    .table(PackageRelatesToPackage::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(PackageRelatesToPackage::LeftPackageId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageRelatesToPackage::LeftPackageId)
                            .to(QualifiedPackage::Table, QualifiedPackage::Id),
                    )
                    .col(
                        ColumnDef::new(PackageRelatesToPackage::Relationship)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageRelatesToPackage::Relationship)
                            .to(Relationship::Table, Relationship::Id),
                    )
                    .col(
                        ColumnDef::new(PackageRelatesToPackage::RightPackageId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageRelatesToPackage::RightPackageId)
                            .to(QualifiedPackage::Table, QualifiedPackage::Id),
                    )
                    .col(
                        ColumnDef::new(PackageRelatesToPackage::SbomId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageRelatesToPackage::SbomId)
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .primary_key(
                        Index::create()
                            .col(PackageRelatesToPackage::LeftPackageId)
                            .col(PackageRelatesToPackage::Relationship)
                            .col(PackageRelatesToPackage::RightPackageId)
                            .col(PackageRelatesToPackage::SbomId),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(PackageRelatesToPackage::Table)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum PackageRelatesToPackage {
    Table,
    LeftPackageId,
    Relationship,
    RightPackageId,
    SbomId,
}
