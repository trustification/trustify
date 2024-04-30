use crate::m0000030_create_sbom::Sbom;
use crate::m0000130_create_qualified_package::QualifiedPackage;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SbomPackage::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SbomPackage::SbomId).integer().not_null())
                    .col(
                        ColumnDef::new(SbomPackage::QualifiedPackageId)
                            .uuid()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomPackage::SbomId)
                            .col(SbomPackage::QualifiedPackageId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(SbomPackage::SbomId)
                            .to(Sbom::Table, Sbom::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(SbomPackage::QualifiedPackageId)
                            .to(QualifiedPackage::Table, QualifiedPackage::Id),
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
                    .table(SbomPackage::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum SbomPackage {
    Table,
    SbomId,
    QualifiedPackageId,
}
