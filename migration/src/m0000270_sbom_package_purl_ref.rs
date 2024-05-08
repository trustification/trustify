use crate::m0000030_create_sbom::Sbom;
use crate::m0000130_create_qualified_package::QualifiedPackage;
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
                    .table(SbomPackagePurlRef::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(SbomPackagePurlRef::SbomId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                SbomPackagePurlRef::Table,
                                (SbomPackagePurlRef::SbomId, SbomPackagePurlRef::NodeId),
                            )
                            .to(Sbom::Table, (Sbom::SbomId, Sbom::NodeId))
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(SbomPackagePurlRef::QualifiedPackageId)
                            .uuid()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomPackagePurlRef::SbomId)
                            .col(SbomPackagePurlRef::QualifiedPackageId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                SbomPackagePurlRef::Table,
                                SbomPackagePurlRef::QualifiedPackageId,
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
                    .table(SbomPackagePurlRef::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomPackagePurlRef {
    Table,

    SbomId,
    NodeId,
    QualifiedPackageId,
}
