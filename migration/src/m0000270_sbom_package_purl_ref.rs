use crate::m0000130_create_qualified_package::QualifiedPackage;
use crate::m0000250_create_sbom_package::SbomPackage;
use crate::m0000260_sbom_package_cpe_ref::SbomPackageCpeRef;
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
                    .col(ColumnDef::new(SbomPackagePurlRef::SbomId).uuid().not_null())
                    .col(
                        ColumnDef::new(SbomPackageCpeRef::NodeId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SbomPackagePurlRef::QualifiedPackageId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                SbomPackagePurlRef::Table,
                                (SbomPackagePurlRef::SbomId, SbomPackagePurlRef::NodeId),
                            )
                            .to(
                                SbomPackage::Table,
                                (SbomPackage::SbomId, SbomPackage::NodeId),
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                SbomPackagePurlRef::Table,
                                SbomPackagePurlRef::QualifiedPackageId,
                            )
                            .to(QualifiedPackage::Table, QualifiedPackage::Id),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomPackagePurlRef::SbomId)
                            .col(SbomPackagePurlRef::NodeId)
                            .col(SbomPackagePurlRef::QualifiedPackageId)
                            .primary(),
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
