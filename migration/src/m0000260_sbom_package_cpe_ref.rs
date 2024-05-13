use crate::m0000110_create_cpe::Cpe;
use crate::m0000250_create_sbom_package::SbomPackage;
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
                    .table(SbomPackageCpeRef::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SbomPackageCpeRef::SbomId).uuid().not_null())
                    .col(
                        ColumnDef::new(SbomPackageCpeRef::NodeId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SbomPackageCpeRef::CpeId)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                SbomPackageCpeRef::Table,
                                (SbomPackageCpeRef::SbomId, SbomPackageCpeRef::NodeId),
                            )
                            .to(
                                SbomPackage::Table,
                                (SbomPackage::SbomId, SbomPackage::NodeId),
                            )
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(SbomPackageCpeRef::Table, SbomPackageCpeRef::CpeId)
                            .to(Cpe::Table, Cpe::Id),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomPackageCpeRef::SbomId)
                            .col(SbomPackageCpeRef::NodeId)
                            .col(SbomPackageCpeRef::CpeId)
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
                    .table(SbomPackageCpeRef::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum SbomPackageCpeRef {
    Table,

    SbomId,
    NodeId,
    CpeId,
}
