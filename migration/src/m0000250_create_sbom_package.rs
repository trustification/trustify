use crate::m0000030_create_sbom::SbomNode;
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
                    .col(ColumnDef::new(SbomPackage::SbomId).uuid().not_null())
                    .col(ColumnDef::new(SbomPackage::NodeId).string().not_null())
                    .primary_key(
                        Index::create()
                            .col(SbomPackage::SbomId)
                            .col(SbomPackage::NodeId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                SbomPackage::Table,
                                (SbomPackage::SbomId, SbomPackage::NodeId),
                            )
                            .to(SbomNode::Table, (SbomNode::SbomId, SbomNode::NodeId))
                            .on_delete(ForeignKeyAction::Cascade),
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
    NodeId,
}
