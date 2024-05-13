use crate::m0000030_create_sbom::{Sbom, SbomNode};
use crate::m0000210_create_relationship::Relationship;
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
                        ColumnDef::new(PackageRelatesToPackage::LeftNodeId)
                            .string()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                PackageRelatesToPackage::Table,
                                (
                                    PackageRelatesToPackage::SbomId,
                                    PackageRelatesToPackage::LeftNodeId,
                                ),
                            )
                            .to(SbomNode::Table, (SbomNode::SbomId, SbomNode::NodeId)),
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
                        ColumnDef::new(PackageRelatesToPackage::RightNodeId)
                            .string()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(
                                PackageRelatesToPackage::Table,
                                (
                                    PackageRelatesToPackage::SbomId,
                                    PackageRelatesToPackage::RightNodeId,
                                ),
                            )
                            .to(SbomNode::Table, (SbomNode::SbomId, SbomNode::NodeId)),
                    )
                    .col(
                        ColumnDef::new(PackageRelatesToPackage::SbomId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PackageRelatesToPackage::SbomId)
                            .to(Sbom::Table, Sbom::SbomId),
                    )
                    .primary_key(
                        Index::create()
                            .col(PackageRelatesToPackage::SbomId)
                            .col(PackageRelatesToPackage::LeftNodeId)
                            .col(PackageRelatesToPackage::Relationship)
                            .col(PackageRelatesToPackage::RightNodeId),
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
    LeftNodeId,
    Relationship,
    RightNodeId,
    SbomId,
}
