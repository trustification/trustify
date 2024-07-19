use sea_orm_migration::prelude::*;

use crate::m0000030_create_sbom::{Sbom, SbomNode};
use crate::m0000220_create_package_relates_to_package::PackageRelatesToPackage;
use crate::ForeignKeyAction::Cascade;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let (mut fk1, mut fk2, mut fk3) = fks();
        fk1.on_delete(Cascade);
        fk2.on_delete(Cascade);
        fk3.on_delete(Cascade);

        manager
            .alter_table(
                Table::alter()
                    .table(PackageRelatesToPackage::Table)
                    .drop_foreign_key(Alias::new("package_relates_to_package_sbom_id_fkey"))
                    .drop_foreign_key(Alias::new(
                        "package_relates_to_package_sbom_id_right_node_id_fkey",
                    ))
                    .drop_foreign_key(Alias::new(
                        "package_relates_to_package_sbom_id_left_node_id_fkey",
                    ))
                    .add_foreign_key(&fk1)
                    .add_foreign_key(&fk2)
                    .add_foreign_key(&fk3)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let (fk1, fk2, fk3) = fks();

        manager
            .alter_table(
                Table::alter()
                    .table(PackageRelatesToPackage::Table)
                    .drop_foreign_key(Alias::new("package_relates_to_package_sbom_id_fkey"))
                    .drop_foreign_key(Alias::new(
                        "package_relates_to_package_sbom_id_right_node_id_fkey",
                    ))
                    .drop_foreign_key(Alias::new(
                        "package_relates_to_package_sbom_id_left_node_id_fkey",
                    ))
                    .add_foreign_key(&fk1)
                    .add_foreign_key(&fk2)
                    .add_foreign_key(&fk3)
                    .to_owned(),
            )
            .await
    }
}

fn fks() -> (TableForeignKey, TableForeignKey, TableForeignKey) {
    (
        TableForeignKey::new()
            .from_tbl(PackageRelatesToPackage::Table)
            .from_col(PackageRelatesToPackage::SbomId)
            .from_col(PackageRelatesToPackage::LeftNodeId)
            .to_tbl(SbomNode::Table)
            .to_col(SbomNode::SbomId)
            .to_col(SbomNode::NodeId)
            .to_owned(),
        TableForeignKey::new()
            .from_tbl(PackageRelatesToPackage::Table)
            .from_col(PackageRelatesToPackage::SbomId)
            .from_col(PackageRelatesToPackage::RightNodeId)
            .to_tbl(SbomNode::Table)
            .to_col(SbomNode::SbomId)
            .to_col(SbomNode::NodeId)
            .to_owned(),
        TableForeignKey::new()
            .from_tbl(PackageRelatesToPackage::Table)
            .from_col(PackageRelatesToPackage::SbomId)
            .to_tbl(Sbom::Table)
            .to_col(Sbom::SbomId)
            .to_owned(),
    )
}
