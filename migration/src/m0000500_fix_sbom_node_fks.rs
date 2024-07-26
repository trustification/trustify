use sea_orm_migration::prelude::*;

use crate::ForeignKeyAction::Cascade;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, name, _) in dropped_fk() {
            manager
                .alter_table(
                    Table::alter()
                        .table(table)
                        .drop_foreign_key(Alias::new(name))
                        .to_owned(),
                )
                .await?;
        }
        for (table, name, mut fk) in added_fk() {
            fk.name(name);
            manager
                .alter_table(Table::alter().table(table).add_foreign_key(&fk).to_owned())
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, name, _) in added_fk() {
            manager
                .alter_table(
                    Table::alter()
                        .table(table)
                        .drop_foreign_key(Alias::new(name))
                        .to_owned(),
                )
                .await?;
        }
        for (table, name, mut fk) in dropped_fk() {
            fk.name(name);
            manager
                .alter_table(Table::alter().table(table).add_foreign_key(&fk).to_owned())
                .await?;
        }
        Ok(())
    }
}

fn added_fk() -> Vec<(DynIden, &'static str, TableForeignKey)> {
    vec![
        (
            SbomNode::Table.into_iden(),
            "sbom_node_sbom_id_fkey",
            TableForeignKey::new()
                .from_tbl(SbomNode::Table)
                .from_col(SbomNode::SbomId)
                .to_tbl(Sbom::Table)
                .to_col(Sbom::SbomId)
                .on_delete(Cascade)
                .to_owned(),
        ),
        (
            SbomFile::Table.into_iden(),
            "sbom_file_sbom_id_fkey",
            TableForeignKey::new()
                .from_tbl(SbomFile::Table)
                .from_col(SbomFile::SbomId)
                .to_tbl(Sbom::Table)
                .to_col(Sbom::SbomId)
                .on_delete(Cascade)
                .to_owned(),
        ),
        (
            SbomPackage::Table.into_iden(),
            "sbom_package_sbom_id_fkey",
            TableForeignKey::new()
                .from_tbl(SbomPackage::Table)
                .from_col(SbomPackage::SbomId)
                .to_tbl(Sbom::Table)
                .to_col(Sbom::SbomId)
                .on_delete(Cascade)
                .to_owned(),
        ),
    ]
}

fn dropped_fk() -> Vec<(DynIden, &'static str, TableForeignKey)> {
    vec![
        (
            Sbom::Table.into_iden(),
            "sbom_sbom_id_node_id_fkey",
            TableForeignKey::new()
                .from_tbl(Sbom::Table)
                .from_col(Sbom::SbomId)
                .from_col(Sbom::NodeId)
                .to_tbl(SbomNode::Table)
                .to_col(SbomNode::SbomId)
                .to_col(SbomNode::NodeId)
                .on_delete(Cascade)
                .to_owned(),
        ),
        (
            SbomFile::Table.into_iden(),
            "sbom_file_sbom_id_node_id_fkey",
            TableForeignKey::new()
                .from_tbl(SbomFile::Table)
                .from_col(SbomFile::SbomId)
                .from_col(SbomFile::NodeId)
                .to_tbl(SbomNode::Table)
                .to_col(SbomNode::SbomId)
                .to_col(SbomNode::NodeId)
                .on_delete(Cascade)
                .to_owned(),
        ),
        (
            SbomPackage::Table.into_iden(),
            "sbom_package_sbom_id_node_id_fkey",
            TableForeignKey::new()
                .from_tbl(SbomPackage::Table)
                .from_col(SbomPackage::SbomId)
                .from_col(SbomPackage::NodeId)
                .to_tbl(SbomNode::Table)
                .to_col(SbomNode::SbomId)
                .to_col(SbomNode::NodeId)
                .on_delete(Cascade)
                .to_owned(),
        ),
    ]
}

#[derive(DeriveIden)]
pub enum SbomNode {
    Table,
    SbomId,
    NodeId,
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    #[allow(clippy::enum_variant_names)]
    SbomId,
    NodeId,
}

#[derive(DeriveIden)]
enum SbomFile {
    Table,
    SbomId,
    NodeId,
}

#[derive(DeriveIden)]
enum SbomPackage {
    Table,
    SbomId,
    NodeId,
}
