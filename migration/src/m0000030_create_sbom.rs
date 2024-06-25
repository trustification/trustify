use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SbomNode::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(SbomNode::SbomId).uuid().not_null())
                    .col(ColumnDef::new(SbomNode::NodeId).string().not_null())
                    .col(ColumnDef::new(SbomNode::Name).string().not_null())
                    .primary_key(Index::create().col(SbomNode::SbomId).col(SbomNode::NodeId))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Sbom::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Sbom::SbomId).uuid().not_null())
                    .col(ColumnDef::new(Sbom::NodeId).string().not_null())
                    .col(ColumnDef::new(Sbom::Location).string().not_null())
                    .col(ColumnDef::new(Sbom::DocumentId).string().not_null())
                    .col(ColumnDef::new(Sbom::Sha256).string().not_null())
                    .col(ColumnDef::new(Sbom::Published).timestamp_with_time_zone())
                    .col(ColumnDef::new(Sbom::Authors).array(ColumnType::String(None)))
                    .primary_key(Index::create().col(Sbom::SbomId))
                    .to_owned(),
            )
            .await?;

        manager
            .create_foreign_key(
                ForeignKey::create()
                    .from(Sbom::Table, (Sbom::SbomId, Sbom::NodeId))
                    .to(SbomNode::Table, (SbomNode::SbomId, SbomNode::NodeId))
                    .on_delete(ForeignKeyAction::Cascade)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Sbom::Table).if_exists().to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(SbomNode::Table).if_exists().to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum SbomNode {
    Table,
    SbomId,
    NodeId,
    Name,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    // an internal SBOM id
    #[allow(clippy::enum_variant_names)]
    SbomId,
    NodeId,
    Location,
    Sha256,
    // the SPDX namespace
    DocumentId,

    Published,
    Authors,
}
