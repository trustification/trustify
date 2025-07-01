use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .table(SbomExternalNode::Table)
                    .name(Indexes::SbomExternalNodeIdIdx.to_string())
                    .col(SbomExternalNode::NodeId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomExternalNode::Table)
                    .name(Indexes::SbomExternalNodeIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    SbomExternalNodeIdIdx,
}

#[derive(DeriveIden)]
pub enum SbomExternalNode {
    Table,
    NodeId,
}
