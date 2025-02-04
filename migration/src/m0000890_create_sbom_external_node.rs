use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

pub(crate) const _EXTERNAL_TYPE_ENUM: [(i32, &str); 3] =
    [(0, "SPDX"), (1, "CDX"), (2, "RH_PRODUCT_COMPONENT")];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SbomExternalNode::Table)
                    .col(ColumnDef::new(SbomExternalNode::SbomId).uuid().not_null())
                    .col(ColumnDef::new(SbomExternalNode::NodeId).string().not_null())
                    .primary_key(
                        Index::create()
                            .col(SbomExternalNode::SbomId)
                            .col(SbomExternalNode::NodeId),
                    )
                    .col(
                        ColumnDef::new(SbomExternalNode::ExternalDocRef)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SbomExternalNode::ExternalNodeRef)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SbomExternalNode::ExternalType)
                            .integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(SbomExternalNode::TargetSbomId).uuid())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(SbomExternalNode::Table)
                    .name(Indexes::SbomExternalNodeExternalDocRefIdx.to_string())
                    .col(SbomExternalNode::ExternalType)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(SbomExternalNode::Table)
                    .name(Indexes::SbomExternalNodeExternalNodeRefIdx.to_string())
                    .col(SbomExternalNode::ExternalDocRef)
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
                    .name(Indexes::SbomExternalNodeExternalNodeRefIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomExternalNode::Table)
                    .name(Indexes::SbomExternalNodeExternalDocRefIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(SbomExternalNode::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Indexes {
    SbomExternalNodeExternalDocRefIdx,
    SbomExternalNodeExternalNodeRefIdx,
}

#[derive(DeriveIden)]
enum SbomExternalNode {
    Table,
    SbomId,
    NodeId,
    ExternalDocRef,
    ExternalNodeRef,
    ExternalType,
    TargetSbomId,
}
