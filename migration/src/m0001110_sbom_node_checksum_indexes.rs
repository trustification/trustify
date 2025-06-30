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
                    .table(SbomNodeChecksum::Table)
                    .name(Indexes::SbomNodeChecksumSbomIdIdx.to_string())
                    .col(SbomNodeChecksum::SbomId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(SbomNodeChecksum::Table)
                    .name(Indexes::SbomNodeChecksumNodeIdIdx.to_string())
                    .col(SbomNodeChecksum::NodeId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(SbomNodeChecksum::Table)
                    .name(Indexes::SbomNodeChecksumValueIdx.to_string())
                    .col(SbomNodeChecksum::Value)
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
                    .table(SbomNodeChecksum::Table)
                    .name(Indexes::SbomNodeChecksumValueIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomNodeChecksum::Table)
                    .name(Indexes::SbomNodeChecksumNodeIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomNodeChecksum::Table)
                    .name(Indexes::SbomNodeChecksumSbomIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    SbomNodeChecksumSbomIdIdx,
    SbomNodeChecksumNodeIdIdx,
    SbomNodeChecksumValueIdx,
}

#[derive(DeriveIden)]
pub enum SbomNodeChecksum {
    Table,
    SbomId,
    NodeId,
    Value,
}
