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
                    .table(PurlStatus::Table)
                    .name(Indexes::PurlStatusVulnIdIDX.to_string())
                    .col(PurlStatus::VulnerabilityId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(SbomPackage::Table)
                    .name(Indexes::SbomPackageSbomIdNodeIdIDX.to_string())
                    .col(SbomPackage::SbomId)
                    .col(SbomPackage::NodeId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(SbomPackage::Table)
                    .name(Indexes::SbomPackageSbomIdIDX.to_string())
                    .col(SbomPackage::SbomId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(SbomNode::Table)
                    .name(Indexes::SbomNodeSbomIdNodeIdIDX.to_string())
                    .col(SbomNode::SbomId)
                    .col(SbomNode::NodeId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(SbomNode::Table)
                    .name(Indexes::SbomNodeSbomIdIDX.to_string())
                    .col(SbomNode::SbomId)
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
                    .table(SbomNode::Table)
                    .name(Indexes::SbomNodeSbomIdIDX.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomNode::Table)
                    .name(Indexes::SbomNodeSbomIdNodeIdIDX.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomPackage::Table)
                    .name(Indexes::SbomPackageSbomIdIDX.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomPackage::Table)
                    .name(Indexes::SbomPackageSbomIdNodeIdIDX.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(PurlStatus::Table)
                    .name(Indexes::PurlStatusVulnIdIDX.to_string())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    PurlStatusVulnIdIDX,
    SbomPackageSbomIdNodeIdIDX,
    SbomPackageSbomIdIDX,
    SbomNodeSbomIdNodeIdIDX,
    SbomNodeSbomIdIDX,
}

#[derive(DeriveIden)]
enum PurlStatus {
    Table,
    VulnerabilityId,
}

#[derive(DeriveIden)]
enum SbomPackage {
    Table,
    SbomId,
    NodeId,
}

#[derive(DeriveIden)]
enum SbomNode {
    Table,
    SbomId,
    NodeId,
}
