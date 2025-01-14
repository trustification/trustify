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
                    .table(VersionedPurl::Table)
                    .name(Indexes::VersionedPurlBasePurlIdIDX.to_string())
                    .col(VersionedPurl::BasePurlId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(PurlStatus::Table)
                    .name(Indexes::PurlStatusBasePurlIdIDX.to_string())
                    .col(PurlStatus::BasePurlId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(SbomPackagePurlRef::Table)
                    .name(Indexes::SbomPackagePurlRefSbomIdIDX.to_string())
                    .col(SbomPackagePurlRef::SbomId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(SbomPackagePurlRef::Table)
                    .name(Indexes::SbomPackagePurlRefNodeIdIDX.to_string())
                    .col(SbomPackagePurlRef::NodeId)
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
                    .table(SbomPackagePurlRef::Table)
                    .name(Indexes::SbomPackagePurlRefNodeIdIDX.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomPackagePurlRef::Table)
                    .name(Indexes::SbomPackagePurlRefSbomIdIDX.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(PurlStatus::Table)
                    .name(Indexes::PurlStatusBasePurlIdIDX.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(VersionedPurl::Table)
                    .name(Indexes::VersionedPurlBasePurlIdIDX.to_string())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    VersionedPurlBasePurlIdIDX,
    PurlStatusBasePurlIdIDX,
    SbomPackagePurlRefSbomIdIDX,
    SbomPackagePurlRefNodeIdIDX,
}

#[derive(DeriveIden)]
enum VersionedPurl {
    Table,
    BasePurlId,
}

#[derive(DeriveIden)]
enum PurlStatus {
    Table,
    BasePurlId,
}

#[derive(DeriveIden)]
enum SbomPackagePurlRef {
    Table,
    SbomId,
    NodeId,
}
