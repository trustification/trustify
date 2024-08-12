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
                    .table(SbomPackagePurlRef::Table)
                    .name(Indexes::SbomPackagePurlRefQualPurlIdIdx.to_string())
                    .col(SbomPackagePurlRef::QualifiedPurlId)
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
                    .name(Indexes::SbomPackagePurlRefQualPurlIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    SbomPackagePurlRefQualPurlIdIdx,
}

#[derive(DeriveIden)]
pub enum SbomPackagePurlRef {
    Table,
    QualifiedPurlId,
}
