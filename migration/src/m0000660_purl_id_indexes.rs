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
                    .table(BasePurl::Table)
                    .name(Indexes::BasePurlIdIdx.to_string())
                    .col(BasePurl::Id)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(VersionedPurl::Table)
                    .name(Indexes::VersionedPurlIdIdx.to_string())
                    .col(VersionedPurl::Id)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlIdIdx.to_string())
                    .col(QualifiedPurl::Id)
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
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlIdIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(VersionedPurl::Table)
                    .name(Indexes::VersionedPurlIdIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(BasePurl::Table)
                    .name(Indexes::BasePurlIdIdx.to_string())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    BasePurlIdIdx,
    VersionedPurlIdIdx,
    QualifiedPurlIdIdx,
}

#[derive(DeriveIden)]
enum BasePurl {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum VersionedPurl {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum QualifiedPurl {
    Table,
    Id,
}
