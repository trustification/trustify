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
                    .table(SourceDocument::Table)
                    .name(Indexes::Sha256Index.to_string())
                    .col(SourceDocument::Sha256)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(SourceDocument::Table)
                    .name(Indexes::Sha384Index.to_string())
                    .col(SourceDocument::Sha384)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(SourceDocument::Table)
                    .name(Indexes::Sha512Index.to_string())
                    .col(SourceDocument::Sha512)
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
                    .table(SourceDocument::Table)
                    .name(Indexes::Sha512Index.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SourceDocument::Table)
                    .name(Indexes::Sha384Index.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SourceDocument::Table)
                    .name(Indexes::Sha256Index.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    Sha256Index,
    Sha384Index,
    Sha512Index,
}

#[derive(DeriveIden)]
enum SourceDocument {
    Table,
    Sha256,
    Sha384,
    Sha512,
}
