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
                    .table(Sbom::Table)
                    .name(Indexes::AdvisoryLabelsIdx.to_string())
                    .index_type(IndexType::Custom(gin()))
                    .col(Advisory::Labels)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Sbom::Table)
                    .name(Indexes::SbomLabelsIdx.to_string())
                    .index_type(IndexType::Custom(gin()))
                    .col(Sbom::Labels)
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
                    .table(Sbom::Table)
                    .name(Indexes::SbomLabelsIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisoryLabelsIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

fn gin() -> DynIden {
    Alias::new("GIN").into_iden()
}

#[derive(DeriveIden)]
pub enum Indexes {
    SbomLabelsIdx,
    AdvisoryLabelsIdx,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    Labels,
}

#[derive(DeriveIden)]
pub enum Advisory {
    Table,
    Labels,
}
