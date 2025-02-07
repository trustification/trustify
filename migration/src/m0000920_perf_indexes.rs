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
                    .table(VulnerabilityDescription::Table)
                    .name(Indexes::AdvisoryIdIndex.to_string())
                    .col(VulnerabilityDescription::AdvisoryId)
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
                    .table(VulnerabilityDescription::Table)
                    .name(Indexes::AdvisoryIdIndex.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    AdvisoryIdIndex,
}

#[derive(DeriveIden)]
enum VulnerabilityDescription {
    Table,
    AdvisoryId,
}
