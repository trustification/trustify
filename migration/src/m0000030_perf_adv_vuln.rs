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
                    .name(Indexes::VulnerabilityDescriptionVulnerabilityIdIdx.to_string())
                    .col(VulnerabilityDescription::VulnerabilityId)
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
                    .name(Indexes::VulnerabilityDescriptionVulnerabilityIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    VulnerabilityDescriptionVulnerabilityIdIdx,
}

#[derive(DeriveIden)]
pub enum VulnerabilityDescription {
    Table,
    VulnerabilityId,
}
