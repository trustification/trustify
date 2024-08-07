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
                    .table(Cvss3::Table)
                    .name(Indexes::Cvss3VulnIdIdx.to_string())
                    .col(Cvss3::VulnerabilityId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Cvss3::Table)
                    .name(Indexes::Cvss3AdvIdIdx.to_string())
                    .col(Cvss3::AdvisoryId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Cvss4::Table)
                    .name(Indexes::Cvss4VulnIdIdx.to_string())
                    .col(Cvss4::VulnerabilityId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Cvss4::Table)
                    .name(Indexes::Cvss4AdvIdIdx.to_string())
                    .col(Cvss4::AdvisoryId)
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
                    .table(Cvss4::Table)
                    .name(Indexes::Cvss4AdvIdIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Cvss4::Table)
                    .name(Indexes::Cvss4VulnIdIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Cvss3::Table)
                    .name(Indexes::Cvss3AdvIdIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Cvss3::Table)
                    .name(Indexes::Cvss3VulnIdIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    Cvss3VulnIdIdx,
    Cvss3AdvIdIdx,
    Cvss4VulnIdIdx,
    Cvss4AdvIdIdx,
}

#[derive(DeriveIden)]
pub enum Cvss3 {
    Table,
    AdvisoryId,
    VulnerabilityId,
}

#[derive(DeriveIden)]
pub enum Cvss4 {
    Table,
    AdvisoryId,
    VulnerabilityId,
}
