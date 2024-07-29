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
                    .table(Advisory::Table)
                    .name(Indexes::AdvisorySha256Idx.to_string())
                    .col(Advisory::Sha256)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisorySha384Idx.to_string())
                    .col(Advisory::Sha384)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisorySha512Idx.to_string())
                    .col(Advisory::Sha512)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(AdvisoryVulnerability::Table)
                    .name(Indexes::AdvisoryVulnerabilityAdvisoryIdIdx.to_string())
                    .col(AdvisoryVulnerability::AdvisoryId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(Cvss3::Table)
                    .name(Indexes::Cvss3AdvIdVulnIdMinorVersionIdx.to_string())
                    .col(Cvss3::AdvisoryId)
                    .col(Cvss3::VulnerabilityId)
                    .col(Cvss3::MinorVersion)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .table(PurlStatus::Table)
                    .name(Indexes::PurlStatusComboIdx.to_string())
                    .col(PurlStatus::BasePurlId)
                    .col(PurlStatus::AdvisoryId)
                    .col(PurlStatus::VulnerabilityId)
                    .col(PurlStatus::StatusId)
                    .col(PurlStatus::ContextCpeId)
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
                    .table(PurlStatus::Table)
                    .name(Indexes::PurlStatusComboIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Cvss3::Table)
                    .name(Indexes::Cvss3AdvIdVulnIdMinorVersionIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(AdvisoryVulnerability::Table)
                    .name(Indexes::AdvisoryVulnerabilityAdvisoryIdIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisorySha512Idx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisorySha384Idx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisorySha256Idx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    AdvisorySha256Idx,
    AdvisorySha384Idx,
    AdvisorySha512Idx,
    AdvisoryVulnerabilityAdvisoryIdIdx,
    Cvss3AdvIdVulnIdMinorVersionIdx,
    PurlStatusComboIdx,
}

#[derive(DeriveIden)]
pub enum Advisory {
    Table,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(DeriveIden)]
pub enum AdvisoryVulnerability {
    Table,
    AdvisoryId,
}

#[derive(DeriveIden)]
pub enum Cvss3 {
    Table,
    AdvisoryId,
    VulnerabilityId,
    MinorVersion,
}

#[derive(DeriveIden)]
pub enum PurlStatus {
    Table,
    BasePurlId,
    AdvisoryId,
    VulnerabilityId,
    StatusId,
    ContextCpeId,
}
