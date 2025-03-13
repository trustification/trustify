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
                    .name(Indexes::AdvisoryModifiedIdx.to_string())
                    .col(Advisory::Modified)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisoryIdentifierIdx.to_string())
                    .col(Advisory::Identifier)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Sbom::Table)
                    .name(Indexes::SbomPublishedIdx.to_string())
                    .col(Sbom::Published)
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                "
                    DROP INDEX IF EXISTS purl_status_vulnerability_id_gist;
                    CREATE INDEX purl_status_vulnerability_id_gist ON purl_status USING GIST (vulnerability_id gist_trgm_ops);
                    DROP INDEX IF EXISTS advisory_vulnerability_vulnerability_id_gist;
                    CREATE INDEX advisory_vulnerability_vulnerability_id_gist ON advisory_vulnerability USING GIST (vulnerability_id gist_trgm_ops);
                ")
            .await
            .map(|_| ())?;

        // This is a stable change eg. no need for rollback
        manager
            .get_connection()
            .execute_unprepared(
                "
                    ALTER FUNCTION cvss3_a_score IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_ac_score IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_ac_score IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_c_score IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_exploitability IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_i_score IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_impact IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_pr_scoped_score IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_scope_changed IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_score IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_severity IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION cvss3_ui_score IMMUTABLE PARALLEL SAFE;
                    ALTER FUNCTION encode_uri_component IMMUTABLE PARALLEL SAFE;
                ",
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisoryIdentifierIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Advisory::Table)
                    .name(Indexes::AdvisoryModifiedIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(PurlStatus::Table)
                    .name(Indexes::PurlStatusVulnerabilityIdGistIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(AdvisoryVulnerability::Table)
                    .name(Indexes::AdvisoryVulnerabilityVulnerabilityIdGistIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(Sbom::Table)
                    .name(Indexes::SbomPublishedIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    SbomPublishedIdx,
    AdvisoryVulnerabilityVulnerabilityIdGistIdx,
    PurlStatusVulnerabilityIdGistIdx,
    AdvisoryIdentifierIdx,
    AdvisoryModifiedIdx,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    Published,
}

#[derive(DeriveIden)]
#[allow(dead_code)]
pub enum AdvisoryVulnerability {
    Table,
    VulnerabilityId,
}

#[derive(DeriveIden)]
#[allow(dead_code)]
pub enum PurlStatus {
    Table,
    VulnerabilityId,
}

#[derive(DeriveIden)]
pub enum Advisory {
    Table,
    Identifier,
    Modified,
}
