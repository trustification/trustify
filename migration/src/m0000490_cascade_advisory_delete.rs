use sea_orm_migration::prelude::*;

use crate::ForeignKeyAction::Cascade;
use crate::m0000310_alter_advisory_primary_key::Advisory;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut fk = purl_status_fk();
        fk.on_delete(Cascade);

        manager
            .alter_table(
                Table::alter()
                    .table(PurlStatus::Table)
                    .drop_foreign_key(Alias::new("package_status_advisory_id_fkey"))
                    .add_foreign_key(&fk)
                    .to_owned(),
            )
            .await?;

        let mut fk = advisory_vulnerability_fk();
        fk.on_delete(Cascade);
        manager
            .alter_table(
                Table::alter()
                    .table(AdvisoryVulnerability::Table)
                    .add_foreign_key(&fk)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut fk = purl_status_fk();
        fk.name("package_status_advisory_id_fkey");

        manager
            .alter_table(
                Table::alter()
                    .table(PurlStatus::Table)
                    .drop_foreign_key(Alias::new("purl_status_advisory_id_fkey"))
                    .add_foreign_key(&fk)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(AdvisoryVulnerability::Table)
                    .drop_foreign_key(Alias::new("advisory_vulnerability_advisory_id_fkey"))
                    .to_owned(),
            )
            .await
    }
}

fn purl_status_fk() -> TableForeignKey {
    TableForeignKey::new()
        .from_tbl(PurlStatus::Table)
        .from_col(PurlStatus::AdvisoryId)
        .to_tbl(Advisory::Table)
        .to_col(Advisory::Id)
        .to_owned()
}

fn advisory_vulnerability_fk() -> TableForeignKey {
    TableForeignKey::new()
        .from_tbl(AdvisoryVulnerability::Table)
        .from_col(AdvisoryVulnerability::AdvisoryId)
        .to_tbl(Advisory::Table)
        .to_col(Advisory::Id)
        .to_owned()
}

#[derive(DeriveIden)]
enum PurlStatus {
    Table,
    AdvisoryId,
}

#[derive(DeriveIden)]
enum AdvisoryVulnerability {
    Table,
    AdvisoryId,
}
