use crate::m0000011_create_cve::Cve;
use crate::m0000030_create_advisory::Advisory;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(AdvisoryCve::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(AdvisoryCve::AdvisoryId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(AdvisoryCve::AdvisoryId)
                            .to(Advisory::Table, Advisory::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(ColumnDef::new(AdvisoryCve::CveId).integer().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(AdvisoryCve::CveId)
                            .to(Cve::Table, Cve::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .primary_key(
                        Index::create()
                            .col(AdvisoryCve::AdvisoryId)
                            .col(AdvisoryCve::CveId),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(AdvisoryCve::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum AdvisoryCve {
    Table,
    AdvisoryId,
    CveId,
}
