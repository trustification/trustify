use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .rename_table(
                Table::rename()
                    .table(PackageStatus::Table, PurlStatus::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(PurlStatus::Table)
                    .rename_column(PurlStatus::PackageId, PurlStatus::BasePurlId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(PurlStatus::Table)
                    .rename_column(PurlStatus::BasePurlId, PurlStatus::PackageId)
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(PurlStatus::Table, PackageStatus::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum PackageStatus {
    Table,
}

#[derive(DeriveIden)]
enum PurlStatus {
    Table,
    PackageId,
    BasePurlId,
}
