use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .table(PackageStatus::Table)
                    .name("package_status_idx")
                    .col(PackageStatus::PackageId)
                    .col(PackageStatus::AdvisoryId)
                    .col(PackageStatus::StatusId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .table(PackageStatus::Table)
                    .name("package_status_idx")
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum PackageStatus {
    Table,
    AdvisoryId,
    StatusId,
    PackageId,
}
