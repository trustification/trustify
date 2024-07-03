use crate::sea_orm::IntoIdentity;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(PurlStatus::Table)
                    .add_column(ColumnDef::new(PurlStatus::ContextCpeId).uuid())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(PurlStatus::Table)
                    .add_foreign_key(
                        TableForeignKey::new()
                            .name("purl_status_cpe_fk")
                            .from_col(PurlStatus::ContextCpeId)
                            .to_tbl(Cpe::Table)
                            .to_col(Cpe::Id),
                    )
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
                    .drop_foreign_key("purl_status_cpe_fk".into_identity())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(PurlStatus::Table)
                    .drop_column(PurlStatus::ContextCpeId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum PurlStatus {
    Table,
    ContextCpeId,
}

#[derive(DeriveIden)]
enum Cpe {
    Table,
    Id,
}
