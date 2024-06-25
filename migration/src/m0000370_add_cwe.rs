use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(AdvisoryVulnerability::Table)
                    .add_column(ColumnDef::new(AdvisoryVulnerability::Cwe).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Vulnerability::Table)
                    .add_column(ColumnDef::new(Vulnerability::Cwe).string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Vulnerability::Table)
                    .drop_column(Vulnerability::Cwe)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(AdvisoryVulnerability::Table)
                    .drop_column(AdvisoryVulnerability::Cwe)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Vulnerability {
    Table,
    Cwe,
}

#[derive(DeriveIden)]
enum AdvisoryVulnerability {
    Table,
    Cwe,
}
