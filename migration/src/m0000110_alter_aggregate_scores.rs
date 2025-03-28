use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add columns to advisory
        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_column(ColumnDef::new(Advisory::AverageScore).double())
                    .add_column(
                        ColumnDef::new(Advisory::AverageSeverity)
                            .custom(Alias::new("cvss3_severity")),
                    )
                    .to_owned(),
            )
            .await?;

        // Add columns to vulnerability
        manager
            .alter_table(
                Table::alter()
                    .table(Vulnerability::Table)
                    .add_column(ColumnDef::new(Vulnerability::AverageScore).double())
                    .add_column(
                        ColumnDef::new(Vulnerability::AverageSeverity)
                            .custom(Alias::new("cvss3_severity")),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m000080_alter_aggregate_scores_fns/recalculate_cvss_aggregates.sql"
            ))
            .await
            .map(|_| ())?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m000080_alter_aggregate_scores_fns/update_cvss_aggregates_on_change.sql"
            ))
            .await
            .map(|_| ())?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop trigger
        manager
            .get_connection()
            .execute_unprepared("DROP TRIGGER IF EXISTS cvss3_insert_update_trigger ON cvss3")
            .await?;

        // Drop functions
        manager
            .get_connection()
            .execute_unprepared("DROP FUNCTION IF EXISTS update_cvss_aggregates_on_change")
            .await?;

        manager
            .get_connection()
            .execute_unprepared("DROP FUNCTION IF EXISTS recalculate_cvss_aggregates")
            .await?;

        // Drop columns from vulnerability
        manager
            .alter_table(
                Table::alter()
                    .table(Vulnerability::Table)
                    .drop_column(Vulnerability::AverageScore)
                    .drop_column(Vulnerability::AverageSeverity)
                    .to_owned(),
            )
            .await?;

        // Drop columns from advisory
        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .drop_column(Advisory::AverageScore)
                    .drop_column(Advisory::AverageSeverity)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
enum Advisory {
    Table,
    AverageScore,
    AverageSeverity,
}

#[derive(Iden)]
enum Vulnerability {
    Table,
    AverageScore,
    AverageSeverity,
}
