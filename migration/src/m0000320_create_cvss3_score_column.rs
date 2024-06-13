use crate::sea_orm::{IntoIdentity, Statement};
use sea_orm_migration::prelude::*;
use std::str::FromStr;

use trustify_cvss::cvss3::Cvss3Base;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add `score` to cvss3 table, allowed to be null
        manager
            .alter_table(
                Table::alter()
                    .table(Cvss3::Table)
                    .add_column(ColumnDef::new(Cvss3::Score).decimal())
                    .to_owned(),
            )
            .await?;

        // Use the Rust codepath to calculate scores for each row and update.

        let results = manager
            .get_connection()
            .query_all(Statement::from_string(
                manager.get_database_backend(),
                Query::select()
                    .columns([
                        Cvss3::Id,
                        Cvss3::MinorVersion,
                        Cvss3::AV,
                        Cvss3::AC,
                        Cvss3::PR,
                        Cvss3::UI,
                        Cvss3::S,
                        Cvss3::C,
                        Cvss3::I,
                        Cvss3::A,
                    ])
                    .from(Cvss3::Table)
                    .to_string(PostgresQueryBuilder),
            ))
            .await?;

        for row in results {
            let id: i32 = row.try_get("", "id")?;
            let minor_version: i32 = row.try_get("", "minor_version")?;
            let av: String = row.try_get("", "av")?;
            let ac: String = row.try_get("", "ac")?;
            let pr: String = row.try_get("", "pr")?;
            let ui: String = row.try_get("", "ui")?;
            let s: String = row.try_get("", "s")?;
            let c: String = row.try_get("", "c")?;
            let i: String = row.try_get("", "i")?;
            let a: String = row.try_get("", "a")?;

            let vector = format!(
                "CVSS:3.{minor_version}/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
            );

            if let Ok(cvss3) = Cvss3Base::from_str(&vector) {
                let score = cvss3.score().roundup().value();

                let _ = manager
                    .get_connection()
                    .execute_unprepared(
                        &Query::update()
                            .table(Cvss3::Table)
                            .value(Cvss3::Score, score)
                            .and_where(Expr::col("id".into_identity()).eq(id))
                            .to_string(PostgresQueryBuilder),
                    )
                    .await?;
            }
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Cvss3::Table)
                    .modify_column(ColumnDef::new(Cvss3::Score).not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Cvss3::Table)
                    .drop_column(Cvss3::Score)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Cvss3 {
    Table,
    Score,

    Id,
    MinorVersion,
    AV,
    AC,
    PR,
    UI,
    S,
    C,
    I,
    A,
}
