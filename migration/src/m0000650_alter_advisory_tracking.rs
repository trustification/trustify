use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_column(ColumnDef::new(Advisory::Version).string().null().to_owned())
                    .add_column(
                        ColumnDef::new(Advisory::Deprecated)
                            .boolean()
                            .default(false)
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .table(Advisory::Table)
                    .name(Indexes::ByIdAndVersion.to_string())
                    .col(Advisory::Identifier)
                    .col(Advisory::Version)
                    .to_owned(),
            )
            .await?;

        // create the function, for updating the state

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000650_alter_advisory_tracking/update_deprecated_advisory.sql"
            ))
            .await
            .map(|_| ())?;

        // create the state of the "deprecated" column, running the function once
        manager
            .get_connection()
            .execute_unprepared(r#"SELECT update_deprecated_advisory();"#)
            .await?;

        manager
            .get_connection()
            .execute_unprepared(
                r#"
CREATE INDEX not_deprecated ON advisory (id)
    WHERE deprecated is not true;
"#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(r#"DROP FUNCTION update_deprecated_advisory"#)
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .table(Advisory::Table)
                    .name(Indexes::NotDeprecated.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .table(Advisory::Table)
                    .name(Indexes::ByIdAndVersion.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .drop_column(Advisory::Deprecated)
                    .drop_column(Advisory::Version)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Advisory {
    Table,
    Identifier,
    Version,
    Deprecated,
}

#[derive(DeriveIden)]
enum Indexes {
    ByIdAndVersion,
    NotDeprecated,
}
