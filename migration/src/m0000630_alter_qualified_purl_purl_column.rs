use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        //create jsonb purl column
        manager
            .alter_table(
                Table::alter()
                    .table(QualifiedPurl::Table)
                    .add_column(ColumnDef::new(QualifiedPurl::Purl).json_binary())
                    .to_owned(),
            )
            .await?;

        //set up indexes
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE INDEX QualifiedPurlNameJsonGistIdx ON qualified_purl USING GIST ((purl ->> 'name') gist_trgm_ops);
                CREATE INDEX QualifiedPurlVersionJsonGistIdx ON qualified_purl USING GIST ((purl ->> 'version') gist_trgm_ops);
                CREATE INDEX QualifiedPurlNamespaceJsonGistIdx ON qualified_purl USING GIST ((purl ->> 'namespace') gist_trgm_ops);
                CREATE INDEX QualifiedPurlTypeJsonGistIdx ON qualified_purl USING GIST ((purl ->> 'ty') gist_trgm_ops);
                "#,
            )
            .await?;

        //data migration
        let _data_migration_result = manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000630_alter_qualified_purl_purl_column/data-migration-up.sql"
            ))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        //drop index
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlNameJsonGistIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlVersionJsonGistIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlNamespaceJsonGistIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlTypeJsonGistIdx.to_string())
                    .to_owned(),
            )
            .await?;

        // Drop the column in the down migration
        manager
            .alter_table(
                Table::alter()
                    .table(QualifiedPurl::Table)
                    .drop_column(QualifiedPurl::Purl) // Just specify the column name
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
pub enum Indexes {
    QualifiedPurlNameJsonGistIdx,
    QualifiedPurlVersionJsonGistIdx,
    QualifiedPurlNamespaceJsonGistIdx,
    QualifiedPurlTypeJsonGistIdx,
}

#[derive(DeriveIden)]
enum QualifiedPurl {
    Table,
    Purl,
}
