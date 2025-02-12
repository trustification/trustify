use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        //drop old indexes (Note: we do not need to fallback as they are completely unused now)
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

        //set up sort indexes for qualified_purl
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE INDEX QualifiedPurlQualifierArchJsonSortIdx ON qualified_purl ((qualifiers ->> 'arch'));
                CREATE INDEX QualifiedPurlQualifierDistroJsonSortIdx ON qualified_purl ((qualifiers ->> 'distro'));
                CREATE INDEX QualifiedPurlPurlNamespaceJsonSortIdx ON qualified_purl ((purl ->> 'namespace'));
                CREATE INDEX QualifiedPurlPurlTyJsonSortIdx ON qualified_purl ((purl ->> 'ty'));
                CREATE INDEX QualifiedPurlPurlNameJsonSortIdx ON qualified_purl ((purl ->> 'name'));
                CREATE INDEX QualifiedPurlPurlVersionJsonSortIdx ON qualified_purl ((purl ->> 'version'));
                "#,
            )
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
                    .name(Indexes::QualifiedPurlPurlVersionJsonSortIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlPurlNameJsonSortIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlPurlTyJsonSortIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlPurlNamespaceJsonSortIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlQualifierDistroJsonSortIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlQualifierArchJsonSortIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    QualifiedPurlQualifierArchJsonSortIdx,
    QualifiedPurlQualifierDistroJsonSortIdx,
    QualifiedPurlPurlNamespaceJsonSortIdx,
    QualifiedPurlPurlTyJsonSortIdx,
    QualifiedPurlPurlNameJsonSortIdx,
    QualifiedPurlPurlVersionJsonSortIdx,
    QualifiedPurlNameJsonGistIdx,
    QualifiedPurlVersionJsonGistIdx,
    QualifiedPurlNamespaceJsonGistIdx,
    QualifiedPurlTypeJsonGistIdx,
}

#[derive(DeriveIden)]
enum QualifiedPurl {
    Table,
}
