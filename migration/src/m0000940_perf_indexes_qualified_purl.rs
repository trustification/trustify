use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        //set up indexes
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                    CREATE INDEX QualifiedPurlQualifierArchJsonGinIdx ON qualified_purl USING GIN ((qualifiers ->> 'arch') gin_trgm_ops);
                    CREATE INDEX QualifiedPurlQualifierDistroJsonGinIdx ON qualified_purl USING GIN ((qualifiers ->> 'distro') gin_trgm_ops);
                    CREATE INDEX QualifiedPurlQualifierRepositoryUrlJsonGinIdx ON qualified_purl USING GIN ((qualifiers ->> 'repository_url') gin_trgm_ops);
                    CREATE INDEX QualifiedPurlPurlTyJsonGinIdx ON qualified_purl USING GIN ((purl ->> 'ty') gin_trgm_ops);
                    CREATE INDEX QualifiedPurlPurlNamespaceJsonGinIdx ON qualified_purl USING GIN ((purl ->> 'namespace') gin_trgm_ops);
                    CREATE INDEX QualifiedPurlPurlNameJsonGinIdx ON qualified_purl USING GIN ((purl ->> 'name') gin_trgm_ops);
                    CREATE INDEX QualifiedPurlPurlVersionJsonGinIdx ON qualified_purl USING GIN ((purl ->> 'version') gin_trgm_ops);                    "#,
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
                    .name(Indexes::QualifiedPurlPurlVersionJsonGinIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlPurlNameJsonGinIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlPurlNamespaceJsonGinIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlPurlTyJsonGinIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlQualifierRepositoryUrlJsonGinIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlQualifierDistroJsonGinIdx.to_string())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(QualifiedPurl::Table)
                    .name(Indexes::QualifiedPurlQualifierArchJsonGinIdx.to_string())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    QualifiedPurlQualifierArchJsonGinIdx,
    QualifiedPurlQualifierDistroJsonGinIdx,
    QualifiedPurlQualifierRepositoryUrlJsonGinIdx,
    QualifiedPurlPurlTyJsonGinIdx,
    QualifiedPurlPurlNamespaceJsonGinIdx,
    QualifiedPurlPurlNameJsonGinIdx,
    QualifiedPurlPurlVersionJsonGinIdx,
}

#[derive(DeriveIden)]
enum QualifiedPurl {
    Table,
}
