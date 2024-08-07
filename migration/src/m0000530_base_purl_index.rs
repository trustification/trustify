use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                CREATE EXTENSION IF NOT EXISTS pg_trgm;
                CREATE INDEX BasePurlTypeGinIdx ON base_purl USING GIN ((type) gin_trgm_ops);
                CREATE INDEX BasePurlNamespaceGinIdx ON base_purl USING GIN ((namespace) gin_trgm_ops);
                CREATE INDEX BasePurlNameGinIdx ON base_purl USING GIN ((name) gin_trgm_ops);
                "#,
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(BasePurl::Table)
                    .name(Indexes::BasePurlNameGinIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(BasePurl::Table)
                    .name(Indexes::BasePurlNamespaceGinIdx.to_string())
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(BasePurl::Table)
                    .name(Indexes::BasePurlTypeGinIdx.to_string())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    BasePurlTypeGinIdx,
    BasePurlNamespaceGinIdx,
    BasePurlNameGinIdx,
}

#[derive(DeriveIden)]
enum BasePurl {
    Table,
}
