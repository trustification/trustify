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
                CREATE INDEX SbomNodeNameGinIdx ON sbom_node USING GIN ((name::text) gin_trgm_ops);
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
                    .table(SbomNode::Table)
                    .name(Indexes::SbomNodeNameGinIdx.to_string())
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
enum Indexes {
    SbomNodeNameGinIdx,
}

#[derive(DeriveIden)]
enum SbomNode {
    Table,
}
