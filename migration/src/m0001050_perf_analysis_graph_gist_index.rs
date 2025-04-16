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
                "
                    DROP INDEX IF EXISTS sbom_node_node_id_gist;
                    CREATE INDEX sbom_node_node_id_gist ON sbom_node USING GIST (node_id gist_trgm_ops);
                ")
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "
                    DROP INDEX IF EXISTS sbom_node_node_id_gist;
                ",
            )
            .await
            .map(|_| ())?;

        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(DeriveIden)]
#[allow(dead_code)]
pub enum Indexes {
    SbomNodeNodeIdGistIdx,
}

#[derive(DeriveIden)]
#[allow(dead_code)]
pub enum SbomNode {
    Table,
    NodeId,
}
