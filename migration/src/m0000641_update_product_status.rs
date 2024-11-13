use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ProductStatus::Table)
                    .add_column(ColumnDef::new(ProductStatus::Package).string())
                    .to_owned(),
            )
            .await?;

        // Transform data: populate `package` from `base_purl`
        let update_sql = r#"
            UPDATE product_status
            SET package =
                (SELECT namespace || '/' || name FROM base_purl WHERE base_purl.id = product_status.base_purl_id)
            WHERE base_purl_id IS NOT NULL;
        "#;
        manager
            .get_connection()
            .execute_unprepared(update_sql)
            .await?;

        // Delete original `purl_status` entries now that data has been migrated
        let delete_statuses_sql = r#"
            DELETE FROM purl_status
            WHERE base_purl_id IN (
                SELECT id FROM base_purl
                WHERE id IN (SELECT DISTINCT base_purl_id FROM product_status WHERE base_purl_id IS NOT NULL)
                AND TYPE = 'generic'
            )
        "#;
        manager
            .get_connection()
            .execute_unprepared(delete_statuses_sql)
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ProductStatus::Table)
                    .drop_column(ProductStatus::BasePurlId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ProductStatus::Table)
                    .add_column(ColumnDef::new(ProductStatus::BasePurlId).uuid())
                    .add_foreign_key(
                        TableForeignKey::new()
                            .from_tbl(ProductStatus::Table)
                            .from_col(ProductStatus::BasePurlId)
                            .to_tbl(BasePurl::Table)
                            .to_col(BasePurl::Id),
                    )
                    .to_owned(),
            )
            .await?;

        // Insert new rows into `base_purl` for each unique `package`, with type set to 'generic'
        let insert_sql = r#"
            INSERT INTO base_purl (namespace, name, type)
            SELECT
                split_part(package, '/', 1) AS namespace,
                split_part(package, '/', 2) AS name,
                'generic' AS type
            FROM product_status
            WHERE package IS NOT NULL
            ON CONFLICT DO NOTHING;
        "#;
        manager
            .get_connection()
            .execute_unprepared(insert_sql)
            .await?;

        // Update `product_status.base_purl_id` to reference the inserted `base_purl` entries
        let update_sql = r#"
            UPDATE product_status
            SET base_purl_id = (
                SELECT id FROM base_purl
                WHERE
                    base_purl.namespace = split_part(product_status.package, '/', 1)
                    AND base_purl.name = split_part(product_status.package, '/', 2)
            )
            WHERE package IS NOT NULL;
        "#;
        manager
            .get_connection()
            .execute_unprepared(update_sql)
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(ProductStatus::Table)
                    .drop_column(ProductStatus::Package)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum ProductStatus {
    Table,
    BasePurlId,
    Package,
}

#[derive(DeriveIden)]
enum BasePurl {
    Table,
    Id,
}
