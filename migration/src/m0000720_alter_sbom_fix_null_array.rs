use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.alter_table(Self::alter_table()).await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

impl Migration {
    fn alter_table() -> TableAlterStatement {
        Table::alter()
            .table(Sbom::Table)
            .modify_column(
                ColumnDef::new(Sbom::DataLicenses)
                    .array(ColumnType::Text)
                    .not_null()
                    .default(SimpleExpr::Custom("ARRAY[]::text[]".to_string()))
                    .to_owned(),
            )
            .to_owned()
    }
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    DataLicenses,
}

#[cfg(test)]
mod test {
    use crate::m0000720_alter_sbom_fix_null_array::Migration;
    use crate::PostgresQueryBuilder;

    #[test]
    fn test() {
        let sql = Migration::alter_table().build(PostgresQueryBuilder);
        assert_eq!(
            sql,
            r#"ALTER TABLE "sbom" ALTER COLUMN "data_licenses" TYPE text[], ALTER COLUMN "data_licenses" SET NOT NULL, ALTER COLUMN "data_licenses" SET DEFAULT ARRAY[]::text[]"#
        );
    }
}
