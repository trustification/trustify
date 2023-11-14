use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(Relationship::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Relationship::Id)
                            .integer()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Relationship::Description)
                            .string()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        let data = [
            (0, "ContainedBy"),
            (1, "DependencyOf"),
            (2, "DevDependencyOf"),
            (3, "OptionalDependencyOf"),
            (4, "ProvidedDependencyOf"),
            (5, "TestDependencyOf"),
            (6, "RuntimeDependencyOf"),
            (7, "ExampleOf"),
            (8, "GeneratedFrom"),
            (9, "AncestorOf"),
            (10, "VariantOf"),
            (11, "BuildToolOf"),
            (12, "DevToolOf"),
        ];

        for (id, description) in data {
            let insert = Query::insert()
                .into_table(Relationship::Table)
                .columns([Relationship::Id, Relationship::Description])
                .values_panic([id.into(), description.into()])
                .to_owned();

            manager.exec_stmt(insert).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(Relationship::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
pub enum Relationship {
    Table,
    Id,
    Description,
}
