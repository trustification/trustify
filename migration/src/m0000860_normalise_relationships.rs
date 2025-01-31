use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;
const DATA: [(i32, &str); 14] = [
    (0, "Contains"),
    (1, "Dependency"),
    (2, "DevDependency"),
    (3, "OptionalDependency"),
    (4, "ProvidedDependency"),
    (5, "TestDependency"),
    (6, "RuntimeDependency"),
    (7, "Example"),
    (8, "Generates"),
    (10, "Variant"),
    (11, "BuildTool"),
    (12, "DevTool"),
    (13, "Describes"),
    (14, "Package"),
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (id, description) in DATA {
            let insert = Query::insert()
                .into_table(Relationship::Table)
                .columns([Relationship::Id, Relationship::Description])
                .values_panic([id.into(), description.into()])
                .on_conflict(
                    OnConflict::columns([Relationship::Id])
                        .update_columns([Relationship::Description])
                        .to_owned(),
                )
                .to_owned();

            manager.exec_stmt(insert).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (id, _) in DATA {
            let insert = Query::delete()
                .from_table(Relationship::Table)
                .and_where(Expr::col(Relationship::Id).lt(id))
                .to_owned();

            manager.exec_stmt(insert).await?;
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Relationship {
    Table,
    Id,
    Description,
}
