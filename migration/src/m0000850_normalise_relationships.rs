use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;
const DATA: [(i32, &str); 14] = [
    (16, "Contains"),
    (17, "Dependency"),
    (18, "DevDependency"),
    (19, "OptionalDependency"),
    (20, "ProvidedDependency"),
    (21, "TestDependency"),
    (22, "RuntimeDependency"),
    (23, "Example"),
    (24, "Generates"),
    (25, "Variant"),
    (26, "BuildTool"),
    (27, "DevTool"),
    (28, "Describes"),
    (29, "Packages"),
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (id, description) in DATA {
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
