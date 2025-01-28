use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;
const DATA: [(i32, &str); 16] = [
    (0, "Contains"),
    (1, "Dependency"),
    (2, "DevDependency"),
    (3, "OptionalDependency"),
    (4, "ProvidedDependency"),
    (5, "TestDependency"),
    (6, "RuntimeDependency"),
    (7, "Example"),
    (8, "Generates"),
    (9, "AncestorOf"),
    (10, "Variant"),
    (11, "BuildTool"),
    (12, "DevTool"),
    (13, "Describes"),
    (14, "Package"),
    (15, "Undefined"),
];

use super::m0000210_create_relationship::DATA as OLD_DATA;

async fn insert(
    manager: &SchemaManager<'_>,
    data: &'static [(i32, &'static str)],
) -> Result<(), DbErr> {
    for (id, description) in data {
        let insert = Query::insert()
            .into_table(Relationship::Table)
            .columns([Relationship::Id, Relationship::Description])
            .values_panic([(*id).into(), (*description).into()])
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

async fn delete(
    manager: &SchemaManager<'_>,
    data: &'static [(i32, &'static str)],
) -> Result<(), DbErr> {
    for (id, _) in data {
        let insert = Query::delete()
            .from_table(Relationship::Table)
            .and_where(Expr::col(Relationship::Id).lt(*id))
            .to_owned();

        manager.exec_stmt(insert).await?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        delete(manager, &OLD_DATA).await?;
        insert(manager, &DATA).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        delete(manager, &DATA).await?;
        insert(manager, &OLD_DATA).await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Relationship {
    Table,
    Id,
    Description,
}
