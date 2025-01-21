use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let data = [(14, "DescribedBy"), (15, "PackageOf")];

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
        let data = [(14, "DescribedBy"), (15, "PackageOf")];

        for (id, _) in data {
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
