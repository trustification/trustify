use crate::UuidV4;
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
                    .table(Status::Table)
                    .col(
                        ColumnDef::new(Status::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Status::Slug).string().not_null())
                    .col(ColumnDef::new(Status::Name).string().not_null())
                    .col(ColumnDef::new(Status::Description).string())
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();

        insert(db, "affected", "Affected", "Vulnerabililty affects").await?;
        insert(
            db,
            "not_affected",
            "Not Affected",
            "Vulnerabililty does not affect",
        )
        .await?;
        insert(db, "fixed", "Fixed", "Vulnerabililty is fixed").await?;
        insert(
            db,
            "under_investigation",
            "Under Investigation",
            "Vulnerabililty is under investigation",
        )
        .await?;
        insert(db, "fixed", "Fixed", "Vulnerabililty is fixed").await?;
        insert(
            db,
            "recommended",
            "Recommended",
            "Vulnerabililty is fixed & recommended",
        )
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Status::Table).if_exists().to_owned())
            .await
    }
}

async fn insert(
    db: &SchemaManagerConnection<'_>,
    slug: &str,
    name: &str,
    description: &str,
) -> Result<(), DbErr> {
    db.execute(
        db.get_database_backend().build(
            Query::insert()
                .into_table(Status::Table)
                .columns([Status::Slug, Status::Name, Status::Description])
                .values([
                    SimpleExpr::Value(Value::String(Some(Box::new(slug.to_string())))),
                    SimpleExpr::Value(Value::String(Some(Box::new(name.to_string())))),
                    SimpleExpr::Value(Value::String(Some(Box::new(description.to_string())))),
                ])
                .map_err(|e| DbErr::Custom(e.to_string()))?,
        ),
    )
    .await?;
    Ok(())
}

#[derive(DeriveIden)]
enum Status {
    Table,
    Id,
    Slug,
    Name,
    Description,
}
