use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
#[allow(deprecated)]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute(
            db.get_database_backend().build(
                Query::update()
                    .table(VersionScheme::Table)
                    .value(VersionScheme::Id, "python")
                    .and_where(Expr::col(VersionScheme::Id).eq("pypi")),
            ),
        )
        .await?;

        db.execute_unprepared(include_str!("m0000850_python_version/pythonver_cmp.sql"))
            .await
            .map(|_| ())?;

        db.execute_unprepared(include_str!(
            "m0000850_python_version/python_version_matches.sql"
        ))
        .await
        .map(|_| ())?;

        db.execute_unprepared(include_str!("m0000850_python_version/version_matches.sql"))
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();

        db.execute_unprepared(include_str!("m0000670_version_cmp/version_matches.sql"))
            .await
            .map(|_| ())?;

        db.execute_unprepared("drop function python_version_matches")
            .await?;

        db.execute_unprepared("drop function pythonver_cmp").await?;

        insert(
            db,
            "pypi",
            "Python",
            Some("https://www.python.org/dev/peps/pep-0440/"),
        )
        .await?;
        update(db, "python", "pypi").await?;
        delete(db, "python").await?;

        Ok(())
    }
}

async fn insert(
    db: &SchemaManagerConnection<'_>,
    id: &str,
    name: &str,
    description: Option<&str>,
) -> Result<(), DbErr> {
    db.execute(
        db.get_database_backend().build(
            Query::insert()
                .into_table(VersionScheme::Table)
                .columns([
                    VersionScheme::Id,
                    VersionScheme::Name,
                    VersionScheme::Description,
                ])
                .values([
                    SimpleExpr::Value(Value::String(Some(Box::new(id.to_string())))),
                    SimpleExpr::Value(Value::String(Some(Box::new(name.to_string())))),
                    SimpleExpr::Value(Value::String(description.map(|e| Box::new(e.to_string())))),
                ])
                .map_err(|e| DbErr::Custom(e.to_string()))?,
        ),
    )
    .await?;
    Ok(())
}

async fn update(
    db: &SchemaManagerConnection<'_>,
    current_version_scheme: &str,
    update_to_version_scheme: &str,
) -> Result<(), DbErr> {
    db.execute(
        db.get_database_backend().build(
            Query::update()
                .table(VersionRange::Table)
                .value(
                    VersionRange::VersionSchemeId,
                    update_to_version_scheme.to_string(),
                )
                .and_where(
                    Expr::col(VersionRange::VersionSchemeId).eq(current_version_scheme.to_string()),
                ),
        ),
    )
    .await?;
    Ok(())
}

async fn delete(db: &SchemaManagerConnection<'_>, version_scheme: &str) -> Result<(), DbErr> {
    db.execute(
        db.get_database_backend().build(
            Query::delete()
                .from_table(VersionScheme::Table)
                .and_where(Expr::col(VersionScheme::Id).eq(version_scheme.to_string())),
        ),
    )
    .await?;
    Ok(())
}

#[derive(DeriveIden)]
pub enum VersionScheme {
    Table,
    Id,
    Name,
    Description,
}

#[derive(DeriveIden)]
enum VersionRange {
    Table,
    VersionSchemeId,
}
