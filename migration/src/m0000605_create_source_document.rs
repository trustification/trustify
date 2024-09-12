use crate::UuidV4;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SourceDocument::Table)
                    .col(
                        ColumnDef::new(SourceDocument::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(ColumnDef::new(SourceDocument::Sha256).string().not_null())
                    .col(ColumnDef::new(SourceDocument::Sha384).string().not_null())
                    .col(ColumnDef::new(SourceDocument::Sha512).string().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .add_column(
                        ColumnDef::new(Sbom::SourceDocumentId)
                            .null()
                            .uuid()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .add_foreign_key(
                        TableForeignKey::new()
                            .to_tbl(SourceDocument::Table)
                            .to_col(SourceDocument::Id)
                            .from_tbl(Sbom::Table)
                            .from_col(Sbom::SourceDocumentId),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_column(
                        ColumnDef::new(Sbom::SourceDocumentId)
                            .null()
                            .uuid()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_foreign_key(
                        TableForeignKey::new()
                            .to_tbl(SourceDocument::Table)
                            .to_col(SourceDocument::Id)
                            .from_tbl(Advisory::SourceDocumentId)
                            .from_col(Advisory::SourceDocumentId),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "m0000605_create_source_document/data-migration-up.sql"
            ))
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .drop_column(Sbom::Sha256)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .drop_column(Sbom::Sha384)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .drop_column(Sbom::Sha512)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .drop_column(Advisory::Sha256)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .drop_column(Advisory::Sha384)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .drop_column(Advisory::Sha512)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .add_column(ColumnDef::new(Sbom::Sha256).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .add_column(ColumnDef::new(Sbom::Sha384).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .add_column(ColumnDef::new(Sbom::Sha512).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_column(ColumnDef::new(Advisory::Sha256).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_column(ColumnDef::new(Advisory::Sha384).string())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .add_column(ColumnDef::new(Advisory::Sha512).string())
                    .to_owned(),
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(include_str!(
                "./m0000605_create_source_document/data-migration-down.sql"
            ))
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .drop_column(Advisory::SourceDocumentId)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .drop_column(Sbom::SourceDocumentId)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(SourceDocument::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum SourceDocument {
    Table,
    Id,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    Sha256,
    Sha384,
    Sha512,
    SourceDocumentId,
}

#[derive(DeriveIden)]
enum Advisory {
    Table,
    Sha256,
    Sha384,
    Sha512,
    SourceDocumentId,
}
