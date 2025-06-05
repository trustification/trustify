use crate::extension::postgres::Type;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_type(
                Type::create()
                    .as_enum(SignatureType::Table)
                    .values(["pgp"])
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SourceDocumentSignature::Table)
                    .col(
                        ColumnDef::new(SourceDocumentSignature::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(SourceDocumentSignature::DocumentId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SourceDocumentSignature::Type)
                            .enumeration(SignatureType::Table, ["pgp"])
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SourceDocumentSignature::Payload)
                            .blob()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(SourceDocumentSignature::DocumentId)
                            .to(SourceDocument::Table, SourceDocument::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .modify_column(ColumnDef::new(Advisory::SourceDocumentId).not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .modify_column(ColumnDef::new(Sbom::SourceDocumentId).not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(TrustAnchor::Table)
                    .col(
                        ColumnDef::new(TrustAnchor::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(TrustAnchor::Revision).uuid().not_null())
                    .col(
                        ColumnDef::new(TrustAnchor::Disabled)
                            .boolean()
                            .default(false)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrustAnchor::Description)
                            .not_null()
                            .default("")
                            .string(),
                    )
                    .col(
                        ColumnDef::new(TrustAnchor::Type)
                            .enumeration(SignatureType::Table, ["pgp"])
                            .not_null(),
                    )
                    .col(ColumnDef::new(TrustAnchor::Payload).blob().not_null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().if_exists().table(TrustAnchor::Table).take())
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Sbom::Table)
                    .modify_column(ColumnDef::new(Sbom::SourceDocumentId).null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Advisory::Table)
                    .modify_column(ColumnDef::new(Advisory::SourceDocumentId).null())
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .if_exists()
                    .table(SourceDocumentSignature::Table)
                    .take(),
            )
            .await?;

        manager
            .drop_type(
                Type::drop()
                    .if_exists()
                    .name(SignatureType::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SourceDocument {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Advisory {
    Table,
    SourceDocumentId,
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    SourceDocumentId,
}

#[derive(DeriveIden)]
enum SourceDocumentSignature {
    Table,
    Id,
    DocumentId,
    Type,
    Payload,
}

#[derive(DeriveIden)]
enum SignatureType {
    Table,
}

#[derive(DeriveIden)]
enum TrustAnchor {
    Table,
    Id,
    Revision,
    Disabled,
    Description,
    Type,
    Payload,
}
