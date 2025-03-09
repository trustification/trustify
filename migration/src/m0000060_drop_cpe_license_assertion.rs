use crate::UuidV4;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CpeLicenseAssertion::Table)
                    .col(
                        ColumnDef::new(CpeLicenseAssertion::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CpeLicenseAssertion::LicenseId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(CpeLicenseAssertion::LicenseId)
                            .to(License::Table, License::Id)
                            .on_delete(ForeignKeyAction::NoAction),
                    )
                    .col(
                        ColumnDef::new(CpeLicenseAssertion::SbomId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(CpeLicenseAssertion::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(ColumnDef::new(CpeLicenseAssertion::CpeId).uuid().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(CpeLicenseAssertion::CpeId)
                            .to(Cpe::Table, Cpe::Id)
                            .on_delete(ForeignKeyAction::NoAction),
                    )
                    .index(
                        Index::create()
                            .table(CpeLicenseAssertion::Table)
                            .name("cpe_license_assertion_idx")
                            .col(CpeLicenseAssertion::SbomId)
                            .col(CpeLicenseAssertion::LicenseId)
                            .col(CpeLicenseAssertion::CpeId)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(CpeLicenseAssertion::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum License {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    SbomId,
}

#[derive(DeriveIden)]
enum Cpe {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum CpeLicenseAssertion {
    Table,
    Id,
    SbomId,
    CpeId,
    LicenseId,
}
