use crate::UuidV4;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(PurlLicenseAssertion::Table).to_owned())
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(PurlLicenseAssertion::Table)
                    .col(
                        ColumnDef::new(PurlLicenseAssertion::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4))
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(PurlLicenseAssertion::LicenseId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PurlLicenseAssertion::LicenseId)
                            .to(License::Table, License::Id)
                            .on_delete(ForeignKeyAction::NoAction),
                    )
                    .col(
                        ColumnDef::new(PurlLicenseAssertion::SbomId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PurlLicenseAssertion::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .col(
                        ColumnDef::new(PurlLicenseAssertion::VersionedPurlId)
                            .uuid()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(PurlLicenseAssertion::VersionedPurlId)
                            .to(VersionedPurl::Table, VersionedPurl::Id)
                            .on_delete(ForeignKeyAction::NoAction),
                    )
                    .index(
                        Index::create()
                            .table(PurlLicenseAssertion::Table)
                            .name("purl_license_assertion_idx")
                            .col(PurlLicenseAssertion::SbomId)
                            .col(PurlLicenseAssertion::LicenseId)
                            .col(PurlLicenseAssertion::VersionedPurlId)
                            .unique(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
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
enum VersionedPurl {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum PurlLicenseAssertion {
    Table,
    Id,
    SbomId,
    VersionedPurlId,
    LicenseId,
}
