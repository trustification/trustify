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
                    .table(LicensingInfos::Table)
                    .col(ColumnDef::new(LicensingInfos::Name).string().not_null())
                    .col(
                        ColumnDef::new(LicensingInfos::LicenseId)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(LicensingInfos::SbomId).uuid().not_null())
                    .col(ColumnDef::new(LicensingInfos::ExtractedText).string())
                    .col(ColumnDef::new(LicensingInfos::Comment).string())
                    .primary_key(
                        Index::create()
                            .col(LicensingInfos::SbomId)
                            .col(LicensingInfos::LicenseId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(LicensingInfos::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(SbomPackageLicense::Table)
                    .col(
                        ColumnDef::new(SbomPackageLicense::Id)
                            .uuid()
                            .not_null()
                            .default(Func::cust(UuidV4)),
                    )
                    .col(ColumnDef::new(SbomPackageLicense::SbomId).uuid().not_null())
                    .col(
                        ColumnDef::new(SbomPackageLicense::LicenseId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SbomPackageLicense::NodeId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SbomPackageLicense::LicenseType)
                            .integer()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(LicensingInfos::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from_col(LicensingInfos::LicenseId)
                            .to(License::Table, License::Id),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomPackageLicense::SbomId)
                            .col(SbomPackageLicense::NodeId)
                            .col(SbomPackageLicense::LicenseId)
                            .col(SbomPackageLicense::LicenseType)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(PurlLicenseAssertion::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(CpeLicenseAssertion::Table).to_owned())
            .await?;
        Ok(())
    }
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(LicensingInfos::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(SbomPackageLicense::Table).to_owned())
            .await?;

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
}

#[derive(DeriveIden)]
pub enum LicensingInfos {
    Table,
    SbomId,
    Name,
    LicenseId,
    ExtractedText,
    Comment,
}

#[derive(DeriveIden)]
pub enum Sbom {
    Table,
    SbomId,
}

#[derive(DeriveIden)]
pub enum SbomPackageLicense {
    Table,
    Id,
    SbomId,
    NodeId,
    LicenseId,
    LicenseType,
}

// #[derive(DeriveIden)]
// pub enum Sbom {
//     Table,
//     SbomId,
// }

#[derive(DeriveIden)]
pub enum License {
    Table,
    Id,
}

// #[derive(DeriveIden)]
// enum License {
//     Table,
//     Id,
// }

// #[derive(DeriveIden)]
// enum Sbom {
//     Table,
//     SbomId,
// }

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

// #[derive(DeriveIden)]
// enum License {
//     Table,
//     Id,
// }

// #[derive(DeriveIden)]
// enum Sbom {
//     Table,
//     SbomId,
// }

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
